/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! Core types for FIX protocol operations.
//!
//! This module provides fundamental types used throughout the IronFix engine:
//! - [`SeqNum`]: Sequence number wrapper with atomic operations
//! - [`Timestamp`]: FIX-formatted timestamp with nanosecond precision
//! - [`CompId`]: Component identifier (SenderCompID, TargetCompID)
//! - [`Side`]: Order side enumeration

use crate::error::{CompIdError, InvalidSide, TimestampError};
use arrayvec::ArrayString;
use chrono::{DateTime, Datelike, Timelike, Utc};
use num_derive::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use std::time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH};

/// Maximum length for CompID strings in bytes.
pub const COMP_ID_MAX_LEN: usize = 32;

/// Length of `YYYYMMDD-HH:MM:SS`, a FIX UTCTimestamp in whole seconds, in
/// bytes.
const UTC_TIMESTAMP_SECONDS_LEN: usize = 17;

/// Length of `YYYYMMDD-HH:MM:SS.`, the part of a FIX UTCTimestamp before its
/// fractional-second digits, in bytes.
const UTC_TIMESTAMP_PREFIX_LEN: usize = 18;

/// The most fractional-second digits a UTCTimestamp carries (nanoseconds).
const MAX_FRACTION_DIGITS: usize = 9;

/// Nanoseconds in one second.
const NANOS_PER_SECOND: u32 = 1_000_000_000;

/// Formats `dt` as a FIX UTCTimestamp of exactly `LEN` bytes, truncated
/// rather than rounded: `YYYYMMDD-HH:MM:SS` in whole seconds when `LEN` is 17,
/// otherwise `YYYYMMDD-HH:MM:SS.` followed by `LEN - 18` fractional-second
/// digits (`LEN` 21 is milliseconds, 24 microseconds, 27 nanoseconds).
///
/// The calendar fields come from chrono's plain accessors and the digits are
/// written into a fixed-size array, so the call allocates nothing.
///
/// The output is byte-identical to chrono's `%Y%m%d-%H:%M:%S` (and
/// `%Y%m%d-%H:%M:%S%.3f` / `%.6f` / `%.9f`), leap second included: chrono
/// represents a leap second as a nanosecond count of 1_000_000_000 or more,
/// prints its second as `60`, and takes the fractional digits from the count
/// modulo one second.
///
/// Returns `None`, never a truncated value, when the year has no four-digit
/// form (outside `0..=9999`) or `LEN` is neither 17 nor room for one to nine
/// fractional digits.
#[must_use]
fn format_utc_timestamp<const LEN: usize>(dt: DateTime<Utc>) -> Option<ArrayString<LEN>> {
    // Whole seconds carry no '.'; a fraction has one to nine digits after it.
    let fraction_digits = match LEN.checked_sub(UTC_TIMESTAMP_PREFIX_LEN) {
        None if LEN == UTC_TIMESTAMP_SECONDS_LEN => 0,
        Some(digits @ 1..=MAX_FRACTION_DIGITS) => digits,
        _ => return None,
    };

    let naive = dt.naive_utc();
    let nanos = naive.nanosecond();
    let second = naive.second().checked_add(nanos / NANOS_PER_SECOND)?;

    // Byte offsets: YYYY 0..4, MM 4..6, DD 6..8, '-' 8, HH 9..11, ':' 11,
    // MM 12..14, ':' 14, SS 15..17, then '.' 17 and the fraction to the end
    // when there is one.
    let mut out = [b'0'; LEN];
    put_digits(out.get_mut(0..4)?, u32::try_from(naive.year()).ok()?)?;
    put_digits(out.get_mut(4..6)?, naive.month())?;
    put_digits(out.get_mut(6..8)?, naive.day())?;
    *out.get_mut(8)? = b'-';
    put_digits(out.get_mut(9..11)?, naive.hour())?;
    *out.get_mut(11)? = b':';
    put_digits(out.get_mut(12..14)?, naive.minute())?;
    *out.get_mut(14)? = b':';
    put_digits(out.get_mut(15..UTC_TIMESTAMP_SECONDS_LEN)?, second)?;
    if fraction_digits > 0 {
        // Nanoseconds per unit of the last fractional digit: 10^(9 - digits).
        let dropped_digits =
            u32::try_from(MAX_FRACTION_DIGITS.checked_sub(fraction_digits)?).ok()?;
        let fraction_unit = 10_u32.checked_pow(dropped_digits)?;
        let fraction = (nanos % NANOS_PER_SECOND).checked_div(fraction_unit)?;
        *out.get_mut(UTC_TIMESTAMP_SECONDS_LEN)? = b'.';
        put_digits(out.get_mut(UTC_TIMESTAMP_PREFIX_LEN..)?, fraction)?;
    }
    ArrayString::from_byte_string(&out).ok()
}

/// Writes `value` into `dst` as zero-padded decimal digits that fill it
/// exactly.
///
/// Returns `None` when `value` has more digits than `dst` holds; `dst` is then
/// partly written and must be discarded.
#[must_use = "a None means the value did not fit and the buffer must be discarded"]
const fn put_digits(mut dst: &mut [u8], mut value: u32) -> Option<()> {
    while let Some((slot, rest)) = dst.split_last_mut() {
        // `value % 10` is below 10, so the narrowing cast is lossless.
        *slot = match b'0'.checked_add((value % 10) as u8) {
            Some(digit) => digit,
            None => return None,
        };
        value /= 10;
        dst = rest;
    }
    if value == 0 { Some(()) } else { None }
}

/// Whole seconds from the Unix epoch of the instant `before` ahead of it,
/// floored like [`DateTime::timestamp`]: half a second before the epoch is
/// `-1`.
#[must_use]
fn seconds_before_epoch(before: Duration) -> i64 {
    let whole = i64::try_from(before.as_secs())
        .ok()
        .and_then(i64::checked_neg);
    let floored = if before.subsec_nanos() == 0 {
        whole
    } else {
        whole.and_then(|seconds| seconds.checked_sub(1))
    };
    // Misses only for a reading more than `i64::MAX` seconds before the
    // epoch, which no system clock produces; `i64::MIN` labels it.
    floored.unwrap_or(i64::MIN)
}

/// FIX message sequence number.
///
/// Sequence numbers are unsigned 64-bit integers that identify messages
/// within a FIX session. They start at 1 and increment for each message sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct SeqNum(u64);

impl SeqNum {
    /// Creates a new sequence number.
    ///
    /// # Arguments
    /// * `value` - The sequence number value (should be >= 1 for valid FIX messages)
    #[inline]
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw sequence number value.
    #[inline]
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Returns the next sequence number.
    #[inline]
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }

    /// Checks if this sequence number is valid (>= 1).
    #[inline]
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.0 >= 1
    }
}

impl Default for SeqNum {
    fn default() -> Self {
        Self(1)
    }
}

impl From<u64> for SeqNum {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<SeqNum> for u64 {
    fn from(seq: SeqNum) -> Self {
        seq.0
    }
}

impl fmt::Display for SeqNum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// FIX protocol timestamp with nanosecond precision.
///
/// Timestamps in FIX are formatted as `YYYYMMDD-HH:MM:SS` (whole seconds, the
/// only form FIX 4.0 and FIX 4.1 define), `YYYYMMDD-HH:MM:SS.sss`
/// (milliseconds), `YYYYMMDD-HH:MM:SS.ssssss` (microseconds) or
/// `YYYYMMDD-HH:MM:SS.sssssssss` (nanoseconds).
///
/// # Representable range
///
/// The count is unsigned nanoseconds since the Unix epoch, bounded by
/// [`Timestamp::MAX_NANOS`]. The representable interval is therefore
/// `1970-01-01T00:00:00.000000000Z ..= 2262-04-11T23:47:16.854775807Z`
/// inclusive. Instants before the epoch and past that ceiling are **not**
/// representable and are rejected by the fallible constructors rather than
/// wrapped or zeroed. Because the bound is enforced at construction,
/// [`Timestamp::to_datetime`] and the `format_*` methods are total.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Timestamp {
    /// Nanoseconds since Unix epoch (1970-01-01 00:00:00 UTC).
    nanos_since_epoch: u64,
}

impl Timestamp {
    /// The largest representable nanosecond count, `i64::MAX` nanoseconds.
    ///
    /// Equals `2262-04-11T23:47:16.854775807Z`. The bound is `i64`-shaped
    /// because a `chrono::DateTime` counts nanoseconds in an `i64`; keeping
    /// the invariant here is what makes [`Timestamp::to_datetime`] total.
    pub const MAX_NANOS: u64 = 9_223_372_036_854_775_807;

    /// The Unix epoch, `1970-01-01T00:00:00.000000000Z`.
    pub const EPOCH: Self = Self {
        nanos_since_epoch: 0,
    };

    /// Creates a timestamp from nanoseconds since Unix epoch.
    ///
    /// # Arguments
    /// * `nanos` - Nanoseconds since 1970-01-01 00:00:00 UTC
    ///
    /// # Errors
    /// Returns [`TimestampError::NanosOutOfRange`] if `nanos` exceeds
    /// [`Timestamp::MAX_NANOS`].
    #[inline]
    pub const fn from_nanos(nanos: u64) -> Result<Self, TimestampError> {
        if nanos > Self::MAX_NANOS {
            return Err(TimestampError::NanosOutOfRange {
                nanos,
                max_nanos: Self::MAX_NANOS,
            });
        }
        Ok(Self {
            nanos_since_epoch: nanos,
        })
    }

    /// Creates a timestamp from milliseconds since Unix epoch.
    ///
    /// # Arguments
    /// * `millis` - Milliseconds since 1970-01-01 00:00:00 UTC
    ///
    /// # Errors
    /// Returns [`TimestampError::MillisOutOfRange`] if scaling `millis` to
    /// nanoseconds overflows, or [`TimestampError::NanosOutOfRange`] if the
    /// result exceeds [`Timestamp::MAX_NANOS`].
    #[inline]
    pub const fn from_millis(millis: u64) -> Result<Self, TimestampError> {
        match millis.checked_mul(1_000_000) {
            Some(nanos) => Self::from_nanos(nanos),
            None => Err(TimestampError::MillisOutOfRange { millis }),
        }
    }

    /// Converts a calendar instant to a timestamp.
    ///
    /// # Errors
    /// Returns [`TimestampError::InstantOutOfRange`] if `dt` lies before the
    /// Unix epoch or past [`Timestamp::MAX_NANOS`].
    fn from_datetime(dt: DateTime<Utc>) -> Result<Self, TimestampError> {
        let out_of_range = || TimestampError::InstantOutOfRange {
            seconds: dt.timestamp(),
        };
        let Some(nanos) = dt.timestamp_nanos_opt() else {
            return Err(out_of_range());
        };
        match u64::try_from(nanos) {
            Ok(nanos) => Self::from_nanos(nanos),
            Err(_) => Err(out_of_range()),
        }
    }

    /// Converts a reading of the system clock, as
    /// `SystemTime::now().duration_since(UNIX_EPOCH)` returns it, to a
    /// timestamp.
    ///
    /// Takes the reading rather than the clock so that a clock before the
    /// epoch, which `duration_since` reports as an `Err`, can be tested.
    ///
    /// # Errors
    /// Returns [`TimestampError::InstantOutOfRange`] if the reading lies
    /// before the Unix epoch, or past [`Timestamp::MAX_NANOS`] (the nanosecond
    /// count is built with checked arithmetic, so an overflow is reported, not
    /// wrapped). `seconds` is the reading's whole seconds from the epoch,
    /// floored like [`DateTime::timestamp`].
    fn from_system_clock(
        reading: Result<Duration, SystemTimeError>,
    ) -> Result<Self, TimestampError> {
        match reading {
            Ok(since_epoch) => {
                let nanos = since_epoch
                    .as_secs()
                    .checked_mul(u64::from(NANOS_PER_SECOND))
                    .and_then(|nanos| nanos.checked_add(u64::from(since_epoch.subsec_nanos())));
                match nanos.map(Self::from_nanos) {
                    Some(Ok(ts)) => Ok(ts),
                    _ => Err(TimestampError::InstantOutOfRange {
                        // A system clock counts seconds in an `i64`, so this
                        // fits; `i64::MAX` only labels an impossible reading.
                        seconds: i64::try_from(since_epoch.as_secs()).unwrap_or(i64::MAX),
                    }),
                }
            }
            Err(before_epoch) => Err(TimestampError::InstantOutOfRange {
                seconds: seconds_before_epoch(before_epoch.duration()),
            }),
        }
    }

    /// Converts a reading of the system clock to a timestamp, clamping an
    /// unrepresentable reading (before 1970 or after 2262) to
    /// [`Timestamp::EPOCH`].
    fn clamp_system_clock(reading: Result<Duration, SystemTimeError>) -> Self {
        Self::from_system_clock(reading).unwrap_or(Self::EPOCH)
    }

    /// Returns the current UTC timestamp.
    ///
    /// # Clamping
    ///
    /// This reads the system clock, which is not untrusted input, and is
    /// infallible so that header stamping cannot fail. A system clock outside
    /// the representable range (before 1970 or after 2262) yields
    /// [`Timestamp::EPOCH`], which formats as `19700101-00:00:00.000` — an
    /// obviously wrong SendingTime a counterparty will reject, not a plausible
    /// substitute. Use [`Timestamp::try_now`] to observe that condition as a
    /// typed error instead.
    ///
    /// The clock is read through [`SystemTime`] directly, never through
    /// `chrono::Utc::now`, which panics on a clock before the epoch.
    #[inline]
    #[must_use]
    pub fn now() -> Self {
        Self::clamp_system_clock(SystemTime::now().duration_since(UNIX_EPOCH))
    }

    /// Returns the current UTC timestamp, or an error if the system clock is
    /// outside the representable range.
    ///
    /// Like [`Timestamp::now`], it reads [`SystemTime`] directly and never
    /// panics.
    ///
    /// # Errors
    /// Returns [`TimestampError::InstantOutOfRange`] if the system clock reads
    /// before the Unix epoch or past [`Timestamp::MAX_NANOS`].
    #[inline]
    pub fn try_now() -> Result<Self, TimestampError> {
        Self::from_system_clock(SystemTime::now().duration_since(UNIX_EPOCH))
    }

    /// Returns nanoseconds since Unix epoch.
    #[inline]
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.nanos_since_epoch
    }

    /// Returns milliseconds since Unix epoch.
    #[inline]
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.nanos_since_epoch / 1_000_000
    }

    /// Returns microseconds since Unix epoch.
    #[inline]
    #[must_use]
    pub const fn as_micros(self) -> u64 {
        self.nanos_since_epoch / 1_000
    }

    /// Converts to a chrono `DateTime<Utc>`.
    ///
    /// Total by construction: every constructor bounds the nanosecond count to
    /// [`Timestamp::MAX_NANOS`], which is exactly what an `i64` nanosecond
    /// count can hold.
    #[must_use]
    pub fn to_datetime(self) -> DateTime<Utc> {
        debug_assert!(
            self.nanos_since_epoch <= Self::MAX_NANOS,
            "Timestamp constructors bound nanos_since_epoch to MAX_NANOS"
        );
        match i64::try_from(self.nanos_since_epoch) {
            Ok(nanos) => DateTime::from_timestamp_nanos(nanos),
            // Unreachable while the constructor invariant holds; still typed
            // rather than a panic, since the release profile aborts.
            Err(_) => DateTime::from_timestamp_nanos(i64::MAX),
        }
    }

    /// Formats the timestamp in FIX format with whole-second precision.
    ///
    /// Format: `YYYYMMDD-HH:MM:SS`, the fraction truncated, not rounded, so it
    /// is always the first 17 bytes of [`Timestamp::format_millis`]. It is
    /// the only form of `time`, the type FIX 4.0 and FIX 4.1 give
    /// `SendingTime` (52) and `OrigSendingTime` (122); FIX 4.2 replaced that
    /// type with a `UTCTimestamp` that may also carry milliseconds. The digits
    /// are written straight into the returned buffer, so the call allocates
    /// nothing.
    ///
    /// # Examples
    ///
    /// ```
    /// use ironfix_core::Timestamp;
    ///
    /// // 2024-02-29T12:34:56.789012345Z
    /// let ts = Timestamp::from_nanos(1_709_210_096_789_012_345)?;
    /// assert_eq!(ts.format_seconds().as_str(), "20240229-12:34:56");
    /// assert_eq!(ts.format_millis().as_str(), "20240229-12:34:56.789");
    /// # Ok::<(), ironfix_core::error::TimestampError>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn format_seconds(self) -> ArrayString<17> {
        self.format_fixed()
    }

    /// Formats the timestamp in FIX format with millisecond precision.
    ///
    /// Format: `YYYYMMDD-HH:MM:SS.sss`, the fraction truncated, not rounded.
    /// The digits are written straight into the returned buffer, so the call
    /// allocates nothing; it runs for every outbound `SendingTime` (52) on a
    /// FIX 4.2 or later session.
    #[inline]
    #[must_use]
    pub fn format_millis(self) -> ArrayString<21> {
        self.format_fixed()
    }

    /// Formats the timestamp in FIX format with microsecond precision.
    ///
    /// Format: `YYYYMMDD-HH:MM:SS.ssssss`, the fraction truncated, not
    /// rounded. The digits are written straight into the returned buffer, so
    /// the call allocates nothing.
    #[inline]
    #[must_use]
    pub fn format_micros(self) -> ArrayString<24> {
        self.format_fixed()
    }

    /// Formats the timestamp as a `LEN`-byte FIX UTCTimestamp.
    ///
    /// Total for every timestamp: the constructors bound the instant to
    /// `1970..=2262`, whose years all have four digits, and the callers pass
    /// a `LEN` of whole seconds or one with one to nine fractional digits.
    /// Were that ever violated, the result would be empty, which is also what
    /// the chrono-based formatter this replaced produced for a year without
    /// four digits: never a truncated or wrapped value.
    #[must_use]
    fn format_fixed<const LEN: usize>(self) -> ArrayString<LEN> {
        let formatted = format_utc_timestamp(self.to_datetime());
        debug_assert!(
            formatted.is_some(),
            "a Timestamp's year has four digits and LEN fits a UTCTimestamp"
        );
        formatted.unwrap_or_default()
    }
}

impl Default for Timestamp {
    fn default() -> Self {
        Self::now()
    }
}

impl TryFrom<DateTime<Utc>> for Timestamp {
    type Error = TimestampError;

    /// Converts a calendar instant to a timestamp.
    ///
    /// This is the landing point for a parsed SendingTime (tag 52), so an
    /// instant outside the representable range is an error rather than a
    /// silently zeroed or wrapped value.
    ///
    /// # Errors
    /// Returns [`TimestampError::InstantOutOfRange`] if `dt` lies before the
    /// Unix epoch or past [`Timestamp::MAX_NANOS`].
    fn try_from(dt: DateTime<Utc>) -> Result<Self, Self::Error> {
        Self::from_datetime(dt)
    }
}

impl fmt::Display for Timestamp {
    /// Writes [`Timestamp::format_millis`] as is. Width, fill and alignment
    /// flags are ignored, as they always were: `f.pad` would honour them.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.format_millis().as_str())
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    /// Deserializes a timestamp, routing the raw nanosecond count through
    /// [`Timestamp::from_nanos`] so the [`Timestamp::MAX_NANOS`] bound is
    /// enforced. A serialized value whose `nanos_since_epoch` exceeds the
    /// ceiling is a deserialization error, not a silently clamped or wrapped
    /// instant — that is what keeps [`Timestamp::to_datetime`] total by
    /// construction even for values that arrive over serde.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Mirrors the field-per-struct shape the derived `Serialize` emits, so
        // the pair round-trips, but re-validates instead of trusting the input.
        #[derive(Deserialize)]
        struct Raw {
            nanos_since_epoch: u64,
        }
        let raw = Raw::deserialize(deserializer)?;
        Self::from_nanos(raw.nanos_since_epoch).map_err(serde::de::Error::custom)
    }
}

/// Component identifier for FIX sessions.
///
/// Used for SenderCompID (tag 49), TargetCompID (tag 56), and related fields.
///
/// # Bounds
///
/// The value is at most [`COMP_ID_MAX_LEN`] **bytes**. That bound is an
/// IronFix engineering choice — it is what keeps a CompID in inline
/// [`ArrayString`] storage instead of a heap allocation. The FIX specification
/// types CompID as an unbounded `String` and does not bound its length.
///
/// # Charset
///
/// Only printable ASCII (`0x20..=0x7e`) is accepted, and the value must not be
/// empty. A CompID is written verbatim into tags 49 and 56 on every outbound
/// message, so a SOH or any other control byte would terminate the field early
/// and let a hostile CompID inject header fields or corrupt framing; an empty
/// value would emit `49=<SOH>`, a field FIX TagValue treats as malformed.
/// Rejecting those at construction is the chokepoint that makes such a value
/// unrepresentable rather than escaping it at every encode site. The `=` byte
/// is deliberately **not** rejected: it is a legal FIX String value byte (only
/// the first `=` of a field separates tag from value, and a CompID is a value,
/// never a tag), so a counterparty identifier may legitimately contain it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct CompId(ArrayString<COMP_ID_MAX_LEN>);

impl CompId {
    /// Creates a new CompId from a string slice.
    ///
    /// # Arguments
    /// * `s` - The component identifier string
    ///
    /// # Errors
    /// Returns [`CompIdError::Empty`] if `s` is empty, [`CompIdError::TooLong`]
    /// if `s` exceeds [`COMP_ID_MAX_LEN`] bytes, or [`CompIdError::IllegalByte`]
    /// if it contains any byte outside printable ASCII (`0x20..=0x7e`).
    pub fn new(s: &str) -> Result<Self, CompIdError> {
        if s.is_empty() {
            return Err(CompIdError::Empty);
        }
        if s.len() > COMP_ID_MAX_LEN {
            return Err(CompIdError::TooLong {
                len: s.len(),
                max_len: COMP_ID_MAX_LEN,
            });
        }
        for (position, &byte) in s.as_bytes().iter().enumerate() {
            let printable = byte.is_ascii_graphic() || byte == b' ';
            if !printable {
                return Err(CompIdError::IllegalByte { byte, position });
            }
        }
        match ArrayString::from(s) {
            Ok(inner) => Ok(Self(inner)),
            // Unreachable: the length was checked above.
            Err(_) => Err(CompIdError::TooLong {
                len: s.len(),
                max_len: COMP_ID_MAX_LEN,
            }),
        }
    }

    /// Returns the CompId as a string slice.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Returns the length of the CompId in bytes.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the CompId is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<str> for CompId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for CompId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for CompId {
    type Err = CompIdError;

    /// Parses a CompID, applying the same emptiness, length, and charset checks
    /// as [`CompId::new`].
    ///
    /// # Errors
    /// Returns [`CompIdError::Empty`], [`CompIdError::TooLong`], or
    /// [`CompIdError::IllegalByte`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl<'de> Deserialize<'de> for CompId {
    /// Deserializes a CompID by routing the raw string through [`CompId::new`],
    /// so the emptiness, length, and charset invariants hold for a value that
    /// arrives over serde exactly as they do for one built in code. The derived
    /// `Serialize` is transparent, so a serialized CompID is just its string;
    /// re-validating it here stops a hand-crafted payload (an embedded SOH, a
    /// control byte, an over-length or empty value) from reconstructing a
    /// `CompId` that never passed the constructor and then being written
    /// verbatim into tags 49 and 56.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(&raw).map_err(serde::de::Error::custom)
    }
}

/// Order side enumeration (tag 54).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, FromPrimitive, ToPrimitive,
)]
#[repr(u8)]
#[serde(rename_all = "UPPERCASE")]
pub enum Side {
    /// Buy order.
    Buy = b'1',
    /// Sell order.
    Sell = b'2',
    /// Buy minus (sell short exempt).
    BuyMinus = b'3',
    /// Sell plus (buy to cover).
    SellPlus = b'4',
    /// Sell short.
    SellShort = b'5',
    /// Sell short exempt.
    SellShortExempt = b'6',
    /// Undisclosed.
    Undisclosed = b'7',
    /// Cross (both sides).
    Cross = b'8',
    /// Cross short.
    CrossShort = b'9',
    /// Cross short exempt.
    CrossShortExempt = b'A',
    /// As defined (for multileg).
    AsDefined = b'B',
    /// Opposite (for multileg).
    Opposite = b'C',
    /// Subscribe.
    Subscribe = b'D',
    /// Redeem.
    Redeem = b'E',
    /// Lend (for securities lending).
    Lend = b'F',
    /// Borrow (for securities lending).
    Borrow = b'G',
}

impl Side {
    /// Creates a Side from a single character.
    ///
    /// # Arguments
    /// * `c` - The character representing the side
    ///
    /// # Returns
    /// `Some(Side)` if the character is valid, `None` otherwise.
    #[must_use]
    pub const fn from_char(c: char) -> Option<Self> {
        match c {
            '1' => Some(Self::Buy),
            '2' => Some(Self::Sell),
            '3' => Some(Self::BuyMinus),
            '4' => Some(Self::SellPlus),
            '5' => Some(Self::SellShort),
            '6' => Some(Self::SellShortExempt),
            '7' => Some(Self::Undisclosed),
            '8' => Some(Self::Cross),
            '9' => Some(Self::CrossShort),
            'A' => Some(Self::CrossShortExempt),
            'B' => Some(Self::AsDefined),
            'C' => Some(Self::Opposite),
            'D' => Some(Self::Subscribe),
            'E' => Some(Self::Redeem),
            'F' => Some(Self::Lend),
            'G' => Some(Self::Borrow),
            _ => None,
        }
    }

    /// Returns the character representation of this side.
    #[must_use]
    pub const fn as_char(self) -> char {
        self as u8 as char
    }

    /// Returns true if this is a buy-side order.
    #[must_use]
    pub const fn is_buy(self) -> bool {
        matches!(self, Self::Buy | Self::BuyMinus)
    }

    /// Returns true if this is a sell-side order.
    #[must_use]
    pub const fn is_sell(self) -> bool {
        matches!(
            self,
            Self::Sell | Self::SellPlus | Self::SellShort | Self::SellShortExempt
        )
    }
}

impl fmt::Display for Side {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_char())
    }
}

impl TryFrom<u8> for Side {
    type Error = InvalidSide;

    /// Converts a wire byte to a `Side`.
    ///
    /// # Errors
    /// Returns [`InvalidSide`] if `value` is not one of the Side (tag 54)
    /// codes.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_char(char::from(value)).ok_or(InvalidSide::new(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seq_num_operations() {
        let seq = SeqNum::new(5);
        assert_eq!(seq.value(), 5);
        assert_eq!(seq.next().value(), 6);
        assert!(seq.is_valid());
        assert!(!SeqNum::new(0).is_valid());
    }

    #[test]
    fn test_seq_num_default() {
        let seq = SeqNum::default();
        assert_eq!(seq.value(), 1);
    }

    /// Unwraps a `Result` with test context instead of `.unwrap()`.
    #[track_caller]
    fn ok<T, E: fmt::Debug>(result: Result<T, E>, what: &str) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("{what}: {err:?}"),
        }
    }

    #[test]
    fn test_timestamp_from_millis_converts() {
        let ts = ok(Timestamp::from_millis(1000), "1000ms is representable");
        assert_eq!(ts.as_millis(), 1000);
        assert_eq!(ts.as_micros(), 1_000_000);
        assert_eq!(ts.as_nanos(), 1_000_000_000);
    }

    #[test]
    fn test_timestamp_from_millis_overflow_is_typed_error() {
        // u64::MAX ms scaled to nanoseconds overflows the multiply itself.
        assert_eq!(
            Timestamp::from_millis(u64::MAX),
            Err(TimestampError::MillisOutOfRange { millis: u64::MAX })
        );
    }

    #[test]
    fn test_timestamp_from_millis_past_ceiling_is_typed_error() {
        // Multiplies cleanly within u64 but lands past MAX_NANOS (year 2262).
        let millis = 10_000_000_000_000_u64;
        assert_eq!(
            Timestamp::from_millis(millis),
            Err(TimestampError::NanosOutOfRange {
                nanos: 10_000_000_000_000_000_000,
                max_nanos: Timestamp::MAX_NANOS,
            })
        );
    }

    #[test]
    fn test_timestamp_from_nanos_boundaries() {
        let max = ok(
            Timestamp::from_nanos(Timestamp::MAX_NANOS),
            "MAX_NANOS is representable",
        );
        assert_eq!(max.as_nanos(), Timestamp::MAX_NANOS);
        assert_eq!(
            Timestamp::from_nanos(Timestamp::MAX_NANOS + 1),
            Err(TimestampError::NanosOutOfRange {
                nanos: Timestamp::MAX_NANOS + 1,
                max_nanos: Timestamp::MAX_NANOS,
            })
        );
    }

    #[test]
    fn test_timestamp_try_from_pre_epoch_datetime_is_typed_error() {
        let Some(dt) = DateTime::from_timestamp(-1, 0) else {
            panic!("1969-12-31T23:59:59Z is a valid chrono instant");
        };
        assert_eq!(
            Timestamp::try_from(dt),
            Err(TimestampError::InstantOutOfRange { seconds: -1 })
        );
    }

    /// What `SystemTime::now().duration_since(UNIX_EPOCH)` returns on a clock
    /// that reads `before` ahead of the epoch: the real clock cannot be moved.
    #[track_caller]
    fn reading_before_epoch(before: Duration) -> Result<Duration, SystemTimeError> {
        let Some(instant) = UNIX_EPOCH.checked_sub(before) else {
            panic!("{before:?} before the epoch is a valid SystemTime");
        };
        let reading = instant.duration_since(UNIX_EPOCH);
        assert!(reading.is_err(), "an instant before the epoch reads as Err");
        reading
    }

    #[test]
    fn test_timestamp_from_system_clock_pre_epoch_is_typed_error() {
        // Whole multiples of 100 ns, the coarsest `SystemTime` resolution
        // (Windows), so every instant really lies before the epoch.
        let cases = [
            (Duration::from_micros(1), -1),
            (Duration::from_secs(1), -1),
            (Duration::from_millis(1_500), -2),
            (Duration::from_secs(86_400), -86_400),
        ];
        for (before, seconds) in cases {
            assert_eq!(
                Timestamp::from_system_clock(reading_before_epoch(before)),
                Err(TimestampError::InstantOutOfRange { seconds }),
                "{before:?} before the epoch"
            );
        }
    }

    #[test]
    fn test_timestamp_from_system_clock_pre_epoch_seconds_match_try_from_datetime() {
        // 1.5 s before the epoch, through the clock and through chrono.
        let Some(dt) = DateTime::from_timestamp(-2, 500_000_000) else {
            panic!("1969-12-31T23:59:58.5Z is a valid chrono instant");
        };
        assert_eq!(
            Timestamp::from_system_clock(reading_before_epoch(Duration::from_millis(1_500))),
            Timestamp::try_from(dt)
        );
    }

    #[test]
    fn test_timestamp_clamp_system_clock_pre_epoch_yields_epoch() {
        let reading = reading_before_epoch(Duration::from_secs(86_400));
        assert_eq!(Timestamp::clamp_system_clock(reading), Timestamp::EPOCH);
        assert_eq!(Timestamp::EPOCH.as_nanos(), 0);
    }

    #[test]
    fn test_timestamp_from_system_clock_in_range_is_exact() {
        let reading = Ok(Duration::new(1_700_000_000, 123_456_789));
        let ts = ok(Timestamp::from_system_clock(reading), "in range");
        assert_eq!(ts.as_nanos(), 1_700_000_000_123_456_789);
        assert_eq!(
            Timestamp::clamp_system_clock(Ok(Duration::new(1_700_000_000, 123_456_789))),
            ts
        );
        assert_eq!(
            Timestamp::from_system_clock(Ok(Duration::ZERO)),
            Ok(Timestamp::EPOCH)
        );
    }

    #[test]
    fn test_timestamp_from_system_clock_past_ceiling_is_typed_error() {
        let ceiling = Duration::from_nanos(Timestamp::MAX_NANOS);
        let max = ok(Timestamp::from_system_clock(Ok(ceiling)), "MAX_NANOS");
        assert_eq!(max.as_nanos(), Timestamp::MAX_NANOS);

        let past = Duration::from_nanos(Timestamp::MAX_NANOS + 1);
        assert_eq!(
            Timestamp::from_system_clock(Ok(past)),
            Err(TimestampError::InstantOutOfRange {
                seconds: 9_223_372_036
            })
        );
        assert_eq!(Timestamp::clamp_system_clock(Ok(past)), Timestamp::EPOCH);
    }

    #[test]
    fn test_timestamp_from_system_clock_nanos_overflow_is_typed_error() {
        // u64::MAX seconds overflows the checked scale to nanoseconds.
        assert_eq!(
            Timestamp::from_system_clock(Ok(Duration::MAX)),
            Err(TimestampError::InstantOutOfRange { seconds: i64::MAX })
        );
        assert_eq!(
            Timestamp::clamp_system_clock(Ok(Duration::MAX)),
            Timestamp::EPOCH
        );
    }

    #[test]
    fn test_seconds_before_epoch_floors() {
        let i64_max_secs = Duration::from_secs(9_223_372_036_854_775_807);
        let cases = [
            (Duration::ZERO, 0),
            (Duration::from_nanos(1), -1),
            (Duration::from_secs(1), -1),
            (Duration::from_millis(1_500), -2),
            (i64_max_secs, -i64::MAX),
            (i64_max_secs + Duration::from_nanos(1), i64::MIN),
            (Duration::MAX, i64::MIN),
        ];
        for (before, seconds) in cases {
            assert_eq!(seconds_before_epoch(before), seconds, "{before:?}");
        }
    }

    #[test]
    fn test_timestamp_try_now_is_representable() {
        let now = ok(Timestamp::try_now(), "the system clock is in range");
        assert!(now.as_nanos() > 0);
        assert!(Timestamp::now() >= now);
    }

    #[test]
    fn test_timestamp_display_ignores_width_flags() {
        let ts = ok(
            Timestamp::from_nanos(1_709_210_096_789_012_345),
            "instant is representable",
        );
        assert_eq!(format!("{ts}"), "20240229-12:34:56.789");
        assert_eq!(format!("{ts:>30}"), "20240229-12:34:56.789");
        assert_eq!(format!("{ts:*<30}"), "20240229-12:34:56.789");
    }

    #[test]
    fn test_timestamp_format_millis_at_epoch() {
        let ts = ok(Timestamp::from_millis(0), "0ms is representable");
        assert_eq!(ts.format_millis().as_str(), "19700101-00:00:00.000");
    }

    #[test]
    fn test_timestamp_format_seconds_at_epoch() {
        let ts = ok(Timestamp::from_millis(0), "0ms is representable");
        assert_eq!(ts.format_seconds().as_str(), "19700101-00:00:00");
    }

    #[test]
    fn test_timestamp_format_seconds_truncates_the_fraction() {
        // 23:59:59.999999999 stays in its second: truncated, never rounded up
        // into the next minute, hour, day or year.
        let ts = ok(
            Timestamp::from_nanos(946_684_799_999_999_999),
            "1999-12-31T23:59:59.999999999Z is representable",
        );
        assert_eq!(ts.format_seconds().as_str(), "19991231-23:59:59");
        // No '.', and nothing after the seconds.
        assert_eq!(ts.format_seconds().len(), 17);
        assert!(!ts.format_seconds().contains('.'));
    }

    #[test]
    fn test_timestamp_format_micros_at_known_instant() {
        // 2023-11-14T22:13:20.123456Z
        let ts = ok(
            Timestamp::from_nanos(1_700_000_000_123_456_000),
            "instant is representable",
        );
        assert_eq!(ts.format_micros().as_str(), "20231114-22:13:20.123456");
    }

    /// chrono's pattern for a whole-second UTCTimestamp.
    const SECONDS_PATTERN: &str = "%Y%m%d-%H:%M:%S";
    /// chrono's pattern for a millisecond UTCTimestamp.
    const MILLIS_PATTERN: &str = "%Y%m%d-%H:%M:%S%.3f";
    /// chrono's pattern for a microsecond UTCTimestamp.
    const MICROS_PATTERN: &str = "%Y%m%d-%H:%M:%S%.6f";
    /// chrono's pattern for a nanosecond UTCTimestamp.
    const NANOS_PATTERN: &str = "%Y%m%d-%H:%M:%S%.9f";

    /// The chrono-based formatter `format_millis` / `format_micros` used
    /// before #127, kept verbatim as the byte-for-byte reference; with
    /// [`SECONDS_PATTERN`] it is the reference for `format_seconds` too. It
    /// formats into a `String` first, and writes nothing when that does not
    /// fit `LEN`.
    fn chrono_reference<const LEN: usize>(dt: DateTime<Utc>, pattern: &str) -> ArrayString<LEN> {
        let mut buf = ArrayString::new();
        let _ = std::fmt::write(&mut buf, format_args!("{}", dt.format(pattern)));
        buf
    }

    /// Builds a UTC instant; `nano` may be 1_000_000_000 or more on second 59,
    /// which is how chrono represents a leap second.
    #[track_caller]
    fn utc(ymd: (i32, u32, u32), hms: (u32, u32, u32), nano: u32) -> DateTime<Utc> {
        let (year, month, day) = ymd;
        let (hour, minute, second) = hms;
        let Some(date) = chrono::NaiveDate::from_ymd_opt(year, month, day) else {
            panic!("{year:04}-{month:02}-{day:02} is a valid date");
        };
        let Some(naive) = date.and_hms_nano_opt(hour, minute, second, nano) else {
            panic!("{hour:02}:{minute:02}:{second:02}.{nano} is a valid time");
        };
        naive.and_utc()
    }

    /// Edge instants inside the range a [`Timestamp`] can hold.
    fn representable_edges() -> Vec<DateTime<Utc>> {
        vec![
            // The epoch, the earliest representable instant.
            utc((1970, 1, 1), (0, 0, 0), 0),
            utc((1970, 1, 1), (0, 0, 0), 1),
            // Leap days, a century leap day among them.
            utc((2024, 2, 29), (12, 34, 56), 789_012_345),
            utc((2000, 2, 29), (0, 0, 0), 0),
            // Year boundaries, the last instant of a year on every digit.
            utc((1999, 12, 31), (23, 59, 59), 999_999_999),
            utc((2000, 1, 1), (0, 0, 0), 0),
            utc((2023, 12, 31), (23, 59, 59), 999_000_000),
            utc((2024, 1, 1), (0, 0, 0), 1),
            // Truncated, not rounded, at every precision.
            utc((2025, 6, 30), (23, 59, 59), 999_999_999),
            utc((2025, 6, 30), (23, 59, 59), 999_499_999),
            utc((2025, 6, 30), (23, 59, 59), 1_000),
            // Single-digit calendar and time fields.
            utc((2001, 2, 3), (4, 5, 6), 7_008_009),
            utc((2009, 9, 9), (9, 9, 9), 9),
            // The latest representable instant, Timestamp::MAX_NANOS.
            utc((2262, 4, 11), (23, 47, 16), 854_775_807),
        ]
    }

    #[test]
    fn test_format_utc_timestamp_edges_match_chrono() {
        for dt in representable_edges() {
            let seconds: Option<ArrayString<17>> = format_utc_timestamp(dt);
            let millis: Option<ArrayString<21>> = format_utc_timestamp(dt);
            let micros: Option<ArrayString<24>> = format_utc_timestamp(dt);
            let nanos: Option<ArrayString<27>> = format_utc_timestamp(dt);
            assert_eq!(seconds, Some(chrono_reference(dt, SECONDS_PATTERN)), "{dt}");
            assert_eq!(millis, Some(chrono_reference(dt, MILLIS_PATTERN)), "{dt}");
            assert_eq!(micros, Some(chrono_reference(dt, MICROS_PATTERN)), "{dt}");
            assert_eq!(nanos, Some(chrono_reference(dt, NANOS_PATTERN)), "{dt}");
        }
    }

    #[test]
    fn test_timestamp_format_edges_match_chrono() {
        for dt in representable_edges() {
            let ts = ok(Timestamp::try_from(dt), "edge instant is representable");
            let seconds: ArrayString<17> = chrono_reference(dt, SECONDS_PATTERN);
            let millis: ArrayString<21> = chrono_reference(dt, MILLIS_PATTERN);
            let micros: ArrayString<24> = chrono_reference(dt, MICROS_PATTERN);
            assert_eq!(ts.format_seconds(), seconds, "{dt}");
            assert_eq!(ts.format_millis(), millis, "{dt}");
            assert_eq!(ts.format_micros(), micros, "{dt}");
            assert_eq!(ts.to_string(), millis.as_str(), "{dt}");
        }
    }

    #[test]
    fn test_timestamp_format_edges_exact_bytes() {
        let cases = [
            (
                0,
                "19700101-00:00:00",
                "19700101-00:00:00.000",
                "19700101-00:00:00.000000",
            ),
            (
                1_709_210_096_789_012_345,
                "20240229-12:34:56",
                "20240229-12:34:56.789",
                "20240229-12:34:56.789012",
            ),
            (
                946_684_799_999_999_999,
                "19991231-23:59:59",
                "19991231-23:59:59.999",
                "19991231-23:59:59.999999",
            ),
            (
                981_173_106_007_008_009,
                "20010203-04:05:06",
                "20010203-04:05:06.007",
                "20010203-04:05:06.007008",
            ),
            (
                Timestamp::MAX_NANOS,
                "22620411-23:47:16",
                "22620411-23:47:16.854",
                "22620411-23:47:16.854775",
            ),
        ];
        for (nanos, seconds, millis, micros) in cases {
            let ts = ok(Timestamp::from_nanos(nanos), "instant is representable");
            assert_eq!(ts.format_seconds().as_str(), seconds);
            assert_eq!(ts.format_millis().as_str(), millis);
            assert_eq!(ts.format_micros().as_str(), micros);
        }
    }

    #[test]
    fn test_timestamp_format_matches_chrono_across_range() {
        // About 50_000 instants spread over the whole range; the step is not
        // a whole second, so the fractional digits vary from one to the next.
        let step = Timestamp::MAX_NANOS / 50_000;
        let mut nanos = 0_u64;
        while let Ok(ts) = Timestamp::from_nanos(nanos) {
            let dt = ts.to_datetime();
            let seconds: ArrayString<17> = chrono_reference(dt, SECONDS_PATTERN);
            let millis: ArrayString<21> = chrono_reference(dt, MILLIS_PATTERN);
            let micros: ArrayString<24> = chrono_reference(dt, MICROS_PATTERN);
            assert_eq!(ts.format_seconds(), seconds, "{nanos}");
            assert_eq!(ts.format_millis(), millis, "{nanos}");
            assert_eq!(ts.format_micros(), micros, "{nanos}");
            // Whole seconds is the millisecond form with its fraction cut off.
            assert_eq!(
                Some(ts.format_seconds().as_str()),
                ts.format_millis().get(..17),
                "{nanos}"
            );
            let Some(next) = nanos.checked_add(step) else {
                break;
            };
            nanos = next;
        }
    }

    #[test]
    fn test_timestamp_format_matches_chrono_through_leap_day() {
        // 2024-02-28T23:00:00Z to 2024-03-01T01:00:00Z in steps just under
        // 7.4 seconds, so every hour, minute and second field turns over.
        let start = 1_709_161_200_000_000_000_u64;
        let end = 1_709_254_800_000_000_000_u64;
        let mut nanos = start;
        while nanos <= end {
            let ts = ok(Timestamp::from_nanos(nanos), "instant is representable");
            let dt = ts.to_datetime();
            let seconds: ArrayString<17> = chrono_reference(dt, SECONDS_PATTERN);
            let millis: ArrayString<21> = chrono_reference(dt, MILLIS_PATTERN);
            let micros: ArrayString<24> = chrono_reference(dt, MICROS_PATTERN);
            assert_eq!(ts.format_seconds(), seconds, "{nanos}");
            assert_eq!(ts.format_millis(), millis, "{nanos}");
            assert_eq!(ts.format_micros(), micros, "{nanos}");
            // Whole seconds is the millisecond form with its fraction cut off.
            assert_eq!(
                Some(ts.format_seconds().as_str()),
                ts.format_millis().get(..17),
                "{nanos}"
            );
            let Some(next) = nanos.checked_add(7_398_765_431) else {
                break;
            };
            nanos = next;
        }
    }

    #[test]
    fn test_format_utc_timestamp_leap_second_matches_chrono() {
        // chrono represents 2016-12-31T23:59:60 as second 59 with a nanosecond
        // count of one second or more, and prints that second as 60.
        let cases = [
            (
                1_000_000_000,
                "20161231-23:59:60.000",
                "20161231-23:59:60.000000",
            ),
            (
                1_500_000_000,
                "20161231-23:59:60.500",
                "20161231-23:59:60.500000",
            ),
            (
                1_999_999_999,
                "20161231-23:59:60.999",
                "20161231-23:59:60.999999",
            ),
        ];
        for (nano, millis, micros) in cases {
            let dt = utc((2016, 12, 31), (23, 59, 59), nano);
            let ours_seconds: Option<ArrayString<17>> = format_utc_timestamp(dt);
            assert_eq!(ours_seconds, Some(chrono_reference(dt, SECONDS_PATTERN)));
            assert_eq!(
                ours_seconds.as_ref().map(ArrayString::as_str),
                Some("20161231-23:59:60")
            );
            let ours_millis: Option<ArrayString<21>> = format_utc_timestamp(dt);
            let ours_micros: Option<ArrayString<24>> = format_utc_timestamp(dt);
            let ours_nanos: Option<ArrayString<27>> = format_utc_timestamp(dt);
            assert_eq!(ours_millis, Some(chrono_reference(dt, MILLIS_PATTERN)));
            assert_eq!(ours_micros, Some(chrono_reference(dt, MICROS_PATTERN)));
            assert_eq!(ours_nanos, Some(chrono_reference(dt, NANOS_PATTERN)));
            assert_eq!(ours_millis.as_ref().map(ArrayString::as_str), Some(millis));
            assert_eq!(ours_micros.as_ref().map(ArrayString::as_str), Some(micros));
        }
    }

    #[test]
    fn test_timestamp_from_leap_second_formats_as_next_second() {
        // A Timestamp counts nanoseconds since the epoch, which has no slot
        // for a leap second: 23:59:60.5 becomes 00:00:00.5 of the next day
        // when it is converted, before any formatting happens.
        let leap = utc((2016, 12, 31), (23, 59, 59), 1_500_000_000);
        let ts = ok(Timestamp::try_from(leap), "a leap second is representable");
        let dt = ts.to_datetime();
        let seconds: ArrayString<17> = chrono_reference(dt, SECONDS_PATTERN);
        let millis: ArrayString<21> = chrono_reference(dt, MILLIS_PATTERN);
        let micros: ArrayString<24> = chrono_reference(dt, MICROS_PATTERN);
        assert_eq!(ts.format_seconds(), seconds);
        assert_eq!(ts.format_millis(), millis);
        assert_eq!(ts.format_micros(), micros);
        assert_eq!(ts.format_seconds().as_str(), "20170101-00:00:00");
        assert_eq!(ts.format_millis().as_str(), "20170101-00:00:00.500");
    }

    #[test]
    fn test_format_utc_timestamp_four_digit_year_limits_match_chrono() {
        // Outside the Timestamp range, but still four digits: zero-padded.
        let cases = [
            (utc((0, 1, 1), (0, 0, 0), 0), "00000101-00:00:00.000"),
            (utc((1, 1, 1), (0, 0, 0), 0), "00010101-00:00:00.000"),
            (
                utc((999, 12, 31), (23, 59, 59), 999_999_999),
                "09991231-23:59:59.999",
            ),
            (utc((1000, 1, 1), (0, 0, 0), 0), "10000101-00:00:00.000"),
            (
                utc((9999, 12, 31), (23, 59, 59), 999_999_999),
                "99991231-23:59:59.999",
            ),
        ];
        for (dt, expected) in cases {
            let seconds: Option<ArrayString<17>> = format_utc_timestamp(dt);
            let millis: Option<ArrayString<21>> = format_utc_timestamp(dt);
            let micros: Option<ArrayString<24>> = format_utc_timestamp(dt);
            assert_eq!(seconds, Some(chrono_reference(dt, SECONDS_PATTERN)), "{dt}");
            assert_eq!(
                seconds.as_ref().map(ArrayString::as_str),
                expected.get(..17),
                "{dt}"
            );
            assert_eq!(millis, Some(chrono_reference(dt, MILLIS_PATTERN)), "{dt}");
            assert_eq!(micros, Some(chrono_reference(dt, MICROS_PATTERN)), "{dt}");
            assert_eq!(millis.as_ref().map(ArrayString::as_str), Some(expected));
        }
    }

    #[test]
    fn test_format_utc_timestamp_year_without_four_digits_is_none() {
        // chrono prints a sign on such a year (`+10000`, `-0001`), which
        // overflows the buffer, so the reference wrote nothing at all. The
        // hand-written formatter reports it instead of truncating, and its
        // caller's fallback is the same empty buffer.
        let cases = [
            utc((10_000, 1, 1), (0, 0, 0), 0),
            utc((-1, 12, 31), (23, 59, 59), 999_999_999),
            DateTime::<Utc>::MIN_UTC,
            DateTime::<Utc>::MAX_UTC,
        ];
        for dt in cases {
            let seconds: Option<ArrayString<17>> = format_utc_timestamp(dt);
            let millis: Option<ArrayString<21>> = format_utc_timestamp(dt);
            let micros: Option<ArrayString<24>> = format_utc_timestamp(dt);
            let reference_seconds: ArrayString<17> = chrono_reference(dt, SECONDS_PATTERN);
            let reference_millis: ArrayString<21> = chrono_reference(dt, MILLIS_PATTERN);
            let reference_micros: ArrayString<24> = chrono_reference(dt, MICROS_PATTERN);
            assert_eq!(seconds, None, "{dt}");
            assert_eq!(reference_seconds.as_str(), "", "{dt}");
            assert_eq!(seconds.unwrap_or_default(), reference_seconds, "{dt}");
            assert_eq!(millis, None, "{dt}");
            assert_eq!(micros, None, "{dt}");
            assert_eq!(reference_millis.as_str(), "", "{dt}");
            assert_eq!(reference_micros.as_str(), "", "{dt}");
            assert_eq!(millis.unwrap_or_default(), reference_millis, "{dt}");
            assert_eq!(micros.unwrap_or_default(), reference_micros, "{dt}");
        }
    }

    #[test]
    fn test_format_utc_timestamp_length_of_no_utc_timestamp_form_is_none() {
        let dt = utc((2024, 2, 29), (12, 34, 56), 789_012_345);
        // Too short for whole seconds, a bare dot, and ten fractional digits.
        assert_eq!(format_utc_timestamp::<0>(dt), None);
        assert_eq!(format_utc_timestamp::<16>(dt), None);
        assert_eq!(format_utc_timestamp::<18>(dt), None);
        assert_eq!(format_utc_timestamp::<28>(dt), None);
    }

    #[test]
    fn test_format_utc_timestamp_seventeen_bytes_is_whole_seconds() {
        let dt = utc((2024, 2, 29), (12, 34, 56), 789_012_345);
        let seconds: Option<ArrayString<17>> = format_utc_timestamp(dt);
        assert_eq!(
            seconds.as_ref().map(ArrayString::as_str),
            Some("20240229-12:34:56")
        );
        // One fractional digit is the shortest fraction there is.
        let tenths: Option<ArrayString<19>> = format_utc_timestamp(dt);
        assert_eq!(
            tenths.as_ref().map(ArrayString::as_str),
            Some("20240229-12:34:56.7")
        );
    }

    #[test]
    fn test_put_digits_zero_pads_and_rejects_overflow() {
        let mut four = [0_u8; 4];
        assert_eq!(put_digits(&mut four, 7), Some(()));
        assert_eq!(&four, b"0007");
        assert_eq!(put_digits(&mut four, 9_999), Some(()));
        assert_eq!(&four, b"9999");
        assert_eq!(put_digits(&mut four, 10_000), None);

        let mut two = [0_u8; 2];
        assert_eq!(put_digits(&mut two, 0), Some(()));
        assert_eq!(&two, b"00");
        assert_eq!(put_digits(&mut two, 100), None);
        assert_eq!(put_digits(&mut [], 0), Some(()));
        assert_eq!(put_digits(&mut [], 1), None);
    }

    #[test]
    fn test_timestamp_round_trips_through_datetime() {
        let ts = ok(
            Timestamp::from_nanos(1_700_000_000_123_456_789),
            "instant is representable",
        );
        assert_eq!(Timestamp::try_from(ts.to_datetime()), Ok(ts));
    }

    #[test]
    fn test_timestamp_deserialize_out_of_range_nanos_is_rejected() {
        use serde::de::value::{Error as ValueError, MapDeserializer};

        // A payload one nanosecond past MAX_NANOS must not rebuild a Timestamp
        // that skipped `from_nanos` and would trip `to_datetime`'s bound.
        let de = MapDeserializer::new(std::iter::once((
            "nanos_since_epoch",
            Timestamp::MAX_NANOS + 1,
        )));
        let result: Result<Timestamp, ValueError> = Timestamp::deserialize(de);
        assert!(
            result.is_err(),
            "nanos past MAX_NANOS must fail to deserialize"
        );
    }

    #[test]
    fn test_timestamp_deserialize_in_range_nanos_round_trips() {
        use serde::de::value::{Error as ValueError, MapDeserializer};

        let de = MapDeserializer::new(std::iter::once((
            "nanos_since_epoch",
            1_700_000_000_123_456_789_u64,
        )));
        let result: Result<Timestamp, ValueError> = Timestamp::deserialize(de);
        let ts = ok(result, "in-range nanos deserializes");
        assert_eq!(ts.as_nanos(), 1_700_000_000_123_456_789);
    }

    #[test]
    fn test_comp_id_accepts_plain_value() {
        let id = ok(CompId::new("SENDER"), "SENDER is a valid CompId");
        assert_eq!(id.as_str(), "SENDER");
        assert_eq!(id.len(), 6);
        assert!(!id.is_empty());
    }

    #[test]
    fn test_comp_id_at_exact_capacity_is_accepted() {
        let exact = "A".repeat(COMP_ID_MAX_LEN);
        let id = ok(CompId::new(&exact), "32 bytes is exactly the bound");
        assert_eq!(id.len(), COMP_ID_MAX_LEN);
        assert_eq!(id.as_str(), exact.as_str());
    }

    #[test]
    fn test_comp_id_one_past_capacity_is_rejected() {
        let long = "A".repeat(COMP_ID_MAX_LEN + 1);
        assert_eq!(
            CompId::new(&long),
            Err(CompIdError::TooLong {
                len: COMP_ID_MAX_LEN + 1,
                max_len: COMP_ID_MAX_LEN,
            })
        );
    }

    #[test]
    fn test_comp_id_rejects_soh() {
        assert_eq!(
            CompId::new("SEND\u{1}ER"),
            Err(CompIdError::IllegalByte {
                byte: 0x01,
                position: 4,
            })
        );
    }

    #[test]
    fn test_comp_id_accepts_equals() {
        // `=` is a legal FIX String value byte: only the first `=` of a field
        // separates tag from value, and a CompID is a value, never a tag.
        let id = ok(CompId::new("SEND=ER"), "'=' is legal inside a CompId value");
        assert_eq!(id.as_str(), "SEND=ER");
    }

    #[test]
    fn test_comp_id_new_empty_is_rejected() {
        assert_eq!(CompId::new(""), Err(CompIdError::Empty));
    }

    #[test]
    fn test_comp_id_deserialize_with_soh_is_rejected() {
        // A serialized CompID is transparently its string; a hand-crafted value
        // carrying SOH must not rebuild a CompId that skipped `CompId::new`.
        let de = serde::de::value::StrDeserializer::<serde::de::value::Error>::new("SEND\u{1}ER");
        let result = CompId::deserialize(de);
        assert!(
            result.is_err(),
            "SOH-bearing CompId must fail to deserialize"
        );
    }

    #[test]
    fn test_comp_id_deserialize_valid_round_trips() {
        let de = serde::de::value::StrDeserializer::<serde::de::value::Error>::new("SENDER");
        let id = ok(CompId::deserialize(de), "SENDER is a valid CompId");
        assert_eq!(id.as_str(), "SENDER");
    }

    #[test]
    fn test_comp_id_rejects_non_ascii() {
        // 'ñ' is two bytes, 0xc3 0xb1; the first is reported.
        assert_eq!(
            CompId::new("SEÑOR"),
            Err(CompIdError::IllegalByte {
                byte: 0xc3,
                position: 2,
            })
        );
    }

    #[test]
    fn test_comp_id_rejects_control_bytes() {
        assert_eq!(
            CompId::new("SENDER\n"),
            Err(CompIdError::IllegalByte {
                byte: b'\n',
                position: 6,
            })
        );
    }

    #[test]
    fn test_comp_id_from_str_matches_new() {
        let parsed = ok("SENDER".parse::<CompId>(), "SENDER is a valid CompId");
        let built = ok(CompId::new("SENDER"), "SENDER is a valid CompId");
        assert_eq!(parsed, built);
        assert!("SEND\u{1}ER".parse::<CompId>().is_err());
    }

    #[test]
    fn test_side_from_char() {
        assert_eq!(Side::from_char('1'), Some(Side::Buy));
        assert_eq!(Side::from_char('2'), Some(Side::Sell));
        assert_eq!(Side::from_char('X'), None);
    }

    #[test]
    fn test_side_round_trips_every_variant() {
        const ALL: [Side; 16] = [
            Side::Buy,
            Side::Sell,
            Side::BuyMinus,
            Side::SellPlus,
            Side::SellShort,
            Side::SellShortExempt,
            Side::Undisclosed,
            Side::Cross,
            Side::CrossShort,
            Side::CrossShortExempt,
            Side::AsDefined,
            Side::Opposite,
            Side::Subscribe,
            Side::Redeem,
            Side::Lend,
            Side::Borrow,
        ];
        for side in ALL {
            assert_eq!(Side::from_char(side.as_char()), Some(side));
            let byte = u8::try_from(side.as_char());
            let byte = ok(byte, "every Side code is a single ASCII byte");
            assert_eq!(Side::try_from(byte), Ok(side));
        }
    }

    #[test]
    fn test_side_try_from_unknown_byte_is_typed_error() {
        assert_eq!(Side::try_from(b'X'), Err(InvalidSide::new(b'X')));
        let Err(err) = Side::try_from(0xff) else {
            panic!("0xff is not a Side code");
        };
        assert_eq!(err.value(), 0xff);
        assert_eq!(err.to_string(), "0xff is not a FIX Side (tag 54) code");
    }

    #[test]
    fn test_side_is_buy_sell() {
        assert!(Side::Buy.is_buy());
        assert!(!Side::Buy.is_sell());
        assert!(Side::Sell.is_sell());
        assert!(!Side::Sell.is_buy());
    }

    #[test]
    fn test_side_display() {
        assert_eq!(Side::Buy.to_string(), "1");
        assert_eq!(Side::Sell.to_string(), "2");
    }
}
