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
use chrono::{DateTime, Utc};
use num_derive::{FromPrimitive, ToPrimitive};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Maximum length for CompID strings in bytes.
pub const COMP_ID_MAX_LEN: usize = 32;

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
/// Timestamps in FIX are formatted as `YYYYMMDD-HH:MM:SS.sss` (milliseconds)
/// or `YYYYMMDD-HH:MM:SS.ssssss` (microseconds) or `YYYYMMDD-HH:MM:SS.sssssssss` (nanoseconds).
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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

    /// Converts a calendar instant to a timestamp, clamping an unrepresentable
    /// instant to [`Timestamp::EPOCH`].
    fn clamp_datetime(dt: DateTime<Utc>) -> Self {
        match Self::from_datetime(dt) {
            Ok(ts) => ts,
            Err(_) => Self::EPOCH,
        }
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
    #[inline]
    #[must_use]
    pub fn now() -> Self {
        Self::clamp_datetime(Utc::now())
    }

    /// Returns the current UTC timestamp, or an error if the system clock is
    /// outside the representable range.
    ///
    /// # Errors
    /// Returns [`TimestampError::InstantOutOfRange`] if the system clock reads
    /// before the Unix epoch or past [`Timestamp::MAX_NANOS`].
    #[inline]
    pub fn try_now() -> Result<Self, TimestampError> {
        Self::from_datetime(Utc::now())
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

    /// Formats the timestamp in FIX format with millisecond precision.
    ///
    /// Format: `YYYYMMDD-HH:MM:SS.sss`
    #[must_use]
    pub fn format_millis(self) -> ArrayString<21> {
        let dt = self.to_datetime();
        let mut buf = ArrayString::new();
        let _ = std::fmt::write(
            &mut buf,
            format_args!("{}", dt.format("%Y%m%d-%H:%M:%S%.3f")),
        );
        buf
    }

    /// Formats the timestamp in FIX format with microsecond precision.
    ///
    /// Format: `YYYYMMDD-HH:MM:SS.ssssss`
    #[must_use]
    pub fn format_micros(self) -> ArrayString<24> {
        let dt = self.to_datetime();
        let mut buf = ArrayString::new();
        let _ = std::fmt::write(
            &mut buf,
            format_args!("{}", dt.format("%Y%m%d-%H:%M:%S%.6f")),
        );
        buf
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_millis())
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
/// Only printable ASCII (`0x20..=0x7e`) except `=` is accepted. A CompID is
/// written verbatim into tags 49 and 56 on every outbound message, so SOH
/// would terminate the field early and `=` would open a new tag/value pair:
/// either byte lets a hostile CompID inject header fields or corrupt framing.
/// Rejecting them at construction is the chokepoint that makes such a value
/// unrepresentable rather than escaping it at every encode site.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
    /// Returns [`CompIdError::TooLong`] if `s` exceeds [`COMP_ID_MAX_LEN`]
    /// bytes, or [`CompIdError::IllegalByte`] if it contains any byte outside
    /// printable ASCII, or the `=` tag/value separator.
    pub fn new(s: &str) -> Result<Self, CompIdError> {
        if s.len() > COMP_ID_MAX_LEN {
            return Err(CompIdError::TooLong {
                len: s.len(),
                max_len: COMP_ID_MAX_LEN,
            });
        }
        for (position, &byte) in s.as_bytes().iter().enumerate() {
            let printable = byte.is_ascii_graphic() || byte == b' ';
            if !printable || byte == b'=' {
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

    /// Parses a CompID, applying the same length and charset checks as
    /// [`CompId::new`].
    ///
    /// # Errors
    /// Returns [`CompIdError::TooLong`] or [`CompIdError::IllegalByte`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
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

    #[test]
    fn test_timestamp_clamp_datetime_pre_epoch_yields_epoch() {
        let Some(dt) = DateTime::from_timestamp(-86_400, 0) else {
            panic!("1969-12-31T00:00:00Z is a valid chrono instant");
        };
        assert_eq!(Timestamp::clamp_datetime(dt), Timestamp::EPOCH);
        assert_eq!(Timestamp::EPOCH.as_nanos(), 0);
    }

    #[test]
    fn test_timestamp_clamp_datetime_in_range_is_exact() {
        let Some(dt) = DateTime::from_timestamp(1_700_000_000, 123_456_789) else {
            panic!("2023-11-14T22:13:20Z is a valid chrono instant");
        };
        assert_eq!(
            Timestamp::clamp_datetime(dt).as_nanos(),
            1_700_000_000_123_456_789
        );
    }

    #[test]
    fn test_timestamp_try_now_is_representable() {
        let now = ok(Timestamp::try_now(), "the system clock is in range");
        assert!(now.as_nanos() > 0);
    }

    #[test]
    fn test_timestamp_format_millis_at_epoch() {
        let ts = ok(Timestamp::from_millis(0), "0ms is representable");
        assert_eq!(ts.format_millis().as_str(), "19700101-00:00:00.000");
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

    #[test]
    fn test_timestamp_round_trips_through_datetime() {
        let ts = ok(
            Timestamp::from_nanos(1_700_000_000_123_456_789),
            "instant is representable",
        );
        assert_eq!(Timestamp::try_from(ts.to_datetime()), Ok(ts));
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
    fn test_comp_id_rejects_equals() {
        assert_eq!(
            CompId::new("SEND=ER"),
            Err(CompIdError::IllegalByte {
                byte: b'=',
                position: 4,
            })
        );
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
