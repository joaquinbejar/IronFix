/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 14/7/26
******************************************************************************/

//! Internal helpers for building and parsing FIX frames.
//!
//! Admin messages (Logon, Heartbeat, TestRequest, Logout, ResendRequest,
//! SequenceReset, Reject) are built here as [`PendingMessage`]s — a MsgType
//! plus body fields, with no header and no sequence number yet — exactly the
//! form an application message arrives in. [`MessageFactory::encode`] stamps
//! the standard header and trailer around either.
//!
//! The split is what makes `to_admin` / `to_app` mean something: the callback
//! mutates the [`OutboundMessage`] inside a [`PendingMessage`], and that is the
//! value the encoder then reads. It is also what lets the caller encode
//! **before** spending a sequence number, so a body with no legal wire form
//! costs nothing.
//!
//! One [`Encoder`] lives for the life of the factory and is rewound with
//! [`Encoder::clear`] between messages, so its buffer is allocated once and
//! [`MessageFactory::encode`] hands back a slice of it rather than a fresh
//! owned frame.
//!
//! A resend of a **stored** message takes a different path: [`resend_frame`]
//! rebuilds a verbatim frame the store handed back, keeping its original
//! `MsgSeqNum` and stamping `PossDupFlag` (43) / `OrigSendingTime` (122). That
//! is a replay of real traffic, not a freshly numbered message, so it does not
//! go through the factory's sequence-numbering `encode`.

use crate::application::RejectReason;
use crate::outbound::{OutboundField, OutboundMessage};
use bytes::BytesMut;
use ironfix_core::error::{DecodeError, EncodeError};
use ironfix_core::field::FieldRef;
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::Timestamp;
use ironfix_core::version::FixVersion;
use ironfix_session::SessionConfig;
use ironfix_tagvalue::{Decoder, Encoder};
use std::time::Duration;

/// A configured `BeginString` the engine cannot frame conformantly.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unsupported FIX version {version}: {detail}")]
pub(crate) struct UnsupportedVersion {
    /// The configured version string.
    pub(crate) version: String,
    /// Why it cannot be framed.
    pub(crate) detail: String,
}

/// Resolves the configured version string to the [`FixVersion`] whose wire
/// representation the header stamper uses.
///
/// The version-to-wire mapping — `BeginString` (8), and the application
/// version for `DefaultApplVerID` (1137) and `ApplVerID` (1128) — belongs to
/// [`FixVersion`] in `ironfix-core`, which is the workspace's single copy of
/// it. This function only decides whether a configured string names a version
/// the engine can frame; it does not restate the table.
///
/// Two strings are refused:
///
/// - one that names no version at all, which has no `BeginString` to stamp;
/// - bare `FIXT.1.1`, which names the transport version only. A FIXT Logon
///   must carry `DefaultApplVerID` (1137), which is **required**, and the
///   application version is exactly what this string failed to state.
///   Defaulting it would put a guessed version on the wire, so the session is
///   refused instead — configure `FIX.5.0`, `FIX.5.0SP1` or `FIX.5.0SP2`.
///
/// # Errors
/// Returns [`UnsupportedVersion`] in either of those cases.
pub(crate) fn wire_version(value: &str) -> Result<FixVersion, UnsupportedVersion> {
    let version: FixVersion = value.parse().map_err(|_| UnsupportedVersion {
        version: value.to_owned(),
        detail: format!(
            "not a FIX version this engine can frame; supported values are {}",
            framable_versions()
        ),
    })?;

    if version.uses_fixt() && version.appl_ver_id().is_none() {
        return Err(UnsupportedVersion {
            version: value.to_owned(),
            detail: format!(
                "{version} names only the transport version and carries no application version \
                 for DefaultApplVerID (1137), which a FIXT Logon requires; supported values are {}",
                framable_versions()
            ),
        });
    }

    Ok(version)
}

/// Lists the versions [`wire_version`] accepts, derived from [`FixVersion`] so
/// the message cannot go stale when a version is added.
fn framable_versions() -> String {
    FixVersion::ALL
        .into_iter()
        .filter(|version| !(version.uses_fixt() && version.appl_ver_id().is_none()))
        .map(FixVersion::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

/// A mismatch between an inbound message's identity fields and the
/// configured counterparty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IdentityMismatch {
    /// The offending tag (49, 56, 50 or 57).
    pub(crate) tag: u32,
    /// The value the configuration requires.
    pub(crate) expected: String,
    /// The value the counterparty sent, empty when the tag was absent.
    pub(crate) received: String,
    /// True when the tag carried the right value but was found outside the
    /// standard header, where it does not identify the counterparty.
    pub(crate) misplaced: bool,
}

impl std::fmt::Display for IdentityMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.misplaced {
            return write!(
                f,
                "CompID problem: tag {} appears outside the standard header",
                self.tag
            );
        }
        write!(
            f,
            "CompID problem: tag {} expected '{}', received '{}'",
            self.tag, self.expected, self.received
        )
    }
}

/// Whether `tag` belongs to the FIX standard header.
///
/// The set is the standard header of FIX 4.0 through 5.0 SP2 taken together:
/// the framing fields, the routing and CompID fields, `MsgSeqNum` (34), the
/// PossDup/PossResend pair, `SendingTime` (52) and `OrigSendingTime` (122),
/// the `NoHops` group (627 and its 628/629/630 entries), and the FIXT.1.1
/// application-version fields (1128, 1129, 1156). A tag outside this set is
/// the first field of the message body.
const fn is_standard_header_tag(tag: u32) -> bool {
    matches!(
        tag,
        8 | 9
            | 34
            | 35
            | 43
            | 49
            | 50
            | 52
            | 56
            | 57
            | 90
            | 91
            | 97
            | 115
            | 116
            | 122
            | 128
            | 129
            | 142
            | 143
            | 144
            | 145
            | 212
            | 213
            | 347
            | 369
            | 627
            | 628
            | 629
            | 630
            | 1128
            | 1129
            | 1156
    )
}

/// Whether `tag` occurs in the standard header of `raw`.
///
/// The header is the leading run of standard-header tags, so the scan stops at
/// the first body field. Decoded fields keep their wire order, which is what
/// makes the distinction available here at all — nothing else in a decoded
/// message says where the header ended.
fn in_standard_header(raw: &RawMessage<'_>, tag: u32) -> bool {
    for field in raw.fields() {
        if field.tag == tag {
            return true;
        }
        if !is_standard_header_tag(field.tag) {
            return false;
        }
    }
    false
}

/// The identity every inbound message must carry, derived from the session
/// configuration with sender and target reversed.
///
/// A cross-wired connection that is never checked advances sequence state
/// against the wrong counterparty and delivers another session's traffic to
/// the application, so this is validated before anything else touches
/// session state. A mismatch is `SessionRejectReason` 9, "CompID problem"
/// (`doc/fix_operations.md`, "Session Reject Reasons").
#[derive(Debug, Clone)]
pub(crate) struct PeerIdentity {
    /// Required inbound `SenderCompID` (49) — our configured target.
    sender_comp_id: String,
    /// Required inbound `TargetCompID` (56) — our configured sender.
    target_comp_id: String,
    /// Required inbound `SenderSubID` (50), when configured.
    sender_sub_id: Option<String>,
    /// Required inbound `TargetSubID` (57), when configured.
    target_sub_id: Option<String>,
}

impl PeerIdentity {
    /// Builds the expected inbound identity from the session configuration.
    #[must_use]
    pub(crate) fn new(config: &SessionConfig) -> Self {
        Self {
            sender_comp_id: config.target_comp_id.as_str().to_string(),
            target_comp_id: config.sender_comp_id.as_str().to_string(),
            sender_sub_id: config.target_sub_id.clone(),
            target_sub_id: config.sender_sub_id.clone(),
        }
    }

    /// Checks an inbound message's identity fields.
    ///
    /// Sub IDs are only checked when configured; an unconfigured sub ID
    /// places no requirement on the counterparty.
    ///
    /// Each field must both carry the expected value **and** occur in the
    /// standard header. A CompID that appears only after the message body
    /// identifies nothing: the standard header is where the counterparty is
    /// named, and a message that omits it from there is missing a required
    /// header field however many copies it carries elsewhere. Both failures
    /// are `SessionRejectReason` 9.
    pub(crate) fn validate(&self, raw: &RawMessage<'_>) -> Result<(), IdentityMismatch> {
        check_field(raw, 49, &self.sender_comp_id)?;
        check_field(raw, 56, &self.target_comp_id)?;
        if let Some(expected) = &self.sender_sub_id {
            check_field(raw, 50, expected)?;
        }
        if let Some(expected) = &self.target_sub_id {
            check_field(raw, 57, expected)?;
        }
        Ok(())
    }
}

/// Compares one inbound identity field against its required value, and
/// requires it to sit in the standard header.
///
/// The value is compared first so a cross-wired CompID keeps reporting the
/// value it sent rather than its position.
fn check_field(raw: &RawMessage<'_>, tag: u32, expected: &str) -> Result<(), IdentityMismatch> {
    let received = raw.get_field_str(tag).unwrap_or_default();
    if received != expected {
        return Err(IdentityMismatch {
            tag,
            expected: expected.to_string(),
            received: received.to_string(),
            misplaced: false,
        });
    }
    if !in_standard_header(raw, tag) {
        return Err(IdentityMismatch {
            tag,
            expected: expected.to_string(),
            received: received.to_string(),
            misplaced: true,
        });
    }
    Ok(())
}

/// Why an inbound `SendingTime` (52) failed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SendingTimeProblem {
    /// The field is absent. It is required in every standard header.
    Missing,
    /// The field is present but is not a FIX `UTCTimestamp`.
    Malformed {
        /// The offending value, truncated for the log and the Reject text.
        value: String,
    },
    /// The field parses but lies outside the configured tolerance.
    Skewed {
        /// Absolute difference from the local clock, in milliseconds.
        skew_millis: u64,
        /// The configured tolerance, in milliseconds.
        tolerance_millis: u64,
    },
}

impl SendingTimeProblem {
    /// The session-level Reject this problem produces.
    ///
    /// Reason 10 is "SendingTime accuracy problem"; a missing required field
    /// is reason 1 and an unparseable one is reason 6, "incorrect data
    /// format" (`doc/fix_operations.md`, "Session Reject Reasons").
    #[must_use]
    pub(crate) fn reject_reason(&self) -> RejectReason {
        let code = match self {
            Self::Missing => 1,
            Self::Malformed { .. } => 6,
            Self::Skewed { .. } => 10,
        };
        RejectReason::new(code, self.to_string()).with_ref_tag(52)
    }
}

impl std::fmt::Display for SendingTimeProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "SendingTime (52) is missing"),
            Self::Malformed { value } => {
                write!(f, "SendingTime (52) '{value}' is not a UTC timestamp")
            }
            Self::Skewed {
                skew_millis,
                tolerance_millis,
            } => write!(
                f,
                "SendingTime (52) differs from the local clock by {skew_millis}ms, \
                 outside the {tolerance_millis}ms tolerance"
            ),
        }
    }
}

/// Longest `SendingTime` value echoed back in a Reject or a log line.
///
/// The value is counterparty-controlled and lands in `Text` (58) on the wire,
/// so it is bounded. A legal `UTCTimestamp` is at most 27 characters.
const MAX_ECHOED_SENDING_TIME: usize = 32;

/// Checks inbound `SendingTime` (52) against the local clock.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SendingTimeGuard {
    /// Configured tolerance. `Duration::ZERO` — and only that — disables the
    /// check; any nonzero value, including a sub-millisecond one, leaves it on.
    tolerance: Duration,
}

impl SendingTimeGuard {
    /// Builds the guard from the session configuration.
    #[must_use]
    pub(crate) const fn new(config: &SessionConfig) -> Self {
        Self {
            tolerance: config.sending_time_tolerance,
        }
    }

    /// Whether the check is switched off.
    ///
    /// Only an exactly-zero tolerance disables it. The duration is compared as
    /// a duration rather than flattened to whole milliseconds first, so a
    /// sub-millisecond tolerance — which floors to zero milliseconds — cannot
    /// masquerade as "disabled" and silently switch the whole check off, the
    /// opposite of what the operator asked for.
    #[must_use]
    pub(crate) const fn is_disabled(&self) -> bool {
        self.tolerance.is_zero()
    }

    /// Validates the `SendingTime` (52) of an inbound message.
    ///
    /// A zero tolerance disables the check entirely, including the presence
    /// and format checks: the knob governs `SendingTime` validation as a
    /// whole, so an operator who has switched it off for a peer with a known
    /// clock problem does not get half of it back.
    ///
    /// Tag 52 must sit in the standard header: a copy appearing only after the
    /// body opens names no sending time, exactly as a misplaced CompID names no
    /// counterparty, so it is treated as absent. The binding spec assigns no
    /// positional reject reason for 52 (reason 9 is CompID-only), so this is
    /// inbound-acceptance hardening rather than a spec-mandated reject.
    ///
    /// # Errors
    /// Returns [`SendingTimeProblem::Missing`] when tag 52 is absent from the
    /// standard header, [`SendingTimeProblem::Malformed`] when it is present but
    /// is not a UTF-8 `UTCTimestamp`, and [`SendingTimeProblem::Skewed`] when it
    /// parses but lies further from the local clock than the configured
    /// tolerance, in either direction.
    pub(crate) fn validate(&self, raw: &RawMessage<'_>) -> Result<(), SendingTimeProblem> {
        if self.is_disabled() {
            return Ok(());
        }
        // Present AND in the standard header, in that order: the header copy is
        // the one that counts, so a body-only 52 is as good as missing.
        let Some(field) = raw.get_field(52).filter(|_| in_standard_header(raw, 52)) else {
            return Err(SendingTimeProblem::Missing);
        };
        // A present-but-unreadable value is malformed (reason 6), not missing
        // (reason 1). Invalid UTF-8 fails `as_str`, so it is folded into the
        // same malformed path instead of being misreported as absent, per
        // `doc/fix_operations.md`, "Session Reject Reasons".
        let Ok(value) = field.as_str() else {
            return Err(SendingTimeProblem::Malformed {
                value: String::from_utf8_lossy(field.value)
                    .chars()
                    .take(MAX_ECHOED_SENDING_TIME)
                    .collect(),
            });
        };
        let Some(sent_millis) = parse_utc_timestamp_millis(value) else {
            return Err(SendingTimeProblem::Malformed {
                value: value.chars().take(MAX_ECHOED_SENDING_TIME).collect(),
            });
        };

        let skew_millis = Timestamp::now().as_millis().abs_diff(sent_millis);
        // Compared as a duration so the tolerance is never truncated to whole
        // milliseconds: a sub-millisecond tolerance stays meaningful.
        if Duration::from_millis(skew_millis) > self.tolerance {
            return Err(SendingTimeProblem::Skewed {
                skew_millis,
                tolerance_millis: u64::try_from(self.tolerance.as_millis()).unwrap_or(u64::MAX),
            });
        }
        Ok(())
    }
}

/// Parses a FIX `UTCTimestamp` into milliseconds since the Unix epoch.
///
/// Accepts `YYYYMMDD-HH:MM:SS` with an optional fractional part of one to nine
/// digits, which covers every precision FIX 4.0 through 5.0 SP2 puts on the
/// wire. Digits below the millisecond are truncated; the tolerance this feeds
/// is measured in seconds.
///
/// Returns `None` for anything else, including a well-shaped string naming a
/// date that does not exist and any year before 1970. There is no
/// representable instant for those, and inventing one would let a malformed
/// value pass the accuracy check.
fn parse_utc_timestamp_millis(value: &str) -> Option<u64> {
    let bytes = value.as_bytes();
    // "YYYYMMDD-HH:MM:SS" — the fractional part is optional.
    if bytes.len() < 17 || bytes.get(8) != Some(&b'-') {
        return None;
    }
    if bytes.get(11) != Some(&b':') || bytes.get(14) != Some(&b':') {
        return None;
    }

    let year = parse_digits(bytes.get(0..4)?)?;
    let month = parse_digits(bytes.get(4..6)?)?;
    let day = parse_digits(bytes.get(6..8)?)?;
    let hour = parse_digits(bytes.get(9..11)?)?;
    let minute = parse_digits(bytes.get(12..14)?)?;
    // 60 is a leap second, which FIX permits.
    let second = parse_digits(bytes.get(15..17)?)?;

    let fraction_millis = match bytes.get(17) {
        None => 0,
        Some(&b'.') => parse_fraction_millis(bytes.get(18..)?)?,
        Some(_) => return None,
    };

    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)?
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }

    let days = days_from_civil(year, month, day)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(hour.checked_mul(3_600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)?;
    seconds.checked_mul(1_000)?.checked_add(fraction_millis)
}

/// Parses a run of ASCII digits into an integer.
fn parse_digits(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut value: u64 = 0;
    for byte in bytes {
        value = value.checked_mul(10)?.checked_add(u64::from(byte - b'0'))?;
    }
    Some(value)
}

/// Parses the fractional-second digits of a `UTCTimestamp` into milliseconds,
/// truncating anything below a millisecond.
fn parse_fraction_millis(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 9 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut millis: u64 = 0;
    for index in 0..3 {
        let digit = bytes.get(index).map_or(0, |byte| u64::from(byte - b'0'));
        millis = millis * 10 + digit;
    }
    Some(millis)
}

/// Days in `month` of `year`, Gregorian.
fn days_in_month(year: u64, month: u64) -> Option<u64> {
    const LENGTHS: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    if month == 2 && leap {
        return Some(29);
    }
    let index = usize::try_from(month.checked_sub(1)?).ok()?;
    LENGTHS.get(index).copied()
}

/// Days from `1970-01-01` to the given Gregorian date.
///
/// Hinnant's `days_from_civil`, restricted to dates at or after the epoch so
/// every intermediate stays non-negative. The caller has already range-checked
/// the components.
fn days_from_civil(year: u64, month: u64, day: u64) -> Option<u64> {
    let shifted = if month <= 2 {
        year.checked_sub(1)?
    } else {
        year
    };
    let era = shifted / 400;
    let year_of_era = shifted - era * 400;
    let shifted_month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    (era * 146_097 + day_of_era).checked_sub(719_468)
}

/// Decodes a framed FIX message.
///
/// Checksum validation is skipped: the transport codec has already
/// validated the frame when configured to do so.
pub(crate) fn decode_frame(frame: &[u8]) -> Result<RawMessage<'_>, DecodeError> {
    let mut decoder = Decoder::new(frame).with_checksum_validation(false);
    decoder.decode()
}

/// Why a stored message could not be rebuilt as a resend.
///
/// Every variant means the same thing to the reactor — this particular message
/// cannot be replayed and its sequence number must be gap-filled instead — but
/// they are kept apart so the log line says which defect was hit.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ResendError {
    /// The stored frame does not decode.
    #[error("stored frame does not decode: {0}")]
    Decode(#[from] DecodeError),

    /// The rebuilt frame has no legal wire form.
    #[error("resend frame cannot be encoded: {0}")]
    Encode(#[from] EncodeError),

    /// The stored frame carries no `SendingTime` (52).
    ///
    /// FIX requires `OrigSendingTime` (122) on a message carrying
    /// `PossDupFlag` (43) = Y. On the first resend that original time is the
    /// frame's own 52 (a resend-of-a-resend keeps it in its own 122 instead —
    /// see [`resend_frame`]). With no 52 recorded there is no header position to
    /// re-stamp and nothing truthful to put in 122, and inventing one would
    /// misreport when the message was first sent.
    #[error("stored frame carries no SendingTime (52) to copy into OrigSendingTime (122)")]
    MissingSendingTime,
}

/// Rebuilds a stored frame as a resend of itself.
///
/// The message keeps its original `MsgSeqNum` (34) — a resend re-occupies the
/// number it was first sent under and allocates nothing — and gains
/// `PossDupFlag` (43) = Y with `OrigSendingTime` (122) set to when the message
/// was *first* sent, while 52 is restamped with the time of *this* transmission
/// (`doc/fix_operations.md`, "Resend Request", items 2 and 4). Both are written
/// in their standard-header positions: 43 immediately before 52, 122 immediately
/// after it.
///
/// On a plain resend the first-sent time is the frame's own `SendingTime` (52).
/// On a **resend of a resend** the frame already carries that original in its
/// own 122 — its 52 by then is only the prior transmission's time — so an
/// existing 122 is preferred and copied through unchanged. Overwriting it with
/// 52 would silently move `OrigSendingTime` forward to the last replay.
///
/// Every other field is copied through verbatim in its original order, so the
/// business content of the replayed message is byte-identical to what was
/// sent. `BodyLength` (9) and `CheckSum` (10) are restamped by the encoder,
/// because both change with the two inserted fields.
///
/// # Errors
/// Returns [`ResendError`] if the stored frame does not decode, carries no
/// `SendingTime` (52), or cannot be re-encoded. The caller must gap-fill the
/// sequence number instead of skipping it.
pub(crate) fn resend_frame(stored: &[u8]) -> Result<BytesMut, ResendError> {
    let raw = decode_frame(stored)?;
    let begin_string = raw.begin_string()?;
    // 52 is both the emission trigger below and the fallback source for 122, so
    // its absence is the terminal error: our own stored frames always carry it.
    let sending_time_52 = raw
        .get_field_str(52)
        .ok_or(ResendError::MissingSendingTime)?;
    // Prefer an existing OrigSendingTime (122): on a resend-of-a-resend it holds
    // the *first* transmission's time, whereas 52 by then is the prior replay's.
    // Falling back to 52 covers the first resend, where no 122 is present yet.
    let orig_sending_time = raw.get_field_str(122).unwrap_or(sending_time_52);
    let sending_time = Timestamp::now().format_millis();

    // The rebuilt frame is the original plus 43 and 122; the extra headroom
    // keeps the encoder from reallocating while it copies the body across.
    let mut encoder = Encoder::with_capacity(begin_string, stored.len() + RESEND_HEADROOM);

    // Collected so a LENGTH field can look ahead to its DATA field. This is
    // the resend path, not the hot path: one allocation per replayed message
    // is the right trade for handling every spec-defined field shape.
    let fields: Vec<&FieldRef<'_>> = raw.fields().collect();
    let mut index = 0;
    while let Some(field) = fields.get(index) {
        index += 1;
        match field.tag {
            // BeginString and BodyLength are stamped by `finish`.
            8 | 9 => {}
            // Re-emitted below, in their standard-header positions. A frame
            // already carrying them is being replayed a second time.
            43 | 122 => {}
            52 => {
                encoder.try_put_raw(43, b"Y")?;
                encoder.try_put_raw(52, sending_time.as_str().as_bytes())?;
                encoder.try_put_raw(122, orig_sending_time.as_bytes())?;
            }
            tag => {
                if let Err(err) = encoder.try_put_raw(tag, field.value) {
                    // The encoder refuses a LENGTH or DATA tag on its own,
                    // because it derives the declared count from the payload
                    // so the two cannot disagree. Pair it with the field that
                    // follows and write both together.
                    let paired = fields.get(index).is_some_and(|data| {
                        encoder.try_put_data(tag, data.tag, data.value).is_ok()
                    });
                    if !paired {
                        return Err(err.into());
                    }
                    index += 1;
                }
            }
        }
    }

    Ok(into_frame(&mut encoder)?)
}

/// Extra bytes reserved for the `PossDupFlag` (43) and `OrigSendingTime` (122)
/// a resend inserts, plus the framing fields the encoder restamps.
const RESEND_HEADROOM: usize = 64;

/// Stamps the frame and moves it into a buffer the transport owns.
///
/// Used by [`resend_frame`], which builds a fresh encoder per replayed message
/// rather than sharing the factory's reused one.
///
/// # Errors
/// Returns the [`EncodeError`] the encoder recorded — a field value that
/// cannot be represented on the wire, such as a `Text` (58) carrying the SOH
/// delimiter. A frame is never produced from a rejected value.
fn into_frame(encoder: &mut Encoder) -> Result<BytesMut, EncodeError> {
    let mut frame = BytesMut::new();
    encoder.finish_into(&mut frame)?;
    Ok(frame)
}

/// A message built but not yet framed: body fields, plus the one header
/// property that is not derivable from the MsgType.
///
/// This is what the `to_admin` / `to_app` callbacks mutate and what
/// [`MessageFactory::encode`] reads, so the two cannot disagree about what
/// goes on the wire.
#[derive(Debug, Clone)]
pub(crate) struct PendingMessage {
    /// MsgType and body fields.
    message: OutboundMessage,
    /// Whether the header carries `PossDupFlag` (43) and `OrigSendingTime`
    /// (122). Only a SequenceReset-GapFill answering a ResendRequest sets it.
    poss_dup: bool,
}

impl PendingMessage {
    /// Wraps a message that is not a possible duplicate.
    #[must_use]
    fn plain(message: OutboundMessage) -> Self {
        Self {
            message,
            poss_dup: false,
        }
    }

    /// Wraps an application message handed in by a consumer.
    #[must_use]
    pub(crate) fn application(message: OutboundMessage) -> Self {
        Self::plain(message)
    }

    /// Returns the message type.
    #[must_use]
    pub(crate) fn msg_type(&self) -> &MsgType {
        self.message.msg_type()
    }

    /// Returns the message body.
    #[must_use]
    pub(crate) fn message(&self) -> &OutboundMessage {
        &self.message
    }

    /// Returns the message body for the `to_admin` / `to_app` callbacks.
    #[must_use]
    pub(crate) fn message_mut(&mut self) -> &mut OutboundMessage {
        &mut self.message
    }
}

/// Builds outbound messages and frames them with the session header stamped.
#[derive(Debug)]
pub(crate) struct MessageFactory {
    version: FixVersion,
    sender_comp_id: String,
    target_comp_id: String,
    sender_sub_id: Option<String>,
    target_sub_id: Option<String>,
    sender_location_id: Option<String>,
    target_location_id: Option<String>,
    /// Reused across every message: [`Encoder::clear`] rewinds it while
    /// retaining its buffer, so framing does not allocate per message.
    encoder: Encoder,
}

impl MessageFactory {
    /// Creates a factory from the session configuration.
    #[must_use]
    pub(crate) fn new(config: &SessionConfig, version: FixVersion) -> Self {
        Self {
            version,
            sender_comp_id: config.sender_comp_id.as_str().to_string(),
            target_comp_id: config.target_comp_id.as_str().to_string(),
            sender_sub_id: config.sender_sub_id.clone(),
            target_sub_id: config.target_sub_id.clone(),
            sender_location_id: config.sender_location_id.clone(),
            target_location_id: config.target_location_id.clone(),
            encoder: Encoder::new(version.begin_string()),
        }
    }

    /// Frames `pending` under `seq` and returns the finished frame, which
    /// borrows the factory's own buffer until the next call.
    ///
    /// The standard header is stamped first —
    /// 35, [1128], 49, 56, [50], [142], [57], [143], 34, [43], 52, [122] —
    /// then the body fields in insertion order.
    ///
    /// `SenderLocationID` (142) follows `SenderSubID` (50) and
    /// `TargetLocationID` (143) follows `TargetSubID` (57), the standard-header
    /// pairing of the routing fields. Both are stamped only when configured; an
    /// unset LocationID places nothing on the wire.
    ///
    /// `PossDupFlag` (43) is always accompanied by `OrigSendingTime` (122):
    /// FIX requires 122 on every message carrying 43=Y. Its only user here is a
    /// SequenceReset-GapFill, whose "original" messages are administrative
    /// filler that was never sent, so there is no recorded sending time to copy
    /// and 122 takes the same value as `SendingTime` (52) — the FIX handling
    /// for an unavailable OrigSendingTime. A genuine replay of a stored message
    /// goes through [`resend_frame`], which copies the real original 52 into
    /// 122.
    ///
    /// `ApplVerID` (1128) is stamped immediately after MsgType, its position in
    /// the FIXT.1.1 standard header, and only for application messages;
    /// session-level messages are versioned by the FIXT.1.1 BeginString itself.
    ///
    /// # Errors
    /// Returns the [`EncodeError`] the encoder recorded — a field value with no
    /// on-the-wire form, such as a `Text` (58) carrying the SOH delimiter or an
    /// empty `TestReqID` (112) echoed back from a peer. A frame is never
    /// produced from a rejected value, and the caller has not yet spent a
    /// sequence number on it.
    pub(crate) fn encode(
        &mut self,
        seq: u64,
        pending: &PendingMessage,
    ) -> Result<&[u8], EncodeError> {
        let poss_dup = pending.poss_dup;
        let message = &pending.message;
        // Session-level messages are versioned by the BeginString; only
        // application messages carry ApplVerID.
        let appl_ver_id = if message.msg_type().is_admin() {
            None
        } else {
            self.version.appl_ver_id()
        };

        self.encoder.clear();
        self.encoder.put_str(35, message.msg_type().as_str());
        if let Some(appl_ver_id) = appl_ver_id {
            self.encoder.put_str(1128, appl_ver_id);
        }
        self.encoder.put_str(49, &self.sender_comp_id);
        self.encoder.put_str(56, &self.target_comp_id);
        if let Some(sub) = &self.sender_sub_id {
            self.encoder.put_str(50, sub);
        }
        if let Some(location) = &self.sender_location_id {
            self.encoder.put_str(142, location);
        }
        if let Some(sub) = &self.target_sub_id {
            self.encoder.put_str(57, sub);
        }
        if let Some(location) = &self.target_location_id {
            self.encoder.put_str(143, location);
        }
        self.encoder.put_uint(34, seq);
        if poss_dup {
            self.encoder.put_bool(43, true);
        }
        let sending_time = Timestamp::now().format_millis();
        self.encoder.put_str(52, sending_time.as_str());
        if poss_dup {
            self.encoder.put_str(122, sending_time.as_str());
        }

        for field in message.fields() {
            match field {
                OutboundField::Raw { tag, value } => self.encoder.put_raw(*tag, value),
                OutboundField::Data {
                    length_tag,
                    data_tag,
                    value,
                } => self.encoder.put_data(*length_tag, *data_tag, value),
            }
        }
        self.encoder.finish()
    }

    /// Builds a Logon (35=A) with EncryptMethod=0, HeartBtInt and, for a
    /// FIXT.1.1 session, DefaultApplVerID (1137).
    #[must_use]
    pub(crate) fn logon(&self, heartbeat_secs: u64, reset_seq: bool) -> PendingMessage {
        let mut message = OutboundMessage::new(MsgType::Logon);
        message.push_uint(98, 0).push_uint(108, heartbeat_secs);
        if reset_seq {
            message.push_bool(141, true);
        }
        if let Some(appl_ver_id) = self.version.appl_ver_id() {
            message.push_str(1137, appl_ver_id);
        }
        PendingMessage::plain(message)
    }

    /// Builds a Heartbeat (35=0), echoing TestReqID (112) when replying to
    /// a TestRequest.
    #[must_use]
    pub(crate) fn heartbeat(&self, test_req_id: Option<&str>) -> PendingMessage {
        let mut message = OutboundMessage::new(MsgType::Heartbeat);
        if let Some(id) = test_req_id {
            message.push_str(112, id);
        }
        PendingMessage::plain(message)
    }

    /// Builds a TestRequest (35=1) with TestReqID (112).
    #[must_use]
    pub(crate) fn test_request(&self, test_req_id: &str) -> PendingMessage {
        let mut message = OutboundMessage::new(MsgType::TestRequest);
        message.push_str(112, test_req_id);
        PendingMessage::plain(message)
    }

    /// Builds a Logout (35=5) with optional Text (58).
    ///
    /// An empty text is dropped rather than written: `58=` has no legal wire
    /// form, and losing the reason is better than losing the Logout.
    #[must_use]
    pub(crate) fn logout(&self, text: Option<&str>) -> PendingMessage {
        let mut message = OutboundMessage::new(MsgType::Logout);
        if let Some(text) = text.filter(|text| !text.is_empty()) {
            message.push_str(58, text);
        }
        PendingMessage::plain(message)
    }

    /// Builds a ResendRequest (35=2) for `begin_seq..end_seq`
    /// (`end_seq` = 0 means "up to infinity").
    #[must_use]
    pub(crate) fn resend_request(&self, begin_seq: u64, end_seq: u64) -> PendingMessage {
        let mut message = OutboundMessage::new(MsgType::ResendRequest);
        message.push_uint(7, begin_seq).push_uint(16, end_seq);
        PendingMessage::plain(message)
    }

    /// Builds a SequenceReset-GapFill (35=4, 123=Y) that answers a
    /// ResendRequest by jumping the counterparty's expectation to `new_seq`.
    /// Carries PossDupFlag (43=Y) and OrigSendingTime (122); the caller
    /// encodes it under the gap's begin sequence.
    #[must_use]
    pub(crate) fn sequence_reset_gap_fill(&self, new_seq: u64) -> PendingMessage {
        let mut message = OutboundMessage::new(MsgType::SequenceReset);
        message.push_bool(123, true).push_uint(36, new_seq);
        PendingMessage {
            message,
            poss_dup: true,
        }
    }

    /// Builds a session-level Reject (35=3).
    #[must_use]
    pub(crate) fn session_reject(
        &self,
        ref_seq: u64,
        ref_msg_type: &str,
        reason: &RejectReason,
    ) -> PendingMessage {
        let mut message = OutboundMessage::new(MsgType::Reject);
        message.push_uint(45, ref_seq);
        if let Some(ref_tag) = reason.ref_tag {
            message.push_uint(371, u64::from(ref_tag));
        }
        message
            .push_str(372, ref_msg_type)
            .push_uint(373, u64::from(reason.code));
        if !reason.text.is_empty() {
            message.push_str(58, &reason.text);
        }
        PendingMessage::plain(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironfix_core::message::MsgType;
    use ironfix_core::types::CompId;
    use std::time::Duration;

    fn config_for(begin_string: &str) -> SessionConfig {
        let Ok(sender) = CompId::new("CLIENT") else {
            unreachable!("CLIENT is a valid CompId")
        };
        let Ok(target) = CompId::new("VENUE") else {
            unreachable!("VENUE is a valid CompId")
        };
        SessionConfig::new(sender, target, begin_string)
    }

    fn factory_for(begin_string: &str) -> MessageFactory {
        let config = config_for(begin_string);
        match wire_version(&config.begin_string) {
            Ok(version) => MessageFactory::new(&config, version),
            Err(err) => panic!("test fixture uses an unsupported version: {err}"),
        }
    }

    fn factory() -> MessageFactory {
        factory_for("FIX.4.4")
    }

    fn decode(frame: &[u8]) -> RawMessage<'_> {
        match decode_frame(frame) {
            Ok(raw) => raw,
            Err(err) => unreachable!("factory frame must decode: {err}"),
        }
    }

    /// Frames `pending` under `seq`, failing the test with the encoder's
    /// rejection.
    #[track_caller]
    fn framed(factory: &mut MessageFactory, seq: u64, pending: &PendingMessage) -> Vec<u8> {
        match factory.encode(seq, pending) {
            Ok(frame) => frame.to_vec(),
            Err(err) => panic!("factory frame must encode: {err}"),
        }
    }

    /// Unwraps a hand-built frame, failing the test with the encoder's
    /// rejection.
    #[track_caller]
    fn built(frame: Result<BytesMut, EncodeError>) -> BytesMut {
        match frame {
            Ok(frame) => frame,
            Err(err) => panic!("fixture frame must encode: {err}"),
        }
    }

    /// Fails the test with context instead of `.unwrap()` / `.expect()`.
    #[track_caller]
    fn some<T>(value: Option<T>, what: &str) -> T {
        match value {
            Some(value) => value,
            None => panic!("{what}"),
        }
    }

    /// Reads a field out of a finished frame as an owned `String`.
    fn field_of(frame: &[u8], tag: u32) -> Option<String> {
        decode_frame(frame)
            .ok()
            .and_then(|raw| raw.get_field_str(tag).map(str::to_string))
    }

    #[test]
    fn test_logon_frame_roundtrip() {
        let mut factory = factory();
        let logon = factory.logon(30, true);
        let frame = framed(&mut factory, 1, &logon);
        let raw = decode(&frame);
        assert_eq!(raw.msg_type(), &MsgType::Logon);
        assert_eq!(raw.get_field_str(49), Some("CLIENT"));
        assert_eq!(raw.get_field_str(56), Some("VENUE"));
        assert_eq!(raw.get_field_str(34), Some("1"));
        assert_eq!(raw.get_field_str(98), Some("0"));
        assert_eq!(raw.get_field_str(108), Some("30"));
        assert_eq!(raw.get_field_str(141), Some("Y"));
        // Pre-5.0 session: no application version fields.
        assert_eq!(raw.get_field_str(1137), None);
    }

    #[test]
    fn test_gap_fill_frame_carries_orig_sending_time() {
        let mut factory = factory();
        let gap_fill = factory.sequence_reset_gap_fill(10);
        let frame = framed(&mut factory, 3, &gap_fill);
        let raw = decode(&frame);
        assert_eq!(raw.msg_type(), &MsgType::SequenceReset);
        assert_eq!(raw.get_field_str(34), Some("3"));
        assert_eq!(raw.get_field_str(43), Some("Y"));
        assert_eq!(raw.get_field_str(123), Some("Y"));
        assert_eq!(raw.get_field_str(36), Some("10"));
        // Every frame carrying PossDupFlag must carry OrigSendingTime, and
        // absent a store it equals SendingTime.
        assert_eq!(raw.get_field_str(122), raw.get_field_str(52));
        assert!(raw.get_field_str(122).is_some());
    }

    #[test]
    fn test_non_poss_dup_frame_omits_orig_sending_time() {
        let mut factory = factory();
        let heartbeat = factory.heartbeat(None);
        let frame = framed(&mut factory, 4, &heartbeat);
        let raw = decode(&frame);
        assert_eq!(raw.get_field_str(43), None);
        assert_eq!(raw.get_field_str(122), None);
    }

    #[test]
    fn test_encoder_reuse_produces_independent_frames() {
        // One encoder is reused for the life of the session; a message must
        // never carry residue of the one before it.
        let mut factory = factory();
        let logon = factory.logon(30, false);
        let first = framed(&mut factory, 1, &logon);
        let heartbeat = factory.heartbeat(Some("TEST-1"));
        let second = framed(&mut factory, 2, &heartbeat);

        assert_eq!(decode(&first).msg_type(), &MsgType::Logon);
        assert_eq!(decode(&first).get_field_str(108), Some("30"));
        let raw = decode(&second);
        assert_eq!(raw.msg_type(), &MsgType::Heartbeat);
        assert_eq!(raw.get_field_str(34), Some("2"));
        assert_eq!(raw.get_field_str(112), Some("TEST-1"));
        assert_eq!(raw.get_field_str(108), None);
    }

    #[test]
    fn test_encode_rejects_an_unframeable_body_without_a_frame() {
        // A value with no legal wire form is refused here, before the caller
        // spends a sequence number on it.
        let mut factory = factory();
        let mut logout = factory.logout(None);
        logout.message_mut().push_str(58, "bye\x0149=EVIL");
        match factory.encode(9, &logout) {
            Err(EncodeError::InvalidFieldValue { tag: 58, .. }) => {}
            other => panic!("an embedded SOH must be refused, got {other:?}"),
        }

        // And the factory still frames the next message.
        let heartbeat = factory.heartbeat(None);
        let frame = framed(&mut factory, 9, &heartbeat);
        assert_eq!(decode(&frame).msg_type(), &MsgType::Heartbeat);
    }

    #[test]
    fn test_logout_drops_an_empty_text() {
        let mut factory = factory();
        let logout = factory.logout(Some(""));
        let frame = framed(&mut factory, 1, &logout);
        let raw = decode(&frame);
        assert_eq!(raw.msg_type(), &MsgType::Logout);
        assert_eq!(raw.get_field_str(58), None);
    }

    #[test]
    fn test_application_message_frame() {
        let mut message = OutboundMessage::new(MsgType::NewOrderSingle);
        message.push_str(11, "ORDER-1").push_char(54, '1');

        let mut factory = factory();
        let pending = PendingMessage::application(message);
        let frame = framed(&mut factory, 7, &pending);
        let raw = decode(&frame);
        assert_eq!(raw.msg_type(), &MsgType::NewOrderSingle);
        assert_eq!(raw.get_field_str(34), Some("7"));
        assert_eq!(raw.get_field_str(11), Some("ORDER-1"));
        assert_eq!(raw.get_field_str(54), Some("1"));
        assert_eq!(raw.get_field_str(1128), None);
    }

    #[test]
    fn test_application_message_encodes_raw_data_as_a_counted_pair() {
        // A RawData payload carrying SOH is routed through the encoder's
        // LENGTH/DATA path, not put_raw, so the frame encodes and the payload
        // survives byte-exact instead of the message being refused.
        let payload: &[u8] = b"a\x01b=c";
        let mut message = OutboundMessage::new(MsgType::NewOrderSingle);
        message
            .push_str(11, "ORDER-1")
            .push_data(95, 96, payload.to_vec());

        let mut factory = factory();
        let pending = PendingMessage::application(message);
        let frame = framed(&mut factory, 7, &pending);
        let raw = decode(&frame);
        assert_eq!(raw.get_field_str(11), Some("ORDER-1"));
        assert_eq!(raw.get_field(95).map(|f| f.value), Some(b"5".as_slice()));
        assert_eq!(raw.get_field(96).map(|f| f.value), Some(payload));
    }

    #[test]
    fn test_header_stamps_configured_location_ids() {
        let mut config = config_for("FIX.4.4");
        config.sender_location_id = Some("LON".to_string());
        config.target_location_id = Some("NYC".to_string());
        let version = match wire_version(&config.begin_string) {
            Ok(version) => version,
            Err(err) => panic!("test fixture uses an unsupported version: {err}"),
        };
        let mut factory = MessageFactory::new(&config, version);

        let logon = factory.logon(30, false);
        let frame = framed(&mut factory, 1, &logon);
        let raw = decode(&frame);
        // SenderLocationID (142) and TargetLocationID (143) are routing fields
        // of the standard header, so a configured value is stamped onto every
        // outbound message.
        assert_eq!(raw.get_field_str(142), Some("LON"));
        assert_eq!(raw.get_field_str(143), Some("NYC"));
    }

    #[test]
    fn test_header_omits_unset_location_ids() {
        let mut factory = factory();
        let logon = factory.logon(30, false);
        let frame = framed(&mut factory, 1, &logon);
        let raw = decode(&frame);
        assert_eq!(raw.get_field_str(142), None);
        assert_eq!(raw.get_field_str(143), None);
    }

    #[test]
    fn test_wire_version_pre_fixt_passthrough() {
        assert_eq!(wire_version("FIX.4.4"), Ok(FixVersion::Fix44));
    }

    /// The mapping now lives once, in `ironfix_core::FixVersion`. This walks
    /// every version from that single list and asserts the engine frames each
    /// one exactly as the core table says — the cross-check that was
    /// impossible while the engine kept its own copy, since asserting against
    /// `ironfix-dictionary` would have taken a forbidden dependency.
    #[test]
    fn test_wire_version_matches_core_table_for_every_version() {
        for version in FixVersion::ALL {
            let resolved = wire_version(version.as_str());

            // Only a FIXT session with no application version is refused; it
            // cannot supply the required DefaultApplVerID (1137).
            if version.uses_fixt() && version.appl_ver_id().is_none() {
                match resolved {
                    Err(err) => assert_eq!(err.version, version.as_str()),
                    Ok(framable) => {
                        unreachable!("{version} must be refused, got {framable:?}")
                    }
                }
                continue;
            }

            assert_eq!(resolved, Ok(version));

            let mut factory = factory_for(version.as_str());
            let logon = factory.logon(30, false);
            let frame = framed(&mut factory, 1, &logon);
            let raw = decode(&frame);
            assert_eq!(
                raw.begin_string(),
                Ok(version.begin_string()),
                "{version} framed the wrong BeginString"
            );
            assert_eq!(
                raw.get_field_str(1137),
                version.appl_ver_id(),
                "{version} framed the wrong DefaultApplVerID"
            );
        }
    }

    #[test]
    fn test_wire_version_unknown_is_typed_error() {
        // An unsupported version must degrade to an explicit typed error, never
        // travel onto the wire as a fabricated BeginString.
        match wire_version("FIX.9.9") {
            Err(err) => assert_eq!(err.version, "FIX.9.9"),
            Ok(version) => panic!("FIX.9.9 must not be framed, got {version:?}"),
        }
    }

    #[test]
    fn test_wire_version_bare_fixt_is_rejected_for_missing_appl_ver_id() {
        // FIXT.1.1 names only the transport version. Its Logon requires
        // DefaultApplVerID (1137) and nothing here can supply it, so the
        // session is refused rather than sent without a required field.
        match wire_version("FIXT.1.1") {
            Err(err) => {
                assert_eq!(err.version, "FIXT.1.1");
                assert!(
                    err.detail.contains("1137"),
                    "the reason should name the missing field, got {}",
                    err.detail
                );
            }
            Ok(version) => panic!("bare FIXT.1.1 must be refused, got {version:?}"),
        }
    }

    #[test]
    fn test_wire_version_fix50_maps_to_fixt() {
        for (configured, appl_ver_id) in
            [("FIX.5.0", "7"), ("FIX.5.0SP1", "8"), ("FIX.5.0SP2", "9")]
        {
            match wire_version(configured) {
                Ok(version) => {
                    assert_eq!(version.begin_string(), "FIXT.1.1");
                    assert_eq!(version.appl_ver_id(), Some(appl_ver_id));
                }
                Err(err) => unreachable!("{configured} must be framable: {err}"),
            }
        }
    }

    #[test]
    fn test_fix50sp2_logon_carries_fixt_begin_string_and_default_appl_ver_id() {
        let mut factory = factory_for("FIX.5.0SP2");
        let logon = factory.logon(30, false);
        let frame = framed(&mut factory, 1, &logon);
        let raw = decode(&frame);
        assert_eq!(raw.begin_string(), Ok("FIXT.1.1"));
        assert_eq!(raw.get_field_str(1137), Some("9"));
    }

    #[test]
    fn test_fix50sp2_application_message_carries_appl_ver_id() {
        let mut message = OutboundMessage::new(MsgType::NewOrderSingle);
        message.push_str(11, "ORDER-1");

        let mut factory = factory_for("FIX.5.0SP2");
        let pending = PendingMessage::application(message);
        let frame = framed(&mut factory, 2, &pending);
        let raw = decode(&frame);
        assert_eq!(raw.begin_string(), Ok("FIXT.1.1"));
        assert_eq!(raw.get_field_str(1128), Some("9"));
    }

    #[test]
    fn test_resend_frame_preserves_body_and_stamps_poss_dup() {
        let mut message = OutboundMessage::new(MsgType::NewOrderSingle);
        message.push_str(11, "ORDER-1").push_char(54, '1');
        let mut factory = factory();
        let pending = PendingMessage::application(message);
        let original = framed(&mut factory, 7, &pending);
        let original_sending_time = some(
            field_of(&original, 52),
            "the original must carry SendingTime",
        );

        let resent = match resend_frame(&original) {
            Ok(frame) => frame,
            Err(err) => panic!("a factory frame must rebuild as a resend: {err}"),
        };
        let raw = decode(&resent);

        // Same message, same number: a resend re-occupies the sequence number
        // it was first sent under.
        assert_eq!(raw.msg_type(), &MsgType::NewOrderSingle);
        assert_eq!(raw.get_field_str(34), Some("7"));
        assert_eq!(raw.get_field_str(11), Some("ORDER-1"));
        assert_eq!(raw.get_field_str(54), Some("1"));
        assert_eq!(raw.get_field_str(49), Some("CLIENT"));
        assert_eq!(raw.get_field_str(56), Some("VENUE"));

        // The whole point: 122 is the *original* sending time, not a fresh one.
        assert_eq!(raw.get_field_str(43), Some("Y"));
        assert_eq!(raw.get_field_str(122), Some(original_sending_time.as_str()));
    }

    #[test]
    fn test_resend_frame_of_a_resend_preserves_the_first_sending_time() {
        // The intermediate frame is built by hand so its SendingTime (52, the
        // *prior* replay) and OrigSendingTime (122, the *first* transmission)
        // are deterministically different. Chaining two `resend_frame` calls
        // would let both land in the same millisecond — SendingTime is
        // millisecond-resolution — and hide a 122 overwritten with 52.
        const FIRST_SENT: &str = "20260721-10:00:00.000";
        const PRIOR_REPLAY: &str = "20260721-11:30:45.500";

        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "D");
        encoder.put_str(49, "CLIENT");
        encoder.put_str(56, "VENUE");
        encoder.put_uint(34, 3);
        encoder.put_bool(43, true);
        encoder.put_str(52, PRIOR_REPLAY);
        encoder.put_str(122, FIRST_SENT);
        encoder.put_str(11, "ORDER-1");
        let once = built(into_frame(&mut encoder));

        let twice = match resend_frame(&once) {
            Ok(frame) => frame,
            Err(err) => panic!("second resend must build: {err}"),
        };
        let raw = decode(&twice);

        // The prior 43/122 are re-emitted once in their header positions, never
        // duplicated.
        assert_eq!(raw.fields().filter(|field| field.tag == 43).count(), 1);
        assert_eq!(raw.fields().filter(|field| field.tag == 122).count(), 1);
        // The whole point: 122 still names the *first* transmission, not the
        // prior replay's SendingTime.
        assert_eq!(raw.get_field_str(122), Some(FIRST_SENT));
        assert_ne!(raw.get_field_str(122), Some(PRIOR_REPLAY));
        // 52 is this transmission's time, distinct from both, and the body and
        // number survive.
        assert_eq!(raw.get_field_str(34), Some("3"));
        assert_eq!(raw.get_field_str(11), Some("ORDER-1"));
        assert_eq!(raw.get_field_str(43), Some("Y"));
    }

    #[test]
    fn test_resend_frame_without_sending_time_is_a_typed_error() {
        // Built by hand: the factory always stamps 52.
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "D");
        encoder.put_str(49, "CLIENT");
        encoder.put_str(56, "VENUE");
        encoder.put_uint(34, 4);
        let frame = built(into_frame(&mut encoder));

        match resend_frame(&frame) {
            Err(ResendError::MissingSendingTime) => {}
            Err(err) => panic!("expected MissingSendingTime, got {err}"),
            Ok(_) => panic!("a frame with no SendingTime must not be replayed"),
        }
    }

    #[test]
    fn test_resend_frame_of_undecodable_bytes_is_a_typed_error() {
        match resend_frame(b"not a fix message") {
            Err(ResendError::Decode(_)) => {}
            Err(err) => panic!("expected a decode error, got {err}"),
            Ok(_) => panic!("garbage must not rebuild into a frame"),
        }
    }

    #[test]
    fn test_resend_frame_preserves_a_length_data_pair() {
        // RawData (96) is framed by the count in RawDataLength (95), so the two
        // have to be rebuilt together or the frame is corrupt. The payload
        // carries SOH deliberately: that is what the pair exists for.
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "D");
        encoder.put_str(49, "CLIENT");
        encoder.put_str(56, "VENUE");
        encoder.put_uint(34, 9);
        encoder.put_str(52, "20260721-10:00:00.000");
        encoder.put_data(95, 96, b"opaque\x01payload");
        let original = built(into_frame(&mut encoder));

        let resent = match resend_frame(&original) {
            Ok(frame) => frame,
            Err(err) => panic!("a frame with a LENGTH/DATA pair must rebuild: {err}"),
        };
        let raw = decode(&resent);

        assert_eq!(raw.get_field_str(95), Some("14"));
        assert_eq!(
            some(raw.get_field(96), "RawData must survive the rebuild").value,
            b"opaque\x01payload"
        );
        assert_eq!(raw.get_field_str(43), Some("Y"));
        assert_eq!(raw.get_field_str(122), Some("20260721-10:00:00.000"));
    }

    #[test]
    fn test_peer_identity_accepts_reversed_comp_ids() {
        let identity = PeerIdentity::new(&config_for("FIX.4.4"));
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "0");
        encoder.put_str(49, "VENUE");
        encoder.put_str(56, "CLIENT");
        encoder.put_uint(34, 1);
        let frame = match encoder.finish() {
            Ok(frame) => frame.to_vec(),
            Err(err) => panic!("fixture frame must encode: {err}"),
        };

        assert_eq!(identity.validate(&decode(&frame)), Ok(()));
    }

    #[test]
    fn test_peer_identity_rejects_wrong_sender_comp_id() {
        let identity = PeerIdentity::new(&config_for("FIX.4.4"));
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "0");
        encoder.put_str(49, "OTHER");
        encoder.put_str(56, "CLIENT");
        encoder.put_uint(34, 1);
        let frame = match encoder.finish() {
            Ok(frame) => frame.to_vec(),
            Err(err) => panic!("fixture frame must encode: {err}"),
        };

        assert_eq!(
            identity.validate(&decode(&frame)),
            Err(IdentityMismatch {
                tag: 49,
                expected: "VENUE".to_string(),
                received: "OTHER".to_string(),
                misplaced: false,
            })
        );
    }

    #[test]
    fn test_peer_identity_rejects_missing_sub_id_when_configured() {
        let config = config_for("FIX.4.4").with_sender_sub_id("DESK");
        let identity = PeerIdentity::new(&config);
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "0");
        encoder.put_str(49, "VENUE");
        encoder.put_str(56, "CLIENT");
        encoder.put_uint(34, 1);
        let frame = match encoder.finish() {
            Ok(frame) => frame.to_vec(),
            Err(err) => panic!("fixture frame must encode: {err}"),
        };

        // Our SenderSubID is the peer's TargetSubID (57).
        assert_eq!(
            identity.validate(&decode(&frame)),
            Err(IdentityMismatch {
                tag: 57,
                expected: "DESK".to_string(),
                received: String::new(),
                misplaced: false,
            })
        );
    }

    /// Builds a frame with an explicit field order, bypassing the encoder's
    /// header conformance so the body can carry the CompIDs.
    fn frame_with_fields(fields: &[(u32, &str)]) -> Vec<u8> {
        let fields: Vec<(u32, &[u8])> = fields
            .iter()
            .map(|(tag, value)| (*tag, value.as_bytes()))
            .collect();
        frame_with_raw_fields(&fields)
    }

    /// Builds a framed message from raw field bytes, so a value can carry a
    /// sequence that is not valid UTF-8.
    fn frame_with_raw_fields(fields: &[(u32, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (tag, value) in fields {
            body.extend_from_slice(format!("{tag}=").as_bytes());
            body.extend_from_slice(value);
            body.push(0x01);
        }
        let mut frame = Vec::new();
        frame.extend_from_slice(b"8=FIX.4.4\x01");
        frame.extend_from_slice(format!("9={}\x01", body.len()).as_bytes());
        frame.extend_from_slice(&body);
        let sum: u64 = frame.iter().map(|&byte| u64::from(byte)).sum();
        frame.extend_from_slice(format!("10={:03}\x01", sum % 256).as_bytes());
        frame
    }

    #[test]
    fn test_peer_identity_rejects_comp_ids_outside_the_standard_header() {
        let identity = PeerIdentity::new(&config_for("FIX.4.4"));
        // 11 (ClOrdID) opens the body; the CompIDs that follow it are not in
        // the standard header and identify nothing.
        let frame = frame_with_fields(&[
            (35, "D"),
            (34, "2"),
            (52, "20260721-10:00:00.000"),
            (11, "ORDER-1"),
            (49, "VENUE"),
            (56, "CLIENT"),
        ]);

        assert_eq!(
            identity.validate(&decode(&frame)),
            Err(IdentityMismatch {
                tag: 49,
                expected: "VENUE".to_string(),
                received: "VENUE".to_string(),
                misplaced: true,
            })
        );
    }

    #[test]
    fn test_peer_identity_accepts_comp_ids_across_the_whole_standard_header() {
        // 50/57/122 sit after MsgSeqNum in the standard header, so the run the
        // scan walks must not stop before them.
        let config = config_for("FIX.4.4")
            .with_sender_sub_id("DESK")
            .with_target_sub_id("MM");
        let identity = PeerIdentity::new(&config);
        let frame = frame_with_fields(&[
            (35, "D"),
            (49, "VENUE"),
            (56, "CLIENT"),
            (34, "2"),
            (50, "MM"),
            (57, "DESK"),
            (43, "Y"),
            (52, "20260721-10:00:00.000"),
            (122, "20260721-10:00:00.000"),
            (11, "ORDER-1"),
        ]);

        assert_eq!(identity.validate(&decode(&frame)), Ok(()));
    }

    #[test]
    fn test_parse_utc_timestamp_accepts_every_fix_precision() {
        // 1970-01-01T00:00:00Z is 0; the fractional part only adds millis.
        assert_eq!(parse_utc_timestamp_millis("19700101-00:00:00"), Some(0));
        assert_eq!(parse_utc_timestamp_millis("19700101-00:00:00.000"), Some(0));
        assert_eq!(
            parse_utc_timestamp_millis("19700101-00:00:00.123456"),
            Some(123)
        );
        assert_eq!(
            parse_utc_timestamp_millis("19700101-00:00:00.123456789"),
            Some(123)
        );
        assert_eq!(
            parse_utc_timestamp_millis("19700102-00:00:01.500"),
            Some(86_401_500)
        );
    }

    /// The parser must agree with the formatter it validates against, for
    /// dates on both sides of a leap day.
    #[test]
    fn test_parse_utc_timestamp_roundtrips_the_formatter() {
        for millis in [
            0,
            951_782_400_000,   // 2000-02-29, a leap day in a leap century
            1_078_012_800_000, // 2004-02-29
            1_769_000_000_123,
            4_102_444_800_999, // 2100-01-01, a common year divisible by 100
        ] {
            let Ok(timestamp) = Timestamp::from_millis(millis) else {
                unreachable!("{millis} is representable")
            };
            assert_eq!(
                parse_utc_timestamp_millis(timestamp.format_millis().as_str()),
                Some(millis),
                "{} did not round-trip",
                timestamp.format_millis()
            );
        }
    }

    #[test]
    fn test_parse_utc_timestamp_rejects_malformed_values() {
        for value in [
            "",
            "not-a-timestamp",
            "20260721",
            "20260721-10:00",
            "20260721 10:00:00",
            "20260721-10-00-00",
            "2026072a-10:00:00",
            "20260721-10:00:00.",
            "20260721-10:00:00.1234567890", // more than nanosecond precision
            "20260721-10:00:00x000",
            "20260231-10:00:00.000", // February has no 31st
            "20260732-10:00:00.000",
            "20261301-10:00:00.000",
            "20260721-24:00:00.000",
            "20260721-10:60:00.000",
            "20260721-10:00:61.000",
            "19690721-10:00:00.000", // before the epoch
        ] {
            assert_eq!(
                parse_utc_timestamp_millis(value),
                None,
                "{value} must not parse"
            );
        }
    }

    /// A leap second is a legal UTCTimestamp and must not be refused.
    #[test]
    fn test_parse_utc_timestamp_accepts_leap_second() {
        assert!(parse_utc_timestamp_millis("20261231-23:59:60.000").is_some());
    }

    fn guard_with(tolerance: Duration) -> SendingTimeGuard {
        SendingTimeGuard::new(&config_for("FIX.4.4").with_sending_time_tolerance(tolerance))
    }

    fn frame_sent_at(sending_time: &str) -> Vec<u8> {
        frame_with_fields(&[
            (35, "0"),
            (49, "VENUE"),
            (56, "CLIENT"),
            (34, "2"),
            (52, sending_time),
        ])
    }

    #[test]
    fn test_sending_time_guard_accepts_the_current_clock() {
        let frame = frame_sent_at(Timestamp::now().format_millis().as_str());

        assert_eq!(
            guard_with(Duration::from_secs(120)).validate(&decode(&frame)),
            Ok(())
        );
    }

    #[test]
    fn test_sending_time_guard_rejects_a_stale_timestamp_with_reason_10() {
        let frame = frame_sent_at("20200101-00:00:00.000");

        let problem = match guard_with(Duration::from_secs(120)).validate(&decode(&frame)) {
            Err(problem) => problem,
            Ok(()) => panic!("a five-year-old SendingTime must not pass"),
        };
        assert!(matches!(problem, SendingTimeProblem::Skewed { .. }));
        assert_eq!(problem.reject_reason().code, 10);
        assert_eq!(problem.reject_reason().ref_tag, Some(52));
    }

    /// The window is symmetric: a peer whose clock runs fast is as broken as
    /// one that runs slow.
    #[test]
    fn test_sending_time_guard_rejects_a_future_timestamp() {
        let frame = frame_sent_at("21000101-00:00:00.000");

        assert!(matches!(
            guard_with(Duration::from_secs(120)).validate(&decode(&frame)),
            Err(SendingTimeProblem::Skewed { .. })
        ));
    }

    #[test]
    fn test_sending_time_guard_accepts_skew_inside_the_window() {
        let Some(millis) = Timestamp::now().as_millis().checked_sub(60_000) else {
            unreachable!("the system clock is at least a minute past the epoch")
        };
        let Ok(stale) = Timestamp::from_millis(millis) else {
            unreachable!("a minute before now is representable")
        };
        let frame = frame_sent_at(stale.format_millis().as_str());

        // A minute of skew inside a two-minute window is tolerated: the check
        // is a broken-clock detector, not a latency budget.
        assert_eq!(
            guard_with(Duration::from_secs(120)).validate(&decode(&frame)),
            Ok(())
        );
    }

    #[test]
    fn test_sending_time_guard_reports_missing_and_malformed_fields() {
        let missing = frame_with_fields(&[(35, "0"), (49, "VENUE"), (56, "CLIENT"), (34, "2")]);
        let guard = guard_with(Duration::from_secs(120));
        assert_eq!(
            guard.validate(&decode(&missing)),
            Err(SendingTimeProblem::Missing)
        );
        assert_eq!(
            SendingTimeProblem::Missing.reject_reason().code,
            1,
            "a missing required header field is reason 1"
        );

        let malformed = frame_sent_at("yesterday");
        assert_eq!(
            guard.validate(&decode(&malformed)),
            Err(SendingTimeProblem::Malformed {
                value: "yesterday".to_string(),
            })
        );
        assert_eq!(
            SendingTimeProblem::Malformed {
                value: "yesterday".to_string()
            }
            .reject_reason()
            .code,
            6,
            "an unparseable timestamp is reason 6"
        );
    }

    #[test]
    fn test_sending_time_guard_zero_tolerance_disables_every_check() {
        let guard = guard_with(Duration::ZERO);
        assert!(guard.is_disabled());

        // Neither a wildly skewed value nor an absent one is reported once the
        // operator has switched the check off.
        let stale = frame_sent_at("20200101-00:00:00.000");
        assert_eq!(guard.validate(&decode(&stale)), Ok(()));
        let missing = frame_with_fields(&[(35, "0"), (49, "VENUE"), (56, "CLIENT"), (34, "2")]);
        assert_eq!(guard.validate(&decode(&missing)), Ok(()));
    }

    #[test]
    fn test_sending_time_guard_echoes_a_bounded_value() {
        let long = "9".repeat(200);
        let frame = frame_sent_at(&long);

        match guard_with(Duration::from_secs(120)).validate(&decode(&frame)) {
            Err(SendingTimeProblem::Malformed { value }) => {
                assert_eq!(value.chars().count(), MAX_ECHOED_SENDING_TIME);
            }
            other => panic!("a 200-character SendingTime must be malformed: {other:?}"),
        }
    }

    /// A tag 52 that appears only after the body opens is not in the standard
    /// header and names no sending time: it is treated as missing, mirroring the
    /// positional guard the CompID check already applies.
    #[test]
    fn test_sending_time_guard_treats_a_body_only_sending_time_as_missing() {
        // 11 (ClOrdID) opens the body; the 52 that follows it is not a header
        // field however well-formed its value is.
        let frame = frame_with_fields(&[
            (35, "D"),
            (49, "VENUE"),
            (56, "CLIENT"),
            (34, "2"),
            (11, "ORDER-1"),
            (52, "20260721-10:00:00.000"),
        ]);

        assert_eq!(
            guard_with(Duration::from_secs(120)).validate(&decode(&frame)),
            Err(SendingTimeProblem::Missing)
        );
    }

    /// A present tag 52 whose bytes are not valid UTF-8 is malformed (reason 6),
    /// not missing (reason 1): the field is there, it is just unreadable.
    #[test]
    fn test_sending_time_guard_reports_invalid_utf8_as_malformed() {
        let frame = frame_with_raw_fields(&[
            (35, b"0"),
            (49, b"VENUE"),
            (56, b"CLIENT"),
            (34, b"2"),
            (52, &[0xFF, 0xFE, 0xFD]),
        ]);

        let problem = match guard_with(Duration::from_secs(120)).validate(&decode(&frame)) {
            Err(problem) => problem,
            Ok(()) => panic!("a non-UTF-8 SendingTime must not pass"),
        };
        assert!(matches!(problem, SendingTimeProblem::Malformed { .. }));
        assert_eq!(
            problem.reject_reason().code,
            6,
            "a present but unreadable timestamp is reason 6, not the reason 1 of an absent one"
        );
    }

    /// A sub-millisecond tolerance floors to zero milliseconds, but the check
    /// stays enabled: it must still validate rather than treating the truncated
    /// value as the disabled sentinel.
    #[test]
    fn test_sending_time_guard_sub_millisecond_tolerance_stays_enabled() {
        let guard = guard_with(Duration::from_micros(500));
        assert!(!guard.is_disabled(), "a 500us tolerance is not disabled");

        // A wildly stale timestamp is still rejected under the tiny tolerance.
        let stale = frame_sent_at("20200101-00:00:00.000");
        assert!(matches!(
            guard.validate(&decode(&stale)),
            Err(SendingTimeProblem::Skewed { .. })
        ));

        // And an absent field is still reported, proving the presence check was
        // not switched off along with the skew check.
        let missing = frame_with_fields(&[(35, "0"), (49, "VENUE"), (56, "CLIENT"), (34, "2")]);
        assert_eq!(
            guard.validate(&decode(&missing)),
            Err(SendingTimeProblem::Missing)
        );
    }
}
