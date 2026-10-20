/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! Inbound header acceptance: the checks every inbound frame passes before
//! the session acts on it (issue #189, ADR-0002).
//!
//! Each is a decision over a decoded [`RawMessage`] and the session's
//! configuration, with no I/O and no clock read, so every driver runs the
//! same rules:
//!
//! - [`PeerIdentity`]: the CompIDs, sub and location IDs, each in the
//!   standard header ([`IdentityMismatch`], `SessionRejectReason` 9);
//! - [`SendingTimeGuard`]: presence, format and skew of `SendingTime` (52)
//!   against the wall clock the driver passes in ([`SendingTimeProblem`]);
//! - [`ApplVersionGuard`]: `DefaultApplVerID` (1137) on a FIXT.1.1 Logon and
//!   `ApplVerID` (1128) on application messages ([`ApplVersionProblem`]);
//! - [`parse_heartbeat_interval`]: a bounded `HeartBtInt` (108)
//!   ([`HeartBtIntProblem`]);
//! - the standard-header readers ([`header_field`], [`header_seq_num`],
//!   [`in_standard_header`], [`message_field`]).
//!
//! A problem reports the `SessionRejectReason` (373) and `RefTagID` (371) of
//! the Reject it calls for; building the Reject message is the driver's.
//! Values echoed in a problem are counterparty-controlled and bounded.

use crate::config::SessionConfig;
use ironfix_core::message::RawMessage;
use ironfix_core::version::FixVersion;
use std::time::Duration;

/// A mismatch between an inbound message's identity fields and the
/// configured counterparty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityMismatch {
    /// The offending tag (49, 56, 50, 57, 142 or 143).
    pub tag: u32,
    /// The value the configuration requires.
    pub expected: String,
    /// The value the counterparty sent, empty when the tag was absent.
    pub received: String,
    /// True when the tag carried the right value but was found outside the
    /// standard header, where it does not identify the counterparty.
    pub misplaced: bool,
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
/// `OnBehalfOfSendingTime` (370), the `NoHops` group (627 and its 628/629/630 entries), and the FIXT.1.1
/// application-version fields (1128, 1129, 1156). A tag outside this set is
/// the first field of the message body.
#[must_use]
pub const fn is_standard_header_tag(tag: u32) -> bool {
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
            | 370
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
#[must_use]
pub fn in_standard_header(raw: &RawMessage<'_>, tag: u32) -> bool {
    // The boundary is checked first: the first body field ends the header,
    // whatever its tag, so a body tag is never reported as in the header
    // (as [`header_field`] reads it).
    for field in raw.fields() {
        if !is_standard_header_tag(field.tag) {
            return false;
        }
        if field.tag == tag {
            return true;
        }
    }
    false
}

/// How often a tag occurs in the part of a message a read covers: the
/// standard header for [`header_field`], the whole message for the
/// message-wide read of a body field such as `DefaultApplVerID` (1137).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldOccurrence<'a> {
    /// The part read does not carry the tag.
    Absent,
    /// The part read carries the tag once, with this raw value.
    Once(&'a [u8]),
    /// The part read carries the tag more than once (`SessionRejectReason`
    /// 13, "tag appears more than once"): no occurrence can be trusted over
    /// the others.
    Repeated,
}

/// Reads `tag` from the standard header of `raw`.
///
/// The header is the leading run of standard-header tags, as for
/// [`in_standard_header`]: a `tag` that occurs only in the body is
/// [`FieldOccurrence::Absent`], and a tag outside the standard header set is never
/// found. The whole header is scanned, so a tag repeated in it is
/// [`FieldOccurrence::Repeated`] rather than its first value. One scan, no
/// allocation, and the value is returned as raw bytes, so a caller bounding an
/// untrusted value sees every byte before deciding whether it is text at all.
#[must_use]
pub fn header_field<'a>(raw: &RawMessage<'a>, tag: u32) -> FieldOccurrence<'a> {
    let mut found = FieldOccurrence::Absent;
    for field in raw.fields() {
        if !is_standard_header_tag(field.tag) {
            break;
        }
        if field.tag == tag {
            if found != FieldOccurrence::Absent {
                return FieldOccurrence::Repeated;
            }
            found = FieldOccurrence::Once(field.value);
        }
    }
    found
}

/// Reads `MsgSeqNum` (34) from the standard header of `raw`.
///
/// A tag 34 that appears only in the message body is treated as **absent**: it
/// is not the standard-header field the session sequences against, and the same
/// positional contract the identity check enforces on 49/56 applies here.
/// Accepting a body-only 34 would let a peer smuggle a sequence number past a
/// Logon that is, in fact, missing its header `MsgSeqNum`.
///
/// Returns `None` when 34 is absent from the header or is not a valid `u64`.
#[must_use]
pub fn header_seq_num(raw: &RawMessage<'_>) -> Option<u64> {
    if !in_standard_header(raw, 34) {
        return None;
    }
    raw.get_field_str(34)
        .and_then(|value| value.parse::<u64>().ok())
}

/// Upper bound, in seconds, on a `HeartBtInt` (108) accepted from a
/// counterparty.
///
/// One day. FIX types `HeartBtInt` as an unbounded non-negative int, and
/// `108 = 0` is legal ("do not send heartbeats"), so the *lower* end is left
/// open. The upper end is not: a [`Duration`] built from a
/// counterparty-controlled value must stay finite, because the heartbeat clock
/// adds a grace period to it (`interval + grace`), and
/// `Duration::from_secs(u64::MAX) + _` overflows and panics — which, under the
/// release profile's `panic = "abort"`, takes the whole process down. A single
/// crafted Logon carrying `108 = u64::MAX` would otherwise be a remote abort. A
/// day is orders of magnitude beyond any real interval while leaving enormous
/// headroom below that overflow.
pub const MAX_HEARTBEAT_INTERVAL_SECS: u64 = 86_400;

/// Longest `HeartBtInt` (108) value echoed back in a log line or a Logout
/// `Text` (58). The field is counterparty-controlled, so it is bounded.
pub const MAX_ECHOED_HEARTBEAT: usize = 32;

/// Why an inbound `HeartBtInt` (108) was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeartBtIntProblem {
    /// The field is absent. FIX requires it on every Logon.
    Missing,
    /// The field is present but is not a non-negative integer.
    Malformed {
        /// The offending value, truncated for the log and the Logout text.
        value: String,
    },
    /// The field parses but exceeds [`MAX_HEARTBEAT_INTERVAL_SECS`].
    OutOfRange {
        /// The requested interval, in seconds.
        secs: u64,
    },
}

impl std::fmt::Display for HeartBtIntProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "HeartBtInt (108) is missing"),
            Self::Malformed { value } => {
                write!(
                    f,
                    "HeartBtInt (108) '{value}' is not a non-negative integer"
                )
            }
            Self::OutOfRange { secs } => write!(
                f,
                "HeartBtInt (108) {secs}s exceeds the {MAX_HEARTBEAT_INTERVAL_SECS}s maximum"
            ),
        }
    }
}

/// Parses and bounds the `HeartBtInt` (108) of an inbound Logon.
///
/// The value is adopted by the acceptor and drives a
/// [`HeartbeatManager`](ironfix_session::HeartbeatManager), so it is validated
/// at the handshake rather than trusted onto the heartbeat clock. `108 = 0` is
/// accepted (it is legal FIX and is not specially handled today); anything above
/// [`MAX_HEARTBEAT_INTERVAL_SECS`] is refused so a crafted value can never
/// overflow the clock's `interval + grace` arithmetic.
///
/// # Errors
/// Returns [`HeartBtIntProblem::Missing`] when tag 108 is absent,
/// [`HeartBtIntProblem::Malformed`] when it is not a non-negative integer, and
/// [`HeartBtIntProblem::OutOfRange`] when it exceeds the maximum.
pub fn parse_heartbeat_interval(raw: &RawMessage<'_>) -> Result<u64, HeartBtIntProblem> {
    let Some(value) = raw.get_field_str(108) else {
        return Err(HeartBtIntProblem::Missing);
    };
    let Ok(secs) = value.parse::<u64>() else {
        return Err(HeartBtIntProblem::Malformed {
            value: value.chars().take(MAX_ECHOED_HEARTBEAT).collect(),
        });
    };
    if secs > MAX_HEARTBEAT_INTERVAL_SECS {
        return Err(HeartBtIntProblem::OutOfRange { secs });
    }
    Ok(secs)
}

/// The identity every inbound message must carry, derived from the session
/// configuration with sender and target reversed: the CompIDs always, and the
/// sub and location IDs the session configures.
///
/// A cross-wired connection that is never checked advances sequence state
/// against the wrong counterparty and delivers another session's traffic to
/// the application, so this is validated before anything else touches
/// session state. A mismatch is `SessionRejectReason` 9, "CompID problem"
/// (`doc/fix_operations.md`, "Session Reject Reasons").
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    /// Required inbound `SenderCompID` (49) — our configured target.
    sender_comp_id: String,
    /// Required inbound `TargetCompID` (56) — our configured sender.
    target_comp_id: String,
    /// Required inbound `SenderSubID` (50), when configured.
    sender_sub_id: Option<String>,
    /// Required inbound `TargetSubID` (57), when configured.
    target_sub_id: Option<String>,
    /// Required inbound `SenderLocationID` (142), when configured.
    sender_location_id: Option<String>,
    /// Required inbound `TargetLocationID` (143), when configured.
    target_location_id: Option<String>,
}

impl PeerIdentity {
    /// Builds the expected inbound identity from the session configuration.
    #[must_use]
    pub fn new(config: &SessionConfig) -> Self {
        Self {
            sender_comp_id: config.target_comp_id.as_str().to_string(),
            target_comp_id: config.sender_comp_id.as_str().to_string(),
            sender_sub_id: config.target_sub_id.clone(),
            target_sub_id: config.sender_sub_id.clone(),
            sender_location_id: config.target_location_id.clone(),
            target_location_id: config.sender_location_id.clone(),
        }
    }

    /// Checks an inbound message's identity fields.
    ///
    /// Sub and location IDs are only checked when configured; an
    /// unconfigured one places no requirement on the counterparty. This is
    /// the rule an `ironfix_engine::AcceptorRegistry` routes a
    /// Logon by, so a routed session enforces on every message the identity
    /// it was routed on.
    ///
    /// Each field must both carry the expected value **and** occur in the
    /// standard header. A CompID that appears only after the message body
    /// identifies nothing: the standard header is where the counterparty is
    /// named, and a message that omits it from there is missing a required
    /// header field however many copies it carries elsewhere. Both failures
    /// are `SessionRejectReason` 9.
    pub fn validate(&self, raw: &RawMessage<'_>) -> Result<(), IdentityMismatch> {
        check_field(raw, 49, &self.sender_comp_id)?;
        check_field(raw, 56, &self.target_comp_id)?;
        if let Some(expected) = &self.sender_sub_id {
            check_field(raw, 50, expected)?;
        }
        if let Some(expected) = &self.target_sub_id {
            check_field(raw, 57, expected)?;
        }
        if let Some(expected) = &self.sender_location_id {
            check_field(raw, 142, expected)?;
        }
        if let Some(expected) = &self.target_location_id {
            check_field(raw, 143, expected)?;
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
pub enum SendingTimeProblem {
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
    /// The `SessionRejectReason` (373) of the session-level Reject this
    /// problem produces; its `Text` (58) is the problem's `Display`.
    ///
    /// Reason 10 is "SendingTime accuracy problem"; a missing required field
    /// is reason 1 and an unparseable one is reason 6, "incorrect data
    /// format" (`doc/fix_operations.md`, "Session Reject Reasons").
    #[must_use]
    pub const fn reject_code(&self) -> u32 {
        match self {
            Self::Missing => 1,
            Self::Malformed { .. } => 6,
            Self::Skewed { .. } => 10,
        }
    }

    /// The `RefTagID` (371) of that Reject: `SendingTime` (52).
    #[must_use]
    pub const fn ref_tag(&self) -> u32 {
        52
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
pub const MAX_ECHOED_SENDING_TIME: usize = 32;

/// Checks inbound `SendingTime` (52) against the local clock.
#[derive(Debug, Clone, Copy)]
pub struct SendingTimeGuard {
    /// Configured tolerance. `Duration::ZERO` — and only that — disables the
    /// check; any nonzero value, including a sub-millisecond one, leaves it on.
    tolerance: Duration,
}

impl SendingTimeGuard {
    /// Builds the guard from the session configuration.
    #[must_use]
    pub const fn new(config: &SessionConfig) -> Self {
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
    pub const fn is_disabled(&self) -> bool {
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
    /// `now_millis` is the driver's wall clock: UTC milliseconds since the
    /// Unix epoch, the scale [`parse_utc_timestamp_millis`] reads 52 into.
    /// The check reads no clock itself.
    ///
    /// # Errors
    /// Returns [`SendingTimeProblem::Missing`] when tag 52 is absent from the
    /// standard header, [`SendingTimeProblem::Malformed`] when it is present but
    /// is not a UTF-8 `UTCTimestamp`, and [`SendingTimeProblem::Skewed`] when it
    /// parses but lies further from the local clock than the configured
    /// tolerance, in either direction.
    pub fn validate(
        &self,
        raw: &RawMessage<'_>,
        now_millis: u64,
    ) -> Result<(), SendingTimeProblem> {
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

        let skew_millis = now_millis.abs_diff(sent_millis);
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

/// `DefaultApplVerID` (1137): the counterparty's default application version,
/// declared in the body of a FIXT.1.1 Logon.
pub const DEFAULT_APPL_VER_ID: u32 = 1137;

/// `ApplVerID` (1128): the application version of one FIXT.1.1 application
/// message. A standard-header field (`FIXT11.xml`, `<header>`), and only that.
pub const APPL_VER_ID: u32 = 1128;

/// `RefApplVerID` (1130): on a FIXT.1.1 Reject, the `ApplVerID` of the
/// rejected message.
pub const REF_APPL_VER_ID: u32 = 1130;

/// Longest application-version value echoed in a log line, a Reject or a
/// Logout `Text` (58). The value is counterparty-controlled, so it is bounded;
/// a legal one is a single digit.
pub const MAX_ECHOED_APPL_VER_ID: usize = 16;

/// Why an inbound application version was refused: `DefaultApplVerID` (1137)
/// on a Logon, or `ApplVerID` (1128) on an application message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplVersionProblem {
    /// A FIXT.1.1 Logon without the required `DefaultApplVerID` (1137).
    Missing {
        /// The missing tag.
        tag: u32,
    },
    /// The tag occurs more than once: no occurrence can be trusted over the
    /// others (`SessionRejectReason` 13).
    Repeated {
        /// The repeated tag.
        tag: u32,
    },
    /// A header-only tag (`ApplVerID` (1128)) occurs after the standard
    /// header has ended (`SessionRejectReason` 14, "tag specified out of
    /// required order").
    OutsideHeader {
        /// The misplaced tag.
        tag: u32,
    },
    /// The value names no version: it is not one of the `ApplVerID` codes
    /// `2` to `9` that [`FixVersion::from_appl_ver_id`] decodes (`0`, `1` and
    /// `10` included).
    Unknown {
        /// The offending tag.
        tag: u32,
        /// The value, truncated to [`MAX_ECHOED_APPL_VER_ID`] bytes and
        /// escaped.
        value: String,
        /// The versions the session accepts, for the text.
        accepted: String,
    },
    /// The value names a version this session does not accept: a FIX 4.x
    /// code (`2` to `6`), or a FIX 5.0 one outside the accepted set.
    NotAccepted {
        /// The offending tag.
        tag: u32,
        /// The code received: one of `2` to `9`, so a single digit.
        code: String,
        /// The version the code names.
        version: FixVersion,
        /// The versions the session accepts, for the text.
        accepted: String,
    },
}

impl ApplVersionProblem {
    /// The tag the problem is about, `RefTagID` (371) of a Reject.
    #[must_use]
    pub const fn tag(&self) -> u32 {
        match self {
            Self::Missing { tag }
            | Self::Repeated { tag }
            | Self::OutsideHeader { tag }
            | Self::Unknown { tag, .. }
            | Self::NotAccepted { tag, .. } => *tag,
        }
    }

    /// The `SessionRejectReason` (373) of the session-level Reject this
    /// problem produces; its `RefTagID` (371) is the offending tag
    /// ([`ApplVersionProblem::tag`]) and its `Text` (58) the problem's
    /// `Display`.
    ///
    /// `SessionRejectReason` 18 is "Invalid/Unsupported Application Version"
    /// in the FIXT.1.1 session dictionary (QuickFIX `FIXT11.xml`,
    /// `INVALID_UNSUPPORTED_APPLICATION_VERSION`), which governs the Reject
    /// message on every FIXT.1.1 session; this check runs on no other kind. A
    /// missing required tag is reason 1, a repeated one reason 13 and a
    /// header tag outside the header reason 14 (`doc/fix_operations.md`,
    /// "Session Reject Reasons").
    #[must_use]
    pub const fn reject_code(&self) -> u32 {
        match self {
            // Reaches the wire only from an initiator in strict mode
            // (`require_ack_default_appl_ver_id`): the acceptor answers a
            // Logon without 1137 with a Logout alone, and by default the
            // initiator accepts an ack without it.
            Self::Missing { .. } => 1,
            Self::Repeated { .. } => 13,
            Self::OutsideHeader { .. } => 14,
            Self::Unknown { .. } | Self::NotAccepted { .. } => 18,
        }
    }

    /// The `RefApplVerID` (1130) a Reject for this problem carries: the
    /// rejected message's `ApplVerID` (1128), when it is a code that names a
    /// version (`2` to `9`) and the session does not accept it.
    ///
    /// `None` for every other problem: a 1137 problem concerns a Logon,
    /// which has no `ApplVerID` of its own; a value that names no version
    /// (`0` and `1` included, which name versions [`FixVersion`] does not
    /// model) has nothing validated to echo; and a repeated or misplaced
    /// 1128 has no single value to name.
    #[must_use]
    pub fn ref_appl_ver_id(&self) -> Option<&str> {
        match self {
            Self::NotAccepted { tag, code, .. } if *tag == APPL_VER_ID => Some(code),
            _ => None,
        }
    }
}

/// The field name of an application-version tag, for refusal texts.
const fn appl_ver_tag_name(tag: u32) -> &'static str {
    if tag == DEFAULT_APPL_VER_ID {
        "DefaultApplVerID"
    } else {
        "ApplVerID"
    }
}

impl std::fmt::Display for ApplVersionProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = appl_ver_tag_name(self.tag());
        match self {
            Self::Missing { tag } => write!(
                f,
                "{name} ({tag}) is missing; a FIXT.1.1 Logon must declare its default \
                 application version"
            ),
            Self::Repeated { tag } => write!(f, "{name} ({tag}) appears more than once"),
            Self::OutsideHeader { tag } => write!(
                f,
                "{name} ({tag}) appears outside the standard header, where it belongs"
            ),
            Self::Unknown {
                tag,
                value,
                accepted,
            } => write!(
                f,
                "{name} ({tag}) '{value}' is not a supported application version; \
                 this session accepts {accepted}"
            ),
            Self::NotAccepted {
                tag,
                code,
                version,
                accepted,
            } => write!(
                f,
                "{name} ({tag}) {code} ({version}) is not an application version this \
                 session accepts; it accepts {accepted}"
            ),
        }
    }
}

/// Where a tag occurs anywhere in a message, header, body or trailer.
///
/// Used for `DefaultApplVerID` (1137) and `NextExpectedMsgSeqNum` (789), body
/// fields of the Logon: an application reads them with
/// [`RawMessage::get_field_str`], which finds the first occurrence wherever it
/// is, so the value the session checks has to be the only one the message
/// carries.
#[must_use]
pub fn message_field<'a>(raw: &RawMessage<'a>, tag: u32) -> FieldOccurrence<'a> {
    let mut found = FieldOccurrence::Absent;
    for field in raw.fields() {
        if field.tag == tag {
            if found != FieldOccurrence::Absent {
                return FieldOccurrence::Repeated;
            }
            found = FieldOccurrence::Once(field.value);
        }
    }
    found
}

/// Checks the application versions a FIXT.1.1 counterparty declares
/// (`DefaultApplVerID` (1137) on its Logon) and uses (`ApplVerID` (1128) on
/// an application message) against the versions the session accepts.
///
/// The accepted set is [`SessionConfig::accepts_appl_version`], resolved once:
/// the session's own version plus
/// [`SessionConfig::allowed_appl_versions`]. A FIX 4.x session carries
/// neither field, and its guard checks nothing.
///
/// Both checks are synchronous decisions over one message, read no clock and
/// keep no state (ADR-0002), so any path that releases an application message
/// to the application (in sequence today; from a gap queue later) applies the
/// same [`ApplVersionGuard::check_application`].
#[derive(Debug, Clone)]
pub struct ApplVersionGuard {
    /// Whether the session is framed as FIXT.1.1. Off, nothing is checked.
    fixt: bool,
    /// The accepted versions, in ascending order.
    accepted: Vec<FixVersion>,
    /// The accepted versions as `code (name)`, for refusal texts.
    accepted_text: String,
}

impl ApplVersionGuard {
    /// Builds the guard for a session framed as `version`.
    #[must_use]
    pub fn new(config: &SessionConfig, version: FixVersion) -> Self {
        let fixt = version.uses_fixt();
        let accepted: Vec<FixVersion> = if fixt {
            FixVersion::ALL
                .into_iter()
                .filter(|candidate| config.accepts_appl_version(*candidate))
                .collect()
        } else {
            Vec::new()
        };
        let accepted_text = if accepted.is_empty() {
            "none".to_string()
        } else {
            accepted
                .iter()
                .map(|version| format!("{} ({version})", version.appl_ver_id().unwrap_or_default()))
                .collect::<Vec<_>>()
                .join(", ")
        };
        Self {
            fixt,
            accepted,
            accepted_text,
        }
    }

    /// Checks one occurrence of an application-version tag.
    fn check_value(&self, tag: u32, value: &[u8]) -> Result<FixVersion, ApplVersionProblem> {
        // Decoding is `FixVersion`'s; acceptance is the session's. A FIX 4.x
        // code decodes to a version no FIX 5.0 session accepts.
        let text = std::str::from_utf8(value).ok();
        match text.and_then(FixVersion::from_appl_ver_id) {
            Some(version) if self.accepted.contains(&version) => Ok(version),
            Some(version) => Err(ApplVersionProblem::NotAccepted {
                tag,
                code: text.unwrap_or_default().to_owned(),
                version,
                accepted: self.accepted_text.clone(),
            }),
            None => {
                let shown = value.get(..MAX_ECHOED_APPL_VER_ID).unwrap_or(value);
                Err(ApplVersionProblem::Unknown {
                    tag,
                    value: shown.escape_ascii().to_string(),
                    accepted: self.accepted_text.clone(),
                })
            }
        }
    }

    /// Checks the `DefaultApplVerID` (1137) of an inbound Logon or Logon
    /// acknowledgement, and returns the version it declares.
    ///
    /// `required` is the acceptor's rule: 1137 is a required field of the
    /// FIXT.1.1 Logon, so a Logon without it is refused. The initiator passes
    /// [`SessionConfig::require_ack_default_appl_ver_id`]: by default it
    /// checks an acknowledgement's 1137 only when present (issue #67), so an
    /// absent one is `Ok(None)` there, and in strict mode it requires it. On
    /// a FIX 4.x session nothing is checked and the answer is `Ok(None)`.
    ///
    /// # Errors
    /// [`ApplVersionProblem::Missing`] when `required` and 1137 is absent,
    /// [`ApplVersionProblem::Repeated`] when it occurs more than once,
    /// [`ApplVersionProblem::Unknown`] when its value names no version, and
    /// [`ApplVersionProblem::NotAccepted`] when it names one the session does
    /// not accept.
    pub fn check_logon(
        &self,
        raw: &RawMessage<'_>,
        required: bool,
    ) -> Result<Option<FixVersion>, ApplVersionProblem> {
        if !self.fixt {
            return Ok(None);
        }
        match message_field(raw, DEFAULT_APPL_VER_ID) {
            FieldOccurrence::Absent if required => Err(ApplVersionProblem::Missing {
                tag: DEFAULT_APPL_VER_ID,
            }),
            FieldOccurrence::Absent => Ok(None),
            FieldOccurrence::Repeated => Err(ApplVersionProblem::Repeated {
                tag: DEFAULT_APPL_VER_ID,
            }),
            FieldOccurrence::Once(value) => self.check_value(DEFAULT_APPL_VER_ID, value).map(Some),
        }
    }

    /// Checks the `ApplVerID` (1128) of an inbound application message.
    ///
    /// A message without 1128 is in the counterparty's default application
    /// version, which its Logon declared and the handshake already checked,
    /// so it passes. 1128 is a standard-header field (`FIXT11.xml`), so it is
    /// read positionally, as [`header_field`] reads the CompIDs: one in the
    /// header is the message's version, and one after the header has ended is
    /// out of order, wherever else 1128 occurs. Every occurrence is looked at,
    /// so no 1128 the application could read with
    /// [`RawMessage::get_field_str`] escapes the check. On a FIX 4.x session
    /// nothing is checked.
    ///
    /// # Errors
    /// [`ApplVersionProblem::OutsideHeader`] when any 1128 occurs after the
    /// standard header (this outranks a repetition),
    /// [`ApplVersionProblem::Repeated`] when the header carries it more than
    /// once,
    /// [`ApplVersionProblem::Unknown`] when its value names no version, and
    /// [`ApplVersionProblem::NotAccepted`] when it names one the session does
    /// not accept.
    pub fn check_application(&self, raw: &RawMessage<'_>) -> Result<(), ApplVersionProblem> {
        if !self.fixt {
            return Ok(());
        }
        // One scan: the header is the leading run of standard-header tags,
        // and any 1128 after it is out of order.
        let mut in_header = true;
        let mut found = FieldOccurrence::Absent;
        for field in raw.fields() {
            in_header = in_header && is_standard_header_tag(field.tag);
            if field.tag != APPL_VER_ID {
                continue;
            }
            if !in_header {
                return Err(ApplVersionProblem::OutsideHeader { tag: APPL_VER_ID });
            }
            found = match found {
                FieldOccurrence::Absent => FieldOccurrence::Once(field.value),
                FieldOccurrence::Once(_) | FieldOccurrence::Repeated => FieldOccurrence::Repeated,
            };
        }
        match found {
            FieldOccurrence::Absent => Ok(()),
            FieldOccurrence::Repeated => Err(ApplVersionProblem::Repeated { tag: APPL_VER_ID }),
            FieldOccurrence::Once(value) => self.check_value(APPL_VER_ID, value).map(|_| ()),
        }
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
#[must_use]
pub fn parse_utc_timestamp_millis(value: &str) -> Option<u64> {
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

/// Longest `EncryptMethod` (98) value echoed in a log line, a Reject or a
/// Logout `Text` (58). The value is counterparty-controlled, so it is bounded.
pub const MAX_ECHOED_ENCRYPT_METHOD: usize = 16;

/// Why an inbound Logon's `EncryptMethod` (98) was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptMethodProblem {
    /// The field is absent: it is a required field of the Logon.
    Missing,
    /// The field names a method other than 0 (None): IronFix implements no
    /// encryption, so nothing else can be honoured.
    Unsupported {
        /// The offending value, bounded by [`MAX_ECHOED_ENCRYPT_METHOD`].
        value: String,
    },
}

impl EncryptMethodProblem {
    /// The `SessionRejectReason` (373) of the session-level Reject this
    /// problem produces: 1 (required tag missing) or 5 (value is incorrect).
    /// Its `RefTagID` (371) is 98 and its `Text` (58) the problem's
    /// `Display`.
    #[must_use]
    pub const fn reject_code(&self) -> u32 {
        match self {
            Self::Missing => 1,
            Self::Unsupported { .. } => 5,
        }
    }

    /// The `RefTagID` (371) of that Reject: `EncryptMethod` (98).
    #[must_use]
    pub const fn ref_tag(&self) -> u32 {
        98
    }
}

impl std::fmt::Display for EncryptMethodProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(
                f,
                "unsupported EncryptMethod (98) '<absent>'; only 0 (None) is supported"
            ),
            Self::Unsupported { value } => write!(
                f,
                "unsupported EncryptMethod (98) '{value}'; only 0 (None) is supported"
            ),
        }
    }
}

/// Checks the `EncryptMethod` (98) of an inbound Logon or Logon
/// acknowledgement: it is required, and only 0 (None) is supported.
///
/// # Errors
/// [`EncryptMethodProblem::Missing`] when 98 is absent and
/// [`EncryptMethodProblem::Unsupported`] when it is anything but `0`.
pub fn check_encrypt_method(raw: &RawMessage<'_>) -> Result<(), EncryptMethodProblem> {
    match raw.get_field(98) {
        None => Err(EncryptMethodProblem::Missing),
        Some(field) if field.value == b"0" => Ok(()),
        Some(field) => Err(EncryptMethodProblem::Unsupported {
            value: String::from_utf8_lossy(field.value)
                .chars()
                .take(MAX_ECHOED_ENCRYPT_METHOD)
                .collect(),
        }),
    }
}
