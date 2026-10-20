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

use crate::application::{RejectReason, SessionId};
use crate::outbound::{OutboundField, OutboundMessage};
use bytes::BytesMut;
use ironfix_core::error::{DecodeError, EncodeError};
use ironfix_core::field::FieldRef;
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::Timestamp;
use ironfix_core::validation::{InboundDefect, InboundRejection};
use ironfix_core::version::FixVersion;
use ironfix_session::{ReplayField, SessionConfig, orig_sending_time, replay_field};
use ironfix_tagvalue::{Decoder, Encoder, FieldIndex};
use std::time::Duration;

/// Derives the [`SessionId`] from a session configuration.
///
/// The identity is taken sender-first from the configuration, so both the
/// [`Initiator`](crate::Initiator) and the [`Acceptor`](crate::Acceptor) name a
/// session the same way: `begin_string:sender_comp_id->target_comp_id`, with
/// the optional sub IDs attached when configured.
pub(crate) fn session_id_from_config(config: &SessionConfig) -> SessionId {
    let mut session_id = SessionId::new(
        config.begin_string.clone(),
        config.sender_comp_id.as_str(),
        config.target_comp_id.as_str(),
    );
    if let Some(sub) = &config.sender_sub_id {
        session_id = session_id.with_sender_sub_id(sub.clone());
    }
    if let Some(sub) = &config.target_sub_id {
        session_id = session_id.with_target_sub_id(sub.clone());
    }
    session_id
}

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
    /// The offending tag (49, 56, 50, 57, 142 or 143).
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
/// `OnBehalfOfSendingTime` (370), the `NoHops` group (627 and its 628/629/630 entries), and the FIXT.1.1
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

/// How often a tag occurs in the part of a message a read covers: the
/// standard header for [`header_field`], the whole message for the
/// message-wide read of a body field such as `DefaultApplVerID` (1137).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FieldOccurrence<'a> {
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
pub(crate) fn header_field<'a>(raw: &RawMessage<'a>, tag: u32) -> FieldOccurrence<'a> {
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
pub(crate) fn header_seq_num(raw: &RawMessage<'_>) -> Option<u64> {
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
pub(crate) const MAX_HEARTBEAT_INTERVAL_SECS: u64 = 86_400;

/// Longest `HeartBtInt` (108) value echoed back in a log line or a Logout
/// `Text` (58). The field is counterparty-controlled, so it is bounded.
const MAX_ECHOED_HEARTBEAT: usize = 32;

/// Why an inbound `HeartBtInt` (108) was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HeartBtIntProblem {
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
pub(crate) fn parse_heartbeat_interval(raw: &RawMessage<'_>) -> Result<u64, HeartBtIntProblem> {
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
pub(crate) struct PeerIdentity {
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
    pub(crate) fn new(config: &SessionConfig) -> Self {
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
    /// the rule an [`AcceptorRegistry`](crate::AcceptorRegistry) routes a
    /// Logon by, so a routed session enforces on every message the identity
    /// it was routed on.
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

/// `DefaultApplVerID` (1137): the counterparty's default application version,
/// declared in the body of a FIXT.1.1 Logon.
pub(crate) const DEFAULT_APPL_VER_ID: u32 = 1137;

/// `ApplVerID` (1128): the application version of one FIXT.1.1 application
/// message. A standard-header field (`FIXT11.xml`, `<header>`), and only that.
pub(crate) const APPL_VER_ID: u32 = 1128;

/// `RefApplVerID` (1130): on a FIXT.1.1 Reject, the `ApplVerID` of the
/// rejected message.
pub(crate) const REF_APPL_VER_ID: u32 = 1130;

/// Longest application-version value echoed in a log line, a Reject or a
/// Logout `Text` (58). The value is counterparty-controlled, so it is bounded;
/// a legal one is a single digit.
const MAX_ECHOED_APPL_VER_ID: usize = 16;

/// Why an inbound application version was refused: `DefaultApplVerID` (1137)
/// on a Logon, or `ApplVerID` (1128) on an application message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ApplVersionProblem {
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
    pub(crate) const fn tag(&self) -> u32 {
        match self {
            Self::Missing { tag }
            | Self::Repeated { tag }
            | Self::OutsideHeader { tag }
            | Self::Unknown { tag, .. }
            | Self::NotAccepted { tag, .. } => *tag,
        }
    }

    /// The session-level Reject this problem produces, `RefTagID` (371) the
    /// offending tag.
    ///
    /// `SessionRejectReason` 18 is "Invalid/Unsupported Application Version"
    /// in the FIXT.1.1 session dictionary (QuickFIX `FIXT11.xml`,
    /// `INVALID_UNSUPPORTED_APPLICATION_VERSION`), which governs the Reject
    /// message on every FIXT.1.1 session; this check runs on no other kind. A
    /// missing required tag is reason 1, a repeated one reason 13 and a
    /// header tag outside the header reason 14 (`doc/fix_operations.md`,
    /// "Session Reject Reasons").
    #[must_use]
    pub(crate) fn reject_reason(&self) -> RejectReason {
        let code = match self {
            // Reaches the wire only from an initiator in strict mode
            // (`require_ack_default_appl_ver_id`): the acceptor answers a
            // Logon without 1137 with a Logout alone, and by default the
            // initiator accepts an ack without it.
            Self::Missing { .. } => 1,
            Self::Repeated { .. } => 13,
            Self::OutsideHeader { .. } => 14,
            Self::Unknown { .. } | Self::NotAccepted { .. } => 18,
        };
        RejectReason::new(code, self.to_string()).with_ref_tag(self.tag())
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
    pub(crate) fn ref_appl_ver_id(&self) -> Option<&str> {
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
pub(crate) fn message_field<'a>(raw: &RawMessage<'a>, tag: u32) -> FieldOccurrence<'a> {
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
pub(crate) struct ApplVersionGuard {
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
    pub(crate) fn new(config: &SessionConfig, version: FixVersion) -> Self {
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
    pub(crate) fn check_logon(
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
    pub(crate) fn check_application(&self, raw: &RawMessage<'_>) -> Result<(), ApplVersionProblem> {
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

/// Decodes a framed FIX message through the session's reusable field index.
///
/// Same checks and errors as [`decode_frame`], plus
/// [`DecodeError::TooManyFields`] when the message has more fields than
/// `index` holds; the caller falls back to [`decode_frame`] then. The
/// returned message borrows `frame` only, not `index`.
pub(crate) fn decode_frame_into<'f>(
    frame: &'f [u8],
    index: &mut FieldIndex,
) -> Result<RawMessage<'f>, DecodeError> {
    let mut decoder = Decoder::new(frame).with_checksum_validation(false);
    decoder.decode_into(index)?.to_raw_message()
}

/// Returns whether `frame`, which framed but failed to decode with `error`, is
/// *garbled* in the FIX Session Layer's sense.
///
/// Garbled means the header cannot be trusted: BeginString (8) not first,
/// BodyLength (9) not second or invalid, MsgType (35) not third, or a CheckSum
/// (10) mismatch. Such a frame is ignored and counts toward
/// [`SessionConfig::garbled_frame_limit`].
///
/// The verdict follows **where** decoding failed, not which error it raised:
/// the decoder can stop on a malformed third field (`abc=0`) with an invalid
/// tag before it ever reports MsgType missing, and that is still MsgType not
/// third. So any failure while the first three fields are not structurally
/// `8=…`, `9=…`, `35=…`, each SOH-terminated, is garbled.
///
/// Every other failure is a malformed *body* behind a sound header (an invalid
/// tag, an unterminated field, a bad data length or Length value). So is a
/// MsgType field whose value is unacceptable: the field sits where it should,
/// and FIX answers an invalid MsgType with a Reject (reason 11), not by
/// treating the message as garbled. None of these is garbled: the reactor
/// answers them with a session Reject ([`malformed_reject`]) and does not
/// count them.
#[must_use]
pub(crate) fn decode_is_garbled(error: &DecodeError, frame: &[u8]) -> bool {
    match error {
        DecodeError::InvalidBeginString
        | DecodeError::MissingBodyLength
        | DecodeError::InvalidBodyLength
        | DecodeError::MissingMsgType
        | DecodeError::ChecksumMismatch { .. } => true,
        DecodeError::InvalidMsgType(_) => false,
        _ => !header_fields_in_place(frame),
    }
}

/// The FIX field delimiter.
const SOH: u8 = 0x01;

/// Returns whether the first three fields of `frame` are, structurally, `8=…`,
/// `9=…` and `35=…`, each terminated by SOH. Values are not checked.
#[must_use]
fn header_fields_in_place(frame: &[u8]) -> bool {
    let mut rest = frame;
    for tag in [&b"8="[..], b"9=", b"35="] {
        let Some(end) = rest.iter().position(|&byte| byte == SOH) else {
            return false;
        };
        if !rest.get(..end).is_some_and(|field| field.starts_with(tag)) {
            return false;
        }
        let Some(next) = end.checked_add(1).and_then(|start| rest.get(start..)) else {
            return false;
        };
        rest = next;
    }
    true
}

/// Names the defect behind a frame that framed but did not decode, for a log
/// line that must not carry the frame's bytes.
///
/// [`DecodeError`]'s `Display` can quote input: an `InvalidTag` shows the first
/// bytes of the offending tag, which in a garbled frame may be the start of a
/// `Password` (554) value. The engine logs this static label instead.
#[must_use]
pub(crate) const fn decode_defect(error: &DecodeError) -> &'static str {
    match error {
        DecodeError::InvalidBeginString => "BeginString (8) not first",
        DecodeError::MissingBodyLength => "BodyLength (9) not second",
        DecodeError::InvalidBodyLength => "BodyLength (9) invalid",
        DecodeError::MissingMsgType => "MsgType (35) not third",
        DecodeError::ChecksumMismatch { .. } => "CheckSum (10) mismatch",
        DecodeError::InvalidMsgType(_) => "MsgType (35) value invalid",
        DecodeError::InvalidTag(_) => "invalid tag",
        DecodeError::UnterminatedField { .. } => "unterminated field",
        DecodeError::InvalidDataLength { .. } => "invalid data length",
        DecodeError::InvalidFieldValue { .. } => "invalid field value",
        DecodeError::InvalidUtf8(_) => "invalid UTF-8",
        _ => "malformed message",
    }
}

/// What a positional read of the standard header of a framed but undecodable
/// frame found.
///
/// The frame's body failed to decode, so no [`RawMessage`] exists; the session
/// still needs `MsgSeqNum` (34) to reference the frame in a Reject and to
/// sequence it, and `PossDupFlag` (43) to recognise a resend of a number it
/// has already consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MalformedHeader<'a> {
    /// `MsgSeqNum` (34), when the header carries it exactly once as a valid
    /// number before the first defect or the first non-header field.
    pub(crate) seq: Option<u64>,
    /// Whether the header carries `PossDupFlag` (43) = `Y`.
    pub(crate) poss_dup: bool,
    /// The frame's MsgType (35), when it is a valid one.
    pub(crate) msg_type: Option<&'a str>,
}

/// The DATA tag paired with a standard-header Length tag, whose value may
/// contain SOH: SecureDataLen (90) / SecureData (91) and XmlDataLen (212) /
/// XmlData (213).
const fn header_data_tag(length_tag: u32) -> Option<u32> {
    match length_tag {
        90 => Some(91),
        212 => Some(213),
        _ => None,
    }
}

/// Parses 1 to `max_len` ASCII digits into a `u64`, with checked arithmetic.
fn parse_ascii_u64(bytes: &[u8], max_len: usize) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > max_len {
        return None;
    }
    let mut value: u64 = 0;
    for &byte in bytes {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte.checked_sub(b'0')?),
            _ => return None,
        };
        value = value.checked_mul(10)?.checked_add(digit)?;
    }
    Some(value)
}

/// Reads `MsgSeqNum` (34), `PossDupFlag` (43) and MsgType (35) by position
/// from a frame whose header is sound but whose body does not decode.
///
/// The scan walks the fields in order, `8`, `9`, `35`, then the standard
/// header, and stops at the first field that is not a standard header field
/// or does not parse as `tag=value<SOH>`. A 34 past that point is not read:
/// it is either in the body, where the decoded path does not accept it
/// either ([`header_seq_num`]), or behind a defect, where nothing can be
/// trusted. A 34 that appears twice, or whose value is not a number, is
/// unreadable. The header Length/Data pairs (90/91, 212/213) are skipped by
/// their declared count, bounded by the frame.
///
/// No allocation; values are never copied or logged.
#[must_use]
pub(crate) fn scan_malformed_header(frame: &[u8]) -> MalformedHeader<'_> {
    let mut found = MalformedHeader {
        seq: None,
        poss_dup: false,
        msg_type: None,
    };
    let mut seq_seen = false;
    let mut seq_repeated = false;
    let mut pending_data: Option<(u32, usize)> = None;
    let mut rest = frame;
    let mut position: usize = 0;
    while let Some(eq) = rest.iter().position(|&byte| byte == b'=') {
        let Some(tag) = rest
            .get(..eq)
            .and_then(|bytes| parse_ascii_u64(bytes, 9))
            .and_then(|tag| u32::try_from(tag).ok())
        else {
            break;
        };
        let Some(after_eq) = eq.checked_add(1).and_then(|start| rest.get(start..)) else {
            break;
        };
        let value_len = match pending_data.take() {
            Some((data_tag, declared)) if data_tag == tag => {
                if after_eq.get(declared) != Some(&SOH) {
                    break;
                }
                declared
            }
            _ => match after_eq.iter().position(|&byte| byte == SOH) {
                Some(end) => end,
                None => break,
            },
        };
        let Some(value) = after_eq.get(..value_len) else {
            break;
        };
        let in_place = match position {
            0 => tag == 8,
            1 => tag == 9,
            2 => tag == 35,
            _ => is_standard_header_tag(tag) && !matches!(tag, 8 | 9 | 35),
        };
        if !in_place {
            break;
        }
        match tag {
            35 => {
                found.msg_type = std::str::from_utf8(value)
                    .ok()
                    .filter(|text| text.parse::<MsgType>().is_ok());
            }
            34 => {
                seq_repeated |= seq_seen;
                seq_seen = true;
                found.seq = parse_ascii_u64(value, 20);
            }
            43 => found.poss_dup = value == b"Y",
            _ => {}
        }
        if let Some(data_tag) = header_data_tag(tag) {
            match parse_ascii_u64(value, 9).and_then(|count| usize::try_from(count).ok()) {
                Some(declared) => pending_data = Some((data_tag, declared)),
                None => break,
            }
        }
        let Some(next) = value_len
            .checked_add(1)
            .and_then(|skip| after_eq.get(skip..))
        else {
            break;
        };
        rest = next;
        position = match position.checked_add(1) {
            Some(next) => next,
            None => break,
        };
    }
    if seq_repeated {
        found.seq = None;
    }
    found
}

/// The session-level Reject for a framed message whose body does not decode:
/// `SessionRejectReason` (373), `RefTagID` (371) when a tag can be named, and
/// a fixed `Text` (58).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MalformedReject {
    /// `SessionRejectReason` (373). Every code used exists from FIX 4.2 on.
    pub(crate) code: u32,
    /// `RefTagID` (371), when the defect names a tag.
    pub(crate) ref_tag: Option<u32>,
    /// A fixed label, never the frame's bytes.
    pub(crate) text: &'static str,
}

/// Maps the decode failure of a framed message whose header is sound to the
/// session-level Reject it gets.
///
/// Only codes FIX 4.2 already defines are used (0, 4, 6 and 11; FIX 4.2
/// defines 0 to 11, `ironfix-dictionary/spec/FIX42.xml`), so the mapping is
/// the same on every version that carries 373. FIX 4.0 and FIX 4.1 have no
/// 373 and get `RefSeqNum` and the `Text` alone
/// ([`MessageFactory::session_reject`]).
///
/// - an invalid tag (not a number, or no `=`): 0, "Invalid tag number";
/// - a Length field with no value: 4, "Tag specified without a value",
///   `RefTagID` = the Length tag;
/// - a Length field whose value is not a byte count, a Length/Data pair
///   whose count the frame cannot satisfy, an unterminated field: 6,
///   "Incorrect data format for value", `RefTagID` = the tag;
/// - a MsgType (35) value that is not a valid message type: 11, "Invalid
///   MsgType", `RefTagID` = 35;
/// - anything else: 6, without `RefTagID`.
#[must_use]
pub(crate) fn malformed_reject(error: &DecodeError, frame: &[u8]) -> MalformedReject {
    match error {
        DecodeError::InvalidTag(_) => MalformedReject {
            code: 0,
            ref_tag: None,
            text: "malformed message: invalid tag number",
        },
        DecodeError::InvalidFieldValue { tag, .. } if field_is_empty(frame, *tag) => {
            MalformedReject {
                code: 4,
                ref_tag: Some(*tag),
                text: "malformed message: tag specified without a value",
            }
        }
        DecodeError::InvalidFieldValue { tag, .. } => MalformedReject {
            code: 6,
            ref_tag: Some(*tag),
            text: "malformed message: incorrect data format for value",
        },
        DecodeError::InvalidDataLength { data_tag, .. } => MalformedReject {
            code: 6,
            ref_tag: Some(*data_tag),
            text: "malformed message: data length does not match the data field",
        },
        DecodeError::UnterminatedField { tag } => MalformedReject {
            code: 6,
            ref_tag: Some(*tag),
            text: "malformed message: unterminated field",
        },
        DecodeError::InvalidMsgType(_) | DecodeError::InvalidUtf8(_) => MalformedReject {
            code: 11,
            ref_tag: Some(35),
            text: "malformed message: invalid MsgType",
        },
        _ => MalformedReject {
            code: 6,
            ref_tag: None,
            text: "malformed message: body does not decode",
        },
    }
}

/// Whether the field whose value failed to parse as `tag`'s byte count is
/// empty (`tag=<SOH>`).
///
/// The failing field is found by position with the decoder's own walk, so
/// Length/Data pairs are framed by count exactly as during the decode (a
/// DATA payload that happens to contain `<SOH>95=<SOH>` is skipped, not
/// matched) and tags are parsed numerically (a zero-padded `095=` is tag
/// 95). Every successful step advances the walk, so it ends. The decoder may
/// allocate the reason string of the error it returns; this runs only on the
/// malformed path.
fn field_is_empty(frame: &[u8], tag: u32) -> bool {
    let mut decoder = Decoder::new(frame);
    loop {
        let start = decoder.offset();
        match decoder.next_field() {
            Ok(Some(_)) => {}
            Err(DecodeError::InvalidFieldValue { tag: failed, .. }) if failed == tag => {
                let Some(field) = frame.get(start..) else {
                    return false;
                };
                let Some(eq) = field.iter().position(|&byte| byte == b'=') else {
                    return false;
                };
                return eq
                    .checked_add(1)
                    .and_then(|value_start| field.get(value_start))
                    == Some(&SOH);
            }
            Ok(None) | Err(_) => return false,
        }
    }
}

/// Length of a whole-second `UTCTimestamp`, `YYYYMMDD-HH:MM:SS`, in bytes.
const WHOLE_SECONDS_LEN: usize = 17;

/// The precision of the `UTCTimestamp`s the engine writes into `SendingTime`
/// (52) and `OrigSendingTime` (122), which the session's FIX version decides.
///
/// FIX 4.0 and FIX 4.1 type both fields as `time`: `YYYYMMDD-HH:MM:SS`, whole
/// seconds with nothing after them. FIX 4.2 replaced that type with
/// `UTCTimestamp`, which is either the same whole-second form or one with
/// milliseconds (FIX Repository 2010 edition, `Datatypes.xml`: `time` in
/// FIX.4.0 and FIX.4.1, `UTCTimestamp` from FIX.4.2; the QuickFIX `FIX40.xml`
/// and `FIX41.xml` type 52 and 122 as `TIME`). A strict FIX 4.0 or FIX 4.1
/// counterparty may reject a millisecond value as malformed, so those
/// sessions write whole seconds and every later one keeps milliseconds. That
/// is the cut QuickFIX makes too (`Session::supportsSubSecondTimestamps`).
///
/// Only what the engine writes depends on it: inbound parsing
/// ([`parse_utc_timestamp_millis`]) accepts both forms on every version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendingTimePrecision {
    /// `YYYYMMDD-HH:MM:SS`: FIX 4.0 and FIX 4.1.
    Seconds,
    /// `YYYYMMDD-HH:MM:SS.sss`: FIX 4.2 and later, FIXT.1.1 included.
    Millis,
}

impl SendingTimePrecision {
    /// Returns the precision a session in `version` writes.
    ///
    /// The match names every version, so a new [`FixVersion`] does not
    /// compile until it has been given a precision.
    #[inline]
    #[must_use]
    pub(crate) const fn for_version(version: FixVersion) -> Self {
        match version {
            FixVersion::Fix40 | FixVersion::Fix41 => Self::Seconds,
            FixVersion::Fix42
            | FixVersion::Fix43
            | FixVersion::Fix44
            | FixVersion::Fix50
            | FixVersion::Fix50Sp1
            | FixVersion::Fix50Sp2
            | FixVersion::Fixt11 => Self::Millis,
        }
    }

    /// Formats `at` in this precision and passes the text to `write`,
    /// returning whatever `write` returns.
    ///
    /// The text sits in a fixed-size buffer on the stack for the length of
    /// the call, so this allocates nothing; it runs for every outbound frame.
    #[inline]
    fn with_formatted<R>(self, at: Timestamp, write: impl FnOnce(&str) -> R) -> R {
        match self {
            Self::Seconds => write(at.format_seconds().as_str()),
            Self::Millis => write(at.format_millis().as_str()),
        }
    }

    /// Returns `at` as this precision writes it on the wire: truncated to the
    /// whole second, or to the millisecond, exactly as
    /// [`Timestamp::format_seconds`] and [`Timestamp::format_millis`]
    /// truncate. A tracked send reports this value, so it equals the
    /// `SendingTime` (52) the counterparty reads.
    #[must_use]
    pub(crate) fn truncate(self, at: Timestamp) -> Timestamp {
        let millis = at.as_millis();
        let kept = match self {
            Self::Millis => Some(millis),
            Self::Seconds => (millis / 1_000).checked_mul(1_000),
        };
        kept.and_then(|millis| Timestamp::from_millis(millis).ok())
            .unwrap_or(at)
    }

    /// Returns a stored `UTCTimestamp` in this precision, for the
    /// `OrigSendingTime` (122) of a resend.
    ///
    /// At whole seconds, a value that parses as a `UTCTimestamp` and carries
    /// a fraction is cut back to its first 17 bytes, `YYYYMMDD-HH:MM:SS`. That
    /// is the same instant truncated exactly as [`Timestamp::format_seconds`]
    /// truncates, so it is what the session would have written had it sent
    /// the original at this precision. It covers a frame stored before the
    /// session wrote whole seconds, for example in a journal kept across an
    /// upgrade.
    ///
    /// Everything else comes back unchanged and borrowed: any value at
    /// millisecond precision (FIX 4.2 and later accept both forms), a value
    /// already in whole seconds, and a value that does not parse as a
    /// `UTCTimestamp`, which is not this function's to repair.
    #[must_use]
    fn narrow(self, value: &str) -> &str {
        match self {
            Self::Millis => value,
            Self::Seconds => {
                let has_fraction = value.as_bytes().get(WHOLE_SECONDS_LEN) == Some(&b'.');
                if has_fraction && parse_utc_timestamp_millis(value).is_some() {
                    value.get(..WHOLE_SECONDS_LEN).unwrap_or(value)
                } else {
                    value
                }
            }
        }
    }
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
/// Both times are written in the session's `precision`, the one
/// [`MessageFactory::encode`] stamps its own 52 with: the new 52 is formatted
/// in it, and the copied 122 is narrowed to it by
/// [`SendingTimePrecision::narrow`]. On a FIX 4.2 or later session that copy
/// is verbatim; on a FIX 4.0 or FIX 4.1 one a stored millisecond time loses
/// its fraction, so a frame stored before the session wrote whole seconds
/// still replays with a 122 that session's counterparty accepts.
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
pub(crate) fn resend_frame(
    stored: &[u8],
    precision: SendingTimePrecision,
) -> Result<BytesMut, ResendError> {
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
    let orig_sending_time =
        precision.narrow(orig_sending_time(raw.get_field_str(122), sending_time_52));
    let now = Timestamp::now();

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
        // Which header fields are dropped, reinserted or restamped is the
        // sans-IO core's decision (issue #91, stage 3).
        match replay_field(field.tag) {
            // BeginString and BodyLength are stamped by `finish`.
            ReplayField::Framing => {}
            // Re-emitted below, in their standard-header positions. A frame
            // already carrying them is being replayed a second time.
            ReplayField::Reinserted => {}
            ReplayField::SendingTime => {
                encoder.try_put_raw(43, b"Y")?;
                precision.with_formatted(now, |sending_time| {
                    encoder.try_put_raw(52, sending_time.as_bytes())
                })?;
                encoder.try_put_raw(122, orig_sending_time.as_bytes())?;
            }
            ReplayField::Copied => {
                let tag = field.tag;
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

/// How a session writes and reads the open-ended ("to infinity") `EndSeqNo`
/// (16) of a ResendRequest (35=2): decided by the sans-IO core (issue #91,
/// stage 3), by FIX version.
pub(crate) use ironfix_session::EndSeqNoInfinity;

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
    /// The session's `max_message_size`: the largest frame the codec feeds.
    max_message_size: usize,
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
            max_message_size: config.max_message_size,
        }
    }

    /// The session's `max_message_size`, in bytes: a frame longer than this
    /// is refused before it is filed or spends a number.
    #[inline]
    #[must_use]
    pub(crate) const fn max_message_size(&self) -> usize {
        self.max_message_size
    }

    /// Returns the precision this session writes `SendingTime` (52) and
    /// `OrigSendingTime` (122) in, decided by its FIX version.
    ///
    /// [`resend_frame`] takes it too, so a replayed message carries the same
    /// precision as everything else the session sends.
    #[inline]
    #[must_use]
    pub(crate) const fn sending_time_precision(&self) -> SendingTimePrecision {
        SendingTimePrecision::for_version(self.version)
    }

    /// Frames `pending` under `seq` and returns the finished frame, which
    /// borrows the factory's own buffer until the next call.
    ///
    /// The standard header is stamped first —
    /// 35, \[1128\], 49, 56, \[50\], \[142\], \[57\], \[143\], 34, \[43\], 52, \[122\] —
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
    /// `SendingTime` (52), and 122 with it, is written in the precision of
    /// [`MessageFactory::sending_time_precision`]: whole seconds on a FIX 4.0
    /// or FIX 4.1 session, milliseconds on every later one.
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
        self.encode_stamped(seq, pending).map(|(frame, _)| frame)
    }

    /// [`MessageFactory::encode`], also returning the clock reading stamped
    /// into `SendingTime` (52), at full precision: what the frame carries is
    /// that instant in [`MessageFactory::sending_time_precision`] (see
    /// [`SendingTimePrecision::truncate`]). The reading is taken once, so the
    /// value returned and the value written are the same instant.
    ///
    /// # Errors
    /// As for [`MessageFactory::encode`].
    pub(crate) fn encode_stamped(
        &mut self,
        seq: u64,
        pending: &PendingMessage,
    ) -> Result<(&[u8], Timestamp), EncodeError> {
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
        let precision = self.sending_time_precision();
        let encoder = &mut self.encoder;
        let stamped = Timestamp::now();
        precision.with_formatted(stamped, |sending_time| {
            encoder.put_str(52, sending_time);
            if poss_dup {
                encoder.put_str(122, sending_time);
            }
        });

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
        self.encoder.finish().map(|frame| (frame, stamped))
    }

    /// Builds a Logon (35=A) with EncryptMethod=0, HeartBtInt,
    /// `ResetSeqNumFlag` (141) = Y when `reset_seq`,
    /// `NextExpectedMsgSeqNum` (789) when `next_expected` is given and, for a
    /// FIXT.1.1 session, DefaultApplVerID (1137).
    ///
    /// The fields follow the order the FIX.4.4 and FIXT.1.1 Logon defines
    /// them in: 98, 108, 141, 789, then 1137. `next_expected` is the next
    /// `MsgSeqNum` this session expects to receive; the caller passes it only
    /// when [`SessionConfig::send_next_expected_msg_seq_num`] is set, which
    /// configuration validation allows only on versions that define 789.
    #[must_use]
    pub(crate) fn logon(
        &self,
        heartbeat_secs: u64,
        reset_seq: bool,
        next_expected: Option<u64>,
    ) -> PendingMessage {
        let mut message = OutboundMessage::new(MsgType::Logon);
        message.push_uint(98, 0).push_uint(108, heartbeat_secs);
        if reset_seq {
            message.push_bool(141, true);
        }
        if let Some(next_expected) = next_expected {
            message.push_uint(
                crate::next_expected::NEXT_EXPECTED_MSG_SEQ_NUM,
                next_expected,
            );
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

    /// Builds a ResendRequest (35=2) for `begin_seq..end_seq`.
    ///
    /// `end_seq` = 0 means "up to infinity" and is written as this session's
    /// open-ended `EndSeqNo` (16): `999999` on FIX 4.0 and 4.1, `0` on FIX 4.2
    /// and later (see [`EndSeqNoInfinity`]).
    #[must_use]
    pub(crate) fn resend_request(&self, begin_seq: u64, end_seq: u64) -> PendingMessage {
        let end_seq = match end_seq {
            0 => EndSeqNoInfinity::for_version(self.version).sentinel(),
            bounded => bounded,
        };
        let mut message = OutboundMessage::new(MsgType::ResendRequest);
        message.push_uint(7, begin_seq).push_uint(16, end_seq);
        PendingMessage::plain(message)
    }

    /// Whether an inbound ResendRequest's `EndSeqNo` (16) means "to infinity"
    /// on this session (see [`EndSeqNoInfinity::is_open_ended`]).
    #[inline]
    #[must_use]
    #[cfg(test)]
    pub(crate) const fn is_open_ended_end_seq_no(&self, end_seq: u64) -> bool {
        self.end_seq_no_infinity().is_open_ended(end_seq)
    }

    /// This session's "to infinity" `EndSeqNo` (16) convention, the input the
    /// sans-IO core's `decide_resend_request` reads it through.
    #[inline]
    #[must_use]
    pub(crate) const fn end_seq_no_infinity(&self) -> EndSeqNoInfinity {
        EndSeqNoInfinity::for_version(self.version)
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
        self.session_reject_with_appl_ver(ref_seq, ref_msg_type, reason, None)
    }

    /// Builds a session-level Reject (35=3) that also names the `ApplVerID`
    /// of the rejected message in `RefApplVerID` (1130), a FIXT.1.1 Reject
    /// field.
    ///
    /// The fields follow the FIXT.1.1 Reject layout: `RefSeqNum` (45),
    /// `RefTagID` (371), `RefMsgType` (372), `RefApplVerID` (1130),
    /// `SessionRejectReason` (373), `Text` (58). `ref_appl_ver_id` must be a
    /// code the caller has validated; it is written verbatim.
    #[must_use]
    pub(crate) fn session_reject_with_appl_ver(
        &self,
        ref_seq: u64,
        ref_msg_type: &str,
        reason: &RejectReason,
        ref_appl_ver_id: Option<&str>,
    ) -> PendingMessage {
        self.reject_frame(
            ref_seq,
            ref_msg_type,
            reason.ref_tag,
            Some(reason.code),
            ref_appl_ver_id,
            &reason.text,
        )
    }

    /// Builds a session-level Reject (35=3) from its parts; `code` is the
    /// `SessionRejectReason` (373), omitted when `None`.
    fn reject_frame(
        &self,
        ref_seq: u64,
        ref_msg_type: &str,
        ref_tag: Option<u32>,
        code: Option<u32>,
        ref_appl_ver_id: Option<&str>,
        text: &str,
    ) -> PendingMessage {
        let mut message = OutboundMessage::new(MsgType::Reject);
        message.push_uint(45, ref_seq);
        // FIX 4.0 and FIX 4.1 define the Reject as RefSeqNum (45) and Text
        // (58) only: RefTagID (371), RefMsgType (372) and SessionRejectReason
        // (373) arrived with FIX 4.2 (QuickFIX `FIX40.xml` / `FIX41.xml`), so
        // a strict counterparty of those versions would refuse them. The
        // reason travels in Text there.
        if self.reject_has_reason_fields() {
            if let Some(ref_tag) = ref_tag {
                message.push_uint(371, u64::from(ref_tag));
            }
            if !ref_msg_type.is_empty() {
                message.push_str(372, ref_msg_type);
            }
            if let Some(code) = ref_appl_ver_id {
                message.push_str(REF_APPL_VER_ID, code);
            }
            if let Some(code) = code {
                message.push_uint(373, u64::from(code));
            }
        }
        if !text.is_empty() {
            message.push_str(58, text);
        }
        PendingMessage::plain(message)
    }

    /// Builds the answer to an inbound application message that failed
    /// dictionary validation (issue #84, ADR-0031).
    ///
    /// With `business` set, a missing required tag or an unsupported message
    /// type is answered with a BusinessMessageReject (35=j) on FIX 4.2 and
    /// later ([`MessageFactory::business_message_reject`]); everything else
    /// with a session-level Reject (35=3) whose `SessionRejectReason` (373)
    /// is the defect's code on this version ([`validation_reject_code`]),
    /// omitted when the version defines none. The `Text` (58) is the
    /// rejection's value-free text.
    #[must_use]
    pub(crate) fn validation_reject(
        &self,
        ref_seq: u64,
        ref_msg_type: &str,
        rejection: &InboundRejection,
        business: bool,
    ) -> PendingMessage {
        if business
            && self.has_business_message_reject()
            && let Some(reason) = business_reject_reason(rejection.defect())
        {
            return self.business_message_reject(ref_seq, ref_msg_type, reason, rejection.text());
        }
        self.reject_frame(
            ref_seq,
            ref_msg_type,
            rejection.ref_tag(),
            validation_reject_code(self.version, rejection.defect()),
            None,
            rejection.text(),
        )
    }

    /// Builds a BusinessMessageReject (35=j): `RefSeqNum` (45), `RefMsgType`
    /// (372), `BusinessRejectReason` (380) and `Text` (58), the layout FIX
    /// 4.2 and FIX 4.4 define (`spec/FIX42.xml`, `spec/FIX44.xml`).
    #[must_use]
    pub(crate) fn business_message_reject(
        &self,
        ref_seq: u64,
        ref_msg_type: &str,
        reason: u32,
        text: &str,
    ) -> PendingMessage {
        let mut message = OutboundMessage::new(MsgType::BusinessMessageReject);
        message
            .push_uint(45, ref_seq)
            .push_str(372, ref_msg_type)
            .push_uint(380, u64::from(reason));
        if !text.is_empty() {
            message.push_str(58, text);
        }
        PendingMessage::plain(message)
    }

    /// Whether this session's version defines the BusinessMessageReject
    /// (35=j): FIX 4.2 and later, the versions whose Reject carries 373.
    #[must_use]
    const fn has_business_message_reject(&self) -> bool {
        self.reject_has_reason_fields()
    }

    /// Whether this session's Reject (35=3) carries RefTagID (371),
    /// RefMsgType (372) and SessionRejectReason (373): FIX 4.2 and later.
    ///
    /// The match names every version, so a new [`FixVersion`] does not
    /// compile until its Reject layout is decided.
    #[must_use]
    const fn reject_has_reason_fields(&self) -> bool {
        match self.version {
            FixVersion::Fix40 | FixVersion::Fix41 => false,
            FixVersion::Fix42
            | FixVersion::Fix43
            | FixVersion::Fix44
            | FixVersion::Fix50
            | FixVersion::Fix50Sp1
            | FixVersion::Fix50Sp2
            | FixVersion::Fixt11 => true,
        }
    }

    /// Builds the session-level Reject (35=3) for a framed message whose body
    /// does not decode: `RefSeqNum` (45) = `ref_seq`, and on FIX 4.2 and later
    /// `RefMsgType` (372) when the frame's MsgType was valid, then `RefTagID`
    /// (371) and `SessionRejectReason` (373) from the [`MalformedReject`]. The
    /// `Text` (58) is the defect's fixed label and never carries field bytes.
    #[must_use]
    pub(crate) fn malformed_reject(
        &self,
        ref_seq: u64,
        ref_msg_type: Option<&str>,
        reject: MalformedReject,
    ) -> PendingMessage {
        let mut reason = RejectReason::new(reject.code, reject.text);
        if let Some(tag) = reject.ref_tag {
            reason = reason.with_ref_tag(tag);
        }
        self.session_reject(ref_seq, ref_msg_type.unwrap_or(""), &reason)
    }
}

/// The `SessionRejectReason` (373) a validation defect is reported with on
/// `version`, or `None` when the version defines no code for it.
///
/// FIX 4.4 and later (FIXT.1.1 included) define every code a defect maps to.
/// FIX 4.3 has 13, 15 and 16 but not 99 (*Other*, added in FIX 4.4), and FIX
/// 4.2 defines 0 to 11 only (`spec/FIX42.xml`). Where the version has no
/// code, the Reject goes out without 373, and `RefTagID` (371) and `Text`
/// (58) name the problem. FIX 4.0 and 4.1 carry no 373 at all, which
/// [`MessageFactory`] already enforces; `None` is returned for them too.
///
/// The match names every version, so a new [`FixVersion`] does not compile
/// until its codes are decided. A defect added to [`InboundDefect`] after
/// this was written maps to *Other* (99).
#[must_use]
pub(crate) const fn validation_reject_code(
    version: FixVersion,
    defect: InboundDefect,
) -> Option<u32> {
    let code = match defect {
        InboundDefect::InvalidTagNumber => 0,
        InboundDefect::RequiredTagMissing => 1,
        InboundDefect::TagNotDefinedForMessageType => 2,
        InboundDefect::ValueIncorrect => 5,
        InboundDefect::IncorrectDataFormat => 6,
        InboundDefect::InvalidMsgType => 11,
        InboundDefect::TagAppearsMoreThanOnce => 13,
        InboundDefect::RepeatingGroupFieldsOutOfOrder => 15,
        InboundDefect::IncorrectNumInGroupCount => 16,
        // `InboundDefect` is non-exhaustive: a later defect is *Other*.
        _ => 99,
    };
    match version {
        FixVersion::Fix40 | FixVersion::Fix41 => None,
        FixVersion::Fix42 => {
            if code <= 11 {
                Some(code)
            } else {
                None
            }
        }
        // 13, 15 and 16 exist from FIX 4.3; 99 (Other) only from FIX 4.4.
        FixVersion::Fix43 => {
            if code == 99 {
                None
            } else {
                Some(code)
            }
        }
        FixVersion::Fix44
        | FixVersion::Fix50
        | FixVersion::Fix50Sp1
        | FixVersion::Fix50Sp2
        | FixVersion::Fixt11 => Some(code),
    }
}

/// The `BusinessRejectReason` (380) a validation defect is answered with
/// when a BusinessMessageReject is configured, or `None` for a defect that
/// always gets a session-level Reject.
///
/// Only the two content defects qualify: a missing required tag is
/// *Conditionally required field missing* (5), an undefined message type is
/// *Unsupported message type* (3). Every other defect is a syntax problem
/// of the message, which the session layer rejects.
#[must_use]
pub(crate) const fn business_reject_reason(defect: InboundDefect) -> Option<u32> {
    match defect {
        InboundDefect::RequiredTagMissing => Some(5),
        InboundDefect::InvalidMsgType => Some(3),
        _ => None,
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
    fn test_decode_defect_names_msg_type_out_of_place() {
        // MsgType (35) second in the body: the FIX Session Layer's "MsgType not
        // third" garbling.
        let frame = b"8=FIX.4.4\x019=15\x0149=X\x0135=0\x0134=2\x0110=000\x01";
        match decode_frame(frame) {
            Err(err) => {
                assert_eq!(decode_defect(&err), "MsgType (35) not third");
                assert!(decode_is_garbled(&err, frame));
            }
            Ok(_) => panic!("a frame with MsgType out of place must not decode"),
        }
    }

    #[test]
    fn test_decode_defect_never_quotes_input() {
        // An InvalidTag's Display quotes the start of the bad tag; in a garbled
        // frame that can be a Password (554) value whose `=` was lost.
        let err = DecodeError::InvalidTag("554hunter2".to_string());
        assert!(err.to_string().contains("hunter2"));
        let label = decode_defect(&err);
        assert!(!label.contains("hunter2"));
        assert_eq!(label, "invalid tag");
    }

    #[test]
    fn test_decode_is_garbled_covers_header_defects_only() {
        // A frame whose first three fields are in place.
        let sound_header = b"8=FIX.4.4\x019=16\x0135=0\x0134=2\x01abc=1\x0110=000\x01";
        let garbled = [
            DecodeError::InvalidBeginString,
            DecodeError::MissingBodyLength,
            DecodeError::InvalidBodyLength,
            DecodeError::MissingMsgType,
            DecodeError::ChecksumMismatch {
                calculated: 1,
                declared: 2,
            },
        ];
        for err in &garbled {
            assert!(
                decode_is_garbled(err, sound_header),
                "{err:?} is a header defect"
            );
        }

        let malformed_body = [
            DecodeError::InvalidTag("abc".to_string()),
            DecodeError::InvalidFieldValue {
                tag: 95,
                reason: "length field value is not a valid byte count".to_string(),
            },
            DecodeError::MissingRequiredField { tag: 36 },
        ];
        for err in &malformed_body {
            assert!(
                !decode_is_garbled(err, sound_header),
                "{err:?} behind a sound header is a malformed body"
            );
        }

        // A real frame: header and MsgType are fine, a body tag is not.
        match decode_frame(sound_header) {
            Err(err) => {
                assert!(matches!(err, DecodeError::InvalidTag(_)), "{err:?}");
                assert!(!decode_is_garbled(&err, sound_header), "{err:?}");
            }
            Ok(_) => panic!("a frame with a non-numeric tag must not decode"),
        }
    }

    #[test]
    fn test_decode_is_garbled_by_position_of_the_failure() {
        // The third field is `abc=0`: the decoder stops on an invalid tag
        // before it can report MsgType missing, but the failure sits inside
        // the header, so the frame is garbled (MsgType not third).
        let third_field_bad = b"8=FIX.4.4\x019=11\x01abc=0\x0135=0\x0110=000\x01";
        match decode_frame(third_field_bad) {
            Err(err) => {
                assert!(matches!(err, DecodeError::InvalidTag(_)), "{err:?}");
                assert!(decode_is_garbled(&err, third_field_bad), "{err:?}");
            }
            Ok(_) => panic!("a frame with a non-numeric third tag must not decode"),
        }

        // An unacceptable MsgType value in the right place is FIX's invalid
        // MsgType (Reject reason 11), not garbling.
        let invalid_value = DecodeError::InvalidMsgType(ironfix_core::error::MsgTypeError::Empty);
        assert!(!decode_is_garbled(
            &invalid_value,
            b"8=FIX.4.4\x019=4\x0135=\x01"
        ));

        // The structural check itself.
        assert!(header_fields_in_place(b"8=FIX.4.4\x019=5\x0135=0\x01"));
        assert!(!header_fields_in_place(b"8=FIX.4.4\x019=5\x0134=2\x01"));
        assert!(!header_fields_in_place(b"8=FIX.4.4\x019=5"));
        assert!(!header_fields_in_place(b""));
    }

    #[test]
    fn test_logon_frame_roundtrip() {
        let mut factory = factory();
        let logon = factory.logon(30, true, None);
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
        // Not asked for: no NextExpectedMsgSeqNum.
        assert_eq!(raw.get_field_str(789), None);
    }

    #[test]
    fn test_logon_carries_next_expected_msg_seq_num_in_logon_order() {
        // FIX.4.4: 98, 108, 141, 789.
        let mut factory = factory();
        let logon = factory.logon(30, true, Some(1));
        let frame = framed(&mut factory, 1, &logon);
        let raw = decode(&frame);
        assert_eq!(raw.get_field_str(789), Some("1"));
        let body: Vec<u32> = raw
            .fields()
            .map(|field| field.tag)
            .filter(|tag| matches!(tag, 98 | 108 | 141 | 789 | 1137))
            .collect();
        assert_eq!(body, [98, 108, 141, 789]);

        // FIXT.1.1: 789 before DefaultApplVerID (1137), without 141.
        let mut factory = factory_for("FIX.5.0SP2");
        let logon = factory.logon(30, false, Some(42));
        let frame = framed(&mut factory, 7, &logon);
        let raw = decode(&frame);
        assert_eq!(raw.get_field_str(789), Some("42"));
        let body: Vec<u32> = raw
            .fields()
            .map(|field| field.tag)
            .filter(|tag| matches!(tag, 98 | 108 | 141 | 789 | 1137))
            .collect();
        assert_eq!(body, [98, 108, 789, 1137]);
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
        let logon = factory.logon(30, false, None);
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

        let logon = factory.logon(30, false, None);
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
        let logon = factory.logon(30, false, None);
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
            let logon = factory.logon(30, false, None);
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
        let logon = factory.logon(30, false, None);
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

        let resent = match resend_frame(&original, SendingTimePrecision::Millis) {
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

        let twice = match resend_frame(&once, SendingTimePrecision::Millis) {
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

        match resend_frame(&frame, SendingTimePrecision::Millis) {
            Err(ResendError::MissingSendingTime) => {}
            Err(err) => panic!("expected MissingSendingTime, got {err}"),
            Ok(_) => panic!("a frame with no SendingTime must not be replayed"),
        }
    }

    #[test]
    fn test_resend_frame_of_undecodable_bytes_is_a_typed_error() {
        match resend_frame(b"not a fix message", SendingTimePrecision::Millis) {
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

        let resent = match resend_frame(&original, SendingTimePrecision::Millis) {
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

    /// Asserts `value` is a whole-second `UTCTimestamp`, `YYYYMMDD-HH:MM:SS`
    /// with nothing after the seconds, that the inbound parser reads.
    #[track_caller]
    fn assert_whole_seconds(value: Option<&str>, what: &str) {
        let value = some(value, what);
        assert_eq!(value.len(), 17, "{what}: '{value}' is not whole seconds");
        assert!(!value.contains('.'), "{what}: '{value}' carries a fraction");
        assert!(
            parse_utc_timestamp_millis(value).is_some(),
            "{what}: '{value}' does not parse"
        );
    }

    /// Asserts `value` is a millisecond `UTCTimestamp`,
    /// `YYYYMMDD-HH:MM:SS.sss`, that the inbound parser reads.
    #[track_caller]
    fn assert_millis(value: Option<&str>, what: &str) {
        let value = some(value, what);
        assert_eq!(value.len(), 21, "{what}: '{value}' is not milliseconds");
        assert_eq!(value.as_bytes().get(17), Some(&b'.'), "{what}: '{value}'");
        assert!(
            parse_utc_timestamp_millis(value).is_some(),
            "{what}: '{value}' does not parse"
        );
    }

    /// Every framable version, by the precision its 52 and 122 carry.
    const WHOLE_SECOND_VERSIONS: [&str; 2] = ["FIX.4.0", "FIX.4.1"];
    const MILLISECOND_VERSIONS: [&str; 6] = [
        "FIX.4.2",
        "FIX.4.3",
        "FIX.4.4",
        "FIX.5.0",
        "FIX.5.0SP1",
        "FIX.5.0SP2",
    ];

    #[test]
    fn test_encode_stamped_reports_the_sending_time_on_the_wire() {
        for (begin_string, precision) in [
            ("FIX.4.0", SendingTimePrecision::Seconds),
            ("FIX.4.1", SendingTimePrecision::Seconds),
            ("FIX.4.2", SendingTimePrecision::Millis),
            ("FIX.4.4", SendingTimePrecision::Millis),
            ("FIX.5.0SP2", SendingTimePrecision::Millis),
        ] {
            let mut factory = factory_for(begin_string);
            assert_eq!(factory.sending_time_precision(), precision);
            let heartbeat = factory.heartbeat(None);
            let (frame, stamped) = match factory.encode_stamped(4, &heartbeat) {
                Ok((frame, stamped)) => (frame.to_vec(), stamped),
                Err(err) => panic!("factory frame must encode: {err}"),
            };
            let on_wire = precision.truncate(stamped);
            let expected = match precision {
                SendingTimePrecision::Seconds => on_wire.format_seconds().to_string(),
                SendingTimePrecision::Millis => on_wire.format_millis().to_string(),
            };
            assert_eq!(
                decode(&frame).get_field_str(52),
                Some(expected.as_str()),
                "{begin_string}: the reported time formats to the stamped SendingTime (52)"
            );
            let unit = match precision {
                SendingTimePrecision::Seconds => 1_000_000_000,
                SendingTimePrecision::Millis => 1_000_000,
            };
            assert_eq!(
                on_wire.as_nanos() % unit,
                0,
                "{begin_string}: truncated to the precision the wire carries"
            );
        }
    }

    #[test]
    fn test_sending_time_precision_truncates_as_the_formatters_do() {
        let Ok(at) = Timestamp::from_nanos(1_700_000_000_987_654_321) else {
            panic!("a representable instant")
        };
        let seconds = SendingTimePrecision::Seconds.truncate(at);
        assert_eq!(seconds.as_nanos(), 1_700_000_000_000_000_000);
        assert_eq!(seconds.format_seconds(), at.format_seconds());
        let millis = SendingTimePrecision::Millis.truncate(at);
        assert_eq!(millis.as_nanos(), 1_700_000_000_987_000_000);
        assert_eq!(millis.format_millis(), at.format_millis());
    }

    #[test]
    fn test_sending_time_precision_is_whole_seconds_only_before_fix42() {
        use SendingTimePrecision::{Millis, Seconds};
        let expected = [
            (FixVersion::Fix40, Seconds),
            (FixVersion::Fix41, Seconds),
            (FixVersion::Fix42, Millis),
            (FixVersion::Fix43, Millis),
            (FixVersion::Fix44, Millis),
            (FixVersion::Fix50, Millis),
            (FixVersion::Fix50Sp1, Millis),
            (FixVersion::Fix50Sp2, Millis),
            // The transport of FIX 5.0, which carries UTCTimestamp.
            (FixVersion::Fixt11, Millis),
        ];
        // The table names every version, in order.
        assert_eq!(expected.map(|(version, _)| version), FixVersion::ALL);
        for (version, precision) in expected {
            assert_eq!(
                SendingTimePrecision::for_version(version),
                precision,
                "{version}"
            );
        }
    }

    #[test]
    fn test_end_seq_no_infinity_is_999999_only_before_fix42() {
        use EndSeqNoInfinity::{Nines, Zero};
        let expected = [
            (FixVersion::Fix40, Nines),
            (FixVersion::Fix41, Nines),
            (FixVersion::Fix42, Zero),
            (FixVersion::Fix43, Zero),
            (FixVersion::Fix44, Zero),
            (FixVersion::Fix50, Zero),
            (FixVersion::Fix50Sp1, Zero),
            (FixVersion::Fix50Sp2, Zero),
            (FixVersion::Fixt11, Zero),
        ];
        assert_eq!(expected.map(|(version, _)| version), FixVersion::ALL);
        for (version, convention) in expected {
            assert_eq!(
                EndSeqNoInfinity::for_version(version),
                convention,
                "{version}"
            );
        }
        assert_eq!(Nines.sentinel(), 999_999);
        assert_eq!(Zero.sentinel(), 0);
        // FIX 4.0 / 4.1 also read 0 as infinity; later versions keep 999999
        // a literal bound.
        assert!(Nines.is_open_ended(999_999) && Nines.is_open_ended(0));
        assert!(!Nines.is_open_ended(999_998));
        assert!(Zero.is_open_ended(0) && !Zero.is_open_ended(999_999));
    }

    /// An open-ended ResendRequest encodes and decodes with the version's
    /// sentinel; a bounded one keeps its bound on every version.
    #[test]
    fn test_resend_request_end_seq_no_round_trips_per_version() {
        let versions = WHOLE_SECOND_VERSIONS
            .iter()
            .map(|v| (*v, "999999"))
            .chain(MILLISECOND_VERSIONS.iter().map(|v| (*v, "0")));
        for (begin_string, infinity) in versions {
            let mut factory = factory_for(begin_string);
            for (end_seq, wire) in [(0, infinity), (9, "9")] {
                let pending = factory.resend_request(3, end_seq);
                let frame = framed(&mut factory, 7, &pending);
                let raw = decode(&frame);
                // FIX 5.0 and later frame under FIXT.1.1.
                let header = wire_version(begin_string)
                    .ok()
                    .map(FixVersion::begin_string);
                assert_eq!(raw.get_field_str(8), header);
                assert_eq!(raw.get_field_str(35), Some("2"));
                assert_eq!(raw.get_field_str(7), Some("3"));
                assert_eq!(raw.get_field_str(16), Some(wire), "{begin_string}");
                let parsed = raw.get_field_str(16).and_then(|s| s.parse::<u64>().ok());
                let open = parsed.is_some_and(|v| factory.is_open_ended_end_seq_no(v));
                assert_eq!(open, end_seq == 0, "{begin_string}");
            }
        }
    }

    #[test]
    fn test_fix40_and_fix41_frames_stamp_whole_second_sending_times() {
        for begin_string in WHOLE_SECOND_VERSIONS {
            let mut factory = factory_for(begin_string);
            assert_eq!(
                factory.sending_time_precision(),
                SendingTimePrecision::Seconds
            );

            let logon = factory.logon(30, false, None);
            let frame = framed(&mut factory, 1, &logon);
            let raw = decode(&frame);
            assert_eq!(raw.begin_string(), Ok(begin_string));
            assert_whole_seconds(raw.get_field_str(52), begin_string);

            let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
            order.push_str(11, "ORDER-1");
            let frame = framed(&mut factory, 2, &PendingMessage::application(order));
            assert_whole_seconds(decode(&frame).get_field_str(52), begin_string);

            // A GapFill carries 43=Y and its 122 equals its 52: both in
            // whole seconds.
            let gap_fill = factory.sequence_reset_gap_fill(10);
            let frame = framed(&mut factory, 3, &gap_fill);
            let raw = decode(&frame);
            assert_eq!(raw.get_field_str(43), Some("Y"));
            assert_whole_seconds(raw.get_field_str(52), begin_string);
            assert_whole_seconds(raw.get_field_str(122), begin_string);
            assert_eq!(raw.get_field_str(122), raw.get_field_str(52));
        }
    }

    #[test]
    fn test_fix42_and_later_frames_keep_millisecond_sending_times() {
        for configured in MILLISECOND_VERSIONS {
            let mut factory = factory_for(configured);
            assert_eq!(
                factory.sending_time_precision(),
                SendingTimePrecision::Millis
            );

            let heartbeat = factory.heartbeat(None);
            let frame = framed(&mut factory, 1, &heartbeat);
            assert_millis(decode(&frame).get_field_str(52), configured);

            let gap_fill = factory.sequence_reset_gap_fill(10);
            let frame = framed(&mut factory, 2, &gap_fill);
            let raw = decode(&frame);
            assert_millis(raw.get_field_str(52), configured);
            assert_millis(raw.get_field_str(122), configured);
            assert_eq!(raw.get_field_str(122), raw.get_field_str(52));
        }
    }

    #[test]
    fn test_resend_frame_on_fix40_and_fix41_stamps_whole_seconds() {
        for begin_string in WHOLE_SECOND_VERSIONS {
            let mut factory = factory_for(begin_string);
            let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
            order.push_str(11, "ORDER-1");
            let original = framed(&mut factory, 7, &PendingMessage::application(order));
            let original_sending_time = some(
                field_of(&original, 52),
                "the original must carry SendingTime",
            );

            let resent = match resend_frame(&original, factory.sending_time_precision()) {
                Ok(frame) => frame,
                Err(err) => panic!("a {begin_string} frame must rebuild: {err}"),
            };
            let raw = decode(&resent);
            assert_eq!(raw.begin_string(), Ok(begin_string));
            assert_eq!(raw.get_field_str(43), Some("Y"));
            assert_whole_seconds(raw.get_field_str(52), begin_string);
            // Copied from the original 52, which was already whole seconds.
            assert_whole_seconds(raw.get_field_str(122), begin_string);
            assert_eq!(raw.get_field_str(122), Some(original_sending_time.as_str()));
        }
    }

    /// A stored FIX 4.0 or FIX 4.1 frame from before the session wrote
    /// whole seconds, built by hand with the fields `resend_frame` reads.
    fn legacy_frame(begin_string: &str, sending_time: &str, orig: Option<&str>) -> BytesMut {
        let mut encoder = Encoder::new(begin_string);
        encoder.put_str(35, "D");
        encoder.put_str(49, "CLIENT");
        encoder.put_str(56, "VENUE");
        encoder.put_uint(34, 5);
        if let Some(orig) = orig {
            encoder.put_bool(43, true);
            encoder.put_str(52, sending_time);
            encoder.put_str(122, orig);
        } else {
            encoder.put_str(52, sending_time);
        }
        encoder.put_str(11, "ORDER-1");
        built(into_frame(&mut encoder))
    }

    #[test]
    fn test_resend_frame_narrows_a_stored_millisecond_time_at_whole_seconds() {
        for begin_string in WHOLE_SECOND_VERSIONS {
            // First resend: 122 comes from the stored 52, without its fraction.
            let stored = legacy_frame(begin_string, "20260721-10:00:00.999", None);
            let resent = match resend_frame(&stored, SendingTimePrecision::Seconds) {
                Ok(frame) => frame,
                Err(err) => panic!("a stored {begin_string} frame must rebuild: {err}"),
            };
            let raw = decode(&resent);
            assert_whole_seconds(raw.get_field_str(52), begin_string);
            // Truncated, as format_seconds truncates: never rounded up.
            assert_eq!(raw.get_field_str(122), Some("20260721-10:00:00"));

            // Resend of a resend: the existing 122 still wins over the prior
            // replay's 52, and is narrowed the same way.
            let stored = legacy_frame(
                begin_string,
                "20260721-11:30:45.500",
                Some("20260721-09:15:30.250"),
            );
            let resent = match resend_frame(&stored, SendingTimePrecision::Seconds) {
                Ok(frame) => frame,
                Err(err) => panic!("a stored {begin_string} resend must rebuild: {err}"),
            };
            let raw = decode(&resent);
            assert_eq!(raw.fields().filter(|field| field.tag == 122).count(), 1);
            assert_eq!(raw.get_field_str(122), Some("20260721-09:15:30"));
            assert_whole_seconds(raw.get_field_str(52), begin_string);
            assert_eq!(raw.get_field_str(11), Some("ORDER-1"));
        }
    }

    #[test]
    fn test_resend_frame_copies_a_stored_time_verbatim_at_milliseconds() {
        // FIX 4.2 and later accept both forms, so nothing is rewritten: a
        // whole-second original stays whole seconds, a millisecond one stays
        // milliseconds.
        for stored_time in ["20260721-10:00:00", "20260721-10:00:00.999"] {
            let stored = legacy_frame("FIX.4.4", stored_time, None);
            let resent = match resend_frame(&stored, SendingTimePrecision::Millis) {
                Ok(frame) => frame,
                Err(err) => panic!("a stored FIX.4.4 frame must rebuild: {err}"),
            };
            let raw = decode(&resent);
            assert_eq!(raw.get_field_str(122), Some(stored_time));
            assert_millis(raw.get_field_str(52), "FIX.4.4");
        }
    }

    #[test]
    fn test_sending_time_precision_narrow_cuts_only_a_parsed_fraction() {
        let seconds = SendingTimePrecision::Seconds;
        // Every fraction length FIX defines loses its fraction.
        for value in [
            "20260721-10:00:00.1",
            "20260721-10:00:00.123",
            "20260721-10:00:00.123456",
            "20260721-10:00:00.123456789",
        ] {
            assert_eq!(seconds.narrow(value), "20260721-10:00:00", "{value}");
        }
        // Already whole seconds: unchanged.
        assert_eq!(seconds.narrow("20260721-10:00:00"), "20260721-10:00:00");
        // A leap second keeps its 60.
        assert_eq!(seconds.narrow("20261231-23:59:60.500"), "20261231-23:59:60");
        // Not a UTCTimestamp, or not one the parser reads: copied as it is,
        // never cut into a value that looks valid.
        for value in [
            "20261399-10:00:00.123",
            "20260721-10:00:00.",
            "20260721-10:00:00.12a",
            "19691231-23:59:59.999",
            "20260721T10:00:00.123",
            "not a time at all.123",
            "",
        ] {
            assert_eq!(seconds.narrow(value), value, "{value}");
        }
        // At milliseconds nothing is ever rewritten.
        let millis = SendingTimePrecision::Millis;
        for value in ["20260721-10:00:00", "20260721-10:00:00.123", "garbage"] {
            assert_eq!(millis.narrow(value), value, "{value}");
        }
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
    fn test_header_field_reads_the_header_only_and_returns_raw_bytes() {
        let frame = frame_with_raw_fields(&[
            (35, b"A"),
            (49, b"CLIENT"),
            (56, b"VENUE"),
            (34, b"1"),
            (142, b"LON\x80"),
            (52, b"20260721-10:00:00.000"),
            (98, b"0"),
            // Body: a 57 here is not the header's.
            (57, b"DESK"),
        ]);
        let raw = decode(&frame);

        assert_eq!(header_field(&raw, 49), FieldOccurrence::Once(b"CLIENT"));
        assert_eq!(header_field(&raw, 56), FieldOccurrence::Once(b"VENUE"));
        // Not UTF-8, returned as bytes for the caller to bound.
        assert_eq!(header_field(&raw, 142), FieldOccurrence::Once(b"LON\x80"));
        assert_eq!(header_field(&raw, 57), FieldOccurrence::Absent);
        assert_eq!(header_field(&raw, 50), FieldOccurrence::Absent);
        // A body tag is never a header field, even as the first body field.
        assert_eq!(header_field(&raw, 98), FieldOccurrence::Absent);
    }

    #[test]
    fn test_header_field_reports_a_repeated_tag() {
        let frame = frame_with_fields(&[
            (35, "A"),
            (49, "CLIENT"),
            (56, "VENUE"),
            (34, "1"),
            (49, "OTHER"),
            (52, "20260721-10:00:00.000"),
            (98, "0"),
            // A body copy does not make the header's 56 repeated.
            (56, "VENUE"),
        ]);
        let raw = decode(&frame);

        assert_eq!(header_field(&raw, 49), FieldOccurrence::Repeated);
        assert_eq!(header_field(&raw, 56), FieldOccurrence::Once(b"VENUE"));
    }

    #[test]
    fn test_on_behalf_of_sending_time_is_a_header_field() {
        // 370 sits between 34 and 56; the header run must not end at it.
        let frame = frame_with_fields(&[
            (35, "D"),
            (49, "VENUE"),
            (34, "2"),
            (370, "20260721-10:00:00.000"),
            (56, "CLIENT"),
            (52, "20260721-10:00:00.000"),
            (11, "ORDER-1"),
        ]);
        let raw = decode(&frame);

        assert!(is_standard_header_tag(370));
        assert_eq!(header_field(&raw, 56), FieldOccurrence::Once(b"CLIENT"));
        assert_eq!(
            PeerIdentity::new(&config_for("FIX.4.4")).validate(&raw),
            Ok(())
        );
    }

    #[test]
    fn test_peer_identity_checks_configured_location_ids() {
        let mut config = config_for("FIX.4.4");
        config.sender_location_id = Some("NYC".to_string());
        config.target_location_id = Some("LON".to_string());
        let identity = PeerIdentity::new(&config);
        let with_locations = |sender: &str, target: &str| {
            frame_with_fields(&[
                (35, "D"),
                (49, "VENUE"),
                (56, "CLIENT"),
                (34, "2"),
                (142, sender),
                (143, target),
                (52, "20260721-10:00:00.000"),
                (11, "ORDER-1"),
            ])
        };

        // Reversed: the peer's 142 is our target location, its 143 ours.
        assert_eq!(
            identity.validate(&decode(&with_locations("LON", "NYC"))),
            Ok(())
        );
        match identity.validate(&decode(&with_locations("PAR", "NYC"))) {
            Err(mismatch) => assert_eq!(mismatch.tag, 142),
            Ok(()) => panic!("a wrong SenderLocationID must be refused"),
        }
        match identity.validate(&decode(&with_locations("LON", "PAR"))) {
            Err(mismatch) => assert_eq!(mismatch.tag, 143),
            Ok(()) => panic!("a wrong TargetLocationID must be refused"),
        }
        let without = frame_with_fields(&[
            (35, "D"),
            (49, "VENUE"),
            (56, "CLIENT"),
            (34, "2"),
            (52, "20260721-10:00:00.000"),
        ]);
        match identity.validate(&decode(&without)) {
            Err(mismatch) => assert_eq!(mismatch.tag, 142),
            Ok(()) => panic!("a configured location ID must be carried"),
        }
        // Unconfigured: no requirement.
        assert_eq!(
            PeerIdentity::new(&config_for("FIX.4.4")).validate(&decode(&without)),
            Ok(())
        );
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
    fn test_sending_time_guard_accepts_the_current_clock_in_whole_seconds() {
        // What a FIX 4.0 or FIX 4.1 peer, IronFix included, now sends. The
        // guard reads both forms whatever the session's version.
        for begin_string in ["FIX.4.0", "FIX.4.1", "FIX.4.4"] {
            let guard = SendingTimeGuard::new(
                &config_for(begin_string).with_sending_time_tolerance(Duration::from_secs(120)),
            );
            for sending_time in [
                Timestamp::now().format_seconds().as_str(),
                Timestamp::now().format_millis().as_str(),
            ] {
                let frame = frame_sent_at(sending_time);
                assert_eq!(
                    guard.validate(&decode(&frame)),
                    Ok(()),
                    "{begin_string}: {sending_time}"
                );
            }
        }
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

    #[test]
    fn test_header_seq_num_reads_the_header_field() {
        let frame = frame_with_fields(&[
            (35, "A"),
            (49, "VENUE"),
            (56, "CLIENT"),
            (34, "7"),
            (52, "20260721-10:00:00.000"),
        ]);
        assert_eq!(header_seq_num(&decode(&frame)), Some(7));
    }

    #[test]
    fn test_header_seq_num_ignores_a_body_only_seq_num() {
        // 11 (ClOrdID) opens the body; the 34 that follows it is not the
        // standard-header MsgSeqNum and must read as absent.
        let frame = frame_with_fields(&[
            (35, "A"),
            (49, "VENUE"),
            (56, "CLIENT"),
            (52, "20260721-10:00:00.000"),
            (11, "ORDER-1"),
            (34, "7"),
        ]);
        assert_eq!(header_seq_num(&decode(&frame)), None);
    }

    #[test]
    fn test_header_seq_num_rejects_a_non_numeric_value() {
        let frame = frame_with_fields(&[
            (35, "A"),
            (49, "VENUE"),
            (56, "CLIENT"),
            (34, "not-a-number"),
        ]);
        assert_eq!(header_seq_num(&decode(&frame)), None);
    }

    /// Reads a `HeartBtInt` (108) into a Logon fixture.
    fn logon_with_heartbeat(heartbeat: &str) -> Vec<u8> {
        frame_with_fields(&[
            (35, "A"),
            (49, "VENUE"),
            (56, "CLIENT"),
            (34, "1"),
            (52, "20260721-10:00:00.000"),
            (98, "0"),
            (108, heartbeat),
        ])
    }

    #[test]
    fn test_parse_heartbeat_interval_accepts_a_sane_value() {
        assert_eq!(
            parse_heartbeat_interval(&decode(&logon_with_heartbeat("30"))),
            Ok(30)
        );
    }

    #[test]
    fn test_parse_heartbeat_interval_accepts_zero() {
        // 108=0 is legal FIX ("do not send heartbeats") and is not specially
        // handled today; the bound only refuses values that would overflow.
        assert_eq!(
            parse_heartbeat_interval(&decode(&logon_with_heartbeat("0"))),
            Ok(0)
        );
    }

    #[test]
    fn test_parse_heartbeat_interval_rejects_u64_max() {
        // The remote-abort case: Duration::from_secs(u64::MAX) overflows the
        // heartbeat clock's interval + grace, which aborts under panic=abort.
        match parse_heartbeat_interval(&decode(&logon_with_heartbeat(&u64::MAX.to_string()))) {
            Err(HeartBtIntProblem::OutOfRange { secs }) => assert_eq!(secs, u64::MAX),
            other => panic!("u64::MAX HeartBtInt must be out of range, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_heartbeat_interval_rejects_over_one_day() {
        let over = MAX_HEARTBEAT_INTERVAL_SECS + 1;
        match parse_heartbeat_interval(&decode(&logon_with_heartbeat(&over.to_string()))) {
            Err(HeartBtIntProblem::OutOfRange { secs }) => assert_eq!(secs, over),
            other => panic!("an over-a-day HeartBtInt must be out of range, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_heartbeat_interval_rejects_missing_and_malformed() {
        let missing = frame_with_fields(&[(35, "A"), (49, "VENUE"), (56, "CLIENT"), (34, "1")]);
        assert_eq!(
            parse_heartbeat_interval(&decode(&missing)),
            Err(HeartBtIntProblem::Missing)
        );

        match parse_heartbeat_interval(&decode(&logon_with_heartbeat("thirty"))) {
            Err(HeartBtIntProblem::Malformed { value }) => assert_eq!(value, "thirty"),
            other => panic!("a non-numeric HeartBtInt must be malformed, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_heartbeat_interval_echoes_a_bounded_value() {
        let long = "9".repeat(200);
        match parse_heartbeat_interval(&decode(&logon_with_heartbeat(&long))) {
            // 200 nines parse as u64 overflow -> Malformed, echoed bounded.
            Err(HeartBtIntProblem::Malformed { value }) => {
                assert_eq!(value.chars().count(), MAX_ECHOED_HEARTBEAT);
            }
            other => panic!("a 200-digit HeartBtInt must be malformed, got {other:?}"),
        }
    }

    // --- Application versions (FIXT.1.1) ------------------------------------

    /// The guard of a session configured as `begin_string`, with `allowed`
    /// accepted besides its own version.
    fn appl_guard(begin_string: &str, allowed: &[FixVersion]) -> ApplVersionGuard {
        let config = config_for(begin_string).with_allowed_appl_versions(allowed.iter().copied());
        match wire_version(&config.begin_string) {
            Ok(version) => ApplVersionGuard::new(&config, version),
            Err(err) => panic!("test fixture uses an unsupported version: {err}"),
        }
    }

    /// A Logon carrying `extra` after the required fields.
    fn logon_with(extra: &[(u32, &str)]) -> Vec<u8> {
        let mut fields = vec![
            (35, "A"),
            (49, "VENUE"),
            (56, "CLIENT"),
            (34, "1"),
            (98, "0"),
            (108, "30"),
        ];
        fields.extend_from_slice(extra);
        frame_with_fields(&fields)
    }

    /// An application message (ExecutionReport) carrying `extra`.
    fn report_with(extra: &[(u32, &str)]) -> Vec<u8> {
        let mut fields = vec![(35, "8"), (49, "VENUE"), (56, "CLIENT"), (34, "2")];
        fields.extend_from_slice(extra);
        fields.extend_from_slice(&[(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")]);
        frame_with_fields(&fields)
    }

    #[test]
    fn test_appl_guard_accepts_the_configured_default_appl_ver_id() {
        let guard = appl_guard("FIX.5.0SP2", &[]);
        assert_eq!(
            guard.check_logon(&decode(&logon_with(&[(1137, "9")])), true),
            Ok(Some(FixVersion::Fix50Sp2))
        );
    }

    #[test]
    fn test_appl_guard_requires_default_appl_ver_id_on_the_acceptor_only() {
        let guard = appl_guard("FIX.5.0SP2", &[]);
        let logon = logon_with(&[]);
        let refused = guard.check_logon(&decode(&logon), true);
        assert_eq!(refused, Err(ApplVersionProblem::Missing { tag: 1137 }));
        if let Err(problem) = refused {
            let reason = problem.reject_reason();
            assert_eq!(reason.code, 1);
            assert_eq!(reason.ref_tag, Some(1137));
        }
        assert_eq!(guard.check_logon(&decode(&logon), false), Ok(None));
    }

    #[test]
    fn test_appl_guard_refuses_a_default_appl_ver_id_not_accepted() {
        let guard = appl_guard("FIX.5.0SP2", &[]);
        match guard.check_logon(&decode(&logon_with(&[(1137, "7")])), true) {
            Err(problem @ ApplVersionProblem::NotAccepted { .. }) => {
                let text = problem.to_string();
                assert!(text.contains("1137"), "{text}");
                assert!(text.contains("FIX.5.0"), "{text}");
                assert!(text.contains("9 (FIX.5.0SP2)"), "{text}");
                let reason = problem.reject_reason();
                assert_eq!(reason.code, 18);
                assert_eq!(reason.ref_tag, Some(1137));
            }
            other => panic!("1137=7 must not be accepted, got {other:?}"),
        }
    }

    #[test]
    fn test_appl_guard_refuses_a_fix4_code_as_not_accepted() {
        // 2 to 6 decode to FIX 4.x versions, which no FIX 5.0 session
        // accepts: the refusal names the version.
        let guard = appl_guard("FIX.5.0SP2", &[]);
        for (code, version) in [("2", FixVersion::Fix40), ("6", FixVersion::Fix44)] {
            match guard.check_logon(&decode(&logon_with(&[(1137, code)])), true) {
                Err(problem @ ApplVersionProblem::NotAccepted { .. }) => {
                    assert_eq!(
                        problem,
                        ApplVersionProblem::NotAccepted {
                            tag: 1137,
                            code: code.to_string(),
                            version,
                            accepted: "9 (FIX.5.0SP2)".to_string(),
                        }
                    );
                    let text = problem.to_string();
                    assert!(text.contains(&format!("{code} ({version})")), "{text}");
                    assert_eq!(problem.reject_reason().code, 18);
                }
                other => panic!("1137={code} must not be accepted, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_appl_guard_refuses_values_that_name_no_version() {
        let guard = appl_guard("FIX.5.0SP2", &[]);
        for value in ["X", "0", "1", "10", "09"] {
            match guard.check_logon(&decode(&logon_with(&[(1137, value)])), true) {
                Err(ApplVersionProblem::Unknown {
                    tag, value: shown, ..
                }) => {
                    assert_eq!(tag, 1137);
                    assert_eq!(shown, value);
                }
                other => panic!("1137={value} must be unknown, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_appl_guard_refuses_a_repeated_default_appl_ver_id() {
        let guard = appl_guard("FIX.5.0SP2", &[]);
        let logon = logon_with(&[(1137, "9"), (1137, "9")]);
        let refused = guard.check_logon(&decode(&logon), true);
        assert_eq!(refused, Err(ApplVersionProblem::Repeated { tag: 1137 }));
        if let Err(problem) = refused {
            assert_eq!(problem.reject_reason().code, 13);
        }
    }

    #[test]
    fn test_appl_guard_echoes_a_bounded_escaped_value() {
        let guard = appl_guard("FIX.5.0SP2", &[]);
        let long = format!("{}\u{7f}", "A".repeat(200));
        let logon = frame_with_raw_fields(&[
            (35, b"A"),
            (49, b"VENUE"),
            (56, b"CLIENT"),
            (34, b"1"),
            (98, b"0"),
            (108, b"30"),
            (1137, &[0xff, 0xfe]),
        ]);
        match guard.check_logon(&decode(&logon), true) {
            Err(ApplVersionProblem::Unknown { value, .. }) => assert_eq!(value, "\\xff\\xfe"),
            other => panic!("non-UTF-8 1137 must be unknown, got {other:?}"),
        }
        match guard.check_logon(&decode(&logon_with(&[(1137, &long)])), true) {
            Err(ApplVersionProblem::Unknown { value, .. }) => {
                assert_eq!(value, "A".repeat(MAX_ECHOED_APPL_VER_ID));
            }
            other => panic!("an over-long 1137 must be unknown, got {other:?}"),
        }
    }

    #[test]
    fn test_appl_guard_accepts_an_allowed_version_besides_the_configured_one() {
        let guard = appl_guard("FIX.5.0SP2", &[FixVersion::Fix50Sp1]);
        assert_eq!(
            guard.check_logon(&decode(&logon_with(&[(1137, "8")])), true),
            Ok(Some(FixVersion::Fix50Sp1))
        );
        assert_eq!(
            guard.check_application(&decode(&report_with(&[(1128, "8")]))),
            Ok(())
        );
        assert!(matches!(
            guard.check_application(&decode(&report_with(&[(1128, "7")]))),
            Err(ApplVersionProblem::NotAccepted {
                tag: 1128,
                version: FixVersion::Fix50,
                ..
            })
        ));
    }

    #[test]
    fn test_appl_guard_application_message_without_appl_ver_id_passes() {
        let guard = appl_guard("FIX.5.0SP2", &[]);
        assert_eq!(guard.check_application(&decode(&report_with(&[]))), Ok(()));
        assert_eq!(
            guard.check_application(&decode(&report_with(&[(1128, "9")]))),
            Ok(())
        );
    }

    #[test]
    fn test_appl_guard_refuses_a_disallowed_appl_ver_id_with_reason_18() {
        let guard = appl_guard("FIX.5.0SP2", &[]);
        let refused = guard.check_application(&decode(&report_with(&[(1128, "7")])));
        match refused {
            Err(problem) => {
                let reason = problem.reject_reason();
                assert_eq!(reason.code, 18);
                assert_eq!(reason.ref_tag, Some(1128));
                assert!(reason.text.contains("ApplVerID (1128)"), "{}", reason.text);
            }
            Ok(()) => panic!("1128=7 must not be accepted on an SP2 session"),
        }
    }

    #[test]
    fn test_appl_guard_refuses_an_appl_ver_id_outside_the_header() {
        // 1128 is header-only: one after the body opens is out of order
        // (reason 14), whatever its value, accepted or not.
        let guard = appl_guard("FIX.5.0SP2", &[]);
        for value in ["7", "9"] {
            let frame = frame_with_fields(&[
                (35, "8"),
                (49, "VENUE"),
                (56, "CLIENT"),
                (34, "2"),
                (37, "EX-1"),
                (1128, value),
            ]);
            let refused = guard.check_application(&decode(&frame));
            assert_eq!(
                refused,
                Err(ApplVersionProblem::OutsideHeader { tag: 1128 })
            );
            if let Err(problem) = refused {
                let reason = problem.reject_reason();
                assert_eq!(reason.code, 14);
                assert_eq!(reason.ref_tag, Some(1128));
            }
        }
        // A header copy and a body copy: the body one is out of order, which
        // outranks the repetition.
        let both = frame_with_fields(&[
            (35, "8"),
            (1128, "9"),
            (49, "VENUE"),
            (56, "CLIENT"),
            (34, "2"),
            (37, "EX-1"),
            (1128, "9"),
        ]);
        assert_eq!(
            guard.check_application(&decode(&both)),
            Err(ApplVersionProblem::OutsideHeader { tag: 1128 })
        );
    }

    #[test]
    fn test_appl_guard_refuses_an_appl_ver_id_repeated_in_the_header() {
        let guard = appl_guard("FIX.5.0SP2", &[]);
        let frame = frame_with_fields(&[
            (35, "8"),
            (1128, "9"),
            (1128, "9"),
            (49, "VENUE"),
            (56, "CLIENT"),
            (34, "2"),
            (37, "EX-1"),
        ]);
        let refused = guard.check_application(&decode(&frame));
        assert_eq!(refused, Err(ApplVersionProblem::Repeated { tag: 1128 }));
        if let Err(problem) = refused {
            assert_eq!(problem.reject_reason().code, 13);
        }
    }

    #[test]
    fn test_appl_guard_reads_appl_ver_id_anywhere_in_the_header() {
        // After the CompIDs and MsgSeqNum is still the header.
        let guard = appl_guard("FIX.5.0SP2", &[]);
        let frame = frame_with_fields(&[
            (35, "8"),
            (49, "VENUE"),
            (56, "CLIENT"),
            (34, "2"),
            (1128, "7"),
            (37, "EX-1"),
        ]);
        assert!(matches!(
            guard.check_application(&decode(&frame)),
            Err(ApplVersionProblem::NotAccepted { tag: 1128, .. })
        ));
    }

    #[test]
    fn test_session_reject_with_appl_ver_places_ref_appl_ver_id() {
        let mut factory = factory_for("FIX.5.0SP2");
        let reason = RejectReason::new(18, "not accepted").with_ref_tag(1128);
        let pending = factory.session_reject_with_appl_ver(2, "D", &reason, Some("7"));
        let frame = framed(&mut factory, 3, &pending);
        assert_eq!(field_of(&frame, 1130).as_deref(), Some("7"));
        // The FIXT.1.1 Reject layout: 45, 371, 372, 1130, 373, 58.
        let raw = decode(&frame);
        let order: Vec<u32> = raw
            .fields()
            .map(|field| field.tag)
            .filter(|tag| [45, 371, 372, 1130, 373, 58].contains(tag))
            .collect();
        assert_eq!(order, vec![45, 371, 372, 1130, 373, 58]);

        let plain = factory.session_reject(2, "D", &reason);
        assert_eq!(field_of(&framed(&mut factory, 4, &plain), 1130), None);
    }

    #[test]
    fn test_appl_problem_ref_appl_ver_id_names_only_a_refused_1128_code() {
        let guard = appl_guard("FIX.5.0SP2", &[]);
        let refused =
            |extra: &[(u32, &str)]| match guard.check_application(&decode(&report_with(extra))) {
                Err(problem) => problem,
                Ok(()) => panic!("{extra:?} must be refused"),
            };
        assert_eq!(refused(&[(1128, "7")]).ref_appl_ver_id(), Some("7"));
        assert_eq!(refused(&[(1128, "6")]).ref_appl_ver_id(), Some("6"));
        // A value that names no version, and a repetition, name nothing.
        assert_eq!(refused(&[(1128, "0")]).ref_appl_ver_id(), None);
        assert_eq!(refused(&[(1128, "X")]).ref_appl_ver_id(), None);
        assert_eq!(refused(&[(1128, "7"), (1128, "7")]).ref_appl_ver_id(), None);
        // A 1137 problem concerns a Logon, which has no ApplVerID.
        match guard.check_logon(&decode(&logon_with(&[(1137, "7")])), true) {
            Err(problem) => assert_eq!(problem.ref_appl_ver_id(), None),
            Ok(declared) => panic!("1137=7 must be refused, got {declared:?}"),
        }
    }

    #[test]
    fn test_appl_guard_is_off_on_fix4_sessions() {
        for begin_string in ["FIX.4.2", "FIX.4.4"] {
            let guard = appl_guard(begin_string, &[]);
            assert_eq!(guard.check_logon(&decode(&logon_with(&[])), true), Ok(None));
            assert_eq!(
                guard.check_logon(&decode(&logon_with(&[(1137, "7")])), true),
                Ok(None)
            );
            assert_eq!(
                guard.check_application(&decode(&report_with(&[(1128, "7")]))),
                Ok(())
            );
        }
    }

    /// Frames `body` behind `8=FIX.4.4|9=n|` with a correct checksum.
    fn malformed_frame(body: &[u8]) -> Vec<u8> {
        let mut frame = format!("8=FIX.4.4\x019={}\x01", body.len()).into_bytes();
        frame.extend_from_slice(body);
        let sum = frame.iter().map(|&byte| u64::from(byte)).sum::<u64>() % 256;
        frame.extend_from_slice(format!("10={sum:03}\x01").as_bytes());
        frame
    }

    #[test]
    fn test_scan_malformed_header_reads_seq_poss_dup_and_msg_type() {
        let frame = malformed_frame(b"35=D\x0149=A\x0156=B\x0134=17\x0143=Y\x01abc=1\x01");
        assert_eq!(
            scan_malformed_header(&frame),
            MalformedHeader {
                seq: Some(17),
                poss_dup: true,
                msg_type: Some("D"),
            }
        );
    }

    #[test]
    fn test_scan_malformed_header_stops_at_the_body_and_at_a_defect() {
        // A 34 after a body field is not the header MsgSeqNum.
        let body_only = malformed_frame(b"35=0\x0149=A\x0111=X\x0134=5\x01abc=1\x01");
        assert_eq!(scan_malformed_header(&body_only).seq, None);
        // A 34 behind a defect in the header cannot be trusted.
        let behind = malformed_frame(b"35=0\x01abc=1\x0134=5\x01");
        assert_eq!(scan_malformed_header(&behind).seq, None);
        // A repeated or non-numeric 34 is unreadable.
        let repeated = malformed_frame(b"35=0\x0134=5\x0134=6\x01abc=1\x01");
        assert_eq!(scan_malformed_header(&repeated).seq, None);
        let text = malformed_frame(b"35=0\x0134=5a\x01abc=1\x01");
        assert_eq!(scan_malformed_header(&text).seq, None);
        let overflow = malformed_frame(b"35=0\x0134=99999999999999999999\x01abc=1\x01");
        assert_eq!(scan_malformed_header(&overflow).seq, None);
        // An invalid MsgType is not reported.
        let empty_type = malformed_frame(b"35=\x0134=3\x01");
        let header = scan_malformed_header(&empty_type);
        assert_eq!((header.seq, header.msg_type), (Some(3), None));
    }

    #[test]
    fn test_scan_malformed_header_skips_header_data_by_count() {
        // SecureData (91) holds an SOH and a fake 34; the real 34 follows it.
        let frame = malformed_frame(b"35=0\x0190=7\x0191=a\x0134=99\x0134=4\x01abc=1\x01");
        assert_eq!(scan_malformed_header(&frame).seq, Some(4));
        // A count past the frame stops the scan without panicking.
        let short = malformed_frame(b"35=0\x0190=999\x0191=a\x0134=4\x01");
        assert_eq!(scan_malformed_header(&short).seq, None);
    }

    #[test]
    fn test_malformed_reject_maps_each_defect() {
        let cases: [(&[u8], u32, Option<u32>); 6] = [
            (b"35=0\x0134=2\x01abc=1\x01", 0, None),
            (b"35=0\x0134=2\x0195=\x0196=x\x01", 4, Some(95)),
            (b"35=0\x0134=2\x0195=40\x0196=x\x01", 6, Some(96)),
            (b"35=\x0134=2\x01", 11, Some(35)),
            // A DATA payload spelling `<SOH>95=<SOH>` is framed by count and
            // never matched: the failing 95 holds a non-count value, so 6.
            (
                b"35=0\x0134=2\x0195=7\x0196=\x0195=\x01xx\x0195=abc\x0196=q\x01",
                6,
                Some(95),
            ),
            // A zero-padded tag is the same tag: an empty `095=` is 4.
            (b"35=0\x0134=2\x01095=\x0196=x\x01", 4, Some(95)),
        ];
        for (body, code, ref_tag) in cases {
            let frame = malformed_frame(body);
            let Err(err) = decode_frame(&frame) else {
                panic!("fixture must not decode");
            };
            assert!(!decode_is_garbled(&err, &frame), "{err:?}");
            let reject = malformed_reject(&err, &frame);
            assert_eq!((reject.code, reject.ref_tag), (code, ref_tag), "{err:?}");
            assert!(!reject.text.contains('x'), "the Text quotes no value");
        }
    }

    #[test]
    fn test_reject_layout_follows_the_session_version() {
        let reject = MalformedReject {
            code: 0,
            ref_tag: Some(35),
            text: "malformed message: invalid tag number",
        };
        for (begin_string, has_reason) in [
            ("FIX.4.0", false),
            ("FIX.4.1", false),
            ("FIX.4.2", true),
            ("FIX.4.4", true),
        ] {
            let mut factory = factory_for(begin_string);
            let pending = factory.malformed_reject(7, Some("D"), reject);
            let frame = framed(&mut factory, 3, &pending);
            let raw = decode(&frame);
            assert_eq!(raw.get_field_str(45), Some("7"), "{begin_string}");
            assert_eq!(
                raw.get_field_str(58),
                Some("malformed message: invalid tag number")
            );
            for tag in [371, 372, 373] {
                assert_eq!(
                    raw.get_field_str(tag).is_some(),
                    has_reason,
                    "{begin_string} tag {tag}"
                );
            }
        }
        // No RefMsgType when the MsgType was invalid.
        let mut factory = factory();
        let pending = factory.malformed_reject(7, None, reject);
        let frame = framed(&mut factory, 3, &pending);
        assert_eq!(decode(&frame).get_field_str(372), None);
    }
}

#[cfg(test)]
mod validation_reject_tests {
    use super::*;
    use ironfix_core::types::CompId;

    fn factory_for(begin_string: &str) -> MessageFactory {
        let (Ok(sender), Ok(target)) = (CompId::new("CLIENT"), CompId::new("VENUE")) else {
            unreachable!("CLIENT and VENUE are valid CompIds")
        };
        let config = SessionConfig::new(sender, target, begin_string);
        match wire_version(&config.begin_string) {
            Ok(version) => MessageFactory::new(&config, version),
            Err(err) => panic!("unsupported test version: {err}"),
        }
    }

    /// Frames `pending` under MsgSeqNum 3 and returns the reject fields, as
    /// (tag, value) pairs in wire order.
    fn fields(factory: &mut MessageFactory, pending: &PendingMessage) -> Vec<(u32, String)> {
        let frame = match factory.encode(3, pending) {
            Ok(frame) => frame.to_vec(),
            Err(err) => panic!("the reject must encode: {err}"),
        };
        let raw = match decode_frame(&frame) {
            Ok(raw) => raw,
            Err(err) => panic!("the reject must decode: {err}"),
        };
        raw.fields()
            .filter(|field| [35, 45, 58, 371, 372, 373, 380].contains(&field.tag))
            .map(|field| (field.tag, String::from_utf8_lossy(field.value).into_owned()))
            .collect()
    }

    fn get(fields: &[(u32, String)], tag: u32) -> Option<&str> {
        fields
            .iter()
            .find(|(t, _)| *t == tag)
            .map(|(_, value)| value.as_str())
    }

    fn missing_side() -> InboundRejection {
        InboundRejection::new(
            InboundDefect::RequiredTagMissing,
            Some(54),
            "required tag missing: Side(54)",
        )
    }

    #[test]
    fn test_validation_reject_code_per_version() {
        use InboundDefect as D;
        let all = [
            (D::InvalidTagNumber, 0),
            (D::RequiredTagMissing, 1),
            (D::TagNotDefinedForMessageType, 2),
            (D::ValueIncorrect, 5),
            (D::IncorrectDataFormat, 6),
            (D::InvalidMsgType, 11),
            (D::TagAppearsMoreThanOnce, 13),
            (D::RepeatingGroupFieldsOutOfOrder, 15),
            (D::IncorrectNumInGroupCount, 16),
            (D::Other, 99),
        ];
        for (defect, code) in all {
            for version in [FixVersion::Fix40, FixVersion::Fix41] {
                assert_eq!(validation_reject_code(version, defect), None);
            }
            let fix42 = if code <= 11 { Some(code) } else { None };
            assert_eq!(validation_reject_code(FixVersion::Fix42, defect), fix42);
            let fix43 = if code == 99 { None } else { Some(code) };
            assert_eq!(validation_reject_code(FixVersion::Fix43, defect), fix43);
            for version in [
                FixVersion::Fix44,
                FixVersion::Fix50,
                FixVersion::Fix50Sp1,
                FixVersion::Fix50Sp2,
                FixVersion::Fixt11,
            ] {
                assert_eq!(validation_reject_code(version, defect), Some(code));
            }
        }
    }

    #[test]
    fn test_validation_reject_fix44_is_a_session_reject_with_ref_tag() {
        let mut factory = factory_for("FIX.4.4");
        let pending = factory.validation_reject(7, "D", &missing_side(), false);
        let fields = fields(&mut factory, &pending);
        assert_eq!(get(&fields, 35), Some("3"));
        assert_eq!(get(&fields, 45), Some("7"));
        assert_eq!(get(&fields, 371), Some("54"));
        assert_eq!(get(&fields, 372), Some("D"));
        assert_eq!(get(&fields, 373), Some("1"));
        assert_eq!(get(&fields, 58), Some("required tag missing: Side(54)"));
    }

    #[test]
    fn test_validation_reject_fix42_omits_a_code_it_does_not_define() {
        let mut factory = factory_for("FIX.4.2");
        let count = InboundRejection::new(
            InboundDefect::IncorrectNumInGroupCount,
            Some(78),
            "incorrect NumInGroup count for group NoAllocs(78)",
        );
        let pending = factory.validation_reject(7, "J", &count, false);
        let first = fields(&mut factory, &pending);
        assert_eq!(get(&first, 35), Some("3"));
        assert_eq!(get(&first, 371), Some("78"));
        assert_eq!(get(&first, 373), None);
        assert!(get(&first, 58).is_some());
        // A code FIX 4.2 has is sent.
        let pending = factory.validation_reject(8, "D", &missing_side(), false);
        assert_eq!(get(&fields(&mut factory, &pending), 373), Some("1"));
    }

    #[test]
    fn test_validation_reject_fix43_omits_99_and_keeps_16() {
        let mut factory = factory_for("FIX.4.3");
        let other = InboundRejection::new(InboundDefect::Other, None, "too many validation errors");
        let pending = factory.validation_reject(7, "D", &other, false);
        let first = fields(&mut factory, &pending);
        assert_eq!(get(&first, 35), Some("3"));
        assert_eq!(get(&first, 373), None);
        assert_eq!(get(&first, 58), Some("too many validation errors"));
        let count = InboundRejection::new(
            InboundDefect::IncorrectNumInGroupCount,
            Some(453),
            "incorrect NumInGroup count for group NoPartyIDs(453)",
        );
        let pending = factory.validation_reject(8, "D", &count, false);
        let second = fields(&mut factory, &pending);
        assert_eq!(get(&second, 373), Some("16"));
        assert_eq!(get(&second, 371), Some("453"));
        assert!(get(&second, 58).is_some());
    }

    #[test]
    fn test_validation_reject_fix40_carries_text_only() {
        let mut factory = factory_for("FIX.4.0");
        let pending = factory.validation_reject(7, "D", &missing_side(), true);
        let fields = fields(&mut factory, &pending);
        // No BusinessMessageReject before FIX 4.2, and no 371/372/373.
        assert_eq!(get(&fields, 35), Some("3"));
        for tag in [371, 372, 373, 380] {
            assert_eq!(get(&fields, tag), None, "tag {tag}");
        }
        assert_eq!(get(&fields, 58), Some("required tag missing: Side(54)"));
    }

    #[test]
    fn test_validation_reject_business_option_answers_content_defects_with_35_j() {
        let mut factory = factory_for("FIX.4.4");
        let pending = factory.validation_reject(7, "D", &missing_side(), true);
        let bmr = fields(&mut factory, &pending);
        assert_eq!(get(&bmr, 35), Some("j"));
        assert_eq!(get(&bmr, 45), Some("7"));
        assert_eq!(get(&bmr, 372), Some("D"));
        assert_eq!(get(&bmr, 380), Some("5"));
        assert_eq!(get(&bmr, 373), None);
        assert_eq!(get(&bmr, 58), Some("required tag missing: Side(54)"));

        let unknown = InboundRejection::new(InboundDefect::InvalidMsgType, Some(35), "unknown");
        let pending = factory.validation_reject(8, "ZZ", &unknown, true);
        let unsupported = fields(&mut factory, &pending);
        assert_eq!(get(&unsupported, 35), Some("j"));
        assert_eq!(get(&unsupported, 380), Some("3"));

        // A syntax defect stays a session-level Reject.
        let format = InboundRejection::new(
            InboundDefect::IncorrectDataFormat,
            Some(38),
            "incorrect data format for OrderQty(38)",
        );
        let pending = factory.validation_reject(9, "D", &format, true);
        let session = fields(&mut factory, &pending);
        assert_eq!(get(&session, 35), Some("3"));
        assert_eq!(get(&session, 373), Some("6"));
    }

    #[test]
    fn test_validation_reject_fixt_uses_fixt_codes() {
        let mut factory = factory_for("FIX.5.0SP2");
        let dup = InboundRejection::new(
            InboundDefect::TagAppearsMoreThanOnce,
            Some(11),
            "tag ClOrdID(11) appears more than once",
        );
        let pending = factory.validation_reject(7, "D", &dup, false);
        let fields = fields(&mut factory, &pending);
        assert_eq!(get(&fields, 373), Some("13"));
        assert_eq!(get(&fields, 371), Some("11"));
    }
}
