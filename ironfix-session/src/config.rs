/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! Session configuration.
//!
//! [`SessionConfig`] is the typed configuration surface of a FIX session.
//! There is no environment-variable or file-based configuration anywhere in
//! this workspace, by design: a session knob is a typed field with a default,
//! a documented unit and range, and validation.
//!
//! # Where validity is decided
//!
//! [`SessionConfig::validate`] is the single definition of "valid". Two
//! callers use it:
//!
//! - [`SessionConfigBuilder::build`], the canonical constructor — it exposes a
//!   setter for every knob and reports the first violation as a typed
//!   [`SessionConfigError`] instead of panicking.
//! - `ironfix-engine`, before it dials, so an out-of-range knob assembled by
//!   hand through the public fields still cannot reach the wire.
//!
//! [`GarbledFrameLimit`] goes one step further and is valid by construction,
//! like [`CompId`]: [`GarbledFrameLimit::try_new`] is its only constructor.
//!
//! # Ranges
//!
//! | Knob | Unit | Range | Default |
//! |---|---|---|---|
//! | `sender_comp_id` / `target_comp_id` | — | validated by [`CompId`] | required |
//! | `begin_string` | ASCII | 1..=[`MAX_ID_LEN`] bytes, printable ASCII except `=` | `FIX.4.4` |
//! | `heartbeat_interval` | whole seconds | 0 (disabled) or [`MIN_HEARTBEAT_INTERVAL_SECS`]..=[`MAX_HEARTBEAT_INTERVAL_SECS`] | 30 s |
//! | `logon_timeout` / `logout_timeout` | duration | non-zero, at most [`MAX_TIMEOUT`] | 10 s |
//! | `max_message_size` | bytes | [`MIN_MESSAGE_SIZE_LIMIT`]..=[`MAX_MESSAGE_SIZE_LIMIT`] | 1 MiB |
//! | `garbled_frame_limit` | frames within a duration | unset, or 1..=[`MAX_GARBLED_FRAME_LIMIT`] frames within a non-zero window of at most [`MAX_GARBLED_FRAME_WINDOW`] | unset |
//! | `sender_sub_id` / `target_sub_id` | ASCII | unset, or 1..=[`MAX_ID_LEN`] bytes, printable ASCII except `=` | unset |
//! | `sender_location_id` / `target_location_id` | ASCII | as above | unset |
//! | `allowed_appl_versions` | [`FixVersion`] set | empty, or FIX.5.0 / FIX.5.0SP1 / FIX.5.0SP2 on a FIX 5.0 session | empty: the configured version only |
//! | `require_ack_default_appl_ver_id` | flag | any; read by a FIX 5.0 initiator only | `false` |
//! | `send_next_expected_msg_seq_num` | flag | `true` only on FIX.4.4 or a FIXT.1.1 session | `false` |
//! | `gap_policy` | [`GapPolicy`] | `Discard`, or `Queue` with 1..=[`MAX_GAP_QUEUE_MESSAGES`] messages and 1..=[`MAX_GAP_QUEUE_BYTES`] bytes | `Discard` |
//! | `reset_on_*`, `validate_*` | flag | any | see [`SessionConfig::new`] |
//!
//! # `HeartBtInt` (108) is whole seconds
//!
//! Tag 108 carries whole seconds, and `HeartBtInt = 0` means *do not
//! heartbeat* (see the [`crate::heartbeat`] module). A fractional
//! `heartbeat_interval` therefore has no honest wire form: truncating 500 ms
//! to `108=0` would negotiate no heartbeating at all while local timers ran
//! sub-second. Fractional intervals are rejected rather than truncated, and
//! `HeartBtInt = 0` must be asked for explicitly through
//! [`SessionConfigBuilder::disable_heartbeats`].
//!
//! # Application versions on a FIX 5.0 session
//!
//! A FIX 5.0 session is framed as FIXT.1.1: its counterparty declares its
//! default application version in `DefaultApplVerID` (1137) on the Logon, and
//! may name another per message in `ApplVerID` (1128). The session accepts
//! its own configured version (the one `begin_string` names, and the one it
//! stamps in its own 1137 and 1128) and any version in
//! [`SessionConfig::allowed_appl_versions`];
//! [`SessionConfig::accepts_appl_version`] is that rule. `ironfix-engine`
//! enforces it. A FIX 4.x session carries neither field, so the set must be
//! empty there.
//!
//! # `NextExpectedMsgSeqNum` (789) on the Logon
//!
//! FIX.4.4 and FIXT.1.1 define `NextExpectedMsgSeqNum` (789) on the Logon:
//! the next `MsgSeqNum` the sender expects to receive, so each side learns at
//! Logon which of its messages the other missed.
//! [`SessionConfig::send_next_expected_msg_seq_num`] opts a session into it,
//! in both directions: `ironfix-engine` then declares 789 on its own Logon or
//! Logon acknowledgement and acts on the counterparty's. It is bilateral:
//! both sides must enable it. Earlier versions do not define the field, so
//! the flag is refused there
//! ([`SessionConfigError::NextExpectedMsgSeqNumUnsupported`]).

use crate::heartbeat::MAX_HEARTBEAT_INTERVAL_SECS;
use ironfix_core::types::{COMP_ID_MAX_LEN, CompId};
use ironfix_core::version::FixVersion;
use std::num::NonZeroU32;
use std::time::Duration;

/// Smallest `HeartBtInt` (108) this engine will configure, in seconds.
///
/// One second is the smallest interval tag 108 can express. Anything shorter
/// has no wire representation; see the module documentation. Zero is not in
/// this range — it is the separate "heartbeating disabled" case.
pub const MIN_HEARTBEAT_INTERVAL_SECS: u64 = 1;

/// Largest handshake timeout this engine will configure.
///
/// Both `logon_timeout` and `logout_timeout` bound one round trip with the
/// counterparty. Five minutes is far beyond any real venue's response time; a
/// larger value would leave a dead handshake hanging rather than failing it.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(300);

/// Smallest `max_message_size` this engine will configure, in bytes.
///
/// The limit must at least admit the session's own Logon: the standard header
/// with maximum-length CompIDs, SubIDs and LocationIDs plus a Logon body runs
/// to a few hundred bytes. Below this floor the session could not complete its
/// own handshake.
pub const MIN_MESSAGE_SIZE_LIMIT: usize = 512;

/// Largest `max_message_size` this engine will configure, in bytes (64 MiB).
///
/// The codec buffers up to this much per connection before it can reject a
/// frame, so the knob is also a per-connection memory ceiling. 64 MiB is well
/// above the largest realistic FIX message (a mass quote or security list)
/// and far below anything that would let one connection exhaust a host.
pub const MAX_MESSAGE_SIZE_LIMIT: usize = 64 * 1024 * 1024;

/// Maximum length, in bytes, of a configured identity string.
///
/// Applies to `begin_string`, the sub IDs and the location IDs. It is
/// [`COMP_ID_MAX_LEN`], the same bound [`CompId`] applies to tags 49 and 56:
/// these values sit in the same standard header and are written verbatim
/// alongside it.
pub const MAX_ID_LEN: usize = COMP_ID_MAX_LEN;

/// `BeginString` (tag 8) used when the builder is not told otherwise.
const DEFAULT_BEGIN_STRING: &str = "FIX.4.4";

/// `HeartBtInt` (108) used when the builder is not told otherwise.
const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Handshake timeout used when the builder is not told otherwise.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// `max_message_size` used when the builder is not told otherwise (1 MiB).
const DEFAULT_MESSAGE_SIZE_LIMIT: usize = 1024 * 1024;

/// Largest number of garbled frames a [`GarbledFrameLimit`] may allow within
/// its window.
///
/// The engine remembers when each garbled frame in the window arrived, so this
/// is also a per-session memory ceiling (1024 timestamps). It is far above any
/// bound worth configuring: a link that garbles a thousand frames inside one
/// window is not one a session should stay on.
pub const MAX_GARBLED_FRAME_LIMIT: u32 = 1024;

/// Longest window a [`GarbledFrameLimit`] may count garbled frames over (24
/// hours, one trading day).
pub const MAX_GARBLED_FRAME_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// Largest number of messages a [`GapPolicy::Queue`] may hold.
///
/// Each queued message keeps its frame in memory until the gap below it is
/// filled, so this is a per-session ceiling on what a counterparty can make
/// the session hold while a gap is open.
pub const MAX_GAP_QUEUE_MESSAGES: usize = 65_536;

/// Largest number of frame bytes a [`GapPolicy::Queue`] may hold (1 GiB).
pub const MAX_GAP_QUEUE_BYTES: usize = 1024 * 1024 * 1024;

/// What the session does with a message that arrives above the expected
/// `MsgSeqNum` (34) while a gap is open (`doc/fix_operations.md`, "Resend
/// Request").
///
/// Either way the gap is requested with a `ResendRequest` (2): the
/// counterparty cannot know what this session kept, so it resends the whole
/// range. The policy decides only whether the messages received intact above
/// the gap are kept until it is filled.
///
/// - [`GapPolicy::Discard`] (the default): an application message above the
///   gap is dropped and taken from the counterparty's resend. An
///   administrative message is acted on at once and its number left for the
///   resend to gap-fill. This is the behaviour of every release before the
///   policy existed.
/// - [`GapPolicy::Queue`]: messages above the gap are kept, keyed by
///   `MsgSeqNum`, and released in order through the normal in-sequence path
///   once the expectation reaches them; the resent copies, which carry
///   `PossDupFlag` (43) = Y, then arrive below the expectation and are
///   ignored. An administrative message is still acted on at once (a
///   TestRequest is answered, a ResendRequest is served) and only its number
///   is kept, to be consumed in turn; a gapped `SequenceReset`-GapFill is
///   kept whole and applied in turn. A Logout, a `SequenceReset`-Reset and
///   the session's own Logout empty the queue. Past either bound, a further
///   message is discarded as under `Discard`, and the session stays up.
///
/// `ironfix-engine` applies the policy; this crate only describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
#[repr(u8)]
pub enum GapPolicy {
    /// Drop application messages above a gap; the counterparty's resend
    /// delivers them.
    #[default]
    Discard,
    /// Keep messages above a gap, up to both bounds, and release them in
    /// order once the gap is filled.
    Queue {
        /// Most messages held at once, 1..=[`MAX_GAP_QUEUE_MESSAGES`].
        max_messages: usize,
        /// Most frame bytes held at once, counted as the length of each
        /// held frame, 1..=[`MAX_GAP_QUEUE_BYTES`]. An administrative
        /// message, already acted on, counts as a message and holds no bytes.
        max_bytes: usize,
    },
}

/// Reason a session configuration cannot be used.
///
/// Every variant names the offending knob, so the message is actionable
/// without the caller having to guess which setter produced it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionConfigError {
    /// A field with no default was never set on the builder.
    #[error("{field} is required")]
    MissingField {
        /// Name of the field that was never set.
        field: &'static str,
    },

    /// A string knob was set to the empty string.
    ///
    /// An empty value has no wire form: the encoder refuses it, so it would
    /// fail at the first outbound message rather than at configuration time.
    #[error("{field} must not be empty")]
    EmptyField {
        /// Name of the empty field.
        field: &'static str,
    },

    /// A string knob is longer than [`MAX_ID_LEN`] bytes.
    #[error("{field} is {len} bytes, over the {max}-byte maximum")]
    FieldTooLong {
        /// Name of the oversized field.
        field: &'static str,
        /// Length of the configured value, in bytes.
        len: usize,
        /// The maximum accepted, in bytes.
        max: usize,
    },

    /// A string knob carries a byte with no on-the-wire form.
    ///
    /// These values are written verbatim into the standard header, so SOH
    /// would terminate the field early and `=` would open a new tag/value
    /// pair: either byte structurally corrupts every outbound message.
    #[error("{field} contains illegal byte 0x{byte:02x} at position {position}")]
    IllegalByte {
        /// Name of the offending field.
        field: &'static str,
        /// The byte that was refused.
        byte: u8,
        /// Its zero-based position in the value.
        position: usize,
    },

    /// The heartbeat interval is not a whole number of seconds.
    #[error(
        "heartbeat interval {interval:?} is not a whole number of seconds; HeartBtInt (108) is expressed in whole seconds"
    )]
    FractionalHeartbeatInterval {
        /// The configured interval.
        interval: Duration,
    },

    /// The heartbeat interval is outside the supported range.
    #[error("heartbeat interval of {secs}s is outside the supported range {min}s..={max}s")]
    HeartbeatIntervalOutOfRange {
        /// The configured interval, in seconds.
        secs: u64,
        /// The smallest interval accepted, in seconds.
        min: u64,
        /// The largest interval accepted, in seconds.
        max: u64,
    },

    /// A zero heartbeat interval reached the builder without the explicit
    /// opt-in.
    ///
    /// `HeartBtInt = 0` is legal and means "do not heartbeat", which switches
    /// dead-peer detection off for the whole session. That is a decision, not
    /// a default, so it has to be asked for by name.
    #[error(
        "a zero heartbeat interval disables heartbeating entirely (HeartBtInt = 0); call SessionConfigBuilder::disable_heartbeats to ask for that explicitly"
    )]
    HeartbeatDisabledWithoutOptIn,

    /// A handshake timeout is zero or above [`MAX_TIMEOUT`].
    #[error("{field} of {timeout:?} is outside the supported range (non-zero, at most {max:?})")]
    TimeoutOutOfRange {
        /// Name of the offending timeout.
        field: &'static str,
        /// The configured timeout.
        timeout: Duration,
        /// The largest timeout accepted.
        max: Duration,
    },

    /// `max_message_size` is outside its supported range.
    #[error("max_message_size of {size} bytes is outside the supported range {min}..={max}")]
    MessageSizeLimitOutOfRange {
        /// The configured limit, in bytes.
        size: usize,
        /// The smallest limit accepted, in bytes.
        min: usize,
        /// The largest limit accepted, in bytes.
        max: usize,
    },

    /// A [`GarbledFrameLimit`] is outside its supported range.
    #[error(
        "garbled_frame_limit of {max} frames within {window:?} is outside the supported range (1..={max_frames} frames within a non-zero window of at most {max_window:?})"
    )]
    GarbledFrameLimitOutOfRange {
        /// The configured number of garbled frames.
        max: NonZeroU32,
        /// The configured window.
        window: Duration,
        /// The largest number of frames accepted, [`MAX_GARBLED_FRAME_LIMIT`].
        max_frames: u32,
        /// The longest window accepted, [`MAX_GARBLED_FRAME_WINDOW`].
        max_window: Duration,
    },

    /// [`SessionConfig::allowed_appl_versions`] names a version this session
    /// cannot accept.
    ///
    /// Only a FIX 5.0 session (`begin_string` FIX.5.0, FIX.5.0SP1 or
    /// FIX.5.0SP2, framed as FIXT.1.1) carries `DefaultApplVerID` (1137) and
    /// `ApplVerID` (1128), and only those three versions have a code there.
    /// A set on any other session, or a set naming any other version, would
    /// promise a check the session cannot make.
    #[error(
        "allowed_appl_versions names {version}, which a {begin_string} session cannot accept: only a FIX.5.0, FIX.5.0SP1 or FIX.5.0SP2 session (framed as FIXT.1.1) carries DefaultApplVerID (1137) and ApplVerID (1128), and only those versions have a code there"
    )]
    UnusableApplVersion {
        /// The version that cannot be accepted.
        version: FixVersion,
        /// The session's configured `begin_string`.
        begin_string: String,
    },

    /// [`SessionConfig::send_next_expected_msg_seq_num`] is set on a session
    /// whose version does not define `NextExpectedMsgSeqNum` (789).
    ///
    /// The field exists on the Logon from FIX.4.4 on, and on every FIXT.1.1
    /// session (FIX.5.0, FIX.5.0SP1, FIX.5.0SP2). FIX.4.0 to FIX.4.3 do not
    /// define it, so sending it would put an undefined tag on the Logon, and a
    /// counterparty on those versions does not send it.
    #[error(
        "send_next_expected_msg_seq_num is set on a {begin_string} session, but NextExpectedMsgSeqNum (789) is defined only from FIX.4.4 and on FIXT.1.1 sessions (FIX.5.0, FIX.5.0SP1, FIX.5.0SP2)"
    )]
    NextExpectedMsgSeqNumUnsupported {
        /// The session's configured `begin_string`.
        begin_string: String,
    },

    /// A [`GapPolicy::Queue`] bound is zero or above its maximum.
    #[error(
        "gap_policy queue of {max_messages} messages and {max_bytes} bytes is outside the supported range (1..={max_messages_limit} messages and 1..={max_bytes_limit} bytes)"
    )]
    GapQueueOutOfRange {
        /// The configured message bound.
        max_messages: usize,
        /// The configured byte bound.
        max_bytes: usize,
        /// The largest message bound accepted, [`MAX_GAP_QUEUE_MESSAGES`].
        max_messages_limit: usize,
        /// The largest byte bound accepted, [`MAX_GAP_QUEUE_BYTES`].
        max_bytes_limit: usize,
    },
}

/// Bound on garbled inbound frames: the session is closed once
/// [`GarbledFrameLimit::max`] garbled frames arrive within any
/// [`GarbledFrameLimit::window`].
///
/// FIX ignores a garbled message, meaning one whose BeginString (8), BodyLength
/// (9), MsgType (35) position or CheckSum (10) cannot be trusted. It consumes no
/// `MsgSeqNum` (34) and does not count as proof that the peer is alive, so the
/// gap it leaves is recovered by the usual `ResendRequest` (2). The
/// specification sets no limit on how many may be ignored. This bound is the
/// opt-in limit: a link that keeps garbling frames while its valid traffic
/// keeps the session alive is logged out rather than left to recover gap after
/// gap.
///
/// Valid by construction: [`GarbledFrameLimit::try_new`] is the only
/// constructor and enforces the range, so a configuration holding one never
/// needs it re-checked. The count is a [`NonZeroU32`], so a zero bound cannot
/// even be expressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GarbledFrameLimit {
    /// The number of garbled frames within `window` that closes the session.
    max: NonZeroU32,
    /// The sliding window the frames are counted over.
    window: Duration,
}

impl GarbledFrameLimit {
    /// Creates a bound of `max` garbled frames within `window`.
    ///
    /// The session closes on the garbled frame that brings the count inside
    /// the window to `max`; `max = 1` therefore closes it on the first one.
    ///
    /// # Arguments
    /// * `max` - Garbled frames, at most [`MAX_GARBLED_FRAME_LIMIT`]
    /// * `window` - Wall-clock duration, non-zero and at most
    ///   [`MAX_GARBLED_FRAME_WINDOW`]
    ///
    /// # Errors
    /// [`SessionConfigError::GarbledFrameLimitOutOfRange`] when `max` is above
    /// [`MAX_GARBLED_FRAME_LIMIT`] or `window` is outside its range.
    ///
    /// # Examples
    ///
    /// ```
    /// use ironfix_session::config::GarbledFrameLimit;
    /// use std::num::NonZeroU32;
    /// use std::time::Duration;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let five = NonZeroU32::new(5).ok_or("five is not zero")?;
    /// let limit = GarbledFrameLimit::try_new(five, Duration::from_secs(60))?;
    /// assert_eq!(limit.max(), five);
    /// assert!(GarbledFrameLimit::try_new(five, Duration::ZERO).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn try_new(max: NonZeroU32, window: Duration) -> Result<Self, SessionConfigError> {
        if max.get() > MAX_GARBLED_FRAME_LIMIT
            || window.is_zero()
            || window > MAX_GARBLED_FRAME_WINDOW
        {
            return Err(SessionConfigError::GarbledFrameLimitOutOfRange {
                max,
                window,
                max_frames: MAX_GARBLED_FRAME_LIMIT,
                max_window: MAX_GARBLED_FRAME_WINDOW,
            });
        }
        Ok(Self { max, window })
    }

    /// Returns how many garbled frames within the window close the session,
    /// 1..=[`MAX_GARBLED_FRAME_LIMIT`].
    #[must_use]
    pub const fn max(&self) -> NonZeroU32 {
        self.max
    }

    /// Returns the sliding window garbled frames are counted over: non-zero,
    /// at most [`MAX_GARBLED_FRAME_WINDOW`].
    #[must_use]
    pub const fn window(&self) -> Duration {
        self.window
    }
}

/// Validates one identity string written verbatim into the standard header.
///
/// Charset and length match [`CompId`]: printable ASCII (`0x20..=0x7e`)
/// except `=`, at most [`MAX_ID_LEN`] bytes, never empty.
fn validate_id(field: &'static str, value: &str) -> Result<(), SessionConfigError> {
    if value.is_empty() {
        return Err(SessionConfigError::EmptyField { field });
    }
    if value.len() > MAX_ID_LEN {
        return Err(SessionConfigError::FieldTooLong {
            field,
            len: value.len(),
            max: MAX_ID_LEN,
        });
    }
    for (position, &byte) in value.as_bytes().iter().enumerate() {
        let printable = byte.is_ascii_graphic() || byte == b' ';
        if !printable || byte == b'=' {
            return Err(SessionConfigError::IllegalByte {
                field,
                byte,
                position,
            });
        }
    }
    Ok(())
}

/// Validates a [`GapPolicy`]: a queue needs both bounds in range.
const fn validate_gap_policy(policy: GapPolicy) -> Result<(), SessionConfigError> {
    match policy {
        GapPolicy::Discard => Ok(()),
        GapPolicy::Queue {
            max_messages,
            max_bytes,
        } => {
            if max_messages == 0
                || max_messages > MAX_GAP_QUEUE_MESSAGES
                || max_bytes == 0
                || max_bytes > MAX_GAP_QUEUE_BYTES
            {
                return Err(SessionConfigError::GapQueueOutOfRange {
                    max_messages,
                    max_bytes,
                    max_messages_limit: MAX_GAP_QUEUE_MESSAGES,
                    max_bytes_limit: MAX_GAP_QUEUE_BYTES,
                });
            }
            Ok(())
        }
    }
}

/// Validates a handshake timeout: non-zero and at most [`MAX_TIMEOUT`].
fn validate_timeout(field: &'static str, timeout: Duration) -> Result<(), SessionConfigError> {
    if timeout.is_zero() || timeout > MAX_TIMEOUT {
        return Err(SessionConfigError::TimeoutOutOfRange {
            field,
            timeout,
            max: MAX_TIMEOUT,
        });
    }
    Ok(())
}

/// The FIX 5.0 application version `begin_string` names, or `None` when it
/// names no version with an `ApplVerID` code (a FIX 4.x version, bare
/// FIXT.1.1, or no version at all).
fn configured_appl_version(begin_string: &str) -> Option<FixVersion> {
    begin_string
        .parse::<FixVersion>()
        .ok()
        .filter(|version| version.appl_ver_id().is_some())
}

/// Validates [`SessionConfig::allowed_appl_versions`]: empty, or only
/// versions with an `ApplVerID` code on a session whose own version has one.
fn validate_appl_versions(
    begin_string: &str,
    allowed: &[FixVersion],
) -> Result<(), SessionConfigError> {
    let fixt_session = configured_appl_version(begin_string).is_some();
    match allowed
        .iter()
        .find(|version| !fixt_session || version.appl_ver_id().is_none())
    {
        Some(&version) => Err(SessionConfigError::UnusableApplVersion {
            version,
            begin_string: begin_string.to_owned(),
        }),
        None => Ok(()),
    }
}

/// Whether the version `begin_string` names defines `NextExpectedMsgSeqNum`
/// (789) on its Logon: FIX.4.4 and every version framed as FIXT.1.1. A string
/// that names no version defines nothing.
fn defines_next_expected_msg_seq_num(begin_string: &str) -> bool {
    matches!(
        begin_string.parse::<FixVersion>(),
        Ok(FixVersion::Fix44
            | FixVersion::Fix50
            | FixVersion::Fix50Sp1
            | FixVersion::Fix50Sp2
            | FixVersion::Fixt11)
    )
}

/// Validates [`SessionConfig::send_next_expected_msg_seq_num`]: unset, or set
/// on a session whose version defines `NextExpectedMsgSeqNum` (789).
fn validate_next_expected_msg_seq_num(
    begin_string: &str,
    enabled: bool,
) -> Result<(), SessionConfigError> {
    if enabled && !defines_next_expected_msg_seq_num(begin_string) {
        return Err(SessionConfigError::NextExpectedMsgSeqNumUnsupported {
            begin_string: begin_string.to_owned(),
        });
    }
    Ok(())
}

/// Validates the heartbeat interval against what tag 108 can carry.
///
/// [`Duration::ZERO`] is accepted here: it is the legal `HeartBtInt = 0`
/// case. The builder is what insists that zero be asked for explicitly.
fn validate_heartbeat_interval(interval: Duration) -> Result<(), SessionConfigError> {
    if interval.is_zero() {
        return Ok(());
    }
    if interval.subsec_nanos() != 0 {
        return Err(SessionConfigError::FractionalHeartbeatInterval { interval });
    }
    let secs = interval.as_secs();
    if !(MIN_HEARTBEAT_INTERVAL_SECS..=MAX_HEARTBEAT_INTERVAL_SECS).contains(&secs) {
        return Err(SessionConfigError::HeartbeatIntervalOutOfRange {
            secs,
            min: MIN_HEARTBEAT_INTERVAL_SECS,
            max: MAX_HEARTBEAT_INTERVAL_SECS,
        });
    }
    Ok(())
}

/// Configuration for a FIX session.
///
/// Construct one with [`SessionConfigBuilder`], which validates every knob, or
/// start from [`SessionConfig::new`]. The fields are public so a configuration
/// can be read and adjusted directly; [`SessionConfig::validate`] then says
/// whether the result is usable, and `ironfix-engine` calls it before
/// dialling.
///
/// The struct is `#[non_exhaustive]`: outside this crate it cannot be built
/// with a struct literal, so a new knob can be added without breaking callers.
/// Every field keeps its public read and write access.
///
/// # Migrating from a struct literal
///
/// Functional-update syntax is rejected too:
/// `SessionConfig { heartbeat_interval, ..SessionConfig::new(sender, target, "FIX.4.4") }`
/// no longer compiles outside this crate. Start from [`SessionConfig::new`] or
/// [`SessionConfigBuilder`] and either chain the `with_*` setters or assign the
/// public fields on a `let mut` binding:
///
/// ```
/// use ironfix_core::types::CompId;
/// use ironfix_session::SessionConfig;
/// use std::time::Duration;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut config = SessionConfig::new(CompId::new("CLIENT")?, CompId::new("VENUE")?, "FIX.4.4");
/// config.heartbeat_interval = Duration::from_secs(10);
/// let config = config.with_logon_timeout(Duration::from_secs(5));
/// assert_eq!(config.validate(), Ok(()));
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SessionConfig {
    /// Sender CompID (tag 49).
    pub sender_comp_id: CompId,
    /// Target CompID (tag 56).
    pub target_comp_id: CompId,
    /// FIX version BeginString, tag 8 (e.g. `FIX.4.4`).
    ///
    /// 1..=[`MAX_ID_LEN`] bytes of printable ASCII except `=`. Whether the
    /// version can actually be framed is a separate question, answered by
    /// `ironfix-engine`.
    pub begin_string: String,
    /// Heartbeat interval, `HeartBtInt` (108).
    ///
    /// Whole seconds, from [`MIN_HEARTBEAT_INTERVAL_SECS`] to
    /// [`MAX_HEARTBEAT_INTERVAL_SECS`]. [`Duration::ZERO`] is the legal
    /// `HeartBtInt = 0` case and disables heartbeating entirely.
    pub heartbeat_interval: Duration,
    /// Whether to set `ResetSeqNumFlag` (141) on the outbound Logon.
    pub reset_on_logon: bool,
    /// Whether to reset sequence numbers after a graceful Logout.
    pub reset_on_logout: bool,
    /// Whether to reset sequence numbers when the session disconnects.
    pub reset_on_disconnect: bool,
    /// Maximum accepted message size, in bytes.
    ///
    /// From [`MIN_MESSAGE_SIZE_LIMIT`] to [`MAX_MESSAGE_SIZE_LIMIT`]. Also the
    /// per-connection buffering ceiling of the codec.
    pub max_message_size: usize,
    /// How long to wait for the Logon acknowledgement.
    ///
    /// Non-zero, at most [`MAX_TIMEOUT`].
    pub logon_timeout: Duration,
    /// How long to wait for the Logout acknowledgement.
    ///
    /// Non-zero, at most [`MAX_TIMEOUT`].
    pub logout_timeout: Duration,
    /// Whether to validate the `CheckSum` (10) of inbound messages.
    pub validate_checksum: bool,
    /// Whether to validate incoming message length.
    pub validate_length: bool,
    /// Largest difference tolerated, in either direction, between an inbound
    /// message's `SendingTime` (52) and the local clock.
    ///
    /// Units: wall-clock duration. Range: any duration; `Duration::ZERO`
    /// disables `SendingTime` validation entirely, including the presence and
    /// format checks. Default: 120 seconds.
    ///
    /// The default matches the tolerance FIX engines have converged on
    /// (QuickFIX's `MaxLatency`) and is the interval it is worth choosing:
    /// a host synchronised by NTP stays within milliseconds of true time, so
    /// two minutes is orders of magnitude more slack than a healthy peer ever
    /// needs, while a host that is not synchronised at all drifts past two
    /// minutes within days. Anything much tighter starts rejecting sessions
    /// over ordinary drift and queueing latency; anything much looser stops
    /// distinguishing a wrong clock from a right one.
    pub sending_time_tolerance: Duration,
    /// How long an outstanding `ResendRequest` (2) may make no progress before
    /// it is retried, and eventually abandoned.
    ///
    /// Units: wall-clock duration, measured from the moment the request was
    /// sent and restarted by every request that follows it. Any in-sequence
    /// message clears the outstanding request altogether, so this measures a
    /// gap that is not being filled at all, not a slow replay. Range: any
    /// duration; a value below the engine's 100 ms reactor tick simply retries
    /// on the next tick. Default: 10 seconds.
    pub resend_timeout: Duration,
    /// Maximum number of `ResendRequest` (2) messages sent for one gap,
    /// counting the first.
    ///
    /// Once they are spent the session is ended with a Logout rather than left
    /// waiting for a peer that is not answering. Range: 1 and above; 0 is read
    /// as 1, because the first request is unconditional. Default: 3, which
    /// with the default [`SessionConfig::resend_timeout`] bounds an
    /// unrecoverable gap at 30 seconds plus the logout handshake.
    ///
    /// Read it through [`SessionConfig::resend_attempt_limit`], which applies
    /// the lower bound.
    pub max_resend_requests: u32,
    /// Bound on garbled inbound frames, or `None` for no bound.
    ///
    /// A garbled frame (a wrong CheckSum (10), a BodyLength (9) that does not
    /// match the frame, bytes before `8=`) is always ignored, as FIX requires:
    /// it consumes no `MsgSeqNum` (34) and does not refresh the heartbeat
    /// clock, and the gap it leaves is recovered by the usual `ResendRequest`
    /// (2). With a bound, the session is logged out once
    /// [`GarbledFrameLimit::max`] garbled frames arrive within
    /// [`GarbledFrameLimit::window`]. Units and range: see
    /// [`GarbledFrameLimit::try_new`]. Default: `None`.
    ///
    /// No bound is the default because the specification sets none, and the
    /// heartbeat already bounds a peer that sends nothing but garbage: garbled
    /// bytes are not proof of life, so such a peer is timed out by the
    /// TestRequest cycle. The bound is for a link that garbles intermittently
    /// while its valid traffic keeps the session alive, and for
    /// `HeartBtInt = 0`, where there is no heartbeat to fall back on.
    pub garbled_frame_limit: Option<GarbledFrameLimit>,
    /// Optional sender sub ID (tag 50), 1..=[`MAX_ID_LEN`] bytes when set.
    pub sender_sub_id: Option<String>,
    /// Optional target sub ID (tag 57), 1..=[`MAX_ID_LEN`] bytes when set.
    pub target_sub_id: Option<String>,
    /// Optional sender location ID (tag 142), 1..=[`MAX_ID_LEN`] bytes when set.
    pub sender_location_id: Option<String>,
    /// Optional target location ID (tag 143), 1..=[`MAX_ID_LEN`] bytes when set.
    pub target_location_id: Option<String>,
    /// Application versions accepted from the counterparty besides the
    /// session's own, on a FIX 5.0 session.
    ///
    /// The counterparty declares its default application version in
    /// `DefaultApplVerID` (1137) on the Logon and may name another per
    /// application message in `ApplVerID` (1128). The version `begin_string`
    /// names is always accepted: it is the one this session declares and
    /// stamps itself. This set adds others. Default: empty, which accepts the
    /// configured version only. Read the rule through
    /// [`SessionConfig::accepts_appl_version`].
    ///
    /// When the set admits more than one version, which one the counterparty
    /// chose matters to the application: `ironfix-engine` keeps the 1137 it
    /// accepted and exposes it on its `Connection`
    /// (`counterparty_default_appl_version`), as the version of every inbound
    /// message without 1128, and the application can also read 1137 off the
    /// Logon itself in its `from_admin` callback.
    ///
    /// Range: empty, or FIX.5.0, FIX.5.0SP1 and FIX.5.0SP2 on a session whose
    /// `begin_string` is one of them. A FIX 4.x session carries neither field,
    /// so a set there, or a set naming a version without an `ApplVerID` code
    /// (FIX 4.x, bare FIXT.1.1), is refused by [`SessionConfig::validate`]
    /// with [`SessionConfigError::UnusableApplVersion`]. It is a set held in
    /// a `Vec`: duplicates are harmless and order is irrelevant.
    pub allowed_appl_versions: Vec<FixVersion>,
    /// Whether an initiator requires `DefaultApplVerID` (1137) on the Logon
    /// acknowledgement of a FIX 5.0 session (strict mode).
    ///
    /// FIXT.1.1 makes 1137 a required field of every Logon, the
    /// acknowledgement included, but by default the initiator checks the
    /// acknowledgement's 1137 only when present, so an acceptor that omits it
    /// is still accepted. With this flag set, an acknowledgement without 1137
    /// fails the handshake with a session Reject (`SessionRejectReason` 1,
    /// "required tag missing", `RefTagID` 1137) and a Logout. A present 1137
    /// is checked the same way in either mode, against
    /// [`SessionConfig::accepts_appl_version`].
    ///
    /// Range: any flag. Default: `false`. Read only by an initiator on a FIX
    /// 5.0 session: an acceptor always requires 1137 on the Logon it
    /// receives, and a FIX 4.x Logon carries no 1137, so the flag has no
    /// effect there.
    pub require_ack_default_appl_ver_id: bool,
    /// Whether the session uses `NextExpectedMsgSeqNum` (789) on the Logon
    /// exchange, in both directions.
    ///
    /// When set, `ironfix-engine` declares 789 on the session's own Logon (an
    /// initiator) or Logon acknowledgement (an acceptor): the next `MsgSeqNum`
    /// it expects to receive, which is 1 on a Logon declaring
    /// `ResetSeqNumFlag` (141) = Y. It also acts on the 789 the counterparty
    /// declares: a value below the `MsgSeqNum` of the session's own Logon or
    /// acknowledgement makes it resend the messages the counterparty missed,
    /// up to but not including that Logon, once the session is Active; a
    /// value above the next `MsgSeqNum` the session sends (the counterparty
    /// claims messages that were never sent) refuses the Logon with a Logout.
    /// And when both sides declared 789 and the counterparty's Logon or
    /// acknowledgement arrives with a gap below it, the session sends no
    /// `ResendRequest`: the counterparty resends that gap on its own, because
    /// of this session's 789, so its Logon is held and consumed once the gap
    /// is filled. One `ResendRequest` goes out only when the gap makes no
    /// progress for [`SessionConfig::resend_timeout`], a resend that stalls
    /// partway included. When unset, no 789 is sent and a counterparty's 789
    /// is ignored, as before.
    ///
    /// 789 is bilateral: enable it on both sides. A counterparty that uses it
    /// while this session does not may wait on a resend this session never
    /// sends: QuickFIX/C++, for one, acts on an inbound 789 whatever its own
    /// setting, and when it declared 789 itself it sends no `ResendRequest`
    /// for a gapped Logon and runs no resend timer.
    ///
    /// Range: any flag on a FIX.4.4 or FIXT.1.1 session (FIX.5.0, FIX.5.0SP1,
    /// FIX.5.0SP2); `true` on an earlier version is refused by
    /// [`SessionConfig::validate`] with
    /// [`SessionConfigError::NextExpectedMsgSeqNumUnsupported`], since those
    /// versions do not define the field. Default: `false`.
    pub send_next_expected_msg_seq_num: bool,
    /// What happens to messages that arrive above the expected `MsgSeqNum`
    /// (34) while a gap is open: dropped and taken from the resend, or kept
    /// and released in order once the gap is filled. See [`GapPolicy`].
    ///
    /// Range: [`GapPolicy::Discard`], or [`GapPolicy::Queue`] with
    /// 1..=[`MAX_GAP_QUEUE_MESSAGES`] messages and 1..=[`MAX_GAP_QUEUE_BYTES`]
    /// bytes; anything else is refused by [`SessionConfig::validate`] with
    /// [`SessionConfigError::GapQueueOutOfRange`]. Default:
    /// [`GapPolicy::Discard`].
    pub gap_policy: GapPolicy,
}

impl SessionConfig {
    /// Creates a session configuration with the documented defaults: a 30 s
    /// heartbeat, 10 s handshake timeouts, a 1 MiB message limit, checksum and
    /// length validation on, and no sequence resets.
    ///
    /// This applies defaults; it does not validate. `begin_string` is the one
    /// argument that can be malformed — call [`SessionConfig::validate`], or
    /// build through [`SessionConfigBuilder`], to find out before the session
    /// dials.
    ///
    /// # Arguments
    /// * `sender_comp_id` - The sender CompID (tag 49)
    /// * `target_comp_id` - The target CompID (tag 56)
    /// * `begin_string` - The `BeginString` (tag 8), e.g. `FIX.4.4`
    #[must_use]
    pub fn new(
        sender_comp_id: CompId,
        target_comp_id: CompId,
        begin_string: impl Into<String>,
    ) -> Self {
        Self {
            sender_comp_id,
            target_comp_id,
            begin_string: begin_string.into(),
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            reset_on_logon: false,
            reset_on_logout: false,
            reset_on_disconnect: false,
            max_message_size: DEFAULT_MESSAGE_SIZE_LIMIT,
            logon_timeout: DEFAULT_TIMEOUT,
            logout_timeout: DEFAULT_TIMEOUT,
            validate_checksum: true,
            validate_length: true,
            sending_time_tolerance: Duration::from_secs(120),
            resend_timeout: Duration::from_secs(10),
            max_resend_requests: 3,
            garbled_frame_limit: None,
            sender_sub_id: None,
            target_sub_id: None,
            sender_location_id: None,
            target_location_id: None,
            allowed_appl_versions: Vec::new(),
            require_ack_default_appl_ver_id: false,
            send_next_expected_msg_seq_num: false,
            gap_policy: GapPolicy::Discard,
        }
    }

    /// Checks every knob against the ranges documented on the module.
    ///
    /// The CompIDs are not re-checked: [`CompId`] validates its charset and
    /// length at construction, so an illegal one is unrepresentable. The same
    /// holds for `garbled_frame_limit`: [`GarbledFrameLimit::try_new`] is the
    /// only way to obtain one.
    ///
    /// [`Duration::ZERO`] passes as a heartbeat interval — it is the legal
    /// `HeartBtInt = 0`. Only [`SessionConfigBuilder`] requires that case to
    /// be opted into by name.
    ///
    /// # Errors
    /// Returns the first [`SessionConfigError`] found: an empty, oversized or
    /// non-encodable identity string, a fractional or out-of-range heartbeat
    /// interval, a zero or excessive handshake timeout, a message-size
    /// limit outside [`MIN_MESSAGE_SIZE_LIMIT`]..=[`MAX_MESSAGE_SIZE_LIMIT`],
    /// an [`SessionConfig::allowed_appl_versions`] set the session cannot
    /// honour, or [`SessionConfig::send_next_expected_msg_seq_num`] on a
    /// version that does not define `NextExpectedMsgSeqNum` (789), or a
    /// [`GapPolicy::Queue`] bound outside its range.
    pub fn validate(&self) -> Result<(), SessionConfigError> {
        validate_id("begin_string", &self.begin_string)?;
        validate_heartbeat_interval(self.heartbeat_interval)?;
        validate_timeout("logon_timeout", self.logon_timeout)?;
        validate_timeout("logout_timeout", self.logout_timeout)?;

        if !(MIN_MESSAGE_SIZE_LIMIT..=MAX_MESSAGE_SIZE_LIMIT).contains(&self.max_message_size) {
            return Err(SessionConfigError::MessageSizeLimitOutOfRange {
                size: self.max_message_size,
                min: MIN_MESSAGE_SIZE_LIMIT,
                max: MAX_MESSAGE_SIZE_LIMIT,
            });
        }

        let optional = [
            ("sender_sub_id", self.sender_sub_id.as_deref()),
            ("target_sub_id", self.target_sub_id.as_deref()),
            ("sender_location_id", self.sender_location_id.as_deref()),
            ("target_location_id", self.target_location_id.as_deref()),
        ];
        for (field, value) in optional {
            if let Some(value) = value {
                validate_id(field, value)?;
            }
        }
        validate_appl_versions(&self.begin_string, &self.allowed_appl_versions)?;
        validate_next_expected_msg_seq_num(
            &self.begin_string,
            self.send_next_expected_msg_seq_num,
        )?;
        validate_gap_policy(self.gap_policy)
    }

    /// Whether `version` is an application version this session accepts from
    /// its counterparty, in `DefaultApplVerID` (1137) on the Logon or
    /// `ApplVerID` (1128) on an application message.
    ///
    /// True for the version `begin_string` names, which the session declares
    /// and stamps itself, and for every version in
    /// [`SessionConfig::allowed_appl_versions`]; false for anything else, and
    /// always false on a session that is not a FIX 5.0 session (FIX 4.x
    /// carries neither field) or for a version without an `ApplVerID` code.
    /// The rule is pure: it reads no clock and no counterparty state, so the
    /// engine can apply it to each message on its own.
    ///
    /// # Examples
    ///
    /// ```
    /// use ironfix_core::FixVersion;
    /// use ironfix_core::types::CompId;
    /// use ironfix_session::SessionConfig;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = SessionConfig::new(CompId::new("VENUE")?, CompId::new("CLIENT")?, "FIX.5.0SP2")
    ///     .with_allowed_appl_versions([FixVersion::Fix50Sp1]);
    /// assert_eq!(config.validate(), Ok(()));
    /// assert!(config.accepts_appl_version(FixVersion::Fix50Sp2));
    /// assert!(config.accepts_appl_version(FixVersion::Fix50Sp1));
    /// assert!(!config.accepts_appl_version(FixVersion::Fix50));
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn accepts_appl_version(&self, version: FixVersion) -> bool {
        if version.appl_ver_id().is_none() {
            return false;
        }
        match configured_appl_version(&self.begin_string) {
            Some(configured) => {
                version == configured || self.allowed_appl_versions.contains(&version)
            }
            None => false,
        }
    }

    /// Sets the application versions accepted from the counterparty besides
    /// the session's own; an empty set accepts the configured version only.
    ///
    /// FIX.5.0, FIX.5.0SP1 or FIX.5.0SP2, on a FIX 5.0 session. Checked by
    /// [`SessionConfig::validate`], not here. See
    /// [`SessionConfig::allowed_appl_versions`].
    #[must_use]
    pub fn with_allowed_appl_versions(
        mut self,
        versions: impl IntoIterator<Item = FixVersion>,
    ) -> Self {
        self.allowed_appl_versions = versions.into_iter().collect();
        self
    }

    /// Sets whether an initiator requires `DefaultApplVerID` (1137) on the
    /// Logon acknowledgement of a FIX 5.0 session (strict mode). See
    /// [`SessionConfig::require_ack_default_appl_ver_id`].
    #[must_use]
    pub const fn with_require_ack_default_appl_ver_id(mut self, require: bool) -> Self {
        self.require_ack_default_appl_ver_id = require;
        self
    }

    /// Sets whether the session uses `NextExpectedMsgSeqNum` (789) on the
    /// Logon exchange, sending it and acting on the counterparty's.
    ///
    /// `true` only on a FIX.4.4 or FIXT.1.1 session. Checked by
    /// [`SessionConfig::validate`], not here. See
    /// [`SessionConfig::send_next_expected_msg_seq_num`].
    #[must_use]
    pub const fn with_send_next_expected_msg_seq_num(mut self, send: bool) -> Self {
        self.send_next_expected_msg_seq_num = send;
        self
    }

    /// Sets the heartbeat interval, `HeartBtInt` (108).
    ///
    /// Whole seconds, [`MIN_HEARTBEAT_INTERVAL_SECS`]..=[`MAX_HEARTBEAT_INTERVAL_SECS`],
    /// or [`Duration::ZERO`] to disable heartbeating. Checked by
    /// [`SessionConfig::validate`], not here.
    #[must_use]
    pub const fn with_heartbeat_interval(mut self, interval: Duration) -> Self {
        self.heartbeat_interval = interval;
        self
    }

    /// Sets whether the outbound Logon carries `ResetSeqNumFlag` (141) = Y.
    #[must_use]
    pub const fn with_reset_on_logon(mut self, reset: bool) -> Self {
        self.reset_on_logon = reset;
        self
    }

    /// Sets the maximum accepted message size, in bytes.
    ///
    /// [`MIN_MESSAGE_SIZE_LIMIT`]..=[`MAX_MESSAGE_SIZE_LIMIT`]. Checked by
    /// [`SessionConfig::validate`], not here.
    #[must_use]
    pub const fn with_max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    /// Sets how long to wait for the Logon acknowledgement.
    ///
    /// Non-zero, at most [`MAX_TIMEOUT`]. Checked by
    /// [`SessionConfig::validate`], not here.
    #[must_use]
    pub const fn with_logon_timeout(mut self, timeout: Duration) -> Self {
        self.logon_timeout = timeout;
        self
    }

    /// Sets the sender sub ID (tag 50).
    ///
    /// 1..=[`MAX_ID_LEN`] bytes of printable ASCII except `=`. Checked by
    /// [`SessionConfig::validate`], not here.
    #[must_use]
    pub fn with_sender_sub_id(mut self, sub_id: impl Into<String>) -> Self {
        self.sender_sub_id = Some(sub_id.into());
        self
    }

    /// Sets the target sub ID (tag 57).
    ///
    /// 1..=[`MAX_ID_LEN`] bytes of printable ASCII except `=`. Checked by
    /// [`SessionConfig::validate`], not here.
    #[must_use]
    pub fn with_target_sub_id(mut self, sub_id: impl Into<String>) -> Self {
        self.target_sub_id = Some(sub_id.into());
        self
    }

    /// Sets the logout timeout.
    #[must_use]
    pub fn with_logout_timeout(mut self, timeout: Duration) -> Self {
        self.logout_timeout = timeout;
        self
    }

    /// Sets the tolerance applied to an inbound `SendingTime` (52).
    ///
    /// `Duration::ZERO` disables `SendingTime` validation. See
    /// [`SessionConfig::sending_time_tolerance`] for the default and its
    /// rationale.
    #[must_use]
    pub fn with_sending_time_tolerance(mut self, tolerance: Duration) -> Self {
        self.sending_time_tolerance = tolerance;
        self
    }

    /// Sets how long an outstanding `ResendRequest` (2) may make no progress
    /// before it is retried.
    #[must_use]
    pub fn with_resend_timeout(mut self, timeout: Duration) -> Self {
        self.resend_timeout = timeout;
        self
    }

    /// Sets how many `ResendRequest` (2) messages may be sent for one gap,
    /// counting the first. A value of 0 is read as 1.
    #[must_use]
    pub const fn with_max_resend_requests(mut self, attempts: u32) -> Self {
        self.max_resend_requests = attempts;
        self
    }

    /// Sets what happens to messages above a gap; see
    /// [`SessionConfig::gap_policy`]. Checked by [`SessionConfig::validate`].
    #[must_use]
    pub const fn with_gap_policy(mut self, policy: GapPolicy) -> Self {
        self.gap_policy = policy;
        self
    }

    /// Sets the bound on garbled inbound frames; `None` removes it.
    ///
    /// See [`SessionConfig::garbled_frame_limit`] for what the bound does and
    /// why there is none by default.
    #[must_use]
    pub const fn with_garbled_frame_limit(mut self, limit: Option<GarbledFrameLimit>) -> Self {
        self.garbled_frame_limit = limit;
        self
    }

    /// Returns the heartbeat interval as the whole seconds that go into
    /// `HeartBtInt` (108).
    ///
    /// Exact for any configuration that passed [`SessionConfig::validate`],
    /// which is what rules out a fractional interval; on an unvalidated
    /// configuration a sub-second interval would floor to 0, which on the wire
    /// means "do not heartbeat".
    #[must_use]
    pub const fn heartbeat_interval_secs(&self) -> u64 {
        self.heartbeat_interval.as_secs()
    }

    /// Returns how many `ResendRequest` (2) messages may be sent for one gap,
    /// never less than the one that opens the recovery.
    #[must_use]
    pub const fn resend_attempt_limit(&self) -> u32 {
        if self.max_resend_requests == 0 {
            1
        } else {
            self.max_resend_requests
        }
    }
}

/// How the builder was told to configure heartbeating.
///
/// Keeps "no heartbeats, deliberately" distinguishable from "an interval that
/// happens to be zero", which the plain [`Duration`] field cannot express.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeartbeatSetting {
    /// Heartbeat at this interval.
    Interval(Duration),
    /// `HeartBtInt = 0`: do not heartbeat at all.
    Disabled,
}

/// Builder for [`SessionConfig`] — the canonical way to configure a session.
///
/// Every knob has a setter here, and [`SessionConfigBuilder::build`] validates
/// all of them together. The sender and target CompIDs have no default and
/// must be set; everything else falls back to the defaults documented on
/// [`SessionConfig::new`].
///
/// # Example
///
/// ```
/// use ironfix_core::types::CompId;
/// use ironfix_session::config::SessionConfigBuilder;
/// use std::time::Duration;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = SessionConfigBuilder::new()
///     .sender_comp_id(CompId::new("CLIENT")?)
///     .target_comp_id(CompId::new("VENUE")?)
///     .begin_string("FIX.4.4")
///     .heartbeat_interval(Duration::from_secs(30))
///     .sender_sub_id("DESK")
///     .build()?;
///
/// assert_eq!(config.heartbeat_interval_secs(), 30);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct SessionConfigBuilder {
    /// Sender CompID (tag 49); required.
    sender_comp_id: Option<CompId>,
    /// Target CompID (tag 56); required.
    target_comp_id: Option<CompId>,
    /// `BeginString` (tag 8).
    begin_string: String,
    /// Heartbeat configuration, including the explicit "disabled" case.
    heartbeat: HeartbeatSetting,
    /// `ResetSeqNumFlag` (141) on the outbound Logon.
    reset_on_logon: bool,
    /// Reset sequence numbers after a graceful Logout.
    reset_on_logout: bool,
    /// Reset sequence numbers on disconnect.
    reset_on_disconnect: bool,
    /// Maximum accepted message size, in bytes.
    max_message_size: usize,
    /// Logon acknowledgement timeout.
    logon_timeout: Duration,
    /// Logout acknowledgement timeout.
    logout_timeout: Duration,
    /// Validate inbound `CheckSum` (10).
    validate_checksum: bool,
    /// Garbled-frame bound as given, `(max, window)`; checked by `build()`.
    garbled_frame_limit: Option<(NonZeroU32, Duration)>,
    /// Sender sub ID (tag 50).
    sender_sub_id: Option<String>,
    /// Target sub ID (tag 57).
    target_sub_id: Option<String>,
    /// Sender location ID (tag 142).
    sender_location_id: Option<String>,
    /// Target location ID (tag 143).
    target_location_id: Option<String>,
    /// Application versions accepted besides the configured one.
    allowed_appl_versions: Vec<FixVersion>,
    /// Strict mode: require 1137 on the Logon acknowledgement.
    require_ack_default_appl_ver_id: bool,
    /// Use `NextExpectedMsgSeqNum` (789) on the Logon exchange.
    send_next_expected_msg_seq_num: bool,
    /// What happens to messages above a gap.
    gap_policy: GapPolicy,
}

impl Default for SessionConfigBuilder {
    fn default() -> Self {
        Self {
            sender_comp_id: None,
            target_comp_id: None,
            begin_string: DEFAULT_BEGIN_STRING.to_string(),
            heartbeat: HeartbeatSetting::Interval(DEFAULT_HEARTBEAT_INTERVAL),
            reset_on_logon: false,
            reset_on_logout: false,
            reset_on_disconnect: false,
            max_message_size: DEFAULT_MESSAGE_SIZE_LIMIT,
            logon_timeout: DEFAULT_TIMEOUT,
            logout_timeout: DEFAULT_TIMEOUT,
            validate_checksum: true,
            garbled_frame_limit: None,
            sender_sub_id: None,
            target_sub_id: None,
            sender_location_id: None,
            target_location_id: None,
            allowed_appl_versions: Vec::new(),
            require_ack_default_appl_ver_id: false,
            send_next_expected_msg_seq_num: false,
            gap_policy: GapPolicy::Discard,
        }
    }
}

impl SessionConfigBuilder {
    /// Creates a builder holding the defaults documented on
    /// [`SessionConfig::new`].
    #[must_use = "builders do nothing unless .build() is called"]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the sender CompID (tag 49). Required.
    #[must_use = "builders do nothing unless .build() is called"]
    pub fn sender_comp_id(mut self, id: CompId) -> Self {
        self.sender_comp_id = Some(id);
        self
    }

    /// Sets the target CompID (tag 56). Required.
    #[must_use = "builders do nothing unless .build() is called"]
    pub fn target_comp_id(mut self, id: CompId) -> Self {
        self.target_comp_id = Some(id);
        self
    }

    /// Sets the `BeginString` (tag 8), e.g. `FIX.4.4`.
    ///
    /// 1..=[`MAX_ID_LEN`] bytes of printable ASCII except `=`.
    #[must_use = "builders do nothing unless .build() is called"]
    pub fn begin_string(mut self, version: impl Into<String>) -> Self {
        self.begin_string = version.into();
        self
    }

    /// Sets the heartbeat interval, `HeartBtInt` (108).
    ///
    /// Whole seconds, from [`MIN_HEARTBEAT_INTERVAL_SECS`] to
    /// [`MAX_HEARTBEAT_INTERVAL_SECS`]. A fractional or out-of-range value is
    /// refused by [`SessionConfigBuilder::build`]; [`Duration::ZERO`] is
    /// refused there too, because disabling heartbeats is
    /// [`SessionConfigBuilder::disable_heartbeats`].
    #[must_use = "builders do nothing unless .build() is called"]
    pub const fn heartbeat_interval(mut self, interval: Duration) -> Self {
        self.heartbeat = HeartbeatSetting::Interval(interval);
        self
    }

    /// Configures `HeartBtInt` (108) = 0: no Heartbeats, no TestRequests, and
    /// no heartbeat-driven liveness check for the life of the session.
    ///
    /// This is legal FIX and sometimes what a venue asks for, but it means a
    /// dead peer is only noticed when TCP notices. See the
    /// [`crate::heartbeat`] module.
    #[must_use = "builders do nothing unless .build() is called"]
    pub const fn disable_heartbeats(mut self) -> Self {
        self.heartbeat = HeartbeatSetting::Disabled;
        self
    }

    /// Sets whether the outbound Logon carries `ResetSeqNumFlag` (141) = Y.
    #[must_use = "builders do nothing unless .build() is called"]
    pub const fn reset_on_logon(mut self, reset: bool) -> Self {
        self.reset_on_logon = reset;
        self
    }

    /// Sets whether sequence numbers reset after a graceful Logout.
    #[must_use = "builders do nothing unless .build() is called"]
    pub const fn reset_on_logout(mut self, reset: bool) -> Self {
        self.reset_on_logout = reset;
        self
    }

    /// Sets whether sequence numbers reset when the session disconnects.
    #[must_use = "builders do nothing unless .build() is called"]
    pub const fn reset_on_disconnect(mut self, reset: bool) -> Self {
        self.reset_on_disconnect = reset;
        self
    }

    /// Sets the maximum accepted message size, in bytes.
    ///
    /// [`MIN_MESSAGE_SIZE_LIMIT`]..=[`MAX_MESSAGE_SIZE_LIMIT`].
    #[must_use = "builders do nothing unless .build() is called"]
    pub const fn max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    /// Sets how long to wait for the Logon acknowledgement.
    ///
    /// Non-zero, at most [`MAX_TIMEOUT`].
    #[must_use = "builders do nothing unless .build() is called"]
    pub const fn logon_timeout(mut self, timeout: Duration) -> Self {
        self.logon_timeout = timeout;
        self
    }

    /// Sets how long to wait for the Logout acknowledgement.
    ///
    /// Non-zero, at most [`MAX_TIMEOUT`].
    #[must_use = "builders do nothing unless .build() is called"]
    pub const fn logout_timeout(mut self, timeout: Duration) -> Self {
        self.logout_timeout = timeout;
        self
    }

    /// Sets whether inbound `CheckSum` (10) is validated.
    #[must_use = "builders do nothing unless .build() is called"]
    pub const fn validate_checksum(mut self, validate: bool) -> Self {
        self.validate_checksum = validate;
        self
    }

    /// Closes the session once `max` garbled inbound frames arrive within
    /// `window`.
    ///
    /// `max` is a frame count, 1..=[`MAX_GARBLED_FRAME_LIMIT`]; `window` is a
    /// wall-clock duration, non-zero and at most [`MAX_GARBLED_FRAME_WINDOW`].
    /// An out-of-range pair is refused by [`SessionConfigBuilder::build`]. See
    /// [`SessionConfig::garbled_frame_limit`]; without this call there is no
    /// bound.
    #[must_use = "builders do nothing unless .build() is called"]
    pub const fn garbled_frame_limit(mut self, max: NonZeroU32, window: Duration) -> Self {
        self.garbled_frame_limit = Some((max, window));
        self
    }

    /// Sets the sender sub ID (tag 50).
    ///
    /// 1..=[`MAX_ID_LEN`] bytes of printable ASCII except `=`.
    #[must_use = "builders do nothing unless .build() is called"]
    pub fn sender_sub_id(mut self, sub_id: impl Into<String>) -> Self {
        self.sender_sub_id = Some(sub_id.into());
        self
    }

    /// Sets the target sub ID (tag 57).
    ///
    /// 1..=[`MAX_ID_LEN`] bytes of printable ASCII except `=`.
    #[must_use = "builders do nothing unless .build() is called"]
    pub fn target_sub_id(mut self, sub_id: impl Into<String>) -> Self {
        self.target_sub_id = Some(sub_id.into());
        self
    }

    /// Sets the sender location ID (tag 142).
    ///
    /// 1..=[`MAX_ID_LEN`] bytes of printable ASCII except `=`.
    #[must_use = "builders do nothing unless .build() is called"]
    pub fn sender_location_id(mut self, location_id: impl Into<String>) -> Self {
        self.sender_location_id = Some(location_id.into());
        self
    }

    /// Sets the target location ID (tag 143).
    ///
    /// 1..=[`MAX_ID_LEN`] bytes of printable ASCII except `=`.
    #[must_use = "builders do nothing unless .build() is called"]
    pub fn target_location_id(mut self, location_id: impl Into<String>) -> Self {
        self.target_location_id = Some(location_id.into());
        self
    }

    /// Sets the application versions accepted from the counterparty in
    /// `DefaultApplVerID` (1137) and `ApplVerID` (1128) besides the session's
    /// own; without this call, the configured version only.
    ///
    /// FIX.5.0, FIX.5.0SP1 or FIX.5.0SP2, on a FIX 5.0 session. Anything else
    /// is refused by [`SessionConfigBuilder::build`] with
    /// [`SessionConfigError::UnusableApplVersion`]. See
    /// [`SessionConfig::allowed_appl_versions`].
    #[must_use = "builders do nothing unless .build() is called"]
    pub fn allowed_appl_versions(mut self, versions: impl IntoIterator<Item = FixVersion>) -> Self {
        self.allowed_appl_versions = versions.into_iter().collect();
        self
    }

    /// Sets whether an initiator requires `DefaultApplVerID` (1137) on the
    /// Logon acknowledgement of a FIX 5.0 session (strict mode; default
    /// `false`). See [`SessionConfig::require_ack_default_appl_ver_id`].
    #[must_use = "builders do nothing unless .build() is called"]
    pub const fn require_ack_default_appl_ver_id(mut self, require: bool) -> Self {
        self.require_ack_default_appl_ver_id = require;
        self
    }

    /// Sets whether the session uses `NextExpectedMsgSeqNum` (789) on the
    /// Logon exchange, sending it and acting on the counterparty's (default
    /// `false`).
    ///
    /// `true` only on a FIX.4.4 or FIXT.1.1 session; anything earlier is
    /// refused by [`SessionConfigBuilder::build`] with
    /// [`SessionConfigError::NextExpectedMsgSeqNumUnsupported`]. See
    /// [`SessionConfig::send_next_expected_msg_seq_num`].
    #[must_use = "builders do nothing unless .build() is called"]
    pub const fn send_next_expected_msg_seq_num(mut self, send: bool) -> Self {
        self.send_next_expected_msg_seq_num = send;
        self
    }

    /// Sets what happens to messages above a gap (default
    /// [`GapPolicy::Discard`]); a [`GapPolicy::Queue`] bound outside its
    /// range is refused by [`SessionConfigBuilder::build`] with
    /// [`SessionConfigError::GapQueueOutOfRange`]. See
    /// [`SessionConfig::gap_policy`].
    #[must_use = "builders do nothing unless .build() is called"]
    pub const fn gap_policy(mut self, policy: GapPolicy) -> Self {
        self.gap_policy = policy;
        self
    }

    /// Builds the configuration, validating every knob.
    ///
    /// # Errors
    /// Returns [`SessionConfigError::MissingField`] if either CompID was never
    /// set, [`SessionConfigError::HeartbeatDisabledWithoutOptIn`] if
    /// [`SessionConfigBuilder::heartbeat_interval`] was given
    /// [`Duration::ZERO`] instead of calling
    /// [`SessionConfigBuilder::disable_heartbeats`], and
    /// [`SessionConfigError::GarbledFrameLimitOutOfRange`] for an out-of-range
    /// [`SessionConfigBuilder::garbled_frame_limit`]. Everything else is the
    /// first violation reported by [`SessionConfig::validate`].
    pub fn build(self) -> Result<SessionConfig, SessionConfigError> {
        let sender_comp_id = self
            .sender_comp_id
            .ok_or(SessionConfigError::MissingField {
                field: "sender_comp_id",
            })?;
        let target_comp_id = self
            .target_comp_id
            .ok_or(SessionConfigError::MissingField {
                field: "target_comp_id",
            })?;

        let heartbeat_interval = match self.heartbeat {
            HeartbeatSetting::Disabled => Duration::ZERO,
            HeartbeatSetting::Interval(interval) if interval.is_zero() => {
                return Err(SessionConfigError::HeartbeatDisabledWithoutOptIn);
            }
            HeartbeatSetting::Interval(interval) => interval,
        };

        let garbled_frame_limit = self
            .garbled_frame_limit
            .map(|(max, window)| GarbledFrameLimit::try_new(max, window))
            .transpose()?;

        let config = SessionConfig {
            sender_comp_id,
            target_comp_id,
            begin_string: self.begin_string,
            heartbeat_interval,
            reset_on_logon: self.reset_on_logon,
            reset_on_logout: self.reset_on_logout,
            reset_on_disconnect: self.reset_on_disconnect,
            max_message_size: self.max_message_size,
            logon_timeout: self.logon_timeout,
            logout_timeout: self.logout_timeout,
            validate_checksum: self.validate_checksum,
            // Inbound-hardening knobs are not exposed on the builder; they take
            // the same defaults as `SessionConfig::new` and are tuned through
            // the fluent `SessionConfig::with_*` setters after `build()`.
            validate_length: true,
            sending_time_tolerance: Duration::from_secs(120),
            resend_timeout: Duration::from_secs(10),
            max_resend_requests: 3,
            garbled_frame_limit,
            sender_sub_id: self.sender_sub_id,
            target_sub_id: self.target_sub_id,
            sender_location_id: self.sender_location_id,
            target_location_id: self.target_location_id,
            allowed_appl_versions: self.allowed_appl_versions,
            require_ack_default_appl_ver_id: self.require_ack_default_appl_ver_id,
            send_next_expected_msg_seq_num: self.send_next_expected_msg_seq_num,
            gap_policy: self.gap_policy,
        };
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a CompID, failing the test rather than the session.
    #[track_caller]
    fn comp_id(value: &str) -> CompId {
        match CompId::new(value) {
            Ok(id) => id,
            Err(err) => panic!("test CompID '{value}' must be valid: {err}"),
        }
    }

    /// A builder with only the required knobs set.
    fn required() -> SessionConfigBuilder {
        SessionConfigBuilder::new()
            .sender_comp_id(comp_id("SENDER"))
            .target_comp_id(comp_id("TARGET"))
    }

    /// Unwraps a build that the test expects to succeed.
    #[track_caller]
    fn built(builder: SessionConfigBuilder) -> SessionConfig {
        match builder.build() {
            Ok(config) => config,
            Err(err) => panic!("configuration must build: {err}"),
        }
    }

    /// Returns the error from a build the test expects to fail.
    #[track_caller]
    fn build_error(builder: SessionConfigBuilder) -> SessionConfigError {
        match builder.build() {
            Ok(_) => panic!("configuration must not build"),
            Err(err) => err,
        }
    }

    // --- Defaults ------------------------------------------------------------

    #[test]
    fn test_session_config_new_applies_documented_defaults() {
        let config = SessionConfig::new(comp_id("SENDER"), comp_id("TARGET"), "FIX.4.4");

        assert_eq!(config.sender_comp_id.as_str(), "SENDER");
        assert_eq!(config.target_comp_id.as_str(), "TARGET");
        assert_eq!(config.begin_string, "FIX.4.4");
        assert_eq!(config.heartbeat_interval, Duration::from_secs(30));
        assert_eq!(config.logon_timeout, Duration::from_secs(10));
        assert_eq!(config.logout_timeout, Duration::from_secs(10));
        assert_eq!(config.max_message_size, 1024 * 1024);
        assert!(config.validate_checksum);
        assert!(!config.reset_on_logon);
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn test_builder_defaults_match_session_config_new() {
        let built_config = built(required());
        let direct = SessionConfig::new(comp_id("SENDER"), comp_id("TARGET"), "FIX.4.4");

        assert_eq!(built_config.begin_string, direct.begin_string);
        assert_eq!(built_config.heartbeat_interval, direct.heartbeat_interval);
        assert_eq!(built_config.logon_timeout, direct.logon_timeout);
        assert_eq!(built_config.logout_timeout, direct.logout_timeout);
        assert_eq!(built_config.max_message_size, direct.max_message_size);
        assert_eq!(built_config.validate_checksum, direct.validate_checksum);
    }

    // --- Required fields -----------------------------------------------------

    #[test]
    fn test_build_without_sender_comp_id_reports_missing_field() {
        let builder = SessionConfigBuilder::new().target_comp_id(comp_id("TARGET"));
        assert_eq!(
            build_error(builder),
            SessionConfigError::MissingField {
                field: "sender_comp_id"
            }
        );
    }

    #[test]
    fn test_build_without_target_comp_id_reports_missing_field() {
        let builder = SessionConfigBuilder::new().sender_comp_id(comp_id("SENDER"));
        assert_eq!(
            build_error(builder),
            SessionConfigError::MissingField {
                field: "target_comp_id"
            }
        );
    }

    // --- Every setter lands in the built configuration -----------------------

    #[test]
    fn test_builder_setters_land_in_the_built_config() {
        let config = built(
            required()
                .begin_string("FIX.4.2")
                .heartbeat_interval(Duration::from_secs(60))
                .reset_on_logon(true)
                .reset_on_logout(true)
                .reset_on_disconnect(true)
                .max_message_size(4096)
                .logon_timeout(Duration::from_secs(5))
                .logout_timeout(Duration::from_secs(7))
                .validate_checksum(false)
                .sender_sub_id("SDESK")
                .target_sub_id("TDESK")
                .sender_location_id("LON")
                .target_location_id("NYC"),
        );

        assert_eq!(config.sender_comp_id.as_str(), "SENDER");
        assert_eq!(config.target_comp_id.as_str(), "TARGET");
        assert_eq!(config.begin_string, "FIX.4.2");
        assert_eq!(config.heartbeat_interval, Duration::from_secs(60));
        assert!(config.reset_on_logon);
        assert!(config.reset_on_logout);
        assert!(config.reset_on_disconnect);
        assert_eq!(config.max_message_size, 4096);
        assert_eq!(config.logon_timeout, Duration::from_secs(5));
        assert_eq!(config.logout_timeout, Duration::from_secs(7));
        assert!(!config.validate_checksum);
        assert_eq!(config.sender_sub_id.as_deref(), Some("SDESK"));
        assert_eq!(config.target_sub_id.as_deref(), Some("TDESK"));
        assert_eq!(config.sender_location_id.as_deref(), Some("LON"));
        assert_eq!(config.target_location_id.as_deref(), Some("NYC"));
    }

    // --- Heartbeat interval --------------------------------------------------

    #[test]
    fn test_build_with_fractional_heartbeat_interval_is_rejected() {
        let interval = Duration::from_millis(500);
        assert_eq!(
            build_error(required().heartbeat_interval(interval)),
            SessionConfigError::FractionalHeartbeatInterval { interval }
        );
    }

    #[test]
    fn test_build_with_sub_second_heartbeat_never_truncates_to_zero() {
        // The defect this replaces: 500ms floored to HeartBtInt=0, which now
        // means "no heartbeating at all" on the wire.
        assert!(
            required()
                .heartbeat_interval(Duration::from_millis(500))
                .build()
                .is_err()
        );
    }

    #[test]
    fn test_build_with_zero_heartbeat_interval_requires_the_explicit_opt_in() {
        assert_eq!(
            build_error(required().heartbeat_interval(Duration::ZERO)),
            SessionConfigError::HeartbeatDisabledWithoutOptIn
        );
    }

    #[test]
    fn test_disable_heartbeats_builds_a_zero_interval() {
        let config = built(required().disable_heartbeats());
        assert_eq!(config.heartbeat_interval, Duration::ZERO);
        assert_eq!(config.heartbeat_interval_secs(), 0);
    }

    #[test]
    fn test_build_with_heartbeat_interval_above_the_ceiling_is_rejected() {
        let secs = MAX_HEARTBEAT_INTERVAL_SECS + 1;
        assert_eq!(
            build_error(required().heartbeat_interval(Duration::from_secs(secs))),
            SessionConfigError::HeartbeatIntervalOutOfRange {
                secs,
                min: MIN_HEARTBEAT_INTERVAL_SECS,
                max: MAX_HEARTBEAT_INTERVAL_SECS,
            }
        );
    }

    #[test]
    fn test_build_accepts_the_heartbeat_interval_bounds() {
        let min =
            built(required().heartbeat_interval(Duration::from_secs(MIN_HEARTBEAT_INTERVAL_SECS)));
        assert_eq!(min.heartbeat_interval_secs(), MIN_HEARTBEAT_INTERVAL_SECS);

        let max =
            built(required().heartbeat_interval(Duration::from_secs(MAX_HEARTBEAT_INTERVAL_SECS)));
        assert_eq!(max.heartbeat_interval_secs(), MAX_HEARTBEAT_INTERVAL_SECS);
    }

    #[test]
    fn test_heartbeat_interval_secs_equals_the_configured_whole_seconds() {
        let config = built(required().heartbeat_interval(Duration::from_secs(45)));
        assert_eq!(
            config.heartbeat_interval_secs(),
            config.heartbeat_interval.as_secs()
        );
        assert_eq!(config.heartbeat_interval_secs(), 45);
    }

    // --- BeginString ---------------------------------------------------------

    #[test]
    fn test_build_with_empty_begin_string_is_rejected() {
        assert_eq!(
            build_error(required().begin_string("")),
            SessionConfigError::EmptyField {
                field: "begin_string"
            }
        );
    }

    #[test]
    fn test_build_with_soh_in_begin_string_is_rejected() {
        assert_eq!(
            build_error(required().begin_string("FIX\x014.4")),
            SessionConfigError::IllegalByte {
                field: "begin_string",
                byte: 0x01,
                position: 3,
            }
        );
    }

    #[test]
    fn test_build_with_overlong_begin_string_is_rejected() {
        let long = "F".repeat(MAX_ID_LEN + 1);
        assert_eq!(
            build_error(required().begin_string(long)),
            SessionConfigError::FieldTooLong {
                field: "begin_string",
                len: MAX_ID_LEN + 1,
                max: MAX_ID_LEN,
            }
        );
    }

    // --- Timeouts ------------------------------------------------------------

    #[test]
    fn test_build_with_zero_logon_timeout_is_rejected() {
        assert_eq!(
            build_error(required().logon_timeout(Duration::ZERO)),
            SessionConfigError::TimeoutOutOfRange {
                field: "logon_timeout",
                timeout: Duration::ZERO,
                max: MAX_TIMEOUT,
            }
        );
    }

    #[test]
    fn test_build_with_zero_logout_timeout_is_rejected() {
        assert_eq!(
            build_error(required().logout_timeout(Duration::ZERO)),
            SessionConfigError::TimeoutOutOfRange {
                field: "logout_timeout",
                timeout: Duration::ZERO,
                max: MAX_TIMEOUT,
            }
        );
    }

    #[test]
    fn test_build_with_excessive_logon_timeout_is_rejected() {
        let timeout = MAX_TIMEOUT + Duration::from_secs(1);
        assert_eq!(
            build_error(required().logon_timeout(timeout)),
            SessionConfigError::TimeoutOutOfRange {
                field: "logon_timeout",
                timeout,
                max: MAX_TIMEOUT,
            }
        );
    }

    #[test]
    fn test_build_accepts_a_sub_second_timeout() {
        // Timeouts are not wire values: unlike HeartBtInt they may be
        // fractional, and short ones are how a test drives the handshake.
        let config = built(required().logon_timeout(Duration::from_millis(300)));
        assert_eq!(config.logon_timeout, Duration::from_millis(300));
    }

    // --- Message size limit --------------------------------------------------

    #[test]
    fn test_build_with_zero_max_message_size_is_rejected() {
        assert_eq!(
            build_error(required().max_message_size(0)),
            SessionConfigError::MessageSizeLimitOutOfRange {
                size: 0,
                min: MIN_MESSAGE_SIZE_LIMIT,
                max: MAX_MESSAGE_SIZE_LIMIT,
            }
        );
    }

    #[test]
    fn test_build_with_max_message_size_below_the_floor_is_rejected() {
        let size = MIN_MESSAGE_SIZE_LIMIT - 1;
        assert_eq!(
            build_error(required().max_message_size(size)),
            SessionConfigError::MessageSizeLimitOutOfRange {
                size,
                min: MIN_MESSAGE_SIZE_LIMIT,
                max: MAX_MESSAGE_SIZE_LIMIT,
            }
        );
    }

    #[test]
    fn test_build_with_max_message_size_above_the_ceiling_is_rejected() {
        let size = MAX_MESSAGE_SIZE_LIMIT + 1;
        assert_eq!(
            build_error(required().max_message_size(size)),
            SessionConfigError::MessageSizeLimitOutOfRange {
                size,
                min: MIN_MESSAGE_SIZE_LIMIT,
                max: MAX_MESSAGE_SIZE_LIMIT,
            }
        );
    }

    #[test]
    fn test_build_accepts_the_message_size_bounds() {
        assert_eq!(
            built(required().max_message_size(MIN_MESSAGE_SIZE_LIMIT)).max_message_size,
            MIN_MESSAGE_SIZE_LIMIT
        );
        assert_eq!(
            built(required().max_message_size(MAX_MESSAGE_SIZE_LIMIT)).max_message_size,
            MAX_MESSAGE_SIZE_LIMIT
        );
    }

    // --- Sub IDs and location IDs --------------------------------------------

    #[test]
    fn test_build_with_empty_sender_sub_id_is_rejected() {
        assert_eq!(
            build_error(required().sender_sub_id("")),
            SessionConfigError::EmptyField {
                field: "sender_sub_id"
            }
        );
    }

    #[test]
    fn test_build_with_soh_in_target_sub_id_is_rejected() {
        assert_eq!(
            build_error(required().target_sub_id("DE\x01SK")),
            SessionConfigError::IllegalByte {
                field: "target_sub_id",
                byte: 0x01,
                position: 2,
            }
        );
    }

    #[test]
    fn test_build_with_equals_in_sender_location_id_is_rejected() {
        assert_eq!(
            build_error(required().sender_location_id("LON=1")),
            SessionConfigError::IllegalByte {
                field: "sender_location_id",
                byte: b'=',
                position: 3,
            }
        );
    }

    #[test]
    fn test_build_with_overlong_target_location_id_is_rejected() {
        let long = "N".repeat(MAX_ID_LEN + 1);
        assert_eq!(
            build_error(required().target_location_id(long)),
            SessionConfigError::FieldTooLong {
                field: "target_location_id",
                len: MAX_ID_LEN + 1,
                max: MAX_ID_LEN,
            }
        );
    }

    #[test]
    fn test_build_with_non_ascii_sub_id_is_rejected() {
        // 'é' is two UTF-8 bytes, neither of them printable ASCII.
        assert!(matches!(
            build_error(required().sender_sub_id("DESKé")),
            SessionConfigError::IllegalByte {
                field: "sender_sub_id",
                ..
            }
        ));
    }

    // --- validate() on a hand-assembled configuration ------------------------

    #[test]
    fn test_validate_rejects_a_hand_assembled_fractional_heartbeat() {
        let config = SessionConfig::new(comp_id("SENDER"), comp_id("TARGET"), "FIX.4.4")
            .with_heartbeat_interval(Duration::from_millis(1500));

        assert_eq!(
            config.validate(),
            Err(SessionConfigError::FractionalHeartbeatInterval {
                interval: Duration::from_millis(1500)
            })
        );
    }

    #[test]
    fn test_validate_accepts_a_zero_heartbeat_interval() {
        // HeartBtInt = 0 is legal FIX; only the builder insists it be asked
        // for by name.
        let config = SessionConfig::new(comp_id("SENDER"), comp_id("TARGET"), "FIX.4.4")
            .with_heartbeat_interval(Duration::ZERO);
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn test_validate_rejects_a_hand_assembled_sub_id_with_soh() {
        let config = SessionConfig::new(comp_id("SENDER"), comp_id("TARGET"), "FIX.4.4")
            .with_sender_sub_id("DESK\x01");

        assert_eq!(
            config.validate(),
            Err(SessionConfigError::IllegalByte {
                field: "sender_sub_id",
                byte: 0x01,
                position: 4,
            })
        );
    }

    #[test]
    fn test_validate_rejects_a_hand_assembled_message_size_of_zero() {
        let mut config = SessionConfig::new(comp_id("SENDER"), comp_id("TARGET"), "FIX.4.4");
        config.max_message_size = 0;

        assert_eq!(
            config.validate(),
            Err(SessionConfigError::MessageSizeLimitOutOfRange {
                size: 0,
                min: MIN_MESSAGE_SIZE_LIMIT,
                max: MAX_MESSAGE_SIZE_LIMIT,
            })
        );
    }

    fn config() -> SessionConfig {
        SessionConfig::new(comp_id("SENDER"), comp_id("TARGET"), "FIX.4.4")
    }

    #[test]
    fn test_session_config_recovery_defaults_are_bounded() {
        let config = config();

        // Two minutes of clock skew, the interval FIX engines have converged
        // on; three resend attempts ten seconds apart.
        assert_eq!(config.sending_time_tolerance, Duration::from_secs(120));
        assert_eq!(config.resend_timeout, Duration::from_secs(10));
        assert_eq!(config.max_resend_requests, 3);
        assert_eq!(config.resend_attempt_limit(), 3);
    }

    #[test]
    fn test_session_config_zero_resend_requests_still_allows_one() {
        // The first ResendRequest is unconditional: it is what opens the
        // recovery the limit governs, so zero cannot mean "never ask".
        let config = config().with_max_resend_requests(0);

        assert_eq!(config.resend_attempt_limit(), 1);
    }

    #[test]
    fn test_session_config_zero_tolerance_disables_sending_time_check() {
        let config = config().with_sending_time_tolerance(Duration::ZERO);

        assert_eq!(config.sending_time_tolerance, Duration::ZERO);
    }

    #[test]
    fn test_session_config_recovery_setters_apply() {
        let config = config()
            .with_sending_time_tolerance(Duration::from_secs(5))
            .with_resend_timeout(Duration::from_millis(250))
            .with_max_resend_requests(7)
            .with_logout_timeout(Duration::from_secs(3));

        assert_eq!(config.sending_time_tolerance, Duration::from_secs(5));
        assert_eq!(config.resend_timeout, Duration::from_millis(250));
        assert_eq!(config.resend_attempt_limit(), 7);
        assert_eq!(config.logout_timeout, Duration::from_secs(3));
    }

    // --- Garbled-frame limit -------------------------------------------------

    /// A non-zero frame count, failing the test rather than the session.
    #[track_caller]
    fn frames(count: u32) -> NonZeroU32 {
        match NonZeroU32::new(count) {
            Some(count) => count,
            None => panic!("test frame count must be non-zero"),
        }
    }

    /// The out-of-range error for a given `(max, window)`.
    fn garbled_out_of_range(max: NonZeroU32, window: Duration) -> SessionConfigError {
        SessionConfigError::GarbledFrameLimitOutOfRange {
            max,
            window,
            max_frames: MAX_GARBLED_FRAME_LIMIT,
            max_window: MAX_GARBLED_FRAME_WINDOW,
        }
    }

    #[test]
    fn test_session_config_garbled_frame_limit_defaults_to_none() {
        assert_eq!(config().garbled_frame_limit, None);
        assert_eq!(built(required()).garbled_frame_limit, None);
    }

    #[test]
    fn test_builder_garbled_frame_limit_lands_in_the_built_config() {
        let config = built(required().garbled_frame_limit(frames(5), Duration::from_secs(60)));
        let Some(limit) = config.garbled_frame_limit else {
            panic!("the limit must be set");
        };
        assert_eq!(limit.max(), frames(5));
        assert_eq!(limit.window(), Duration::from_secs(60));
    }

    #[test]
    fn test_build_with_too_many_garbled_frames_is_rejected() {
        let max = frames(MAX_GARBLED_FRAME_LIMIT + 1);
        let window = Duration::from_secs(60);
        assert_eq!(
            build_error(required().garbled_frame_limit(max, window)),
            garbled_out_of_range(max, window)
        );
    }

    #[test]
    fn test_build_with_zero_garbled_window_is_rejected() {
        assert_eq!(
            build_error(required().garbled_frame_limit(frames(3), Duration::ZERO)),
            garbled_out_of_range(frames(3), Duration::ZERO)
        );
    }

    #[test]
    fn test_build_with_excessive_garbled_window_is_rejected() {
        let window = MAX_GARBLED_FRAME_WINDOW + Duration::from_nanos(1);
        assert_eq!(
            build_error(required().garbled_frame_limit(frames(3), window)),
            garbled_out_of_range(frames(3), window)
        );
    }

    #[test]
    fn test_garbled_frame_limit_try_new_accepts_the_bounds() {
        for (max, window) in [
            (frames(1), Duration::from_nanos(1)),
            (frames(MAX_GARBLED_FRAME_LIMIT), MAX_GARBLED_FRAME_WINDOW),
        ] {
            match GarbledFrameLimit::try_new(max, window) {
                Ok(limit) => {
                    assert_eq!(limit.max(), max);
                    assert_eq!(limit.window(), window);
                }
                Err(err) => panic!("({max}, {window:?}) is in range: {err}"),
            }
        }
    }

    #[test]
    fn test_garbled_frame_limit_try_new_rejects_out_of_range_values() {
        let over = frames(MAX_GARBLED_FRAME_LIMIT + 1);
        assert_eq!(
            GarbledFrameLimit::try_new(over, Duration::from_secs(1)),
            Err(garbled_out_of_range(over, Duration::from_secs(1)))
        );
        assert_eq!(
            GarbledFrameLimit::try_new(frames(1), Duration::ZERO),
            Err(garbled_out_of_range(frames(1), Duration::ZERO))
        );
    }

    // --- Application versions (FIXT.1.1) ------------------------------------

    /// A FIX.5.0SP2 configuration, built through the builder.
    fn fixt_required() -> SessionConfigBuilder {
        required().begin_string("FIX.5.0SP2")
    }

    #[test]
    fn test_allowed_appl_versions_default_to_empty() {
        assert!(config().allowed_appl_versions.is_empty());
        assert!(built(fixt_required()).allowed_appl_versions.is_empty());
    }

    #[test]
    fn test_default_accepts_only_the_configured_appl_version() {
        let config = built(fixt_required());
        assert!(config.accepts_appl_version(FixVersion::Fix50Sp2));
        for other in [
            FixVersion::Fix50,
            FixVersion::Fix50Sp1,
            FixVersion::Fix44,
            FixVersion::Fixt11,
        ] {
            assert!(
                !config.accepts_appl_version(other),
                "{other} must not be accepted"
            );
        }
    }

    #[test]
    fn test_builder_allowed_appl_versions_lands_and_extends_the_configured_one() {
        let config = built(fixt_required().allowed_appl_versions([FixVersion::Fix50Sp1]));
        assert_eq!(config.allowed_appl_versions, vec![FixVersion::Fix50Sp1]);
        assert!(config.accepts_appl_version(FixVersion::Fix50Sp2));
        assert!(config.accepts_appl_version(FixVersion::Fix50Sp1));
        assert!(!config.accepts_appl_version(FixVersion::Fix50));
    }

    #[test]
    fn test_build_with_allowed_appl_versions_on_a_fix44_session_is_rejected() {
        assert_eq!(
            build_error(
                required()
                    .begin_string("FIX.4.4")
                    .allowed_appl_versions([FixVersion::Fix50Sp2])
            ),
            SessionConfigError::UnusableApplVersion {
                version: FixVersion::Fix50Sp2,
                begin_string: "FIX.4.4".to_string(),
            }
        );
    }

    #[test]
    fn test_build_with_allowed_appl_versions_on_a_fix42_session_is_rejected() {
        assert!(matches!(
            build_error(
                required()
                    .begin_string("FIX.4.2")
                    .allowed_appl_versions([FixVersion::Fix50])
            ),
            SessionConfigError::UnusableApplVersion { .. }
        ));
    }

    #[test]
    fn test_build_with_a_version_without_an_appl_ver_id_code_is_rejected() {
        for version in [FixVersion::Fix44, FixVersion::Fixt11] {
            assert_eq!(
                build_error(fixt_required().allowed_appl_versions([version])),
                SessionConfigError::UnusableApplVersion {
                    version,
                    begin_string: "FIX.5.0SP2".to_string(),
                }
            );
        }
    }

    #[test]
    fn test_build_with_allowed_appl_versions_on_bare_fixt_is_rejected() {
        // FIXT.1.1 alone names no application version, so the session has no
        // own version for the set to extend.
        assert!(matches!(
            build_error(
                required()
                    .begin_string("FIXT.1.1")
                    .allowed_appl_versions([FixVersion::Fix50Sp2])
            ),
            SessionConfigError::UnusableApplVersion { .. }
        ));
    }

    #[test]
    fn test_validate_rejects_a_hand_assembled_appl_version_set_on_fix44() {
        let config = config().with_allowed_appl_versions([FixVersion::Fix50Sp1]);
        assert_eq!(
            config.validate(),
            Err(SessionConfigError::UnusableApplVersion {
                version: FixVersion::Fix50Sp1,
                begin_string: "FIX.4.4".to_string(),
            })
        );
    }

    #[test]
    fn test_with_allowed_appl_versions_sets_and_clears_the_set() {
        let base = SessionConfig::new(comp_id("SENDER"), comp_id("TARGET"), "FIX.5.0");
        let set = base.with_allowed_appl_versions([FixVersion::Fix50Sp1, FixVersion::Fix50Sp2]);
        assert_eq!(set.validate(), Ok(()));
        assert!(set.accepts_appl_version(FixVersion::Fix50));
        assert!(set.accepts_appl_version(FixVersion::Fix50Sp1));
        assert!(set.accepts_appl_version(FixVersion::Fix50Sp2));
        let cleared = set.with_allowed_appl_versions([]);
        assert!(cleared.allowed_appl_versions.is_empty());
        assert!(!cleared.accepts_appl_version(FixVersion::Fix50Sp2));
    }

    #[test]
    fn test_require_ack_default_appl_ver_id_defaults_to_false_and_is_settable() {
        assert!(!config().require_ack_default_appl_ver_id);
        assert!(!built(fixt_required()).require_ack_default_appl_ver_id);
        assert!(
            built(fixt_required().require_ack_default_appl_ver_id(true))
                .require_ack_default_appl_ver_id
        );
        let strict = config().with_require_ack_default_appl_ver_id(true);
        assert!(strict.require_ack_default_appl_ver_id);
        // Any flag is valid: it is read by a FIX 5.0 initiator only.
        assert_eq!(strict.validate(), Ok(()));
    }

    #[test]
    fn test_fix4_session_accepts_no_appl_version() {
        for begin_string in ["FIX.4.2", "FIX.4.4"] {
            let config = SessionConfig::new(comp_id("SENDER"), comp_id("TARGET"), begin_string);
            for version in FixVersion::ALL {
                assert!(
                    !config.accepts_appl_version(version),
                    "a {begin_string} session must accept no application version, accepted {version}"
                );
            }
        }
    }

    // --- NextExpectedMsgSeqNum (789) ----------------------------------------

    #[test]
    fn test_send_next_expected_msg_seq_num_defaults_to_false() {
        assert!(!config().send_next_expected_msg_seq_num);
        assert!(!built(required()).send_next_expected_msg_seq_num);
    }

    #[test]
    fn test_send_next_expected_msg_seq_num_builds_on_every_version_defining_789() {
        for begin_string in ["FIX.4.4", "FIX.5.0", "FIX.5.0SP1", "FIX.5.0SP2", "FIXT.1.1"] {
            let config = built(
                required()
                    .begin_string(begin_string)
                    .send_next_expected_msg_seq_num(true),
            );
            assert!(config.send_next_expected_msg_seq_num, "{begin_string}");
        }
    }

    #[test]
    fn test_build_with_send_next_expected_msg_seq_num_below_fix44_is_rejected() {
        for begin_string in ["FIX.4.0", "FIX.4.1", "FIX.4.2", "FIX.4.3"] {
            assert_eq!(
                build_error(
                    required()
                        .begin_string(begin_string)
                        .send_next_expected_msg_seq_num(true)
                ),
                SessionConfigError::NextExpectedMsgSeqNumUnsupported {
                    begin_string: begin_string.to_string(),
                },
                "{begin_string}"
            );
        }
    }

    #[test]
    fn test_build_with_send_next_expected_msg_seq_num_on_an_unknown_version_is_rejected() {
        // A string that names no version defines no 789 either.
        assert_eq!(
            build_error(
                required()
                    .begin_string("FIX.9.9")
                    .send_next_expected_msg_seq_num(true)
            ),
            SessionConfigError::NextExpectedMsgSeqNumUnsupported {
                begin_string: "FIX.9.9".to_string(),
            }
        );
    }

    #[test]
    fn test_send_next_expected_msg_seq_num_off_is_valid_on_every_version() {
        for begin_string in ["FIX.4.0", "FIX.4.2", "FIX.4.4", "FIX.5.0SP2"] {
            let config = SessionConfig::new(comp_id("SENDER"), comp_id("TARGET"), begin_string)
                .with_send_next_expected_msg_seq_num(false);
            assert_eq!(config.validate(), Ok(()), "{begin_string}");
        }
    }

    #[test]
    fn test_validate_rejects_a_hand_assembled_next_expected_flag_on_fix42() {
        let mut config = SessionConfig::new(comp_id("SENDER"), comp_id("TARGET"), "FIX.4.2");
        config.send_next_expected_msg_seq_num = true;
        assert_eq!(
            config.validate(),
            Err(SessionConfigError::NextExpectedMsgSeqNumUnsupported {
                begin_string: "FIX.4.2".to_string(),
            })
        );
        let config = config.with_send_next_expected_msg_seq_num(false);
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn test_with_send_next_expected_msg_seq_num_sets_the_flag() {
        let config = config().with_send_next_expected_msg_seq_num(true);
        assert!(config.send_next_expected_msg_seq_num);
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn test_next_expected_unsupported_error_names_the_version_and_the_tag() {
        let message = SessionConfigError::NextExpectedMsgSeqNumUnsupported {
            begin_string: "FIX.4.2".to_string(),
        }
        .to_string();
        assert!(message.contains("FIX.4.2"), "{message}");
        assert!(message.contains("789"), "{message}");
    }

    #[test]
    fn test_gap_policy_defaults_to_discard() {
        assert_eq!(config().gap_policy, GapPolicy::Discard);
        assert_eq!(built(required()).gap_policy, GapPolicy::Discard);
        assert_eq!(GapPolicy::default(), GapPolicy::Discard);
    }

    #[test]
    fn test_builder_gap_policy_queue_lands_in_the_built_config() {
        let queue = GapPolicy::Queue {
            max_messages: 100,
            max_bytes: 1 << 20,
        };
        assert_eq!(built(required().gap_policy(queue)).gap_policy, queue);
        assert_eq!(config().with_gap_policy(queue).gap_policy, queue);
        let bounds = GapPolicy::Queue {
            max_messages: MAX_GAP_QUEUE_MESSAGES,
            max_bytes: MAX_GAP_QUEUE_BYTES,
        };
        assert_eq!(built(required().gap_policy(bounds)).gap_policy, bounds);
    }

    #[test]
    fn test_gap_policy_queue_out_of_range_is_refused() {
        let cases = [
            (0, 1),
            (1, 0),
            (MAX_GAP_QUEUE_MESSAGES + 1, 1),
            (1, MAX_GAP_QUEUE_BYTES + 1),
        ];
        for (max_messages, max_bytes) in cases {
            let policy = GapPolicy::Queue {
                max_messages,
                max_bytes,
            };
            let expected = SessionConfigError::GapQueueOutOfRange {
                max_messages,
                max_bytes,
                max_messages_limit: MAX_GAP_QUEUE_MESSAGES,
                max_bytes_limit: MAX_GAP_QUEUE_BYTES,
            };
            assert_eq!(build_error(required().gap_policy(policy)), expected);
            assert_eq!(config().with_gap_policy(policy).validate(), Err(expected));
        }
    }

    #[test]
    fn test_with_garbled_frame_limit_sets_and_clears_the_bound() {
        let limit = match GarbledFrameLimit::try_new(frames(2), Duration::from_secs(5)) {
            Ok(limit) => limit,
            Err(err) => panic!("limit must be valid: {err}"),
        };
        let set = config().with_garbled_frame_limit(Some(limit));
        assert_eq!(set.garbled_frame_limit, Some(limit));
        assert_eq!(set.validate(), Ok(()));
        assert_eq!(set.with_garbled_frame_limit(None).garbled_frame_limit, None);
    }
}
