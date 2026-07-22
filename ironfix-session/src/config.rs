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
//! # Ranges
//!
//! | Knob | Unit | Range | Default |
//! |---|---|---|---|
//! | `sender_comp_id` / `target_comp_id` | — | validated by [`CompId`] | required |
//! | `begin_string` | ASCII | 1..=[`MAX_ID_LEN`] bytes, printable ASCII except `=` | `FIX.4.4` |
//! | `heartbeat_interval` | whole seconds | 0 (disabled) or [`MIN_HEARTBEAT_INTERVAL_SECS`]..=[`MAX_HEARTBEAT_INTERVAL_SECS`] | 30 s |
//! | `logon_timeout` / `logout_timeout` | duration | non-zero, at most [`MAX_TIMEOUT`] | 10 s |
//! | `max_message_size` | bytes | [`MIN_MESSAGE_SIZE_LIMIT`]..=[`MAX_MESSAGE_SIZE_LIMIT`] | 1 MiB |
//! | `sender_sub_id` / `target_sub_id` | ASCII | unset, or 1..=[`MAX_ID_LEN`] bytes, printable ASCII except `=` | unset |
//! | `sender_location_id` / `target_location_id` | ASCII | as above | unset |
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

use crate::heartbeat::MAX_HEARTBEAT_INTERVAL_SECS;
use ironfix_core::types::{COMP_ID_MAX_LEN, CompId};
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
/// Construct one with [`SessionConfigBuilder`], which validates every knob.
/// The fields are public so a configuration can also be assembled or adjusted
/// directly; [`SessionConfig::validate`] then says whether the result is
/// usable, and `ironfix-engine` calls it before dialling.
#[derive(Debug, Clone)]
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
    /// Optional sender sub ID (tag 50), 1..=[`MAX_ID_LEN`] bytes when set.
    pub sender_sub_id: Option<String>,
    /// Optional target sub ID (tag 57), 1..=[`MAX_ID_LEN`] bytes when set.
    pub target_sub_id: Option<String>,
    /// Optional sender location ID (tag 142), 1..=[`MAX_ID_LEN`] bytes when set.
    pub sender_location_id: Option<String>,
    /// Optional target location ID (tag 143), 1..=[`MAX_ID_LEN`] bytes when set.
    pub target_location_id: Option<String>,
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
            sender_sub_id: None,
            target_sub_id: None,
            sender_location_id: None,
            target_location_id: None,
        }
    }

    /// Checks every knob against the ranges documented on the module.
    ///
    /// The CompIDs are not re-checked: [`CompId`] validates its charset and
    /// length at construction, so an illegal one is unrepresentable.
    ///
    /// [`Duration::ZERO`] passes as a heartbeat interval — it is the legal
    /// `HeartBtInt = 0`. Only [`SessionConfigBuilder`] requires that case to
    /// be opted into by name.
    ///
    /// # Errors
    /// Returns the first [`SessionConfigError`] found: an empty, oversized or
    /// non-encodable identity string, a fractional or out-of-range heartbeat
    /// interval, a zero or excessive handshake timeout, or a message-size
    /// limit outside [`MIN_MESSAGE_SIZE_LIMIT`]..=[`MAX_MESSAGE_SIZE_LIMIT`].
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
        Ok(())
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
    /// Sender sub ID (tag 50).
    sender_sub_id: Option<String>,
    /// Target sub ID (tag 57).
    target_sub_id: Option<String>,
    /// Sender location ID (tag 142).
    sender_location_id: Option<String>,
    /// Target location ID (tag 143).
    target_location_id: Option<String>,
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
            sender_sub_id: None,
            target_sub_id: None,
            sender_location_id: None,
            target_location_id: None,
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

    /// Builds the configuration, validating every knob.
    ///
    /// # Errors
    /// Returns [`SessionConfigError::MissingField`] if either CompID was never
    /// set, and [`SessionConfigError::HeartbeatDisabledWithoutOptIn`] if
    /// [`SessionConfigBuilder::heartbeat_interval`] was given
    /// [`Duration::ZERO`] instead of calling
    /// [`SessionConfigBuilder::disable_heartbeats`]. Everything else is the
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
            sender_sub_id: self.sender_sub_id,
            target_sub_id: self.target_sub_id,
            sender_location_id: self.sender_location_id,
            target_location_id: self.target_location_id,
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
}
