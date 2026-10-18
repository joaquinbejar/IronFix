/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 14/7/26
******************************************************************************/

//! Engine error types.

use ironfix_core::error::{DecodeError, EncodeError, StoreError};
use ironfix_session::config::SessionConfigError;
use ironfix_session::sequence::{SequenceCounter, SequenceExhausted};
use ironfix_transport::CodecError;
use std::time::Duration;

/// Errors produced by the engine transport layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EngineError {
    /// Underlying I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Fatal failure at the codec layer.
    ///
    /// Both engines frame with garbled-frame recovery on, so a garbled frame
    /// (a bad CheckSum or BodyLength, bytes before `8=`) is skipped rather than
    /// reported here, during the Logon handshake as well as afterwards. What
    /// remains is fatal: a frame above
    /// [`SessionConfig::max_message_size`](ironfix_session::SessionConfig::max_message_size),
    /// or an I/O failure inside the codec.
    #[error("codec error: {0}")]
    Codec(#[from] CodecError),

    /// Failure decoding a framed FIX message.
    ///
    /// Neither Logon handshake returns this for a frame that does not decode
    /// any more: both skip such frames and keep waiting until
    /// [`EngineError::LogonTimeout`]. What can still produce it: the
    /// initiator, when a Logon ack that decodes carries a BeginString (8) value
    /// that is not valid UTF-8; and the `?` and `From` conversions on the
    /// handshake paths that re-read a frame already decoded once, which cannot
    /// fail and are kept as typed errors rather than unwraps. During the Active
    /// session a frame that does not decode never surfaces as an error: it is
    /// dropped (and, if garbled, counted) by the reactor.
    #[error("decode error: {0}")]
    Decode(#[from] DecodeError),

    /// A message could not be encoded into a legal frame.
    ///
    /// Raised when a field value has no on-the-wire form — a value carrying the
    /// SOH delimiter, or an empty one. The encoder refuses to stamp such a
    /// frame rather than emit one whose `BodyLength` and `CheckSum` are correct
    /// for corrupted bytes.
    #[error("encode error: {0}")]
    Encode(#[from] EncodeError),

    /// The session configuration is not usable.
    ///
    /// Checked before the socket is dialled by the initiator, and before the
    /// handshake by the acceptor: an out-of-range knob — a fractional
    /// `HeartBtInt`, an identity string carrying SOH or `=`, a zero timeout —
    /// would otherwise corrupt the session's own messages.
    /// [`ironfix_session::SessionConfigBuilder`] reports the same errors at
    /// configuration time.
    #[error("invalid session configuration: {0}")]
    Config(#[from] SessionConfigError),

    /// TCP connect did not complete within the configured timeout.
    #[error("connect timed out after {0:?}")]
    ConnectTimeout(Duration),

    /// The Logon (acceptor) or Logon acknowledgement (initiator) did not
    /// arrive intact within the logon timeout.
    ///
    /// Garbled frames received while waiting are ignored, not reported, so a
    /// counterparty that sends only garbled Logons ends here once the timeout
    /// expires rather than in an immediate [`EngineError::Codec`] or
    /// [`EngineError::Decode`].
    #[error("logon timed out after {0:?}")]
    LogonTimeout(Duration),

    /// The counterparty rejected the Logon.
    #[error("logon rejected: {reason}")]
    LogonRejected {
        /// Text supplied by the counterparty, or a generic description.
        reason: String,
    },

    /// The `HeartBtInt` (108) on the Logon acknowledgement could not be adopted
    /// as the session's heartbeat interval.
    ///
    /// Raised when the ack omits the required field, carries a non-numeric
    /// value, or confirms an interval above
    /// [`ironfix_session::heartbeat::MAX_HEARTBEAT_INTERVAL_SECS`] — the value
    /// drives every liveness timer in the session and is counterparty
    /// controlled, so an unbounded one is refused. `108=0` is legal and never
    /// raises this — it means "do not heartbeat".
    #[error("unsupported heartbeat interval: {detail}")]
    HeartbeatInterval {
        /// Why the confirmed `HeartBtInt` was refused.
        detail: String,
    },

    /// An unexpected message type arrived while awaiting the Logon
    /// acknowledgement.
    #[error("unexpected message during logon: 35={msg_type}")]
    UnexpectedMessage {
        /// The received MsgType (tag 35) value.
        msg_type: String,
    },

    /// A sequence number violation that is fatal for the session.
    #[error("sequence error: {0}")]
    Sequence(String),

    /// A sequence counter reached `u64::MAX`. No further messages can be
    /// numbered until the session performs a sequence reset.
    #[error(transparent)]
    SequenceExhausted(#[from] SequenceExhausted),

    /// A seeded initial sequence number was zero.
    ///
    /// FIX numbers messages from 1; a seeded `MsgSeqNum` (34) of 0 would be
    /// rejected by every conforming counterparty. Checked before the socket is
    /// dialled. Set through
    /// [`Initiator::with_initial_sequences`](crate::Initiator::with_initial_sequences).
    #[error("initial {counter} sequence number must be at least 1, was 0")]
    InvalidInitialSequence {
        /// Which seeded counter was zero.
        counter: SequenceCounter,
    },

    /// A seeded initial sender sequence number is below the next sender
    /// number the attached store holds, under
    /// [`StoreFailurePolicy::CloseSession`](crate::StoreFailurePolicy::CloseSession).
    ///
    /// The store has frames filed at the numbers in between, so the
    /// counterparty has seen them; reusing one would send a different message
    /// under a `MsgSeqNum` it already holds. Checked by
    /// [`Initiator::connect`](crate::Initiator::connect) and
    /// [`Acceptor::serve`](crate::Acceptor::serve) after the store is
    /// refreshed and before anything is written. Set through
    /// [`Initiator::with_initial_sequences`](crate::Initiator::with_initial_sequences)
    /// or [`Acceptor::with_initial_sequences`](crate::Acceptor::with_initial_sequences).
    #[error(
        "initial sender sequence number {seeded} is below the store's next sender sequence \
         number {stored}"
    )]
    InitialSequenceBelowStore {
        /// The seeded next sender sequence number.
        seeded: u64,
        /// The next sender sequence number the store holds.
        stored: u64,
    },

    /// The counterparty's identity fields (49/56, and 50/57 and 142/143 when
    /// configured) did not match the session configuration.
    #[error("identity mismatch: {detail}")]
    IdentityMismatch {
        /// Which field mismatched, with the expected and received values.
        detail: String,
    },

    /// An inbound Logon cannot be routed to a session by an
    /// [`AcceptorRegistry`](crate::AcceptorRegistry): one of its identity
    /// fields is absent from the standard header (`SenderCompID` (49),
    /// `TargetCompID` (56)), empty, longer than
    /// [`MAX_ID_LEN`](ironfix_session::config::MAX_ID_LEN) bytes, or carries
    /// a byte outside printable ASCII.
    ///
    /// Checked before any registered session or the lookup is consulted. The
    /// connection is closed without a reply; no store is touched and no
    /// [`Application`](crate::Application) callback runs.
    #[error("unroutable logon: tag {tag} {detail}")]
    UnroutableLogon {
        /// The identity field that failed: 49, 56, 50, 57, 142 or 143.
        tag: u32,
        /// What is wrong with it. It never quotes the value.
        detail: String,
    },

    /// No session is registered in an
    /// [`AcceptorRegistry`](crate::AcceptorRegistry) for the identity an
    /// inbound Logon claims, and no
    /// [`SessionLookup`](crate::SessionLookup) admitted one.
    ///
    /// The connection is closed without a reply; no store is touched and no
    /// [`Application`](crate::Application) callback runs.
    #[error("no session for the logon identity {identity}")]
    UnknownSession {
        /// The identity the Logon claimed, in its own orientation (its
        /// `SenderCompID` (49) first). Every value in it has passed the
        /// routing bounds, so it is at most a few hundred printable bytes.
        identity: String,
    },

    /// The Logon acknowledgement carried a `BeginString` (8) that does not
    /// match the configured session version.
    ///
    /// For a FIX 5.0 / FIXT.1.1 session the configured transport
    /// `BeginString` is `FIXT.1.1`, so an ack tagged `FIX.5.0*` — or any
    /// other version — is not this session's acknowledgement and aborts the
    /// handshake.
    #[error("begin string mismatch: expected {expected}, received {received}")]
    BeginStringMismatch {
        /// The configured transport `BeginString`.
        expected: String,
        /// The `BeginString` the counterparty sent on the Logon ack.
        received: String,
    },

    /// The counterparty's `SendingTime` (52) failed validation: absent,
    /// unparseable, or further from the local clock than
    /// `SessionConfig::sending_time_tolerance` allows.
    #[error("SendingTime problem: {detail}")]
    SendingTime {
        /// Which check failed, with the offending value or the measured skew.
        detail: String,
    },

    /// The configured `BeginString` cannot be framed conformantly.
    ///
    /// An unknown version, or `FIXT.1.1` on its own — which names the
    /// transport version but no application version for the required
    /// `DefaultApplVerID` (1137).
    #[error("unsupported FIX version {version}: {detail}")]
    UnsupportedVersion {
        /// The configured version string.
        version: String,
        /// Why it cannot be framed.
        detail: String,
    },

    /// A message-store operation the session depends on failed during setup.
    ///
    /// Raised by [`Initiator::connect`](crate::Initiator::connect) when the
    /// store cannot be reset for a `ResetSeqNumFlag` (141) Logon, for a reset
    /// an earlier session owes, or for the `ResetSeqNumFlag` the counterparty
    /// declared on its Logon ack, or refreshed to recover its counters,
    /// whatever the policy. Continuing anyway would either run a new stream
    /// over a previous one's numbers or reuse a `MsgSeqNum` the counterparty
    /// has already seen, so the session is refused rather than started from a
    /// counter the store could not vouch for. A failed reset for the ack is
    /// owed to the next connect, whose Logon then declares the reset itself.
    ///
    /// Raised the same way by [`Acceptor::serve`](crate::Acceptor::serve),
    /// once the inbound Logon is authenticated, when the store cannot be reset
    /// (the Logon carries `ResetSeqNumFlag`, `reset_on_logon` is set, or a
    /// reset is owed) or refreshed, whatever the policy.
    ///
    /// Under [`StoreFailurePolicy::CloseSession`](crate::StoreFailurePolicy::CloseSession)
    /// it is also raised when a handshake store call fails, in either role:
    /// filing the Logon or its acknowledgement together with the next sender
    /// number, persisting the target number the inbound Logon or ack consumed,
    /// and filing a Reject or Logout that refuses it (this error then replaces
    /// the refusal's own). The frame concerned is never written. Once
    /// `on_logon` has run, the same failure closes the session instead,
    /// through `on_logout`.
    ///
    /// A store call that overruns the store timeout fails with
    /// [`StoreError::Timeout`]. A failed store mutation, whatever the error,
    /// also owes the next session a sequence reset.
    #[error("store error: {0}")]
    Store(#[from] StoreError),

    /// A write to the counterparty did not complete within the write timeout.
    ///
    /// A peer that stops reading parks a socket write forever once its receive
    /// window closes, which would take the reactor's liveness timers with it.
    /// The write is therefore bounded and its expiry closes the session, which
    /// is the same verdict heartbeat detection would have reached.
    #[error("write timed out after {0:?}")]
    WriteTimeout(Duration),

    /// An administrative MsgType was offered on the application send path.
    ///
    /// Logon (A), Logout (5), SequenceReset (4) and the rest of the
    /// administrative set belong to the session state machine. One emitted
    /// through [`Connection::send`](crate::Connection::send) would bypass the
    /// typestate and the engine's phase tracking — a Logout sent that way, for
    /// instance, never arms the logout timeout.
    #[error("MsgType {msg_type} is administrative and belongs to the session layer")]
    ReservedMsgType {
        /// The offered MsgType (tag 35) value.
        msg_type: String,
    },

    /// An outbound body carried a tag the engine stamps itself.
    ///
    /// See [`crate::outbound::RESERVED_TAGS`]. The frame would carry two
    /// occurrences of the tag, which a conforming counterparty rejects or
    /// misparses.
    #[error(
        "tag {tag} is stamped by the engine's standard header or trailer and must not be set on \
         an outbound message"
    )]
    ReservedTag {
        /// The offending tag.
        tag: u32,
    },

    /// An outbound field value has no legal wire form.
    ///
    /// The reason never quotes the value: an outbound Logon body carries
    /// `Password` (554) and `NewPassword` (925).
    #[error("invalid outbound field {tag}: {reason}")]
    InvalidField {
        /// The offending tag.
        tag: u32,
        /// Why the value cannot be framed.
        reason: String,
    },

    /// An administrative message lost a field its MsgType cannot go out without.
    ///
    /// A `to_admin` callback removed a required body field — `HeartBtInt` (108)
    /// from a Logon, `TestReqID` (112) from a TestRequest, `NewSeqNo` (36) from
    /// a SequenceReset, and the like. Emitting the message anyway would put a
    /// malformed administrative frame on the wire that a conforming
    /// counterparty rejects; the session refuses it instead.
    #[error("administrative message {msg_type} is missing required field {tag}")]
    MissingRequiredField {
        /// The administrative MsgType (tag 35) value.
        msg_type: String,
        /// The required tag that is absent.
        tag: u32,
    },

    /// The connection is closed; no more messages can be sent.
    #[error("connection closed")]
    Closed,

    /// The builder was asked to produce an engine it was not configured for —
    /// for example a terminal method called with no session, or with more than
    /// one where a single-session engine is required.
    #[error("engine configuration error: {0}")]
    Configuration(String),
}
