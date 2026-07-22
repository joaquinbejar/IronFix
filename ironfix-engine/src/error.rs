/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 14/7/26
******************************************************************************/

//! Engine error types.

use ironfix_core::error::{DecodeError, EncodeError};
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

    /// Framing or checksum failure at the codec layer.
    #[error("codec error: {0}")]
    Codec(#[from] CodecError),

    /// Failure decoding a framed FIX message.
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
    /// Checked before the socket is dialled: an out-of-range knob — a
    /// fractional `HeartBtInt`, an identity string carrying SOH or `=`, a zero
    /// timeout — would otherwise corrupt the session's own messages.
    /// [`ironfix_session::SessionConfigBuilder`] reports the same errors at
    /// configuration time.
    #[error("invalid session configuration: {0}")]
    Config(#[from] SessionConfigError),

    /// TCP connect did not complete within the configured timeout.
    #[error("connect timed out after {0:?}")]
    ConnectTimeout(Duration),

    /// The Logon acknowledgement did not arrive within the logon timeout.
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

    /// The counterparty's identity fields (49/56, and 50/57 when
    /// configured) did not match the session configuration.
    #[error("identity mismatch: {detail}")]
    IdentityMismatch {
        /// Which field mismatched, with the expected and received values.
        detail: String,
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

    /// The connection is closed; no more messages can be sent.
    #[error("connection closed")]
    Closed,
}
