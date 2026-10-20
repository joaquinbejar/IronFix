/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! The error type of the FIXP engine entry points.

use ironfix_fixp::{
    EstablishmentRejectCode, FixpDecodeError, FixpEncodeError, FixpError, HandshakeStage,
    NegotiationRejectCode,
};
use ironfix_sofh::SofhError;
use std::time::Duration;

/// Everything that can go wrong running a FIXP session over SOFH.
///
/// A failure of the counterparty to follow FIXP is not an error of this type
/// while the session is up: the session core answers it on the wire (FIXP
/// v1.1 section 6.3) and reports it as an
/// [`Event`](ironfix_fixp::Event). It becomes one only when it ends the
/// handshake an entry point is waiting for.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FixpEngineError {
    /// The transport failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The SOFH framing failed. Every SOFH error is fatal for the stream
    /// (there is no resynchronisation point), so the transport is closed.
    #[error("framing error: {0}")]
    Framing(#[from] SofhError),

    /// A frame named the FIXP session schema but did not decode.
    #[error("malformed FIXP session message: {0}")]
    Decode(#[from] FixpDecodeError),

    /// A session message could not be encoded.
    #[error("cannot encode a FIXP session message: {0}")]
    Encode(#[from] FixpEncodeError),

    /// The session core refused a command.
    #[error("FIXP session error: {0}")]
    Session(#[from] FixpError),

    /// The TCP connection was not established in time.
    #[error("connect timed out after {0:?}")]
    ConnectTimeout(Duration),

    /// A write did not complete in time; the transport is closed.
    #[error("write timed out after {0:?}")]
    WriteTimeout(Duration),

    /// The server refused the Negotiate (FIXP v1.1 section 4.2.3).
    #[error("negotiation rejected ({code:?}): {reason}")]
    NegotiationRejected {
        /// The server's code.
        code: NegotiationRejectCode,
        /// The server's free-text reason.
        reason: String,
    },

    /// The server refused the Establish (FIXP v1.1 section 4.3.3).
    #[error("establishment rejected ({code:?}): {reason}")]
    EstablishmentRejected {
        /// The server's code.
        code: EstablishmentRejectCode,
        /// The server's free-text reason.
        reason: String,
    },

    /// A handshake step was not answered within the configured handshake
    /// timeout.
    #[error("FIXP handshake timed out during {stage:?}")]
    HandshakeTimedOut {
        /// The step that timed out.
        stage: HandshakeStage,
    },

    /// The transport closed before the session was established, for a
    /// reason none of the other variants names (the counterparty closing,
    /// a protocol violation the core answered).
    #[error("FIXP handshake failed: {detail}")]
    HandshakeFailed {
        /// What ended the handshake.
        detail: String,
    },

    /// An application payload starts with an SBE header naming the FIXP
    /// session schema (id 2748). Sent as an application message, the
    /// counterparty would decode it as a session message, so it is refused
    /// before any sequence number is spent.
    #[error("the payload is a FIXP session message; the session layer owns that schema")]
    ReservedSchema,

    /// An application payload is larger than the SOFH size ceiling; nothing
    /// was sent and no sequence number was spent.
    #[error("payload of {len} bytes exceeds the frame ceiling of {max} bytes")]
    PayloadTooLarge {
        /// The payload length, in bytes.
        len: usize,
        /// The largest `Message_Length` accepted, header included.
        max: u32,
    },

    /// The connection is closed.
    #[error("connection closed")]
    Closed,
}
