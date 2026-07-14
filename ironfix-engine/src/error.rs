/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 14/7/26
******************************************************************************/

//! Engine error types.

use ironfix_core::error::DecodeError;
use ironfix_transport::CodecError;
use std::time::Duration;

/// Errors produced by the engine transport layer.
#[derive(Debug, thiserror::Error)]
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

    /// The connection is closed; no more messages can be sent.
    #[error("connection closed")]
    Closed,
}
