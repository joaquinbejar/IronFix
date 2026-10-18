/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Typed errors of the FIXP session core.
//!
//! Three boundaries, three types:
//!
//! - [`FixpDecodeError`]: bytes from the counterparty that are not a valid
//!   FIXP session message. Untrusted input: every malformed shape is one of
//!   these variants, never a panic, and nothing is allocated from a length the
//!   input declares before the bytes it declares are known to be present.
//! - [`FixpEncodeError`]: a message this side asked to encode that cannot be
//!   put on the wire, such as a variable-length field above its 16-bit length
//!   prefix or a destination buffer that is too small.
//! - [`FixpError`]: a command the local application issued that the session
//!   cannot carry out in its current state. Protocol violations by the
//!   *counterparty* are not errors of this type: the session answers them on
//!   the wire (a reject or a Terminate) and reports them as events.

use crate::output::SessionStatus;
use crate::types::FlowType;
use thiserror::Error;

/// A byte sequence that is not a valid FIXP session message.
///
/// Produced by [`crate::SessionMessage::decode`]. Every variant names the
/// offending value where there is one.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum FixpDecodeError {
    /// Fewer bytes than the message needs: the 8-byte SBE message header, the
    /// root block its `blockLength` declares, or a variable-length field.
    #[error("truncated message: {needed} bytes needed, {available} available")]
    Truncated {
        /// Bytes the message needs up to and including the part being read.
        needed: usize,
        /// Bytes available in the input.
        available: usize,
    },

    /// The SBE `schemaId` is not the FIXP session schema (2748).
    ///
    /// On a transport that mixes FIXP session messages with application
    /// messages of another schema this is how an application message shows
    /// up; check [`crate::is_session_message`] first to route it.
    #[error("schema id {schema_id} is not the FIXP session schema {expected}")]
    SchemaMismatch {
        /// The schema id found in the header.
        schema_id: u16,
        /// The FIXP session schema id.
        expected: u16,
    },

    /// A `templateId` the FIXP session schema does not define.
    #[error("template id {template_id} is not a FIXP session message")]
    UnknownTemplate {
        /// The template id found in the header.
        template_id: u16,
    },

    /// A `blockLength` smaller than the root block of the message.
    ///
    /// SBE lets a newer schema version append fields, so a larger block is
    /// accepted and its extra bytes skipped; a smaller one would put the
    /// fields this version reads outside the block.
    #[error("block length {block_length} is below the {minimum} bytes of the {message} root block")]
    BlockLengthTooShort {
        /// The message name.
        message: &'static str,
        /// The `blockLength` found in the header.
        block_length: u16,
        /// The root block length of this message in schema version 0.
        minimum: u16,
    },

    /// An enumeration field holds a value the schema does not define.
    #[error("invalid {field} value {value}")]
    InvalidEnumValue {
        /// The schema field name.
        field: &'static str,
        /// The raw value.
        value: u8,
    },

    /// A `CharacterString` field (a reject or terminate `Reason`) is not
    /// UTF-8, the character encoding FIXP names as normative.
    #[error("{field} is not valid UTF-8")]
    InvalidUtf8 {
        /// The schema field name.
        field: &'static str,
    },
}

/// A message that cannot be encoded.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum FixpEncodeError {
    /// A variable-length field longer than its 16-bit length prefix allows.
    #[error("{field} is {len} bytes, above the {max}-byte maximum of its length prefix")]
    VarDataTooLong {
        /// The schema field name.
        field: &'static str,
        /// The field length in bytes.
        len: usize,
        /// The largest encodable length in bytes (65 535).
        max: usize,
    },

    /// The destination slice cannot hold the encoded message.
    #[error("buffer too small: {needed} bytes needed, {available} available")]
    BufferTooSmall {
        /// Encoded length of the message in bytes.
        needed: usize,
        /// Length of the destination slice in bytes.
        available: usize,
    },

    /// The destination vector cannot grow by the encoded length: its length
    /// would overflow or the allocation failed.
    #[error("cannot grow the destination by {needed} bytes")]
    CapacityOverflow {
        /// Encoded length of the message in bytes.
        needed: usize,
    },
}

/// A local command the session cannot carry out.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum FixpError {
    /// The command is not legal in the current state.
    #[error("{operation} is not allowed while the session is {status:?}")]
    InvalidState {
        /// The command that was refused.
        operation: &'static str,
        /// The state the session was in.
        status: SessionStatus,
    },

    /// Application messages are not allowed on a flow of type None
    /// (FIXP v1.1 section 3.4.4).
    #[error("a {flow:?} flow carries no application messages")]
    FlowCarriesNoApplicationMessages {
        /// This side's outbound flow type.
        flow: FlowType,
    },

    /// Both flows of a point-to-point session would be None, which FIXP v1.1
    /// section 3.4.4.1 forbids.
    #[error("both flows of a session cannot be None")]
    BothFlowsNone,

    /// The outbound sequence counter cannot number another message without
    /// leaving the range a `NextSeqNo` field can carry. The logical session
    /// must end; negotiate a new one.
    #[error("outbound sequence numbers exhausted")]
    SequenceExhausted,

    /// A retransmission batch larger than what is left of the request being
    /// answered.
    #[error("retransmission batch of {count} messages exceeds the {remaining} left in the request")]
    RetransmissionOverrun {
        /// Messages in the batch.
        count: u32,
        /// Messages of the request not yet retransmitted.
        remaining: u32,
    },

    /// No counterparty RetransmitRequest is being answered.
    #[error("no retransmission request is being answered")]
    NoRetransmissionInProgress,

    /// A reason text longer than the 16-bit length prefix of its field.
    #[error("reason of {len} bytes exceeds the {max}-byte maximum")]
    ReasonTooLong {
        /// Reason length in bytes.
        len: usize,
        /// The largest encodable length in bytes (65 535).
        max: usize,
    },

    /// The wall-clock time derived from the [`crate::ClockAnchor`] does not
    /// fit a 64-bit nanosecond count.
    #[error("the session clock is out of range")]
    ClockOutOfRange,

    /// The session has asked the driver to close the transport
    /// ([`crate::Output::CloseTransport`]) and the driver has not reported it
    /// closed yet. Anything sent now would go to the closing transport:
    /// report it closed (`on_transport_closed`) and use a new one.
    #[error("{operation} needs a new transport: the current one is closing")]
    TransportClosing {
        /// The command that was refused.
        operation: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_error_display_names_the_offending_values() {
        let truncated = FixpDecodeError::Truncated {
            needed: 8,
            available: 3,
        };
        assert_eq!(
            truncated.to_string(),
            "truncated message: 8 bytes needed, 3 available"
        );
        let schema = FixpDecodeError::SchemaMismatch {
            schema_id: 7,
            expected: 2748,
        };
        assert_eq!(
            schema.to_string(),
            "schema id 7 is not the FIXP session schema 2748"
        );
        let short = FixpDecodeError::BlockLengthTooShort {
            message: "Sequence",
            block_length: 4,
            minimum: 8,
        };
        assert!(short.to_string().contains("Sequence"));
        let bad_enum = FixpDecodeError::InvalidEnumValue {
            field: "ClientFlow",
            value: 9,
        };
        assert_eq!(bad_enum.to_string(), "invalid ClientFlow value 9");
    }

    #[test]
    fn test_encode_and_command_error_display() {
        let long = FixpEncodeError::VarDataTooLong {
            field: "Reason",
            len: 70_000,
            max: 65_535,
        };
        assert!(long.to_string().contains("70000"));
        let state = FixpError::InvalidState {
            operation: "establish",
            status: SessionStatus::Idle,
        };
        assert_eq!(
            state.to_string(),
            "establish is not allowed while the session is Idle"
        );
    }
}
