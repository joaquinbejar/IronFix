/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! Error types for the IronFix FIX protocol engine.
//!
//! This module provides a unified error hierarchy using `thiserror` for typed,
//! domain-specific errors across all IronFix operations.

use std::ops::Range;
use thiserror::Error;

/// Result type alias using [`FixError`] as the error type.
pub type Result<T> = std::result::Result<T, FixError>;

/// Top-level error type for all IronFix operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FixError {
    /// Error during message decoding.
    #[error("decode error: {0}")]
    Decode(#[from] DecodeError),

    /// Error during message encoding.
    #[error("encode error: {0}")]
    Encode(#[from] EncodeError),

    /// Error in session layer operations.
    #[error("session error: {0}")]
    Session(#[from] SessionError),

    /// Error in message store operations.
    #[error("store error: {0}")]
    Store(#[from] StoreError),

    /// I/O error from underlying transport.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors that occur during FIX message decoding.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// Message buffer is incomplete, need more data.
    #[error("incomplete message, need more data")]
    Incomplete,

    /// Invalid BeginString field (tag 8).
    #[error("invalid begin string: expected 8=FIX.x.y")]
    InvalidBeginString,

    /// Missing BodyLength field (tag 9).
    #[error("missing body length field (tag 9)")]
    MissingBodyLength,

    /// Invalid BodyLength value.
    #[error("invalid body length value")]
    InvalidBodyLength,

    /// Missing MsgType field (tag 35).
    #[error("missing msg type field (tag 35)")]
    MissingMsgType,

    /// Invalid MsgType value.
    #[error("invalid msg type: {0}")]
    InvalidMsgType(String),

    /// Checksum mismatch between calculated and declared values.
    #[error("checksum mismatch: calculated {calculated}, declared {declared}")]
    ChecksumMismatch {
        /// Calculated checksum value.
        calculated: u8,
        /// Declared checksum value in message.
        declared: u8,
    },

    /// Invalid tag format (not a valid integer).
    #[error("invalid tag format: {0}")]
    InvalidTag(String),

    /// Missing required field.
    #[error("missing required field: tag {tag}")]
    MissingRequiredField {
        /// The tag number of the missing field.
        tag: u32,
    },

    /// Invalid field value for the expected type.
    #[error("invalid field value for tag {tag}: {reason}")]
    InvalidFieldValue {
        /// The tag number of the field.
        tag: u32,
        /// Description of why the value is invalid.
        reason: String,
    },

    /// Repeating group count mismatch.
    #[error("group count mismatch for tag {count_tag}: expected {expected}, found {actual}")]
    GroupCountMismatch {
        /// The tag containing the group count.
        count_tag: u32,
        /// Expected number of group entries.
        expected: u32,
        /// Actual number of group entries found.
        actual: u32,
    },

    /// Invalid UTF-8 in string field.
    #[error("invalid utf-8 in field: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),

    /// Message exceeds maximum allowed size.
    #[error("message too large: {size} bytes exceeds maximum {max_size}")]
    MessageTooLarge {
        /// Actual message size in bytes.
        size: usize,
        /// Maximum allowed size in bytes.
        max_size: usize,
    },

    /// A field is not terminated by the SOH delimiter.
    ///
    /// Distinct from [`DecodeError::Incomplete`]: the tag was well formed, so
    /// the bytes are structurally a field, but its value never ends.
    #[error("unterminated field for tag {tag}: missing SOH delimiter")]
    UnterminatedField {
        /// The tag whose value is not terminated.
        tag: u32,
    },

    /// A Length/Data field pair declares a byte count the buffer cannot satisfy.
    ///
    /// Raised when the count declared by a `LENGTH` field (for example
    /// `RawDataLength`, tag 95) runs past the end of the buffer, or when the
    /// byte at the declared end of the `DATA` field is not the SOH delimiter.
    #[error(
        "data field {data_tag} declares {declared} bytes not terminated by SOH within {available} remaining bytes"
    )]
    InvalidDataLength {
        /// The tag of the `DATA` field being framed.
        data_tag: u32,
        /// The byte count declared by the paired `LENGTH` field.
        declared: usize,
        /// Bytes actually available after the `=` delimiter.
        available: usize,
    },

    /// A stored byte range does not lie within the message buffer.
    ///
    /// Guards the offset bookkeeping in [`crate::message::RawMessage`], whose
    /// ranges are buffer-relative.
    #[error("range {start}..{end} is out of bounds for a {buffer_len}-byte buffer")]
    RangeOutOfBounds {
        /// Start offset of the offending range.
        start: usize,
        /// End offset of the offending range.
        end: usize,
        /// Length of the buffer the range was applied to.
        buffer_len: usize,
    },
}

/// Errors that occur during FIX message encoding.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    /// Buffer capacity exceeded during encoding.
    #[error("buffer overflow: need {needed} bytes, have {available}")]
    BufferOverflow {
        /// Bytes needed to complete encoding.
        needed: usize,
        /// Bytes available in buffer.
        available: usize,
    },

    /// Missing required field during encoding.
    #[error("missing required field: tag {tag}")]
    MissingRequiredField {
        /// The tag number of the missing field.
        tag: u32,
    },

    /// Invalid field value for encoding.
    #[error("invalid field value for tag {tag}: {reason}")]
    InvalidFieldValue {
        /// The tag number of the field.
        tag: u32,
        /// Description of why the value is invalid.
        reason: String,
    },

    /// Field value exceeds maximum length.
    #[error("field value too long for tag {tag}: {length} exceeds max {max_length}")]
    FieldTooLong {
        /// The tag number of the field.
        tag: u32,
        /// Actual length of the value.
        length: usize,
        /// Maximum allowed length.
        max_length: usize,
    },
}

/// Errors in FIX session layer operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionError {
    /// Session is not in the correct state for the operation.
    #[error("invalid session state: expected {expected}, current {current}")]
    InvalidState {
        /// Expected state for the operation.
        expected: String,
        /// Current session state.
        current: String,
    },

    /// Logon was rejected by counterparty.
    #[error("logon rejected: {reason}")]
    LogonRejected {
        /// Reason for rejection.
        reason: String,
    },

    /// Heartbeat timeout - no response to TestRequest.
    #[error("heartbeat timeout after {elapsed_ms} milliseconds")]
    HeartbeatTimeout {
        /// Elapsed time in milliseconds since last message.
        elapsed_ms: u64,
    },

    /// Sequence number gap detected.
    #[error("sequence gap detected: expected {expected}, received {received}")]
    SequenceGap {
        /// Expected sequence number.
        expected: u64,
        /// Received sequence number.
        received: u64,
    },

    /// Sequence number too low (possible duplicate).
    #[error("sequence too low: expected >= {expected}, received {received}")]
    SequenceTooLow {
        /// Minimum expected sequence number.
        expected: u64,
        /// Received sequence number.
        received: u64,
    },

    /// Message rejected by counterparty.
    #[error("message rejected: ref_seq={ref_seq_num}, reason={reason}")]
    MessageRejected {
        /// Reference sequence number of rejected message.
        ref_seq_num: u64,
        /// Rejection reason.
        reason: String,
    },

    /// Resend request for unavailable messages.
    #[error("resend request for unavailable range: {begin}..{end}")]
    ResendUnavailable {
        /// Begin sequence number of requested range.
        begin: u64,
        /// End sequence number of requested range.
        end: u64,
    },

    /// Session configuration error.
    #[error("configuration error: {0}")]
    Configuration(String),

    /// Connection error.
    #[error("connection error: {0}")]
    Connection(String),
}

/// Errors in message store operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreError {
    /// Failed to store message.
    #[error("failed to store message seq={seq_num}: {reason}")]
    StoreFailed {
        /// Sequence number of the message.
        seq_num: u64,
        /// Reason for failure.
        reason: String,
    },

    /// Failed to retrieve message.
    #[error("failed to retrieve message seq={seq_num}: {reason}")]
    RetrieveFailed {
        /// Sequence number of the message.
        seq_num: u64,
        /// Reason for failure.
        reason: String,
    },

    /// Message not found in store.
    #[error("message not found: seq={seq_num}")]
    NotFound {
        /// Sequence number of the missing message.
        seq_num: u64,
    },

    /// Range of messages not available.
    #[error("messages not available for range: {range:?}")]
    RangeNotAvailable {
        /// The requested range of sequence numbers.
        range: Range<u64>,
    },

    /// Store is corrupted.
    #[error("store corrupted: {reason}")]
    Corrupted {
        /// Description of the corruption.
        reason: String,
    },

    /// I/O error in persistent store.
    #[error("store i/o error: {0}")]
    Io(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_error_display() {
        let err = DecodeError::ChecksumMismatch {
            calculated: 100,
            declared: 200,
        };
        assert_eq!(
            err.to_string(),
            "checksum mismatch: calculated 100, declared 200"
        );
    }

    #[test]
    fn test_fix_error_from_decode() {
        let decode_err = DecodeError::Incomplete;
        let fix_err: FixError = decode_err.into();
        assert!(matches!(fix_err, FixError::Decode(DecodeError::Incomplete)));
    }

    #[test]
    fn test_session_error_display() {
        let err = SessionError::SequenceGap {
            expected: 5,
            received: 10,
        };
        assert_eq!(
            err.to_string(),
            "sequence gap detected: expected 5, received 10"
        );
    }

    #[test]
    fn test_store_error_display() {
        let err = StoreError::NotFound { seq_num: 42 };
        assert_eq!(err.to_string(), "message not found: seq=42");
    }
}
