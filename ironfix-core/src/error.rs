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

    /// Invalid UTF-8 in string field.
    #[error("invalid utf-8 in field: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),

    /// A field is not terminated by the SOH delimiter.
    ///
    /// Distinct from [`DecodeError::Incomplete`]: the tag was well formed, so
    /// the bytes are structurally a field, but its value never ends.
    #[error("unterminated field for tag {tag}: missing SOH delimiter")]
    UnterminatedField {
        /// The tag whose value is not terminated.
        tag: u32,
    },

    /// A Length/Data field pair declares a byte count the frame cannot satisfy.
    ///
    /// Raised when the count declared by a `LENGTH` field (for example
    /// `RawDataLength`, tag 95) runs past what the field may consume, or when
    /// the byte at the declared end of the `DATA` field is not the SOH
    /// delimiter.
    #[error(
        "data field {data_tag} declares {declared} bytes not terminated by SOH within {available} remaining bytes"
    )]
    InvalidDataLength {
        /// The tag of the `DATA` field being framed.
        data_tag: u32,
        /// The byte count declared by the paired `LENGTH` field.
        declared: usize,
        /// Bytes the field was allowed to consume: what remains after the `=`
        /// delimiter, bounded by the frame's declared body end when decoding a
        /// whole message. The terminating SOH must fall inside this.
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

/// Rejection reasons for [`crate::types::CompId`] construction.
///
/// A CompID is written verbatim into SenderCompID (49) and TargetCompID (56)
/// on every outbound message, so a value carrying SOH or `=` would inject
/// header fields into the frame. Construction is the chokepoint that makes
/// that unrepresentable.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompIdError {
    /// The value does not fit in the fixed inline storage.
    #[error("comp id is {len} bytes, exceeding the {max_len}-byte inline storage bound")]
    TooLong {
        /// Length of the offered value in bytes.
        len: usize,
        /// Maximum length in bytes, [`crate::types::COMP_ID_MAX_LEN`].
        max_len: usize,
    },

    /// The value contains a byte outside printable ASCII, or the `=`
    /// tag/value separator.
    #[error(
        "comp id contains illegal byte {byte:#04x} at offset {position}: \
         only printable ASCII (0x20..=0x7e) except '=' is allowed"
    )]
    IllegalByte {
        /// The offending byte.
        byte: u8,
        /// Zero-based offset of the offending byte within the value.
        position: usize,
    },
}

/// Rejection reasons for [`crate::types::Timestamp`] construction.
///
/// A `Timestamp` counts nanoseconds since the Unix epoch as an unsigned value
/// bounded by [`crate::types::Timestamp::MAX_NANOS`], so instants before
/// 1970-01-01 and after 2262-04-11 are not representable.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimestampError {
    /// The nanosecond count exceeds the representable range.
    #[error("{nanos} nanoseconds since the epoch exceeds the maximum {max_nanos}")]
    NanosOutOfRange {
        /// The offered nanosecond count.
        nanos: u64,
        /// The largest representable nanosecond count.
        max_nanos: u64,
    },

    /// The millisecond count overflows when scaled to nanoseconds.
    #[error("{millis} milliseconds since the epoch is not representable in nanoseconds")]
    MillisOutOfRange {
        /// The offered millisecond count.
        millis: u64,
    },

    /// A calendar instant falls outside the representable range — before the
    /// Unix epoch, or past the nanosecond ceiling.
    #[error("instant at {seconds} seconds from the epoch is outside the representable range")]
    InstantOutOfRange {
        /// Whole seconds from the Unix epoch, negative before 1970.
        seconds: i64,
    },
}

/// A number that is not a legal FIX field tag.
///
/// FIX tags are positive integers; `0` is neither a standard nor a
/// user-defined tag.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("{tag} is not a legal FIX field tag: tags are positive integers starting at 1")]
pub struct InvalidFieldTag {
    tag: u32,
}

impl InvalidFieldTag {
    /// Creates the error for an offending tag number.
    #[inline]
    #[must_use]
    pub const fn new(tag: u32) -> Self {
        Self { tag }
    }

    /// Returns the offending tag number.
    #[inline]
    #[must_use]
    pub const fn tag(self) -> u32 {
        self.tag
    }
}

/// A byte that is not a legal Side (tag 54) code.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("{value:#04x} is not a FIX Side (tag 54) code")]
pub struct InvalidSide {
    value: u8,
}

impl InvalidSide {
    /// Creates the error for an offending byte.
    #[inline]
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self { value }
    }

    /// Returns the offending byte.
    #[inline]
    #[must_use]
    pub const fn value(self) -> u8 {
        self.value
    }
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
