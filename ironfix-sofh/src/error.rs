/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! The typed error of the SOFH framing layer.
//!
//! Every framing failure, on decode and on encode, is one [`SofhError`]
//! variant. None of them is a panic, and none of them is reached by allocating
//! a buffer sized from the input.

use thiserror::Error;

/// Errors raised while framing or unframing SOFH messages.
///
/// # Every error is fatal for the stream
///
/// The tag=value `FixCodec` can skip a garbled frame because a FIX frame opens
/// with a literal anchor (`8=FIX…`) that a resynchronisation can search for.
/// A Simple Open Framing Header has no such anchor: it is two binary integers,
/// and any six bytes of a payload read as a plausible header. Once a declared
/// `Message_Length` cannot be trusted, the position of the next frame is
/// unknown, and guessing one would hand payload bytes up as forged frames. So
/// no variant here is recoverable:
///
/// - on decode, nothing is consumed from the read buffer and the same bytes
///   produce the same error again. The caller must close the connection.
///   `tokio_util::codec::Framed` already ends its stream at the first decoder
///   error, which is the right behaviour here;
/// - on encode, nothing is written to the destination buffer.
///
/// An encoding type the receiver has no codec for is **not** an error: the
/// frame boundary does not depend on it, so the frame is returned with its
/// encoding type preserved (see [`crate::EncodingType`]) and the caller
/// decides whether to skip it, as SOFH v1.0 intends.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SofhError {
    /// The `Message_Length` is below the smallest legal frame.
    ///
    /// SOFH v1.0 defines `Message_Length` as the length of the message
    /// *including* the 6-byte header, and defines a message as 1..n bytes, so
    /// the smallest legal frame is 7 bytes. A declared length of 0 to 5 cannot
    /// even cover its own header; a declared length of 6 frames an empty
    /// message. On encode, an empty payload is refused with this variant, so
    /// the codec never sends a frame it would refuse to receive.
    #[error(
        "message length {length} is below the minimum of {min_length} bytes (the 6-byte header and at least one payload byte)"
    )]
    MessageLengthTooSmall {
        /// The declared, or on encode the computed, `Message_Length` in bytes.
        length: u32,
        /// The smallest legal `Message_Length` in bytes (7).
        min_length: u32,
    },

    /// The `Message_Length` exceeds the configured ceiling
    /// ([`crate::SofhCodec::with_max_message_size`]).
    ///
    /// Raised on decode as soon as the header is buffered, before anything is
    /// reserved for the frame, and on encode before anything is written.
    #[error("message too large: {size} bytes exceeds maximum {max_size}")]
    MessageTooLarge {
        /// The declared, or on encode the computed, `Message_Length` in bytes,
        /// header included.
        size: u32,
        /// The configured ceiling in bytes, header included.
        max_size: u32,
    },

    /// A payload too long to be framed at all: the payload plus the 6-byte
    /// header does not fit the 4-octet `Message_Length` field.
    ///
    /// Encode only. The decoder never sees it, since every declared length
    /// fits the field by construction.
    #[error(
        "payload of {payload_len} bytes cannot be framed: the message length would exceed the 4-octet Message_Length field"
    )]
    PayloadTooLong {
        /// The payload length in bytes.
        payload_len: usize,
    },

    /// The stream ended inside a frame.
    ///
    /// Raised by `Decoder::decode_eof` only. While the stream is open, an
    /// incomplete frame is `Ok(None)`, the `tokio_util` idiom for "read more".
    #[error("stream ended inside a frame: {received} bytes received, {expected} expected")]
    Truncated {
        /// Bytes buffered when the stream ended.
        received: usize,
        /// Bytes the frame needed: its declared `Message_Length` when the
        /// header was complete, otherwise the 6 bytes of the header itself.
        expected: usize,
    },

    /// An I/O error from the underlying transport.
    ///
    /// Carried as its message so the error stays `Clone` and `Eq`, as
    /// `ironfix_transport::CodecError::Io` does.
    #[error("io error: {0}")]
    Io(String),
}

impl From<std::io::Error> for SofhError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sofh_error_from_io_error_keeps_the_message() {
        let error = SofhError::from(std::io::Error::other("connection reset"));
        assert_eq!(error, SofhError::Io("connection reset".to_owned()));
    }

    #[test]
    fn test_sofh_error_display_names_the_offending_values() {
        let too_small = SofhError::MessageLengthTooSmall {
            length: 3,
            min_length: 7,
        };
        assert_eq!(
            too_small.to_string(),
            "message length 3 is below the minimum of 7 bytes (the 6-byte header and at least one payload byte)"
        );

        let too_large = SofhError::MessageTooLarge {
            size: 2_000_000,
            max_size: 1_048_576,
        };
        assert_eq!(
            too_large.to_string(),
            "message too large: 2000000 bytes exceeds maximum 1048576"
        );

        let truncated = SofhError::Truncated {
            received: 4,
            expected: 6,
        };
        assert_eq!(
            truncated.to_string(),
            "stream ended inside a frame: 4 bytes received, 6 expected"
        );

        let too_long = SofhError::PayloadTooLong { payload_len: 9 };
        assert!(too_long.to_string().contains("payload of 9 bytes"));
    }
}
