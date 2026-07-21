/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! Tokio codec for FIX message framing.
//!
//! This module provides a codec that handles FIX message framing over TCP,
//! including BeginString, BodyLength, and Checksum validation.

use bytes::{BufMut, BytesMut};
use ironfix_tagvalue::checksum::{calculate_checksum, parse_checksum};
use memchr::memchr;
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

/// Errors that can occur during codec operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// Message is incomplete, need more data.
    #[error("incomplete message")]
    Incomplete,

    /// Invalid BeginString field.
    #[error("invalid begin string: message must start with 8=")]
    InvalidBeginString,

    /// Missing BodyLength field.
    #[error("missing body length field (tag 9)")]
    MissingBodyLength,

    /// Invalid BodyLength value.
    #[error("invalid body length value")]
    InvalidBodyLength,

    /// Checksum mismatch.
    #[error("checksum mismatch: calculated {calculated}, declared {declared}")]
    ChecksumMismatch {
        /// Calculated checksum.
        calculated: u8,
        /// Declared checksum in message.
        declared: u8,
    },

    /// Message exceeds maximum size.
    #[error("message too large: {size} bytes exceeds maximum {max_size}")]
    MessageTooLarge {
        /// Actual message size.
        size: usize,
        /// Maximum allowed size.
        max_size: usize,
    },

    /// I/O error.
    #[error("io error: {0}")]
    Io(String),
}

impl From<std::io::Error> for CodecError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

/// SOH delimiter.
const SOH: u8 = 0x01;

/// Tokio codec for FIX message framing.
///
/// Handles parsing of FIX messages from a byte stream, validating
/// BeginString, BodyLength, and optionally Checksum.
#[derive(Debug, Clone)]
pub struct FixCodec {
    /// Maximum message size in bytes.
    max_message_size: usize,
    /// Whether to validate checksums.
    validate_checksum: bool,
}

impl FixCodec {
    /// Creates a new codec with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_message_size: 1024 * 1024, // 1MB
            validate_checksum: true,
        }
    }

    /// Sets the maximum message size.
    #[must_use]
    pub const fn with_max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    /// Sets whether to validate checksums.
    #[must_use]
    pub const fn with_checksum_validation(mut self, validate: bool) -> Self {
        self.validate_checksum = validate;
        self
    }
}

impl Default for FixCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for FixCodec {
    type Item = BytesMut;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Minimum FIX message size: 8=FIX.4.2|9=X|35=0|10=XXX| (minimum ~25 bytes)
        if src.len() < 20 {
            return Ok(None);
        }

        // Validate BeginString starts with "8="
        if src.len() < 2 || &src[0..2] != b"8=" {
            return Err(CodecError::InvalidBeginString);
        }

        // Find first SOH to get BeginString value
        let first_soh = match memchr(SOH, src) {
            Some(pos) => pos,
            None => return Ok(None),
        };

        // Find BodyLength field (9=XXX|)
        let body_len_start = first_soh + 1;
        if src.len() < body_len_start + 3 {
            return Ok(None);
        }

        if &src[body_len_start..body_len_start + 2] != b"9=" {
            return Err(CodecError::MissingBodyLength);
        }

        // Find SOH after BodyLength
        let body_len_soh = match memchr(SOH, &src[body_len_start..]) {
            Some(pos) => body_len_start + pos,
            None => return Ok(None),
        };

        // Parse BodyLength value
        let body_len_str = std::str::from_utf8(&src[body_len_start + 2..body_len_soh])
            .map_err(|_| CodecError::InvalidBodyLength)?;
        let body_length: usize = body_len_str
            .parse()
            .map_err(|_| CodecError::InvalidBodyLength)?;

        // Calculate total message length
        // BodyLength counts from after 9=XXX| to before 10=
        // Total = header + body + trailer (10=XXX|)
        // BodyLength is attacker-controlled: fold with checked arithmetic so a
        // hostile declared length errors instead of overflowing usize.
        let total_length = body_len_soh
            .checked_add(1)
            .and_then(|n| n.checked_add(body_length))
            .and_then(|n| n.checked_add(7)) // +7 for |10=XXX|
            .ok_or(CodecError::InvalidBodyLength)?;

        // Check maximum size
        if total_length > self.max_message_size {
            return Err(CodecError::MessageTooLarge {
                size: total_length,
                max_size: self.max_message_size,
            });
        }

        // Check if we have the complete message
        if src.len() < total_length {
            src.reserve(total_length - src.len());
            return Ok(None);
        }

        // Validate checksum if enabled
        if self.validate_checksum {
            // Checksum is at total_length - 4 to total_length - 1 (3 digits)
            let checksum_start = total_length - 4;
            let checksum_bytes = &src[checksum_start..checksum_start + 3];

            let declared = parse_checksum(checksum_bytes).ok_or(CodecError::InvalidBodyLength)?;

            // Calculate checksum of everything before 10=
            let checksum_field_start = total_length - 7;
            let calculated = calculate_checksum(&src[..checksum_field_start]);

            if calculated != declared {
                return Err(CodecError::ChecksumMismatch {
                    calculated,
                    declared,
                });
            }
        }

        // Extract the complete message
        let message = src.split_to(total_length);
        Ok(Some(message))
    }
}

impl Encoder<&[u8]> for FixCodec {
    type Error = CodecError;

    fn encode(&mut self, item: &[u8], dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(item.len());
        dst.put_slice(item);
        Ok(())
    }
}

impl Encoder<BytesMut> for FixCodec {
    type Error = CodecError;

    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(item.len());
        dst.put_slice(&item);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fix_message(body: &str) -> Vec<u8> {
        let header = format!("8=FIX.4.4\x019={}\x01", body.len());
        let without_checksum = format!("{}{}", header, body);
        let checksum = calculate_checksum(without_checksum.as_bytes());
        format!("{}10={:03}\x01", without_checksum, checksum).into_bytes()
    }

    #[test]
    fn test_codec_decode_complete_message() {
        let mut codec = FixCodec::new();
        let msg = make_fix_message("35=0\x01");
        let mut buf = BytesMut::from(&msg[..]);

        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_some());
        assert!(buf.is_empty());
    }

    #[test]
    fn test_codec_decode_incomplete() {
        let mut codec = FixCodec::new();
        let msg = make_fix_message("35=0\x01");
        let mut buf = BytesMut::from(&msg[..msg.len() - 5]);

        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_codec_decode_body_length_overflow() {
        let mut codec = FixCodec::new();
        let msg = format!("8=FIX.4.4\x019={}\x0135=0\x0110=000\x01", usize::MAX);
        let mut buf = BytesMut::from(msg.as_bytes());

        // Must error, not overflow the framing arithmetic.
        assert!(matches!(
            codec.decode(&mut buf),
            Err(CodecError::InvalidBodyLength)
        ));
    }

    #[test]
    fn test_codec_decode_body_length_too_large() {
        let mut codec = FixCodec::new();
        let msg = format!("8=FIX.4.4\x019={}\x0135=0\x0110=000\x01", 10 * 1024 * 1024);
        let mut buf = BytesMut::from(msg.as_bytes());

        assert!(matches!(
            codec.decode(&mut buf),
            Err(CodecError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn test_codec_decode_invalid_begin_string() {
        let mut codec = FixCodec::new();
        // Message without proper 8= prefix (needs at least 20 bytes)
        let mut buf = BytesMut::from(&b"9=FIX.4.4\x019=5\x0135=0\x0110=000\x01"[..]);

        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(CodecError::InvalidBeginString)));
    }

    #[test]
    fn test_codec_decode_checksum_mismatch() {
        let mut codec = FixCodec::new();
        let mut buf = BytesMut::from(&b"8=FIX.4.4\x019=5\x0135=0\x0110=000\x01"[..]);

        let result = codec.decode(&mut buf);
        assert!(matches!(result, Err(CodecError::ChecksumMismatch { .. })));
    }

    #[test]
    fn test_codec_decode_no_checksum_validation() {
        let mut codec = FixCodec::new().with_checksum_validation(false);
        let mut buf = BytesMut::from(&b"8=FIX.4.4\x019=5\x0135=0\x0110=000\x01"[..]);

        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_codec_encode() {
        let mut codec = FixCodec::new();
        let msg = b"8=FIX.4.4\x019=5\x0135=0\x0110=123\x01";
        let mut dst = BytesMut::new();

        codec.encode(&msg[..], &mut dst).unwrap();
        assert_eq!(&dst[..], msg);
    }
}
