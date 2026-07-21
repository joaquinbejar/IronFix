/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! FAST protocol decoder.
//!
//! This module provides decoding of FAST-encoded messages using stop-bit
//! encoding and presence maps.
//!
//! Every function here is an untrusted-input parser: the bytes arrive from a
//! counterparty over a socket. Malformed input maps to a typed [`FastError`]
//! with a resource ceiling — never a panic, never an allocation sized from a
//! declared length that has not been validated against the bytes actually
//! available.

use crate::error::FastError;
use crate::operators::DictionaryValue;
use crate::pmap::PresenceMap;
use std::collections::HashMap;

/// Stop bit: set on the final byte of a stop-bit encoded value.
pub(crate) const STOP_BIT: u8 = 0x80;

/// Mask selecting the seven payload bits of a stop-bit encoded byte.
pub(crate) const PAYLOAD_MASK: u8 = 0x7F;

/// Number of payload bits carried by each stop-bit encoded byte.
pub(crate) const PAYLOAD_BITS: usize = 7;

/// Bit 6 of the most significant payload byte: the sign of a signed integer.
pub(crate) const SIGN_BIT: u8 = 0x40;

/// Maximum number of bytes a stop-bit encoded 64-bit integer may occupy.
///
/// A 64-bit value carries at most 64 significant bits at
/// [`PAYLOAD_BITS`] bits per byte; a signed value needs nine payload bytes
/// plus one sign-carry byte, so ten bytes is the longest legal encoding of
/// either `i64::MIN` / `i64::MAX` or `u64::MAX`.
///
/// Anything longer is rejected as [`FastError::IntegerOverflow`]. This is the
/// resource ceiling that stops a hostile stream from spinning the decoder over
/// an unbounded run of continuation bytes whose value never trips the
/// arithmetic check (a run of `0x00` or `0x7F` bytes accumulates no new
/// magnitude).
pub const MAX_INT_ENCODED_LEN: usize = 10;

/// Reads one byte and advances `offset`.
///
/// # Errors
/// Returns [`FastError::UnexpectedEof`] if `offset` is at or past the end of
/// `data`.
#[inline]
pub(crate) fn read_byte(data: &[u8], offset: &mut usize) -> Result<u8, FastError> {
    let byte = *data.get(*offset).ok_or(FastError::UnexpectedEof)?;
    // `get` succeeded, so `*offset < data.len() <= isize::MAX`; the increment
    // cannot overflow a `usize`.
    *offset += 1;
    Ok(byte)
}

/// FAST protocol decoder.
#[derive(Debug)]
pub struct FastDecoder {
    /// Global dictionary for operator state.
    global_dict: HashMap<String, DictionaryValue>,
    /// Template-specific dictionaries.
    template_dicts: HashMap<u32, HashMap<String, DictionaryValue>>,
    /// Last used template ID.
    last_template_id: Option<u32>,
}

impl FastDecoder {
    /// Creates a new FAST decoder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            global_dict: HashMap::new(),
            template_dicts: HashMap::new(),
            last_template_id: None,
        }
    }

    /// Resets the decoder state.
    pub fn reset(&mut self) {
        self.global_dict.clear();
        self.template_dicts.clear();
        self.last_template_id = None;
    }

    /// Decodes an unsigned integer using stop-bit encoding.
    ///
    /// Over-long encodings are tolerated up to [`MAX_INT_ENCODED_LEN`] bytes,
    /// which is the longest legal encoding of `u64::MAX`.
    ///
    /// # Arguments
    /// * `data` - The input bytes
    /// * `offset` - Current position (will be updated)
    ///
    /// # Returns
    /// The decoded unsigned integer.
    ///
    /// # Errors
    /// Returns [`FastError::UnexpectedEof`] if the stop bit is never reached
    /// before the end of `data`, or [`FastError::IntegerOverflow`] if the
    /// encoding is longer than [`MAX_INT_ENCODED_LEN`] bytes or denotes a
    /// value that does not fit in a `u64`.
    pub fn decode_uint(data: &[u8], offset: &mut usize) -> Result<u64, FastError> {
        /// Value of one payload byte position.
        const RADIX: u64 = 1 << PAYLOAD_BITS;

        let mut result: u64 = 0;
        let mut consumed: usize = 0;

        loop {
            if consumed == MAX_INT_ENCODED_LEN {
                return Err(FastError::IntegerOverflow);
            }
            let byte = read_byte(data, offset)?;
            consumed += 1;

            // `checked_mul` rejects any value that would lose significant bits.
            // The product's low seven bits are zero, so the `|` below cannot
            // carry and is exact.
            result = result
                .checked_mul(RADIX)
                .ok_or(FastError::IntegerOverflow)?
                | u64::from(byte & PAYLOAD_MASK);

            if byte & STOP_BIT != 0 {
                break;
            }
        }

        Ok(result)
    }

    /// Decodes a signed integer using stop-bit encoding.
    ///
    /// The sign is taken from bit 6 of the first byte and the value is
    /// accumulated in two's complement, so a leading sign-carry byte (`0x00`
    /// for a positive value, `0x7F` for a negative one) decodes transparently.
    ///
    /// # Arguments
    /// * `data` - The input bytes
    /// * `offset` - Current position (will be updated)
    ///
    /// # Returns
    /// The decoded signed integer.
    ///
    /// # Errors
    /// Returns [`FastError::UnexpectedEof`] if the stop bit is never reached
    /// before the end of `data`, or [`FastError::IntegerOverflow`] if the
    /// encoding is longer than [`MAX_INT_ENCODED_LEN`] bytes or denotes a
    /// value that does not fit in an `i64`.
    pub fn decode_int(data: &[u8], offset: &mut usize) -> Result<i64, FastError> {
        /// Value of one payload byte position.
        const RADIX: i64 = 1 << PAYLOAD_BITS;

        let first_byte = *data.get(*offset).ok_or(FastError::UnexpectedEof)?;
        let negative = (first_byte & SIGN_BIT) != 0;

        // Sign extension: a negative value starts from all-ones so the
        // accumulated two's complement stays negative.
        let mut result: i64 = if negative { -1 } else { 0 };
        let mut consumed: usize = 0;

        loop {
            if consumed == MAX_INT_ENCODED_LEN {
                return Err(FastError::IntegerOverflow);
            }
            let byte = read_byte(data, offset)?;
            consumed += 1;

            // `checked_mul` rejects any value that would lose significant bits
            // in either direction. The product is a multiple of `RADIX`, so its
            // low seven bits are zero and the `|` below is exact.
            result = result
                .checked_mul(RADIX)
                .ok_or(FastError::IntegerOverflow)?
                | i64::from(byte & PAYLOAD_MASK);

            if byte & STOP_BIT != 0 {
                break;
            }
        }

        Ok(result)
    }

    /// Decodes an ASCII string using stop-bit encoding.
    ///
    /// Follows the FAST 1.1 string encodings: a lone stop byte (`0x80`) is the
    /// empty string and `0x00 0x80` is the one-character NUL string. Any other
    /// encoding beginning with `0x00` is over-long and is rejected.
    ///
    /// # Arguments
    /// * `data` - The input bytes
    /// * `offset` - Current position (will be updated)
    ///
    /// # Returns
    /// The decoded string.
    ///
    /// # Errors
    /// Returns [`FastError::UnexpectedEof`] if the stop bit is never reached
    /// before the end of `data`, or [`FastError::InvalidString`] for an
    /// over-long encoding with a leading `0x00`.
    pub fn decode_ascii(data: &[u8], offset: &mut usize) -> Result<String, FastError> {
        let first_byte = *data.get(*offset).ok_or(FastError::UnexpectedEof)?;

        if first_byte == STOP_BIT {
            *offset += 1;
            return Ok(String::new());
        }

        if first_byte == 0x00 {
            let next_index = offset.checked_add(1).ok_or(FastError::UnexpectedEof)?;
            let second_byte = *data.get(next_index).ok_or(FastError::UnexpectedEof)?;
            if second_byte != STOP_BIT {
                return Err(FastError::InvalidString);
            }
            *offset += 2;
            return Ok(String::from('\0'));
        }

        let mut result = String::new();

        loop {
            let byte = read_byte(data, offset)?;

            // The payload is always <= 0x7F, so it is a valid ASCII scalar.
            result.push(char::from(byte & PAYLOAD_MASK));

            if byte & STOP_BIT != 0 {
                break;
            }
        }

        Ok(result)
    }

    /// Decodes a length-prefixed byte vector.
    ///
    /// The declared length is validated against the bytes actually remaining
    /// **before** it is narrowed to a `usize` or used to size an allocation,
    /// so a hostile length prefix can never over-allocate or index out of
    /// bounds.
    ///
    /// # Arguments
    /// * `data` - The input bytes
    /// * `offset` - Current position (will be updated)
    ///
    /// # Returns
    /// The decoded bytes.
    ///
    /// # Errors
    /// Returns [`FastError::UnexpectedEof`] if the length prefix is truncated
    /// or declares more bytes than remain in `data`, or
    /// [`FastError::IntegerOverflow`] if the length prefix itself is not a
    /// valid unsigned integer.
    pub fn decode_bytes(data: &[u8], offset: &mut usize) -> Result<Vec<u8>, FastError> {
        let declared_length = Self::decode_uint(data, offset)?;

        let remaining = data
            .len()
            .checked_sub(*offset)
            .ok_or(FastError::UnexpectedEof)?;

        // Narrow in the direction that cannot truncate: a length that does not
        // fit in a `usize` cannot possibly be available on this target either.
        let length = usize::try_from(declared_length).map_err(|_| FastError::UnexpectedEof)?;
        if length > remaining {
            return Err(FastError::UnexpectedEof);
        }

        let end = offset.checked_add(length).ok_or(FastError::UnexpectedEof)?;
        let bytes = data
            .get(*offset..end)
            .ok_or(FastError::UnexpectedEof)?
            .to_vec();
        *offset = end;

        Ok(bytes)
    }

    /// Decodes a presence map.
    ///
    /// # Arguments
    /// * `data` - The input bytes
    /// * `offset` - Current position (will be updated)
    ///
    /// # Returns
    /// The decoded presence map.
    ///
    /// # Errors
    /// Returns [`FastError::UnexpectedEof`] if the data is incomplete, or
    /// [`FastError::PresenceMapTooLarge`] if the map exceeds
    /// [`crate::pmap::MAX_PMAP_BYTES`].
    pub fn decode_pmap(data: &[u8], offset: &mut usize) -> Result<PresenceMap, FastError> {
        PresenceMap::decode(data, offset)
    }

    /// Gets a value from the global dictionary.
    #[must_use]
    pub fn get_global(&self, key: &str) -> Option<&DictionaryValue> {
        self.global_dict.get(key)
    }

    /// Sets a value in the global dictionary.
    pub fn set_global(&mut self, key: impl Into<String>, value: DictionaryValue) {
        self.global_dict.insert(key.into(), value);
    }

    /// Gets a value from a template dictionary.
    #[must_use]
    pub fn get_template(&self, template_id: u32, key: &str) -> Option<&DictionaryValue> {
        self.template_dicts
            .get(&template_id)
            .and_then(|dict| dict.get(key))
    }

    /// Sets a value in a template dictionary.
    pub fn set_template(
        &mut self,
        template_id: u32,
        key: impl Into<String>,
        value: DictionaryValue,
    ) {
        self.template_dicts
            .entry(template_id)
            .or_default()
            .insert(key.into(), value);
    }

    /// Returns the last used template ID.
    #[must_use]
    pub const fn last_template_id(&self) -> Option<u32> {
        self.last_template_id
    }

    /// Sets the last used template ID.
    pub fn set_last_template_id(&mut self, id: u32) {
        self.last_template_id = Some(id);
    }
}

impl Default for FastDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoder::FastEncoder;

    /// Encodes `value` as a signed integer and decodes it back, asserting the
    /// decoder consumed exactly the bytes the encoder produced.
    fn round_trip_int(value: i64) -> Result<i64, FastError> {
        let mut encoder = FastEncoder::new();
        encoder.encode_int(value);
        let bytes = encoder.finish();

        let mut offset = 0;
        let decoded = FastDecoder::decode_int(&bytes, &mut offset)?;
        assert_eq!(
            offset,
            bytes.len(),
            "decode_int must consume the whole encoding of {value}"
        );
        Ok(decoded)
    }

    /// Encodes `value` as an unsigned integer and decodes it back, asserting
    /// the decoder consumed exactly the bytes the encoder produced.
    fn round_trip_uint(value: u64) -> Result<u64, FastError> {
        let mut encoder = FastEncoder::new();
        encoder.encode_uint(value);
        let bytes = encoder.finish();

        let mut offset = 0;
        let decoded = FastDecoder::decode_uint(&bytes, &mut offset)?;
        assert_eq!(
            offset,
            bytes.len(),
            "decode_uint must consume the whole encoding of {value}"
        );
        Ok(decoded)
    }

    #[test]
    fn test_decode_uint_single_byte() {
        let data = [0x81]; // 1 with stop bit
        let mut offset = 0;
        assert_eq!(FastDecoder::decode_uint(&data, &mut offset), Ok(1));
        assert_eq!(offset, 1);
    }

    #[test]
    fn test_decode_uint_multi_byte() {
        let data = [0x00, 0x81]; // 1 in two bytes
        let mut offset = 0;
        assert_eq!(FastDecoder::decode_uint(&data, &mut offset), Ok(1));
        assert_eq!(offset, 2);
    }

    #[test]
    fn test_decode_uint_larger() {
        // 942 = 7 * 128 + 46; first byte 7 (0x07), second byte 46 | 0x80 (0xAE)
        let data = [0x07, 0xAE];
        let mut offset = 0;
        assert_eq!(FastDecoder::decode_uint(&data, &mut offset), Ok(942));
    }

    #[test]
    fn test_decode_uint_max_uses_ten_bytes() {
        let data = [0x01, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0xFF];
        let mut offset = 0;
        assert_eq!(FastDecoder::decode_uint(&data, &mut offset), Ok(u64::MAX));
        assert_eq!(offset, MAX_INT_ENCODED_LEN);
    }

    #[test]
    fn test_decode_uint_truncated_is_unexpected_eof() {
        // No stop bit anywhere.
        let data = [0x01, 0x02, 0x03];
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_uint(&data, &mut offset),
            Err(FastError::UnexpectedEof)
        );
    }

    #[test]
    fn test_decode_uint_empty_input_is_unexpected_eof() {
        let data: [u8; 0] = [];
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_uint(&data, &mut offset),
            Err(FastError::UnexpectedEof)
        );
    }

    #[test]
    fn test_decode_uint_value_above_u64_max_is_integer_overflow() {
        // Ten bytes whose value is 2 * 2^63 — one bit too wide for a u64.
        let data = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80];
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_uint(&data, &mut offset),
            Err(FastError::IntegerOverflow)
        );
    }

    #[test]
    fn test_decode_uint_over_long_encoding_is_integer_overflow() {
        // Eleven continuation bytes that never accumulate magnitude: only the
        // byte-count ceiling can reject this.
        let mut data = vec![0x00; MAX_INT_ENCODED_LEN + 1];
        data.push(0x80);
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_uint(&data, &mut offset),
            Err(FastError::IntegerOverflow)
        );
    }

    #[test]
    fn test_decode_uint_round_trips_boundaries() {
        let mut values: Vec<u64> = vec![0, u64::MAX];
        for shift in 0..64u32 {
            let Some(base) = 1u64.checked_shl(shift) else {
                continue;
            };
            values.push(base);
            if let Some(below) = base.checked_sub(1) {
                values.push(below);
            }
            if let Some(above) = base.checked_add(1) {
                values.push(above);
            }
        }

        for value in values {
            assert_eq!(round_trip_uint(value), Ok(value), "uint round trip {value}");
        }
    }

    #[test]
    fn test_decode_int_positive() {
        let data = [0x81]; // 1
        let mut offset = 0;
        assert_eq!(FastDecoder::decode_int(&data, &mut offset), Ok(1));
    }

    #[test]
    fn test_decode_int_negative() {
        let data = [0xFF]; // -1
        let mut offset = 0;
        assert_eq!(FastDecoder::decode_int(&data, &mut offset), Ok(-1));
    }

    #[test]
    fn test_decode_int_min_and_max_use_ten_bytes() {
        let max = [0x00, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0xFF];
        let mut offset = 0;
        assert_eq!(FastDecoder::decode_int(&max, &mut offset), Ok(i64::MAX));
        assert_eq!(offset, MAX_INT_ENCODED_LEN);

        let min = [0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80];
        let mut offset = 0;
        assert_eq!(FastDecoder::decode_int(&min, &mut offset), Ok(i64::MIN));
        assert_eq!(offset, MAX_INT_ENCODED_LEN);
    }

    #[test]
    fn test_decode_int_value_below_i64_min_is_integer_overflow() {
        // Ten bytes denoting -(2^69): the sign-extended accumulator overflows.
        let data = [0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80];
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_int(&data, &mut offset),
            Err(FastError::IntegerOverflow)
        );
    }

    #[test]
    fn test_decode_int_over_long_negative_run_is_integer_overflow() {
        // Twelve 0x7F bytes then a stop byte: every byte re-encodes -1, so the
        // arithmetic check never fires and only the byte ceiling rejects it.
        let mut data = vec![0x7F; 12];
        data.push(0xFF);
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_int(&data, &mut offset),
            Err(FastError::IntegerOverflow)
        );
    }

    #[test]
    fn test_decode_int_truncated_is_unexpected_eof() {
        let data = [0x00, 0x40];
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_int(&data, &mut offset),
            Err(FastError::UnexpectedEof)
        );
    }

    #[test]
    fn test_decode_int_empty_input_is_unexpected_eof() {
        let data: [u8; 0] = [];
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_int(&data, &mut offset),
            Err(FastError::UnexpectedEof)
        );
    }

    #[test]
    fn test_encode_int_round_trips_every_seven_bit_boundary() {
        let mut values: Vec<i64> = vec![0, i64::MIN, i64::MAX];

        for shift in 0..63u32 {
            let Some(base) = 1i64.checked_shl(shift) else {
                continue;
            };
            for candidate in [base.checked_sub(1), Some(base), base.checked_add(1)] {
                let Some(value) = candidate else {
                    continue;
                };
                values.push(value);
                if let Some(negated) = value.checked_neg() {
                    values.push(negated);
                }
            }
        }

        for value in values {
            assert_eq!(round_trip_int(value), Ok(value), "int round trip {value}");
        }
    }

    #[test]
    fn test_encode_int_boundaries_are_byte_exact() {
        let cases: [(i64, &[u8]); 13] = [
            (0, &[0x80]),
            (1, &[0x81]),
            (63, &[0xBF]),
            (64, &[0x00, 0xC0]),
            (127, &[0x00, 0xFF]),
            (128, &[0x01, 0x80]),
            (8191, &[0x3F, 0xFF]),
            (8192, &[0x00, 0x40, 0x80]),
            (-1, &[0xFF]),
            (-64, &[0xC0]),
            (-65, &[0x7F, 0xBF]),
            (-128, &[0x7F, 0x80]),
            (-8192, &[0x40, 0x80]),
        ];

        for (value, expected) in cases {
            let mut encoder = FastEncoder::new();
            encoder.encode_int(value);
            assert_eq!(encoder.finish(), expected, "minimal encoding of {value}");
        }
    }

    #[test]
    fn test_decode_ascii() {
        let data = [b'H', b'i', b'!' | 0x80]; // "Hi!"
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_ascii(&data, &mut offset),
            Ok("Hi!".to_string())
        );
        assert_eq!(offset, 3);
    }

    #[test]
    fn test_decode_ascii_lone_stop_byte_is_the_empty_string() {
        let data = [0x80];
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_ascii(&data, &mut offset),
            Ok(String::new())
        );
        assert_eq!(offset, 1);
    }

    #[test]
    fn test_decode_ascii_zero_stop_is_the_nul_string() {
        let data = [0x00, 0x80];
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_ascii(&data, &mut offset),
            Ok("\0".to_string())
        );
        assert_eq!(offset, 2);
    }

    #[test]
    fn test_decode_ascii_over_long_leading_zero_is_invalid_string() {
        // 0x00 followed by anything other than the stop byte is over-long.
        let data = [0x00, 0x00, 0x80];
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_ascii(&data, &mut offset),
            Err(FastError::InvalidString)
        );

        let data = [0x00, b'a' | 0x80];
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_ascii(&data, &mut offset),
            Err(FastError::InvalidString)
        );
    }

    #[test]
    fn test_decode_ascii_truncated_leading_zero_is_unexpected_eof() {
        let data = [0x00];
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_ascii(&data, &mut offset),
            Err(FastError::UnexpectedEof)
        );
    }

    #[test]
    fn test_decode_ascii_without_stop_bit_is_unexpected_eof() {
        let data = *b"Hi";
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_ascii(&data, &mut offset),
            Err(FastError::UnexpectedEof)
        );
    }

    #[test]
    fn test_decode_ascii_round_trips_through_the_encoder() {
        for value in ["", "\0", "A", "Hi!", "EURUSD", "a\0b", "\x7f"] {
            let mut encoder = FastEncoder::new();
            assert_eq!(encoder.encode_ascii(value), Ok(()));
            let bytes = encoder.finish();

            let mut offset = 0;
            assert_eq!(
                FastDecoder::decode_ascii(&bytes, &mut offset),
                Ok(value.to_string()),
                "ascii round trip {value:?}"
            );
            assert_eq!(offset, bytes.len());
        }
    }

    #[test]
    fn test_decode_bytes_round_trip() {
        let mut encoder = FastEncoder::new();
        encoder.encode_bytes(&[1, 2, 3]);
        let bytes = encoder.finish();

        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_bytes(&bytes, &mut offset),
            Ok(vec![1, 2, 3])
        );
        assert_eq!(offset, bytes.len());
    }

    #[test]
    fn test_decode_bytes_empty_payload() {
        let data = [0x80];
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_bytes(&data, &mut offset),
            Ok(Vec::new())
        );
        assert_eq!(offset, 1);
    }

    #[test]
    fn test_decode_bytes_huge_declared_length_is_unexpected_eof() {
        // Stop-bit encoding of u64::MAX as the length prefix, then a short body.
        let mut data = vec![0x01, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0xFF];
        data.extend_from_slice(&[1, 2, 3]);

        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_bytes(&data, &mut offset),
            Err(FastError::UnexpectedEof)
        );
    }

    #[test]
    fn test_decode_bytes_length_one_past_the_end_is_unexpected_eof() {
        // Declares four bytes but only three follow.
        let data = [0x84, 1, 2, 3];
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_bytes(&data, &mut offset),
            Err(FastError::UnexpectedEof)
        );
    }

    #[test]
    fn test_decode_bytes_truncated_length_prefix_is_unexpected_eof() {
        let data = [0x01];
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_bytes(&data, &mut offset),
            Err(FastError::UnexpectedEof)
        );
    }

    #[test]
    fn test_decode_pmap_delegates_to_presence_map() {
        let data = [0b1100_0000];
        let mut offset = 0;
        let decoded = FastDecoder::decode_pmap(&data, &mut offset);
        assert!(decoded.is_ok());
        if let Ok(pmap) = decoded {
            assert_eq!(pmap.len(), PAYLOAD_BITS);
            assert_eq!(pmap.bit(0), Some(true));
        }
        assert_eq!(offset, 1);
    }

    #[test]
    fn test_decoder_dictionary() {
        let mut decoder = FastDecoder::new();

        decoder.set_global("test", DictionaryValue::Int(42));
        assert_eq!(
            decoder.get_global("test").and_then(DictionaryValue::as_i64),
            Some(42)
        );

        decoder.set_template(1, "field", DictionaryValue::UInt(100));
        assert_eq!(
            decoder
                .get_template(1, "field")
                .and_then(DictionaryValue::as_u64),
            Some(100)
        );
    }

    #[test]
    fn test_decoder_reset_clears_state() {
        let mut decoder = FastDecoder::new();
        decoder.set_global("test", DictionaryValue::Int(1));
        decoder.set_last_template_id(7);
        assert_eq!(decoder.last_template_id(), Some(7));

        decoder.reset();
        assert!(decoder.get_global("test").is_none());
        assert_eq!(decoder.last_template_id(), None);
    }
}
