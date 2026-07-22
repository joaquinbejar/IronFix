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
//! declared length before it is validated. The ceilings are fixed for
//! integers and presence maps; a string or byte vector is instead bounded by
//! the bytes the peer has actually delivered, since neither has a length the
//! specification caps. A caller that must bound field size does so by bounding
//! the frame it hands in.
//!
//! On error the read offset is left wherever the failure was detected, which
//! differs per entry point. Every error here is fatal for the frame, so a
//! caller must not resume from a partially advanced offset; restart from a
//! known frame boundary instead.

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
/// A 64-bit value carries at most 64 significant bits at seven payload bits
/// per byte; a signed value needs nine payload bytes
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

/// Writes `value` into `dict` under `key`, reusing the stored key when it is
/// already there.
///
/// Operator state is rewritten for the same handful of fields on every message,
/// so the interesting case is the one that must not allocate: an entry that
/// already exists is overwritten in place, and only a key seen for the first
/// time is copied into the map.
pub(crate) fn store(
    dict: &mut HashMap<String, DictionaryValue>,
    key: &str,
    value: DictionaryValue,
) {
    if let Some(slot) = dict.get_mut(key) {
        *slot = value;
    } else {
        dict.insert(key.to_owned(), value);
    }
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

    /// Decodes a stop-bit unsigned integer into a `u128`.
    ///
    /// Identical to [`FastDecoder::decode_uint`] but accumulates in `u128`, so
    /// it can hold the biased `2^64` a nullable unsigned uses to denote
    /// `u64::MAX`. The same [`MAX_INT_ENCODED_LEN`] ceiling bounds the read, so
    /// a hostile over-long encoding is [`FastError::IntegerOverflow`] rather
    /// than an unbounded loop.
    ///
    /// # Errors
    /// [`FastError::UnexpectedEof`] if the input ends mid-value, or
    /// [`FastError::IntegerOverflow`] if the encoding exceeds
    /// [`MAX_INT_ENCODED_LEN`] bytes.
    fn decode_uint_u128(data: &[u8], offset: &mut usize) -> Result<u128, FastError> {
        /// Value of one payload byte position.
        const RADIX: u128 = 1 << PAYLOAD_BITS;

        let mut result: u128 = 0;
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
                | u128::from(byte & PAYLOAD_MASK);

            if byte & STOP_BIT != 0 {
                break;
            }
        }

        Ok(result)
    }

    /// Decodes a nullable unsigned integer.
    ///
    /// FAST represents a nullable unsigned integer with a bias of one: a lone
    /// stop byte is NULL, and any other value is the encoded value minus one.
    /// This is the counterpart of
    /// [`FastEncoder::encode_nullable_uint`](crate::FastEncoder::encode_nullable_uint);
    /// the two must agree, so the bias lives here rather than in every caller,
    /// which is where an off-by-one reappears.
    ///
    /// The representable domain is the full `0..=u64::MAX`: `u64::MAX` biases to
    /// `2^64`, which does not fit `u64`, so the biased value is decoded through
    /// `u128` and only the debiased result is narrowed back to `u64`.
    ///
    /// # Errors
    /// Returns [`FastError::UnexpectedEof`] if the input ends mid-value, or
    /// [`FastError::IntegerOverflow`] if the debiased value exceeds `u64::MAX`
    /// (a hostile over-long encoding) — never a panic and never an unbounded
    /// read.
    pub fn decode_nullable_uint(data: &[u8], offset: &mut usize) -> Result<Option<u64>, FastError> {
        let biased = Self::decode_uint_u128(data, offset)?;
        match biased {
            0 => Ok(None),
            // `checked_sub` keeps the decode path free of bare arithmetic even
            // though the `0` arm above already guarantees `biased >= 1`; the
            // debiased value may still exceed `u64::MAX` for an over-long
            // encoding, which the narrowing rejects as `IntegerOverflow`.
            biased => biased
                .checked_sub(1)
                .and_then(|value| u64::try_from(value).ok())
                .map(Some)
                .ok_or(FastError::IntegerOverflow),
        }
    }

    /// Decodes a nullable signed integer.
    ///
    /// FAST biases only the non-negative half of the range: zero is NULL, a
    /// positive encoded value is one more than the value it denotes, and a
    /// negative encoded value denotes itself. This is the counterpart of
    /// [`FastEncoder::encode_nullable_int`](crate::FastEncoder::encode_nullable_int),
    /// and the bias lives here rather than in every caller for the same reason
    /// it does for the unsigned form.
    ///
    /// The representable domain is `i64::MIN..=i64::MAX - 1`.
    ///
    /// # Arguments
    /// * `data` - The input bytes
    /// * `offset` - Current position (will be updated)
    ///
    /// # Returns
    /// The decoded value, or `None` for NULL.
    ///
    /// # Errors
    /// Returns [`FastError::UnexpectedEof`] if the input ends mid-value, or
    /// [`FastError::IntegerOverflow`] if the encoding is over-long or denotes a
    /// value outside `i64`.
    pub fn decode_nullable_int(data: &[u8], offset: &mut usize) -> Result<Option<i64>, FastError> {
        let raw = Self::decode_int(data, offset)?;

        if raw == 0 {
            return Ok(None);
        }

        if raw < 0 {
            // Negative values carry no bias.
            return Ok(Some(raw));
        }

        raw.checked_sub(1)
            .map(Some)
            .ok_or(FastError::IntegerOverflow)
    }

    /// Decodes a nullable ASCII string.
    ///
    /// The nullable string forms shift each of the FAST 1.1 special encodings
    /// by one leading `0x00`: a lone stop byte is NULL, `0x00 0x80` is the
    /// empty string, and `0x00 0x00 0x80` is the one-character NUL string. Any
    /// other encoding beginning with `0x00` is over-long and is rejected. This
    /// is the counterpart of
    /// [`FastEncoder::encode_nullable_ascii`](crate::FastEncoder::encode_nullable_ascii).
    ///
    /// # Arguments
    /// * `data` - The input bytes
    /// * `offset` - Current position (will be updated)
    ///
    /// # Returns
    /// The decoded string, or `None` for NULL.
    ///
    /// # Errors
    /// Returns [`FastError::UnexpectedEof`] if the stop bit is never reached
    /// before the end of `data`, or [`FastError::InvalidString`] for an
    /// over-long encoding with a leading `0x00`.
    pub fn decode_nullable_ascii(
        data: &[u8],
        offset: &mut usize,
    ) -> Result<Option<String>, FastError> {
        let first_byte = *data.get(*offset).ok_or(FastError::UnexpectedEof)?;

        if first_byte == STOP_BIT {
            *offset += 1;
            return Ok(None);
        }

        if first_byte == 0x00 {
            let second_index = offset.checked_add(1).ok_or(FastError::UnexpectedEof)?;
            let second_byte = *data.get(second_index).ok_or(FastError::UnexpectedEof)?;

            if second_byte == STOP_BIT {
                *offset = second_index
                    .checked_add(1)
                    .ok_or(FastError::UnexpectedEof)?;
                return Ok(Some(String::new()));
            }

            if second_byte != 0x00 {
                return Err(FastError::InvalidString);
            }

            let third_index = second_index
                .checked_add(1)
                .ok_or(FastError::UnexpectedEof)?;
            if *data.get(third_index).ok_or(FastError::UnexpectedEof)? != STOP_BIT {
                return Err(FastError::InvalidString);
            }

            *offset = third_index.checked_add(1).ok_or(FastError::UnexpectedEof)?;
            return Ok(Some(String::from('\0')));
        }

        Self::read_ascii_run(data, offset).map(Some)
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

        Self::read_ascii_run(data, offset)
    }

    /// Reads a stop-bit terminated run of ASCII characters.
    ///
    /// This is the general string form, shared by the nullable and non-nullable
    /// entry points once each has handled its own special encodings.
    ///
    /// # Errors
    /// Returns [`FastError::UnexpectedEof`] if the stop bit is never reached
    /// before the end of `data`.
    fn read_ascii_run(data: &[u8], offset: &mut usize) -> Result<String, FastError> {
        // Locate the stop byte first, so the buffer is sized once from bytes
        // that are actually present rather than grown geometrically -- which
        // otherwise costs twice the field size in peak heap. The scan is
        // bounded by the input, and a field with no stop byte is rejected
        // before anything is allocated.
        let tail = data.get(*offset..).ok_or(FastError::UnexpectedEof)?;
        let len = tail
            .iter()
            .position(|byte| byte & STOP_BIT != 0)
            .ok_or(FastError::UnexpectedEof)?
            .checked_add(1)
            .ok_or(FastError::UnexpectedEof)?;

        let mut result = String::with_capacity(len);
        for _ in 0..len {
            let byte = read_byte(data, offset)?;
            // The payload is always <= 0x7F, so it is a valid ASCII scalar.
            result.push(char::from(byte & PAYLOAD_MASK));
        }

        Ok(result)
    }

    /// Decodes a length-prefixed byte vector, borrowing it from the input.
    ///
    /// The returned slice points into `data`, so decoding a byte field costs
    /// neither an allocation nor a copy: a caller materialises an owned value
    /// only when it needs one to outlive the buffer — which, for a FAST field,
    /// is only true when it becomes operator state.
    ///
    /// The declared length is validated against the bytes actually remaining
    /// **before** it is narrowed to a `usize` or used to bound a slice, so a
    /// hostile length prefix can never index out of bounds.
    ///
    /// # Arguments
    /// * `data` - The input bytes
    /// * `offset` - Current position (will be updated)
    ///
    /// # Returns
    /// The decoded bytes, borrowed from `data`.
    ///
    /// # Errors
    /// Returns [`FastError::UnexpectedEof`] if the length prefix is truncated
    /// or declares more bytes than remain in `data`, or
    /// [`FastError::IntegerOverflow`] if the length prefix itself is not a
    /// valid unsigned integer.
    pub fn decode_bytes<'a>(data: &'a [u8], offset: &mut usize) -> Result<&'a [u8], FastError> {
        let declared_length = Self::decode_uint(data, offset)?;
        Self::take_bytes(data, offset, declared_length)
    }

    /// Decodes a nullable length-prefixed byte vector, borrowing it from the
    /// input.
    ///
    /// The length prefix is a nullable unsigned integer, so a lone stop byte is
    /// NULL and every other length is biased by one. This is the counterpart of
    /// [`FastEncoder::encode_nullable_bytes`](crate::FastEncoder::encode_nullable_bytes).
    ///
    /// # Arguments
    /// * `data` - The input bytes
    /// * `offset` - Current position (will be updated)
    ///
    /// # Returns
    /// The decoded bytes borrowed from `data`, or `None` for NULL.
    ///
    /// # Errors
    /// Returns [`FastError::UnexpectedEof`] if the length prefix is truncated
    /// or declares more bytes than remain in `data`, or
    /// [`FastError::IntegerOverflow`] if the length prefix is not a valid
    /// unsigned integer.
    pub fn decode_nullable_bytes<'a>(
        data: &'a [u8],
        offset: &mut usize,
    ) -> Result<Option<&'a [u8]>, FastError> {
        match Self::decode_nullable_uint(data, offset)? {
            Some(declared_length) => Self::take_bytes(data, offset, declared_length).map(Some),
            None => Ok(None),
        }
    }

    /// Borrows `declared_length` bytes from `data` at `offset`, validating the
    /// length against the bytes actually present before it is used.
    ///
    /// # Errors
    /// Returns [`FastError::UnexpectedEof`] if `declared_length` exceeds the
    /// bytes remaining in `data`.
    fn take_bytes<'a>(
        data: &'a [u8],
        offset: &mut usize,
        declared_length: u64,
    ) -> Result<&'a [u8], FastError> {
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
        let bytes = data.get(*offset..end).ok_or(FastError::UnexpectedEof)?;
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
    ///
    /// Overwriting an entry that already exists reuses its key, so the steady
    /// state — the same fields updated message after message — allocates
    /// nothing. Only the first write of a given key allocates.
    pub fn set_global(&mut self, key: impl AsRef<str>, value: DictionaryValue) {
        store(&mut self.global_dict, key.as_ref(), value);
    }

    /// Gets a value from a template dictionary.
    #[must_use]
    pub fn get_template(&self, template_id: u32, key: &str) -> Option<&DictionaryValue> {
        self.template_dicts
            .get(&template_id)
            .and_then(|dict| dict.get(key))
    }

    /// Sets a value in a template dictionary.
    ///
    /// As with [`FastDecoder::set_global`], overwriting an existing entry
    /// reuses its key and allocates nothing.
    pub fn set_template(&mut self, template_id: u32, key: impl AsRef<str>, value: DictionaryValue) {
        store(
            self.template_dicts.entry(template_id).or_default(),
            key.as_ref(),
            value,
        );
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
    fn test_decode_nullable_uint_round_trips_through_the_encoder() {
        // The bias lives in one place now, so encoder and decoder cannot
        // disagree about it -- which is exactly where the off-by-one this
        // change fixes used to reappear in every caller.
        for value in [
            None,
            Some(0),
            Some(1),
            Some(127),
            Some(128),
            Some(u64::MAX - 1),
            // u64::MAX biases to 2^64, decoded through u128: the domain now
            // covers the full unsigned range, not 0..=u64::MAX-1.
            Some(u64::MAX),
        ] {
            let mut encoder = crate::FastEncoder::new();
            assert!(encoder.encode_nullable_uint(value).is_ok());
            let buffer = encoder.finish();
            let mut offset = 0;
            assert_eq!(
                FastDecoder::decode_nullable_uint(&buffer, &mut offset),
                Ok(value),
                "round trip failed for {value:?}"
            );
            assert_eq!(offset, buffer.len(), "the whole value must be consumed");
        }
    }

    #[test]
    fn test_decode_nullable_uint_lone_stop_byte_is_null() {
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_nullable_uint(&[0x80], &mut offset),
            Ok(None)
        );
    }

    #[test]
    fn test_decode_nullable_uint_over_long_encoding_is_bounded_overflow() {
        // The full u64 range now decodes, so the remaining hostile case is an
        // encoding longer than MAX_INT_ENCODED_LEN bytes. A ten-byte run with
        // no stop bit exhausts the ceiling on the next read: a bounded
        // IntegerOverflow, never an unbounded loop or a panic.
        let hostile = [0x00u8; MAX_INT_ENCODED_LEN];
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_nullable_uint(&hostile, &mut offset),
            Err(FastError::IntegerOverflow)
        );
    }

    #[test]
    fn test_decode_nullable_uint_boundary_from_external_fixtures() {
        // Hand-built stop-bit fixtures, independent of the encoder, that pin the
        // u128 narrowing branch directly: a properly stopped biased value that
        // does fit u64 after debiasing, and the first one that does not.
        //
        // Biased 2^64 (10 stop-bit bytes, MSB first, stop bit on the last):
        // decodes to 2^64, debiases to u64::MAX. This is the accepted boundary.
        let biased_two_pow_64 = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80];
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_nullable_uint(&biased_two_pow_64, &mut offset),
            Ok(Some(u64::MAX))
        );
        assert_eq!(offset, biased_two_pow_64.len());

        // Biased 2^64 + 1: a valid, fully-stopped ten-byte encoding whose
        // debiased value is 2^64, one past u64::MAX. This exercises the
        // `u64::try_from` narrowing failure, not the byte-count ceiling.
        let biased_two_pow_64_plus_one =
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81];
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_nullable_uint(&biased_two_pow_64_plus_one, &mut offset),
            Err(FastError::IntegerOverflow)
        );
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
            Ok(&[1, 2, 3][..])
        );
        assert_eq!(offset, bytes.len());
    }

    #[test]
    fn test_decode_bytes_borrows_from_the_input() {
        // The decoded field must point into the caller's buffer, not a copy of
        // it: that is what makes decoding a byte field allocation-free.
        let data = [0x83, 1, 2, 3];
        let mut offset = 0;
        let decoded = FastDecoder::decode_bytes(&data, &mut offset);
        let payload = data.get(1..4);

        assert!(decoded.is_ok());
        assert!(payload.is_some());

        if let (Ok(decoded), Some(payload)) = (decoded, payload) {
            assert!(
                std::ptr::eq(decoded.as_ptr(), payload.as_ptr()),
                "the decoded slice must borrow the input buffer, not copy it"
            );
        }
    }

    #[test]
    fn test_decode_bytes_empty_payload() {
        let data = [0x80];
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_bytes(&data, &mut offset),
            Ok(&[][..] as &[u8])
        );
        assert_eq!(offset, 1);
    }

    #[test]
    fn test_decode_nullable_bytes_round_trips_through_the_encoder() {
        for value in [None, Some(&[][..]), Some(&[1, 2, 3][..]), Some(&[0xFF][..])] {
            let mut encoder = FastEncoder::new();
            assert_eq!(encoder.encode_nullable_bytes(value), Ok(()));
            let buffer = encoder.finish();

            let mut offset = 0;
            assert_eq!(
                FastDecoder::decode_nullable_bytes(&buffer, &mut offset),
                Ok(value),
                "nullable bytes round trip {value:?}"
            );
            assert_eq!(offset, buffer.len(), "the whole value must be consumed");
        }
    }

    #[test]
    fn test_decode_nullable_bytes_lone_stop_byte_is_null() {
        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_nullable_bytes(&[0x80], &mut offset),
            Ok(None)
        );
        assert_eq!(offset, 1);
    }

    #[test]
    fn test_decode_nullable_bytes_huge_declared_length_is_unexpected_eof() {
        // A biased length of u64::MAX with a three-byte body.
        let mut data = vec![0x01, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0xFF];
        data.extend_from_slice(&[1, 2, 3]);

        let mut offset = 0;
        assert_eq!(
            FastDecoder::decode_nullable_bytes(&data, &mut offset),
            Err(FastError::UnexpectedEof)
        );
    }

    #[test]
    fn test_decode_nullable_int_round_trips_through_the_encoder() {
        for value in [
            None,
            Some(0),
            Some(1),
            Some(-1),
            Some(63),
            Some(64),
            Some(-64),
            Some(-65),
            Some(i64::MIN),
            Some(i64::MAX - 1),
        ] {
            let mut encoder = FastEncoder::new();
            assert_eq!(encoder.encode_nullable_int(value), Ok(()));
            let buffer = encoder.finish();

            let mut offset = 0;
            assert_eq!(
                FastDecoder::decode_nullable_int(&buffer, &mut offset),
                Ok(value),
                "nullable int round trip {value:?}"
            );
            assert_eq!(offset, buffer.len(), "the whole value must be consumed");
        }
    }

    #[test]
    fn test_decode_nullable_int_biases_only_the_non_negative_half() {
        // Zero is NULL, positive values carry the bias, negative ones do not.
        let cases: [(&[u8], Option<i64>); 4] = [
            (&[0x80], None),
            (&[0x81], Some(0)),
            (&[0x82], Some(1)),
            (&[0xFF], Some(-1)),
        ];

        for (encoded, expected) in cases {
            let mut offset = 0;
            assert_eq!(
                FastDecoder::decode_nullable_int(encoded, &mut offset),
                Ok(expected),
                "{encoded:?}"
            );
        }
    }

    #[test]
    fn test_encode_nullable_int_rejects_the_value_outside_its_domain() {
        let mut encoder = FastEncoder::new();
        assert_eq!(
            encoder.encode_nullable_int(Some(i64::MAX)),
            Err(FastError::IntegerOverflow)
        );
        assert!(
            encoder.is_empty(),
            "an overflowing value must not be biased into the NULL representation"
        );
    }

    #[test]
    fn test_decode_nullable_ascii_round_trips_through_the_encoder() {
        for value in [None, Some(""), Some("\0"), Some("A"), Some("EURUSD")] {
            let mut encoder = FastEncoder::new();
            assert_eq!(encoder.encode_nullable_ascii(value), Ok(()));
            let buffer = encoder.finish();

            let mut offset = 0;
            assert_eq!(
                FastDecoder::decode_nullable_ascii(&buffer, &mut offset),
                Ok(value.map(str::to_string)),
                "nullable ascii round trip {value:?}"
            );
            assert_eq!(offset, buffer.len(), "the whole value must be consumed");
        }
    }

    #[test]
    fn test_decode_nullable_ascii_special_forms_are_shifted_by_one_zero_byte() {
        // Each nullable form is its non-nullable counterpart with one more
        // leading 0x00; confusing the two shifts every value in the message.
        let cases: [(&[u8], Option<&str>); 3] = [
            (&[0x80], None),
            (&[0x00, 0x80], Some("")),
            (&[0x00, 0x00, 0x80], Some("\0")),
        ];

        for (encoded, expected) in cases {
            let mut offset = 0;
            assert_eq!(
                FastDecoder::decode_nullable_ascii(encoded, &mut offset),
                Ok(expected.map(str::to_string)),
                "{encoded:?}"
            );
            assert_eq!(offset, encoded.len());
        }
    }

    #[test]
    fn test_decode_nullable_ascii_over_long_leading_zero_is_invalid_string() {
        for data in [
            &[0x00, b'a' | 0x80][..],
            &[0x00, 0x00, b'a' | 0x80][..],
            &[0x00, 0x00, 0x00, 0x80][..],
        ] {
            let mut offset = 0;
            assert_eq!(
                FastDecoder::decode_nullable_ascii(data, &mut offset),
                Err(FastError::InvalidString),
                "{data:?}"
            );
        }
    }

    #[test]
    fn test_decode_nullable_ascii_truncated_leading_zeros_is_unexpected_eof() {
        for data in [&[0x00][..], &[0x00, 0x00][..]] {
            let mut offset = 0;
            assert_eq!(
                FastDecoder::decode_nullable_ascii(data, &mut offset),
                Err(FastError::UnexpectedEof),
                "{data:?}"
            );
        }
    }

    #[test]
    fn test_encode_nullable_ascii_leading_nul_string_is_invalid_string() {
        let mut encoder = FastEncoder::new();
        assert_eq!(
            encoder.encode_nullable_ascii(Some("\0a")),
            Err(FastError::InvalidString)
        );
        assert!(encoder.is_empty(), "nothing may reach the wire on error");
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
