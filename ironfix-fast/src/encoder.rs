/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! FAST protocol encoder.
//!
//! This module provides encoding of values using FAST stop-bit encoding.
//!
//! Every encoding produced here is minimal — the shortest byte sequence that
//! decodes back to the same value — and never longer than
//! [`MAX_INT_ENCODED_LEN`] for an integer, so the encoder can never emit a
//! frame its own decoder would reject.

use crate::decoder::{MAX_INT_ENCODED_LEN, PAYLOAD_BITS, PAYLOAD_MASK, SIGN_BIT, STOP_BIT, store};
use crate::error::FastError;
use crate::operators::DictionaryValue;
use smallvec::SmallVec;
use std::collections::HashMap;

/// Scratch buffer for one stop-bit encoded integer.
///
/// Sized so a full-width `i64` or `u64` encoding never spills to the heap.
type IntScratch = SmallVec<[u8; MAX_INT_ENCODED_LEN]>;

/// FAST protocol encoder.
#[derive(Debug)]
pub struct FastEncoder {
    /// Output buffer.
    buffer: Vec<u8>,
    /// Global dictionary for operator state.
    global_dict: HashMap<String, DictionaryValue>,
    /// Template-specific dictionaries.
    template_dicts: HashMap<u32, HashMap<String, DictionaryValue>>,
}

impl FastEncoder {
    /// Creates a new FAST encoder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            global_dict: HashMap::new(),
            template_dicts: HashMap::new(),
        }
    }

    /// Creates a new encoder with pre-allocated capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
            global_dict: HashMap::new(),
            template_dicts: HashMap::new(),
        }
    }

    /// Encodes an unsigned integer using stop-bit encoding.
    ///
    /// The encoding is minimal: `0` is a single stop byte and `u64::MAX`
    /// occupies [`MAX_INT_ENCODED_LEN`] bytes.
    ///
    /// # Arguments
    /// * `value` - The value to encode
    pub fn encode_uint(&mut self, value: u64) {
        let mut bytes = IntScratch::new();
        let mut remaining = value;

        loop {
            bytes.push((remaining & u64::from(PAYLOAD_MASK)) as u8);
            remaining >>= PAYLOAD_BITS;

            if remaining == 0 {
                break;
            }
        }

        Self::flush_stop_bit_encoded(&mut self.buffer, &mut bytes);
    }

    /// Encodes a signed integer using stop-bit encoding.
    ///
    /// The value is emitted in two's complement, seven bits per byte, most
    /// significant byte first. When bit 6 of the most significant payload byte
    /// does not already carry the sign, an extra carry byte (`0x00` for a
    /// positive value, `0x7F` for a negative one) is prepended — without it the
    /// decoder would read the value back with the opposite sign.
    ///
    /// The encoding is minimal and never exceeds [`MAX_INT_ENCODED_LEN`] bytes.
    ///
    /// # Arguments
    /// * `value` - The value to encode
    pub fn encode_int(&mut self, value: i64) {
        let negative = value < 0;
        let mut bytes = IntScratch::new();
        let mut remaining = value;

        loop {
            bytes.push((remaining & i64::from(PAYLOAD_MASK)) as u8);
            // Arithmetic shift: converges to 0 for a positive value and to -1
            // for a negative one.
            remaining >>= PAYLOAD_BITS;

            if (negative && remaining == -1) || (!negative && remaining == 0) {
                break;
            }
        }

        // The loop always pushes at least one byte, so `last` is always `Some`.
        let sign_conflicts = bytes
            .last()
            .is_some_and(|most_significant| (most_significant & SIGN_BIT != 0) != negative);

        if sign_conflicts {
            bytes.push(if negative { PAYLOAD_MASK } else { 0x00 });
        }

        Self::flush_stop_bit_encoded(&mut self.buffer, &mut bytes);
    }

    /// Encodes an ASCII string using stop-bit encoding.
    ///
    /// Follows the FAST 1.1 string encodings: the empty string is a lone stop
    /// byte (`0x80`) and the one-character NUL string is `0x00 0x80`. A longer
    /// string beginning with NUL has no legal representation — its encoding
    /// would be an over-long form the decoder must reject — so it is refused
    /// here rather than written to the wire.
    ///
    /// # Arguments
    /// * `value` - The string to encode
    ///
    /// # Errors
    /// Returns [`FastError::InvalidString`] if `value` contains a non-ASCII
    /// character, or if it begins with a NUL and is longer than one character.
    pub fn encode_ascii(&mut self, value: &str) -> Result<(), FastError> {
        if !value.is_ascii() {
            return Err(FastError::InvalidString);
        }

        let bytes = value.as_bytes();

        match bytes {
            [] => {
                self.buffer.push(STOP_BIT);
                return Ok(());
            }
            [0x00] => {
                self.buffer.extend_from_slice(&[0x00, STOP_BIT]);
                return Ok(());
            }
            [0x00, ..] => return Err(FastError::InvalidString),
            _ => {}
        }

        let Some((last, head)) = bytes.split_last() else {
            // Unreachable: the empty slice is handled above.
            return Err(FastError::InvalidString);
        };

        self.buffer.reserve(bytes.len());
        // Every byte is ASCII, so no payload bit is lost and no stop bit is set
        // by accident.
        self.buffer.extend_from_slice(head);
        self.buffer.push(last | STOP_BIT);

        Ok(())
    }

    /// Encodes a byte vector with a stop-bit encoded length prefix.
    ///
    /// # Arguments
    /// * `value` - The bytes to encode
    pub fn encode_bytes(&mut self, value: &[u8]) {
        self.encode_uint(value.len() as u64);
        self.buffer.extend_from_slice(value);
    }

    /// Encodes a `u128` using stop-bit encoding.
    ///
    /// Identical to [`FastEncoder::encode_uint`] but takes a `u128`, so it can
    /// emit the biased `2^64` a nullable unsigned uses to denote `u64::MAX`.
    /// `2^64` occupies ten payload bytes, within [`MAX_INT_ENCODED_LEN`].
    fn encode_uint_u128(&mut self, value: u128) {
        let mut bytes = IntScratch::new();
        let mut remaining = value;

        loop {
            bytes.push((remaining & u128::from(PAYLOAD_MASK)) as u8);
            remaining >>= PAYLOAD_BITS;

            if remaining == 0 {
                break;
            }
        }

        Self::flush_stop_bit_encoded(&mut self.buffer, &mut bytes);
    }

    /// Encodes a nullable unsigned integer.
    ///
    /// A nullable unsigned integer is encoded with a bias of one so that the
    /// single stop byte `0x80` is reserved for `None`. The full `0..=u64::MAX`
    /// domain is representable: `Some(u64::MAX)` biases to `2^64`, which does
    /// not fit `u64`, so the biased value is widened to `u128` and emitted in
    /// ten stop-bit bytes — the same frame
    /// [`FastDecoder::decode_nullable_uint`](crate::FastDecoder::decode_nullable_uint)
    /// reads back.
    ///
    /// # Arguments
    /// * `value` - The optional value to encode
    ///
    /// # Errors
    /// Never returns an error; the `Result` is kept for API stability and to
    /// match the fallible signed and byte-vector encoders.
    pub fn encode_nullable_uint(&mut self, value: Option<u64>) -> Result<(), FastError> {
        match value {
            Some(v) => {
                // The biased value is at most `2^64`, which fits `u128`, not `u64`.
                let biased = u128::from(v) + 1;
                self.encode_uint_u128(biased);
            }
            None => self.buffer.push(STOP_BIT),
        }

        Ok(())
    }

    /// Encodes a nullable signed integer.
    ///
    /// FAST biases only the non-negative half of the range: `None` is the
    /// single stop byte `0x80`, a non-negative value is encoded one higher than
    /// it is, and a negative value is encoded as itself. The representable
    /// domain is therefore `i64::MIN..=i64::MAX - 1`: `Some(i64::MAX)` has no
    /// encoding and is rejected rather than silently biased into the `None`
    /// representation.
    ///
    /// # Arguments
    /// * `value` - The optional value to encode
    ///
    /// # Errors
    /// Returns [`FastError::IntegerOverflow`] for `Some(i64::MAX)`.
    pub fn encode_nullable_int(&mut self, value: Option<i64>) -> Result<(), FastError> {
        match value {
            Some(v) if v < 0 => self.encode_int(v),
            Some(v) => {
                let biased = v.checked_add(1).ok_or(FastError::IntegerOverflow)?;
                self.encode_int(biased);
            }
            None => self.buffer.push(STOP_BIT),
        }

        Ok(())
    }

    /// Encodes a nullable ASCII string.
    ///
    /// The nullable string forms shift each of the FAST 1.1 special encodings
    /// by one leading `0x00`: `None` is a lone stop byte (`0x80`), the empty
    /// string is `0x00 0x80`, and the one-character NUL string is
    /// `0x00 0x00 0x80`. A longer string beginning with NUL has no legal
    /// representation and is refused rather than written to the wire in a form
    /// the decoder must reject.
    ///
    /// # Arguments
    /// * `value` - The optional string to encode
    ///
    /// # Errors
    /// Returns [`FastError::InvalidString`] if `value` contains a non-ASCII
    /// character, or if it begins with a NUL and is longer than one character.
    pub fn encode_nullable_ascii(&mut self, value: Option<&str>) -> Result<(), FastError> {
        let Some(value) = value else {
            self.buffer.push(STOP_BIT);
            return Ok(());
        };

        if !value.is_ascii() {
            return Err(FastError::InvalidString);
        }

        match value.as_bytes() {
            [] => {
                self.buffer.extend_from_slice(&[0x00, STOP_BIT]);
                Ok(())
            }
            [0x00] => {
                self.buffer.extend_from_slice(&[0x00, 0x00, STOP_BIT]);
                Ok(())
            }
            [0x00, ..] => Err(FastError::InvalidString),
            _ => self.encode_ascii(value),
        }
    }

    /// Encodes a nullable byte vector with a nullable length prefix.
    ///
    /// `None` is a lone stop byte; any other value carries a length prefix
    /// biased by one, matching
    /// [`FastDecoder::decode_nullable_bytes`](crate::FastDecoder::decode_nullable_bytes).
    ///
    /// # Arguments
    /// * `value` - The optional bytes to encode
    ///
    /// # Errors
    /// Returns [`FastError::IntegerOverflow`] if the length of `value` cannot
    /// be represented in the biased nullable domain.
    pub fn encode_nullable_bytes(&mut self, value: Option<&[u8]>) -> Result<(), FastError> {
        match value {
            Some(bytes) => {
                let length = u64::try_from(bytes.len()).map_err(|_| FastError::IntegerOverflow)?;
                self.encode_nullable_uint(Some(length))?;
                self.buffer.extend_from_slice(bytes);
            }
            None => self.buffer.push(STOP_BIT),
        }

        Ok(())
    }

    /// Returns the encoded bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buffer
    }

    /// Returns a reference to the current buffer.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Returns the current buffer length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns true if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Clears the buffer for reuse.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    /// Resets the encoder including dictionaries.
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.global_dict.clear();
        self.template_dicts.clear();
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

    /// Appends `bytes` — accumulated least significant byte first — to `out` in
    /// wire order with the stop bit set on the final byte.
    fn flush_stop_bit_encoded(out: &mut Vec<u8>, bytes: &mut IntScratch) {
        bytes.reverse();

        if let Some(last) = bytes.last_mut() {
            *last |= STOP_BIT;
        }

        out.extend_from_slice(bytes.as_slice());
    }
}

impl Default for FastEncoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_uint_zero() {
        let mut encoder = FastEncoder::new();
        encoder.encode_uint(0);
        assert_eq!(encoder.finish(), vec![0x80]);
    }

    #[test]
    fn test_encode_uint_one() {
        let mut encoder = FastEncoder::new();
        encoder.encode_uint(1);
        assert_eq!(encoder.finish(), vec![0x81]);
    }

    #[test]
    fn test_encode_uint_larger() {
        let mut encoder = FastEncoder::new();
        encoder.encode_uint(942);
        // 942 = 7 * 128 + 46, so first byte is 7, second is 46 | 0x80 = 0xAE
        assert_eq!(encoder.finish(), vec![0x07, 0xAE]);
    }

    #[test]
    fn test_encode_uint_boundaries_are_byte_exact() {
        let cases: [(u64, &[u8]); 6] = [
            (0, &[0x80]),
            (127, &[0xFF]),
            (128, &[0x01, 0x80]),
            (16383, &[0x7F, 0xFF]),
            (16384, &[0x01, 0x00, 0x80]),
            (
                u64::MAX,
                &[0x01, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0xFF],
            ),
        ];

        for (value, expected) in cases {
            let mut encoder = FastEncoder::new();
            encoder.encode_uint(value);
            assert_eq!(encoder.finish(), expected, "minimal encoding of {value}");
        }
    }

    #[test]
    fn test_encode_uint_never_exceeds_the_decoder_ceiling() {
        for shift in 0..64u32 {
            let Some(value) = 1u64.checked_shl(shift) else {
                continue;
            };
            let mut encoder = FastEncoder::new();
            encoder.encode_uint(value);
            assert!(encoder.len() <= MAX_INT_ENCODED_LEN, "value {value}");
        }
    }

    #[test]
    fn test_encode_int_emits_the_sign_carry_byte() {
        // 64 needs a leading 0x00: without it, bit 6 of the only payload byte
        // would make the decoder read -64.
        let mut encoder = FastEncoder::new();
        encoder.encode_int(64);
        assert_eq!(encoder.finish(), vec![0x00, 0xC0]);

        // -65 needs a leading 0x7F for the mirror-image reason.
        let mut encoder = FastEncoder::new();
        encoder.encode_int(-65);
        assert_eq!(encoder.finish(), vec![0x7F, 0xBF]);
    }

    #[test]
    fn test_encode_int_omits_the_carry_byte_when_the_sign_already_fits() {
        let mut encoder = FastEncoder::new();
        encoder.encode_int(63);
        assert_eq!(encoder.finish(), vec![0xBF]);

        let mut encoder = FastEncoder::new();
        encoder.encode_int(-64);
        assert_eq!(encoder.finish(), vec![0xC0]);
    }

    #[test]
    fn test_encode_int_extremes_use_ten_bytes() {
        let mut encoder = FastEncoder::new();
        encoder.encode_int(i64::MAX);
        assert_eq!(
            encoder.finish(),
            vec![0x00, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0xFF]
        );

        let mut encoder = FastEncoder::new();
        encoder.encode_int(i64::MIN);
        assert_eq!(
            encoder.finish(),
            vec![0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80]
        );
    }

    #[test]
    fn test_encode_int_never_exceeds_the_decoder_ceiling() {
        for shift in 0..63u32 {
            let Some(value) = 1i64.checked_shl(shift) else {
                continue;
            };
            for candidate in [Some(value), value.checked_neg(), value.checked_sub(1)] {
                let Some(value) = candidate else {
                    continue;
                };
                let mut encoder = FastEncoder::new();
                encoder.encode_int(value);
                assert!(encoder.len() <= MAX_INT_ENCODED_LEN, "value {value}");
            }
        }
    }

    #[test]
    fn test_encode_ascii() {
        let mut encoder = FastEncoder::new();
        assert_eq!(encoder.encode_ascii("Hi!"), Ok(()));
        assert_eq!(encoder.finish(), vec![b'H', b'i', b'!' | 0x80]);
    }

    #[test]
    fn test_encode_ascii_empty_is_a_lone_stop_byte() {
        let mut encoder = FastEncoder::new();
        assert_eq!(encoder.encode_ascii(""), Ok(()));
        assert_eq!(encoder.finish(), vec![0x80]);
    }

    #[test]
    fn test_encode_ascii_nul_is_zero_then_stop() {
        let mut encoder = FastEncoder::new();
        assert_eq!(encoder.encode_ascii("\0"), Ok(()));
        assert_eq!(encoder.finish(), vec![0x00, 0x80]);
    }

    #[test]
    fn test_encode_ascii_leading_nul_string_is_invalid_string() {
        let mut encoder = FastEncoder::new();
        assert_eq!(
            encoder.encode_ascii("\0a"),
            Err(FastError::InvalidString),
            "a leading NUL followed by more characters is an over-long form"
        );
        assert!(encoder.is_empty(), "nothing may reach the wire on error");
    }

    #[test]
    fn test_encode_ascii_non_ascii_is_invalid_string() {
        let mut encoder = FastEncoder::new();
        assert_eq!(encoder.encode_ascii("€"), Err(FastError::InvalidString));
        assert_eq!(encoder.encode_ascii("café"), Err(FastError::InvalidString));
        assert!(encoder.is_empty(), "nothing may reach the wire on error");
    }

    #[test]
    fn test_encode_bytes() {
        let mut encoder = FastEncoder::new();
        encoder.encode_bytes(&[1, 2, 3]);
        assert_eq!(encoder.finish(), vec![0x83, 1, 2, 3]);
    }

    #[test]
    fn test_encode_bytes_empty_is_a_zero_length_prefix() {
        let mut encoder = FastEncoder::new();
        encoder.encode_bytes(&[]);
        assert_eq!(encoder.finish(), vec![0x80]);
    }

    #[test]
    fn test_encode_nullable_uint_none_is_a_lone_stop_byte() {
        let mut encoder = FastEncoder::new();
        assert_eq!(encoder.encode_nullable_uint(None), Ok(()));
        assert_eq!(encoder.finish(), vec![0x80]);
    }

    #[test]
    fn test_encode_nullable_uint_some_is_biased_by_one() {
        let mut encoder = FastEncoder::new();
        assert_eq!(encoder.encode_nullable_uint(Some(0)), Ok(()));
        assert_eq!(encoder.finish(), vec![0x81]);

        let mut encoder = FastEncoder::new();
        assert_eq!(encoder.encode_nullable_uint(Some(126)), Ok(()));
        assert_eq!(encoder.finish(), vec![0xFF]);
    }

    #[test]
    fn test_encode_nullable_uint_max_is_representable() {
        // u64::MAX biases to 2^64, which does not fit u64; it now encodes
        // through u128 in ten stop-bit bytes instead of being rejected as
        // IntegerOverflow. The round-trip is pinned in the decoder tests.
        let mut encoder = FastEncoder::new();
        assert_eq!(encoder.encode_nullable_uint(Some(u64::MAX)), Ok(()));
        assert_eq!(encoder.len(), MAX_INT_ENCODED_LEN);
    }

    #[test]
    fn test_encode_nullable_uint_domain_upper_bound_is_representable() {
        let mut encoder = FastEncoder::new();
        assert_eq!(encoder.encode_nullable_uint(Some(u64::MAX - 1)), Ok(()));
        assert_eq!(encoder.len(), MAX_INT_ENCODED_LEN);
    }

    #[test]
    fn test_encoder_clear() {
        let mut encoder = FastEncoder::new();
        encoder.encode_uint(42);
        assert!(!encoder.is_empty());

        encoder.clear();
        assert!(encoder.is_empty());
    }

    #[test]
    fn test_encoder_reset_clears_buffer_and_dictionaries() {
        let mut encoder = FastEncoder::with_capacity(64);
        encoder.encode_uint(42);
        encoder.set_global("test", DictionaryValue::UInt(7));
        assert_eq!(
            encoder.get_global("test").and_then(DictionaryValue::as_u64),
            Some(7)
        );

        encoder.reset();
        assert!(encoder.is_empty());
        assert_eq!(encoder.as_bytes(), &[] as &[u8]);
        assert!(encoder.get_global("test").is_none());
    }
}
