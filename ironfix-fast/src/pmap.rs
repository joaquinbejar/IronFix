/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! FAST presence map handling.
//!
//! The presence map (PMAP) is a bitmap that indicates which optional fields
//! are present in a FAST message. It uses stop-bit encoding where the high
//! bit of each byte indicates whether more bytes follow.
//!
//! Two hardening rules apply, because a presence map is attacker-controlled
//! input: its encoded size is capped by [`MAX_PMAP_BYTES`], and running off
//! the end of the map is an explicit [`FastError::PresenceMapExhausted`]
//! rather than a fabricated "field absent" answer.
//!
//! On the way out, [`PresenceMap::encode`] emits the minimal form — no
//! trailing all-absent bytes — because that is what a conformant FAST receiver
//! expects and what a strict one insists on.

use crate::decoder::{PAYLOAD_BITS, STOP_BIT, read_byte};
use crate::error::FastError;
use smallvec::SmallVec;

/// Maximum number of encoded bytes a presence map may occupy.
///
/// Each byte carries seven field bits, so this ceiling admits
/// presence maps of up to 448 fields — far beyond any practical FAST template
/// — while bounding the work and the memory a single hostile map can cost.
///
/// The ceiling applies to [`PresenceMap::decode`], the only path fed by the
/// wire. [`PresenceMap::from_bits`] and [`PresenceMapBuilder`] take bits the
/// caller already holds and are not bounded by it; an oversized map built that
/// way is refused by [`PresenceMap::encode`] before it can reach a socket.
pub const MAX_PMAP_BYTES: usize = 64;

/// Number of presence bits held inline before spilling to the heap.
///
/// Eight encoded bytes, which covers every realistic template.
const INLINE_PMAP_BITS: usize = 56;

/// Storage for the decoded presence bits.
type PmapBits = SmallVec<[bool; INLINE_PMAP_BITS]>;

/// FAST presence map.
///
/// The presence map tracks which optional fields are present in a message.
/// Bits are consumed in order as fields are decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceMap {
    /// The raw bits of the presence map.
    bits: PmapBits,
    /// Current bit position.
    position: usize,
}

impl PresenceMap {
    /// Creates an empty presence map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bits: PmapBits::new(),
            position: 0,
        }
    }

    /// Creates a presence map from raw bits.
    #[must_use]
    pub fn from_bits(bits: Vec<bool>) -> Self {
        Self {
            bits: PmapBits::from_vec(bits),
            position: 0,
        }
    }

    /// Decodes a presence map from a byte slice.
    ///
    /// # Arguments
    /// * `data` - The input bytes
    /// * `offset` - Current position in the data (will be updated)
    ///
    /// # Returns
    /// The decoded presence map.
    ///
    /// # Errors
    /// Returns [`FastError::UnexpectedEof`] if the stop bit is never reached
    /// before the end of `data`, or [`FastError::PresenceMapTooLarge`] if the
    /// map would exceed [`MAX_PMAP_BYTES`] encoded bytes.
    pub fn decode(data: &[u8], offset: &mut usize) -> Result<Self, FastError> {
        let mut bits = PmapBits::new();
        let mut consumed: usize = 0;

        loop {
            if consumed == MAX_PMAP_BYTES {
                return Err(FastError::PresenceMapTooLarge {
                    max_bytes: MAX_PMAP_BYTES,
                });
            }

            let byte = read_byte(data, offset)?;
            consumed += 1;

            // Extract the seven payload bits, most significant first.
            for shift in (0..PAYLOAD_BITS).rev() {
                bits.push((byte >> shift) & 1 == 1);
            }

            if byte & STOP_BIT != 0 {
                break;
            }
        }

        Ok(Self { bits, position: 0 })
    }

    /// Consumes and returns the next bit from the presence map.
    ///
    /// # Returns
    /// `true` if the corresponding field is present, `false` otherwise.
    ///
    /// # Errors
    /// Returns [`FastError::PresenceMapExhausted`] once every decoded bit has
    /// been consumed, rather than answering "absent" forever.
    ///
    /// # Granularity
    ///
    /// A decoded map always holds a multiple of seven bits, because that is
    /// what the wire encoding carries: a sender meaning one present bit emits
    /// a single byte, and this map then offers seven. Those six padding bits
    /// read as "absent" and are indistinguishable here from real absent
    /// fields — the primitive layer never sees the template, so it cannot know
    /// how many bits were meant. Exhaustion therefore only fires at a
    /// seven-bit boundary.
    ///
    /// The mirror of that is over-rejection: a sender that omits trailing
    /// all-absent bytes — which is the minimal form, and what
    /// [`PresenceMap::encode`] itself emits — produces a map shorter than the
    /// template's field count, and reads past its end error here rather than
    /// yielding "absent". A caller that knows how many fields to expect, and
    /// therefore knows a short map is legal rather than truncated, reads with
    /// [`PresenceMap::bit`] and treats `None` as absent. Resolving it inside
    /// `next_bit` would need that field count, which belongs to the template
    /// layer this crate does not yet implement — see the crate-level docs.
    #[inline]
    pub fn next_bit(&mut self) -> Result<bool, FastError> {
        let bit = *self
            .bits
            .get(self.position)
            .ok_or(FastError::PresenceMapExhausted)?;

        // `get` succeeded, so `position < bits.len()`; the increment cannot
        // overflow and keeps the `position <= bits.len()` invariant.
        self.position += 1;

        Ok(bit)
    }

    /// Returns the bit at the specified position without consuming it.
    ///
    /// # Arguments
    /// * `index` - The bit position (0-indexed)
    ///
    /// # Returns
    /// `None` if `index` is past the end of the map.
    pub fn bit(&self, index: usize) -> Option<bool> {
        self.bits.get(index).copied()
    }

    /// Returns the number of bits in the presence map.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    /// Returns true if the presence map is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }

    /// Returns true if every bit has been consumed.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.position >= self.bits.len()
    }

    /// Returns the current position in the presence map.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.position
    }

    /// Resets the position to the beginning.
    pub fn reset(&mut self) {
        self.position = 0;
    }

    /// Encodes the presence map to bytes.
    ///
    /// The encoding is **minimal**: trailing bytes in which every bit is clear
    /// are dropped, so a map of fourteen absent fields is the single byte
    /// `0x80` rather than `0x00 0x80`. FAST allows a receiver to treat bits
    /// past the end of the map as clear, and strict counterparties reject the
    /// over-long form.
    ///
    /// The consequence is that `encode` followed by
    /// [`PresenceMap::decode`] does not round-trip bit count: the decoded map
    /// is as short as the last set bit allows, and every bit past its end is
    /// absent. A reader that knows how many fields to expect uses
    /// [`PresenceMap::bit`], which answers `None` past the end, rather than
    /// [`PresenceMap::next_bit`], which treats running off the end as the
    /// protocol error it is for a reader that does not.
    ///
    /// # Returns
    /// The encoded bytes with stop-bit encoding.
    ///
    /// # Errors
    /// Returns [`FastError::PresenceMapTooLarge`] if the map holds more bits
    /// than [`MAX_PMAP_BYTES`] can carry — the encoder must never emit a map
    /// its own decoder would reject.
    pub fn encode(&self) -> Result<Vec<u8>, FastError> {
        let byte_len = self.bits.len().div_ceil(PAYLOAD_BITS);
        if byte_len > MAX_PMAP_BYTES {
            return Err(FastError::PresenceMapTooLarge {
                max_bytes: MAX_PMAP_BYTES,
            });
        }

        let mut result = Vec::with_capacity(byte_len);

        for chunk in self.bits.chunks(PAYLOAD_BITS) {
            let mut byte: u8 = 0;

            for (index, &present) in chunk.iter().enumerate() {
                if present {
                    // `index < PAYLOAD_BITS`, so the shift stays in range.
                    byte |= 1 << (PAYLOAD_BITS - 1 - index);
                }
            }

            result.push(byte);
        }

        // Drop trailing all-absent bytes: they carry no information and the
        // over-long form is not minimal. At least one byte must survive, since
        // a presence map is never zero bytes on the wire.
        while result.len() > 1 && result.last() == Some(&0) {
            result.pop();
        }

        // An empty map still needs its lone stop byte.
        if result.is_empty() {
            result.push(0);
        }

        // Set the stop bit on the last byte.
        if let Some(last) = result.last_mut() {
            *last |= STOP_BIT;
        }

        Ok(result)
    }
}

impl Default for PresenceMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for constructing presence maps.
///
/// Bits accumulate inline, so a map covering every realistic template is built
/// without touching the heap.
#[derive(Debug, Default)]
pub struct PresenceMapBuilder {
    bits: PmapBits,
}

impl PresenceMapBuilder {
    /// Creates a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a bit to the presence map.
    #[must_use]
    pub fn bit(mut self, present: bool) -> Self {
        self.bits.push(present);
        self
    }

    /// Builds the presence map.
    #[must_use]
    pub fn build(self) -> PresenceMap {
        PresenceMap {
            bits: self.bits,
            position: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_presence_map_decode_single_byte() {
        // 0b1100_0000: stop bit (bit 7) = 1, bits 6-0 = 100_0000
        // Extracted bits (from bit 6 to bit 0): 1, 0, 0, 0, 0, 0, 0
        let data = [0b1100_0000];
        let mut offset = 0;
        let decoded = PresenceMap::decode(&data, &mut offset);
        assert!(decoded.is_ok());

        if let Ok(pmap) = decoded {
            assert_eq!(offset, 1);
            assert_eq!(pmap.len(), 7);
            assert_eq!(pmap.bit(0), Some(true)); // bit 6 of byte = 1
            assert_eq!(pmap.bit(1), Some(false)); // bit 5 of byte = 0
            assert_eq!(pmap.bit(2), Some(false)); // bit 4 of byte = 0
            assert_eq!(pmap.bit(7), None); // past the end
        }
    }

    #[test]
    fn test_presence_map_decode_multi_byte() {
        let data = [0b0100_0000, 0b1000_0000]; // Two bytes
        let mut offset = 0;
        let decoded = PresenceMap::decode(&data, &mut offset);
        assert!(decoded.is_ok());

        if let Ok(pmap) = decoded {
            assert_eq!(offset, 2);
            assert_eq!(pmap.len(), 14);
        }
    }

    #[test]
    fn test_presence_map_decode_without_stop_bit_is_unexpected_eof() {
        let data = [0b0100_0000, 0b0000_0001];
        let mut offset = 0;
        assert_eq!(
            PresenceMap::decode(&data, &mut offset),
            Err(FastError::UnexpectedEof)
        );
    }

    #[test]
    fn test_presence_map_decode_empty_input_is_unexpected_eof() {
        let data: [u8; 0] = [];
        let mut offset = 0;
        assert_eq!(
            PresenceMap::decode(&data, &mut offset),
            Err(FastError::UnexpectedEof)
        );
    }

    #[test]
    fn test_presence_map_decode_at_the_ceiling_is_accepted() {
        let mut data = vec![0x00; MAX_PMAP_BYTES - 1];
        data.push(STOP_BIT);

        let mut offset = 0;
        let decoded = PresenceMap::decode(&data, &mut offset);
        assert!(decoded.is_ok());

        if let Ok(pmap) = decoded {
            assert_eq!(pmap.len(), MAX_PMAP_BYTES * PAYLOAD_BITS);
            assert_eq!(offset, MAX_PMAP_BYTES);
        }
    }

    #[test]
    fn test_presence_map_decode_over_the_ceiling_is_too_large() {
        // A stop bit that never arrives, with more than enough input to run
        // past the ceiling.
        let data = vec![0x00; MAX_PMAP_BYTES * 4];
        let mut offset = 0;
        assert_eq!(
            PresenceMap::decode(&data, &mut offset),
            Err(FastError::PresenceMapTooLarge {
                max_bytes: MAX_PMAP_BYTES
            })
        );
    }

    #[test]
    fn test_presence_map_next_bit() {
        let mut pmap = PresenceMap::from_bits(vec![true, false, true]);

        assert_eq!(pmap.next_bit(), Ok(true));
        assert_eq!(pmap.next_bit(), Ok(false));
        assert_eq!(pmap.next_bit(), Ok(true));
    }

    #[test]
    fn test_presence_map_next_bit_past_the_end_is_exhausted() {
        let mut pmap = PresenceMap::from_bits(vec![true]);

        assert!(!pmap.is_exhausted());
        assert_eq!(pmap.next_bit(), Ok(true));
        assert!(pmap.is_exhausted());
        assert_eq!(pmap.next_bit(), Err(FastError::PresenceMapExhausted));
        assert_eq!(pmap.position(), 1, "a failed read must not advance");
    }

    #[test]
    fn test_presence_map_empty_map_is_exhausted_immediately() {
        let mut pmap = PresenceMap::new();

        assert!(pmap.is_empty());
        assert!(pmap.is_exhausted());
        assert_eq!(pmap.next_bit(), Err(FastError::PresenceMapExhausted));
    }

    #[test]
    fn test_presence_map_reset_rewinds_the_position() {
        let mut pmap = PresenceMap::from_bits(vec![true, false]);

        assert_eq!(pmap.next_bit(), Ok(true));
        assert_eq!(pmap.next_bit(), Ok(false));
        assert!(pmap.is_exhausted());

        pmap.reset();
        assert_eq!(pmap.position(), 0);
        assert_eq!(pmap.next_bit(), Ok(true));
    }

    #[test]
    fn test_presence_map_encode() {
        let pmap = PresenceMap::from_bits(vec![true, true, false, false, false, false, false]);
        assert_eq!(pmap.encode(), Ok(vec![0b1110_0000]));
    }

    #[test]
    fn test_presence_map_encode_empty_is_a_lone_stop_byte() {
        let pmap = PresenceMap::new();
        assert_eq!(pmap.encode(), Ok(vec![STOP_BIT]));
    }

    #[test]
    fn test_presence_map_encode_decode_round_trip() {
        let bits = vec![
            true, false, true, true, false, false, true, false, true, false,
        ];
        let pmap = PresenceMap::from_bits(bits.clone());

        let encoded = pmap.encode();
        assert!(encoded.is_ok());

        if let Ok(encoded) = encoded {
            let mut offset = 0;
            let decoded = PresenceMap::decode(&encoded, &mut offset);
            assert!(decoded.is_ok());

            if let Ok(decoded) = decoded {
                assert_eq!(offset, encoded.len());
                // Every bit survives, either explicitly or as a bit past the
                // end of the minimal map, which reads as absent.
                for (index, &expected) in bits.iter().enumerate() {
                    assert_eq!(decoded.bit(index).unwrap_or(false), expected, "bit {index}");
                }
            }
        }
    }

    #[test]
    fn test_presence_map_encode_drops_trailing_absent_bytes() {
        // Fourteen absent fields fit in one byte, not two: the second byte
        // would carry no information and is not the minimal form.
        let pmap = PresenceMap::from_bits(vec![false; 14]);
        assert_eq!(pmap.encode(), Ok(vec![STOP_BIT]));
    }

    #[test]
    fn test_presence_map_encode_keeps_bytes_up_to_the_last_present_field() {
        // One present field followed by thirteen absent ones: the first byte
        // carries the set bit and the second is dropped.
        let mut bits = vec![false; 14];
        if let Some(first) = bits.first_mut() {
            *first = true;
        }
        let pmap = PresenceMap::from_bits(bits);
        assert_eq!(pmap.encode(), Ok(vec![0b1100_0000]));

        // A set bit in the second byte keeps that byte alive.
        let mut bits = vec![false; 14];
        if let Some(last) = bits.last_mut() {
            *last = true;
        }
        let pmap = PresenceMap::from_bits(bits);
        assert_eq!(pmap.encode(), Ok(vec![0x00, 0b1000_0001]));
    }

    #[test]
    fn test_presence_map_encode_all_absent_is_a_lone_stop_byte() {
        // However many absent fields the template has, the minimal map is one
        // byte -- and it must still decode as a presence map.
        for count in [1_usize, 7, 8, 63, 64] {
            let pmap = PresenceMap::from_bits(vec![false; count]);
            assert_eq!(pmap.encode(), Ok(vec![STOP_BIT]), "{count} absent fields");
        }
    }

    #[test]
    fn test_presence_map_encode_over_the_ceiling_is_too_large() {
        let bits = vec![true; MAX_PMAP_BYTES * PAYLOAD_BITS + 1];
        let pmap = PresenceMap::from_bits(bits);

        assert_eq!(
            pmap.encode(),
            Err(FastError::PresenceMapTooLarge {
                max_bytes: MAX_PMAP_BYTES
            })
        );
    }

    #[test]
    fn test_presence_map_builder() {
        let pmap = PresenceMapBuilder::new()
            .bit(true)
            .bit(false)
            .bit(true)
            .build();

        assert_eq!(pmap.len(), 3);
        assert_eq!(pmap.bit(0), Some(true));
        assert_eq!(pmap.bit(1), Some(false));
        assert_eq!(pmap.bit(2), Some(true));
    }
}
