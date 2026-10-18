/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! CRC-32 (IEEE 802.3) for the [`FileStore`](super::FileStore) journal.
//!
//! Every journal record carries the CRC-32 of its body, so a record that was
//! torn by a crash or damaged on disk is detected rather than returned. This is
//! the common reflected CRC-32 (polynomial `0x04C11DB7`, reflected form
//! `0xEDB88320`, initial value and final XOR `0xFFFF_FFFF`), the one used by
//! zlib, gzip and PNG, so a journal can be checked with standard tools.
//!
//! It is written here rather than taken from a crate because `ironfix-store`
//! adds no dependency for it (ADR-0006). The lookup table is computed at
//! compile time.

/// The reflected CRC-32 polynomial.
const POLYNOMIAL: u32 = 0xEDB8_8320;

/// One table entry per byte value, computed at compile time.
const TABLE: [u32; 256] = build_table();

/// Builds the byte-at-a-time lookup table.
const fn build_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut byte = 0usize;
    while byte < 256 {
        // `byte` is below 256, so the conversion is exact.
        let mut crc = byte as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ POLYNOMIAL
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[byte] = crc;
        byte += 1;
    }
    table
}

/// Returns the CRC-32 (IEEE 802.3) of `bytes`.
#[must_use]
pub(crate) fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in bytes {
        // The index is a `u8`, so it is always inside the 256-entry table.
        let index = usize::from((crc as u8) ^ byte);
        crc = (crc >> 8) ^ TABLE[index];
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_empty_input_is_zero() {
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn test_crc32_matches_the_standard_check_value() {
        // The catalogue check value for CRC-32/ISO-HDLC.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn test_crc32_matches_a_known_sentence() {
        assert_eq!(
            crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }

    #[test]
    fn test_crc32_detects_a_single_flipped_bit() {
        let original = b"8=FIX.4.4\x019=5\x0135=0\x0110=000\x01";
        let mut flipped = *original;
        if let Some(byte) = flipped.get_mut(12) {
            *byte ^= 0x01;
        }
        assert_ne!(crc32(original), crc32(&flipped));
    }
}
