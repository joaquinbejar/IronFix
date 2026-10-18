/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! The 6-byte Simple Open Framing Header.
//!
//! # Wire layout
//!
//! SOFH v1.0 (Draft Standard, December 2016), section *Simple Open Framing
//! Header Fields*:
//!
//! ```text
//! offset  0               4               6
//!         +---------------+-------+-----------------------------+
//!         | Message_Length| Enc.  | message (1..n bytes)        |
//!         | u32           | u16   |                             |
//!         +---------------+-------+-----------------------------+
//!         |<------------------ Message_Length ----------------->|
//! ```
//!
//! - `Message_Length` is four octets and is "the length in octets (i.e.
//!   bytes) of a message inclusive of the length of the Simple Open Framing
//!   Header" (subsection *Message_Length field*);
//! - `Encoding_Type` is two octets (subsection *Encoding_Type field*), see
//!   [`EncodingType`];
//! - both are "unsigned binary integer values in Network Byte Order" (section
//!   *Encoding of the Simple Open Framing Header*), that is big-endian,
//!   whatever the byte order of the payload.
//!   [`EncodingType::SbeV1LittleEndian`] describes the payload only.
//!
//! The section *Definitions* defines a message as "a stream of 1..n bytes",
//! so the smallest legal `Message_Length` is 7: the header plus one byte.
//! [`SofhHeader`] cannot hold a smaller one.

use crate::encoding::EncodingType;
use crate::error::SofhError;

/// Length of the header in bytes, as a `u32` for `Message_Length` arithmetic.
const HEADER_LEN_U32: u32 = 6;

// The two spellings of the header length must agree.
const _: () = assert!(SofhHeader::LEN == HEADER_LEN_U32 as usize);

/// A decoded or to-be-encoded Simple Open Framing Header.
///
/// Its fields are private so that its invariant holds for every value:
/// `message_length` is at least [`SofhHeader::MIN_MESSAGE_LENGTH`]. It does
/// not know the codec's size ceiling; [`crate::SofhCodec`] applies that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SofhHeader {
    /// Frame length in bytes, header included. Never below
    /// [`SofhHeader::MIN_MESSAGE_LENGTH`].
    message_length: u32,
    /// The encoding of the payload.
    encoding_type: EncodingType,
}

impl SofhHeader {
    /// Length of the header on the wire, in bytes.
    pub const LEN: usize = 6;

    /// Smallest legal `Message_Length`, in bytes: the 6-byte header plus a
    /// message of at least one byte.
    pub const MIN_MESSAGE_LENGTH: u32 = 7;

    /// Builds a header from an encoding type and a `Message_Length` (in
    /// bytes, header included).
    ///
    /// Every constructor in this crate takes the encoding type first.
    ///
    /// # Errors
    /// [`SofhError::MessageLengthTooSmall`] if `message_length` is below
    /// [`SofhHeader::MIN_MESSAGE_LENGTH`].
    #[inline]
    pub const fn new(encoding_type: EncodingType, message_length: u32) -> Result<Self, SofhError> {
        if message_length < Self::MIN_MESSAGE_LENGTH {
            return Err(SofhError::MessageLengthTooSmall {
                length: message_length,
                min_length: Self::MIN_MESSAGE_LENGTH,
            });
        }
        Ok(Self {
            message_length,
            encoding_type,
        })
    }

    /// Builds the header that frames a payload of `payload_len` bytes with
    /// the given encoding type.
    ///
    /// # Errors
    /// - [`SofhError::MessageLengthTooSmall`] for an empty payload;
    /// - [`SofhError::PayloadTooLong`] when `payload_len` plus the header does
    ///   not fit the 4-octet `Message_Length` field.
    #[inline]
    pub fn for_payload(encoding_type: EncodingType, payload_len: usize) -> Result<Self, SofhError> {
        let message_length = u32::try_from(payload_len)
            .ok()
            .and_then(|len| len.checked_add(HEADER_LEN_U32))
            .ok_or(SofhError::PayloadTooLong { payload_len })?;
        Self::new(encoding_type, message_length)
    }

    /// Returns the `Message_Length`: the frame length in bytes, header
    /// included.
    #[must_use]
    #[inline]
    pub const fn message_length(self) -> u32 {
        self.message_length
    }

    /// Returns the encoding type of the payload.
    #[must_use]
    #[inline]
    pub const fn encoding_type(self) -> EncodingType {
        self.encoding_type
    }

    /// Returns the payload length in bytes: `Message_Length` minus the
    /// 6-byte header. Always at least 1.
    #[must_use]
    #[inline]
    pub const fn payload_len(self) -> u32 {
        // Every constructor enforces message_length >= MIN_MESSAGE_LENGTH, so
        // the subtraction cannot fail; the None arm only keeps the arithmetic
        // checked, and 0 is the one answer that can never over-read.
        match self.message_length.checked_sub(HEADER_LEN_U32) {
            Some(len) => len,
            None => 0,
        }
    }

    /// Encodes the header: `Message_Length` then `Encoding_Type`, both
    /// big-endian.
    #[must_use]
    #[inline]
    pub const fn to_bytes(self) -> [u8; Self::LEN] {
        let [l0, l1, l2, l3] = self.message_length.to_be_bytes();
        let [e0, e1] = self.encoding_type.to_u16().to_be_bytes();
        [l0, l1, l2, l3, e0, e1]
    }

    /// Decodes a header from exactly six bytes.
    ///
    /// Any `Encoding_Type` is accepted and preserved (see [`EncodingType`]).
    ///
    /// # Errors
    /// [`SofhError::MessageLengthTooSmall`] if the declared `Message_Length`
    /// is below [`SofhHeader::MIN_MESSAGE_LENGTH`].
    #[inline]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Result<Self, SofhError> {
        let [l0, l1, l2, l3, e0, e1] = bytes;
        Self::new(
            EncodingType::from_u16(u16::from_be_bytes([e0, e1])),
            u32::from_be_bytes([l0, l1, l2, l3]),
        )
    }

    /// Decodes the header at the start of `src`, which may hold more bytes
    /// (the payload, further frames) or fewer.
    ///
    /// Returns `Ok(None)` while fewer than six bytes are available. Nothing is
    /// read past the sixth byte.
    ///
    /// # Errors
    /// [`SofhError::MessageLengthTooSmall`] if the declared `Message_Length`
    /// is below [`SofhHeader::MIN_MESSAGE_LENGTH`].
    #[inline]
    pub fn decode(src: &[u8]) -> Result<Option<Self>, SofhError> {
        // Not a `const fn`: const evaluation cannot yet prove that matching
        // on the `Result` of `from_bytes` moves it out without a drop.
        match src.first_chunk::<{ Self::LEN }>() {
            Some(bytes) => Self::from_bytes(*bytes).map(Some),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a header expected to be valid.
    fn header(encoding_type: EncodingType, message_length: u32) -> SofhHeader {
        match SofhHeader::new(encoding_type, message_length) {
            Ok(header) => header,
            Err(error) => panic!("fixture header is valid: {error}"),
        }
    }

    #[test]
    fn test_sofh_header_to_bytes_is_big_endian_length_then_encoding() {
        let bytes = header(EncodingType::SbeV1LittleEndian, 0x0102_0304).to_bytes();
        assert_eq!(bytes, [0x01, 0x02, 0x03, 0x04, 0xEB, 0x50]);

        let bytes = header(EncodingType::TagValue, 7).to_bytes();
        assert_eq!(bytes, [0x00, 0x00, 0x00, 0x07, 0xF0, 0x00]);
    }

    #[test]
    fn test_sofh_header_from_bytes_round_trips() {
        for (length, encoding) in [
            (7, EncodingType::SbeV1BigEndian),
            (8, EncodingType::from_u16(0x0000)),
            (1_048_576, EncodingType::from_u16(0xFA7F)),
            (u32::MAX, EncodingType::from_u16(0xFFFF)),
        ] {
            let original = header(encoding, length);
            assert_eq!(SofhHeader::from_bytes(original.to_bytes()), Ok(original));
        }
    }

    #[test]
    fn test_sofh_header_new_rejects_every_length_below_seven() {
        for length in 0..SofhHeader::MIN_MESSAGE_LENGTH {
            assert_eq!(
                SofhHeader::new(EncodingType::TagValue, length),
                Err(SofhError::MessageLengthTooSmall {
                    length,
                    min_length: 7,
                })
            );
        }
    }

    #[test]
    fn test_sofh_header_new_accepts_the_minimum_and_the_maximum() {
        assert_eq!(header(EncodingType::Json, 7).payload_len(), 1);
        assert_eq!(
            header(EncodingType::Json, u32::MAX).payload_len(),
            u32::MAX - 6
        );
    }

    #[test]
    fn test_sofh_header_from_bytes_rejects_a_length_inside_the_header() {
        assert_eq!(
            SofhHeader::from_bytes([0, 0, 0, 5, 0x5B, 0xE0]),
            Err(SofhError::MessageLengthTooSmall {
                length: 5,
                min_length: 7,
            })
        );
    }

    #[test]
    fn test_sofh_header_decode_waits_for_six_bytes() {
        let bytes = header(EncodingType::GpbV1, 42).to_bytes();
        for available in 0..SofhHeader::LEN {
            let Some(prefix) = bytes.get(..available) else {
                panic!("prefix is inside the header");
            };
            assert_eq!(SofhHeader::decode(prefix), Ok(None), "{available} bytes");
        }
        assert_eq!(
            SofhHeader::decode(&bytes),
            Ok(Some(header(EncodingType::GpbV1, 42)))
        );
    }

    #[test]
    fn test_sofh_header_decode_reads_only_the_first_six_bytes() {
        let mut bytes = header(EncodingType::Asn1BerV1, 9).to_bytes().to_vec();
        bytes.extend_from_slice(&[0xFF, 0x00, 0x00]);
        assert_eq!(
            SofhHeader::decode(&bytes),
            Ok(Some(header(EncodingType::Asn1BerV1, 9)))
        );
    }

    #[test]
    fn test_sofh_header_decode_rejects_a_zero_length() {
        assert_eq!(
            SofhHeader::decode(&[0, 0, 0, 0, 0xEB, 0x50, 0xAA]),
            Err(SofhError::MessageLengthTooSmall {
                length: 0,
                min_length: 7,
            })
        );
    }

    #[test]
    fn test_sofh_header_for_payload_adds_the_header_length() {
        assert_eq!(
            SofhHeader::for_payload(EncodingType::Bson, 1),
            Ok(header(EncodingType::Bson, 7))
        );
        assert_eq!(
            SofhHeader::for_payload(EncodingType::FixmlSchemaV1, 100),
            Ok(header(EncodingType::FixmlSchemaV1, 106))
        );
    }

    #[test]
    fn test_sofh_header_for_payload_rejects_an_empty_payload() {
        assert_eq!(
            SofhHeader::for_payload(EncodingType::TagValue, 0),
            Err(SofhError::MessageLengthTooSmall {
                length: 6,
                min_length: 7,
            })
        );
    }

    #[test]
    fn test_sofh_header_for_payload_largest_framable_payload() {
        let Ok(largest) = usize::try_from(u32::MAX - 6) else {
            // A target whose usize is narrower than 32 bits cannot hold the
            // payload in the first place.
            return;
        };
        assert_eq!(
            SofhHeader::for_payload(EncodingType::SbeV1BigEndian, largest),
            Ok(header(EncodingType::SbeV1BigEndian, u32::MAX))
        );
    }

    #[test]
    fn test_sofh_header_for_payload_rejects_a_payload_past_the_length_field() {
        let mut too_long = vec![usize::MAX];
        if let Ok(just_past) = usize::try_from(u32::MAX - 5) {
            too_long.push(just_past);
        }
        if let Ok(whole_field) = usize::try_from(u32::MAX) {
            too_long.push(whole_field);
        }
        for payload_len in too_long {
            assert_eq!(
                SofhHeader::for_payload(EncodingType::TagValue, payload_len),
                Err(SofhError::PayloadTooLong { payload_len })
            );
        }
    }
}
