/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! The SOFH `Encoding_Type` field: which encoding the framed message uses.
//!
//! # Source
//!
//! Every value here comes from the FIX Simple Open Framing Header Technical
//! Specification **v1.0**, the Draft Standard approved by the FIX Global
//! Technical Committee in December 2016, section *Simple Open Framing Header
//! Fields*, subsection *Encoding_Type field*, table *Simple Open Framing
//! Header – Encoding_Types*. That table, row by row:
//!
//! | Row in the table | Value | Variant |
//! |---|---|---|
//! | Private User Defined | `0x0001` through `0x00FF` | [`EncodingType::Private`] |
//! | FIX SBE Version 1.0 Big Endian | `0x5BE0` | [`EncodingType::SbeV1BigEndian`] |
//! | FIX SBE Version 1.0 Little Endian | `0xEB50` | [`EncodingType::SbeV1LittleEndian`] |
//! | FIX GPB Version 1.0 | `0x4700` | [`EncodingType::GpbV1`] |
//! | FIX ASN.1 PER Version 1.0 | `0xA500` | [`EncodingType::Asn1PerV1`] |
//! | FIX ASN.1 BER Version 1.0 | `0xA501` | [`EncodingType::Asn1BerV1`] |
//! | FIX ASN.1 OER Version 1.0 | `0xA502` | [`EncodingType::Asn1OerV1`] |
//! | FIXTV | `0xF000` | [`EncodingType::TagValue`] |
//! | FIXML SCHEMA Version 1.0 | `0xF100` | [`EncodingType::FixmlSchemaV1`] |
//! | FIX FAST | `0xFA01` through `0xFAFF` | [`EncodingType::Fast`] |
//! | FIX JSON | `0xF500` | [`EncodingType::Json`] |
//! | FIX BSON | `0xFB00` | [`EncodingType::Bson`] |
//!
//! Every other value is [`EncodingType::Unregistered`], `0x0000` included (the
//! private range starts at `0x0001`).
//!
//! # Unknown values are preserved, not rejected
//!
//! An encoding type outside the table is not a framing error. The decoder
//! returns the frame with the raw value kept in [`EncodingType::Unregistered`],
//! and encoding it back writes the same two bytes. Three reasons:
//!
//! - the frame boundary depends on `Message_Length` alone, so an unknown
//!   encoding type leaves the stream perfectly aligned;
//! - SOFH v1.0 says the header exists so that "message processors are then
//!   able to skip over (ignore) any messages for which a CODEC is
//!   unavailable" (section *Simple Open Framing Header*). Skipping is the
//!   receiver's decision, and it needs the frame to make it;
//! - the table is open: "Future encoding types will be defined as part of the
//!   standards process". SOFH v1.1 Release Candidate 1 (September 2019)
//!   already registers SBE 2.0 as `0x5BE1` (big-endian) and `0xEB51`
//!   (little-endian) and no longer lists BSON. Rejecting what v1.0 does not
//!   name would break on a peer that follows v1.1 RC1.
//!
//! [`EncodingType::from_u16`] and [`EncodingType::to_u16`] are therefore a
//! bijection over all 65,536 values, which the tests check exhaustively.
//!
//! The v1.1 RC1 values are not variants yet because v1.1 is a release
//! candidate, not the standard. Adding them later is additive for the type
//! (it is `#[non_exhaustive]`) but changes how `0x5BE1` and `0xEB51` classify,
//! from [`EncodingType::Unregistered`] to the new variants.

use std::num::NonZeroU8;

/// The `Encoding_Type` of a framed message, as registered by SOFH v1.0.
///
/// See the [module documentation](self) for the source table and for why an
/// unregistered value is preserved rather than rejected.
///
/// Every value of this type corresponds to exactly one wire value and back:
/// the payload of [`Self::Private`] and [`Self::Fast`] is a non-zero low byte,
/// so it cannot name a value outside its range, and [`Self::Unregistered`] can
/// only be built by [`Self::from_u16`] from a value no other variant names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EncodingType {
    /// Private user defined encoding, `0x0001` through `0x00FF`; carries the
    /// low byte.
    ///
    /// Row "Private User Defined" of the v1.0 table. The specification adds
    /// that these values "shall not be considered to be unique and are to be
    /// implemented by counterparty agreement" (section *Use of Private User
    /// Defined Encoding_Types*).
    Private(NonZeroU8),
    /// Simple Binary Encoding 1.0, big-endian: `0x5BE0`.
    ///
    /// Row "FIX SBE Version 1.0 Big Endian" of the v1.0 table.
    SbeV1BigEndian,
    /// Simple Binary Encoding 1.0, little-endian: `0xEB50`.
    ///
    /// Row "FIX SBE Version 1.0 Little Endian" of the v1.0 table.
    SbeV1LittleEndian,
    /// FIX over Google Protocol Buffers 1.0: `0x4700`.
    ///
    /// Row "FIX GPB Version 1.0" of the v1.0 table.
    GpbV1,
    /// FIX over ASN.1 Packed Encoding Rules 1.0: `0xA500`.
    ///
    /// Row "FIX ASN.1 PER Version 1.0" of the v1.0 table.
    Asn1PerV1,
    /// FIX over ASN.1 Basic Encoding Rules 1.0: `0xA501`.
    ///
    /// Row "FIX ASN.1 BER Version 1.0" of the v1.0 table.
    Asn1BerV1,
    /// FIX over ASN.1 Octet Encoding Rules 1.0: `0xA502`.
    ///
    /// Row "FIX ASN.1 OER Version 1.0" of the v1.0 table.
    Asn1OerV1,
    /// FIX tag=value: `0xF000`.
    ///
    /// Row "FIXTV" of the v1.0 table.
    TagValue,
    /// FIXML schema 1.0: `0xF100`.
    ///
    /// Row "FIXML SCHEMA Version 1.0" of the v1.0 table.
    FixmlSchemaV1,
    /// FAST, `0xFA01` through `0xFAFF`; carries the low byte.
    ///
    /// Row "FIX FAST" of the v1.0 table. The specification assigns the range
    /// without saying what the low byte identifies, so it is carried as
    /// received. `0xFA00` is outside the range and is
    /// [`Self::Unregistered`].
    Fast(NonZeroU8),
    /// FIX over JSON: `0xF500`.
    ///
    /// Row "FIX JSON" of the v1.0 table.
    Json,
    /// FIX over BSON: `0xFB00`.
    ///
    /// Row "FIX BSON" of the v1.0 table. SOFH v1.1 Release Candidate 1 no
    /// longer lists it.
    Bson,
    /// A value the v1.0 table does not register, preserved as received.
    ///
    /// Only [`Self::from_u16`] builds one, and only for a value no other
    /// variant names, so a registered value is never wrapped in it.
    Unregistered(UnregisteredEncoding),
}

/// An `Encoding_Type` value that SOFH v1.0 does not register.
///
/// Built only by [`EncodingType::from_u16`]; read it back with
/// [`UnregisteredEncoding::value`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnregisteredEncoding(u16);

impl UnregisteredEncoding {
    /// Returns the raw `Encoding_Type` value, as it was on the wire.
    #[must_use]
    #[inline]
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// High byte of the private user defined range `0x0001..=0x00FF`.
const PRIVATE_HIGH_BYTE: u8 = 0x00;

/// High byte of the FAST range `0xFA01..=0xFAFF`.
const FAST_HIGH_BYTE: u8 = 0xFA;

impl EncodingType {
    /// Classifies a raw `Encoding_Type` value.
    ///
    /// Total: every `u16` maps to exactly one variant, and
    /// [`Self::to_u16`] gives the same value back.
    #[must_use]
    #[inline]
    pub const fn from_u16(value: u16) -> Self {
        match value {
            0x5BE0 => Self::SbeV1BigEndian,
            0xEB50 => Self::SbeV1LittleEndian,
            0x4700 => Self::GpbV1,
            0xA500 => Self::Asn1PerV1,
            0xA501 => Self::Asn1BerV1,
            0xA502 => Self::Asn1OerV1,
            0xF000 => Self::TagValue,
            0xF100 => Self::FixmlSchemaV1,
            0xF500 => Self::Json,
            0xFB00 => Self::Bson,
            _ => {
                let [high, low] = value.to_be_bytes();
                match (high, NonZeroU8::new(low)) {
                    (PRIVATE_HIGH_BYTE, Some(low)) => Self::Private(low),
                    (FAST_HIGH_BYTE, Some(low)) => Self::Fast(low),
                    _ => Self::Unregistered(UnregisteredEncoding(value)),
                }
            }
        }
    }

    /// Returns the raw `Encoding_Type` value written on the wire.
    #[must_use]
    #[inline]
    pub const fn to_u16(self) -> u16 {
        match self {
            Self::Private(low) => u16::from_be_bytes([PRIVATE_HIGH_BYTE, low.get()]),
            Self::SbeV1BigEndian => 0x5BE0,
            Self::SbeV1LittleEndian => 0xEB50,
            Self::GpbV1 => 0x4700,
            Self::Asn1PerV1 => 0xA500,
            Self::Asn1BerV1 => 0xA501,
            Self::Asn1OerV1 => 0xA502,
            Self::TagValue => 0xF000,
            Self::FixmlSchemaV1 => 0xF100,
            Self::Fast(low) => u16::from_be_bytes([FAST_HIGH_BYTE, low.get()]),
            Self::Json => 0xF500,
            Self::Bson => 0xFB00,
            Self::Unregistered(raw) => raw.value(),
        }
    }
}

impl From<u16> for EncodingType {
    #[inline]
    fn from(value: u16) -> Self {
        Self::from_u16(value)
    }
}

impl From<EncodingType> for u16 {
    #[inline]
    fn from(encoding_type: EncodingType) -> Self {
        encoding_type.to_u16()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a `NonZeroU8` for a test fixture.
    fn nz(byte: u8) -> NonZeroU8 {
        match NonZeroU8::new(byte) {
            Some(value) => value,
            None => panic!("fixture byte must be non-zero"),
        }
    }

    /// The single-valued rows of the SOFH v1.0 table, transcribed from the
    /// specification.
    const SPEC_SINGLE_VALUES: [(u16, EncodingType); 10] = [
        (0x5BE0, EncodingType::SbeV1BigEndian),
        (0xEB50, EncodingType::SbeV1LittleEndian),
        (0x4700, EncodingType::GpbV1),
        (0xA500, EncodingType::Asn1PerV1),
        (0xA501, EncodingType::Asn1BerV1),
        (0xA502, EncodingType::Asn1OerV1),
        (0xF000, EncodingType::TagValue),
        (0xF100, EncodingType::FixmlSchemaV1),
        (0xF500, EncodingType::Json),
        (0xFB00, EncodingType::Bson),
    ];

    #[test]
    fn test_encoding_type_spec_single_values_map_both_ways() {
        for (value, variant) in SPEC_SINGLE_VALUES {
            assert_eq!(EncodingType::from_u16(value), variant, "{value:#06X}");
            assert_eq!(variant.to_u16(), value, "{variant:?}");
        }
    }

    #[test]
    fn test_encoding_type_private_range_bounds() {
        assert_eq!(EncodingType::from_u16(0x0001), EncodingType::Private(nz(1)));
        assert_eq!(
            EncodingType::from_u16(0x00FF),
            EncodingType::Private(nz(0xFF))
        );
        assert_eq!(EncodingType::Private(nz(0x42)).to_u16(), 0x0042);
    }

    #[test]
    fn test_encoding_type_fast_range_bounds() {
        assert_eq!(EncodingType::from_u16(0xFA01), EncodingType::Fast(nz(1)));
        assert_eq!(EncodingType::from_u16(0xFAFF), EncodingType::Fast(nz(0xFF)));
        assert_eq!(EncodingType::Fast(nz(0x10)).to_u16(), 0xFA10);
    }

    #[test]
    fn test_encoding_type_values_just_outside_the_ranges_are_unregistered() {
        // 0x0000 is below the private range, 0x0100 above it, and 0xFA00 is
        // the one value of the FAST high byte the table leaves out.
        for value in [0x0000, 0x0100, 0xFA00, 0xF001, 0x5BDF] {
            match EncodingType::from_u16(value) {
                EncodingType::Unregistered(raw) => assert_eq!(raw.value(), value),
                other => panic!("{value:#06X} classified as {other:?}"),
            }
        }
    }

    #[test]
    fn test_encoding_type_sofh_v1_1_rc1_sbe2_values_are_preserved_as_unregistered() {
        // SBE 2.0 is registered by SOFH v1.1 RC1 only; under v1.0 it is an
        // unregistered value, kept exactly.
        for value in [0x5BE1, 0xEB51] {
            let classified = EncodingType::from_u16(value);
            assert!(matches!(classified, EncodingType::Unregistered(_)));
            assert_eq!(classified.to_u16(), value);
        }
    }

    #[test]
    fn test_encoding_type_round_trips_every_u16_exhaustively() {
        let mut private = 0u32;
        let mut fast = 0u32;
        let mut single = 0u32;
        let mut unregistered = 0u32;
        for value in 0..=u16::MAX {
            let classified = EncodingType::from_u16(value);
            assert_eq!(classified.to_u16(), value, "{value:#06X}");
            assert_eq!(u16::from(EncodingType::from(value)), value);
            match classified {
                EncodingType::Private(_) => private += 1,
                EncodingType::Fast(_) => fast += 1,
                EncodingType::Unregistered(raw) => {
                    assert_eq!(raw.value(), value);
                    unregistered += 1;
                }
                _ => single += 1,
            }
        }
        assert_eq!(private, 255);
        assert_eq!(fast, 255);
        assert_eq!(single, 10);
        assert_eq!(unregistered, 65_536 - 255 - 255 - 10);
    }
}
