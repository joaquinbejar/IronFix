/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! FAST field operators.
//!
//! Operators define how field values are encoded and decoded relative to
//! previous values in the dictionary.
//!
//! The one thing this module must get right is **which operators occupy a bit
//! in the presence map**, because the presence map is positional: a field that
//! takes a bit it should not have — or skips one it should have taken —
//! shifts every later bit and silently corrupts the rest of the message. The
//! matrix lives in [`Operator::requires_pmap`] and is applied in
//! [`Operator::transfer`], which is the only place the two are allowed to
//! disagree with each other (they cannot: the second calls the first).
//!
//! Note that the answer depends on whether the field is optional — a constant
//! field takes a bit only when it is optional — so the matrix cannot be
//! expressed as one boolean per operator.

use crate::error::FastError;
use crate::pmap::PresenceMap;
use serde::{Deserialize, Serialize};

/// FAST field operator types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum Operator {
    /// No operator - value is always present in stream.
    #[default]
    None,
    /// Constant - value is never in stream, always uses initial value.
    Constant,
    /// Default - if absent, use initial value.
    Default,
    /// Copy - if absent, use previous value from dictionary.
    Copy,
    /// Increment - if absent, increment previous value by 1.
    Increment,
    /// Delta - value in stream is delta from previous value.
    Delta,
    /// Tail - value in stream replaces tail of previous value.
    Tail,
}

/// Where the value of a field comes from, once the presence map has been
/// consulted.
///
/// This is the decision an operator makes for one field occurrence; applying it
/// — reading the value, adding a delta, incrementing, combining a tail — needs
/// the field's type and initial value, which live in a template. See the
/// crate-level docs for what this crate does and does not implement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldTransfer {
    /// The value is encoded in the stream and must be read from it.
    ///
    /// For an optional field this is the nullable representation, so the value
    /// read may itself be NULL.
    Stream,
    /// The value is the initial value declared for the field in the template.
    ///
    /// If an optional field declares no initial value, FAST defines the result
    /// as absent; if a mandatory field declares none, the template is in error.
    /// Neither can be decided here, because an initial value belongs to the
    /// template.
    InitialValue,
    /// The value is derived from the operator's dictionary entry — the previous
    /// value of the field.
    ///
    /// When that entry is undefined the fallback is the initial value, and
    /// failing that the field is absent (optional) or the message is in error
    /// (mandatory). As with [`FieldTransfer::InitialValue`], resolving it needs
    /// the template.
    Dictionary,
    /// The field has no value in this message.
    Absent,
}

impl Operator {
    /// Returns true if this operator keeps state in the operator dictionary.
    ///
    /// Copy, increment, delta and tail all decode against the previous value of
    /// the field; constant and default read their fallback from the template's
    /// initial value instead, and a field with no operator has no fallback at
    /// all.
    #[must_use]
    pub const fn uses_dictionary(&self) -> bool {
        matches!(
            self,
            Self::Copy | Self::Increment | Self::Delta | Self::Tail
        )
    }

    /// Returns true if a field with this operator occupies a bit in the
    /// presence map.
    ///
    /// The presence map is positional, so this answer must be exact: a field
    /// that takes a bit it should not have shifts every later bit and corrupts
    /// the remainder of the message. Per FAST v1.1 §6.3 (field operators) and
    /// the operator table in its appendix:
    ///
    /// | Operator | Mandatory | Optional | Why |
    /// |---|---|---|---|
    /// | [`Operator::None`] | no | no | the value is always in the stream, so there is nothing for a bit to say |
    /// | [`Operator::Constant`] | no | **yes** | the value is never in the stream; when optional, the bit is the only thing that distinguishes the constant from absent |
    /// | [`Operator::Default`] | yes | yes | the bit selects between a value in the stream and the initial value |
    /// | [`Operator::Copy`] | yes | yes | the bit selects between a value in the stream and the previous value |
    /// | [`Operator::Increment`] | yes | yes | the bit selects between a value in the stream and the previous value plus one |
    /// | [`Operator::Delta`] | no | no | the delta is always in the stream; an optional delta signals absence with a NULL delta, not with a bit |
    /// | [`Operator::Tail`] | yes | yes | the bit selects between a tail in the stream and the previous value |
    ///
    /// # Arguments
    /// * `optional` - Whether the field is optional (nullable) in its template
    #[must_use]
    pub const fn requires_pmap(&self, optional: bool) -> bool {
        match self {
            // The value is always transferred, so no bit is needed.
            Self::None | Self::Delta => false,
            // A mandatory constant is fully determined by the template; an
            // optional one needs a bit to say present-or-absent.
            Self::Constant => optional,
            Self::Default | Self::Copy | Self::Increment | Self::Tail => true,
        }
    }

    /// Returns true if the field's value may be omitted from the stream.
    ///
    /// "Omitted" here means *not transferred* — the decoder reconstructs the
    /// value from the template or the dictionary. It is not the same question
    /// as whether the field may be null, which is the field's optionality and
    /// not a property of its operator.
    ///
    /// A constant value is never transferred, so it can always be omitted; a
    /// delta is always transferred, as is a field with no operator. The
    /// remaining operators omit the value whenever their presence map bit is
    /// clear.
    #[must_use]
    pub const fn can_be_absent(&self) -> bool {
        match self {
            Self::None | Self::Delta => false,
            Self::Constant | Self::Default | Self::Copy | Self::Increment | Self::Tail => true,
        }
    }

    /// Consumes this field's presence map bit, if it has one, and reports where
    /// its value comes from.
    ///
    /// This is the pmap-consuming half of FAST field decoding: it advances the
    /// map by the number of bits [`Operator::requires_pmap`] says this field
    /// owns — zero or one — so a sequence of calls stays aligned with the
    /// sender. Reading the value itself is the caller's job, because it needs
    /// the field's type and initial value.
    ///
    /// Per FAST v1.1 §6.3.1 a presence map carries an infinite implied suffix
    /// of zero bits: once the encoded bits are used up, every further
    /// pmap-owning field reads a zero bit and is therefore absent. FAST has no
    /// too-short presence map, so a map that ends before the template's last
    /// pmap field is legal — it is the minimal form a conformant sender emits
    /// when the trailing fields are absent — and decodes without error. A field
    /// that reads the implied suffix does not advance the map, which stays at
    /// its end and answers zero for every later field, keeping the sequence
    /// aligned all the same.
    ///
    /// # Arguments
    /// * `optional` - Whether the field is optional (nullable) in its template
    /// * `pmap` - The message's presence map, positioned at this field's bit
    ///
    /// # Errors
    /// A presence map that ends before this field's bit is not an error: the
    /// bit reads as absent per the zero-suffix rule above. The `Result` is
    /// retained so that any other primitive-level presence-map failure can
    /// propagate rather than be silently read as absent.
    pub fn transfer(
        &self,
        optional: bool,
        pmap: &mut PresenceMap,
    ) -> Result<FieldTransfer, FastError> {
        // Consume the bit first, and exactly once, so the map stays aligned
        // whichever arm below answers. FAST v1.1 §6.3.1 defines the presence
        // map as carrying an infinite implied suffix of zero bits, so a field
        // whose bit lies past the encoded map is absent (0), not a truncation —
        // FAST has no too-short presence map. Only that exhaustion is read as
        // absent; any other primitive-level error still propagates.
        let present = if self.requires_pmap(optional) {
            match pmap.next_bit() {
                Ok(bit) => Some(bit),
                Err(FastError::PresenceMapExhausted) => Some(false),
                Err(other) => return Err(other),
            }
        } else {
            None
        };

        // `None` for an operator that always owns a bit is unreachable, but it
        // is spelled out rather than left to a wildcard that would also swallow
        // a future operator.
        Ok(match (self, present) {
            // Always transferred, with or without a template.
            (Self::None | Self::Delta, _) => FieldTransfer::Stream,
            // The value never travels: a mandatory constant is fully determined
            // by the template, and an optional one uses its bit only to say
            // whether the constant applies at all.
            (Self::Constant, None | Some(true)) => FieldTransfer::InitialValue,
            (Self::Constant, Some(false)) => FieldTransfer::Absent,
            (Self::Default, Some(true)) => FieldTransfer::Stream,
            (Self::Default, Some(false) | None) => FieldTransfer::InitialValue,
            (Self::Copy | Self::Increment | Self::Tail, Some(true)) => FieldTransfer::Stream,
            (Self::Copy | Self::Increment | Self::Tail, Some(false) | None) => {
                FieldTransfer::Dictionary
            }
        })
    }
}

/// Dictionary scope for operator state.
///
/// Only [`DictionaryScope::Global`] and [`DictionaryScope::Template`] have
/// backing storage in this crate today — see
/// [`FastDecoder`](crate::FastDecoder). [`DictionaryScope::Type`] is part of the
/// FAST model and is named here, but nothing stores against it yet; it arrives
/// with the template layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum DictionaryScope {
    /// Global dictionary shared across all templates.
    #[default]
    Global,
    /// Template-specific dictionary.
    Template,
    /// Type-specific dictionary.
    ///
    /// Not backed by storage in this crate yet.
    Type,
}

/// State for a dictionary entry.
#[derive(Debug, Clone, Default)]
pub enum DictionaryValue {
    /// No value has been set.
    #[default]
    Undefined,
    /// Value is explicitly empty/null.
    Empty,
    /// Integer value.
    Int(i64),
    /// Unsigned integer value.
    UInt(u64),
    /// String value.
    String(String),
    /// Byte sequence value.
    Bytes(Vec<u8>),
    /// Decimal value (mantissa, exponent).
    Decimal(i64, i32),
}

impl DictionaryValue {
    /// Returns true if the value is undefined.
    #[must_use]
    pub const fn is_undefined(&self) -> bool {
        matches!(self, Self::Undefined)
    }

    /// Returns true if the value is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    /// Returns the value as an `i64`, if it is an integer that fits.
    ///
    /// A value stored as [`DictionaryValue::UInt`] is readable here whenever it
    /// is within `i64` range, and `None` otherwise. Reading across the two
    /// integer variants matters because nothing forces the writer and the
    /// reader of a dictionary entry to agree on signedness — a copy or
    /// increment operator that stored a `UInt` must still be able to read its
    /// own previous value back. The conversion is range-checked, never
    /// truncating: an out-of-range value is `None`, not a wrapped number.
    #[must_use]
    pub const fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(*v),
            // The guard makes the cast exact.
            Self::UInt(v) if *v <= i64::MAX as u64 => Some(*v as i64),
            _ => None,
        }
    }

    /// Returns the value as a `u64`, if it is a non-negative integer.
    ///
    /// The mirror of [`DictionaryValue::as_i64`]: a value stored as
    /// [`DictionaryValue::Int`] is readable here when it is non-negative, and
    /// `None` when it is negative rather than a wrapped positive number.
    #[must_use]
    pub const fn as_u64(&self) -> Option<u64> {
        match self {
            Self::UInt(v) => Some(*v),
            // The guard makes the cast exact.
            Self::Int(v) if *v >= 0 => Some(*v as u64),
            _ => None,
        }
    }

    /// Returns the value as a string, if applicable.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the value as a byte slice, if applicable.
    ///
    /// A [`DictionaryValue::String`] answers with its UTF-8 bytes, so a tail or
    /// delta operator working on bytes can read back a value another operator
    /// stored as a string.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            Self::String(s) => Some(s.as_bytes()),
            _ => None,
        }
    }

    /// Returns the value as a decimal `(mantissa, exponent)` pair, if
    /// applicable.
    ///
    /// The pair is the FAST wire form. Converting it to a
    /// `rust_decimal::Decimal` is the typed seam and belongs to the caller;
    /// this crate never represents a price as a floating-point number.
    #[must_use]
    pub const fn as_decimal(&self) -> Option<(i64, i32)> {
        match self {
            Self::Decimal(mantissa, exponent) => Some((*mantissa, *exponent)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operator_uses_dictionary() {
        assert!(!Operator::None.uses_dictionary());
        assert!(!Operator::Constant.uses_dictionary());
        assert!(!Operator::Default.uses_dictionary());
        assert!(Operator::Copy.uses_dictionary());
        assert!(Operator::Increment.uses_dictionary());
        assert!(Operator::Delta.uses_dictionary());
        assert!(Operator::Tail.uses_dictionary());
    }

    /// Every operator, so a new one cannot be added without the matrix tests
    /// below failing to cover it.
    const ALL_OPERATORS: [Operator; 7] = [
        Operator::None,
        Operator::Constant,
        Operator::Default,
        Operator::Copy,
        Operator::Increment,
        Operator::Delta,
        Operator::Tail,
    ];

    #[test]
    fn test_operator_requires_pmap_matches_the_fast_matrix() {
        // (operator, mandatory answer, optional answer) per FAST v1.1 §6.3.
        let matrix: [(Operator, bool, bool); 7] = [
            // No operator: the value is always in the stream.
            (Operator::None, false, false),
            // Constant: a bit only when optional, to say present or absent.
            (Operator::Constant, false, true),
            // Default: the bit selects stream value or initial value.
            (Operator::Default, true, true),
            // Copy: the bit selects stream value or previous value.
            (Operator::Copy, true, true),
            // Increment: the bit selects stream value or previous value + 1.
            (Operator::Increment, true, true),
            // Delta: the delta is always in the stream; absence is a NULL delta.
            (Operator::Delta, false, false),
            // Tail: the bit selects a tail in the stream or the previous value.
            (Operator::Tail, true, true),
        ];

        assert_eq!(
            matrix.len(),
            ALL_OPERATORS.len(),
            "the matrix must cover every operator"
        );

        for (operator, mandatory, optional) in matrix {
            assert_eq!(
                operator.requires_pmap(false),
                mandatory,
                "{operator:?} mandatory"
            );
            assert_eq!(
                operator.requires_pmap(true),
                optional,
                "{operator:?} optional"
            );
        }
    }

    #[test]
    fn test_operator_can_be_absent_matches_the_fast_matrix() {
        // "Absent" is "not transferred": constant never travels, delta and a
        // field with no operator always do, the rest depend on their bit.
        let matrix: [(Operator, bool); 7] = [
            (Operator::None, false),
            (Operator::Constant, true),
            (Operator::Default, true),
            (Operator::Copy, true),
            (Operator::Increment, true),
            (Operator::Delta, false),
            (Operator::Tail, true),
        ];

        for (operator, expected) in matrix {
            assert_eq!(operator.can_be_absent(), expected, "{operator:?}");
        }
    }

    #[test]
    fn test_operator_transfer_consumes_exactly_the_bits_requires_pmap_claims() {
        // The invariant the whole positional presence map rests on: `transfer`
        // advances the map by one bit when `requires_pmap` says so and by none
        // otherwise, for every operator and both optionalities.
        for operator in ALL_OPERATORS {
            for optional in [false, true] {
                let mut pmap = PresenceMap::from_bits(vec![true, true]);
                assert!(
                    operator.transfer(optional, &mut pmap).is_ok(),
                    "{operator:?} optional={optional}"
                );

                let expected = usize::from(operator.requires_pmap(optional));
                assert_eq!(
                    pmap.position(),
                    expected,
                    "{operator:?} optional={optional} consumed the wrong number of bits"
                );
            }
        }
    }

    #[test]
    fn test_operator_transfer_resolves_the_source_of_the_value() {
        // (operator, optional, bit, expected source)
        let cases: [(Operator, bool, bool, FieldTransfer); 12] = [
            // No operator and delta ignore the map entirely.
            (Operator::None, false, false, FieldTransfer::Stream),
            (Operator::None, true, false, FieldTransfer::Stream),
            (Operator::Delta, false, false, FieldTransfer::Stream),
            (Operator::Delta, true, false, FieldTransfer::Stream),
            // A mandatory constant is fully determined by the template.
            (
                Operator::Constant,
                false,
                false,
                FieldTransfer::InitialValue,
            ),
            // An optional constant uses its bit to say present or absent.
            (Operator::Constant, true, true, FieldTransfer::InitialValue),
            (Operator::Constant, true, false, FieldTransfer::Absent),
            // Default falls back to the initial value.
            (Operator::Default, false, true, FieldTransfer::Stream),
            (Operator::Default, false, false, FieldTransfer::InitialValue),
            // The stateful operators fall back to the dictionary.
            (Operator::Copy, false, false, FieldTransfer::Dictionary),
            (Operator::Increment, true, false, FieldTransfer::Dictionary),
            (Operator::Tail, false, true, FieldTransfer::Stream),
        ];

        for (operator, optional, bit, expected) in cases {
            let mut pmap = PresenceMap::from_bits(vec![bit]);
            assert_eq!(
                operator.transfer(optional, &mut pmap),
                Ok(expected),
                "{operator:?} optional={optional} bit={bit}"
            );
        }
    }

    #[test]
    fn test_operator_transfer_past_the_encoded_map_reads_as_absent() {
        // FAST v1.1 §6.3.1: a bit past the encoded presence map is the implied
        // zero suffix — absent — not a truncation error. A Copy field with an
        // empty map therefore falls back to the dictionary, without error, and
        // the exhausted map does not advance.
        let mut pmap = PresenceMap::new();
        assert_eq!(
            Operator::Copy.transfer(false, &mut pmap),
            Ok(FieldTransfer::Dictionary)
        );
        assert_eq!(
            pmap.position(),
            0,
            "the implied zero suffix does not advance the map"
        );

        // An optional constant past the end is likewise absent, not an error.
        let mut pmap = PresenceMap::new();
        assert_eq!(
            Operator::Constant.transfer(true, &mut pmap),
            Ok(FieldTransfer::Absent)
        );

        // The operators that own no bit are unaffected by an empty map.
        let mut pmap = PresenceMap::new();
        assert_eq!(
            Operator::Delta.transfer(true, &mut pmap),
            Ok(FieldTransfer::Stream)
        );
    }

    #[test]
    fn test_operator_transfer_eight_plus_fields_over_one_byte_map_honours_zero_suffix() {
        // A conformant peer whose trailing pmap-owning fields are absent emits a
        // legal one-byte (seven data-bit) presence map. A template with ten Copy
        // fields must decode it: the seven encoded bits drive the first seven
        // fields, and the remaining three read the implied zero suffix as absent
        // — with no `PresenceMapExhausted`.
        //
        // 0b1101_0101: stop bit set, payload bits (6..0) = 1_0_1_0_1_0_1.
        let data = [0b1101_0101];
        let mut offset = 0;
        let decoded = PresenceMap::decode(&data, &mut offset);
        assert!(decoded.is_ok());

        if let Ok(mut pmap) = decoded {
            // A Copy field is `Stream` on a set bit and `Dictionary` on a clear
            // or implied-zero bit. The first seven entries are the encoded bits;
            // the last three are the implied zero suffix.
            let expected = [
                FieldTransfer::Stream,     // bit 1
                FieldTransfer::Dictionary, // bit 0
                FieldTransfer::Stream,     // bit 1
                FieldTransfer::Dictionary, // bit 0
                FieldTransfer::Stream,     // bit 1
                FieldTransfer::Dictionary, // bit 0
                FieldTransfer::Stream,     // bit 1
                FieldTransfer::Dictionary, // implied zero
                FieldTransfer::Dictionary, // implied zero
                FieldTransfer::Dictionary, // implied zero
            ];

            for (index, want) in expected.iter().enumerate() {
                assert_eq!(
                    Operator::Copy.transfer(false, &mut pmap),
                    Ok(*want),
                    "field {index} on a legal one-byte map"
                );
            }

            // Only the seven encoded bits were consumed; the implied suffix does
            // not advance the map past its end.
            assert_eq!(pmap.position(), 7, "only the encoded bits are consumed");
        }
    }

    #[test]
    fn test_dictionary_value() {
        let undefined = DictionaryValue::Undefined;
        assert!(undefined.is_undefined());

        let int_val = DictionaryValue::Int(42);
        assert_eq!(int_val.as_i64(), Some(42));

        let str_val = DictionaryValue::String("test".to_string());
        assert_eq!(str_val.as_str(), Some("test"));
    }

    #[test]
    fn test_dictionary_value_integer_accessors_read_across_both_variants() {
        // A copy or increment operator must be able to read back a value it
        // stored, whichever integer variant the writer chose.
        assert_eq!(DictionaryValue::Int(42).as_u64(), Some(42));
        assert_eq!(DictionaryValue::UInt(42).as_i64(), Some(42));
    }

    #[test]
    fn test_dictionary_value_integer_accessors_reject_out_of_range_values() {
        // Out of range is `None`, never a wrapped number.
        assert_eq!(DictionaryValue::Int(-1).as_u64(), None);
        assert_eq!(DictionaryValue::UInt(u64::MAX).as_i64(), None);

        // The boundary itself is representable in both directions.
        assert_eq!(DictionaryValue::Int(0).as_u64(), Some(0));
        assert_eq!(
            DictionaryValue::Int(i64::MAX).as_u64(),
            Some(i64::MAX as u64)
        );
        assert_eq!(
            DictionaryValue::UInt(i64::MAX as u64).as_i64(),
            Some(i64::MAX)
        );
    }

    #[test]
    fn test_dictionary_value_byte_and_decimal_accessors() {
        assert_eq!(
            DictionaryValue::Bytes(vec![1, 2, 3]).as_bytes(),
            Some(&[1, 2, 3][..])
        );
        assert_eq!(
            DictionaryValue::String("ab".to_string()).as_bytes(),
            Some(&b"ab"[..])
        );
        assert_eq!(
            DictionaryValue::Decimal(1234, -2).as_decimal(),
            Some((1234, -2))
        );
        assert_eq!(DictionaryValue::Undefined.as_decimal(), None);
        assert_eq!(DictionaryValue::Empty.as_bytes(), None);
    }
}
