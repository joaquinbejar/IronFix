/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! Field types and traits for FIX protocol messages.
//!
//! This module provides:
//! - [`FieldTag`]: Type-safe wrapper for FIX field tag numbers
//! - [`FieldRef`]: Zero-copy reference to a field within a message buffer
//! - [`FieldValue`]: Enumeration of possible field value types
//! - [`FixField`]: Trait for typed field access

use crate::error::{DecodeError, EncodeError, InvalidFieldTag};
use bytes::Bytes;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// The lowest tag number in the original FIX bilateral user-defined range.
///
/// FIX reserves 5000-9999 for bilateral user-defined fields, so 4999 is the
/// highest standard tag below the range and 5000 the first user-defined one.
pub const USER_DEFINED_TAG_MIN: u32 = 5000;

/// The highest tag number in the original FIX bilateral user-defined range.
///
/// The first user-defined range is 5000-9999. Tags 10000-19999 are reserved
/// for internal use within a single firm and are not the bilateral range.
pub const USER_DEFINED_TAG_MAX: u32 = 9999;

/// The lowest tag number in the extended FIX bilateral user-defined range.
///
/// The Global Technical Committee approved 20000-39999 as a second bilateral
/// user-defined range in December 2009, once the 5000-9999 range filled up;
/// tags here are used bilaterally and do not need to be registered.
pub const USER_DEFINED_EXT_TAG_MIN: u32 = 20000;

/// The highest tag number in the extended FIX bilateral user-defined range.
///
/// The extended user-defined range is 20000-39999. Tags at or above 40000 are
/// reserved (GTC / internal use), not user-defined; the loaded dictionary, not
/// this type, is what says what an individual high tag means.
pub const USER_DEFINED_EXT_TAG_MAX: u32 = 39999;

/// FIX field tag number.
///
/// Tags are positive integers that identify fields within a FIX message.
/// Standard tags are defined in the FIX specification (1-4999). FIX reserves
/// **two** disjoint bilateral user-defined ranges: 5000-9999, and 20000-39999
/// (approved by the GTC in December 2009 once the first filled up). Tags
/// 10000-19999 are internal-use, and tags at or above 40000 are reserved, so
/// neither is user-defined. Only the two user-defined ranges classify as such
/// here; a dictionary — not this type — is what says whether a given tag is
/// known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct FieldTag(u32);

impl FieldTag {
    /// Creates a new field tag **without validating it**.
    ///
    /// `tag` is not checked against [`FieldTag::is_valid`]; `FieldTag::new(0)`
    /// yields a tag that is neither standard nor user-defined. Use
    /// [`FieldTag::try_new`] for a value that came off the wire or from a
    /// caller.
    #[inline]
    #[must_use]
    pub const fn new(tag: u32) -> Self {
        Self(tag)
    }

    /// Creates a new field tag, rejecting numbers that are not legal FIX tags.
    ///
    /// # Errors
    /// Returns [`InvalidFieldTag`] if `tag` is `0`.
    #[inline]
    pub const fn try_new(tag: u32) -> Result<Self, InvalidFieldTag> {
        if tag == 0 {
            return Err(InvalidFieldTag::new(tag));
        }
        Ok(Self(tag))
    }

    /// Returns the raw tag number.
    #[inline]
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }

    /// Returns true if this is a legal FIX tag number (>= 1).
    #[inline]
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.0 >= 1
    }

    /// Returns true if this is a standard FIX tag below the user-defined range
    /// (1-4999).
    ///
    /// This does not cover assigned tags above 9999: the dictionary — not this
    /// predicate — classifies an individual high tag.
    #[inline]
    #[must_use]
    pub const fn is_standard(self) -> bool {
        self.0 >= 1 && self.0 < USER_DEFINED_TAG_MIN
    }

    /// Returns true if this is a bilateral user-defined tag.
    ///
    /// FIX defines **two** disjoint user-defined ranges:
    /// [`USER_DEFINED_TAG_MIN`]..=[`USER_DEFINED_TAG_MAX`] (5000-9999) and
    /// [`USER_DEFINED_EXT_TAG_MIN`]..=[`USER_DEFINED_EXT_TAG_MAX`]
    /// (20000-39999). A tag in the 10000-19999 internal-use range, or at or
    /// above 40000, is deliberately *not* user-defined.
    #[inline]
    #[must_use]
    pub const fn is_user_defined(self) -> bool {
        (self.0 >= USER_DEFINED_TAG_MIN && self.0 <= USER_DEFINED_TAG_MAX)
            || (self.0 >= USER_DEFINED_EXT_TAG_MIN && self.0 <= USER_DEFINED_EXT_TAG_MAX)
    }
}

impl From<u32> for FieldTag {
    fn from(tag: u32) -> Self {
        Self(tag)
    }
}

impl From<FieldTag> for u32 {
    fn from(tag: FieldTag) -> Self {
        tag.0
    }
}

impl fmt::Display for FieldTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Zero-copy reference to a field within a FIX message buffer.
///
/// This struct holds references to the original message buffer,
/// avoiding allocation during parsing.
#[derive(Debug, Clone, Copy)]
pub struct FieldRef<'a> {
    /// The field tag number.
    pub tag: u32,
    /// Reference to the field value bytes (without delimiters).
    pub value: &'a [u8],
}

impl<'a> FieldRef<'a> {
    /// Creates a new field reference.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    /// * `value` - Reference to the value bytes
    #[inline]
    #[must_use]
    pub const fn new(tag: u32, value: &'a [u8]) -> Self {
        Self { tag, value }
    }

    /// Returns the field tag.
    #[inline]
    #[must_use]
    pub const fn tag(&self) -> FieldTag {
        FieldTag(self.tag)
    }

    /// Returns the value as a string slice.
    ///
    /// # Errors
    /// Returns `DecodeError::InvalidUtf8` if the value is not valid UTF-8.
    pub fn as_str(&self) -> Result<&'a str, DecodeError> {
        std::str::from_utf8(self.value).map_err(DecodeError::from)
    }

    /// Returns the value as an owned String.
    ///
    /// # Errors
    /// Returns `DecodeError::InvalidUtf8` if the value is not valid UTF-8.
    pub fn to_string(&self) -> Result<String, DecodeError> {
        self.as_str().map(String::from)
    }

    /// Parses the value as the specified type.
    ///
    /// # Errors
    /// Returns `DecodeError::InvalidFieldValue` if parsing fails.
    pub fn parse<T: FromStr>(&self) -> Result<T, DecodeError> {
        let s = self.as_str()?;
        s.parse().map_err(|_| DecodeError::InvalidFieldValue {
            tag: self.tag,
            reason: format!("failed to parse '{}' as {}", s, std::any::type_name::<T>()),
        })
    }

    /// Returns the value as a u64.
    ///
    /// # Errors
    /// Returns `DecodeError::InvalidFieldValue` if the value is not a valid integer.
    pub fn as_u64(&self) -> Result<u64, DecodeError> {
        self.parse()
    }

    /// Returns the value as an i64.
    ///
    /// # Errors
    /// Returns `DecodeError::InvalidFieldValue` if the value is not a valid integer.
    pub fn as_i64(&self) -> Result<i64, DecodeError> {
        self.parse()
    }

    /// Returns the value as a Decimal.
    ///
    /// # Errors
    /// Returns `DecodeError::InvalidFieldValue` if the value is not a valid decimal.
    pub fn as_decimal(&self) -> Result<Decimal, DecodeError> {
        self.parse()
    }

    /// Returns the value as a bool (FIX uses 'Y'/'N').
    ///
    /// # Errors
    /// Returns `DecodeError::InvalidFieldValue` if the value is not 'Y' or 'N'.
    pub fn as_bool(&self) -> Result<bool, DecodeError> {
        match self.value {
            b"Y" => Ok(true),
            b"N" => Ok(false),
            _ => Err(DecodeError::InvalidFieldValue {
                tag: self.tag,
                reason: "expected 'Y' or 'N'".to_string(),
            }),
        }
    }

    /// Returns the value as a single character.
    ///
    /// # Errors
    /// Returns `DecodeError::InvalidFieldValue` if the value is not a single ASCII character.
    pub fn as_char(&self) -> Result<char, DecodeError> {
        if self.value.len() == 1 && self.value[0].is_ascii() {
            Ok(self.value[0] as char)
        } else {
            Err(DecodeError::InvalidFieldValue {
                tag: self.tag,
                reason: "expected single ASCII character".to_string(),
            })
        }
    }

    /// Returns the raw bytes of the value.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.value
    }

    /// Returns the length of the value in bytes.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.value.len()
    }

    /// Returns true if the value is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

/// Enumeration of possible FIX field value types.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FieldValue {
    /// String value.
    String(String),
    /// Integer value.
    Int(i64),
    /// Unsigned integer value.
    UInt(u64),
    /// Decimal/float value.
    Decimal(Decimal),
    /// Boolean value (Y/N).
    Bool(bool),
    /// Single character value.
    Char(char),
    /// Raw bytes (for data fields).
    Data(Bytes),
}

impl FieldValue {
    /// Returns the value as a string, if it is a String variant.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the value as an i64, if it is an Int variant.
    #[must_use]
    pub const fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns the value as a u64, if it is a UInt variant.
    #[must_use]
    pub const fn as_u64(&self) -> Option<u64> {
        match self {
            Self::UInt(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns the value as a Decimal, if it is a Decimal variant.
    #[must_use]
    pub const fn as_decimal(&self) -> Option<Decimal> {
        match self {
            Self::Decimal(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns the value as a bool, if it is a Bool variant.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns the value as a char, if it is a Char variant.
    #[must_use]
    pub const fn as_char(&self) -> Option<char> {
        match self {
            Self::Char(v) => Some(*v),
            _ => None,
        }
    }
}

impl fmt::Display for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(s) => write!(f, "{}", s),
            Self::Int(v) => write!(f, "{}", v),
            Self::UInt(v) => write!(f, "{}", v),
            Self::Decimal(v) => write!(f, "{}", v),
            Self::Bool(v) => write!(f, "{}", if *v { "Y" } else { "N" }),
            Self::Char(c) => write!(f, "{}", c),
            Self::Data(d) => write!(f, "<{} bytes>", d.len()),
        }
    }
}

/// Trait for typed FIX field access.
///
/// This trait is implemented by generated field types to provide
/// type-safe access to field values.
pub trait FixField: Sized {
    /// The tag number for this field.
    const TAG: u32;

    /// The Rust type for this field's value.
    type Value;

    /// Decodes the field value from a byte slice.
    ///
    /// # Arguments
    /// * `bytes` - The raw bytes of the field value
    ///
    /// # Errors
    /// Returns `DecodeError` if the value cannot be decoded.
    fn decode(bytes: &[u8]) -> Result<Self::Value, DecodeError>;

    /// Encodes the field value to bytes.
    ///
    /// # Arguments
    /// * `value` - The value to encode
    /// * `buf` - The buffer to write to
    ///
    /// # Errors
    /// Returns [`EncodeError`] if `value` has no legal on-the-wire form — for
    /// example a string carrying the SOH delimiter
    /// ([`EncodeError::InvalidFieldValue`]) or one past a length bound
    /// ([`EncodeError::FieldTooLong`]). Mirrors
    /// [`crate::message::FixMessage::encode`], so an implementor never has to
    /// panic or emit corrupt bytes.
    fn encode(value: &Self::Value, buf: &mut Vec<u8>) -> Result<(), EncodeError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unwraps a `Result` with test context instead of `.unwrap()`.
    #[track_caller]
    fn ok<T, E: fmt::Debug>(result: Result<T, E>, what: &str) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("{what}: {err:?}"),
        }
    }

    /// Asserts that `result` failed with `InvalidFieldValue` for `tag`.
    #[track_caller]
    fn assert_invalid_field_value<T: fmt::Debug>(result: Result<T, DecodeError>, tag: u32) {
        match result {
            Err(DecodeError::InvalidFieldValue { tag: actual, .. }) => assert_eq!(actual, tag),
            other => panic!("expected InvalidFieldValue for tag {tag}, got {other:?}"),
        }
    }

    #[test]
    fn test_field_tag_standard_range() {
        let tag = FieldTag::new(35);
        assert_eq!(tag.value(), 35);
        assert!(tag.is_valid());
        assert!(tag.is_standard());
        assert!(!tag.is_user_defined());
    }

    #[test]
    fn test_field_tag_zero_is_neither_standard_nor_user_defined() {
        let zero = FieldTag::new(0);
        assert!(!zero.is_valid());
        assert!(!zero.is_standard());
        assert!(!zero.is_user_defined());
        assert_eq!(FieldTag::try_new(0), Err(InvalidFieldTag::new(0)));
    }

    #[test]
    fn test_field_tag_boundary_4999_is_standard() {
        let tag = ok(FieldTag::try_new(4999), "4999 is a legal tag");
        assert!(tag.is_standard());
        assert!(!tag.is_user_defined());
    }

    #[test]
    fn test_field_tag_boundary_5000_is_user_defined() {
        let tag = ok(FieldTag::try_new(5000), "5000 is a legal tag");
        assert!(!tag.is_standard());
        assert!(tag.is_user_defined());
        assert_eq!(tag.value(), USER_DEFINED_TAG_MIN);
    }

    #[test]
    fn test_field_tag_boundary_9999_is_user_defined() {
        let tag = ok(FieldTag::try_new(9999), "9999 is a legal tag");
        assert!(!tag.is_standard());
        assert!(tag.is_user_defined());
        assert_eq!(tag.value(), USER_DEFINED_TAG_MAX);
    }

    #[test]
    fn test_field_tag_boundary_10000_is_not_user_defined() {
        // 10000-19999 is internal-use, between the two bilateral ranges.
        let tag = ok(FieldTag::try_new(10000), "10000 is a legal tag");
        assert!(!tag.is_user_defined());
        assert!(!tag.is_standard());
    }

    #[test]
    fn test_field_tag_extended_user_defined_range_boundaries() {
        // The GTC approved 20000-39999 as a second bilateral user-defined range
        // in 2009; the earlier `<= 9999` bound regressed all of it to false.
        // 19999 is still internal-use; 40000+ is reserved.
        let cases = [
            (19999u32, false),
            (20000, true),
            (USER_DEFINED_EXT_TAG_MIN, true),
            (30000, true),
            (39999, true),
            (USER_DEFINED_EXT_TAG_MAX, true),
            (40000, false),
        ];
        for (tag_num, expected) in cases {
            let tag = ok(FieldTag::try_new(tag_num), "high tag is legal");
            assert_eq!(
                tag.is_user_defined(),
                expected,
                "is_user_defined({tag_num}) should be {expected}"
            );
            assert!(!tag.is_standard(), "{tag_num} is not a standard low tag");
        }
    }

    #[test]
    fn test_field_tag_reserved_high_range_is_not_user_defined() {
        // Tags at or above 40000 are reserved (GTC / internal use), not
        // user-defined; the original `>= 5000` predicate misclassified them.
        for tag_num in [40000, 40001, 49999, 50000] {
            let tag = ok(FieldTag::try_new(tag_num), "reserved high tag is legal");
            assert!(
                !tag.is_user_defined(),
                "reserved tag {tag_num} must not be user-defined"
            );
        }
    }

    #[test]
    fn test_field_ref_as_str() {
        let field = FieldRef::new(11, b"ORDER123");
        assert_eq!(field.as_str(), Ok("ORDER123"));
    }

    #[test]
    fn test_field_ref_as_u64() {
        let field = FieldRef::new(34, b"12345");
        assert_eq!(field.as_u64(), Ok(12345));
    }

    #[test]
    fn test_field_ref_as_u64_non_numeric_is_typed_error() {
        assert_invalid_field_value(FieldRef::new(34, b"abc").as_u64(), 34);
    }

    #[test]
    fn test_field_ref_as_u64_negative_is_typed_error() {
        assert_invalid_field_value(FieldRef::new(34, b"-1").as_u64(), 34);
    }

    #[test]
    fn test_field_ref_as_u64_empty_is_typed_error() {
        assert_invalid_field_value(FieldRef::new(34, b"").as_u64(), 34);
    }

    #[test]
    fn test_field_ref_as_i64_accepts_negative() {
        assert_eq!(FieldRef::new(14, b"-42").as_i64(), Ok(-42));
    }

    #[test]
    fn test_field_ref_as_decimal_parses_price() {
        let field = FieldRef::new(44, b"123.45");
        let price = ok(field.as_decimal(), "123.45 is a valid price");
        assert_eq!(price, Decimal::new(12345, 2));
    }

    #[test]
    fn test_field_ref_as_decimal_preserves_scale() {
        // Trailing zeros are significant on the wire; the parse keeps them.
        let field = FieldRef::new(44, b"1.500");
        let price = ok(field.as_decimal(), "1.500 is a valid price");
        assert_eq!(price.to_string(), "1.500");
    }

    #[test]
    fn test_field_ref_as_decimal_negative_price() {
        let field = FieldRef::new(44, b"-0.01");
        let price = ok(field.as_decimal(), "-0.01 is a valid price");
        assert_eq!(price, Decimal::new(-1, 2));
    }

    #[test]
    fn test_field_ref_as_decimal_two_points_is_typed_error() {
        assert_invalid_field_value(FieldRef::new(44, b"1.2.3").as_decimal(), 44);
    }

    #[test]
    fn test_field_ref_as_decimal_garbage_is_typed_error() {
        assert_invalid_field_value(FieldRef::new(44, b"abc").as_decimal(), 44);
        assert_invalid_field_value(FieldRef::new(44, b"").as_decimal(), 44);
        assert_invalid_field_value(FieldRef::new(44, b"1,50").as_decimal(), 44);
    }

    #[test]
    fn test_field_ref_as_decimal_invalid_utf8_is_typed_error() {
        let field = FieldRef::new(44, &[0xFF, 0xFE]);
        assert!(matches!(
            field.as_decimal(),
            Err(DecodeError::InvalidUtf8(_))
        ));
    }

    #[test]
    fn test_field_ref_as_bool() {
        assert_eq!(FieldRef::new(141, b"Y").as_bool(), Ok(true));
        assert_eq!(FieldRef::new(141, b"N").as_bool(), Ok(false));
    }

    #[test]
    fn test_field_ref_as_bool_rejects_lowercase_and_words() {
        assert_invalid_field_value(FieldRef::new(141, b"y").as_bool(), 141);
        assert_invalid_field_value(FieldRef::new(141, b"n").as_bool(), 141);
        assert_invalid_field_value(FieldRef::new(141, b"YES").as_bool(), 141);
        assert_invalid_field_value(FieldRef::new(141, b"").as_bool(), 141);
    }

    #[test]
    fn test_field_ref_as_char() {
        assert_eq!(FieldRef::new(54, b"1").as_char(), Ok('1'));
    }

    #[test]
    fn test_field_ref_as_char_rejects_multi_byte_and_non_ascii() {
        assert_invalid_field_value(FieldRef::new(54, b"12").as_char(), 54);
        assert_invalid_field_value(FieldRef::new(54, b"").as_char(), 54);
        // 'ñ' is two bytes and neither is ASCII.
        assert_invalid_field_value(FieldRef::new(54, "ñ".as_bytes()).as_char(), 54);
        assert_invalid_field_value(FieldRef::new(54, &[0x80]).as_char(), 54);
    }

    #[test]
    fn test_field_ref_invalid_utf8() {
        let field = FieldRef::new(1, &[0xFF, 0xFE]);
        assert!(matches!(field.as_str(), Err(DecodeError::InvalidUtf8(_))));
    }

    #[test]
    fn test_field_value_display() {
        assert_eq!(FieldValue::String("test".to_string()).to_string(), "test");
        assert_eq!(FieldValue::Int(42).to_string(), "42");
        assert_eq!(FieldValue::Bool(true).to_string(), "Y");
        assert_eq!(FieldValue::Bool(false).to_string(), "N");
    }
}
