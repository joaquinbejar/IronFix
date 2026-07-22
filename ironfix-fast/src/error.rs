/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! FAST protocol error types.

use thiserror::Error;

/// Errors that can occur during FAST encoding/decoding.
///
/// This enum is `#[non_exhaustive]`: new failure modes are added as the FAST
/// implementation grows, so downstream `match` expressions must carry a
/// wildcard arm.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FastError {
    /// Unexpected end of input.
    #[error("unexpected end of input")]
    UnexpectedEof,

    /// Unknown template ID.
    #[error("unknown template id: {0}")]
    UnknownTemplate(u32),

    /// Invalid presence map.
    #[error("invalid presence map")]
    InvalidPresenceMap,

    /// A presence map exceeds the resource ceiling for its encoded size.
    #[error("presence map exceeds the ceiling of {max_bytes} encoded bytes")]
    PresenceMapTooLarge {
        /// Maximum number of encoded bytes a presence map may occupy.
        max_bytes: usize,
    },

    /// Every encoded presence-map bit has been consumed.
    ///
    /// This is a primitive-level signal from
    /// [`PresenceMap::next_bit`](crate::PresenceMap::next_bit), not a decode
    /// failure. Per FAST v1.1 §6.3.1 a presence map carries an infinite implied
    /// suffix of zero bits, so a field past the encoded bits is absent; the
    /// operator layer reads this exhaustion as absent and does not surface it.
    /// It is exposed so a caller that wants the strict encoded length can tell
    /// where the encoded bits end.
    #[error("presence map exhausted")]
    PresenceMapExhausted,

    /// Integer overflow during decoding.
    #[error("integer overflow")]
    IntegerOverflow,

    /// Invalid string encoding.
    #[error("invalid string encoding")]
    InvalidString,

    /// Invalid decimal encoding.
    #[error("invalid decimal: exponent={exponent}, mantissa={mantissa}")]
    InvalidDecimal {
        /// Decimal exponent.
        exponent: i32,
        /// Decimal mantissa.
        mantissa: i64,
    },

    /// Missing mandatory field.
    #[error("missing mandatory field: {name}")]
    MissingMandatoryField {
        /// Field name.
        name: String,
    },

    /// Invalid operator application.
    #[error("invalid operator: {0}")]
    InvalidOperator(String),

    /// Dictionary entry not found.
    #[error("dictionary entry not found: {key}")]
    DictionaryEntryNotFound {
        /// Dictionary key.
        key: String,
    },

    /// Sequence length mismatch.
    #[error("sequence length mismatch: expected {expected}, got {actual}")]
    SequenceLengthMismatch {
        /// Expected length.
        expected: u32,
        /// Actual length.
        actual: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fast_error_display_is_descriptive() {
        assert_eq!(
            FastError::UnexpectedEof.to_string(),
            "unexpected end of input"
        );
        assert_eq!(FastError::IntegerOverflow.to_string(), "integer overflow");
        assert_eq!(
            FastError::InvalidString.to_string(),
            "invalid string encoding"
        );
        assert_eq!(
            FastError::PresenceMapExhausted.to_string(),
            "presence map exhausted"
        );
        assert_eq!(
            FastError::PresenceMapTooLarge { max_bytes: 64 }.to_string(),
            "presence map exceeds the ceiling of 64 encoded bytes"
        );
    }

    #[test]
    fn test_fast_error_equality_distinguishes_variants() {
        assert_eq!(FastError::UnexpectedEof, FastError::UnexpectedEof.clone());
        assert_ne!(FastError::UnexpectedEof, FastError::IntegerOverflow);
        assert_ne!(
            FastError::PresenceMapTooLarge { max_bytes: 64 },
            FastError::PresenceMapTooLarge { max_bytes: 32 }
        );
    }
}
