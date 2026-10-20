/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! Inbound message validation as a seam between the engine and a schema
//! (issue #84, ADR-0031).
//!
//! [`InboundValidator`] is what a session engine calls to check an inbound
//! application message against a schema before the application sees it. It
//! lives here, in the root of the crate graph, so that the engine can hold an
//! `Arc<dyn InboundValidator>` without depending on the crate that answers
//! it: `ironfix-dictionary` implements it for its `Validator`, its
//! `Dictionary` and its `SessionDictionary`, and the engine never names them.
//!
//! A failed check is an [`InboundRejection`]: a version-neutral
//! [`InboundDefect`], the tag the defect is about (`RefTagID` (371)), and a
//! short text for `Text` (58). Turning the defect into a
//! `SessionRejectReason` (373) code is the engine's job, because which codes
//! exist depends on the session's FIX version.
//!
//! # The text never carries field values
//!
//! [`InboundRejection::text`] goes on the wire in a Reject and into log
//! lines. An implementation must build it from tag numbers, dictionary names
//! and positions only, never from the bytes of a field: an inbound message
//! can carry `Password` (554), `NewPassword` (925) or `RawData` (96).

use crate::message::RawMessage;
use std::fmt;

/// What is wrong with an inbound message, in FIX terms but independent of the
/// FIX version.
///
/// Each defect names the `SessionRejectReason` (373) it corresponds to in
/// FIX 4.4 and FIXT.1.1. Not every version defines every code (FIX 4.2 stops
/// at 11, FIX 4.0 and 4.1 define no 373 at all), which is why the defect,
/// not the number, is what crosses the seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum InboundDefect {
    /// A tag the schema does not define (373 = 0, *Invalid tag number*).
    InvalidTagNumber,
    /// A required tag, or a required group's count tag, is absent
    /// (373 = 1, *Required tag missing*).
    RequiredTagMissing,
    /// A defined tag that this message type does not allow
    /// (373 = 2, *Tag not defined for this message type*).
    TagNotDefinedForMessageType,
    /// A value outside the set the field admits (373 = 5, *Value is
    /// incorrect (out of range) for this tag*).
    ValueIncorrect,
    /// A value that does not have the form of the field's data type
    /// (373 = 6, *Incorrect data format for value*).
    IncorrectDataFormat,
    /// A message type the schema does not define (373 = 11, *Invalid
    /// MsgType*).
    InvalidMsgType,
    /// A tag repeated at one level of the message (373 = 13, *Tag appears
    /// more than once*; FIX 4.3 and later).
    TagAppearsMoreThanOnce,
    /// A repeating-group entry that does not start with the group's
    /// delimiter (373 = 15, *Repeating group fields out of order*; FIX 4.3
    /// and later).
    RepeatingGroupFieldsOutOfOrder,
    /// A `NumInGroup` count that does not match the entries present
    /// (373 = 16, *Incorrect NumInGroup count for repeating group*; FIX 4.3
    /// and later).
    IncorrectNumInGroupCount,
    /// Anything else, for example a schema that cannot check this message
    /// type (373 = 99, *Other*; FIX 4.4 and later).
    Other,
}

impl InboundDefect {
    /// A fixed, value-free label for log lines.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::InvalidTagNumber => "invalid tag number",
            Self::RequiredTagMissing => "required tag missing",
            Self::TagNotDefinedForMessageType => "tag not defined for this message type",
            Self::ValueIncorrect => "value is incorrect for this tag",
            Self::IncorrectDataFormat => "incorrect data format for value",
            Self::InvalidMsgType => "invalid MsgType",
            Self::TagAppearsMoreThanOnce => "tag appears more than once",
            Self::RepeatingGroupFieldsOutOfOrder => "repeating group fields out of order",
            Self::IncorrectNumInGroupCount => "incorrect NumInGroup count for repeating group",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for InboundDefect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Why an inbound message failed validation: the defect, the tag it is
/// about, and a value-free text.
///
/// The text must never quote a field's value (see the
/// [module docs](crate::validation)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundRejection {
    defect: InboundDefect,
    ref_tag: Option<u32>,
    text: String,
}

impl InboundRejection {
    /// Creates a rejection.
    ///
    /// # Arguments
    /// * `defect` - What is wrong with the message
    /// * `ref_tag` - The tag the defect is about, for `RefTagID` (371)
    /// * `text` - A short explanation for `Text` (58), built from tag
    ///   numbers, dictionary names and positions only, never from field
    ///   values
    #[must_use]
    pub fn new(defect: InboundDefect, ref_tag: Option<u32>, text: impl Into<String>) -> Self {
        Self {
            defect,
            ref_tag,
            text: text.into(),
        }
    }

    /// What is wrong with the message.
    #[must_use]
    pub const fn defect(&self) -> InboundDefect {
        self.defect
    }

    /// The tag the defect is about, if one can be named.
    #[must_use]
    pub const fn ref_tag(&self) -> Option<u32> {
        self.ref_tag
    }

    /// The value-free explanation.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for InboundRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Checks an inbound application message against a schema.
///
/// The session engine calls it once per in-sequence application message,
/// before the message is handed to the application, when a validation
/// policy other than `Off` is configured. It runs inline on the session's
/// task, so it must not block, and it must not panic (the release profile
/// aborts).
///
/// `Ok(())` means the message passed. A message type the schema does not
/// define is a failure ([`InboundDefect::InvalidMsgType`]), never a pass.
pub trait InboundValidator: Send + Sync {
    /// Validates `msg`.
    ///
    /// # Errors
    /// The first problem found, as an [`InboundRejection`] whose text
    /// carries no field value.
    fn validate(&self, msg: &RawMessage<'_>) -> Result<(), InboundRejection>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inbound_rejection_new_keeps_its_parts() {
        let rejection = InboundRejection::new(
            InboundDefect::RequiredTagMissing,
            Some(54),
            "required tag missing: Side(54)",
        );
        assert_eq!(rejection.defect(), InboundDefect::RequiredTagMissing);
        assert_eq!(rejection.ref_tag(), Some(54));
        assert_eq!(rejection.text(), "required tag missing: Side(54)");
        assert_eq!(rejection.to_string(), "required tag missing: Side(54)");
    }

    #[test]
    fn test_inbound_defect_labels_are_distinct() {
        let all = [
            InboundDefect::InvalidTagNumber,
            InboundDefect::RequiredTagMissing,
            InboundDefect::TagNotDefinedForMessageType,
            InboundDefect::ValueIncorrect,
            InboundDefect::IncorrectDataFormat,
            InboundDefect::InvalidMsgType,
            InboundDefect::TagAppearsMoreThanOnce,
            InboundDefect::RepeatingGroupFieldsOutOfOrder,
            InboundDefect::IncorrectNumInGroupCount,
            InboundDefect::Other,
        ];
        for (i, a) in all.iter().enumerate() {
            assert_eq!(a.to_string(), a.label());
            for b in all.iter().skip(i + 1) {
                assert_ne!(a.label(), b.label());
            }
        }
    }

    #[test]
    fn test_inbound_validator_is_object_safe() {
        struct Reject;
        impl InboundValidator for Reject {
            fn validate(&self, _msg: &RawMessage<'_>) -> Result<(), InboundRejection> {
                Err(InboundRejection::new(InboundDefect::Other, None, "no"))
            }
        }
        let validator: std::sync::Arc<dyn InboundValidator> = std::sync::Arc::new(Reject);
        let msg = match RawMessage::new(
            b"",
            0..0,
            0..0,
            crate::message::MsgType::Heartbeat,
            smallvec::SmallVec::new(),
        ) {
            Ok(msg) => msg,
            Err(err) => panic!("an empty message must build: {err}"),
        };
        assert!(validator.validate(&msg).is_err());
    }
}
