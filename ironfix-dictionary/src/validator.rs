/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 12/7/26
******************************************************************************/

//! Dictionary-driven message validation.
//!
//! [`Validator`] checks a parsed [`RawMessage`] against a [`Dictionary`]:
//!
//! - the message type must be defined
//! - every tag must be defined in the dictionary and allowed for the message
//! - required header, body, and trailer fields must be present
//! - enumerated fields must carry a defined value
//! - repeating groups must declare a count matching the delimiter
//!   occurrences, and entries must start with the delimiter tag
//!
//! Notes:
//! - `CheckSum(10)` presence is not re-checked: the tag-value decoder
//!   already consumes and verifies it, so it never appears among the
//!   parsed fields.
//! - Required fields *inside* repeating group entries are not validated
//!   per-entry; group membership is validated via the count/delimiter
//!   checks above.

use crate::schema::{Dictionary, FieldType, GroupDef, MessageDef};
use ironfix_core::message::RawMessage;
use std::collections::{HashMap, HashSet};

/// A single validation failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    /// The message type (tag 35) is not defined in the dictionary.
    #[error("unknown message type `{msg_type}`")]
    UnknownMsgType {
        /// The offending message type value.
        msg_type: String,
    },
    /// A required field is missing.
    #[error("missing required field {name}({tag})")]
    MissingRequiredField {
        /// Field tag.
        tag: u32,
        /// Field name.
        name: String,
    },
    /// A tag is not defined anywhere in the dictionary.
    #[error("tag {tag} is not defined in the dictionary")]
    UnknownTag {
        /// The offending tag.
        tag: u32,
    },
    /// A tag is defined in the dictionary but not allowed for this message type.
    #[error("tag {tag} is not allowed for message type `{msg_type}`")]
    FieldNotAllowedForMessage {
        /// The offending tag.
        tag: u32,
        /// The message type being validated.
        msg_type: String,
    },
    /// An enumerated field carries a value outside its defined set.
    #[error("invalid value `{value}` for field {name}({tag})")]
    InvalidEnumValue {
        /// Field tag.
        tag: u32,
        /// Field name.
        name: String,
        /// The offending value.
        value: String,
    },
    /// A group count field does not hold a valid number.
    #[error("invalid count value `{value}` for group count field {name}({tag})")]
    InvalidGroupCount {
        /// Count field tag (NumInGroup).
        tag: u32,
        /// Group name.
        name: String,
        /// The offending value.
        value: String,
    },
    /// The declared group count does not match the delimiter occurrences.
    #[error(
        "group {name}({count_tag}) declares {declared} entries but found {actual} occurrences of delimiter tag {delimiter_tag}"
    )]
    GroupCountMismatch {
        /// Count field tag (NumInGroup).
        count_tag: u32,
        /// Group name.
        name: String,
        /// Sum of declared entry counts.
        declared: u64,
        /// Observed delimiter occurrences.
        actual: u64,
        /// Delimiter tag expected to start each entry.
        delimiter_tag: u32,
    },
    /// A non-empty group is not immediately followed by its delimiter tag.
    #[error(
        "group {name}({count_tag}) entries must start with delimiter tag {expected}, found tag {found}"
    )]
    GroupDelimiterMismatch {
        /// Count field tag (NumInGroup).
        count_tag: u32,
        /// Group name.
        name: String,
        /// Expected delimiter tag.
        expected: u32,
        /// Tag actually found after the count field.
        found: u32,
    },
    /// A required repeating group is absent.
    #[error("missing required group {name}({count_tag})")]
    MissingRequiredGroup {
        /// Count field tag (NumInGroup).
        count_tag: u32,
        /// Group name.
        name: String,
    },
}

/// Group metadata collected for count/delimiter validation.
#[derive(Debug)]
struct GroupCheck {
    count_tag: u32,
    name: String,
    delimiter_tag: u32,
    required: bool,
}

/// Tags and groups reachable for a given message type.
#[derive(Debug, Default)]
struct Scope {
    allowed: HashSet<u32>,
    required: Vec<(u32, String)>,
    groups: Vec<GroupCheck>,
}

impl Scope {
    fn add_field(&mut self, tag: u32, name: &str, required: bool) {
        self.allowed.insert(tag);
        if required {
            self.required.push((tag, name.to_string()));
        }
    }
}

/// Validates parsed messages against a [`Dictionary`].
#[derive(Debug, Clone, Copy)]
pub struct Validator<'d> {
    dict: &'d Dictionary,
}

impl<'d> Validator<'d> {
    /// Creates a validator for the given dictionary.
    #[must_use]
    pub const fn new(dict: &'d Dictionary) -> Self {
        Self { dict }
    }

    /// Validates a parsed message against the dictionary.
    ///
    /// # Arguments
    /// * `msg` - The decoded message to validate
    ///
    /// # Errors
    /// Returns every [`ValidationError`] found; `Ok(())` means the message
    /// passed all checks.
    pub fn validate(&self, msg: &RawMessage<'_>) -> Result<(), Vec<ValidationError>> {
        let msg_type = msg.msg_type().as_str().to_string();
        let Some(msg_def) = self.dict.get_message(&msg_type) else {
            return Err(vec![ValidationError::UnknownMsgType { msg_type }]);
        };

        let scope = self.collect_scope(msg_def);
        let mut errors = Vec::new();

        let fields: Vec<_> = msg.fields().collect();
        let mut occurrences: HashMap<u32, u64> = HashMap::new();
        for field in &fields {
            *occurrences.entry(field.tag).or_default() += 1;
        }

        // Per-field checks: defined, allowed, enum value.
        for field in &fields {
            let Some(def) = self.dict.get_field(field.tag) else {
                errors.push(ValidationError::UnknownTag { tag: field.tag });
                continue;
            };
            if !scope.allowed.contains(&field.tag) {
                errors.push(ValidationError::FieldNotAllowedForMessage {
                    tag: field.tag,
                    msg_type: msg_type.clone(),
                });
            }
            if let Some(values) = &def.values {
                let value = String::from_utf8_lossy(field.value);
                let valid = match def.field_type {
                    FieldType::MultipleCharValue | FieldType::MultipleStringValue => value
                        .split(' ')
                        .filter(|part| !part.is_empty())
                        .all(|part| values.contains_key(part)),
                    _ => values.contains_key(value.as_ref()),
                };
                if !valid {
                    errors.push(ValidationError::InvalidEnumValue {
                        tag: field.tag,
                        name: def.name.clone(),
                        value: value.into_owned(),
                    });
                }
            }
        }

        // Required fields. CheckSum(10) is consumed by the decoder and
        // never appears among the parsed fields, so it is skipped here.
        for (tag, name) in &scope.required {
            if *tag != 10 && !occurrences.contains_key(tag) {
                errors.push(ValidationError::MissingRequiredField {
                    tag: *tag,
                    name: name.clone(),
                });
            }
        }

        // Repeating groups: count vs delimiter occurrences, entry ordering.
        for group in &scope.groups {
            self.validate_group(group, &fields, &occurrences, &mut errors);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn validate_group(
        &self,
        group: &GroupCheck,
        fields: &[&ironfix_core::field::FieldRef<'_>],
        occurrences: &HashMap<u32, u64>,
        errors: &mut Vec<ValidationError>,
    ) {
        let count_occurrences = occurrences.get(&group.count_tag).copied().unwrap_or(0);
        if count_occurrences == 0 {
            if group.required {
                errors.push(ValidationError::MissingRequiredGroup {
                    count_tag: group.count_tag,
                    name: group.name.clone(),
                });
            }
            return;
        }

        // Sum the declared counts across all occurrences of the count tag
        // (nested repetition makes the count tag itself repeat); the total
        // must match the total delimiter occurrences.
        let mut declared: u64 = 0;
        for (index, field) in fields.iter().enumerate() {
            if field.tag != group.count_tag {
                continue;
            }
            let value = String::from_utf8_lossy(field.value);
            let Ok(count) = value.parse::<u64>() else {
                errors.push(ValidationError::InvalidGroupCount {
                    tag: group.count_tag,
                    name: group.name.clone(),
                    value: value.into_owned(),
                });
                return;
            };
            declared += count;

            // A non-empty group's first entry must start immediately after
            // the count field with the delimiter tag.
            if count > 0
                && let Some(next) = fields.get(index + 1)
                && next.tag != group.delimiter_tag
            {
                errors.push(ValidationError::GroupDelimiterMismatch {
                    count_tag: group.count_tag,
                    name: group.name.clone(),
                    expected: group.delimiter_tag,
                    found: next.tag,
                });
            }
        }

        let actual = occurrences.get(&group.delimiter_tag).copied().unwrap_or(0);
        if declared != actual {
            errors.push(ValidationError::GroupCountMismatch {
                count_tag: group.count_tag,
                name: group.name.clone(),
                declared,
                actual,
                delimiter_tag: group.delimiter_tag,
            });
        }
    }

    /// Collects every tag reachable for the message: header, trailer,
    /// body fields, components (recursively), and repeating groups.
    fn collect_scope(&self, msg_def: &MessageDef) -> Scope {
        let mut scope = Scope::default();
        let mut visited = HashSet::new();

        for field in &self.dict.header {
            scope.add_field(field.tag, &field.name, field.required);
        }
        for group in &self.dict.header_groups {
            self.add_group(&mut scope, group, group.required, &mut visited);
        }
        for field in &self.dict.trailer {
            scope.add_field(field.tag, &field.name, field.required);
        }
        for group in &self.dict.trailer_groups {
            self.add_group(&mut scope, group, group.required, &mut visited);
        }

        for field in &msg_def.fields {
            scope.add_field(field.tag, &field.name, field.required);
        }
        for group in &msg_def.groups {
            self.add_group(&mut scope, group, group.required, &mut visited);
        }
        for component in &msg_def.components {
            self.add_component(&mut scope, component, true, &mut visited);
        }

        scope
    }

    /// Adds a group's count tag and (recursively) its member tags.
    ///
    /// Member fields are allowed but never required at message level:
    /// their requiredness applies within each entry, which is not
    /// validated per-entry.
    fn add_group(
        &self,
        scope: &mut Scope,
        group: &GroupDef,
        required: bool,
        visited: &mut HashSet<String>,
    ) {
        scope.allowed.insert(group.count_tag);
        scope.groups.push(GroupCheck {
            count_tag: group.count_tag,
            name: group.name.clone(),
            delimiter_tag: group.delimiter_tag,
            required,
        });
        for field in &group.fields {
            scope.allowed.insert(field.tag);
        }
        for nested in &group.groups {
            self.add_group(scope, nested, false, visited);
        }
        for component in &group.components {
            self.add_component(scope, component, false, visited);
        }
    }

    /// Expands a component reference into the scope.
    ///
    /// `top_level` is true only for components referenced directly by the
    /// message body; only there can a component's required fields make the
    /// message invalid when absent.
    fn add_component(
        &self,
        scope: &mut Scope,
        name: &str,
        top_level: bool,
        visited: &mut HashSet<String>,
    ) {
        if !visited.insert(name.to_string()) {
            return;
        }
        let Some(component) = self.dict.get_component(name) else {
            return;
        };
        for field in &component.fields {
            scope.add_field(field.tag, &field.name, top_level && field.required);
        }
        for group in &component.groups {
            self.add_group(scope, group, top_level && group.required, visited);
        }
        for nested in &component.components {
            self.add_component(scope, nested, false, visited);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::Dictionary;
    use ironfix_tagvalue::Decoder;

    const SOH: char = '\x01';

    fn build(fields: &[&str]) -> String {
        let mut msg = String::new();
        for field in fields {
            msg.push_str(field);
            msg.push(SOH);
        }
        msg
    }

    fn validate(fields: &[&str]) -> Result<(), Vec<ValidationError>> {
        let msg = build(fields);
        let mut decoder = Decoder::new(msg.as_bytes()).with_checksum_validation(false);
        let raw = decoder.decode().expect("test message decodes");
        Validator::new(Dictionary::fix44()).validate(&raw)
    }

    const HEADER: [&str; 7] = [
        "8=FIX.4.4",
        "9=100",
        "35=D",
        "49=SENDER",
        "56=TARGET",
        "34=1",
        "52=20260712-10:00:00",
    ];

    fn with_header<'a>(body: &[&'a str]) -> Vec<&'a str> {
        let mut fields: Vec<&str> = HEADER.to_vec();
        fields.extend_from_slice(body);
        fields.push("10=000");
        fields
    }

    #[test]
    fn test_valid_new_order_single() {
        let result = validate(&with_header(&[
            "11=ORDER-1",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
        ]));
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_missing_required_field() {
        // OrdType(40) omitted.
        let errors = validate(&with_header(&[
            "11=ORDER-1",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
        ]))
        .unwrap_err();
        assert!(errors.contains(&ValidationError::MissingRequiredField {
            tag: 40,
            name: "OrdType".to_string(),
        }));
    }

    #[test]
    fn test_invalid_enum_value() {
        let errors = validate(&with_header(&[
            "11=ORDER-1",
            "55=EURUSD",
            "54=X",
            "60=20260712-10:00:00",
            "40=1",
        ]))
        .unwrap_err();
        assert!(errors.contains(&ValidationError::InvalidEnumValue {
            tag: 54,
            name: "Side".to_string(),
            value: "X".to_string(),
        }));
    }

    #[test]
    fn test_unknown_tag() {
        let errors = validate(&with_header(&[
            "11=ORDER-1",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
            "20000=zzz",
        ]))
        .unwrap_err();
        assert!(errors.contains(&ValidationError::UnknownTag { tag: 20000 }));
    }

    #[test]
    fn test_field_not_allowed_for_message() {
        // AvgPx(6) is defined in FIX 4.4 but not part of NewOrderSingle.
        let errors = validate(&with_header(&[
            "11=ORDER-1",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
            "6=1.5",
        ]))
        .unwrap_err();
        assert!(
            errors.contains(&ValidationError::FieldNotAllowedForMessage {
                tag: 6,
                msg_type: "D".to_string(),
            })
        );
    }

    #[test]
    fn test_valid_group() {
        // Parties: NoPartyIDs(453)=2, each entry starting with PartyID(448).
        let result = validate(&with_header(&[
            "11=ORDER-1",
            "453=2",
            "448=BROKER-A",
            "447=D",
            "452=1",
            "448=BROKER-B",
            "447=D",
            "452=1",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
        ]));
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_group_count_mismatch() {
        let errors = validate(&with_header(&[
            "11=ORDER-1",
            "453=2",
            "448=BROKER-A",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
        ]))
        .unwrap_err();
        assert!(errors.contains(&ValidationError::GroupCountMismatch {
            count_tag: 453,
            name: "NoPartyIDs".to_string(),
            declared: 2,
            actual: 1,
            delimiter_tag: 448,
        }));
    }

    #[test]
    fn test_group_delimiter_mismatch() {
        // Entry starts with PartyRole(452) instead of PartyID(448).
        let errors = validate(&with_header(&[
            "11=ORDER-1",
            "453=1",
            "452=1",
            "448=BROKER-A",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
        ]))
        .unwrap_err();
        assert!(errors.contains(&ValidationError::GroupDelimiterMismatch {
            count_tag: 453,
            name: "NoPartyIDs".to_string(),
            expected: 448,
            found: 452,
        }));
    }

    #[test]
    fn test_invalid_group_count_value() {
        let errors = validate(&with_header(&[
            "11=ORDER-1",
            "453=abc",
            "448=BROKER-A",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
        ]))
        .unwrap_err();
        assert!(errors.contains(&ValidationError::InvalidGroupCount {
            tag: 453,
            name: "NoPartyIDs".to_string(),
            value: "abc".to_string(),
        }));
    }

    #[test]
    fn test_unknown_msg_type_is_rejected_by_dictionary() {
        // U-prefixed custom types decode fine but are not in FIX 4.4.
        let msg = build(&[
            "8=FIX.4.4",
            "9=100",
            "35=U9",
            "49=SENDER",
            "56=TARGET",
            "34=1",
            "52=20260712-10:00:00",
            "10=000",
        ]);
        let mut decoder = Decoder::new(msg.as_bytes()).with_checksum_validation(false);
        let raw = decoder.decode().expect("test message decodes");
        let errors = Validator::new(Dictionary::fix44())
            .validate(&raw)
            .unwrap_err();
        assert_eq!(
            errors,
            vec![ValidationError::UnknownMsgType {
                msg_type: "U9".to_string(),
            }]
        );
    }

    #[test]
    fn test_valid_heartbeat() {
        let result = validate(&[
            "8=FIX.4.4",
            "9=60",
            "35=0",
            "49=SENDER",
            "56=TARGET",
            "34=2",
            "52=20260712-10:00:00",
            "10=000",
        ]);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_missing_required_header_field() {
        // SendingTime(52) omitted.
        let errors = validate(&[
            "8=FIX.4.4",
            "9=60",
            "35=0",
            "49=SENDER",
            "56=TARGET",
            "34=2",
            "10=000",
        ])
        .unwrap_err();
        assert!(errors.contains(&ValidationError::MissingRequiredField {
            tag: 52,
            name: "SendingTime".to_string(),
        }));
    }
}
