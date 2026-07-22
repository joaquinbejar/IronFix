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
//! - every tag must be defined in the dictionary, and must be allowed at the
//!   place in the message where it appears
//! - required header, body, and trailer fields must be present
//! - a field's value must have the form its [`FieldType`] admits
//! - enumerated fields must carry a defined value
//! - no tag may repeat at the same structural level
//! - repeating groups must be *parseable*: the entries of a group follow its
//!   count field contiguously, each entry starts with the group's delimiter
//!   tag, no tag repeats inside one entry, and the number of entries actually
//!   present matches the declared count
//!
//! # How groups are checked
//!
//! Group structure is checked by walking the fields positionally rather than
//! by counting tag occurrences message-wide. Starting at a group's count
//! field, the validator consumes the run of fields that belong to that
//! group's member set, opening a new entry at every delimiter tag and
//! recursing into nested groups. The run ends at the first field that is not
//! a member, so entries detached from their count field are not silently
//! absorbed, and two different groups that happen to share a delimiter tag
//! can no longer be confused for one another.
//!
//! Notes:
//! - `CheckSum(10)` presence is not re-checked: the tag-value decoder
//!   already consumes and verifies it, so it never appears among the
//!   parsed fields.
//! - Required fields *inside* repeating group entries are still not
//!   validated per-entry; only the entry structure above is.
//! - The validator is a standalone, opt-in facility. It is not invoked by
//!   the codec or by the engine.

use crate::schema::{ComponentRef, Dictionary, FieldType, GroupDef, MessageDef};
use ironfix_core::message::RawMessage;
use std::collections::{HashMap, HashSet};

/// Maximum group/component nesting the validator will expand.
///
/// A [`Dictionary`] produced by the loader is a DAG of bounded depth, but one
/// built by hand or deserialised from an untrusted document need not be, so
/// the expansion carries its own ceiling.
pub const MAX_SCOPE_DEPTH: usize = 32;

/// Maximum number of groups and components expanded for a single message.
///
/// Bounds the total work of expanding a pathological schema, independently of
/// [`MAX_SCOPE_DEPTH`].
pub const MAX_SCOPE_NODES: usize = 4096;

/// A single validation failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
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
    /// A field's value does not have the form its data type requires.
    #[error("value `{value}` is not a valid {field_type:?} for field {name}({tag})")]
    InvalidFieldFormat {
        /// Field tag.
        tag: u32,
        /// Field name.
        name: String,
        /// The offending value.
        value: String,
        /// The type the dictionary declares for this field.
        field_type: FieldType,
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
    /// The same tag appears twice at the message level.
    #[error("tag {name}({tag}) appears more than once in the message")]
    DuplicateTag {
        /// The repeated tag.
        tag: u32,
        /// Field name.
        name: String,
    },
    /// The same tag appears twice inside one repeating group entry.
    #[error("tag {name}({tag}) appears more than once in an entry of group {group}({count_tag})")]
    RepeatedTagInGroupEntry {
        /// Count field tag (NumInGroup) of the group.
        count_tag: u32,
        /// Group name.
        group: String,
        /// The repeated tag.
        tag: u32,
        /// Field name.
        name: String,
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
    /// The declared group count does not match the entries actually present.
    #[error(
        "group {name}({count_tag}) declares {declared} entries but {actual} entries follow it, each led by delimiter tag {delimiter_tag}"
    )]
    GroupCountMismatch {
        /// Count field tag (NumInGroup).
        count_tag: u32,
        /// Group name.
        name: String,
        /// Declared entry count.
        declared: u64,
        /// Entries actually found following the count field.
        actual: u64,
        /// Delimiter tag expected to start each entry.
        delimiter_tag: u32,
    },
    /// A group entry does not start with the group's delimiter tag.
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
        /// Tag actually found where an entry should have started.
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
    /// The message schema references a component the dictionary does not define.
    ///
    /// Dictionaries produced by the loader cannot contain a dangling
    /// reference; this reports one in a dictionary assembled by other means.
    #[error("message schema references undefined component `{name}`")]
    UnknownComponent {
        /// Name of the missing component.
        name: String,
    },
    /// The schema nests groups or components past the validator's ceiling.
    #[error("schema for `{name}` nests deeper than the validator's limit of {limit}")]
    SchemaTooDeep {
        /// Name of the group or component at which the ceiling was reached.
        name: String,
        /// The ceiling that was exceeded.
        limit: usize,
    },
    /// Expanding the schema for this message exceeded the validator's budget.
    #[error("schema expansion exceeded the validator's limit of {limit} nodes")]
    SchemaTooLarge {
        /// The ceiling that was exceeded.
        limit: usize,
    },
}

/// One structural level of a message: the message body itself, or the
/// members of a single repeating-group entry.
#[derive(Debug, Default)]
struct Level {
    /// Tags that may appear at this level, including group count tags.
    allowed: HashSet<u32>,
    /// Tags that must appear at this level, with their field names.
    required: Vec<(u32, String)>,
    /// Groups that may open at this level, keyed by count tag.
    groups: HashMap<u32, GroupNode>,
}

impl Level {
    fn add_field(&mut self, tag: u32, name: &str, required: bool) {
        self.allowed.insert(tag);
        if required {
            self.required.push((tag, name.to_string()));
        }
    }
}

/// A repeating group and the level formed by one of its entries.
#[derive(Debug)]
struct GroupNode {
    count_tag: u32,
    name: String,
    delimiter_tag: u32,
    required: bool,
    entry: Level,
}

/// Expands a [`MessageDef`] into the level tree the walker validates against.
struct ScopeBuilder<'d> {
    dict: &'d Dictionary,
    budget: usize,
    errors: Vec<ValidationError>,
}

impl<'d> ScopeBuilder<'d> {
    fn new(dict: &'d Dictionary) -> Self {
        Self {
            dict,
            budget: MAX_SCOPE_NODES,
            errors: Vec::new(),
        }
    }

    /// Charges one node against the budget and checks the depth ceiling.
    fn spend(&mut self, name: &str, depth: usize) -> bool {
        if depth > MAX_SCOPE_DEPTH {
            self.errors.push(ValidationError::SchemaTooDeep {
                name: name.to_string(),
                limit: MAX_SCOPE_DEPTH,
            });
            return false;
        }
        match self.budget.checked_sub(1) {
            Some(remaining) => {
                self.budget = remaining;
                true
            }
            None => {
                if !self.errors.contains(&ValidationError::SchemaTooLarge {
                    limit: MAX_SCOPE_NODES,
                }) {
                    self.errors.push(ValidationError::SchemaTooLarge {
                        limit: MAX_SCOPE_NODES,
                    });
                }
                false
            }
        }
    }

    /// Builds the message level: header, trailer, body fields, groups, and
    /// directly referenced components.
    fn build(&mut self, msg_def: &MessageDef) -> Level {
        let mut level = Level::default();
        let mut path = HashSet::new();

        for field in &self.dict.header {
            level.add_field(field.tag, &field.name, field.required);
        }
        for group in &self.dict.header_groups {
            self.add_group(&mut level, group, group.required, true, 0, &mut path);
        }
        for field in &self.dict.trailer {
            level.add_field(field.tag, &field.name, field.required);
        }
        for group in &self.dict.trailer_groups {
            self.add_group(&mut level, group, group.required, true, 0, &mut path);
        }

        for field in &msg_def.fields {
            level.add_field(field.tag, &field.name, field.required);
        }
        for group in &msg_def.groups {
            self.add_group(&mut level, group, group.required, true, 0, &mut path);
        }
        for component in &msg_def.components {
            self.add_component(&mut level, component, true, 0, &mut path);
        }

        level
    }

    /// Adds a group to `level` and builds the level formed by one entry.
    ///
    /// `collect_required` is false inside group entries: a member's required
    /// flag applies per entry, which is deliberately not validated.
    fn add_group(
        &mut self,
        level: &mut Level,
        group: &GroupDef,
        required: bool,
        collect_required: bool,
        depth: usize,
        path: &mut HashSet<String>,
    ) {
        if !self.spend(&group.name, depth) {
            return;
        }
        level.allowed.insert(group.count_tag);

        let mut entry = Level::default();
        entry.allowed.insert(group.delimiter_tag);
        for field in &group.fields {
            entry.allowed.insert(field.tag);
        }
        for nested in &group.groups {
            self.add_group(&mut entry, nested, nested.required, false, depth + 1, path);
        }
        for component in &group.components {
            self.add_component(&mut entry, component, false, depth + 1, path);
        }

        // A group already present at this level keeps its first expansion;
        // two groups sharing a count tag at one level is a schema defect,
        // not something to resolve here.
        level.groups.entry(group.count_tag).or_insert(GroupNode {
            count_tag: group.count_tag,
            name: group.name.clone(),
            delimiter_tag: group.delimiter_tag,
            required: required && collect_required,
            entry,
        });
    }

    /// Expands a component reference into `level`.
    ///
    /// `collect_required` says whether requiredness is meaningful where the
    /// reference sits; combined with the reference's own flag it gives the
    /// effective requiredness, so a component's required members can only
    /// make a message invalid when the reference that pulled it in was
    /// itself required.
    fn add_component(
        &mut self,
        level: &mut Level,
        reference: &ComponentRef,
        collect_required: bool,
        depth: usize,
        path: &mut HashSet<String>,
    ) {
        if !self.spend(&reference.name, depth) {
            return;
        }
        let Some(component) = self.dict.get_component(&reference.name) else {
            self.errors.push(ValidationError::UnknownComponent {
                name: reference.name.clone(),
            });
            return;
        };
        // A cycle can only reach here through a hand-built dictionary; the
        // loader rejects one. Expanding a component twice at different
        // places is legitimate, so the guard is per path, not global.
        if !path.insert(reference.name.clone()) {
            return;
        }

        let required = collect_required && reference.required;
        for field in &component.fields {
            level.add_field(field.tag, &field.name, required && field.required);
        }
        for group in &component.groups {
            self.add_group(level, group, group.required, required, depth + 1, path);
        }
        for nested in &component.components {
            self.add_component(level, nested, required, depth + 1, path);
        }

        path.remove(&reference.name);
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

        let mut builder = ScopeBuilder::new(self.dict);
        let level = builder.build(msg_def);
        let mut errors = builder.errors;

        let fields: Vec<_> = msg.fields().collect();

        // Value-level checks apply wherever a field sits.
        for field in &fields {
            self.check_value(field, &mut errors);
        }

        // Structural walk over the message level.
        let mut seen: HashSet<u32> = HashSet::new();
        let mut index = 0;
        while let Some(field) = fields.get(index) {
            let tag = field.tag;
            let Some(def) = self.dict.get_field(tag) else {
                // Already reported as UnknownTag by the value pass.
                index += 1;
                continue;
            };
            if !seen.insert(tag) {
                errors.push(ValidationError::DuplicateTag {
                    tag,
                    name: def.name.clone(),
                });
            }
            if let Some(group) = level.groups.get(&tag) {
                index = self.walk_group(&fields, index, group, &mut errors);
                continue;
            }
            if !level.allowed.contains(&tag) {
                errors.push(ValidationError::FieldNotAllowedForMessage {
                    tag,
                    msg_type: msg_type.clone(),
                });
            }
            index += 1;
        }

        // Required fields. CheckSum(10) is consumed by the decoder and never
        // appears among the parsed fields, so it is skipped here.
        for (tag, name) in &level.required {
            if *tag != 10 && !seen.contains(tag) {
                errors.push(ValidationError::MissingRequiredField {
                    tag: *tag,
                    name: name.clone(),
                });
            }
        }

        for group in level.groups.values() {
            if group.required && !seen.contains(&group.count_tag) {
                errors.push(ValidationError::MissingRequiredGroup {
                    count_tag: group.count_tag,
                    name: group.name.clone(),
                });
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Checks that a field is defined, well-formed for its type, and — when
    /// enumerated — carries a defined value.
    fn check_value(
        &self,
        field: &ironfix_core::field::FieldRef<'_>,
        errors: &mut Vec<ValidationError>,
    ) {
        let Some(def) = self.dict.get_field(field.tag) else {
            errors.push(ValidationError::UnknownTag { tag: field.tag });
            return;
        };
        let value = String::from_utf8_lossy(field.value);
        if !def.field_type.is_valid_value(&value) {
            errors.push(ValidationError::InvalidFieldFormat {
                tag: field.tag,
                name: def.name.clone(),
                value: value.into_owned(),
                field_type: def.field_type,
            });
            return;
        }
        let Some(values) = &def.values else {
            return;
        };
        // A multi-value field carries a space-separated list, and every
        // token has to be in the enumeration. The form check above already
        // guarantees the tokens are non-empty.
        let valid = if def.field_type.is_multi_value() {
            value.split(' ').all(|token| values.contains_key(token))
        } else {
            values.contains_key(value.as_ref())
        };
        if !valid {
            errors.push(ValidationError::InvalidEnumValue {
                tag: field.tag,
                name: def.name.clone(),
                value: value.into_owned(),
            });
        }
    }

    /// Walks one group instance, starting at its count field.
    ///
    /// Returns the index of the first field after the group.
    fn walk_group(
        &self,
        fields: &[&ironfix_core::field::FieldRef<'_>],
        index: usize,
        group: &GroupNode,
        errors: &mut Vec<ValidationError>,
    ) -> usize {
        let Some(count_field) = fields.get(index) else {
            return index;
        };
        let count_value = String::from_utf8_lossy(count_field.value);
        let declared = match count_value.parse::<u64>() {
            Ok(declared) => Some(declared),
            Err(_) => {
                errors.push(ValidationError::InvalidGroupCount {
                    tag: group.count_tag,
                    name: group.name.clone(),
                    value: count_value.into_owned(),
                });
                None
            }
        };

        let mut cursor = index + 1;
        let mut entries: u64 = 0;
        let mut unparseable = false;
        let mut seen_in_entry: HashSet<u32> = HashSet::new();

        while let Some(field) = fields.get(cursor) {
            let tag = field.tag;
            if tag == group.delimiter_tag {
                let Some(next) = entries.checked_add(1) else {
                    break;
                };
                entries = next;
                seen_in_entry.clear();
                seen_in_entry.insert(tag);
                cursor += 1;
                continue;
            }
            if !group.entry.allowed.contains(&tag) {
                // First field that is not a member of this group: the group
                // ends here, and whatever follows belongs to the outer level.
                break;
            }
            if entries == 0 {
                // Members appear before any delimiter, so the first entry is
                // not delimiter-led and the group cannot be split into
                // entries unambiguously.
                errors.push(ValidationError::GroupDelimiterMismatch {
                    count_tag: group.count_tag,
                    name: group.name.clone(),
                    expected: group.delimiter_tag,
                    found: tag,
                });
                unparseable = true;
                entries = 1;
                seen_in_entry.clear();
            }
            if !seen_in_entry.insert(tag) {
                errors.push(ValidationError::RepeatedTagInGroupEntry {
                    count_tag: group.count_tag,
                    group: group.name.clone(),
                    tag,
                    name: self
                        .dict
                        .get_field(tag)
                        .map_or_else(String::new, |def| def.name.clone()),
                });
                unparseable = true;
            }
            cursor = match group.entry.groups.get(&tag) {
                Some(nested) => self.walk_group(fields, cursor, nested, errors),
                None => cursor + 1,
            };
        }

        if let Some(declared) = declared
            && !unparseable
            && declared != entries
        {
            errors.push(ValidationError::GroupCountMismatch {
                count_tag: group.count_tag,
                name: group.name.clone(),
                declared,
                actual: entries,
                delimiter_tag: group.delimiter_tag,
            });
        }

        cursor
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // `FieldRef` is ambiguous across the workspace, so the schema one is
    // always spelled with a qualifier here; `ironfix_core::field::FieldRef`
    // appears in full above.
    use crate::schema::FieldRef as SchemaFieldRef;
    use crate::schema::{ComponentDef, Dictionary, FieldDef, MessageCategory};
    use ironfix_tagvalue::Decoder;
    use std::fmt::Debug;

    const SOH: char = '\x01';

    /// Unwraps a `Result` with test context instead of `.unwrap()`.
    #[track_caller]
    fn ok<T, E: Debug>(result: Result<T, E>, what: &str) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("{what}: {err:?}"),
        }
    }

    /// Returns the errors a validation is expected to produce.
    #[track_caller]
    fn errors(result: Result<(), Vec<ValidationError>>) -> Vec<ValidationError> {
        match result {
            Ok(()) => panic!("expected the message to be rejected, but it validated"),
            Err(errors) => errors,
        }
    }

    #[track_caller]
    fn fix44() -> &'static Dictionary {
        ok(Dictionary::fix44(), "embedded FIX 4.4 dictionary loads")
    }

    /// Builds a message, recomputing BodyLength (9) from the actual body so the
    /// decoder's declared-vs-actual length check passes.
    fn build(fields: &[&str]) -> String {
        let begin = fields
            .iter()
            .find(|f| f.starts_with("8="))
            .copied()
            .unwrap_or("8=FIX.4.4");
        let trailer = fields
            .iter()
            .find(|f| f.starts_with("10="))
            .copied()
            .unwrap_or("10=000");

        let mut body = String::new();
        for field in fields
            .iter()
            .filter(|f| !f.starts_with("8=") && !f.starts_with("9=") && !f.starts_with("10="))
        {
            body.push_str(field);
            body.push(SOH);
        }

        format!(
            "{begin}{SOH}9={}{SOH}{body}{trailer}{SOH}",
            body.len(),
            SOH = SOH
        )
    }

    #[track_caller]
    fn validate_with(dict: &Dictionary, fields: &[&str]) -> Result<(), Vec<ValidationError>> {
        let msg = build(fields);
        let mut decoder = Decoder::new(msg.as_bytes()).with_checksum_validation(false);
        let raw = ok(decoder.decode(), "test message decodes");
        Validator::new(dict).validate(&raw)
    }

    #[track_caller]
    fn validate(fields: &[&str]) -> Result<(), Vec<ValidationError>> {
        validate_with(fix44(), fields)
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
    fn test_validate_new_order_single_valid_passes() {
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
    fn test_validate_missing_required_field_is_reported() {
        // OrdType(40) omitted.
        let found = errors(validate(&with_header(&[
            "11=ORDER-1",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
        ])));
        assert!(found.contains(&ValidationError::MissingRequiredField {
            tag: 40,
            name: "OrdType".to_string(),
        }));
    }

    #[test]
    fn test_validate_invalid_enum_value_is_reported() {
        let found = errors(validate(&with_header(&[
            "11=ORDER-1",
            "55=EURUSD",
            "54=X",
            "60=20260712-10:00:00",
            "40=1",
        ])));
        assert!(found.contains(&ValidationError::InvalidEnumValue {
            tag: 54,
            name: "Side".to_string(),
            value: "X".to_string(),
        }));
    }

    #[test]
    fn test_validate_multiple_value_string_accepts_a_list_of_defined_tokens() {
        // ExecInst(18) is MULTIPLEVALUESTRING in the vendored FIX 4.4
        // dictionary: `1 2` is two defined tokens and must pass.
        let result = validate(&with_header(&[
            "11=ORDER-1",
            "18=1 2",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
        ]));
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_multiple_value_string_rejects_an_undefined_token() {
        // `T` is not among the ExecInst values the vendored dictionary
        // defines, so the list is rejected even though `1` is valid.
        let found = errors(validate(&with_header(&[
            "11=ORDER-1",
            "18=1 T",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
        ])));
        assert!(found.contains(&ValidationError::InvalidEnumValue {
            tag: 18,
            name: "ExecInst".to_string(),
            value: "1 T".to_string(),
        }));
    }

    #[test]
    fn test_validate_multiple_value_string_rejects_an_empty_token() {
        let found = errors(validate(&with_header(&[
            "11=ORDER-1",
            "18=1  2",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
        ])));
        assert!(found.contains(&ValidationError::InvalidFieldFormat {
            tag: 18,
            name: "ExecInst".to_string(),
            value: "1  2".to_string(),
            field_type: FieldType::MultipleStringValue,
        }));
    }

    #[test]
    fn test_validate_unknown_tag_is_reported() {
        let found = errors(validate(&with_header(&[
            "11=ORDER-1",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
            "20000=zzz",
        ])));
        assert!(found.contains(&ValidationError::UnknownTag { tag: 20000 }));
    }

    #[test]
    fn test_validate_field_not_allowed_for_message_is_reported() {
        // AvgPx(6) is defined in FIX 4.4 but not part of NewOrderSingle.
        let found = errors(validate(&with_header(&[
            "11=ORDER-1",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
            "6=1.5",
        ])));
        assert!(found.contains(&ValidationError::FieldNotAllowedForMessage {
            tag: 6,
            msg_type: "D".to_string(),
        }));
    }

    #[test]
    fn test_validate_group_member_outside_its_group_is_not_allowed() {
        // PartyID(448) only exists inside the NoPartyIDs group; on its own it
        // is not a NewOrderSingle field.
        let found = errors(validate(&with_header(&[
            "11=ORDER-1",
            "448=BROKER-A",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
        ])));
        assert!(found.contains(&ValidationError::FieldNotAllowedForMessage {
            tag: 448,
            msg_type: "D".to_string(),
        }));
    }

    #[test]
    fn test_validate_duplicate_tag_at_message_level_is_reported() {
        let found = errors(validate(&with_header(&[
            "11=ORDER-1",
            "55=EURUSD",
            "55=GBPUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
        ])));
        assert!(found.contains(&ValidationError::DuplicateTag {
            tag: 55,
            name: "Symbol".to_string(),
        }));
    }

    #[test]
    fn test_validate_malformed_value_is_reported_for_its_type() {
        // OrderQty(38) is a QTY: `1..2` has no decimal form.
        let found = errors(validate(&with_header(&[
            "11=ORDER-1",
            "55=EURUSD",
            "54=1",
            "38=1..2",
            "60=20260712-10:00:00",
            "40=1",
        ])));
        assert!(found.contains(&ValidationError::InvalidFieldFormat {
            tag: 38,
            name: "OrderQty".to_string(),
            value: "1..2".to_string(),
            field_type: FieldType::Qty,
        }));
    }

    #[test]
    fn test_validate_malformed_timestamp_is_reported() {
        let found = errors(validate(&with_header(&[
            "11=ORDER-1",
            "55=EURUSD",
            "54=1",
            "60=not-a-time",
            "40=1",
        ])));
        assert!(found.contains(&ValidationError::InvalidFieldFormat {
            tag: 60,
            name: "TransactTime".to_string(),
            value: "not-a-time".to_string(),
            field_type: FieldType::UtcTimestamp,
        }));
    }

    #[test]
    fn test_validate_group_valid_entries_pass() {
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
    fn test_validate_group_count_mismatch_is_reported() {
        let found = errors(validate(&with_header(&[
            "11=ORDER-1",
            "453=2",
            "448=BROKER-A",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
        ])));
        assert!(found.contains(&ValidationError::GroupCountMismatch {
            count_tag: 453,
            name: "NoPartyIDs".to_string(),
            declared: 2,
            actual: 1,
            delimiter_tag: 448,
        }));
    }

    #[test]
    fn test_validate_group_second_entry_not_delimiter_led_is_rejected() {
        // 453=2|448=A|447=D|447=D|448=B: the repeated PartyIDSource(447)
        // means the second entry never starts, so the group is unparseable
        // even though two 448s are present and the count says two.
        let found = errors(validate(&with_header(&[
            "11=ORDER-1",
            "453=2",
            "448=BROKER-A",
            "447=D",
            "447=D",
            "448=BROKER-B",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
        ])));
        assert!(found.contains(&ValidationError::RepeatedTagInGroupEntry {
            count_tag: 453,
            group: "NoPartyIDs".to_string(),
            tag: 447,
            name: "PartyIDSource".to_string(),
        }));
    }

    #[test]
    fn test_validate_group_detached_entry_is_rejected() {
        // The second entry is separated from the group by Symbol(55), so it
        // is not part of the group run: one entry found, two declared, and
        // the stray 448 is not a message-level field.
        let found = errors(validate(&with_header(&[
            "11=ORDER-1",
            "453=2",
            "448=BROKER-A",
            "55=EURUSD",
            "448=BROKER-B",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
        ])));
        assert!(found.contains(&ValidationError::GroupCountMismatch {
            count_tag: 453,
            name: "NoPartyIDs".to_string(),
            declared: 2,
            actual: 1,
            delimiter_tag: 448,
        }));
        assert!(found.contains(&ValidationError::FieldNotAllowedForMessage {
            tag: 448,
            msg_type: "D".to_string(),
        }));
    }

    #[test]
    fn test_validate_group_delimiter_mismatch_is_reported() {
        // Entry starts with PartyRole(452) instead of PartyID(448).
        let found = errors(validate(&with_header(&[
            "11=ORDER-1",
            "453=1",
            "452=1",
            "448=BROKER-A",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
        ])));
        assert!(found.contains(&ValidationError::GroupDelimiterMismatch {
            count_tag: 453,
            name: "NoPartyIDs".to_string(),
            expected: 448,
            found: 452,
        }));
    }

    #[test]
    fn test_validate_group_count_value_not_a_number_is_reported() {
        let found = errors(validate(&with_header(&[
            "11=ORDER-1",
            "453=abc",
            "448=BROKER-A",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
        ])));
        assert!(found.contains(&ValidationError::InvalidGroupCount {
            tag: 453,
            name: "NoPartyIDs".to_string(),
            value: "abc".to_string(),
        }));
    }

    /// Builds a dialect whose message carries two distinct groups that share
    /// a delimiter tag.
    fn dialect_with_two_groups_sharing_a_delimiter() -> Dictionary {
        let mut dict = dialect_with_optional_component();
        for (tag, name, field_type) in [
            (100, "NoFirst", FieldType::NumInGroup),
            (101, "NoSecond", FieldType::NumInGroup),
            (200, "SharedDelimiter", FieldType::String),
        ] {
            dict.add_field(FieldDef::new(tag, name, field_type));
        }
        let member = SchemaFieldRef {
            tag: 200,
            name: "SharedDelimiter".to_string(),
            required: true,
        };
        let group = |count_tag: u32, name: &str| GroupDef {
            count_tag,
            name: name.to_string(),
            delimiter_tag: 200,
            fields: vec![member.clone()],
            groups: Vec::new(),
            components: Vec::new(),
            required: false,
        };
        dict.add_message(MessageDef {
            msg_type: "U4".to_string(),
            name: "TwoGroups".to_string(),
            category: MessageCategory::App,
            fields: Vec::new(),
            groups: vec![group(100, "NoFirst"), group(101, "NoSecond")],
            components: Vec::new(),
        });
        dict
    }

    #[test]
    fn test_validate_groups_sharing_a_delimiter_are_counted_separately() {
        // Each group's entries are counted from its own count field, so one
        // group's entries can no longer be credited to the other.
        let dict = dialect_with_two_groups_sharing_a_delimiter();
        let result = validate_with(
            &dict,
            &[
                "8=FIX.4.4",
                "9=100",
                "35=U4",
                "49=SENDER",
                "56=TARGET",
                "34=1",
                "100=1",
                "200=FIRST",
                "101=2",
                "200=SECOND-A",
                "200=SECOND-B",
                "10=000",
            ],
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_groups_sharing_a_delimiter_still_catch_their_own_mismatch() {
        let dict = dialect_with_two_groups_sharing_a_delimiter();
        let found = errors(validate_with(
            &dict,
            &[
                "8=FIX.4.4",
                "9=100",
                "35=U4",
                "49=SENDER",
                "56=TARGET",
                "34=1",
                "100=2",
                "200=FIRST",
                "101=1",
                "200=SECOND",
                "10=000",
            ],
        ));
        assert_eq!(
            found,
            vec![ValidationError::GroupCountMismatch {
                count_tag: 100,
                name: "NoFirst".to_string(),
                declared: 2,
                actual: 1,
                delimiter_tag: 200,
            }]
        );
    }

    #[test]
    fn test_validate_nested_group_entries_pass() {
        // PtysSubGrp: NoPartySubIDs(802) nests inside a NoPartyIDs entry.
        let result = validate(&with_header(&[
            "11=ORDER-1",
            "453=1",
            "448=BROKER-A",
            "447=D",
            "452=1",
            "802=2",
            "523=SUB-1",
            "803=1",
            "523=SUB-2",
            "803=2",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
        ]));
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_nested_group_count_mismatch_is_reported() {
        let found = errors(validate(&with_header(&[
            "11=ORDER-1",
            "453=1",
            "448=BROKER-A",
            "802=2",
            "523=SUB-1",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
        ])));
        assert!(found.contains(&ValidationError::GroupCountMismatch {
            count_tag: 802,
            name: "NoPartySubIDs".to_string(),
            declared: 2,
            actual: 1,
            delimiter_tag: 523,
        }));
    }

    #[test]
    fn test_validate_missing_required_group_is_reported() {
        // MarketDataRequest(V) requires NoMDEntryTypes(267) and
        // NoRelatedSym(146); omitting both must name both groups.
        let found = errors(validate(&[
            "8=FIX.4.4",
            "9=100",
            "35=V",
            "49=SENDER",
            "56=TARGET",
            "34=1",
            "52=20260712-10:00:00",
            "262=REQ-1",
            "263=1",
            "264=1",
            "10=000",
        ]));
        assert!(found.contains(&ValidationError::MissingRequiredGroup {
            count_tag: 267,
            name: "NoMDEntryTypes".to_string(),
        }));
        assert!(found.contains(&ValidationError::MissingRequiredGroup {
            count_tag: 146,
            name: "NoRelatedSym".to_string(),
        }));
    }

    #[test]
    fn test_scope_expansion_fits_every_fix44_message() {
        // The ceilings must accommodate the real dictionary: no message in
        // FIX 4.4 may hit the depth or budget limit, or its own schema would
        // be reported as an error against every message of that type.
        let dict = fix44();
        for msg_def in dict.messages() {
            let mut builder = ScopeBuilder::new(dict);
            let _ = builder.build(msg_def);
            assert_eq!(
                builder.errors,
                Vec::new(),
                "expanding {} exhausted a validator ceiling",
                msg_def.name
            );
        }
    }

    #[test]
    fn test_validate_unknown_msg_type_is_rejected() {
        // U-prefixed custom types decode fine but are not in FIX 4.4.
        let found = errors(validate(&[
            "8=FIX.4.4",
            "9=100",
            "35=U9",
            "49=SENDER",
            "56=TARGET",
            "34=1",
            "52=20260712-10:00:00",
            "10=000",
        ]));
        assert_eq!(
            found,
            vec![ValidationError::UnknownMsgType {
                msg_type: "U9".to_string(),
            }]
        );
    }

    #[test]
    fn test_validate_heartbeat_valid_passes() {
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
    fn test_validate_missing_required_header_field_is_reported() {
        // SendingTime(52) omitted.
        let found = errors(validate(&[
            "8=FIX.4.4",
            "9=60",
            "35=0",
            "49=SENDER",
            "56=TARGET",
            "34=2",
            "10=000",
        ]));
        assert!(found.contains(&ValidationError::MissingRequiredField {
            tag: 52,
            name: "SendingTime".to_string(),
        }));
    }

    /// Builds a dialect whose message carries one required and one optional
    /// component, each with a required member.
    fn dialect_with_optional_component() -> Dictionary {
        let mut dict = Dictionary::new(crate::schema::Version::Fix44);
        for (tag, name, field_type) in [
            (8, "BeginString", FieldType::String),
            (9, "BodyLength", FieldType::Length),
            (10, "CheckSum", FieldType::String),
            (34, "MsgSeqNum", FieldType::SeqNum),
            (35, "MsgType", FieldType::String),
            (49, "SenderCompID", FieldType::String),
            (56, "TargetCompID", FieldType::String),
            (52, "SendingTime", FieldType::UtcTimestamp),
            (55, "Symbol", FieldType::String),
            (44, "Price", FieldType::Price),
        ] {
            dict.add_field(FieldDef::new(tag, name, field_type));
        }
        let required = |tag: u32, name: &str| SchemaFieldRef {
            tag,
            name: name.to_string(),
            required: true,
        };
        dict.header = vec![
            required(8, "BeginString"),
            required(9, "BodyLength"),
            required(35, "MsgType"),
            required(49, "SenderCompID"),
            required(56, "TargetCompID"),
            required(34, "MsgSeqNum"),
        ];
        dict.trailer = vec![required(10, "CheckSum")];
        dict.add_component(ComponentDef {
            name: "Instrument".to_string(),
            fields: vec![required(55, "Symbol")],
            groups: Vec::new(),
            components: Vec::new(),
        });
        dict.add_component(ComponentDef {
            name: "PriceBlock".to_string(),
            fields: vec![required(44, "Price")],
            groups: Vec::new(),
            components: Vec::new(),
        });
        dict.add_message(MessageDef {
            msg_type: "U1".to_string(),
            name: "Ping".to_string(),
            category: MessageCategory::App,
            fields: Vec::new(),
            groups: Vec::new(),
            components: vec![
                ComponentRef::new("Instrument", true),
                ComponentRef::new("PriceBlock", false),
            ],
        });
        dict
    }

    #[test]
    fn test_validate_optional_component_members_are_not_required() {
        // PriceBlock is referenced with required='N', so its required
        // member Price(44) must not be demanded of every message.
        let dict = dialect_with_optional_component();
        let result = validate_with(
            &dict,
            &[
                "8=FIX.4.4",
                "9=100",
                "35=U1",
                "49=SENDER",
                "56=TARGET",
                "34=1",
                "55=EURUSD",
                "10=000",
            ],
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_validate_required_component_members_are_still_required() {
        let dict = dialect_with_optional_component();
        let found = errors(validate_with(
            &dict,
            &[
                "8=FIX.4.4",
                "9=100",
                "35=U1",
                "49=SENDER",
                "56=TARGET",
                "34=1",
                "44=1.25",
                "10=000",
            ],
        ));
        assert!(found.contains(&ValidationError::MissingRequiredField {
            tag: 55,
            name: "Symbol".to_string(),
        }));
    }

    #[test]
    fn test_validate_undefined_component_reference_is_reported() {
        let mut dict = dialect_with_optional_component();
        dict.add_message(MessageDef {
            msg_type: "U2".to_string(),
            name: "Pong".to_string(),
            category: MessageCategory::App,
            fields: Vec::new(),
            groups: Vec::new(),
            components: vec![ComponentRef::new("Nope", true)],
        });
        let found = errors(validate_with(
            &dict,
            &[
                "8=FIX.4.4",
                "9=100",
                "35=U2",
                "49=SENDER",
                "56=TARGET",
                "34=1",
                "10=000",
            ],
        ));
        assert!(found.contains(&ValidationError::UnknownComponent {
            name: "Nope".to_string(),
        }));
    }

    /// Validates a bare `U3` message against `dict`.
    #[track_caller]
    fn validate_u3(dict: &Dictionary) -> Result<(), Vec<ValidationError>> {
        validate_with(
            dict,
            &[
                "8=FIX.4.4",
                "9=100",
                "35=U3",
                "49=SENDER",
                "56=TARGET",
                "34=1",
                "10=000",
            ],
        )
    }

    #[test]
    fn test_validate_component_chain_past_the_depth_ceiling_is_reported() {
        // The loader would reject a chain this long, but a dictionary built
        // by hand can hold one: the expansion stops at the ceiling and says
        // so instead of recursing.
        let mut dict = dialect_with_optional_component();
        let links = MAX_SCOPE_DEPTH + 10;
        for index in 0..links {
            dict.add_component(ComponentDef {
                name: format!("C{index}"),
                fields: Vec::new(),
                groups: Vec::new(),
                components: vec![ComponentRef::new(format!("C{}", index + 1), true)],
            });
        }
        dict.add_component(ComponentDef {
            name: format!("C{links}"),
            fields: Vec::new(),
            groups: Vec::new(),
            components: Vec::new(),
        });
        dict.add_message(MessageDef {
            msg_type: "U3".to_string(),
            name: "Deep".to_string(),
            category: MessageCategory::App,
            fields: Vec::new(),
            groups: Vec::new(),
            components: vec![ComponentRef::new("C0", true)],
        });

        let found = errors(validate_u3(&dict));
        assert!(
            found.iter().any(|error| matches!(
                error,
                ValidationError::SchemaTooDeep {
                    limit: MAX_SCOPE_DEPTH,
                    ..
                }
            )),
            "expected a depth ceiling report, got {found:?}"
        );
    }

    #[test]
    fn test_validate_schema_past_the_node_budget_is_reported() {
        let mut dict = dialect_with_optional_component();
        dict.add_message(MessageDef {
            msg_type: "U3".to_string(),
            name: "Wide".to_string(),
            category: MessageCategory::App,
            fields: Vec::new(),
            groups: Vec::new(),
            components: (0..=MAX_SCOPE_NODES)
                .map(|_| ComponentRef::new("Instrument", false))
                .collect(),
        });

        let found = errors(validate_u3(&dict));
        assert!(
            found.contains(&ValidationError::SchemaTooLarge {
                limit: MAX_SCOPE_NODES,
            }),
            "expected a node budget report, got {found:?}"
        );
    }

    #[test]
    fn test_validate_cyclic_component_schema_terminates() {
        // The loader rejects a cycle, but a dictionary assembled by hand can
        // still hold one: expansion must terminate rather than recurse
        // forever.
        let mut dict = dialect_with_optional_component();
        dict.add_component(ComponentDef {
            name: "Loop".to_string(),
            fields: Vec::new(),
            groups: Vec::new(),
            components: vec![ComponentRef::new("Loop", true)],
        });
        dict.add_message(MessageDef {
            msg_type: "U3".to_string(),
            name: "Looping".to_string(),
            category: MessageCategory::App,
            fields: Vec::new(),
            groups: Vec::new(),
            components: vec![ComponentRef::new("Loop", true)],
        });
        let result = validate_with(
            &dict,
            &[
                "8=FIX.4.4",
                "9=100",
                "35=U3",
                "49=SENDER",
                "56=TARGET",
                "34=1",
                "10=000",
            ],
        );
        assert_eq!(result, Ok(()));
    }
}
