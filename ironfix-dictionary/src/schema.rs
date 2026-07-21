/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! Schema definitions for FIX dictionaries.
//!
//! This module defines the structures that represent FIX protocol specifications:
//! - [`FieldDef`]: Field definitions with tag, name, and type
//! - [`MessageDef`]: Message definitions with required/optional fields
//! - [`ComponentDef`]: Reusable component definitions
//! - [`ComponentRef`]: A reference to a component, with its own required flag
//! - [`GroupDef`]: Repeating group definitions
//! - [`Dictionary`]: Complete FIX version dictionary
//!
//! [`FieldType`] carries both the QuickFIX XML spelling of a FIX data type
//! (via [`FromStr`](std::str::FromStr)) and the on-the-wire form that type
//! admits (via [`FieldType::is_valid_value`]), so the validator never needs a
//! second, hard-coded table of what a tag means.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// FIX protocol version.
///
/// This is [`ironfix_core::FixVersion`], re-exported under the name this
/// crate has always published. The version-to-wire mapping (`BeginString`
/// tag 8, and `ApplVerID` for the 5.0 family) lives in `ironfix-core` because
/// `ironfix-engine` needs the same answer and must not depend on
/// `ironfix-dictionary`; keeping a second copy here let the two drift with no
/// test able to cross-check them.
///
/// Note that `Display` and [`FixVersion::as_str`](ironfix_core::FixVersion::as_str)
/// render the version's own name (`FIX.5.0SP2`), which for the 5.0 family is
/// **not** its
/// [`begin_string`](ironfix_core::FixVersion::begin_string) (`FIXT.1.1`).
pub use ironfix_core::FixVersion as Version;

/// FIX field data type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FieldType {
    /// Integer value.
    Int,
    /// Length field (for data fields).
    Length,
    /// Sequence number.
    SeqNum,
    /// Number of entries in a repeating group.
    NumInGroup,
    /// Tag number reference.
    TagNum,
    /// Day of month (1-31).
    DayOfMonth,
    /// Floating point number.
    Float,
    /// Quantity.
    Qty,
    /// Price.
    Price,
    /// Price offset.
    PriceOffset,
    /// Amount (price * quantity).
    Amt,
    /// Percentage.
    Percentage,
    /// Single character.
    Char,
    /// Boolean (Y/N).
    Boolean,
    /// String.
    String,
    /// Multiple character value (space-separated).
    MultipleCharValue,
    /// Multiple string value (space-separated).
    MultipleStringValue,
    /// Country code (ISO 3166).
    Country,
    /// Currency code (ISO 4217).
    Currency,
    /// Exchange code (ISO 10383 MIC).
    Exchange,
    /// Month-year (YYYYMM or YYYYMMDD or YYYYMMWW).
    MonthYear,
    /// UTC timestamp.
    UtcTimestamp,
    /// UTC time only.
    UtcTimeOnly,
    /// UTC date only.
    UtcDateOnly,
    /// Local market date.
    LocalMktDate,
    /// Local market time.
    LocalMktTime,
    /// Timezone.
    TzTimeOnly,
    /// Timezone with timestamp.
    TzTimestamp,
    /// Raw data (binary).
    Data,
    /// XML data.
    XmlData,
    /// Language code (ISO 639-1).
    Language,
    /// Pattern (regex).
    Pattern,
    /// Tenor (e.g., "1M", "3M").
    Tenor,
    /// Reserved for future use.
    Reserved,
}

impl FieldType {
    /// Returns true if this type represents a numeric value.
    #[must_use]
    pub const fn is_numeric(&self) -> bool {
        matches!(
            self,
            Self::Int
                | Self::Length
                | Self::SeqNum
                | Self::NumInGroup
                | Self::TagNum
                | Self::DayOfMonth
                | Self::Float
                | Self::Qty
                | Self::Price
                | Self::PriceOffset
                | Self::Amt
                | Self::Percentage
        )
    }
}

/// A field type name in a dictionary is not a known FIX data type.
///
/// Returned by [`FieldType`]'s [`FromStr`](std::str::FromStr) implementation.
/// An unknown type name is rejected rather than silently treated as
/// [`FieldType::String`]: mapping it to `String` would drop the field's
/// format and multi-value semantics without any diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown FIX field type `{0}`")]
pub struct UnknownFieldType(
    /// The unrecognised type name, as spelled in the dictionary.
    pub String,
);

impl std::str::FromStr for FieldType {
    type Err = UnknownFieldType;

    /// Creates a FieldType from a string name.
    ///
    /// The accepted spellings are those used by QuickFIX XML dictionaries.
    ///
    /// # Arguments
    /// * `s` - The type name from the FIX dictionary
    ///
    /// # Errors
    /// Returns [`UnknownFieldType`] if `s` is not a known FIX data type name.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_uppercase().as_str() {
            "INT" => Self::Int,
            "LENGTH" => Self::Length,
            "SEQNUM" => Self::SeqNum,
            "NUMINGROUP" => Self::NumInGroup,
            "TAGNUM" => Self::TagNum,
            "DAYOFMONTH" => Self::DayOfMonth,
            "FLOAT" => Self::Float,
            "QTY" | "QUANTITY" => Self::Qty,
            "PRICE" => Self::Price,
            "PRICEOFFSET" => Self::PriceOffset,
            "AMT" | "AMOUNT" => Self::Amt,
            "PERCENTAGE" => Self::Percentage,
            "CHAR" => Self::Char,
            "BOOLEAN" => Self::Boolean,
            "STRING" => Self::String,
            "MULTIPLECHARVALUE" => Self::MultipleCharValue,
            // `MULTIPLEVALUESTRING` is the spelling the vendored FIX 4.4
            // QuickFIX dictionary uses for its eight multi-value string
            // fields (ExecInst(18), QuoteCondition(276), ...);
            // `MULTIPLESTRINGVALUE` is the later FIX 5.0 spelling. Both name
            // the same data type.
            "MULTIPLESTRINGVALUE" | "MULTIPLEVALUESTRING" => Self::MultipleStringValue,
            "COUNTRY" => Self::Country,
            "CURRENCY" => Self::Currency,
            "EXCHANGE" => Self::Exchange,
            "MONTHYEAR" => Self::MonthYear,
            "UTCTIMESTAMP" => Self::UtcTimestamp,
            "UTCTIMEONLY" => Self::UtcTimeOnly,
            "UTCDATEONLY" => Self::UtcDateOnly,
            "LOCALMKTDATE" => Self::LocalMktDate,
            "LOCALMKTTIME" => Self::LocalMktTime,
            "TZTIMEONLY" => Self::TzTimeOnly,
            "TZTIMESTAMP" => Self::TzTimestamp,
            "DATA" => Self::Data,
            "XMLDATA" => Self::XmlData,
            "LANGUAGE" => Self::Language,
            "PATTERN" => Self::Pattern,
            "TENOR" => Self::Tenor,
            "RESERVED100PLUS" | "RESERVED1000PLUS" | "RESERVED4000PLUS" => Self::Reserved,
            _ => return Err(UnknownFieldType(s.to_string())),
        })
    }
}

impl FieldType {
    /// Returns true if this type represents a timestamp.
    #[must_use]
    pub const fn is_timestamp(&self) -> bool {
        matches!(
            self,
            Self::UtcTimestamp
                | Self::UtcTimeOnly
                | Self::UtcDateOnly
                | Self::LocalMktDate
                | Self::LocalMktTime
                | Self::TzTimeOnly
                | Self::TzTimestamp
        )
    }

    /// Returns true if this type carries a space-separated list of values.
    #[must_use]
    pub const fn is_multi_value(&self) -> bool {
        matches!(self, Self::MultipleCharValue | Self::MultipleStringValue)
    }

    /// Returns true if `value` has the on-the-wire form this type admits.
    ///
    /// The check is a *form* check only — it never consults an enumeration,
    /// a calendar, or an ISO registry. `UtcTimestamp` therefore accepts
    /// `20260230-25:99:99` (well-formed, impossible) and `Currency` accepts
    /// `ZZZ`. Types whose FIX form is free text or venue-defined
    /// ([`String`](Self::String), [`Data`](Self::Data),
    /// [`Exchange`](Self::Exchange), [`Tenor`](Self::Tenor), the `Tz`
    /// variants, ...) accept any value.
    ///
    /// # Arguments
    /// * `value` - The field value exactly as it appeared on the wire
    #[must_use]
    pub fn is_valid_value(&self, value: &str) -> bool {
        match self {
            Self::Int => is_integer(value, true),
            Self::Length | Self::SeqNum | Self::NumInGroup | Self::TagNum => {
                is_integer(value, false)
            }
            Self::DayOfMonth => {
                is_integer(value, false) && matches!(value.parse::<u32>(), Ok(1..=31))
            }
            Self::Float
            | Self::Qty
            | Self::Price
            | Self::PriceOffset
            | Self::Amt
            | Self::Percentage => is_decimal(value),
            Self::Char => value.chars().count() == 1,
            Self::Boolean => value == "Y" || value == "N",
            Self::MultipleCharValue => is_multi_value_list(value, Some(1)),
            Self::MultipleStringValue => is_multi_value_list(value, None),
            Self::Country => is_alpha_of_len(value, 2),
            Self::Currency => is_alpha_of_len(value, 3),
            Self::MonthYear => is_month_year(value),
            Self::UtcDateOnly | Self::LocalMktDate => is_digits_of_len(value, 8),
            Self::UtcTimeOnly => is_time_of_day(value),
            Self::UtcTimestamp => match value.split_once('-') {
                Some((date, time)) => is_digits_of_len(date, 8) && is_time_of_day(time),
                None => false,
            },
            Self::String
            | Self::Exchange
            | Self::LocalMktTime
            | Self::TzTimeOnly
            | Self::TzTimestamp
            | Self::Data
            | Self::XmlData
            | Self::Language
            | Self::Pattern
            | Self::Tenor
            | Self::Reserved => true,
        }
    }
}

/// Returns true for a non-empty run of ASCII digits, optionally signed.
fn is_integer(value: &str, allow_sign: bool) -> bool {
    let digits = match value.strip_prefix('-') {
        Some(rest) if allow_sign => rest,
        Some(_) => return false,
        None => value,
    };
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// Returns true for a FIX decimal: optional sign, digits, at most one point.
fn is_decimal(value: &str) -> bool {
    let body = value.strip_prefix('-').unwrap_or(value);
    let mut digits = 0usize;
    let mut points = 0usize;
    for byte in body.bytes() {
        match byte {
            b'0'..=b'9' => digits += 1,
            b'.' => points += 1,
            _ => return false,
        }
    }
    digits > 0 && points <= 1
}

/// Returns true for a non-empty space-separated list whose every token is
/// non-empty and, when `token_len` is set, exactly that many characters.
fn is_multi_value_list(value: &str, token_len: Option<usize>) -> bool {
    let mut tokens = 0usize;
    for token in value.split(' ') {
        if token.is_empty() {
            return false;
        }
        if let Some(len) = token_len
            && token.chars().count() != len
        {
            return false;
        }
        tokens += 1;
    }
    tokens > 0
}

/// Returns true for exactly `len` ASCII alphabetic characters.
fn is_alpha_of_len(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|b| b.is_ascii_alphabetic())
}

/// Returns true for exactly `len` ASCII digits.
fn is_digits_of_len(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|b| b.is_ascii_digit())
}

/// Returns true for `YYYYMM`, `YYYYMMDD`, or `YYYYMMww` (week 1-5).
fn is_month_year(value: &str) -> bool {
    if is_digits_of_len(value, 6) || is_digits_of_len(value, 8) {
        return true;
    }
    match value.split_at_checked(6) {
        Some((year_month, week)) => {
            is_digits_of_len(year_month, 6)
                && matches!(week.as_bytes(), [b'w', digit] if (b'1'..=b'5').contains(digit))
        }
        None => false,
    }
}

/// Returns true for `HH:MM:SS` with an optional `.sss` fraction.
fn is_time_of_day(value: &str) -> bool {
    let (clock, fraction) = match value.split_once('.') {
        Some((clock, fraction)) => (clock, Some(fraction)),
        None => (value, None),
    };
    if let Some(fraction) = fraction
        && !(matches!(fraction.len(), 1..=9) && fraction.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    let mut parts = 0usize;
    for part in clock.split(':') {
        if !is_digits_of_len(part, 2) {
            return false;
        }
        parts += 1;
    }
    parts == 3
}

/// Definition of a FIX field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDef {
    /// Field tag number.
    pub tag: u32,
    /// Field name.
    pub name: String,
    /// Field data type.
    pub field_type: FieldType,
    /// Valid values for enumerated fields.
    pub values: Option<HashMap<String, String>>,
    /// Field description.
    pub description: Option<String>,
}

impl FieldDef {
    /// Creates a new field definition.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    /// * `name` - The field name
    /// * `field_type` - The field data type
    #[must_use]
    pub fn new(tag: u32, name: impl Into<String>, field_type: FieldType) -> Self {
        Self {
            tag,
            name: name.into(),
            field_type,
            values: None,
            description: None,
        }
    }

    /// Adds valid values for an enumerated field.
    #[must_use]
    pub fn with_values(mut self, values: HashMap<String, String>) -> Self {
        self.values = Some(values);
        self
    }

    /// Adds a description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

/// Reference to a field within a message or component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldRef {
    /// Field tag number.
    pub tag: u32,
    /// Field name.
    pub name: String,
    /// Whether the field is required.
    pub required: bool,
}

/// Reference to a component from a message, component, or group.
///
/// The reference carries its own `required` flag: the same component is
/// mandatory in one message and optional in another, so requiredness belongs
/// to the reference and not to the [`ComponentDef`]. Dropping it makes every
/// component look required, which turns an optional component's required
/// members into spurious
/// [`MissingRequiredField`](crate::ValidationError::MissingRequiredField)
/// errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentRef {
    /// Name of the referenced component.
    pub name: String,
    /// Whether the component is required where it is referenced.
    pub required: bool,
}

impl ComponentRef {
    /// Creates a component reference.
    ///
    /// # Arguments
    /// * `name` - Name of the referenced component
    /// * `required` - Whether the component is required at this reference
    #[must_use]
    pub fn new(name: impl Into<String>, required: bool) -> Self {
        Self {
            name: name.into(),
            required,
        }
    }
}

/// Definition of a repeating group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupDef {
    /// Tag of the count field (NumInGroup).
    pub count_tag: u32,
    /// Name of the group.
    pub name: String,
    /// Tag of the first field in each group entry (delimiter).
    pub delimiter_tag: u32,
    /// Fields within each group entry.
    pub fields: Vec<FieldRef>,
    /// Nested groups within this group.
    pub groups: Vec<GroupDef>,
    /// Components used within each group entry.
    #[serde(default)]
    pub components: Vec<ComponentRef>,
    /// Whether the group is required.
    pub required: bool,
}

/// Definition of a reusable component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentDef {
    /// Component name.
    pub name: String,
    /// Fields in this component.
    pub fields: Vec<FieldRef>,
    /// Groups in this component.
    pub groups: Vec<GroupDef>,
    /// Nested components.
    pub components: Vec<ComponentRef>,
}

/// Definition of a FIX message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageDef {
    /// Message type value (tag 35).
    pub msg_type: String,
    /// Message name.
    pub name: String,
    /// Message category (admin or app).
    pub category: MessageCategory,
    /// Fields in this message.
    pub fields: Vec<FieldRef>,
    /// Groups in this message.
    pub groups: Vec<GroupDef>,
    /// Components used in this message.
    pub components: Vec<ComponentRef>,
}

/// Message category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageCategory {
    /// Administrative message (session level).
    Admin,
    /// Application message.
    App,
}

/// Complete FIX dictionary for a specific version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dictionary {
    /// FIX version.
    pub version: Version,
    /// Field definitions indexed by tag.
    pub fields: HashMap<u32, FieldDef>,
    /// Field definitions indexed by name.
    pub fields_by_name: HashMap<String, u32>,
    /// Message definitions indexed by msg_type.
    pub messages: HashMap<String, MessageDef>,
    /// Component definitions indexed by name.
    pub components: HashMap<String, ComponentDef>,
    /// Header fields.
    pub header: Vec<FieldRef>,
    /// Repeating groups in the header (e.g. NoHops in FIX 4.4).
    #[serde(default)]
    pub header_groups: Vec<GroupDef>,
    /// Trailer fields.
    pub trailer: Vec<FieldRef>,
    /// Repeating groups in the trailer.
    #[serde(default)]
    pub trailer_groups: Vec<GroupDef>,
}

impl Dictionary {
    /// Creates a new empty dictionary for the specified version.
    ///
    /// # Arguments
    /// * `version` - The FIX version
    #[must_use]
    pub fn new(version: Version) -> Self {
        Self {
            version,
            fields: HashMap::new(),
            fields_by_name: HashMap::new(),
            messages: HashMap::new(),
            components: HashMap::new(),
            header: Vec::new(),
            header_groups: Vec::new(),
            trailer: Vec::new(),
            trailer_groups: Vec::new(),
        }
    }

    /// Adds a field definition.
    pub fn add_field(&mut self, field: FieldDef) {
        self.fields_by_name.insert(field.name.clone(), field.tag);
        self.fields.insert(field.tag, field);
    }

    /// Adds a message definition.
    pub fn add_message(&mut self, message: MessageDef) {
        self.messages.insert(message.msg_type.clone(), message);
    }

    /// Adds a component definition.
    pub fn add_component(&mut self, component: ComponentDef) {
        self.components.insert(component.name.clone(), component);
    }

    /// Gets a field definition by tag.
    #[must_use]
    pub fn get_field(&self, tag: u32) -> Option<&FieldDef> {
        self.fields.get(&tag)
    }

    /// Gets a field definition by name.
    #[must_use]
    pub fn get_field_by_name(&self, name: &str) -> Option<&FieldDef> {
        self.fields_by_name
            .get(name)
            .and_then(|tag| self.fields.get(tag))
    }

    /// Gets a message definition by type.
    #[must_use]
    pub fn get_message(&self, msg_type: &str) -> Option<&MessageDef> {
        self.messages.get(msg_type)
    }

    /// Gets a component definition by name.
    #[must_use]
    pub fn get_component(&self, name: &str) -> Option<&ComponentDef> {
        self.components.get(name)
    }

    /// Returns an iterator over all field definitions.
    pub fn fields(&self) -> impl Iterator<Item = &FieldDef> {
        self.fields.values()
    }

    /// Returns an iterator over all message definitions.
    pub fn messages(&self) -> impl Iterator<Item = &MessageDef> {
        self.messages.values()
    }

    /// Returns an iterator over all component definitions.
    pub fn components(&self) -> impl Iterator<Item = &ComponentDef> {
        self.components.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_begin_string() {
        assert_eq!(Version::Fix42.begin_string(), "FIX.4.2");
        assert_eq!(Version::Fix44.begin_string(), "FIX.4.4");
        assert_eq!(Version::Fix50Sp2.begin_string(), "FIXT.1.1");
    }

    #[test]
    fn test_version_appl_ver_id() {
        assert_eq!(Version::Fix44.appl_ver_id(), None);
        assert_eq!(Version::Fix50.appl_ver_id(), Some("7"));
        assert_eq!(Version::Fix50Sp2.appl_ver_id(), Some("9"));
    }

    #[test]
    fn test_version_is_the_core_type_not_a_copy() {
        // `Version` is a re-export of `ironfix_core::FixVersion`, so the
        // version-to-wire table exists exactly once in the workspace and
        // cannot drift from the copy `ironfix-engine` consumes. Assigning
        // across the two names only compiles while that holds.
        let from_core: Version = ironfix_core::FixVersion::Fix50Sp2;
        assert_eq!(from_core, Version::Fix50Sp2);
        assert_eq!(Version::ALL.len(), ironfix_core::FixVersion::ALL.len());
    }

    #[test]
    fn test_field_type_from_str_known_names_map() {
        assert_eq!("INT".parse::<FieldType>(), Ok(FieldType::Int));
        assert_eq!("STRING".parse::<FieldType>(), Ok(FieldType::String));
        assert_eq!(
            "UTCTIMESTAMP".parse::<FieldType>(),
            Ok(FieldType::UtcTimestamp)
        );
        assert_eq!(
            "RESERVED100PLUS".parse::<FieldType>(),
            Ok(FieldType::Reserved)
        );
    }

    #[test]
    fn test_field_type_from_str_both_multi_value_string_spellings_map() {
        // The vendored FIX 4.4 dictionary spells it `MULTIPLEVALUESTRING`;
        // FIX 5.0 spells the same type `MULTIPLESTRINGVALUE`.
        assert_eq!(
            "MULTIPLEVALUESTRING".parse::<FieldType>(),
            Ok(FieldType::MultipleStringValue)
        );
        assert_eq!(
            "MULTIPLESTRINGVALUE".parse::<FieldType>(),
            Ok(FieldType::MultipleStringValue)
        );
        assert!(FieldType::MultipleStringValue.is_multi_value());
    }

    #[test]
    fn test_field_type_from_str_unknown_name_is_rejected() {
        assert_eq!(
            "NOTATYPE".parse::<FieldType>(),
            Err(UnknownFieldType("NOTATYPE".to_string()))
        );
    }

    #[test]
    fn test_field_type_is_valid_value_numeric_forms() {
        assert!(FieldType::Int.is_valid_value("-42"));
        assert!(!FieldType::Int.is_valid_value("abc"));
        assert!(!FieldType::Int.is_valid_value(""));
        assert!(!FieldType::SeqNum.is_valid_value("-1"));
        assert!(FieldType::Price.is_valid_value("1.25"));
        assert!(!FieldType::Price.is_valid_value("1..2"));
        assert!(!FieldType::Qty.is_valid_value("1.2.3"));
        assert!(FieldType::DayOfMonth.is_valid_value("31"));
        assert!(!FieldType::DayOfMonth.is_valid_value("32"));
    }

    #[test]
    fn test_field_type_is_valid_value_scalar_forms() {
        assert!(FieldType::Boolean.is_valid_value("Y"));
        assert!(!FieldType::Boolean.is_valid_value("Q"));
        assert!(FieldType::Char.is_valid_value("1"));
        assert!(!FieldType::Char.is_valid_value("12"));
        assert!(FieldType::Currency.is_valid_value("EUR"));
        assert!(!FieldType::Currency.is_valid_value("EU"));
        assert!(FieldType::Country.is_valid_value("ES"));
        assert!(!FieldType::Country.is_valid_value("E1"));
        // Free-form types accept anything.
        assert!(FieldType::String.is_valid_value("anything at all"));
        assert!(FieldType::Exchange.is_valid_value("XMAD"));
    }

    #[test]
    fn test_field_type_is_valid_value_temporal_forms() {
        assert!(FieldType::UtcTimestamp.is_valid_value("20260712-10:00:00"));
        assert!(FieldType::UtcTimestamp.is_valid_value("20260712-10:00:00.123"));
        assert!(!FieldType::UtcTimestamp.is_valid_value("20260712 10:00:00"));
        assert!(!FieldType::UtcTimestamp.is_valid_value("20260712-10:00"));
        assert!(FieldType::UtcTimeOnly.is_valid_value("10:00:00"));
        assert!(FieldType::UtcDateOnly.is_valid_value("20260712"));
        assert!(!FieldType::LocalMktDate.is_valid_value("2026-07-12"));
        assert!(FieldType::MonthYear.is_valid_value("202607"));
        assert!(FieldType::MonthYear.is_valid_value("20260712"));
        assert!(FieldType::MonthYear.is_valid_value("202607w3"));
        assert!(!FieldType::MonthYear.is_valid_value("202607w9"));
    }

    #[test]
    fn test_field_type_is_valid_value_multi_value_forms() {
        assert!(FieldType::MultipleStringValue.is_valid_value("1 2"));
        assert!(!FieldType::MultipleStringValue.is_valid_value(""));
        assert!(!FieldType::MultipleStringValue.is_valid_value("1  2"));
        assert!(FieldType::MultipleCharValue.is_valid_value("A B"));
        assert!(!FieldType::MultipleCharValue.is_valid_value("AB C"));
    }

    #[test]
    fn test_component_ref_carries_its_own_required_flag() {
        let required = ComponentRef::new("Instrument", true);
        let optional = ComponentRef::new("Instrument", false);
        assert_eq!(required.name, optional.name);
        assert!(required.required);
        assert!(!optional.required);
    }

    #[test]
    fn test_field_type_is_numeric() {
        assert!(FieldType::Int.is_numeric());
        assert!(FieldType::Price.is_numeric());
        assert!(!FieldType::String.is_numeric());
    }

    #[test]
    fn test_dictionary_field_operations() {
        let mut dict = Dictionary::new(Version::Fix44);
        let field = FieldDef::new(35, "MsgType", FieldType::String);
        dict.add_field(field);

        assert!(dict.get_field(35).is_some());
        assert!(dict.get_field_by_name("MsgType").is_some());
        assert!(dict.get_field(999).is_none());
    }
}
