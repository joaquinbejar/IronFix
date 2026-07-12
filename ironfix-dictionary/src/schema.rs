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
//! - [`GroupDef`]: Repeating group definitions
//! - [`Dictionary`]: Complete FIX version dictionary

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// FIX protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Version {
    /// FIX 4.0
    Fix40,
    /// FIX 4.1
    Fix41,
    /// FIX 4.2
    Fix42,
    /// FIX 4.3
    Fix43,
    /// FIX 4.4
    Fix44,
    /// FIX 5.0
    Fix50,
    /// FIX 5.0 SP1
    Fix50Sp1,
    /// FIX 5.0 SP2
    Fix50Sp2,
    /// FIXT 1.1 (transport layer for FIX 5.0+)
    Fixt11,
}

impl Version {
    /// Returns the BeginString value for this version.
    #[must_use]
    pub const fn begin_string(&self) -> &'static str {
        match self {
            Self::Fix40 => "FIX.4.0",
            Self::Fix41 => "FIX.4.1",
            Self::Fix42 => "FIX.4.2",
            Self::Fix43 => "FIX.4.3",
            Self::Fix44 => "FIX.4.4",
            Self::Fix50 | Self::Fix50Sp1 | Self::Fix50Sp2 | Self::Fixt11 => "FIXT.1.1",
        }
    }

    /// Returns the ApplVerID for FIX 5.0+ versions.
    #[must_use]
    pub const fn appl_ver_id(&self) -> Option<&'static str> {
        match self {
            Self::Fix50 => Some("7"),
            Self::Fix50Sp1 => Some("8"),
            Self::Fix50Sp2 => Some("9"),
            _ => None,
        }
    }

    /// Returns true if this version uses FIXT transport.
    #[must_use]
    pub const fn uses_fixt(&self) -> bool {
        matches!(
            self,
            Self::Fix50 | Self::Fix50Sp1 | Self::Fix50Sp2 | Self::Fixt11
        )
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.begin_string())
    }
}

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

impl std::str::FromStr for FieldType {
    type Err = std::convert::Infallible;

    /// Creates a FieldType from a string name.
    ///
    /// # Arguments
    /// * `s` - The type name from the FIX dictionary
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
            "MULTIPLESTRINGVALUE" => Self::MultipleStringValue,
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
            _ => Self::String,
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
    pub components: Vec<String>,
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
    pub components: Vec<String>,
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
    pub components: Vec<String>,
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
    fn test_field_type_from_str() {
        assert_eq!("INT".parse::<FieldType>().unwrap(), FieldType::Int);
        assert_eq!("STRING".parse::<FieldType>().unwrap(), FieldType::String);
        assert_eq!(
            "UTCTIMESTAMP".parse::<FieldType>().unwrap(),
            FieldType::UtcTimestamp
        );
        assert_eq!("unknown".parse::<FieldType>().unwrap(), FieldType::String);
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
