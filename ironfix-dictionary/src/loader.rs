/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 12/7/26
******************************************************************************/

//! QuickFIX XML dictionary loader.
//!
//! This module parses QuickFIX-format XML specifications (e.g. `FIX44.xml`)
//! into a [`Dictionary`], and exposes the embedded standard FIX 4.4
//! dictionary via [`Dictionary::fix44`].
//!
//! Venue-specific dialects can be loaded from their own QuickFIX XML files
//! with [`Dictionary::from_quickfix_xml`].

use crate::schema::{
    ComponentDef, Dictionary, FieldDef, FieldRef, FieldType, GroupDef, MessageCategory, MessageDef,
    Version,
};
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use std::collections::HashMap;
use std::sync::OnceLock;

/// Maximum component nesting depth accepted by the resolver.
///
/// Guards against reference cycles in malformed dictionaries.
const MAX_COMPONENT_DEPTH: usize = 32;

/// Embedded QuickFIX FIX 4.4 specification.
///
/// Source: <https://github.com/quickfix/quickfix/blob/master/spec/FIX44.xml>
const FIX44_XML: &str = include_str!("../spec/FIX44.xml");

static FIX44_DICT: OnceLock<Dictionary> = OnceLock::new();

/// Errors produced while loading a dictionary from XML.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DictionaryError {
    /// The XML could not be parsed.
    #[error("XML parse error: {0}")]
    Xml(String),
    /// A required attribute is missing from an element.
    #[error("missing attribute `{attribute}` on element <{element}>")]
    MissingAttribute {
        /// Element name.
        element: String,
        /// Attribute name.
        attribute: String,
    },
    /// The root `<fix>` element describes an unsupported version.
    #[error("unsupported FIX version: {0}")]
    UnsupportedVersion(String),
    /// A field tag could not be parsed as a number.
    #[error("invalid field tag `{0}`")]
    InvalidTag(String),
    /// A field is referenced by name but not defined in the `<fields>` section.
    #[error("unknown field name `{0}` referenced in dictionary")]
    UnknownFieldName(String),
    /// A component is referenced by name but not defined in the `<components>` section.
    #[error("unknown component `{0}` referenced in dictionary")]
    UnknownComponent(String),
    /// A group has no members, so its delimiter cannot be determined.
    #[error("empty group `{0}`: cannot determine delimiter tag")]
    EmptyGroup(String),
    /// Components are nested too deeply (likely a reference cycle).
    #[error("component nesting too deep resolving `{0}` (reference cycle?)")]
    ComponentCycle(String),
}

impl Dictionary {
    /// Returns the embedded standard FIX 4.4 dictionary.
    ///
    /// The dictionary is parsed from the bundled QuickFIX `FIX44.xml`
    /// specification on first use and cached for the lifetime of the
    /// process.
    #[must_use]
    pub fn fix44() -> &'static Self {
        FIX44_DICT.get_or_init(|| {
            Self::from_quickfix_xml(FIX44_XML).expect("embedded FIX 4.4 dictionary is valid")
        })
    }

    /// Loads a dictionary from a QuickFIX-format XML specification.
    ///
    /// # Arguments
    /// * `xml` - The XML document contents
    ///
    /// # Errors
    /// Returns [`DictionaryError`] if the XML is malformed, describes an
    /// unsupported version, or contains dangling field/component references.
    pub fn from_quickfix_xml(xml: &str) -> Result<Self, DictionaryError> {
        load(xml)
    }
}

/// Intermediate representation of a member of a message, component,
/// group, header, or trailer, preserving document order.
#[derive(Debug)]
enum Item {
    /// Field reference.
    Field {
        /// Field name.
        name: String,
        /// Whether the field is required.
        required: bool,
    },
    /// Repeating group.
    Group {
        /// Group (count field) name.
        name: String,
        /// Whether the group is required.
        required: bool,
        /// Members of each group entry, in document order.
        items: Vec<Item>,
    },
    /// Component reference.
    Component {
        /// Component name.
        name: String,
    },
}

/// Intermediate representation of a `<message>` element.
struct MessageIr {
    name: String,
    msg_type: String,
    category: MessageCategory,
    items: Vec<Item>,
}

fn xml_err(e: impl std::fmt::Display) -> DictionaryError {
    DictionaryError::Xml(e.to_string())
}

fn attr_map(e: &BytesStart<'_>) -> Result<HashMap<String, String>, DictionaryError> {
    let mut map = HashMap::new();
    for attr in e.attributes() {
        let attr = attr.map_err(xml_err)?;
        let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
        let value = attr
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(xml_err)?
            .into_owned();
        map.insert(key, value);
    }
    Ok(map)
}

fn required_attr(
    attrs: &HashMap<String, String>,
    element: &str,
    attribute: &str,
) -> Result<String, DictionaryError> {
    attrs
        .get(attribute)
        .cloned()
        .ok_or_else(|| DictionaryError::MissingAttribute {
            element: element.to_string(),
            attribute: attribute.to_string(),
        })
}

fn is_required(attrs: &HashMap<String, String>) -> bool {
    attrs.get("required").is_some_and(|v| v == "Y")
}

fn parse_version(attrs: &HashMap<String, String>) -> Result<Version, DictionaryError> {
    let fix_type = attrs.get("type").map_or("FIX", String::as_str);
    let major = required_attr(attrs, "fix", "major")?;
    let minor = required_attr(attrs, "fix", "minor")?;
    let servicepack = attrs.get("servicepack").map_or("0", String::as_str);

    match (fix_type, major.as_str(), minor.as_str(), servicepack) {
        ("FIXT", "1", "1", _) => Ok(Version::Fixt11),
        ("FIX", "4", "0", _) => Ok(Version::Fix40),
        ("FIX", "4", "1", _) => Ok(Version::Fix41),
        ("FIX", "4", "2", _) => Ok(Version::Fix42),
        ("FIX", "4", "3", _) => Ok(Version::Fix43),
        ("FIX", "4", "4", _) => Ok(Version::Fix44),
        ("FIX", "5", "0", "0") => Ok(Version::Fix50),
        ("FIX", "5", "0", "1") => Ok(Version::Fix50Sp1),
        ("FIX", "5", "0", "2") => Ok(Version::Fix50Sp2),
        _ => Err(DictionaryError::UnsupportedVersion(format!(
            "{fix_type} {major}.{minor} SP{servicepack}"
        ))),
    }
}

/// Parses members until the matching end tag `end` is consumed.
fn parse_items(reader: &mut Reader<&[u8]>, end: &[u8]) -> Result<Vec<Item>, DictionaryError> {
    let mut items = Vec::new();
    loop {
        match reader.read_event().map_err(xml_err)? {
            Event::Empty(e) => {
                let attrs = attr_map(&e)?;
                match e.name().as_ref() {
                    b"field" => items.push(Item::Field {
                        name: required_attr(&attrs, "field", "name")?,
                        required: is_required(&attrs),
                    }),
                    b"component" => items.push(Item::Component {
                        name: required_attr(&attrs, "component", "name")?,
                    }),
                    b"group" => items.push(Item::Group {
                        name: required_attr(&attrs, "group", "name")?,
                        required: is_required(&attrs),
                        items: Vec::new(),
                    }),
                    _ => {}
                }
            }
            Event::Start(e) => {
                let attrs = attr_map(&e)?;
                match e.name().as_ref() {
                    b"group" => {
                        let inner = parse_items(reader, b"group")?;
                        items.push(Item::Group {
                            name: required_attr(&attrs, "group", "name")?,
                            required: is_required(&attrs),
                            items: inner,
                        });
                    }
                    b"field" => {
                        // Field references never have meaningful children here.
                        parse_items(reader, b"field")?;
                        items.push(Item::Field {
                            name: required_attr(&attrs, "field", "name")?,
                            required: is_required(&attrs),
                        });
                    }
                    b"component" => {
                        parse_items(reader, b"component")?;
                        items.push(Item::Component {
                            name: required_attr(&attrs, "component", "name")?,
                        });
                    }
                    _ => {}
                }
            }
            Event::End(e) if e.name().as_ref() == end => return Ok(items),
            Event::Eof => return Err(DictionaryError::Xml("unexpected end of file".to_string())),
            _ => {}
        }
    }
}

/// Parses the `<fields>` section into field definitions.
fn parse_field_defs(reader: &mut Reader<&[u8]>) -> Result<Vec<FieldDef>, DictionaryError> {
    let mut defs = Vec::new();
    loop {
        match reader.read_event().map_err(xml_err)? {
            Event::Empty(e) if e.name().as_ref() == b"field" => {
                defs.push(field_def(&attr_map(&e)?, HashMap::new())?);
            }
            Event::Start(e) if e.name().as_ref() == b"field" => {
                let attrs = attr_map(&e)?;
                let mut values = HashMap::new();
                loop {
                    match reader.read_event().map_err(xml_err)? {
                        Event::Empty(v) | Event::Start(v) if v.name().as_ref() == b"value" => {
                            let value_attrs = attr_map(&v)?;
                            let enum_value = required_attr(&value_attrs, "value", "enum")?;
                            let description =
                                value_attrs.get("description").cloned().unwrap_or_default();
                            values.insert(enum_value, description);
                        }
                        Event::End(v) if v.name().as_ref() == b"field" => break,
                        Event::Eof => {
                            return Err(DictionaryError::Xml("unexpected end of file".to_string()));
                        }
                        _ => {}
                    }
                }
                defs.push(field_def(&attrs, values)?);
            }
            Event::End(e) if e.name().as_ref() == b"fields" => return Ok(defs),
            Event::Eof => return Err(DictionaryError::Xml("unexpected end of file".to_string())),
            _ => {}
        }
    }
}

fn field_def(
    attrs: &HashMap<String, String>,
    values: HashMap<String, String>,
) -> Result<FieldDef, DictionaryError> {
    let number = required_attr(attrs, "field", "number")?;
    let tag: u32 = number
        .parse()
        .map_err(|_| DictionaryError::InvalidTag(number.clone()))?;
    let name = required_attr(attrs, "field", "name")?;
    let field_type = required_attr(attrs, "field", "type")?
        .parse::<FieldType>()
        .unwrap_or(FieldType::String);

    let mut def = FieldDef::new(tag, name, field_type);
    if !values.is_empty() {
        def = def.with_values(values);
    }
    Ok(def)
}

/// Resolves intermediate items into schema structures using the parsed
/// field and component tables.
struct Resolver<'a> {
    fields_by_name: &'a HashMap<String, u32>,
    components: &'a HashMap<String, Vec<Item>>,
}

impl Resolver<'_> {
    fn tag(&self, name: &str) -> Result<u32, DictionaryError> {
        self.fields_by_name
            .get(name)
            .copied()
            .ok_or_else(|| DictionaryError::UnknownFieldName(name.to_string()))
    }

    fn field_ref(&self, name: &str, required: bool) -> Result<FieldRef, DictionaryError> {
        Ok(FieldRef {
            tag: self.tag(name)?,
            name: name.to_string(),
            required,
        })
    }

    /// Returns the tag of the first field reachable in document order,
    /// descending into component references.
    fn first_tag(&self, items: &[Item], depth: usize) -> Result<Option<u32>, DictionaryError> {
        for item in items {
            match item {
                Item::Field { name, .. } | Item::Group { name, .. } => {
                    return self.tag(name).map(Some);
                }
                Item::Component { name } => {
                    if depth >= MAX_COMPONENT_DEPTH {
                        return Err(DictionaryError::ComponentCycle(name.clone()));
                    }
                    let inner = self
                        .components
                        .get(name)
                        .ok_or_else(|| DictionaryError::UnknownComponent(name.clone()))?;
                    if let Some(tag) = self.first_tag(inner, depth + 1)? {
                        return Ok(Some(tag));
                    }
                }
            }
        }
        Ok(None)
    }

    fn group(
        &self,
        name: &str,
        required: bool,
        items: &[Item],
    ) -> Result<GroupDef, DictionaryError> {
        let count_tag = self.tag(name)?;
        let delimiter_tag = self
            .first_tag(items, 0)?
            .ok_or_else(|| DictionaryError::EmptyGroup(name.to_string()))?;
        let (fields, groups, components) = self.split(items)?;
        Ok(GroupDef {
            count_tag,
            name: name.to_string(),
            delimiter_tag,
            fields,
            groups,
            components,
            required,
        })
    }

    /// Splits items into field references, resolved groups, and component names.
    #[allow(clippy::type_complexity)]
    fn split(
        &self,
        items: &[Item],
    ) -> Result<(Vec<FieldRef>, Vec<GroupDef>, Vec<String>), DictionaryError> {
        let mut fields = Vec::new();
        let mut groups = Vec::new();
        let mut components = Vec::new();
        for item in items {
            match item {
                Item::Field { name, required } => fields.push(self.field_ref(name, *required)?),
                Item::Group {
                    name,
                    required,
                    items,
                } => groups.push(self.group(name, *required, items)?),
                Item::Component { name } => components.push(name.clone()),
            }
        }
        Ok((fields, groups, components))
    }
}

fn load(xml: &str) -> Result<Dictionary, DictionaryError> {
    let mut reader = Reader::from_str(xml);

    let mut version: Option<Version> = None;
    let mut header_items: Vec<Item> = Vec::new();
    let mut trailer_items: Vec<Item> = Vec::new();
    let mut message_irs: Vec<MessageIr> = Vec::new();
    let mut component_irs: HashMap<String, Vec<Item>> = HashMap::new();
    let mut component_order: Vec<String> = Vec::new();
    let mut field_defs: Vec<FieldDef> = Vec::new();

    loop {
        match reader.read_event().map_err(xml_err)? {
            Event::Start(e) => match e.name().as_ref() {
                b"fix" => version = Some(parse_version(&attr_map(&e)?)?),
                b"header" => header_items = parse_items(&mut reader, b"header")?,
                b"trailer" => trailer_items = parse_items(&mut reader, b"trailer")?,
                b"message" => {
                    let attrs = attr_map(&e)?;
                    let category = if attrs.get("msgcat").map(String::as_str) == Some("admin") {
                        MessageCategory::Admin
                    } else {
                        MessageCategory::App
                    };
                    message_irs.push(MessageIr {
                        name: required_attr(&attrs, "message", "name")?,
                        msg_type: required_attr(&attrs, "message", "msgtype")?,
                        category,
                        items: parse_items(&mut reader, b"message")?,
                    });
                }
                b"component" => {
                    let attrs = attr_map(&e)?;
                    let name = required_attr(&attrs, "component", "name")?;
                    let items = parse_items(&mut reader, b"component")?;
                    component_order.push(name.clone());
                    component_irs.insert(name, items);
                }
                b"fields" => field_defs = parse_field_defs(&mut reader)?,
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
    }

    let version =
        version.ok_or_else(|| DictionaryError::Xml("missing root <fix> element".to_string()))?;

    let mut dict = Dictionary::new(version);
    for def in field_defs {
        dict.add_field(def);
    }

    let resolver = Resolver {
        fields_by_name: &dict.fields_by_name,
        components: &component_irs,
    };

    let (header_fields, header_groups, _) = resolver.split(&header_items)?;
    let (trailer_fields, trailer_groups, _) = resolver.split(&trailer_items)?;

    let mut components = Vec::with_capacity(component_order.len());
    for name in &component_order {
        let (fields, groups, nested) = resolver.split(&component_irs[name])?;
        components.push(ComponentDef {
            name: name.clone(),
            fields,
            groups,
            components: nested,
        });
    }

    let mut messages = Vec::with_capacity(message_irs.len());
    for ir in &message_irs {
        let (fields, groups, comps) = resolver.split(&ir.items)?;
        messages.push(MessageDef {
            msg_type: ir.msg_type.clone(),
            name: ir.name.clone(),
            category: ir.category,
            fields,
            groups,
            components: comps,
        });
    }

    dict.header = header_fields;
    dict.header_groups = header_groups;
    dict.trailer = trailer_fields;
    dict.trailer_groups = trailer_groups;
    for component in components {
        dict.add_component(component);
    }
    for message in messages {
        dict.add_message(message);
    }

    Ok(dict)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fix44_loads() {
        let dict = Dictionary::fix44();
        assert_eq!(dict.version, Version::Fix44);

        // Cached: same instance on every call.
        assert!(std::ptr::eq(dict, Dictionary::fix44()));
    }

    #[test]
    fn test_fix44_fields() {
        let dict = Dictionary::fix44();

        let msg_type = dict.get_field(35).expect("MsgType defined");
        assert_eq!(msg_type.name, "MsgType");

        let cl_ord_id = dict.get_field_by_name("ClOrdID").expect("ClOrdID defined");
        assert_eq!(cl_ord_id.tag, 11);

        let side = dict.get_field(54).expect("Side defined");
        let values = side.values.as_ref().expect("Side has enum values");
        assert!(values.contains_key("1"));
        assert!(values.contains_key("2"));
        assert!(!values.contains_key("X"));
    }

    #[test]
    fn test_fix44_header_and_trailer() {
        let dict = Dictionary::fix44();

        let sender = dict
            .header
            .iter()
            .find(|f| f.name == "SenderCompID")
            .expect("SenderCompID in header");
        assert_eq!(sender.tag, 49);
        assert!(sender.required);

        let hops = dict
            .header_groups
            .iter()
            .find(|g| g.name == "NoHops")
            .expect("NoHops group in header");
        assert_eq!(hops.count_tag, 627);
        assert_eq!(hops.delimiter_tag, 628);
        assert!(!hops.required);

        let checksum = dict
            .trailer
            .iter()
            .find(|f| f.name == "CheckSum")
            .expect("CheckSum in trailer");
        assert_eq!(checksum.tag, 10);
        assert!(checksum.required);
    }

    #[test]
    fn test_fix44_messages() {
        let dict = Dictionary::fix44();

        let nos = dict.get_message("D").expect("NewOrderSingle defined");
        assert_eq!(nos.name, "NewOrderSingle");
        assert_eq!(nos.category, MessageCategory::App);
        assert!(nos.fields.iter().any(|f| f.name == "ClOrdID" && f.required));
        assert!(nos.components.iter().any(|c| c == "Instrument"));

        let heartbeat = dict.get_message("0").expect("Heartbeat defined");
        assert_eq!(heartbeat.category, MessageCategory::Admin);
    }

    #[test]
    fn test_fix44_components_and_groups() {
        let dict = Dictionary::fix44();

        let instrument = dict
            .get_component("Instrument")
            .expect("Instrument defined");
        assert!(instrument.fields.iter().any(|f| f.name == "Symbol"));

        let parties = dict.get_component("Parties").expect("Parties defined");
        let no_party_ids = parties
            .groups
            .iter()
            .find(|g| g.name == "NoPartyIDs")
            .expect("NoPartyIDs group");
        assert_eq!(no_party_ids.count_tag, 453);
        assert_eq!(no_party_ids.delimiter_tag, 448);
        // Nested component reference within the group.
        assert!(no_party_ids.components.iter().any(|c| c == "PtysSubGrp"));
    }

    #[test]
    fn test_parse_version_covers_every_known_version() {
        // The XML attribute table here is a separate mapping from the wire
        // mapping in `ironfix_core::FixVersion`, so it can only be kept
        // exhaustive by driving it from the same list of versions.
        let attrs_for = |version: Version| -> Vec<(&'static str, &'static str)> {
            match version {
                Version::Fix40 => vec![("type", "FIX"), ("major", "4"), ("minor", "0")],
                Version::Fix41 => vec![("type", "FIX"), ("major", "4"), ("minor", "1")],
                Version::Fix42 => vec![("type", "FIX"), ("major", "4"), ("minor", "2")],
                Version::Fix43 => vec![("type", "FIX"), ("major", "4"), ("minor", "3")],
                Version::Fix44 => vec![("type", "FIX"), ("major", "4"), ("minor", "4")],
                Version::Fix50 => vec![
                    ("type", "FIX"),
                    ("major", "5"),
                    ("minor", "0"),
                    ("servicepack", "0"),
                ],
                Version::Fix50Sp1 => vec![
                    ("type", "FIX"),
                    ("major", "5"),
                    ("minor", "0"),
                    ("servicepack", "1"),
                ],
                Version::Fix50Sp2 => vec![
                    ("type", "FIX"),
                    ("major", "5"),
                    ("minor", "0"),
                    ("servicepack", "2"),
                ],
                Version::Fixt11 => vec![("type", "FIXT"), ("major", "1"), ("minor", "1")],
            }
        };

        for version in Version::ALL {
            let attrs: HashMap<String, String> = attrs_for(version)
                .into_iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect();
            assert_eq!(
                parse_version(&attrs),
                Ok(version),
                "{version} is not loadable from its QuickFIX XML attributes"
            );
        }
    }

    #[test]
    fn test_unsupported_version() {
        let xml = "<fix type='FIX' major='9' minor='9'><fields></fields></fix>";
        let err = Dictionary::from_quickfix_xml(xml).unwrap_err();
        assert!(matches!(err, DictionaryError::UnsupportedVersion(_)));
    }

    #[test]
    fn test_unknown_field_reference() {
        let xml = r"<fix type='FIX' major='4' minor='4'>
            <header><field name='DoesNotExist' required='Y'/></header>
            <trailer></trailer>
            <messages></messages>
            <fields></fields>
        </fix>";
        let err = Dictionary::from_quickfix_xml(xml).unwrap_err();
        assert_eq!(
            err,
            DictionaryError::UnknownFieldName("DoesNotExist".to_string())
        );
    }

    #[test]
    fn test_minimal_dialect() {
        let xml = r"<fix type='FIX' major='4' minor='4'>
            <header><field name='BeginString' required='Y'/></header>
            <trailer><field name='CheckSum' required='Y'/></trailer>
            <messages>
                <message name='Ping' msgtype='U1' msgcat='app'>
                    <field name='TestReqID' required='Y'/>
                </message>
            </messages>
            <fields>
                <field number='8' name='BeginString' type='STRING'/>
                <field number='10' name='CheckSum' type='STRING'/>
                <field number='112' name='TestReqID' type='STRING'/>
            </fields>
        </fix>";
        let dict = Dictionary::from_quickfix_xml(xml).unwrap();
        let ping = dict.get_message("U1").expect("custom message defined");
        assert_eq!(ping.name, "Ping");
        assert_eq!(ping.fields[0].tag, 112);
    }
}
