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
//!
//! # Untrusted input
//!
//! A dictionary file is parser input like any wire message, so the loader is
//! written to the same standard as the decoders: every malformed document
//! maps to a typed [`DictionaryError`], never to a panic, an unbounded
//! recursion, or an allocation sized from the document. Two ceilings bound
//! the work:
//!
//! - [`MAX_NESTING_DEPTH`] caps physical XML element nesting, so a file of
//!   deeply nested `<group>` elements is rejected instead of exhausting the
//!   stack.
//! - [`MAX_COMPONENT_DEPTH`] caps how far component references may chain.
//!
//! Reference cycles among components are rejected up front
//! ([`DictionaryError::ComponentCycle`]), dangling component references are
//! rejected ([`DictionaryError::UnknownComponent`]), and duplicate
//! definitions are rejected rather than silently overwriting each other
//! ([`DictionaryError::DuplicateDefinition`]).

use crate::schema::{
    ComponentDef, ComponentRef, Dictionary, FieldDef, FieldRef, FieldType, GroupDef,
    MessageCategory, MessageDef, Version,
};
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::OnceLock;

/// Maximum component reference chain length accepted by the loader.
///
/// A component whose expansion needs more than this many hops is rejected
/// with [`DictionaryError::NestingTooDeep`]; a component that references
/// itself, directly or transitively, is rejected with
/// [`DictionaryError::ComponentCycle`].
pub const MAX_COMPONENT_DEPTH: usize = 32;

/// Maximum physical XML element nesting depth accepted by the loader.
///
/// Bounds the loader's recursion over `<group>`, `<component>`, and
/// `<field>` elements so that a hostile document of deeply nested elements
/// is rejected with [`DictionaryError::NestingTooDeep`] instead of
/// overflowing the stack.
pub const MAX_NESTING_DEPTH: usize = 32;

/// Embedded QuickFIX FIX 4.4 specification.
///
/// Source: <https://github.com/quickfix/quickfix/blob/master/spec/FIX44.xml>
const FIX44_XML: &str = include_str!("../spec/FIX44.xml");

static FIX44_DICT: OnceLock<Result<Dictionary, DictionaryError>> = OnceLock::new();

/// The kind of definition a [`DictionaryError::DuplicateDefinition`] refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinitionKind {
    /// A `<field>` definition, keyed by name.
    Field,
    /// A `<message>` definition, keyed by `msgtype`.
    Message,
    /// A `<component>` definition, keyed by name.
    Component,
}

impl fmt::Display for DefinitionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Field => "field",
            Self::Message => "message",
            Self::Component => "component",
        };
        f.write_str(name)
    }
}

/// Errors produced while loading a dictionary from XML.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
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
    /// A component references itself, directly or through other components.
    #[error("component `{0}` is part of a reference cycle")]
    ComponentCycle(String),
    /// Elements or component references nest past the loader's ceiling.
    #[error("nesting too deep at `{element}` (limit {limit})")]
    NestingTooDeep {
        /// The element or component name at which the ceiling was reached.
        element: String,
        /// The ceiling that was exceeded.
        limit: usize,
    },
    /// A field declares a data type that is not a known FIX type.
    #[error("field `{field}` declares unknown type `{field_type}`")]
    UnknownFieldType {
        /// Name of the offending field.
        field: String,
        /// The unrecognised type name, as spelled in the document.
        field_type: String,
    },
    /// The same name or message type is defined more than once.
    #[error("duplicate {kind} definition `{name}`")]
    DuplicateDefinition {
        /// Which kind of definition was duplicated.
        kind: DefinitionKind,
        /// The duplicated name (or `msgtype`, for a message).
        name: String,
    },
    /// Two field definitions claim the same tag number.
    #[error("fields `{existing}` and `{duplicate}` both claim tag {tag}")]
    DuplicateFieldTag {
        /// The contested tag number.
        tag: u32,
        /// Name of the field that claimed the tag first.
        existing: String,
        /// Name of the field that claimed it again.
        duplicate: String,
    },
}

impl Dictionary {
    /// Returns the embedded standard FIX 4.4 dictionary.
    ///
    /// The dictionary is parsed from the bundled QuickFIX `FIX44.xml`
    /// specification on first use and cached for the lifetime of the
    /// process.
    ///
    /// FIX 4.4 is the only embedded dictionary. Every other version has to be
    /// supplied by the caller through [`Dictionary::from_quickfix_xml`].
    ///
    /// # Errors
    /// Returns [`DictionaryError`] if the bundled specification fails to
    /// load. That cannot happen for an unmodified checkout — `cargo test`
    /// loads it — so the result is a guarantee rather than a case callers
    /// are expected to recover from; it exists so that the crate has no
    /// panicking path at all.
    pub fn fix44() -> Result<&'static Self, DictionaryError> {
        match FIX44_DICT.get_or_init(|| load(FIX44_XML)) {
            Ok(dict) => Ok(dict),
            Err(err) => Err(err.clone()),
        }
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
        /// Whether the component is required at this reference.
        required: bool,
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
///
/// `depth` is the physical XML nesting depth of `end` itself; recursion is
/// refused past [`MAX_NESTING_DEPTH`], which is what keeps a hostile document
/// of nested `<group>` elements from exhausting the stack.
fn parse_items(
    reader: &mut Reader<&[u8]>,
    end: &[u8],
    depth: usize,
) -> Result<Vec<Item>, DictionaryError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(DictionaryError::NestingTooDeep {
            element: String::from_utf8_lossy(end).into_owned(),
            limit: MAX_NESTING_DEPTH,
        });
    }
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
                        required: is_required(&attrs),
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
                        let inner = parse_items(reader, b"group", depth + 1)?;
                        items.push(Item::Group {
                            name: required_attr(&attrs, "group", "name")?,
                            required: is_required(&attrs),
                            items: inner,
                        });
                    }
                    b"field" => {
                        // Field references never have meaningful children here.
                        parse_items(reader, b"field", depth + 1)?;
                        items.push(Item::Field {
                            name: required_attr(&attrs, "field", "name")?,
                            required: is_required(&attrs),
                        });
                    }
                    b"component" => {
                        parse_items(reader, b"component", depth + 1)?;
                        items.push(Item::Component {
                            name: required_attr(&attrs, "component", "name")?,
                            required: is_required(&attrs),
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
    let declared_type = required_attr(attrs, "field", "type")?;
    // An unrecognised type is rejected rather than quietly demoted to
    // STRING: the dictionary is what answers "what does this tag mean", and
    // a silent demotion would drop the field's format and enum semantics.
    let field_type =
        declared_type
            .parse::<FieldType>()
            .map_err(|_| DictionaryError::UnknownFieldType {
                field: name.clone(),
                field_type: declared_type.clone(),
            })?;

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
    ///
    /// Reference cycles are already rejected by [`check_component_graph`]
    /// before any resolution starts; the depth ceiling here is a second,
    /// independent bound on the recursion.
    fn first_tag(&self, items: &[Item], depth: usize) -> Result<Option<u32>, DictionaryError> {
        for item in items {
            match item {
                Item::Field { name, .. } | Item::Group { name, .. } => {
                    return self.tag(name).map(Some);
                }
                Item::Component { name, .. } => {
                    if depth >= MAX_COMPONENT_DEPTH {
                        return Err(DictionaryError::NestingTooDeep {
                            element: name.clone(),
                            limit: MAX_COMPONENT_DEPTH,
                        });
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

    /// Splits items into field references, resolved groups, and component
    /// references.
    ///
    /// Every component reference is existence-checked here, so a typo'd
    /// `<component name='Nope'/>` fails the load instead of silently
    /// disappearing from the schema at validation time.
    #[allow(clippy::type_complexity)]
    fn split(
        &self,
        items: &[Item],
    ) -> Result<(Vec<FieldRef>, Vec<GroupDef>, Vec<ComponentRef>), DictionaryError> {
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
                Item::Component { name, required } => {
                    if !self.components.contains_key(name) {
                        return Err(DictionaryError::UnknownComponent(name.clone()));
                    }
                    components.push(ComponentRef::new(name.clone(), *required));
                }
            }
        }
        Ok((fields, groups, components))
    }
}

/// Traversal state of a component during cycle detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VisitState {
    /// On the current depth-first path: reaching it again is a cycle.
    InProgress,
    /// Fully expanded already, and acyclic.
    Done,
}

/// Rejects reference cycles and dangling references in the component graph.
///
/// Runs before any resolution, so the rest of the loader (and every consumer
/// of the resulting [`Dictionary`]) can walk component references knowing the
/// graph is a DAG of bounded depth. Components are visited in document order
/// (`order`) and memoised, which keeps the walk linear in the number of
/// references.
fn check_component_graph(
    components: &HashMap<String, Vec<Item>>,
    order: &[String],
) -> Result<(), DictionaryError> {
    let mut state: HashMap<String, VisitState> = HashMap::new();
    for name in order {
        visit_component(name, components, &mut state, 0)?;
    }
    Ok(())
}

/// Depth-first visit of one component definition.
fn visit_component(
    name: &str,
    components: &HashMap<String, Vec<Item>>,
    state: &mut HashMap<String, VisitState>,
    depth: usize,
) -> Result<(), DictionaryError> {
    match state.get(name) {
        Some(VisitState::Done) => return Ok(()),
        Some(VisitState::InProgress) => {
            return Err(DictionaryError::ComponentCycle(name.to_string()));
        }
        None => {}
    }
    let Some(items) = components.get(name) else {
        return Err(DictionaryError::UnknownComponent(name.to_string()));
    };
    state.insert(name.to_string(), VisitState::InProgress);
    visit_items(items, components, state, depth + 1)?;
    state.insert(name.to_string(), VisitState::Done);
    Ok(())
}

/// Depth-first visit of a member list, descending into groups and components.
fn visit_items(
    items: &[Item],
    components: &HashMap<String, Vec<Item>>,
    state: &mut HashMap<String, VisitState>,
    depth: usize,
) -> Result<(), DictionaryError> {
    if depth > MAX_COMPONENT_DEPTH {
        return Err(DictionaryError::NestingTooDeep {
            element: "component".to_string(),
            limit: MAX_COMPONENT_DEPTH,
        });
    }
    for item in items {
        match item {
            Item::Field { .. } => {}
            Item::Group { items, .. } => visit_items(items, components, state, depth + 1)?,
            Item::Component { name, .. } => visit_component(name, components, state, depth)?,
        }
    }
    Ok(())
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
                b"header" => header_items = parse_items(&mut reader, b"header", 1)?,
                b"trailer" => trailer_items = parse_items(&mut reader, b"trailer", 1)?,
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
                        items: parse_items(&mut reader, b"message", 1)?,
                    });
                }
                b"component" => {
                    let attrs = attr_map(&e)?;
                    let name = required_attr(&attrs, "component", "name")?;
                    let items = parse_items(&mut reader, b"component", 1)?;
                    if component_irs.contains_key(&name) {
                        return Err(DictionaryError::DuplicateDefinition {
                            kind: DefinitionKind::Component,
                            name,
                        });
                    }
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

    check_component_graph(&component_irs, &component_order)?;

    let mut dict = Dictionary::new(version);
    for def in field_defs {
        // Last-wins insertion would leave name and tag lookups pointing at
        // different definitions, so a duplicate is a load error.
        if dict.fields_by_name.contains_key(&def.name) {
            return Err(DictionaryError::DuplicateDefinition {
                kind: DefinitionKind::Field,
                name: def.name,
            });
        }
        if let Some(existing) = dict.get_field(def.tag) {
            return Err(DictionaryError::DuplicateFieldTag {
                tag: def.tag,
                existing: existing.name.clone(),
                duplicate: def.name,
            });
        }
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
        let items = component_irs
            .get(name)
            .ok_or_else(|| DictionaryError::UnknownComponent(name.clone()))?;
        let (fields, groups, nested) = resolver.split(items)?;
        components.push(ComponentDef {
            name: name.clone(),
            fields,
            groups,
            components: nested,
        });
    }

    let mut messages = Vec::with_capacity(message_irs.len());
    let mut seen_msg_types: HashSet<&str> = HashSet::new();
    for ir in &message_irs {
        if !seen_msg_types.insert(ir.msg_type.as_str()) {
            return Err(DictionaryError::DuplicateDefinition {
                kind: DefinitionKind::Message,
                name: ir.msg_type.clone(),
            });
        }
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
    use std::fmt::Debug;

    /// Unwraps a `Result` with test context instead of `.unwrap()`.
    #[track_caller]
    fn ok<T, E: Debug>(result: Result<T, E>, what: &str) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("{what}: {err:?}"),
        }
    }

    /// Unwraps an `Option` with test context instead of `.expect()`.
    #[track_caller]
    fn some<T>(value: Option<T>, what: &str) -> T {
        match value {
            Some(value) => value,
            None => panic!("{what}"),
        }
    }

    /// Returns the error a load is expected to fail with.
    #[track_caller]
    fn load_err(xml: &str) -> DictionaryError {
        match Dictionary::from_quickfix_xml(xml) {
            Ok(_) => panic!("expected the dictionary to be rejected, but it loaded"),
            Err(err) => err,
        }
    }

    /// Returns the embedded FIX 4.4 dictionary for a test.
    #[track_caller]
    fn fix44() -> &'static Dictionary {
        ok(Dictionary::fix44(), "embedded FIX 4.4 dictionary loads")
    }

    #[test]
    fn test_fix44_loads() {
        let dict = fix44();
        assert_eq!(dict.version, Version::Fix44);

        // Cached: same instance on every call.
        assert!(std::ptr::eq(dict, fix44()));
    }

    #[test]
    fn test_fix44_fields() {
        let dict = fix44();

        let msg_type = some(dict.get_field(35), "MsgType defined");
        assert_eq!(msg_type.name, "MsgType");

        let cl_ord_id = some(dict.get_field_by_name("ClOrdID"), "ClOrdID defined");
        assert_eq!(cl_ord_id.tag, 11);

        let side = some(dict.get_field(54), "Side defined");
        let values = some(side.values.as_ref(), "Side has enum values");
        assert!(values.contains_key("1"));
        assert!(values.contains_key("2"));
        assert!(!values.contains_key("X"));
    }

    #[test]
    fn test_fix44_multiple_value_string_fields_keep_their_type() {
        // The vendored FIX 4.4 dictionary spells this type
        // `MULTIPLEVALUESTRING`; every one of its eight fields must survive
        // the load as `MultipleStringValue`, not as a plain String.
        let dict = fix44();
        for (tag, name) in [
            (18, "ExecInst"),
            (276, "QuoteCondition"),
            (277, "TradeCondition"),
            (286, "OpenCloseSettlFlag"),
            (291, "FinancialStatus"),
            (292, "CorporateAction"),
            (529, "OrderRestrictions"),
            (546, "Scope"),
        ] {
            let def = some(dict.get_field(tag), "multi-value field defined");
            assert_eq!(def.name, name);
            assert_eq!(
                def.field_type,
                FieldType::MultipleStringValue,
                "{name}({tag}) lost its multi-value type"
            );
        }
    }

    #[test]
    fn test_fix44_header_and_trailer() {
        let dict = fix44();

        let sender = some(
            dict.header.iter().find(|f| f.name == "SenderCompID"),
            "SenderCompID in header",
        );
        assert_eq!(sender.tag, 49);
        assert!(sender.required);

        let hops = some(
            dict.header_groups.iter().find(|g| g.name == "NoHops"),
            "NoHops group in header",
        );
        assert_eq!(hops.count_tag, 627);
        assert_eq!(hops.delimiter_tag, 628);
        assert!(!hops.required);

        let checksum = some(
            dict.trailer.iter().find(|f| f.name == "CheckSum"),
            "CheckSum in trailer",
        );
        assert_eq!(checksum.tag, 10);
        assert!(checksum.required);
    }

    #[test]
    fn test_fix44_messages() {
        let dict = fix44();

        let nos = some(dict.get_message("D"), "NewOrderSingle defined");
        assert_eq!(nos.name, "NewOrderSingle");
        assert_eq!(nos.category, MessageCategory::App);
        assert!(nos.fields.iter().any(|f| f.name == "ClOrdID" && f.required));
        assert!(nos.components.iter().any(|c| c.name == "Instrument"));

        let heartbeat = some(dict.get_message("0"), "Heartbeat defined");
        assert_eq!(heartbeat.category, MessageCategory::Admin);
    }

    #[test]
    fn test_fix44_component_references_keep_their_required_flag() {
        let dict = fix44();

        // NewOrderSingle requires <component name='Instrument' required='Y'/>
        // but only optionally carries Parties.
        let nos = some(dict.get_message("D"), "NewOrderSingle defined");
        let instrument = some(
            nos.components.iter().find(|c| c.name == "Instrument"),
            "NewOrderSingle references Instrument",
        );
        assert!(instrument.required);
        let parties = some(
            nos.components.iter().find(|c| c.name == "Parties"),
            "NewOrderSingle references Parties",
        );
        assert!(!parties.required);
    }

    #[test]
    fn test_fix44_components_and_groups() {
        let dict = fix44();

        let instrument = some(dict.get_component("Instrument"), "Instrument defined");
        assert!(instrument.fields.iter().any(|f| f.name == "Symbol"));

        let parties = some(dict.get_component("Parties"), "Parties defined");
        let no_party_ids = some(
            parties.groups.iter().find(|g| g.name == "NoPartyIDs"),
            "NoPartyIDs group",
        );
        assert_eq!(no_party_ids.count_tag, 453);
        assert_eq!(no_party_ids.delimiter_tag, 448);
        // Nested component reference within the group.
        assert!(
            no_party_ids
                .components
                .iter()
                .any(|c| c.name == "PtysSubGrp")
        );
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
    fn test_unsupported_version_is_rejected() {
        let xml = "<fix type='FIX' major='9' minor='9'><fields></fields></fix>";
        assert!(matches!(
            load_err(xml),
            DictionaryError::UnsupportedVersion(_)
        ));
    }

    #[test]
    fn test_missing_attribute_is_rejected() {
        let xml = r"<fix type='FIX' major='4' minor='4'>
            <header></header><trailer></trailer><messages></messages>
            <fields><field number='8' type='STRING'/></fields>
        </fix>";
        assert_eq!(
            load_err(xml),
            DictionaryError::MissingAttribute {
                element: "field".to_string(),
                attribute: "name".to_string(),
            }
        );
    }

    #[test]
    fn test_non_numeric_field_number_is_rejected() {
        let xml = r"<fix type='FIX' major='4' minor='4'>
            <header></header><trailer></trailer><messages></messages>
            <fields><field number='8x' name='BeginString' type='STRING'/></fields>
        </fix>";
        assert_eq!(load_err(xml), DictionaryError::InvalidTag("8x".to_string()));
    }

    #[test]
    fn test_unknown_field_reference_is_rejected() {
        let xml = r"<fix type='FIX' major='4' minor='4'>
            <header><field name='DoesNotExist' required='Y'/></header>
            <trailer></trailer>
            <messages></messages>
            <fields></fields>
        </fix>";
        assert_eq!(
            load_err(xml),
            DictionaryError::UnknownFieldName("DoesNotExist".to_string())
        );
    }

    #[test]
    fn test_unknown_field_type_is_rejected() {
        let xml = r"<fix type='FIX' major='4' minor='4'>
            <header></header><trailer></trailer><messages></messages>
            <fields>
                <field number='8' name='BeginString' type='NOTATYPE'/>
            </fields>
        </fix>";
        assert_eq!(
            load_err(xml),
            DictionaryError::UnknownFieldType {
                field: "BeginString".to_string(),
                field_type: "NOTATYPE".to_string(),
            }
        );
    }

    #[test]
    fn test_dangling_component_reference_is_rejected() {
        let xml = r"<fix type='FIX' major='4' minor='4'>
            <header></header>
            <trailer></trailer>
            <messages>
                <message name='Ping' msgtype='U1' msgcat='app'>
                    <component name='Nope' required='N'/>
                </message>
            </messages>
            <components></components>
            <fields>
                <field number='112' name='TestReqID' type='STRING'/>
            </fields>
        </fix>";
        assert_eq!(
            load_err(xml),
            DictionaryError::UnknownComponent("Nope".to_string())
        );
    }

    #[test]
    fn test_dangling_component_reference_inside_a_component_is_rejected() {
        let xml = r"<fix type='FIX' major='4' minor='4'>
            <header></header>
            <trailer></trailer>
            <messages></messages>
            <components>
                <component name='Outer'>
                    <component name='Nope' required='N'/>
                </component>
            </components>
            <fields>
                <field number='112' name='TestReqID' type='STRING'/>
            </fields>
        </fix>";
        assert_eq!(
            load_err(xml),
            DictionaryError::UnknownComponent("Nope".to_string())
        );
    }

    #[test]
    fn test_component_cycle_is_rejected() {
        // Two components that reference each other. Nothing here reaches a
        // field, so the cycle has to be caught by the graph check rather
        // than by delimiter discovery.
        let xml = r"<fix type='FIX' major='4' minor='4'>
            <header></header>
            <trailer></trailer>
            <messages></messages>
            <components>
                <component name='Ping'>
                    <component name='Pong' required='N'/>
                </component>
                <component name='Pong'>
                    <component name='Ping' required='N'/>
                </component>
            </components>
            <fields>
                <field number='112' name='TestReqID' type='STRING'/>
            </fields>
        </fix>";
        assert!(matches!(load_err(xml), DictionaryError::ComponentCycle(_)));
    }

    #[test]
    fn test_self_referential_component_is_rejected() {
        let xml = r"<fix type='FIX' major='4' minor='4'>
            <header></header>
            <trailer></trailer>
            <messages></messages>
            <components>
                <component name='Loop'>
                    <field name='TestReqID' required='N'/>
                    <component name='Loop' required='N'/>
                </component>
            </components>
            <fields>
                <field number='112' name='TestReqID' type='STRING'/>
            </fields>
        </fix>";
        assert_eq!(
            load_err(xml),
            DictionaryError::ComponentCycle("Loop".to_string())
        );
    }

    #[test]
    fn test_empty_group_is_rejected() {
        let xml = r"<fix type='FIX' major='4' minor='4'>
            <header></header>
            <trailer></trailer>
            <messages>
                <message name='Ping' msgtype='U1' msgcat='app'>
                    <group name='NoPartyIDs' required='N'></group>
                </message>
            </messages>
            <fields>
                <field number='453' name='NoPartyIDs' type='NUMINGROUP'/>
            </fields>
        </fix>";
        assert_eq!(
            load_err(xml),
            DictionaryError::EmptyGroup("NoPartyIDs".to_string())
        );
    }

    #[test]
    fn test_deeply_nested_groups_are_rejected_without_stack_overflow() {
        // A hostile document: element nesting far past the ceiling. This must
        // come back as a typed error rather than exhausting the stack.
        let depth = MAX_NESTING_DEPTH * 100;
        let mut xml = String::from(
            "<fix type='FIX' major='4' minor='4'><header></header><trailer></trailer>\
             <messages><message name='Ping' msgtype='U1' msgcat='app'>",
        );
        for _ in 0..depth {
            xml.push_str("<group name='NoPartyIDs' required='N'>");
        }
        xml.push_str("<field name='TestReqID' required='N'/>");
        for _ in 0..depth {
            xml.push_str("</group>");
        }
        xml.push_str("</message></messages><fields></fields></fix>");

        assert_eq!(
            load_err(&xml),
            DictionaryError::NestingTooDeep {
                element: "group".to_string(),
                limit: MAX_NESTING_DEPTH,
            }
        );
    }

    #[test]
    fn test_long_component_chain_is_rejected() {
        // A chain of components longer than the component ceiling: acyclic,
        // so only the depth bound stops it.
        let mut xml = String::from(
            "<fix type='FIX' major='4' minor='4'><header></header><trailer></trailer>\
             <messages></messages><components>",
        );
        let links = MAX_COMPONENT_DEPTH + 10;
        for index in 0..links {
            xml.push_str(&format!("<component name='C{index}'>"));
            xml.push_str(&format!("<component name='C{}' required='N'/>", index + 1));
            xml.push_str("</component>");
        }
        xml.push_str(&format!(
            "<component name='C{links}'><field name='TestReqID' required='N'/></component>"
        ));
        xml.push_str(
            "</components><fields><field number='112' name='TestReqID' type='STRING'/></fields></fix>",
        );

        assert!(matches!(
            load_err(&xml),
            DictionaryError::NestingTooDeep {
                limit: MAX_COMPONENT_DEPTH,
                ..
            }
        ));
    }

    #[test]
    fn test_duplicate_field_name_is_rejected() {
        let xml = r"<fix type='FIX' major='4' minor='4'>
            <header></header><trailer></trailer><messages></messages>
            <fields>
                <field number='112' name='TestReqID' type='STRING'/>
                <field number='113' name='TestReqID' type='STRING'/>
            </fields>
        </fix>";
        assert_eq!(
            load_err(xml),
            DictionaryError::DuplicateDefinition {
                kind: DefinitionKind::Field,
                name: "TestReqID".to_string(),
            }
        );
    }

    #[test]
    fn test_duplicate_field_tag_is_rejected() {
        let xml = r"<fix type='FIX' major='4' minor='4'>
            <header></header><trailer></trailer><messages></messages>
            <fields>
                <field number='112' name='TestReqID' type='STRING'/>
                <field number='112' name='OtherName' type='STRING'/>
            </fields>
        </fix>";
        assert_eq!(
            load_err(xml),
            DictionaryError::DuplicateFieldTag {
                tag: 112,
                existing: "TestReqID".to_string(),
                duplicate: "OtherName".to_string(),
            }
        );
    }

    #[test]
    fn test_duplicate_message_type_is_rejected() {
        let xml = r"<fix type='FIX' major='4' minor='4'>
            <header></header><trailer></trailer>
            <messages>
                <message name='Ping' msgtype='U1' msgcat='app'>
                    <field name='TestReqID' required='Y'/>
                </message>
                <message name='Pong' msgtype='U1' msgcat='app'>
                    <field name='TestReqID' required='Y'/>
                </message>
            </messages>
            <fields><field number='112' name='TestReqID' type='STRING'/></fields>
        </fix>";
        assert_eq!(
            load_err(xml),
            DictionaryError::DuplicateDefinition {
                kind: DefinitionKind::Message,
                name: "U1".to_string(),
            }
        );
    }

    #[test]
    fn test_duplicate_component_name_is_rejected() {
        let xml = r"<fix type='FIX' major='4' minor='4'>
            <header></header><trailer></trailer><messages></messages>
            <components>
                <component name='Twice'>
                    <field name='TestReqID' required='N'/>
                </component>
                <component name='Twice'>
                    <field name='TestReqID' required='N'/>
                </component>
            </components>
            <fields><field number='112' name='TestReqID' type='STRING'/></fields>
        </fix>";
        assert_eq!(
            load_err(xml),
            DictionaryError::DuplicateDefinition {
                kind: DefinitionKind::Component,
                name: "Twice".to_string(),
            }
        );
    }

    #[test]
    fn test_malformed_xml_is_rejected() {
        let xml = "<fix type='FIX' major='4' minor='4'><header>";
        assert!(matches!(load_err(xml), DictionaryError::Xml(_)));
    }

    #[test]
    fn test_minimal_dialect_loads() {
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
        let dict = ok(Dictionary::from_quickfix_xml(xml), "dialect loads");
        let ping = some(dict.get_message("U1"), "custom message defined");
        assert_eq!(ping.name, "Ping");
        assert_eq!(some(ping.fields.first(), "Ping has a field").tag, 112);
    }
}
