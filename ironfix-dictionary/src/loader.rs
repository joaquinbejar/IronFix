/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 12/7/26
******************************************************************************/

//! QuickFIX XML dictionary loader.
//!
//! This module parses QuickFIX-format XML specifications (e.g. `FIX44.xml`)
//! into a [`Dictionary`], and exposes four embedded dictionaries, each
//! vendored verbatim from QuickFIX (see `spec/README.md` for provenance and
//! `spec/LICENSE-QUICKFIX` for the license):
//!
//! | Constructor | Vendored file | [`Version`] |
//! |---|---|---|
//! | [`Dictionary::fix42`] | `FIX42.xml` | [`Version::Fix42`] |
//! | [`Dictionary::fix44`] | `FIX44.xml` | [`Version::Fix44`] |
//! | [`Dictionary::fixt11`] | `FIXT11.xml` | [`Version::Fixt11`] |
//! | [`Dictionary::fix50sp2`] | `FIX50SP2.xml` | [`Version::Fix50Sp2`] |
//!
//! `FIXT11.xml` is a *transport* dictionary (session header, trailer, and
//! admin messages) and `FIX50SP2.xml` an *application* dictionary with an
//! empty header and trailer; QuickFIX ships FIX 5.0 that way, and
//! [`SessionDictionary`](crate::SessionDictionary) composes the two.
//!
//! Every other version (FIX 4.0, 4.1, 4.3, 5.0, 5.0 SP1), and any
//! venue-specific dialect, is loaded from caller-supplied QuickFIX XML with
//! [`Dictionary::from_quickfix_xml`].
//!
//! The QuickFIX Software License, Version 1.0, requires this
//! acknowledgement wherever the embedded files are redistributed:
//!
//! > This product includes software developed by quickfixengine.org
//! > (<http://www.quickfixengine.org/>).
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

use crate::orchestra::OrchestraKind;
use crate::schema::{
    ComponentDef, ComponentRef, Dictionary, FieldDef, FieldRef, FieldType, GroupDef, Member,
    MessageCategory, MessageDef, Version,
};
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use std::cell::RefCell;
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

// Every embedded specification below is a byte-for-byte copy of
// `spec/<FILE>` from quickfix/quickfix at commit
// 386ce46e917ae494ab6e90b1be90fd421cdbe3f9; `spec/README.md` records each
// file's SHA-256. Never edit them to make a test pass.

/// Embedded QuickFIX FIX 4.2 specification (`spec/FIX42.xml`).
const FIX42_XML: &str = include_str!("../spec/FIX42.xml");

/// Embedded QuickFIX FIX 4.4 specification (`spec/FIX44.xml`).
const FIX44_XML: &str = include_str!("../spec/FIX44.xml");

/// Embedded QuickFIX FIXT 1.1 transport specification (`spec/FIXT11.xml`).
const FIXT11_XML: &str = include_str!("../spec/FIXT11.xml");

/// Embedded QuickFIX FIX 5.0 SP2 application specification
/// (`spec/FIX50SP2.xml`).
const FIX50SP2_XML: &str = include_str!("../spec/FIX50SP2.xml");

/// Parse-once cache of one embedded specification.
///
/// The load result, error included, is cached: an embedded file that failed
/// once would fail identically on every retry.
type EmbeddedCell = OnceLock<Result<Dictionary, DictionaryError>>;

static FIX42_DICT: EmbeddedCell = OnceLock::new();
static FIX44_DICT: EmbeddedCell = OnceLock::new();
static FIXT11_DICT: EmbeddedCell = OnceLock::new();
static FIX50SP2_DICT: EmbeddedCell = OnceLock::new();

/// Returns the dictionary cached in `cell`, parsing `xml` on first use.
fn embedded(
    cell: &'static EmbeddedCell,
    xml: &str,
) -> Result<&'static Dictionary, DictionaryError> {
    match cell.get_or_init(|| load(xml)) {
        Ok(dict) => Ok(dict),
        Err(err) => Err(err.clone()),
    }
}

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

/// Errors produced while loading or composing dictionaries.
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
    /// A transport and an application dictionary cannot be composed into a
    /// [`SessionDictionary`](crate::SessionDictionary).
    ///
    /// The transport side must be a FIXT.1.1 dictionary, and the application
    /// side any version FIXT.1.1 carries (FIX 4.0 through 5.0 SP2), which is
    /// every version except FIXT.1.1 itself.
    #[error(
        "cannot compose a {transport} transport dictionary with a {application} application dictionary: the transport must be FIXT.1.1 and the application must not be"
    )]
    IncompatibleComposition {
        /// Version of the dictionary offered as the transport.
        transport: Version,
        /// Version of the dictionary offered as the application.
        application: Version,
    },
    /// The document is not a FIX Orchestra 1.0 repository: its root element
    /// is not `repository` in the
    /// [`ORCHESTRA_NAMESPACE`](crate::orchestra::ORCHESTRA_NAMESPACE).
    #[error("not a FIX Orchestra 1.0 repository: the root element is {0}")]
    NotOrchestra(String),
    /// The document is longer than the loader accepts
    /// ([`MAX_ORCHESTRA_DOCUMENT_LEN`](crate::orchestra::MAX_ORCHESTRA_DOCUMENT_LEN)).
    #[error("the document is {len} bytes, over the {limit}-byte limit")]
    DocumentTooLarge {
        /// Length of the document, in bytes.
        len: usize,
        /// The limit, in bytes.
        limit: usize,
    },
    /// The attributes of one element are longer than the loader accepts
    /// ([`MAX_ORCHESTRA_ATTRIBUTES_LEN`](crate::orchestra::MAX_ORCHESTRA_ATTRIBUTES_LEN)).
    #[error("the attributes of <{element}> are {len} bytes, over the {limit}-byte limit")]
    AttributesTooLong {
        /// The element, as written in the document.
        element: String,
        /// Length of its attributes, in bytes.
        len: usize,
        /// The limit, in bytes.
        limit: usize,
    },
    /// An Orchestra `id` is not a positive integer that fits a `u32`.
    #[error("invalid id `{value}` on <{element}>")]
    InvalidOrchestraId {
        /// The element carrying the id.
        element: String,
        /// The id, as written in the document.
        value: String,
    },
    /// An Orchestra reference names an id that no definition in the `base`
    /// scenario has.
    #[error("{owner} references {kind} id {id}, which is not defined")]
    UnknownOrchestraReference {
        /// The kind of definition referenced.
        kind: OrchestraKind,
        /// The referenced id.
        id: u32,
        /// The definition holding the reference.
        owner: String,
    },
    /// Two Orchestra definitions share an id or a name that must be unique.
    #[error("duplicate {kind} `{key}`")]
    DuplicateOrchestraDefinition {
        /// The kind of the duplicated definitions.
        kind: OrchestraKind,
        /// The shared id or name.
        key: String,
    },
    /// A code set names a datatype that is not declared or maps to no FIX
    /// data type.
    #[error("{owner} names datatype `{datatype}`, which maps to no FIX data type")]
    UnknownDatatype {
        /// The definition naming the datatype.
        owner: String,
        /// The datatype name, as written in the document.
        datatype: String,
    },
    /// An Orchestra repeating group has no count field (`numInGroup`).
    #[error("group `{0}` has no numInGroup count field")]
    MissingCountField(String),
    /// An Orchestra repeating group contains itself, directly or through
    /// other groups.
    #[error("group `{0}` is part of a reference cycle")]
    GroupCycle(String),
    /// Expanding the group references of an Orchestra repository would
    /// produce more members than the loader accepts
    /// ([`MAX_ORCHESTRA_MEMBERS`](crate::orchestra::MAX_ORCHESTRA_MEMBERS)).
    #[error("expanding the groups produces more than {limit} members")]
    TooManyMembers {
        /// The limit, in members.
        limit: usize,
    },
    /// An element name, an attribute name, or an attribute value the
    /// Orchestra loader keeps is longer than
    /// [`MAX_ORCHESTRA_NAME_LEN`](crate::orchestra::MAX_ORCHESTRA_NAME_LEN).
    #[error("{what} is {len} bytes, over the {limit}-byte limit")]
    NameTooLong {
        /// What is too long, without the text itself (for example "the value
        /// of attribute `name` of <fixr:field>").
        what: String,
        /// Its length, in bytes.
        len: usize,
        /// The limit, in bytes.
        limit: usize,
    },
    /// Copying an Orchestra repository's code sets onto the fields that name
    /// them would produce more enumeration values than the loader accepts
    /// ([`MAX_ORCHESTRA_FIELD_VALUES`](crate::orchestra::MAX_ORCHESTRA_FIELD_VALUES)).
    #[error("the fields' enumerations hold more than {limit} values")]
    TooManyFieldValues {
        /// The limit, in values over every field.
        limit: usize,
    },
    /// An Orchestra repository holds more constructs the dictionary cannot
    /// hold than the report accepts
    /// ([`MAX_ORCHESTRA_REPORT_ENTRIES`](crate::orchestra::MAX_ORCHESTRA_REPORT_ENTRIES)).
    #[error("more than {limit} unmapped constructs")]
    TooManyUnmapped {
        /// The limit, in report entries.
        limit: usize,
    },
    /// The Orchestra standard header or trailer component is referenced from
    /// a component or a group; only a message's own members may reference
    /// it, which is where the dictionary's header and trailer apply.
    #[error("{owner} references the {component} component, which only a message may reference")]
    EnvelopeReference {
        /// `StandardHeader` or `StandardTrailer`.
        component: String,
        /// The definition holding the reference.
        owner: String,
    },
}

impl Dictionary {
    /// Returns the embedded standard FIX 4.2 dictionary.
    ///
    /// Parsed from the vendored QuickFIX `FIX42.xml` on first use and cached
    /// for the lifetime of the process; every call returns the same
    /// instance.
    ///
    /// # Errors
    /// Returns [`DictionaryError`] if the bundled specification fails to
    /// load. That cannot happen for an unmodified checkout (`cargo test`
    /// loads it), so the result is a guarantee rather than a case callers
    /// are expected to recover from; it exists so that the crate has no
    /// panicking path at all.
    pub fn fix42() -> Result<&'static Self, DictionaryError> {
        embedded(&FIX42_DICT, FIX42_XML)
    }

    /// Returns the embedded standard FIX 4.4 dictionary.
    ///
    /// Parsed from the vendored QuickFIX `FIX44.xml` on first use and cached
    /// for the lifetime of the process; every call returns the same
    /// instance.
    ///
    /// # Errors
    /// Returns [`DictionaryError`] if the bundled specification fails to
    /// load. That cannot happen for an unmodified checkout (`cargo test`
    /// loads it), so the result is a guarantee rather than a case callers
    /// are expected to recover from; it exists so that the crate has no
    /// panicking path at all.
    pub fn fix44() -> Result<&'static Self, DictionaryError> {
        embedded(&FIX44_DICT, FIX44_XML)
    }

    /// Returns the embedded FIXT 1.1 transport dictionary.
    ///
    /// Parsed from the vendored QuickFIX `FIXT11.xml` on first use and cached
    /// for the lifetime of the process; every call returns the same
    /// instance.
    ///
    /// This is a *transport* dictionary: it defines the FIXT.1.1 standard
    /// header and trailer and the session-level (admin) messages, but no
    /// application messages. Pair it with an application dictionary such as
    /// [`Dictionary::fix50sp2`] through
    /// [`SessionDictionary`](crate::SessionDictionary).
    ///
    /// **Upstream deviation.** FIXT 1.1 defines the Logon `MsgTypeGrp`
    /// component as the `NoMsgTypes(384)` group (`RefMsgType(372)`,
    /// `MsgDirection(385)`, `RefApplVerID(1130)`, `RefApplExtID(1406)`,
    /// `RefCstmApplVerID(1131)`, `DefaultVerIndicator(1410)`). The vendored
    /// QuickFIX file defines `MsgTypeGrp` with no members and does not define
    /// tags 384 or 385, so the validator reports a Logon carrying the group
    /// ([`ValidationError::UnknownTag`](crate::ValidationError::UnknownTag)
    /// for 384). The file is not patched; to accept the group, load a FIXT 1.1
    /// dictionary that defines it with [`Dictionary::from_quickfix_xml`].
    ///
    /// # Errors
    /// Returns [`DictionaryError`] if the bundled specification fails to
    /// load. That cannot happen for an unmodified checkout (`cargo test`
    /// loads it), so the result is a guarantee rather than a case callers
    /// are expected to recover from; it exists so that the crate has no
    /// panicking path at all.
    pub fn fixt11() -> Result<&'static Self, DictionaryError> {
        embedded(&FIXT11_DICT, FIXT11_XML)
    }

    /// Returns the embedded FIX 5.0 SP2 application dictionary.
    ///
    /// Parsed from the vendored QuickFIX `FIX50SP2.xml` on first use and
    /// cached for the lifetime of the process; every call returns the same
    /// instance.
    ///
    /// This is an *application* dictionary: its header and trailer are
    /// empty and it defines no session-level messages, because FIX 5.0 runs
    /// over a FIXT.1.1 session. Validating a complete message against it
    /// alone therefore reports every header tag as not allowed; compose it
    /// with [`Dictionary::fixt11`] through
    /// [`SessionDictionary`](crate::SessionDictionary) instead.
    ///
    /// # Errors
    /// Returns [`DictionaryError`] if the bundled specification fails to
    /// load. That cannot happen for an unmodified checkout (`cargo test`
    /// loads it), so the result is a guarantee rather than a case callers
    /// are expected to recover from; it exists so that the crate has no
    /// panicking path at all.
    pub fn fix50sp2() -> Result<&'static Self, DictionaryError> {
        embedded(&FIX50SP2_DICT, FIX50SP2_XML)
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
///
/// Shared with the Orchestra loader ([`crate::orchestra`]), which resolves
/// its id references into these name references and hands them to the same
/// [`assemble`] step.
#[derive(Debug)]
pub(crate) enum Item {
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
pub(crate) struct MessageIr {
    /// Message name.
    pub(crate) name: String,
    /// Message type (tag 35).
    pub(crate) msg_type: String,
    /// Admin or application message.
    pub(crate) category: MessageCategory,
    /// Members, in document order.
    pub(crate) items: Vec<Item>,
}

impl MessageIr {
    /// Builds a message from its element attributes and parsed members.
    fn new(attrs: &HashMap<String, String>, items: Vec<Item>) -> Result<Self, DictionaryError> {
        let category = if attrs.get("msgcat").map(String::as_str) == Some("admin") {
            MessageCategory::Admin
        } else {
            MessageCategory::App
        };
        Ok(Self {
            name: required_attr(attrs, "message", "name")?,
            msg_type: required_attr(attrs, "message", "msgtype")?,
            category,
            items,
        })
    }
}

/// Component definitions collected from the `<components>` section, in
/// declaration order.
#[derive(Default)]
pub(crate) struct ComponentIrs {
    /// Members of each component, keyed by name.
    items: HashMap<String, Vec<Item>>,
    /// Component names in declaration order.
    order: Vec<String>,
}

impl ComponentIrs {
    /// Registers one component definition, rejecting a duplicate name.
    pub(crate) fn define(&mut self, name: String, items: Vec<Item>) -> Result<(), DictionaryError> {
        if self.items.contains_key(&name) {
            return Err(DictionaryError::DuplicateDefinition {
                kind: DefinitionKind::Component,
                name,
            });
        }
        self.order.push(name.clone());
        self.items.insert(name, items);
        Ok(())
    }
}

fn xml_err(e: impl std::fmt::Display) -> DictionaryError {
    DictionaryError::Xml(e.to_string())
}

fn attr_map(e: &BytesStart<'_>) -> Result<HashMap<String, String>, DictionaryError> {
    let mut map = HashMap::new();
    for attr in e.attributes() {
        let attr = attr.map_err(xml_err)?;
        let key = attr.key.as_ref().to_owned();
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
    end: &str,
    depth: usize,
) -> Result<Vec<Item>, DictionaryError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(DictionaryError::NestingTooDeep {
            element: end.to_owned(),
            limit: MAX_NESTING_DEPTH,
        });
    }
    let mut items = Vec::new();
    loop {
        match reader.read_event().map_err(xml_err)? {
            Event::Empty(e) => {
                let attrs = attr_map(&e)?;
                match e.name().as_ref() {
                    "field" => items.push(Item::Field {
                        name: required_attr(&attrs, "field", "name")?,
                        required: is_required(&attrs),
                    }),
                    "component" => items.push(Item::Component {
                        name: required_attr(&attrs, "component", "name")?,
                        required: is_required(&attrs),
                    }),
                    "group" => items.push(Item::Group {
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
                    "group" => {
                        let inner = parse_items(reader, "group", depth + 1)?;
                        items.push(Item::Group {
                            name: required_attr(&attrs, "group", "name")?,
                            required: is_required(&attrs),
                            items: inner,
                        });
                    }
                    "field" => {
                        // Field references never have meaningful children here.
                        parse_items(reader, "field", depth + 1)?;
                        items.push(Item::Field {
                            name: required_attr(&attrs, "field", "name")?,
                            required: is_required(&attrs),
                        });
                    }
                    "component" => {
                        parse_items(reader, "component", depth + 1)?;
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
            Event::Empty(e) if e.name().as_ref() == "field" => {
                defs.push(field_def(&attr_map(&e)?, HashMap::new())?);
            }
            Event::Start(e) if e.name().as_ref() == "field" => {
                let attrs = attr_map(&e)?;
                let mut values = HashMap::new();
                loop {
                    match reader.read_event().map_err(xml_err)? {
                        Event::Empty(v) | Event::Start(v) if v.name().as_ref() == "value" => {
                            let value_attrs = attr_map(&v)?;
                            let enum_value = required_attr(&value_attrs, "value", "enum")?;
                            let description =
                                value_attrs.get("description").cloned().unwrap_or_default();
                            values.insert(enum_value, description);
                        }
                        Event::End(v) if v.name().as_ref() == "field" => break,
                        Event::Eof => {
                            return Err(DictionaryError::Xml("unexpected end of file".to_string()));
                        }
                        _ => {}
                    }
                }
                defs.push(field_def(&attrs, values)?);
            }
            Event::End(e) if e.name().as_ref() == "fields" => return Ok(defs),
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
    /// The first tag of each component already walked, so a component
    /// reached many times (every group whose first member it is, every path
    /// through a chain of components) is walked once.
    first_tags: RefCell<HashMap<String, Option<u32>>>,
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
    /// independent bound on the recursion. Each component's first tag is
    /// computed once ([`Self::component_first_tag`]), so the walk is linear
    /// in the number of component references even where a component without
    /// fields leads to the same component along many paths.
    fn first_tag(&self, items: &[Item], depth: usize) -> Result<Option<u32>, DictionaryError> {
        for item in items {
            match item {
                Item::Field { name, .. } | Item::Group { name, .. } => {
                    return self.tag(name).map(Some);
                }
                Item::Component { name, .. } => {
                    if let Some(tag) = self.component_first_tag(name, depth)? {
                        return Ok(Some(tag));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Returns the first tag of component `name`, computing it once.
    fn component_first_tag(
        &self,
        name: &str,
        depth: usize,
    ) -> Result<Option<u32>, DictionaryError> {
        let cached = self.first_tags.borrow().get(name).copied();
        if let Some(tag) = cached {
            return Ok(tag);
        }
        if depth >= MAX_COMPONENT_DEPTH {
            return Err(DictionaryError::NestingTooDeep {
                element: name.to_owned(),
                limit: MAX_COMPONENT_DEPTH,
            });
        }
        let inner = self
            .components
            .get(name)
            .ok_or_else(|| DictionaryError::UnknownComponent(name.to_owned()))?;
        let tag = self.first_tag(inner, depth + 1)?;
        self.first_tags.borrow_mut().insert(name.to_owned(), tag);
        Ok(tag)
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
        Ok(GroupDef::new(
            count_tag,
            name,
            delimiter_tag,
            required,
            self.members(items)?,
        ))
    }

    /// Resolves items into members, in document order: field references,
    /// resolved groups, and component references.
    ///
    /// Every component reference is existence-checked here, so a typo'd
    /// `<component name='Nope'/>` fails the load instead of silently
    /// disappearing from the schema at validation time.
    fn members(&self, items: &[Item]) -> Result<Vec<Member>, DictionaryError> {
        let mut members = Vec::with_capacity(items.len());
        for item in items {
            members.push(match item {
                Item::Field { name, required } => Member::Field(self.field_ref(name, *required)?),
                Item::Group {
                    name,
                    required,
                    items,
                } => Member::Group(self.group(name, *required, items)?),
                Item::Component { name, required } => {
                    if !self.components.contains_key(name) {
                        return Err(DictionaryError::UnknownComponent(name.clone()));
                    }
                    Member::Component(ComponentRef::new(name.clone(), *required))
                }
            });
        }
        Ok(members)
    }

    /// Resolves the items of the header or trailer into its fields and
    /// groups. A component reference there is existence-checked and, as
    /// before member order was recorded, not kept: [`Dictionary`] has no
    /// place for it.
    fn envelope(&self, items: &[Item]) -> Result<(Vec<FieldRef>, Vec<GroupDef>), DictionaryError> {
        let mut fields = Vec::new();
        let mut groups = Vec::new();
        for member in self.members(items)? {
            match member {
                Member::Field(field) => fields.push(field),
                Member::Group(group) => groups.push(group),
                Member::Component(_) => {}
            }
        }
        Ok((fields, groups))
    }
}

/// Traversal state of a component during graph validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VisitState {
    /// On the current depth-first path: reaching it again is a cycle.
    InProgress,
    /// Fully expanded and acyclic, carrying the height of its subtree — the
    /// number of nested group/component levels reachable below it, counting
    /// the component itself. Memoising the measured height rather than a bare
    /// "done" flag makes the depth ceiling independent of declaration order:
    /// a leaf-first chain is measured exactly like a root-first one.
    Done(usize),
}

/// Rejects reference cycles, dangling references, and over-deep nesting in the
/// component graph.
///
/// Runs before any resolution, so the rest of the loader — and every consumer
/// of the resulting [`Dictionary`], including codegen, whose descent has no
/// ceiling of its own — can walk component references knowing the graph is a
/// DAG whose depth is bounded by [`MAX_COMPONENT_DEPTH`]. Every component is
/// entered at depth zero and its measured height is memoised, so the walk is
/// linear in the number of references and the ceiling is enforced no matter
/// what order the components are declared in.
///
/// # Errors
///
/// Returns [`DictionaryError::ComponentCycle`] for a reference cycle,
/// [`DictionaryError::UnknownComponent`] for a dangling reference, and
/// [`DictionaryError::NestingTooDeep`] when a component chain is longer than
/// [`MAX_COMPONENT_DEPTH`].
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

/// Depth-first visit of one component definition, returning the height of its
/// subtree: the deepest chain of nested groups and components below it,
/// counting the component itself.
///
/// `depth` bounds the recursion so a long root-first chain from hostile XML is
/// rejected before it can exhaust the stack. The returned height is memoised
/// and range-checked, so a leaf-first chain — whose descent stays shallow
/// because each child is already resolved — is rejected just the same.
///
/// # Errors
///
/// Returns [`DictionaryError::ComponentCycle`] on re-entry of an in-progress
/// component, [`DictionaryError::UnknownComponent`] for a dangling reference,
/// and [`DictionaryError::NestingTooDeep`] once the subtree height exceeds
/// [`MAX_COMPONENT_DEPTH`].
fn visit_component(
    name: &str,
    components: &HashMap<String, Vec<Item>>,
    state: &mut HashMap<String, VisitState>,
    depth: usize,
) -> Result<usize, DictionaryError> {
    match state.get(name) {
        Some(VisitState::Done(height)) => return Ok(*height),
        Some(VisitState::InProgress) => {
            return Err(DictionaryError::ComponentCycle(name.to_string()));
        }
        None => {}
    }
    let Some(items) = components.get(name) else {
        return Err(DictionaryError::UnknownComponent(name.to_string()));
    };
    state.insert(name.to_string(), VisitState::InProgress);
    let height = 1 + visit_items(items, components, state, depth + 1)?;
    if height > MAX_COMPONENT_DEPTH {
        return Err(DictionaryError::NestingTooDeep {
            element: "component".to_string(),
            limit: MAX_COMPONENT_DEPTH,
        });
    }
    state.insert(name.to_string(), VisitState::Done(height));
    Ok(height)
}

/// Depth-first visit of a member list, returning the height of its deepest
/// nested group or component (zero when it holds only fields).
///
/// `depth` is checked on entry so recursion through nested groups or a
/// root-first component chain cannot exhaust the stack.
///
/// # Errors
///
/// Propagates any error from [`visit_component`], and returns
/// [`DictionaryError::NestingTooDeep`] if the recursion itself reaches past
/// [`MAX_COMPONENT_DEPTH`].
fn visit_items(
    items: &[Item],
    components: &HashMap<String, Vec<Item>>,
    state: &mut HashMap<String, VisitState>,
    depth: usize,
) -> Result<usize, DictionaryError> {
    if depth > MAX_COMPONENT_DEPTH {
        return Err(DictionaryError::NestingTooDeep {
            element: "component".to_string(),
            limit: MAX_COMPONENT_DEPTH,
        });
    }
    let mut height = 0;
    for item in items {
        let reach = match item {
            Item::Field { .. } => 0,
            Item::Group { items, .. } => 1 + visit_items(items, components, state, depth + 1)?,
            Item::Component { name, .. } => visit_component(name, components, state, depth)?,
        };
        if reach > height {
            height = reach;
        }
    }
    Ok(height)
}

fn load(xml: &str) -> Result<Dictionary, DictionaryError> {
    let mut reader = Reader::from_str(xml);

    let mut version: Option<Version> = None;
    let mut header_items: Vec<Item> = Vec::new();
    let mut trailer_items: Vec<Item> = Vec::new();
    let mut message_irs: Vec<MessageIr> = Vec::new();
    let mut component_defs = ComponentIrs::default();
    let mut field_defs: Vec<FieldDef> = Vec::new();

    loop {
        match reader.read_event().map_err(xml_err)? {
            Event::Start(e) => match e.name().as_ref() {
                "fix" => version = Some(parse_version(&attr_map(&e)?)?),
                "header" => header_items = parse_items(&mut reader, "header", 1)?,
                "trailer" => trailer_items = parse_items(&mut reader, "trailer", 1)?,
                "message" => {
                    let attrs = attr_map(&e)?;
                    let items = parse_items(&mut reader, "message", 1)?;
                    message_irs.push(MessageIr::new(&attrs, items)?);
                }
                "component" => {
                    let attrs = attr_map(&e)?;
                    let name = required_attr(&attrs, "component", "name")?;
                    let items = parse_items(&mut reader, "component", 1)?;
                    component_defs.define(name, items)?;
                }
                "fields" => field_defs = parse_field_defs(&mut reader)?,
                _ => {}
            },
            // A self-closing definition is a definition with no members, not
            // an element to skip. QuickFIX writes them: `FIXT11.xml` defines
            // `<component name='MsgTypeGrp' />` (referenced by Logon), and
            // `FIXT11.xml` / `FIX44.xml` define
            // `<message name='XMLnonFIX' msgtype='n' msgcat='admin' />`.
            // Skipping the first made every reference to it a dangling
            // `UnknownComponent`; skipping the second dropped a message the
            // dictionary defines. Member references never reach this loop:
            // `parse_items` consumes everything inside a message, component,
            // group, header, or trailer.
            Event::Empty(e) => match e.name().as_ref() {
                "message" => message_irs.push(MessageIr::new(&attr_map(&e)?, Vec::new())?),
                "component" => {
                    let name = required_attr(&attr_map(&e)?, "component", "name")?;
                    component_defs.define(name, Vec::new())?;
                }
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
    }

    let version =
        version.ok_or_else(|| DictionaryError::Xml("missing root <fix> element".to_string()))?;

    assemble(Assembly {
        version,
        fields: field_defs,
        header: header_items,
        trailer: trailer_items,
        components: component_defs,
        messages: message_irs,
    })
}

/// A parsed dictionary document, its references still by name, ready for
/// [`assemble`].
pub(crate) struct Assembly {
    /// The version the document declares.
    pub(crate) version: Version,
    /// Field definitions, in document order.
    pub(crate) fields: Vec<FieldDef>,
    /// Header members.
    pub(crate) header: Vec<Item>,
    /// Trailer members.
    pub(crate) trailer: Vec<Item>,
    /// Component definitions.
    pub(crate) components: ComponentIrs,
    /// Message definitions, in document order.
    pub(crate) messages: Vec<MessageIr>,
}

/// Builds a [`Dictionary`] from a parsed document: the step the QuickFIX and
/// the Orchestra loaders share.
///
/// Checks the component graph ([`check_component_graph`]) before resolving
/// anything, rejects duplicate field names and tags and duplicate message
/// types, resolves every name reference, and builds each definition with its
/// members in document order.
///
/// # Errors
/// Returns [`DictionaryError`] for a component cycle, a dangling or over-deep
/// component reference, a duplicate definition, an unknown field name, or an
/// empty group.
pub(crate) fn assemble(assembly: Assembly) -> Result<Dictionary, DictionaryError> {
    let Assembly {
        version,
        fields: field_defs,
        header: header_items,
        trailer: trailer_items,
        components: component_defs,
        messages: message_irs,
    } = assembly;
    let ComponentIrs {
        items: component_irs,
        order: component_order,
    } = component_defs;
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
        first_tags: RefCell::new(HashMap::new()),
    };

    let (header_fields, header_groups) = resolver.envelope(&header_items)?;
    let (trailer_fields, trailer_groups) = resolver.envelope(&trailer_items)?;

    let mut components = Vec::with_capacity(component_order.len());
    for name in &component_order {
        let items = component_irs
            .get(name)
            .ok_or_else(|| DictionaryError::UnknownComponent(name.clone()))?;
        components.push(ComponentDef::new(name.clone(), resolver.members(items)?));
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
        messages.push(MessageDef::new(
            ir.msg_type.clone(),
            ir.name.clone(),
            ir.category,
            resolver.members(&ir.items)?,
        ));
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
    use crate::schema::MemberRef;
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

    /// One of the embedded-dictionary constructors.
    type EmbeddedConstructor = fn() -> Result<&'static Dictionary, DictionaryError>;

    #[test]
    fn test_embedded_dictionaries_load_with_their_version_and_are_cached() {
        let constructors: [(EmbeddedConstructor, Version); 4] = [
            (Dictionary::fix42, Version::Fix42),
            (Dictionary::fix44, Version::Fix44),
            (Dictionary::fixt11, Version::Fixt11),
            (Dictionary::fix50sp2, Version::Fix50Sp2),
        ];
        for (constructor, version) in constructors {
            let first = ok(constructor(), "embedded dictionary loads");
            assert_eq!(first.version, version);
            // Parsed once: every call hands out the same instance.
            let second = ok(constructor(), "embedded dictionary loads again");
            assert!(std::ptr::eq(first, second), "{version} was parsed twice");
        }
    }

    #[test]
    fn test_embedded_dictionaries_are_distinct_instances() {
        let all = [
            ok(Dictionary::fix42(), "FIX 4.2 loads"),
            ok(Dictionary::fix44(), "FIX 4.4 loads"),
            ok(Dictionary::fixt11(), "FIXT 1.1 loads"),
            ok(Dictionary::fix50sp2(), "FIX 5.0 SP2 loads"),
        ];
        for (index, dict) in all.iter().enumerate() {
            for other in all.iter().skip(index + 1) {
                assert!(!std::ptr::eq(*dict, *other));
            }
        }
    }

    #[test]
    fn test_fix42_utcdate_field_loads_as_utc_date_only() {
        // The vendored FIX 4.2 file declares MDEntryDate(272) `UTCDATE`, the
        // FIX 4.2 spelling of UTCDateOnly.
        let dict = ok(Dictionary::fix42(), "FIX 4.2 loads");
        let def = some(dict.get_field(272), "MDEntryDate defined");
        assert_eq!(def.name, "MDEntryDate");
        assert_eq!(def.field_type, FieldType::UtcDateOnly);
    }

    #[test]
    fn test_fix42_header_messages_and_group_count_fields() {
        let dict = ok(Dictionary::fix42(), "FIX 4.2 loads");
        assert!(dict.header.iter().any(|f| f.tag == 49 && f.required));
        assert!(dict.trailer.iter().any(|f| f.tag == 10 && f.required));
        let nos = some(dict.get_message("D"), "NewOrderSingle defined");
        assert!(
            nos.fields()
                .iter()
                .any(|f| f.name == "HandlInst" && f.required)
        );
        let er = some(dict.get_message("8"), "ExecutionReport defined");
        assert!(
            er.fields()
                .iter()
                .any(|f| f.name == "ExecTransType" && f.required)
        );
        // FIX 4.2 has no components; its groups hang off the message.
        assert!(dict.components.is_empty());
        let allocs = some(
            nos.groups().iter().find(|g| g.name == "NoAllocs"),
            "NoAllocs group on NewOrderSingle",
        );
        assert_eq!(allocs.count_tag, 78);
        assert_eq!(allocs.delimiter_tag, 79);
    }

    #[test]
    fn test_fix50sp2_xid_and_xidref_fields_load_as_string() {
        let dict = ok(Dictionary::fix50sp2(), "FIX 5.0 SP2 loads");
        for (tag, name) in [
            (40039, "CashSettlTermXID"),
            (41314, "UnderlyingProtectionTermXIDRef"),
        ] {
            let def = some(dict.get_field(tag), "XID-typed field defined");
            assert_eq!(def.name, name);
            assert_eq!(def.field_type, FieldType::String);
        }
    }

    #[test]
    fn test_fix50sp2_is_an_application_dictionary() {
        // QuickFIX ships FIX 5.0 SP2 with an empty header and trailer and no
        // session-level messages: those come from FIXT 1.1.
        let dict = ok(Dictionary::fix50sp2(), "FIX 5.0 SP2 loads");
        assert!(dict.header.is_empty());
        assert!(dict.header_groups.is_empty());
        assert!(dict.trailer.is_empty());
        assert!(dict.trailer_groups.is_empty());
        assert!(dict.messages().all(|m| m.category == MessageCategory::App));
        let nos = some(dict.get_message("D"), "NewOrderSingle defined");
        assert!(
            nos.components()
                .iter()
                .any(|c| c.name == "Instrument" && c.required)
        );
    }

    #[test]
    fn test_fixt11_is_a_transport_dictionary() {
        let dict = ok(Dictionary::fixt11(), "FIXT 1.1 loads");
        let appl_ver_id = some(
            dict.header.iter().find(|f| f.name == "ApplVerID"),
            "ApplVerID in the FIXT 1.1 header",
        );
        assert_eq!(appl_ver_id.tag, 1128);
        assert!(!appl_ver_id.required);
        assert!(dict.header_groups.iter().any(|g| g.count_tag == 627));
        assert!(dict.trailer.iter().any(|f| f.tag == 10 && f.required));
        // Only session-level messages.
        assert!(
            dict.messages()
                .all(|m| m.category == MessageCategory::Admin)
        );
        let logon = some(dict.get_message("A"), "Logon defined");
        assert!(
            logon
                .fields()
                .iter()
                .any(|f| f.name == "DefaultApplVerID" && f.required)
        );
    }

    #[test]
    fn test_fixt11_empty_component_definition_loads() {
        // The vendored FIXT 1.1 file defines `<component name='MsgTypeGrp' />`
        // with no members, and Logon references it. Skipping the self-closing
        // definition made that reference a dangling UnknownComponent.
        let dict = ok(Dictionary::fixt11(), "FIXT 1.1 loads");
        let group = some(dict.get_component("MsgTypeGrp"), "MsgTypeGrp defined");
        assert!(group.fields().is_empty());
        assert!(group.groups().is_empty());
        assert!(group.components().is_empty());
        let logon = some(dict.get_message("A"), "Logon defined");
        assert!(logon.components().iter().any(|c| c.name == "MsgTypeGrp"));
    }

    #[test]
    fn test_self_closing_message_definition_loads() {
        // FIX 4.4 and FIXT 1.1 both define
        // `<message name='XMLnonFIX' msgtype='n' msgcat='admin' />`.
        for dict in [fix44(), ok(Dictionary::fixt11(), "FIXT 1.1 loads")] {
            let message = some(dict.get_message("n"), "XMLnonFIX defined");
            assert_eq!(message.name, "XMLnonFIX");
            assert_eq!(message.category, MessageCategory::Admin);
            assert!(message.fields().is_empty());
        }
    }

    #[test]
    fn test_empty_component_definition_loads() {
        let xml = r"<fix type='FIX' major='4' minor='4'>
            <header></header><trailer></trailer>
            <messages>
                <message name='Ping' msgtype='U1' msgcat='app'>
                    <field name='TestReqID' required='Y'/>
                    <component name='Nothing' required='Y'/>
                </message>
            </messages>
            <components>
                <component name='Nothing' />
            </components>
            <fields><field number='112' name='TestReqID' type='STRING'/></fields>
        </fix>";
        let dict = ok(Dictionary::from_quickfix_xml(xml), "empty component loads");
        let nothing = some(dict.get_component("Nothing"), "empty component defined");
        assert!(nothing.fields().is_empty());
        let ping = some(dict.get_message("U1"), "Ping defined");
        assert!(ping.components().iter().any(|c| c.name == "Nothing"));
    }

    #[test]
    fn test_group_with_only_an_empty_component_is_rejected() {
        // Accepting empty component definitions must not let a group without
        // any reachable field through: it still has no delimiter.
        let xml = r"<fix type='FIX' major='4' minor='4'>
            <header></header><trailer></trailer>
            <messages>
                <message name='Ping' msgtype='U1' msgcat='app'>
                    <group name='NoPartyIDs' required='N'>
                        <component name='Nothing' required='N'/>
                    </group>
                </message>
            </messages>
            <components>
                <component name='Nothing' />
            </components>
            <fields><field number='453' name='NoPartyIDs' type='NUMINGROUP'/></fields>
        </fix>";
        assert_eq!(
            load_err(xml),
            DictionaryError::EmptyGroup("NoPartyIDs".to_string())
        );
    }

    #[test]
    fn test_duplicate_empty_component_definition_is_rejected() {
        let xml = r"<fix type='FIX' major='4' minor='4'>
            <header></header><trailer></trailer><messages></messages>
            <components>
                <component name='Twice'>
                    <field name='TestReqID' required='N'/>
                </component>
                <component name='Twice' />
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
    fn test_self_closing_message_without_msgtype_is_rejected() {
        let xml = r"<fix type='FIX' major='4' minor='4'>
            <header></header><trailer></trailer>
            <messages><message name='Ping' msgcat='app' /></messages>
            <fields></fields>
        </fix>";
        assert_eq!(
            load_err(xml),
            DictionaryError::MissingAttribute {
                element: "message".to_string(),
                attribute: "msgtype".to_string(),
            }
        );
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
        assert!(
            nos.fields()
                .iter()
                .any(|f| f.name == "ClOrdID" && f.required)
        );
        assert!(nos.components().iter().any(|c| c.name == "Instrument"));

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
            nos.components().iter().find(|c| c.name == "Instrument"),
            "NewOrderSingle references Instrument",
        );
        assert!(instrument.required);
        let parties = some(
            nos.components().iter().find(|c| c.name == "Parties"),
            "NewOrderSingle references Parties",
        );
        assert!(!parties.required);
    }

    #[test]
    fn test_fix44_components_and_groups() {
        let dict = fix44();

        let instrument = some(dict.get_component("Instrument"), "Instrument defined");
        assert!(instrument.fields().iter().any(|f| f.name == "Symbol"));

        let parties = some(dict.get_component("Parties"), "Parties defined");
        let no_party_ids = some(
            parties.groups().iter().find(|g| g.name == "NoPartyIDs"),
            "NoPartyIDs group",
        );
        assert_eq!(no_party_ids.count_tag, 453);
        assert_eq!(no_party_ids.delimiter_tag, 448);
        // Nested component reference within the group.
        assert!(
            no_party_ids
                .components()
                .iter()
                .any(|c| c.name == "PtysSubGrp")
        );
    }

    /// A member as a definition lists it: `F`ield, `G`roup or `C`omponent,
    /// and its name.
    type Listed = (char, String);

    /// Re-reads `xml` without the loader and returns the members of every
    /// message, component, header, trailer and group definition in document
    /// order, keyed by `message:<name>`, `component:<name>`, `header`,
    /// `trailer`, and `<enclosing key>/<group name>` for a group.
    fn xml_members(xml: &str) -> HashMap<String, Vec<Listed>> {
        /// An open element: a definition collecting members, or a member
        /// reference written with an end tag.
        enum Frame {
            Definition(String, Vec<Listed>),
            Reference,
        }
        let mut reader = Reader::from_str(xml);
        let mut stack: Vec<Frame> = Vec::new();
        let mut found: HashMap<String, Vec<Listed>> = HashMap::new();
        loop {
            let (element, open) = match ok(reader.read_event(), "the XML re-reads") {
                Event::Start(e) => (e, true),
                Event::Empty(e) => (e, false),
                Event::End(e) => {
                    let closes = matches!(
                        e.name().as_ref(),
                        "header" | "trailer" | "message" | "component" | "group" | "field"
                    );
                    if closes && let Some(Frame::Definition(key, members)) = stack.pop() {
                        found.insert(key, members);
                    }
                    continue;
                }
                Event::Eof => break,
                _ => continue,
            };
            let kind = element.name().as_ref().to_string();
            let attrs = ok(attr_map(&element), "attributes");
            let name = attrs.get("name").cloned().unwrap_or_default();
            let enclosing = stack.iter().rev().find_map(|frame| match frame {
                Frame::Definition(key, _) => Some(key.clone()),
                Frame::Reference => None,
            });
            let frame = match (kind.as_str(), enclosing) {
                ("header" | "trailer", _) => Frame::Definition(kind.clone(), Vec::new()),
                ("message", None) => Frame::Definition(format!("message:{name}"), Vec::new()),
                ("component", None) => Frame::Definition(format!("component:{name}"), Vec::new()),
                ("group" | "field" | "component", Some(parent)) => {
                    let listed = match kind.as_str() {
                        "group" => 'G',
                        "field" => 'F',
                        _ => 'C',
                    };
                    if let Some(Frame::Definition(_, members)) = stack
                        .iter_mut()
                        .rev()
                        .find(|frame| matches!(frame, Frame::Definition(..)))
                    {
                        members.push((listed, name.clone()));
                    }
                    if listed == 'G' {
                        Frame::Definition(format!("{parent}/{name}"), Vec::new())
                    } else {
                        Frame::Reference
                    }
                }
                // Field definitions in <fields>, their values, sections.
                _ => continue,
            };
            if open {
                stack.push(frame);
            } else if let Frame::Definition(key, members) = frame {
                found.insert(key, members);
            }
        }
        found
    }

    /// Lists members as [`xml_members`] does.
    fn listed<'a>(members: impl Iterator<Item = MemberRef<'a>>) -> Vec<Listed> {
        members
            .map(|member| match member {
                MemberRef::Field(field) => ('F', field.name.clone()),
                MemberRef::Group(group) => ('G', group.name.clone()),
                MemberRef::Component(component) => ('C', component.name.clone()),
            })
            .collect()
    }

    /// Records the members of `groups` and of every group nested in them.
    fn loaded_groups(parent: &str, groups: &[GroupDef], out: &mut HashMap<String, Vec<Listed>>) {
        for group in groups {
            let key = format!("{parent}/{}", group.name);
            out.insert(key.clone(), listed(group.members()));
            loaded_groups(&key, group.groups(), out);
        }
    }

    /// The loaded counterpart of [`xml_members`]. The header and trailer are
    /// left out: a [`Dictionary`] keeps their fields and groups apart, and
    /// only their groups' members are compared.
    fn loaded_members(dict: &Dictionary) -> HashMap<String, Vec<Listed>> {
        let mut out = HashMap::new();
        for message in dict.messages() {
            let key = format!("message:{}", message.name);
            out.insert(key.clone(), listed(message.members()));
            loaded_groups(&key, message.groups(), &mut out);
        }
        for component in dict.components.values() {
            let key = format!("component:{}", component.name);
            out.insert(key.clone(), listed(component.members()));
            loaded_groups(&key, component.groups(), &mut out);
        }
        loaded_groups("header", &dict.header_groups, &mut out);
        loaded_groups("trailer", &dict.trailer_groups, &mut out);
        out
    }

    #[test]
    fn test_every_definition_keeps_its_xml_member_order() {
        for (what, xml, dict) in [
            ("FIX 4.2", FIX42_XML, Dictionary::fix42()),
            ("FIX 4.4", FIX44_XML, Dictionary::fix44()),
            ("FIXT 1.1", FIXT11_XML, Dictionary::fixt11()),
            ("FIX 5.0 SP2", FIX50SP2_XML, Dictionary::fix50sp2()),
        ] {
            let dict = ok(dict, what);
            let mut expected = xml_members(xml);
            expected.remove("header");
            expected.remove("trailer");
            let loaded = loaded_members(dict);
            let groups = expected.keys().filter(|key| key.contains('/')).count();
            assert!(groups > 0, "{what}: group definitions found");
            assert_eq!(loaded.len(), expected.len(), "{what}: definitions");
            for (key, members) in &expected {
                assert_eq!(loaded.get(key), Some(members), "{what}: {key}");
            }
        }
    }

    #[test]
    fn test_fix44_pre_alloc_grp_keeps_its_component_between_fields() {
        // PreAllocGrp NoAllocs(78) lists AllocAccount(79), AllocAcctIDSource
        // (661), AllocSettlCurrency(736), IndividualAllocID(467), the
        // NestedParties component (NoNestedPartyIDs 539) and AllocQty(80):
        // the component sits between fields, which the per-kind lists alone
        // cannot say.
        let component = some(fix44().get_component("PreAllocGrp"), "PreAllocGrp");
        let allocs = some(component.groups().first(), "NoAllocs");
        assert_eq!(allocs.count_tag, 78);
        let order: Vec<String> = allocs
            .members()
            .map(|member| match member {
                MemberRef::Field(field) => field.tag.to_string(),
                MemberRef::Component(component) => component.name.clone(),
                MemberRef::Group(group) => group.count_tag.to_string(),
            })
            .collect();
        assert_eq!(order, ["79", "661", "736", "467", "NestedParties", "80"]);
        let nested = some(fix44().get_component("NestedParties"), "NestedParties");
        assert_eq!(
            nested.groups().first().map(|group| group.count_tag),
            Some(539)
        );
    }

    #[test]
    fn test_definitions_keep_order_and_kinds_in_step_through_push() {
        let field = |tag: u32| FieldRef {
            tag,
            name: tag.to_string(),
            required: false,
        };
        let group = GroupDef::new(78, "NoAllocs", 79, false, [Member::Field(field(79))]);
        let mut component = ComponentDef::new(
            "Edited",
            [
                Member::Field(field(1)),
                Member::Component(ComponentRef::new("Inner", false)),
                Member::Field(field(2)),
            ],
        );
        let names = |component: &ComponentDef| listed(component.members());
        assert_eq!(
            names(&component),
            [
                ('F', "1".to_string()),
                ('C', "Inner".to_string()),
                ('F', "2".to_string())
            ]
        );
        // `push` appends in dictionary order and to its kind's list: the two
        // views cannot disagree, since the lists are not editable otherwise.
        component.push(Member::Group(group));
        component.push(Member::Field(field(3)));
        assert_eq!(
            names(&component),
            [
                ('F', "1".to_string()),
                ('C', "Inner".to_string()),
                ('F', "2".to_string()),
                ('G', "NoAllocs".to_string()),
                ('F', "3".to_string())
            ]
        );
        let tags: Vec<u32> = component.fields().iter().map(|field| field.tag).collect();
        assert_eq!(tags, [1, 2, 3]);
        assert_eq!(component.groups().len(), 1);
        assert_eq!(component.components().len(), 1);
        // The iterator knows how many members remain.
        let mut members = component.members();
        assert_eq!(members.len(), 5);
        let _ = members.next();
        assert_eq!(members.size_hint(), (4, Some(4)));
        assert_eq!(members.by_ref().count(), 4);
        assert!(members.next().is_none());

        let mut message = MessageDef::new("U1", "Grown", MessageCategory::App, []);
        assert_eq!(message.members().len(), 0);
        message.push(Member::Component(ComponentRef::new("Edited", true)));
        message.push(Member::Field(field(11)));
        assert_eq!(
            listed(message.members()),
            [('C', "Edited".to_string()), ('F', "11".to_string())]
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
    fn test_long_component_chain_leaf_first_is_rejected() {
        // The same over-long acyclic chain as the forward-order test, but with
        // the leaf declared first and every parent after its child. Memoising
        // a bare "done" flag would let this load at any length, because each
        // parent finds its child already resolved at depth 1 and never
        // descends — memoising the measured height rejects it regardless of
        // declaration order.
        let mut xml = String::from(
            "<fix type='FIX' major='4' minor='4'><header></header><trailer></trailer>\
             <messages></messages><components>",
        );
        let links = MAX_COMPONENT_DEPTH + 10;
        xml.push_str(&format!(
            "<component name='C{links}'><field name='TestReqID' required='N'/></component>"
        ));
        for index in (0..links).rev() {
            xml.push_str(&format!("<component name='C{index}'>"));
            xml.push_str(&format!("<component name='C{}' required='N'/>", index + 1));
            xml.push_str("</component>");
        }
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
    fn test_component_chain_at_ceiling_leaf_first_loads() {
        // A leaf-first chain exactly at the ceiling must still load: the fix
        // must not reject valid depth, only over-deep nesting.
        let mut xml = String::from(
            "<fix type='FIX' major='4' minor='4'><header></header><trailer></trailer>\
             <messages></messages><components>",
        );
        // `links` components chained plus the leaf, giving a subtree height of
        // exactly MAX_COMPONENT_DEPTH.
        let links = MAX_COMPONENT_DEPTH - 1;
        xml.push_str(&format!(
            "<component name='C{links}'><field name='TestReqID' required='N'/></component>"
        ));
        for index in (0..links).rev() {
            xml.push_str(&format!("<component name='C{index}'>"));
            xml.push_str(&format!("<component name='C{}' required='N'/>", index + 1));
            xml.push_str("</component>");
        }
        xml.push_str(
            "</components><fields><field number='112' name='TestReqID' type='STRING'/></fields></fix>",
        );

        assert!(load(&xml).is_ok());
    }

    #[test]
    fn test_component_chain_without_fields_is_walked_once() {
        // MAX_COMPONENT_DEPTH components, each holding the next twice and
        // the last nothing, ahead of a group's first field. Finding the
        // group's delimiter walks every component once: without the cache it
        // walks 2^31 paths.
        let mut xml = String::from(
            "<fix type='FIX' major='4' minor='4'><header></header><trailer></trailer>\
             <messages><message name='Heartbeat' msgtype='0' msgcat='admin'>\
             <group name='NoHops' required='N'><component name='C0' required='N'/>\
             <field name='HopCompID' required='N'/></group></message></messages><components>",
        );
        let last = MAX_COMPONENT_DEPTH - 1;
        for index in 0..last {
            xml.push_str(&format!("<component name='C{index}'>"));
            for _ in 0..2 {
                xml.push_str(&format!("<component name='C{}' required='N'/>", index + 1));
            }
            xml.push_str("</component>");
        }
        xml.push_str(&format!("<component name='C{last}'/>"));
        xml.push_str(
            "</components><fields><field number='627' name='NoHops' type='NUMINGROUP'/>\
             <field number='628' name='HopCompID' type='STRING'/></fields></fix>",
        );

        let dict = ok(load(&xml), "the chain loads");
        let heartbeat = some(dict.get_message("0"), "Heartbeat");
        assert_eq!(heartbeat.groups()[0].delimiter_tag, 628);
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
        assert_eq!(some(ping.fields().first(), "Ping has a field").tag, 112);
    }
}
