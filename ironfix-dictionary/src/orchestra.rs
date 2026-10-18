/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! FIX Orchestra repository loader.
//!
//! [`Dictionary::from_orchestra_xml`] reads a FIX Orchestra 1.0 repository
//! (the XML the FIX Trading Community publishes the standard in, namespace
//! [`ORCHESTRA_NAMESPACE`]) into the same [`Dictionary`] model the QuickFIX
//! loader builds, and returns it with an [`OrchestraReport`] of everything in
//! the repository the model has no place for. The decision record is
//! `doc/adr/0013-load-fix-orchestra-repositories.md`.
//!
//! # What is tested
//!
//! The loader is exercised against the FIX Trading Community's
//! `OrchestraFIX44.xml` (FIX 4.4 as of Extension Pack 311), vendored as a
//! test fixture and compared with the embedded QuickFIX FIX 4.4 dictionary,
//! and against synthetic documents. No other version's standard repository
//! is exercised.
//!
//! # Mapping
//!
//! | Orchestra | [`Dictionary`] |
//! |---|---|
//! | `repository/@version` (`FIX.4.0` to `FIX.4.4`, `FIX.5.0`, `FIX.5.0SP1`, `FIX.5.0SP2`, `FIXT.1.1`, each optionally `_EP<n>`) | [`Dictionary::version`] |
//! | `field` (`id` is the tag) | [`FieldDef`] |
//! | `datatype`, through `baseType` when its own name is not a FIX type | [`FieldType`] |
//! | `codeSet` / `code` named by a field's `type` | the field's type and [`FieldDef::values`] (value to code name) |
//! | `component` named `StandardHeader` / `StandardTrailer` | [`Dictionary::header`] / [`Dictionary::trailer`] and their groups |
//! | any other `component` | [`ComponentDef`](crate::ComponentDef) |
//! | `group`, at each `groupRef` | a [`GroupDef`](crate::GroupDef) named after its `numInGroup` field, as QuickFIX names groups (`NoPartyIDs`, not `Parties`) |
//! | `message` | [`MessageDef`](crate::MessageDef): category `Session` is [`MessageCategory::Admin`], any other [`MessageCategory::App`] |
//! | `presence="required"` / `"optional"` | `required` |
//!
//! Members keep the order the repository lists them in. A group's delimiter
//! is its first member, as in QuickFIX. A component that the standard header
//! or trailer references is expanded in place, because the dictionary keeps
//! the envelope as fields and groups; when the reference is optional, its
//! members become optional too (a group's entries keep their own required
//! members).
//!
//! Only the `base` scenario is loaded. Two versions are
//! [`DictionaryError::UnsupportedVersion`]: `FIX.Latest`, which names no
//! fixed FIX version, and a repository named `FIXT` whose version is not
//! `FIXT.1.1`. The FIX Trading Community's FIXT session repository is one:
//! it declares `FIX.5.0SP2_EP247`, an application version, where it describes
//! the FIXT.1.1 session layer, so the version cannot be taken from it.
//!
//! # Reported, not mapped
//!
//! Nothing that carries meaning is dropped silently: each of these becomes an
//! [`UnmappedConstruct`] in the report.
//!
//! - an element the loader does not map, skipped with its content: `actors`,
//!   `concepts`, a message's `responses`, a member's `assign` or
//!   `blockAssignment`, an element from another namespace, or one Orchestra
//!   1.0 does not define;
//! - a definition in a scenario other than `base` (not loaded), and a
//!   reference to one (the member is left out);
//! - a member whose presence is `forbidden` (left out), `ignored` or
//!   `constant` (kept, optional);
//! - a conditional presence `rule`, with its presence and `when` condition
//!   (not evaluated: the member keeps its static presence);
//! - an attribute that constrains values the model cannot hold, such as
//!   `minInclusive`, `implMaxLength`, `implMaxOccurs`, `lengthId`,
//!   `discriminatorId` or `unionDataType`, and any attribute Orchestra 1.0
//!   does not define;
//! - a group or code set nothing references: the dictionary holds a group
//!   only where it is referenced, and a code set only on its fields. It is
//!   still checked like the others.
//!
//! Descriptive content is ignored without a report entry: `annotation`
//! (documentation and appinfo), `metadata`, `categories`, `sections`,
//! `mappedDatatype`, and the pedigree, naming and grouping attributes
//! (`added`, `updated`, `deprecated`, `abbrName`, `category`, ...).
//!
//! # Untrusted input
//!
//! A repository is parser input, held to the same standard as the QuickFIX
//! loader: every malformed document maps to a typed [`DictionaryError`],
//! never to a panic, an unbounded recursion, or an allocation that grows
//! faster than the limits below allow. The ceilings:
//!
//! - [`MAX_ORCHESTRA_DOCUMENT_LEN`] bounds the document;
//! - [`MAX_ORCHESTRA_ATTRIBUTES_LEN`] bounds the attributes of one element;
//! - [`MAX_ORCHESTRA_NAME_LEN`] bounds every element name, attribute name
//!   and attribute value the loader keeps, in the dictionary or the report,
//!   so a name copied into every member or report entry that mentions it
//!   stays short;
//! - [`MAX_ORCHESTRA_REPORT_ENTRIES`] bounds the report, so a flood of
//!   unmapped elements or attributes is an error rather than a report as
//!   large as the document allows;
//! - [`MAX_NESTING_DEPTH`] bounds both XML element nesting and
//!   repeating-group nesting, exactly as in the QuickFIX loader;
//! - [`MAX_COMPONENT_DEPTH`] bounds component reference chains, and
//!   component cycles are rejected before resolution, by the step both
//!   loaders share;
//! - [`MAX_ORCHESTRA_MEMBERS`] bounds the members group expansion produces.
//!   Orchestra groups are definitions referenced by id, and the dictionary
//!   holds a group inline at each reference, so a few hundred bytes of nested
//!   references could otherwise expand exponentially;
//! - [`MAX_ORCHESTRA_FIELD_VALUES`] bounds the enumeration values the fields
//!   hold together: every field naming a code set holds its own copy of the
//!   values.
//!
//! Dangling and duplicate ids (a code's id included, within its code set),
//! group cycles, unknown datatypes and code sets, groups without a count
//! field, empty groups, ids that do not fit a `u32`, oversized names and
//! attributes (a section's own attributes included), truncated XML, and
//! content outside the root element other than whitespace, comments,
//! processing instructions, the XML declaration and a document type
//! declaration (text, a CDATA section, a reference, a second element) are
//! each a typed error. Every `base` group is checked, referenced or not: its
//! count field and every id it references resolve, and the groups it nests
//! form no cycle and no chain deeper than a message can hold.

use crate::document::{Prolog, epilog};
use crate::loader::{
    Assembly, ComponentIrs, DefinitionKind, DictionaryError, Item, MAX_COMPONENT_DEPTH,
    MAX_NESTING_DEPTH, MessageIr, assemble,
};
use crate::schema::{Dictionary, FieldDef, FieldType, MessageCategory, Version};
use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::{Namespace, ResolveResult};
use quick_xml::reader::NsReader;
use std::collections::{HashMap, HashSet};
use std::fmt;

/// The XML namespace of FIX Orchestra 1.0 repositories, the only schema the
/// loader reads.
pub const ORCHESTRA_NAMESPACE: &str = "http://fixprotocol.io/2020/orchestra/repository";

/// Maximum length, in bytes, of a repository the loader accepts: 64 MiB.
///
/// FIX Latest as of Extension Pack 312, the largest standard repository, is
/// about 8.6 MB.
pub const MAX_ORCHESTRA_DOCUMENT_LEN: usize = 64 * 1024 * 1024;

/// Maximum length, in bytes, of the attributes of one element: 16 KiB.
///
/// The longest start tag of the FIX 4.4 standard repository is under 300
/// bytes. The limit also bounds the number of attributes on one element.
pub const MAX_ORCHESTRA_ATTRIBUTES_LEN: usize = 16 * 1024;

/// Maximum length, in bytes, of an element name, an attribute name, or an
/// attribute value the loader keeps: 255.
///
/// Orchestra 1.0 limits names and scenario names to 255 characters. The
/// longest value the loader keeps from the FIX 4.4 standard repository is 43
/// bytes, and from FIX Latest (Extension Pack 312) 65. The values it does
/// not keep (documentation links, pedigree) are bounded by
/// [`MAX_ORCHESTRA_ATTRIBUTES_LEN`] only.
pub const MAX_ORCHESTRA_NAME_LEN: usize = 255;

/// Maximum number of entries in an [`OrchestraReport`]: 65 536.
///
/// The FIX 4.4 standard repository needs 41.
pub const MAX_ORCHESTRA_REPORT_ENTRIES: usize = 1 << 16;

/// Maximum number of enumeration values the loaded fields may hold together:
/// 131 072.
///
/// A field naming a code set holds its own copy of the set's values
/// ([`FieldDef::values`]), so a code set named by many fields is copied once
/// per field; every copy counts. FIX Latest as of Extension Pack 312 needs
/// 27 103; FIX 4.4 needs 2 371.
pub const MAX_ORCHESTRA_FIELD_VALUES: usize = 1 << 17;

/// Maximum number of members group expansion may produce: 262 144.
///
/// Every field, component and group reference the loaded definitions hold
/// counts once, at every place a group is expanded. FIX Latest as of
/// Extension Pack 312 needs 17 515; FIX 4.4 needs 4 226.
pub const MAX_ORCHESTRA_MEMBERS: usize = 1 << 18;

/// The default scenario, the only one loaded.
const BASE_SCENARIO: &str = "base";

/// Name of the component holding the standard header.
const HEADER: &str = "StandardHeader";

/// Name of the component holding the standard trailer.
const TRAILER: &str = "StandardTrailer";

/// Message category of the session-level (admin) messages.
const ADMIN_CATEGORY: &str = "Session";

/// The repository sections the loader maps.
const MAPPED_SECTIONS: [&str; 6] = [
    "datatypes",
    "codeSets",
    "fields",
    "components",
    "groups",
    "messages",
];

/// Attributes that describe rather than constrain: pedigree, naming,
/// grouping and documentation links. Ignored without a report entry.
const DESCRIPTIVE_ATTRIBUTES: [&str; 31] = [
    "FIXMLFileName",
    "abbrName",
    "added",
    "addedEP",
    "applVerId",
    "baseCategory",
    "baseCategoryAbbrName",
    "category",
    "changeType",
    "componentType",
    "deprecated",
    "deprecatedEP",
    "displayOrder",
    "expressionLanguage",
    "flow",
    "group",
    "guid",
    "includeFile",
    "issue",
    "lastModified",
    "latestEP",
    "namespace",
    "rendering",
    "replaced",
    "replacedByField",
    "replacedEP",
    "section",
    "sort",
    "specUrl",
    "updated",
    "updatedEP",
];

/// The kind of an Orchestra definition, in errors and report entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OrchestraKind {
    /// A `datatype`.
    Datatype,
    /// A `codeSet`.
    CodeSet,
    /// A `code` of a code set.
    Code,
    /// A `field`.
    Field,
    /// A `component`.
    Component,
    /// A repeating `group`.
    Group,
    /// A `message`.
    Message,
}

impl fmt::Display for OrchestraKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Datatype => "datatype",
            Self::CodeSet => "code set",
            Self::Code => "code",
            Self::Field => "field",
            Self::Component => "component",
            Self::Group => "group",
            Self::Message => "message",
        })
    }
}

/// Something an Orchestra repository holds that the loaded [`Dictionary`]
/// does not.
///
/// `location` names where it sits, as `<definition kind> <name>` followed by
/// `/`-separated child elements (`message NewOrderSingle/fieldRef 44`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnmappedConstruct {
    /// An element the loader does not map, skipped with everything inside it.
    #[non_exhaustive]
    Element {
        /// Where the element sits, ending with its name as written.
        location: String,
    },
    /// A definition in a scenario other than `base`, not loaded.
    #[non_exhaustive]
    Scenario {
        /// The kind of the definition.
        kind: OrchestraKind,
        /// Its name.
        name: String,
        /// Its scenario.
        scenario: String,
    },
    /// A member referencing a definition in a scenario other than `base`;
    /// the member is left out.
    #[non_exhaustive]
    ScenarioReference {
        /// The member.
        location: String,
        /// The scenario it references.
        scenario: String,
    },
    /// A member whose presence the dictionary cannot express: `forbidden`
    /// (left out), `ignored` or `constant` (kept, optional), or a value
    /// Orchestra 1.0 does not define (kept, optional).
    #[non_exhaustive]
    Presence {
        /// The member.
        location: String,
        /// The presence, as written.
        presence: String,
        /// The member's `value` attribute, the constant of a `constant`
        /// member.
        value: Option<String>,
    },
    /// A conditional presence rule, not evaluated: the member keeps its
    /// static presence.
    #[non_exhaustive]
    Rule {
        /// The field or member the rule applies to.
        location: String,
        /// The rule's name, if it has one.
        name: Option<String>,
        /// The presence the rule gives when its condition holds, as written.
        presence: Option<String>,
        /// The rule's `when` condition, with character and entity
        /// references resolved.
        condition: Option<String>,
    },
    /// An attribute whose constraint the dictionary has no place for, or
    /// one Orchestra 1.0 does not define.
    #[non_exhaustive]
    Attribute {
        /// The element carrying it.
        location: String,
        /// The attribute name, as written.
        name: String,
        /// The attribute value.
        value: String,
    },
    /// A `base` group or code set nothing references. The dictionary holds a
    /// group only where it is referenced and a code set only on its fields;
    /// the definition was checked all the same.
    #[non_exhaustive]
    Unreferenced {
        /// The kind of the definition.
        kind: OrchestraKind,
        /// Its name.
        name: String,
    },
}

impl fmt::Display for UnmappedConstruct {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Element { location } => write!(f, "{location}: element not mapped"),
            Self::Scenario {
                kind,
                name,
                scenario,
            } => write!(f, "{kind} {name}: scenario `{scenario}` not loaded"),
            Self::ScenarioReference { location, scenario } => {
                write!(f, "{location}: references scenario `{scenario}`, left out")
            }
            Self::Presence {
                location,
                presence,
                value,
            } => match value {
                Some(value) => write!(f, "{location}: presence `{presence}` (value `{value}`)"),
                None => write!(f, "{location}: presence `{presence}`"),
            },
            Self::Rule {
                location,
                name,
                presence,
                condition,
            } => {
                write!(f, "{location}: rule")?;
                if let Some(name) = name {
                    write!(f, " `{name}`")?;
                }
                if let Some(presence) = presence {
                    write!(f, " (presence `{presence}`)")?;
                }
                if let Some(condition) = condition {
                    write!(f, " when `{condition}`")?;
                }
                write!(f, " not evaluated")
            }
            Self::Attribute {
                location,
                name,
                value,
            } => write!(f, "{location}: attribute {name}=\"{value}\" not mapped"),
            Self::Unreferenced { kind, name } => {
                write!(f, "{kind} {name}: not referenced, not in the dictionary")
            }
        }
    }
}

/// The report under construction, bounded by
/// [`MAX_ORCHESTRA_REPORT_ENTRIES`].
#[derive(Debug, Default)]
struct Report {
    entries: Vec<UnmappedConstruct>,
}

impl Report {
    /// Adds `entry`.
    ///
    /// # Errors
    /// [`DictionaryError::TooManyUnmapped`] past
    /// [`MAX_ORCHESTRA_REPORT_ENTRIES`].
    fn push(&mut self, entry: UnmappedConstruct) -> Result<(), DictionaryError> {
        if self.entries.len() >= MAX_ORCHESTRA_REPORT_ENTRIES {
            return Err(DictionaryError::TooManyUnmapped {
                limit: MAX_ORCHESTRA_REPORT_ENTRIES,
            });
        }
        self.entries.push(entry);
        Ok(())
    }
}

/// What a loaded Orchestra repository holds that the [`Dictionary`] does not:
/// what the document holds in document order, then the unreferenced groups
/// and code sets. At most [`MAX_ORCHESTRA_REPORT_ENTRIES`] entries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrchestraReport {
    /// The entries.
    entries: Vec<UnmappedConstruct>,
}

impl OrchestraReport {
    /// Returns the entries: document order, then the unreferenced
    /// definitions.
    #[must_use]
    pub fn entries(&self) -> &[UnmappedConstruct] {
        &self.entries
    }

    /// Returns the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true when the repository held nothing the dictionary lacks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A [`Dictionary`] loaded from an Orchestra repository, with the report of
/// what it could not hold.
#[derive(Debug, Clone)]
pub struct OrchestraImport {
    /// The loaded dictionary.
    dictionary: Dictionary,
    /// What the repository holds that the dictionary does not.
    report: OrchestraReport,
}

impl OrchestraImport {
    /// Returns the loaded dictionary.
    #[must_use]
    pub const fn dictionary(&self) -> &Dictionary {
        &self.dictionary
    }

    /// Returns what the repository holds that the dictionary does not.
    #[must_use]
    pub const fn report(&self) -> &OrchestraReport {
        &self.report
    }

    /// Returns the dictionary and the report.
    #[must_use]
    pub fn into_parts(self) -> (Dictionary, OrchestraReport) {
        (self.dictionary, self.report)
    }
}

impl Dictionary {
    /// Loads a dictionary from a FIX Orchestra 1.0 repository.
    ///
    /// Reads the `base` scenario into the same model as
    /// [`Dictionary::from_quickfix_xml`], and reports what the model cannot
    /// hold; see the [`orchestra`](crate::orchestra) module docs for the
    /// mapping, what is reported, and the limits.
    ///
    /// # Arguments
    /// * `xml` - The repository document
    ///
    /// # Errors
    /// Returns [`DictionaryError`] if the document is not a well-formed
    /// Orchestra 1.0 repository, declares a version the loader cannot map
    /// (`FIX.Latest`, or a repository named `FIXT` whose version is not
    /// `FIXT.1.1`), holds a dangling, duplicate or invalid id, a group or
    /// component cycle, a datatype or code set that maps to no FIX data type,
    /// a group without a count field or without members, or exceeds one of
    /// the size, length, report, field-value and depth limits.
    pub fn from_orchestra_xml(xml: &str) -> Result<OrchestraImport, DictionaryError> {
        if xml.len() > MAX_ORCHESTRA_DOCUMENT_LEN {
            return Err(DictionaryError::DocumentTooLarge {
                len: xml.len(),
                limit: MAX_ORCHESTRA_DOCUMENT_LEN,
            });
        }
        let mut parser = Parser::new(xml);
        let raw = parser.repository()?;
        let mut report = parser.report;
        let dictionary = build(&raw, &mut report)?;
        Ok(OrchestraImport {
            dictionary,
            report: OrchestraReport {
                entries: report.entries,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Parsing: the document into definitions that still reference by id.
// ---------------------------------------------------------------------------

/// The kind of definition a member references.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefKind {
    /// A `fieldRef`.
    Field,
    /// A `componentRef`.
    Component,
    /// A `groupRef`.
    Group,
}

/// A member of a component, group or message, referencing by id.
#[derive(Debug)]
struct RawRef {
    kind: RefKind,
    id: u32,
    required: bool,
}

/// A `datatype`.
#[derive(Debug)]
struct RawDatatype {
    name: String,
    base: Option<String>,
}

/// A `codeSet` in the `base` scenario.
#[derive(Debug)]
struct RawCodeSet {
    id: u32,
    name: String,
    type_name: String,
    /// `(value, name)` of each `base` code, in document order.
    codes: Vec<(String, String)>,
}

/// A `field` in the `base` scenario.
#[derive(Debug)]
struct RawField {
    id: u32,
    name: String,
    type_name: String,
}

/// A `component` in the `base` scenario.
#[derive(Debug)]
struct RawComponent {
    id: u32,
    name: String,
    members: Vec<RawRef>,
}

/// A `group` in the `base` scenario.
#[derive(Debug)]
struct RawGroup {
    id: u32,
    name: String,
    /// The `numInGroup` field id.
    count: Option<u32>,
    members: Vec<RawRef>,
}

/// A `message` in the `base` scenario.
#[derive(Debug)]
struct RawMessage {
    id: u32,
    name: String,
    msg_type: String,
    category: MessageCategory,
    members: Vec<RawRef>,
}

/// Every `base` definition of a repository, in document order.
#[derive(Debug)]
struct Raw {
    version: Version,
    datatypes: Vec<RawDatatype>,
    code_sets: Vec<RawCodeSet>,
    fields: Vec<RawField>,
    components: Vec<RawComponent>,
    groups: Vec<RawGroup>,
    messages: Vec<RawMessage>,
}

impl Raw {
    fn new(version: Version) -> Self {
        Self {
            version,
            datatypes: Vec::new(),
            code_sets: Vec::new(),
            fields: Vec::new(),
            components: Vec::new(),
            groups: Vec::new(),
            messages: Vec::new(),
        }
    }
}

/// The start of a child element, read by [`Parser::next_child`].
struct Child<'i> {
    start: BytesStart<'i>,
    /// Self-closing: no content and no end tag follow.
    empty: bool,
    /// In [`ORCHESTRA_NAMESPACE`].
    ours: bool,
}

impl Child<'_> {
    /// The element's local name.
    fn local(&self) -> &str {
        self.start.local_name().into_inner()
    }

    /// The element's name as written, prefix included.
    fn qualified(&self) -> &str {
        self.start.name().0
    }

    /// True for an Orchestra element named `local`.
    fn is(&self, local: &str) -> bool {
        self.ours && self.local() == local
    }
}

/// The attributes of one element, consumed as they are mapped.
struct Attrs {
    list: Vec<(String, String)>,
}

impl Attrs {
    /// Reads the attributes of `start`, leaving out namespace declarations
    /// and the `xml:` attributes. The element's name has been checked
    /// ([`check_name`]) by whoever read `start`.
    ///
    /// # Errors
    /// [`DictionaryError::AttributesTooLong`] past
    /// [`MAX_ORCHESTRA_ATTRIBUTES_LEN`], [`DictionaryError::NameTooLong`]
    /// for an attribute name, or a value the loader keeps (any but a
    /// descriptive one), past [`MAX_ORCHESTRA_NAME_LEN`], and
    /// [`DictionaryError::Xml`] for a malformed attribute.
    fn read(start: &BytesStart<'_>) -> Result<Self, DictionaryError> {
        let element = start.name().0;
        let len = start.attributes_raw().len();
        if len > MAX_ORCHESTRA_ATTRIBUTES_LEN {
            return Err(DictionaryError::AttributesTooLong {
                element: element.to_owned(),
                len,
                limit: MAX_ORCHESTRA_ATTRIBUTES_LEN,
            });
        }
        let mut list = Vec::new();
        for attr in start.attributes() {
            let attr = attr.map_err(xml_err)?;
            let key = attr.key.0;
            if key == "xmlns" || key.starts_with("xmlns:") || key.starts_with("xml:") {
                continue;
            }
            check_name(key.len(), || format!("an attribute name of <{element}>"))?;
            let value = attr
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(xml_err)?
                .into_owned();
            if !DESCRIPTIVE_ATTRIBUTES.contains(&key) {
                check_name(value.len(), || {
                    format!("the value of attribute `{key}` of <{element}>")
                })?;
            }
            list.push((key.to_owned(), value));
        }
        Ok(Self { list })
    }

    /// Removes and returns attribute `key`.
    fn take(&mut self, key: &str) -> Option<String> {
        let index = self.list.iter().position(|(name, _)| name == key)?;
        Some(self.list.remove(index).1)
    }

    /// Removes and returns attribute `key` of `element`, which must be there.
    fn required(&mut self, element: &str, key: &str) -> Result<String, DictionaryError> {
        self.take(key)
            .ok_or_else(|| DictionaryError::MissingAttribute {
                element: element.to_owned(),
                attribute: key.to_owned(),
            })
    }

    /// Removes and parses attribute `id` of `element`.
    fn id(&mut self, element: &str) -> Result<u32, DictionaryError> {
        let value = self.required(element, "id")?;
        parse_id(element, value)
    }

    /// Reports every attribute left that constrains rather than describes.
    fn report_rest(self, location: &str, report: &mut Report) -> Result<(), DictionaryError> {
        for (name, value) in self.list {
            let descriptive = DESCRIPTIVE_ATTRIBUTES.contains(&name.as_str())
                || (name == "supported" && value == "supported");
            if !descriptive {
                report.push(UnmappedConstruct::Attribute {
                    location: location.to_owned(),
                    name,
                    value,
                })?;
            }
        }
        Ok(())
    }
}

/// Refuses a name or value of `len` bytes past [`MAX_ORCHESTRA_NAME_LEN`];
/// `what` describes it, without repeating it.
fn check_name(len: usize, what: impl FnOnce() -> String) -> Result<(), DictionaryError> {
    if len > MAX_ORCHESTRA_NAME_LEN {
        return Err(DictionaryError::NameTooLong {
            what: what(),
            len,
            limit: MAX_ORCHESTRA_NAME_LEN,
        });
    }
    Ok(())
}

/// Refuses an element whose name, as written, is longer than
/// [`MAX_ORCHESTRA_NAME_LEN`].
fn check_element(start: &BytesStart<'_>) -> Result<(), DictionaryError> {
    check_name(start.name().0.len(), || "an element name".to_owned())
}

/// Parses an Orchestra id: a positive integer that fits a `u32`.
fn parse_id(element: &str, value: String) -> Result<u32, DictionaryError> {
    match value.parse::<u32>() {
        Ok(id) if id > 0 => Ok(id),
        _ => Err(DictionaryError::InvalidOrchestraId {
            element: element.to_owned(),
            value,
        }),
    }
}

/// Maps a `repository/@version` to the FIX version it names.
///
/// # Errors
/// [`DictionaryError::UnsupportedVersion`] for `FIX.Latest`, the pre-4.0
/// versions, and any version that is not a FIX version.
fn parse_version(version: &str) -> Result<Version, DictionaryError> {
    let unsupported = || DictionaryError::UnsupportedVersion(version.to_owned());
    // An extension-pack suffix (`FIX.4.4_EP311`) names a revision of the
    // same version.
    let name = match version.split_once("_EP") {
        Some((name, pack)) if !pack.is_empty() && pack.bytes().all(|b| b.is_ascii_digit()) => name,
        Some(_) => return Err(unsupported()),
        None => version,
    };
    match name {
        "FIX.4.0" => Ok(Version::Fix40),
        "FIX.4.1" => Ok(Version::Fix41),
        "FIX.4.2" => Ok(Version::Fix42),
        "FIX.4.3" => Ok(Version::Fix43),
        "FIX.4.4" => Ok(Version::Fix44),
        "FIX.5.0" => Ok(Version::Fix50),
        "FIX.5.0SP1" => Ok(Version::Fix50Sp1),
        "FIX.5.0SP2" => Ok(Version::Fix50Sp2),
        "FIXT.1.1" => Ok(Version::Fixt11),
        _ => Err(unsupported()),
    }
}

fn xml_err(e: impl fmt::Display) -> DictionaryError {
    DictionaryError::Xml(e.to_string())
}

fn eof() -> DictionaryError {
    DictionaryError::Xml("unexpected end of file".to_owned())
}

/// Reads a repository into [`Raw`] definitions and the report.
struct Parser<'i> {
    reader: NsReader<&'i [u8]>,
    /// Depth of the element the reader is inside; the root is 1.
    depth: usize,
    report: Report,
}

impl<'i> Parser<'i> {
    fn new(xml: &'i str) -> Self {
        Self {
            reader: NsReader::from_str(xml),
            depth: 0,
            report: Report::default(),
        }
    }

    /// Records entering an element, refusing nesting past
    /// [`MAX_NESTING_DEPTH`].
    fn enter(&mut self, start: &BytesStart<'_>) -> Result<(), DictionaryError> {
        let too_deep = || DictionaryError::NestingTooDeep {
            element: start.local_name().into_inner().to_owned(),
            limit: MAX_NESTING_DEPTH,
        };
        self.depth = self
            .depth
            .checked_add(1)
            .filter(|depth| *depth <= MAX_NESTING_DEPTH)
            .ok_or_else(too_deep)?;
        Ok(())
    }

    /// Records leaving an element.
    fn leave(&mut self) -> Result<(), DictionaryError> {
        self.depth = self
            .depth
            .checked_sub(1)
            .ok_or_else(|| DictionaryError::Xml("unbalanced end tag".to_owned()))?;
        Ok(())
    }

    /// Reads the next child element of the element the reader is inside,
    /// passing over text, comments and processing instructions; `None` once
    /// that element's end tag is read.
    fn next_child(&mut self) -> Result<Option<Child<'i>>, DictionaryError> {
        loop {
            let (namespace, event) = self.reader.read_resolved_event().map_err(xml_err)?;
            let ours = matches!(
                namespace,
                ResolveResult::Bound(Namespace(uri)) if uri == ORCHESTRA_NAMESPACE
            );
            match event {
                Event::Start(start) => {
                    check_element(&start)?;
                    self.enter(&start)?;
                    return Ok(Some(Child {
                        start,
                        empty: false,
                        ours,
                    }));
                }
                Event::Empty(start) => {
                    check_element(&start)?;
                    return Ok(Some(Child {
                        start,
                        empty: true,
                        ours,
                    }));
                }
                Event::End(_) => {
                    self.leave()?;
                    return Ok(None);
                }
                Event::Eof => return Err(eof()),
                Event::Text(_)
                | Event::CData(_)
                | Event::Comment(_)
                | Event::Decl(_)
                | Event::PI(_)
                | Event::DocType(_)
                | Event::GeneralRef(_) => {}
            }
        }
    }

    /// Skips the content of `child`, up to and including its end tag,
    /// without recursion.
    fn skip(&mut self, child: &Child<'_>) -> Result<(), DictionaryError> {
        if child.empty {
            return Ok(());
        }
        let outside = self.depth.checked_sub(1).ok_or_else(eof)?;
        loop {
            match self.reader.read_event().map_err(xml_err)? {
                Event::Start(start) => self.enter(&start)?,
                Event::End(_) => {
                    self.leave()?;
                    if self.depth == outside {
                        return Ok(());
                    }
                }
                Event::Eof => return Err(eof()),
                _ => {}
            }
        }
    }

    /// Handles a child the current element does not map: an `annotation` is
    /// skipped silently, anything else is reported, then skipped.
    fn other(&mut self, child: &Child<'_>, location: &str) -> Result<(), DictionaryError> {
        if !child.is("annotation") {
            self.report.push(UnmappedConstruct::Element {
                location: format!("{location}/{}", child.qualified()),
            })?;
        }
        self.skip(child)
    }

    /// Handles the children of an element that maps none: `annotation` and
    /// the `silent` ones are skipped, a `rule` is reported as such, anything
    /// else as an element.
    fn leaf_children(
        &mut self,
        parent: &Child<'_>,
        location: &str,
        silent: &[&str],
    ) -> Result<(), DictionaryError> {
        if parent.empty {
            return Ok(());
        }
        while let Some(child) = self.next_child()? {
            if child.ours && silent.contains(&child.local()) {
                self.skip(&child)?;
            } else if child.is("rule") {
                self.rule(&child, location)?;
            } else {
                self.other(&child, location)?;
            }
        }
        Ok(())
    }

    /// Reports a conditional presence `rule` with its name, presence and
    /// `when` condition; its other content (`assign`, `unique`) goes with it.
    fn rule(&mut self, child: &Child<'_>, location: &str) -> Result<(), DictionaryError> {
        let mut attrs = Attrs::read(&child.start)?;
        let name = attrs.take("name");
        let presence = attrs.take("presence");
        let mut condition = None;
        if !child.empty {
            while let Some(part) = self.next_child()? {
                if part.is("when") && condition.is_none() {
                    condition = Some(self.text(&part)?);
                } else {
                    self.skip(&part)?;
                }
            }
        }
        self.report.push(UnmappedConstruct::Rule {
            location: location.to_owned(),
            name,
            presence,
            condition,
        })
    }

    /// Reads the text of `child` (an expression), resolving character and
    /// predefined entity references; markup inside it is skipped.
    ///
    /// The text is copied once, from the document, so the condition of every
    /// rule together is at most as long as the document.
    fn text(&mut self, child: &Child<'_>) -> Result<String, DictionaryError> {
        let mut text = String::new();
        if child.empty {
            return Ok(text);
        }
        let outside = self.depth.checked_sub(1).ok_or_else(eof)?;
        loop {
            match self.reader.read_event().map_err(xml_err)? {
                Event::Text(part) if self.depth == outside + 1 => {
                    text.push_str(&part.xml10_content());
                }
                Event::CData(part) if self.depth == outside + 1 => {
                    text.push_str(&part.xml10_content());
                }
                Event::GeneralRef(reference) if self.depth == outside + 1 => {
                    match reference.resolve_char_ref().map_err(xml_err)? {
                        Some(ch) => text.push(ch),
                        None => {
                            let name = reference.xml10_content();
                            let resolved = quick_xml::escape::resolve_predefined_entity(&name)
                                .ok_or_else(|| {
                                    DictionaryError::Xml(format!("unknown entity `&{name};`"))
                                })?;
                            text.push_str(resolved);
                        }
                    }
                }
                Event::Start(start) => self.enter(&start)?,
                Event::End(_) => {
                    self.leave()?;
                    if self.depth == outside {
                        return Ok(text);
                    }
                }
                Event::Eof => return Err(eof()),
                _ => {}
            }
        }
    }

    /// Reads the whole document.
    fn repository(&mut self) -> Result<Raw, DictionaryError> {
        let root = self.root()?;
        let mut attrs = Attrs::read(&root.start)?;
        let declared = attrs.required("repository", "version")?;
        let version = parse_version(&declared)?;
        // The stable name (`FIX.4.4`, `FIXT`) is descriptive, except that a
        // FIXT repository can only describe FIXT.1.1: one that declares
        // another version (the FIX Trading Community's session repository
        // declares `FIX.5.0SP2_EP247`) names no version the loader can map.
        if attrs.take("name").as_deref() == Some("FIXT") && version != Version::Fixt11 {
            return Err(DictionaryError::UnsupportedVersion(format!(
                "{declared} (repository FIXT)"
            )));
        }
        attrs.report_rest("repository", &mut self.report)?;
        let mut raw = Raw::new(version);
        if !root.empty {
            while let Some(child) = self.next_child()? {
                if !child.ours {
                    self.other(&child, "repository")?;
                    continue;
                }
                // A mapped section's own attributes are read like any
                // element's: bounded, and reported unless descriptive
                // (`latestEP`, `xml:base`), self-closing sections included.
                let section = child.local();
                if MAPPED_SECTIONS.contains(&section) {
                    Attrs::read(&child.start)?.report_rest(section, &mut self.report)?;
                }
                match child.local() {
                    "datatypes" => self.datatypes(&child, &mut raw)?,
                    "codeSets" => self.code_sets(&child, &mut raw)?,
                    "fields" => self.fields(&child, &mut raw)?,
                    "components" => self.components(&child, &mut raw)?,
                    "groups" => self.groups(&child, &mut raw)?,
                    "messages" => self.messages(&child, &mut raw)?,
                    // Descriptive: Dublin Core metadata and the business
                    // categories and sections messages are filed under.
                    "metadata" | "categories" | "sections" => self.skip(&child)?,
                    _ => self.other(&child, "repository")?,
                }
            }
        }
        self.rest()?;
        Ok(raw)
    }

    /// Reads the prolog and the root element, which must be an Orchestra
    /// `repository`. The prolog may hold only what XML allows there
    /// ([`Prolog`]): whitespace, comments, processing instructions, the XML
    /// declaration first and one document type declaration.
    fn root(&mut self) -> Result<Child<'i>, DictionaryError> {
        let mut prolog = Prolog::default();
        loop {
            let (namespace, event) = self.reader.read_resolved_event().map_err(xml_err)?;
            let found = match &namespace {
                ResolveResult::Bound(Namespace(uri)) => Some((*uri).to_owned()),
                ResolveResult::Unbound | ResolveResult::Unknown(_) => None,
            };
            let (start, empty) = match event {
                Event::Start(start) => (start, false),
                Event::Empty(start) => (start, true),
                Event::Eof => return Err(eof()),
                other => {
                    prolog.accept(&other)?;
                    continue;
                }
            };
            check_element(&start)?;
            let ours = found.as_deref() == Some(ORCHESTRA_NAMESPACE);
            if !ours || start.local_name().into_inner() != "repository" {
                let element = start.name().0;
                return Err(DictionaryError::NotOrchestra(match found {
                    Some(uri) => format!("<{element}> in namespace `{uri}`"),
                    None => format!("<{element}> in no namespace"),
                }));
            }
            if !empty {
                self.enter(&start)?;
            }
            return Ok(Child { start, empty, ours });
        }
    }

    /// Reads past the root element to the end of the document: only
    /// whitespace, comments and processing instructions may follow it
    /// ([`epilog`]), so text, a CDATA section, a reference or a second
    /// element there is an error, not a repository read from part of the
    /// document.
    fn rest(&mut self) -> Result<(), DictionaryError> {
        loop {
            match self.reader.read_event().map_err(xml_err)? {
                Event::Eof => return Ok(()),
                event => epilog(&event)?,
            }
        }
    }

    /// Reads a `datatypes` section.
    fn datatypes(&mut self, parent: &Child<'_>, raw: &mut Raw) -> Result<(), DictionaryError> {
        if parent.empty {
            return Ok(());
        }
        while let Some(child) = self.next_child()? {
            if !child.is("datatype") {
                self.other(&child, "datatypes")?;
                continue;
            }
            let mut attrs = Attrs::read(&child.start)?;
            let name = attrs.required("datatype", "name")?;
            let base = attrs.take("baseType");
            let location = format!("datatype {name}");
            attrs.report_rest(&location, &mut self.report)?;
            // How the datatype is encoded in XML, SBE, ...: descriptive.
            self.leaf_children(&child, &location, &["mappedDatatype"])?;
            raw.datatypes.push(RawDatatype { name, base });
        }
        Ok(())
    }

    /// Reads a `codeSets` section.
    fn code_sets(&mut self, parent: &Child<'_>, raw: &mut Raw) -> Result<(), DictionaryError> {
        if parent.empty {
            return Ok(());
        }
        while let Some(child) = self.next_child()? {
            if !child.is("codeSet") {
                self.other(&child, "codeSets")?;
                continue;
            }
            let mut attrs = Attrs::read(&child.start)?;
            let id = attrs.id("codeSet")?;
            let name = attrs.required("codeSet", "name")?;
            let type_name = attrs.required("codeSet", "type")?;
            let scenario = attrs.take("scenario");
            let location = format!("code set {name}");
            attrs.report_rest(&location, &mut self.report)?;
            if let Some(scenario) = scenario.filter(|s| s != BASE_SCENARIO) {
                self.report.push(UnmappedConstruct::Scenario {
                    kind: OrchestraKind::CodeSet,
                    name,
                    scenario,
                })?;
                self.skip(&child)?;
                continue;
            }
            let codes = self.codes(&child, &name)?;
            raw.code_sets.push(RawCodeSet {
                id,
                name,
                type_name,
                codes,
            });
        }
        Ok(())
    }

    /// Reads the `code` children of code set `set`.
    fn codes(
        &mut self,
        parent: &Child<'_>,
        set: &str,
    ) -> Result<Vec<(String, String)>, DictionaryError> {
        let mut codes = Vec::new();
        if parent.empty {
            return Ok(codes);
        }
        let set_location = format!("code set {set}");
        // The ids of the set's `base` codes: unique within the set, as the
        // ids of every other kind of definition are (a code in another
        // scenario may reuse a `base` code's id).
        let mut ids = HashSet::new();
        while let Some(child) = self.next_child()? {
            if !child.is("code") {
                self.other(&child, &set_location)?;
                continue;
            }
            let mut attrs = Attrs::read(&child.start)?;
            let id = attrs.id("code")?;
            let name = attrs.required("code", "name")?;
            let value = attrs.required("code", "value")?;
            let scenario = attrs.take("scenario");
            let location = format!("{set_location}/code {name}");
            attrs.report_rest(&location, &mut self.report)?;
            self.leaf_children(&child, &location, &[])?;
            if let Some(scenario) = scenario.filter(|s| s != BASE_SCENARIO) {
                self.report.push(UnmappedConstruct::Scenario {
                    kind: OrchestraKind::Code,
                    name: format!("{set}.{name}"),
                    scenario,
                })?;
                continue;
            }
            if !ids.insert(id) {
                return Err(DictionaryError::DuplicateOrchestraDefinition {
                    kind: OrchestraKind::Code,
                    key: format!("{set} id {id}"),
                });
            }
            codes.push((value, name));
        }
        Ok(codes)
    }

    /// Reads a `fields` section.
    fn fields(&mut self, parent: &Child<'_>, raw: &mut Raw) -> Result<(), DictionaryError> {
        if parent.empty {
            return Ok(());
        }
        while let Some(child) = self.next_child()? {
            if !child.is("field") {
                self.other(&child, "fields")?;
                continue;
            }
            let mut attrs = Attrs::read(&child.start)?;
            let id = attrs.id("field")?;
            let name = attrs.required("field", "name")?;
            let type_name = attrs.required("field", "type")?;
            let scenario = attrs.take("scenario");
            let location = format!("field {name}");
            attrs.report_rest(&location, &mut self.report)?;
            if let Some(scenario) = scenario.filter(|s| s != BASE_SCENARIO) {
                self.report.push(UnmappedConstruct::Scenario {
                    kind: OrchestraKind::Field,
                    name,
                    scenario,
                })?;
                self.skip(&child)?;
                continue;
            }
            self.leaf_children(&child, &location, &[])?;
            raw.fields.push(RawField {
                id,
                name,
                type_name,
            });
        }
        Ok(())
    }

    /// Reads a `components` section.
    fn components(&mut self, parent: &Child<'_>, raw: &mut Raw) -> Result<(), DictionaryError> {
        if parent.empty {
            return Ok(());
        }
        while let Some(child) = self.next_child()? {
            if !child.is("component") {
                self.other(&child, "components")?;
                continue;
            }
            let mut attrs = Attrs::read(&child.start)?;
            let id = attrs.id("component")?;
            let name = attrs.required("component", "name")?;
            let scenario = attrs.take("scenario");
            let location = format!("component {name}");
            attrs.report_rest(&location, &mut self.report)?;
            if let Some(scenario) = scenario.filter(|s| s != BASE_SCENARIO) {
                self.report.push(UnmappedConstruct::Scenario {
                    kind: OrchestraKind::Component,
                    name,
                    scenario,
                })?;
                self.skip(&child)?;
                continue;
            }
            let (_, members) = self.members(&child, &location, false)?;
            raw.components.push(RawComponent { id, name, members });
        }
        Ok(())
    }

    /// Reads a `groups` section.
    fn groups(&mut self, parent: &Child<'_>, raw: &mut Raw) -> Result<(), DictionaryError> {
        if parent.empty {
            return Ok(());
        }
        while let Some(child) = self.next_child()? {
            if !child.is("group") {
                self.other(&child, "groups")?;
                continue;
            }
            let mut attrs = Attrs::read(&child.start)?;
            let id = attrs.id("group")?;
            let name = attrs.required("group", "name")?;
            let scenario = attrs.take("scenario");
            let location = format!("group {name}");
            attrs.report_rest(&location, &mut self.report)?;
            if let Some(scenario) = scenario.filter(|s| s != BASE_SCENARIO) {
                self.report.push(UnmappedConstruct::Scenario {
                    kind: OrchestraKind::Group,
                    name,
                    scenario,
                })?;
                self.skip(&child)?;
                continue;
            }
            let (count, members) = self.members(&child, &location, true)?;
            raw.groups.push(RawGroup {
                id,
                name,
                count,
                members,
            });
        }
        Ok(())
    }

    /// Reads a `messages` section.
    fn messages(&mut self, parent: &Child<'_>, raw: &mut Raw) -> Result<(), DictionaryError> {
        if parent.empty {
            return Ok(());
        }
        while let Some(child) = self.next_child()? {
            if !child.is("message") {
                self.other(&child, "messages")?;
                continue;
            }
            let mut attrs = Attrs::read(&child.start)?;
            let id = attrs.id("message")?;
            let name = attrs.required("message", "name")?;
            let msg_type = attrs.required("message", "msgType")?;
            let scenario = attrs.take("scenario");
            let category = if attrs.take("category").as_deref() == Some(ADMIN_CATEGORY) {
                MessageCategory::Admin
            } else {
                MessageCategory::App
            };
            let location = format!("message {name}");
            attrs.report_rest(&location, &mut self.report)?;
            if let Some(scenario) = scenario.filter(|s| s != BASE_SCENARIO) {
                self.report.push(UnmappedConstruct::Scenario {
                    kind: OrchestraKind::Message,
                    name,
                    scenario,
                })?;
                self.skip(&child)?;
                continue;
            }
            let members = self.structure(&child, &location)?;
            raw.messages.push(RawMessage {
                id,
                name,
                msg_type,
                category,
                members,
            });
        }
        Ok(())
    }

    /// Reads the `structure` of a message: its members. Its `responses`
    /// (workflow) are reported; a second `structure` is reported too.
    fn structure(
        &mut self,
        parent: &Child<'_>,
        location: &str,
    ) -> Result<Vec<RawRef>, DictionaryError> {
        let mut members: Option<Vec<RawRef>> = None;
        if parent.empty {
            return Ok(Vec::new());
        }
        while let Some(child) = self.next_child()? {
            if child.is("structure") && members.is_none() {
                // Its only attribute, `which` (oneOf / anyOf member
                // selection), is a constraint, so it is reported.
                let attrs = Attrs::read(&child.start)?;
                let structure_location = format!("{location}/structure");
                attrs.report_rest(&structure_location, &mut self.report)?;
                members = Some(self.members(&child, location, false)?.1);
            } else {
                self.other(&child, location)?;
            }
        }
        Ok(members.unwrap_or_default())
    }

    /// Reads the members of a component, group or message structure, and a
    /// group's `numInGroup` when `counted`.
    fn members(
        &mut self,
        parent: &Child<'_>,
        location: &str,
        counted: bool,
    ) -> Result<(Option<u32>, Vec<RawRef>), DictionaryError> {
        let mut count = None;
        let mut members = Vec::new();
        if parent.empty {
            return Ok((count, members));
        }
        while let Some(child) = self.next_child()? {
            if !child.ours {
                self.other(&child, location)?;
                continue;
            }
            let kind = match child.local() {
                "fieldRef" => RefKind::Field,
                "componentRef" => RefKind::Component,
                "groupRef" => RefKind::Group,
                "numInGroup" if counted && count.is_none() => {
                    count = self.count(&child, location)?;
                    continue;
                }
                _ => {
                    self.other(&child, location)?;
                    continue;
                }
            };
            if let Some(member) = self.member(&child, kind, location)? {
                members.push(member);
            }
        }
        Ok((count, members))
    }

    /// Reads a group's `numInGroup`: the id of its count field.
    fn count(&mut self, child: &Child<'_>, location: &str) -> Result<Option<u32>, DictionaryError> {
        let mut attrs = Attrs::read(&child.start)?;
        let id = attrs.id("numInGroup")?;
        let scenario = attrs.take("scenario");
        let member_location = format!("{location}/numInGroup {id}");
        attrs.report_rest(&member_location, &mut self.report)?;
        self.leaf_children(child, &member_location, &[])?;
        if let Some(scenario) = scenario.filter(|s| s != BASE_SCENARIO) {
            self.report.push(UnmappedConstruct::ScenarioReference {
                location: member_location,
                scenario,
            })?;
            return Ok(None);
        }
        Ok(Some(id))
    }

    /// Reads one `fieldRef`, `componentRef` or `groupRef`; `None` when the
    /// member is left out (and reported).
    fn member(
        &mut self,
        child: &Child<'_>,
        kind: RefKind,
        location: &str,
    ) -> Result<Option<RawRef>, DictionaryError> {
        let element = child.local();
        let mut attrs = Attrs::read(&child.start)?;
        let id = attrs.id(element)?;
        let member_location = format!("{location}/{element} {id}");
        let scenario = attrs.take("scenario");
        let presence = attrs.take("presence");
        let value = attrs.take("value");
        let mut keep = true;
        let mapped = match presence.as_deref() {
            None | Some("optional") => Some(false),
            Some("required") => Some(true),
            Some(_) => None,
        };
        let required = match (mapped, presence) {
            (Some(required), _) => {
                // A value next to a presence the dictionary maps is a
                // constraint it has no place for.
                if let Some(value) = value {
                    self.report.push(UnmappedConstruct::Attribute {
                        location: member_location.clone(),
                        name: "value".to_owned(),
                        value,
                    })?;
                }
                required
            }
            (None, None) => false,
            (None, Some(presence)) => {
                // `forbidden`: the member must not appear, so the
                // definition leaves it out. `ignored`, `constant` and any
                // undefined value keep it, optional. The value, if any, is
                // reported with the presence.
                keep = presence != "forbidden";
                self.report.push(UnmappedConstruct::Presence {
                    location: member_location.clone(),
                    presence,
                    value,
                })?;
                false
            }
        };
        attrs.report_rest(&member_location, &mut self.report)?;
        self.leaf_children(child, &member_location, &[])?;
        if let Some(scenario) = scenario.filter(|s| s != BASE_SCENARIO) {
            self.report.push(UnmappedConstruct::ScenarioReference {
                location: member_location,
                scenario,
            })?;
            return Ok(None);
        }
        Ok(keep.then_some(RawRef { kind, id, required }))
    }
}

// ---------------------------------------------------------------------------
// Resolution: ids into the name references the shared assembly step takes.
// ---------------------------------------------------------------------------

/// The values of a code set: code value to code name.
type Values = HashMap<String, String>;

/// The FIX data types of the declared datatypes and code sets.
struct Types<'r> {
    /// Declared datatypes: name to base type.
    datatypes: HashMap<&'r str, Option<&'r str>>,
    /// Code sets: name to data type and values.
    code_sets: HashMap<&'r str, (FieldType, Values)>,
}

impl<'r> Types<'r> {
    fn new(raw: &'r Raw) -> Result<Self, DictionaryError> {
        let mut datatypes = HashMap::with_capacity(raw.datatypes.len());
        for datatype in &raw.datatypes {
            if datatypes
                .insert(datatype.name.as_str(), datatype.base.as_deref())
                .is_some()
            {
                return Err(DictionaryError::DuplicateOrchestraDefinition {
                    kind: OrchestraKind::Datatype,
                    key: datatype.name.clone(),
                });
            }
        }
        let mut types = Self {
            datatypes,
            code_sets: HashMap::with_capacity(raw.code_sets.len()),
        };
        let mut ids = HashSet::with_capacity(raw.code_sets.len());
        for set in &raw.code_sets {
            // Field `type`s name a datatype or a code set, so the two share
            // one name space.
            let duplicate_name = types.code_sets.contains_key(set.name.as_str())
                || types.datatypes.contains_key(set.name.as_str());
            if duplicate_name || !ids.insert(set.id) {
                return Err(DictionaryError::DuplicateOrchestraDefinition {
                    kind: OrchestraKind::CodeSet,
                    key: if duplicate_name {
                        set.name.clone()
                    } else {
                        set.id.to_string()
                    },
                });
            }
            let field_type =
                types
                    .datatype(&set.type_name)
                    .ok_or_else(|| DictionaryError::UnknownDatatype {
                        owner: format!("code set {}", set.name),
                        datatype: set.type_name.clone(),
                    })?;
            let mut values = HashMap::with_capacity(set.codes.len());
            for (value, name) in &set.codes {
                if values.insert(value.clone(), name.clone()).is_some() {
                    return Err(DictionaryError::DuplicateOrchestraDefinition {
                        kind: OrchestraKind::Code,
                        key: format!("{} value {value}", set.name),
                    });
                }
            }
            types
                .code_sets
                .insert(set.name.as_str(), (field_type, values));
        }
        Ok(types)
    }

    /// The FIX data type of declared datatype `name`: its own when its name
    /// is a FIX data type, else its base type's, following at most
    /// [`MAX_COMPONENT_DEPTH`] base types (which also ends a cycle).
    fn datatype(&self, name: &str) -> Option<FieldType> {
        let mut current = name;
        for _ in 0..=MAX_COMPONENT_DEPTH {
            let base = self.datatypes.get(current)?;
            if let Ok(field_type) = current.parse::<FieldType>() {
                return Some(field_type);
            }
            current = (*base)?;
        }
        None
    }

    /// The data type and values of `field`.
    fn field(&self, field: &RawField) -> Result<(FieldType, Option<&Values>), DictionaryError> {
        if let Some((field_type, values)) = self.code_sets.get(field.type_name.as_str()) {
            return Ok((*field_type, Some(values)));
        }
        self.datatype(&field.type_name)
            .map(|field_type| (field_type, None))
            .ok_or_else(|| DictionaryError::UnknownFieldType {
                field: field.name.clone(),
                field_type: field.type_name.clone(),
            })
    }
}

/// Where a member list sits, which decides how its component references
/// resolve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// A message's own members: the header and trailer references are the
    /// dictionary's envelope, not members.
    Message,
    /// A component's or a group's members.
    Definition,
    /// The standard header's or trailer's members: a component is expanded
    /// in place.
    Envelope,
}

/// Resolves id references into name [`Item`]s, expanding groups inline.
struct Expander<'r> {
    fields: HashMap<u32, &'r str>,
    components: HashMap<u32, &'r RawComponent>,
    groups: HashMap<u32, &'r RawGroup>,
    /// The `StandardHeader` and `StandardTrailer` component ids.
    envelope: [Option<u32>; 2],
    /// Members still allowed before [`MAX_ORCHESTRA_MEMBERS`].
    budget: usize,
    /// Groups being expanded, outermost first.
    open_groups: Vec<u32>,
    /// Envelope components being expanded, outermost first.
    open_components: Vec<u32>,
}

impl Expander<'_> {
    /// Counts one member against [`MAX_ORCHESTRA_MEMBERS`].
    fn spend(&mut self) -> Result<(), DictionaryError> {
        self.budget = self
            .budget
            .checked_sub(1)
            .ok_or(DictionaryError::TooManyMembers {
                limit: MAX_ORCHESTRA_MEMBERS,
            })?;
        Ok(())
    }

    fn field(&self, id: u32, owner: &str) -> Result<&str, DictionaryError> {
        self.fields
            .get(&id)
            .copied()
            .ok_or_else(|| DictionaryError::UnknownOrchestraReference {
                kind: OrchestraKind::Field,
                id,
                owner: owner.to_owned(),
            })
    }

    /// Resolves `members`. `depth` is the nesting depth of the list itself,
    /// counted as the QuickFIX loader counts elements: a message, component
    /// or envelope is 1, each group one more.
    fn items(
        &mut self,
        members: &[RawRef],
        owner: &str,
        scope: Scope,
        depth: usize,
    ) -> Result<Vec<Item>, DictionaryError> {
        let mut items = Vec::with_capacity(members.len());
        for member in members {
            self.spend()?;
            match member.kind {
                RefKind::Field => items.push(Item::Field {
                    name: self.field(member.id, owner)?.to_owned(),
                    required: member.required,
                }),
                RefKind::Component => {
                    let component = self.components.get(&member.id).copied().ok_or_else(|| {
                        DictionaryError::UnknownOrchestraReference {
                            kind: OrchestraKind::Component,
                            id: member.id,
                            owner: owner.to_owned(),
                        }
                    })?;
                    if self.envelope.contains(&Some(member.id)) {
                        if scope == Scope::Message {
                            continue;
                        }
                        return Err(DictionaryError::EnvelopeReference {
                            component: component.name.clone(),
                            owner: owner.to_owned(),
                        });
                    }
                    if scope == Scope::Envelope {
                        let mut expanded = self.envelope_component(component)?;
                        // An optional block's members are only required when
                        // the block is there: expanded in place, they take
                        // its presence. Members of a group's entries keep
                        // theirs (they are required per entry).
                        if !member.required {
                            for item in &mut expanded {
                                match item {
                                    Item::Field { required, .. }
                                    | Item::Group { required, .. }
                                    | Item::Component { required, .. } => *required = false,
                                }
                            }
                        }
                        items.extend(expanded);
                    } else {
                        items.push(Item::Component {
                            name: component.name.clone(),
                            required: member.required,
                        });
                    }
                }
                RefKind::Group => items.push(self.group(member, owner, depth)?),
            }
        }
        Ok(items)
    }

    /// Expands a group reference inline, named after its count field.
    fn group(
        &mut self,
        member: &RawRef,
        owner: &str,
        depth: usize,
    ) -> Result<Item, DictionaryError> {
        let group = self.groups.get(&member.id).copied().ok_or_else(|| {
            DictionaryError::UnknownOrchestraReference {
                kind: OrchestraKind::Group,
                id: member.id,
                owner: owner.to_owned(),
            }
        })?;
        if self.open_groups.contains(&group.id) {
            return Err(DictionaryError::GroupCycle(group.name.clone()));
        }
        let inner = depth
            .checked_add(1)
            .filter(|inner| *inner <= MAX_NESTING_DEPTH)
            .ok_or_else(|| DictionaryError::NestingTooDeep {
                element: group.name.clone(),
                limit: MAX_NESTING_DEPTH,
            })?;
        let location = format!("group {}", group.name);
        let count = group
            .count
            .ok_or_else(|| DictionaryError::MissingCountField(group.name.clone()))?;
        let name = self.field(count, &location)?.to_owned();
        self.open_groups.push(group.id);
        let items = self.items(&group.members, &location, Scope::Definition, inner)?;
        self.open_groups.pop();
        Ok(Item::Group {
            name,
            required: member.required,
            items,
        })
    }

    /// Checks a group without expanding it: its count field and every id
    /// it references resolve, and it has a member.
    fn check_group(&self, group: &RawGroup) -> Result<(), DictionaryError> {
        let location = format!("group {}", group.name);
        let count = group
            .count
            .ok_or_else(|| DictionaryError::MissingCountField(group.name.clone()))?;
        let count_name = self.field(count, &location)?;
        if group.members.is_empty() {
            return Err(DictionaryError::EmptyGroup(count_name.to_owned()));
        }
        for member in &group.members {
            let (kind, found) = match member.kind {
                RefKind::Field => (OrchestraKind::Field, self.fields.contains_key(&member.id)),
                RefKind::Component => (
                    OrchestraKind::Component,
                    self.components.contains_key(&member.id),
                ),
                RefKind::Group => (OrchestraKind::Group, self.groups.contains_key(&member.id)),
            };
            if !found {
                return Err(DictionaryError::UnknownOrchestraReference {
                    kind,
                    id: member.id,
                    owner: location,
                });
            }
        }
        Ok(())
    }

    /// Expands a component referenced from the standard header or trailer
    /// in place.
    fn envelope_component(
        &mut self,
        component: &RawComponent,
    ) -> Result<Vec<Item>, DictionaryError> {
        if self.open_components.contains(&component.id) {
            return Err(DictionaryError::ComponentCycle(component.name.clone()));
        }
        if self.open_components.len() >= MAX_COMPONENT_DEPTH {
            return Err(DictionaryError::NestingTooDeep {
                element: component.name.clone(),
                limit: MAX_COMPONENT_DEPTH,
            });
        }
        self.open_components.push(component.id);
        let location = format!("component {}", component.name);
        let items = self.items(&component.members, &location, Scope::Envelope, 1)?;
        self.open_components.pop();
        Ok(items)
    }
}

/// Indexes `definitions` by id, rejecting a repeated id.
fn by_id<T>(
    definitions: &[T],
    id: impl Fn(&T) -> u32,
    kind: OrchestraKind,
) -> Result<HashMap<u32, &T>, DictionaryError> {
    let mut map = HashMap::with_capacity(definitions.len());
    for definition in definitions {
        if map.insert(id(definition), definition).is_some() {
            return Err(DictionaryError::DuplicateOrchestraDefinition {
                kind,
                key: id(definition).to_string(),
            });
        }
    }
    Ok(map)
}

/// Traversal state of a group during [`check_group_graph`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupVisit {
    /// On the current path: reaching it again is a cycle.
    InProgress,
    /// Checked, with the length of its longest chain of nested groups,
    /// itself included.
    Done(usize),
}

/// The longest chain of nested groups a message's group may start: the
/// message is level 1 of [`MAX_NESTING_DEPTH`], as in the QuickFIX loader.
const MAX_GROUP_CHAIN: usize = MAX_NESTING_DEPTH - 1;

/// Rejects a cycle of group references and a chain of nested groups no
/// message could hold, over every `base` group, referenced or not.
///
/// Depth-first from every group, in document order, with each group's chain
/// length memoised, so the walk is linear in the group references (a group
/// referenced twice by each of its parents is still checked once) and its
/// recursion is bounded by [`MAX_GROUP_CHAIN`]. Groups are linked by
/// `groupRef` only: a component a group references is expanded on its own,
/// and its cycles are the shared component check's.
///
/// # Errors
/// [`DictionaryError::GroupCycle`] for a cycle,
/// [`DictionaryError::NestingTooDeep`] for a chain past [`MAX_GROUP_CHAIN`].
fn check_group_graph(raw: &Raw, groups: &HashMap<u32, &RawGroup>) -> Result<(), DictionaryError> {
    let mut state: HashMap<u32, GroupVisit> = HashMap::with_capacity(raw.groups.len());
    for group in &raw.groups {
        nested_chain(group, groups, &mut state, 1)?;
    }
    Ok(())
}

/// Visits `group`, the `position`-th of the chain being walked, returning
/// the length of its longest chain of nested groups.
fn nested_chain(
    group: &RawGroup,
    groups: &HashMap<u32, &RawGroup>,
    state: &mut HashMap<u32, GroupVisit>,
    position: usize,
) -> Result<usize, DictionaryError> {
    let too_deep = || DictionaryError::NestingTooDeep {
        element: group.name.clone(),
        limit: MAX_NESTING_DEPTH,
    };
    let chain = match state.get(&group.id) {
        Some(GroupVisit::InProgress) => {
            return Err(DictionaryError::GroupCycle(group.name.clone()));
        }
        Some(GroupVisit::Done(chain)) => *chain,
        None => {
            if position > MAX_GROUP_CHAIN {
                return Err(too_deep());
            }
            state.insert(group.id, GroupVisit::InProgress);
            let mut nested = 0;
            for member in group.members.iter().filter(|m| m.kind == RefKind::Group) {
                // Every id resolves: `check_group` ran first.
                if let Some(child) = groups.get(&member.id) {
                    let inner = position.checked_add(1).ok_or_else(too_deep)?;
                    nested = nested.max(nested_chain(child, groups, state, inner)?);
                }
            }
            let chain = nested.checked_add(1).ok_or_else(too_deep)?;
            state.insert(group.id, GroupVisit::Done(chain));
            chain
        }
    };
    // Where the walk reached it, the group's chain must still fit.
    let deepest = position
        .checked_add(chain)
        .and_then(|end| end.checked_sub(1))
        .ok_or_else(too_deep)?;
    if deepest > MAX_GROUP_CHAIN {
        return Err(too_deep());
    }
    Ok(chain)
}

/// Reports the `base` groups no message or component reaches, and the code
/// sets no field names, in document order: the dictionary does not hold
/// them.
fn report_unreferenced(
    raw: &Raw,
    groups: &HashMap<u32, &RawGroup>,
    report: &mut Report,
) -> Result<(), DictionaryError> {
    let mut reached: HashSet<u32> = HashSet::with_capacity(raw.groups.len());
    let mut pending: Vec<u32> = raw
        .components
        .iter()
        .flat_map(|component| &component.members)
        .chain(raw.messages.iter().flat_map(|message| &message.members))
        .filter(|member| member.kind == RefKind::Group)
        .map(|member| member.id)
        .collect();
    while let Some(id) = pending.pop() {
        if !reached.insert(id) {
            continue;
        }
        if let Some(group) = groups.get(&id) {
            pending.extend(
                group
                    .members
                    .iter()
                    .filter(|member| member.kind == RefKind::Group)
                    .map(|member| member.id),
            );
        }
    }
    for group in raw
        .groups
        .iter()
        .filter(|group| !reached.contains(&group.id))
    {
        report.push(UnmappedConstruct::Unreferenced {
            kind: OrchestraKind::Group,
            name: group.name.clone(),
        })?;
    }
    let named: HashSet<&str> = raw.fields.iter().map(|f| f.type_name.as_str()).collect();
    for set in raw
        .code_sets
        .iter()
        .filter(|set| !named.contains(set.name.as_str()))
    {
        report.push(UnmappedConstruct::Unreferenced {
            kind: OrchestraKind::CodeSet,
            name: set.name.clone(),
        })?;
    }
    Ok(())
}

/// Builds the dictionary from the parsed definitions, adding the
/// unreferenced definitions to `report`.
fn build(raw: &Raw, report: &mut Report) -> Result<Dictionary, DictionaryError> {
    let types = Types::new(raw)?;

    let mut fields = HashMap::with_capacity(raw.fields.len());
    let mut field_defs = Vec::with_capacity(raw.fields.len());
    // Every field naming a code set holds its own copy of the values, so a
    // code set shared by many fields is copied once per field: the copies are
    // counted, before they are made, against MAX_ORCHESTRA_FIELD_VALUES.
    let mut copied: usize = 0;
    for field in &raw.fields {
        if let Some(existing) = fields.insert(field.id, field.name.as_str()) {
            return Err(DictionaryError::DuplicateFieldTag {
                tag: field.id,
                existing: existing.to_owned(),
                duplicate: field.name.clone(),
            });
        }
        let (field_type, values) = types.field(field)?;
        let mut def = FieldDef::new(field.id, field.name.clone(), field_type);
        if let Some(values) = values.filter(|values| !values.is_empty()) {
            copied = copied
                .checked_add(values.len())
                .filter(|copied| *copied <= MAX_ORCHESTRA_FIELD_VALUES)
                .ok_or(DictionaryError::TooManyFieldValues {
                    limit: MAX_ORCHESTRA_FIELD_VALUES,
                })?;
            def = def.with_values(values.clone());
        }
        field_defs.push(def);
    }

    let components = by_id(&raw.components, |c| c.id, OrchestraKind::Component)?;
    let groups = by_id(&raw.groups, |g| g.id, OrchestraKind::Group)?;
    by_id(&raw.messages, |m| m.id, OrchestraKind::Message)?;
    let mut group_names = HashSet::with_capacity(raw.groups.len());
    for group in &raw.groups {
        if !group_names.insert(group.name.as_str()) {
            return Err(DictionaryError::DuplicateOrchestraDefinition {
                kind: OrchestraKind::Group,
                key: group.name.clone(),
            });
        }
    }
    let mut component_names = HashSet::with_capacity(raw.components.len());
    for component in &raw.components {
        if !component_names.insert(component.name.as_str()) {
            return Err(DictionaryError::DuplicateDefinition {
                kind: DefinitionKind::Component,
                name: component.name.clone(),
            });
        }
    }
    let envelope_id = |name: &str| {
        raw.components
            .iter()
            .find(|component| component.name == name)
            .map(|component| component.id)
    };
    let header = envelope_id(HEADER);
    let trailer = envelope_id(TRAILER);

    let mut expander = Expander {
        fields,
        components,
        groups,
        envelope: [header, trailer],
        budget: MAX_ORCHESTRA_MEMBERS,
        open_groups: Vec::new(),
        open_components: Vec::new(),
    };
    // Every group, referenced or not, before any is expanded: its ids
    // resolve, and the groups it nests form no cycle and no chain deeper
    // than a message can hold.
    for group in &raw.groups {
        expander.check_group(group)?;
    }
    check_group_graph(raw, &expander.groups)?;
    report_unreferenced(raw, &expander.groups, report)?;
    let mut envelopes = [Vec::new(), Vec::new()];
    for (items, id) in envelopes.iter_mut().zip([header, trailer]) {
        if let Some(component) = id.and_then(|id| expander.components.get(&id).copied()) {
            *items = expander.envelope_component(component)?;
        }
    }
    let [header_items, trailer_items] = envelopes;

    let mut component_irs = ComponentIrs::default();
    for component in &raw.components {
        if expander.envelope.contains(&Some(component.id)) {
            continue;
        }
        let location = format!("component {}", component.name);
        let items = expander.items(&component.members, &location, Scope::Definition, 1)?;
        component_irs.define(component.name.clone(), items)?;
    }

    let mut messages = Vec::with_capacity(raw.messages.len());
    for message in &raw.messages {
        let location = format!("message {}", message.name);
        messages.push(MessageIr {
            name: message.name.clone(),
            msg_type: message.msg_type.clone(),
            category: message.category,
            items: expander.items(&message.members, &location, Scope::Message, 1)?,
        });
    }

    assemble(Assembly {
        version: raw.version,
        fields: field_defs,
        header: header_items,
        trailer: trailer_items,
        components: component_irs,
        messages,
    })
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

    #[track_caller]
    fn load(xml: &str) -> OrchestraImport {
        ok(Dictionary::from_orchestra_xml(xml), "the repository loads")
    }

    /// Returns the error a load is expected to fail with.
    #[track_caller]
    fn load_err(xml: &str) -> DictionaryError {
        match Dictionary::from_orchestra_xml(xml) {
            Ok(_) => panic!("expected the repository to be rejected, but it loaded"),
            Err(err) => err,
        }
    }

    /// A small, valid repository; each test replaces the sections it needs.
    struct Doc {
        version: String,
        datatypes: String,
        code_sets: String,
        fields: String,
        components: String,
        groups: String,
        messages: String,
        extra: String,
    }

    impl Default for Doc {
        fn default() -> Self {
            Self {
                version: "FIX.4.4_EP311".to_owned(),
                datatypes: r#"
                    <fixr:datatype name="int"/>
                    <fixr:datatype name="NumInGroup" baseType="int"/>
                    <fixr:datatype name="Length" baseType="int"/>
                    <fixr:datatype name="float"/>
                    <fixr:datatype name="Price" baseType="float"/>
                    <fixr:datatype name="char"/>
                    <fixr:datatype name="String"/>"#
                    .to_owned(),
                code_sets: r#"
                    <fixr:codeSet id="54" name="SideCodeSet" type="char">
                      <fixr:code id="54001" name="Buy" value="1"/>
                      <fixr:code id="54002" name="Sell" value="2"/>
                    </fixr:codeSet>"#
                    .to_owned(),
                fields: r#"
                    <fixr:field id="8" name="BeginString" type="String"/>
                    <fixr:field id="9" name="BodyLength" type="Length"/>
                    <fixr:field id="35" name="MsgType" type="String"/>
                    <fixr:field id="10" name="CheckSum" type="String"/>
                    <fixr:field id="11" name="ClOrdID" type="String"/>
                    <fixr:field id="44" name="Price" type="Price"/>
                    <fixr:field id="54" name="Side" type="SideCodeSet"/>
                    <fixr:field id="55" name="Symbol" type="String"/>
                    <fixr:field id="112" name="TestReqID" type="String"/>
                    <fixr:field id="447" name="PartyIDSource" type="char"/>
                    <fixr:field id="448" name="PartyID" type="String"/>
                    <fixr:field id="453" name="NoPartyIDs" type="NumInGroup"/>"#
                    .to_owned(),
                components: r#"
                    <fixr:component id="1024" name="StandardHeader">
                      <fixr:fieldRef id="8" presence="required"/>
                      <fixr:fieldRef id="9" presence="required"/>
                      <fixr:fieldRef id="35" presence="required"/>
                    </fixr:component>
                    <fixr:component id="1025" name="StandardTrailer">
                      <fixr:fieldRef id="10" presence="required"/>
                    </fixr:component>
                    <fixr:component id="1003" name="Instrument">
                      <fixr:fieldRef id="55"/>
                    </fixr:component>"#
                    .to_owned(),
                groups: r#"
                    <fixr:group id="2000" name="Parties">
                      <fixr:numInGroup id="453"/>
                      <fixr:fieldRef id="448"/>
                      <fixr:fieldRef id="447"/>
                    </fixr:group>"#
                    .to_owned(),
                messages: r#"
                    <fixr:message id="1" name="Heartbeat" msgType="0" category="Session">
                      <fixr:structure>
                        <fixr:componentRef id="1024" presence="required"/>
                        <fixr:fieldRef id="112"/>
                        <fixr:componentRef id="1025" presence="required"/>
                      </fixr:structure>
                    </fixr:message>
                    <fixr:message id="14" name="NewOrderSingle" msgType="D" category="SingleGeneralOrderHandling">
                      <fixr:structure>
                        <fixr:componentRef id="1024" presence="required"/>
                        <fixr:fieldRef id="11" presence="required"/>
                        <fixr:groupRef id="2000"/>
                        <fixr:componentRef id="1003" presence="required"/>
                        <fixr:fieldRef id="54" presence="required"/>
                        <fixr:fieldRef id="44"/>
                        <fixr:componentRef id="1025" presence="required"/>
                      </fixr:structure>
                    </fixr:message>"#
                    .to_owned(),
                extra: String::new(),
            }
        }
    }

    impl Doc {
        fn xml(&self) -> String {
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<fixr:repository xmlns:fixr="{ORCHESTRA_NAMESPACE}" name="FIX.4.4" version="{}">
  <fixr:datatypes>{}</fixr:datatypes>
  <fixr:codeSets>{}</fixr:codeSets>
  <fixr:fields>{}</fixr:fields>
  <fixr:components>{}</fixr:components>
  <fixr:groups>{}</fixr:groups>
  <fixr:messages>{}</fixr:messages>{}
</fixr:repository>
"#,
                self.version,
                self.datatypes,
                self.code_sets,
                self.fields,
                self.components,
                self.groups,
                self.messages,
                self.extra,
            )
        }

        /// The default document with `fields` appended to the fields.
        fn with_fields(fields: &str) -> Self {
            let mut doc = Self::default();
            doc.fields.push_str(fields);
            doc
        }
    }

    /// The members of `members`, as `kind tag-or-name` strings.
    fn listed<'a>(members: impl Iterator<Item = MemberRef<'a>>) -> Vec<String> {
        members
            .map(|member| match member {
                MemberRef::Field(field) => format!("field {}{}", field.tag, req(field.required)),
                MemberRef::Group(group) => {
                    format!("group {}{}", group.name, req(group.required))
                }
                MemberRef::Component(component) => {
                    format!("component {}{}", component.name, req(component.required))
                }
            })
            .collect()
    }

    fn req(required: bool) -> &'static str {
        if required { " (required)" } else { "" }
    }

    #[test]
    fn test_minimal_repository_loads() {
        let import = load(&Doc::default().xml());
        assert!(import.report().is_empty(), "{:?}", import.report());
        let dict = import.dictionary();
        assert_eq!(dict.version, Version::Fix44);
        let header: Vec<u32> = dict.header.iter().map(|field| field.tag).collect();
        assert_eq!(header, [8, 9, 35]);
        assert!(dict.header.iter().all(|field| field.required));
        let trailer: Vec<u32> = dict.trailer.iter().map(|field| field.tag).collect();
        assert_eq!(trailer, [10]);
        // The envelope components are the header and trailer, not components.
        let components: Vec<&str> = dict.components().map(|c| c.name.as_str()).collect();
        assert_eq!(components, ["Instrument"]);

        let order = some(dict.get_message("D"), "NewOrderSingle");
        assert_eq!(order.name, "NewOrderSingle");
        assert_eq!(order.category, MessageCategory::App);
        assert_eq!(
            listed(order.members()),
            [
                "field 11 (required)",
                "group NoPartyIDs",
                "component Instrument (required)",
                "field 54 (required)",
                "field 44",
            ]
        );
        let parties = &order.groups()[0];
        assert_eq!(parties.count_tag, 453);
        assert_eq!(parties.delimiter_tag, 448);
        assert_eq!(listed(parties.members()), ["field 448", "field 447"]);

        let heartbeat = some(dict.get_message("0"), "Heartbeat");
        assert_eq!(heartbeat.category, MessageCategory::Admin);

        let side = some(dict.get_field(54), "Side");
        assert_eq!(side.field_type, FieldType::Char);
        let values = some(side.values.as_ref(), "Side values");
        assert_eq!(values.get("1").map(String::as_str), Some("Buy"));
        assert_eq!(values.get("2").map(String::as_str), Some("Sell"));
        assert_eq!(values.len(), 2);
        assert_eq!(
            some(dict.get_field(44), "Price").field_type,
            FieldType::Price
        );
        assert_eq!(
            some(dict.get_field(453), "NoPartyIDs").field_type,
            FieldType::NumInGroup
        );
    }

    #[test]
    fn test_import_into_parts_returns_the_dictionary_and_the_report() {
        let import = load(&Doc::default().xml());
        let fields = import.dictionary().fields.len();
        let (dict, report) = import.into_parts();
        assert_eq!(dict.fields.len(), fields);
        assert!(report.is_empty());
        assert_eq!(report.len(), 0);
    }

    #[test]
    fn test_version_maps_to_the_fix_version_it_names() {
        let cases = [
            ("FIX.4.0", Version::Fix40),
            ("FIX.4.1", Version::Fix41),
            ("FIX.4.2", Version::Fix42),
            ("FIX.4.3", Version::Fix43),
            ("FIX.4.4", Version::Fix44),
            ("FIX.4.4_EP311", Version::Fix44),
            ("FIX.5.0", Version::Fix50),
            ("FIX.5.0SP1", Version::Fix50Sp1),
            ("FIX.5.0SP2", Version::Fix50Sp2),
            ("FIX.5.0SP2_EP254", Version::Fix50Sp2),
            ("FIXT.1.1", Version::Fixt11),
        ];
        for (version, expected) in cases {
            let doc = Doc {
                version: version.to_owned(),
                ..Doc::default()
            };
            assert_eq!(load(&doc.xml()).dictionary().version, expected, "{version}");
        }
    }

    #[test]
    fn test_unmappable_version_is_rejected() {
        for version in [
            "FIX.Latest",
            "FIX.Latest_EP312",
            "FIX.2.7",
            "FIX.3.0",
            "FIX.4.4_EP",
            "FIX.4.4_EPx",
            "FIX.5.0SP3",
            "1.0",
            "20260908",
            "",
        ] {
            let doc = Doc {
                version: version.to_owned(),
                ..Doc::default()
            };
            assert_eq!(
                load_err(&doc.xml()),
                DictionaryError::UnsupportedVersion(version.to_owned()),
                "{version}"
            );
        }
    }

    #[test]
    fn test_missing_version_is_rejected() {
        let xml = Doc::default()
            .xml()
            .replace(r#" version="FIX.4.4_EP311""#, "");
        assert_eq!(
            load_err(&xml),
            DictionaryError::MissingAttribute {
                element: "repository".to_owned(),
                attribute: "version".to_owned(),
            }
        );
    }

    #[test]
    fn test_a_document_that_is_not_an_orchestra_repository_is_rejected() {
        let quickfix = "<fix type='FIX' major='4' minor='4'><fields/></fix>";
        assert_eq!(
            load_err(quickfix),
            DictionaryError::NotOrchestra("<fix> in no namespace".to_owned())
        );
        // The Orchestra 1.1 draft namespace is a different schema.
        let draft = Doc::default().xml().replace(
            ORCHESTRA_NAMESPACE,
            "http://fixprotocol.io/2026/orchestra/repository",
        );
        assert_eq!(
            load_err(&draft),
            DictionaryError::NotOrchestra(
                "<fixr:repository> in namespace `http://fixprotocol.io/2026/orchestra/repository`"
                    .to_owned()
            )
        );
        let unqualified = r#"<repository name="FIX.4.4" version="FIX.4.4"/>"#;
        assert!(matches!(
            load_err(unqualified),
            DictionaryError::NotOrchestra(_)
        ));
        // An empty repository in the right namespace is a repository.
        let empty = format!(r#"<repository xmlns="{ORCHESTRA_NAMESPACE}" version="FIX.4.4"/>"#);
        let import = load(&empty);
        assert_eq!(import.dictionary().version, Version::Fix44);
        assert!(import.dictionary().messages.is_empty());
    }

    #[test]
    fn test_oversized_document_is_rejected_before_parsing() {
        let xml = " ".repeat(MAX_ORCHESTRA_DOCUMENT_LEN + 1);
        assert_eq!(
            load_err(&xml),
            DictionaryError::DocumentTooLarge {
                len: MAX_ORCHESTRA_DOCUMENT_LEN + 1,
                limit: MAX_ORCHESTRA_DOCUMENT_LEN,
            }
        );
    }

    #[test]
    fn test_oversized_attributes_are_rejected() {
        let name = "A".repeat(MAX_ORCHESTRA_ATTRIBUTES_LEN);
        let doc = Doc::with_fields(&format!(
            r#"<fixr:field id="5000" name="{name}" type="String"/>"#
        ));
        match load_err(&doc.xml()) {
            DictionaryError::AttributesTooLong {
                element,
                len,
                limit,
            } => {
                assert_eq!(element, "fixr:field");
                assert!(len > limit);
                assert_eq!(limit, MAX_ORCHESTRA_ATTRIBUTES_LEN);
            }
            other => panic!("expected AttributesTooLong, got {other:?}"),
        }
        // Many small attributes count the same.
        let many: String = (0..4_000).map(|i| format!(" a{i}=\"\"")).collect();
        let doc = Doc::with_fields(&format!(
            r#"<fixr:field id="5000" name="Many" type="String"{many}/>"#
        ));
        assert!(matches!(
            load_err(&doc.xml()),
            DictionaryError::AttributesTooLong { .. }
        ));
    }

    #[test]
    fn test_invalid_ids_are_rejected() {
        for id in ["0", "-1", "4294967296", "99999999999999999999", "abc", ""] {
            let doc = Doc::with_fields(&format!(
                r#"<fixr:field id="{id}" name="Bad" type="String"/>"#
            ));
            assert_eq!(
                load_err(&doc.xml()),
                DictionaryError::InvalidOrchestraId {
                    element: "field".to_owned(),
                    value: id.to_owned(),
                },
                "{id}"
            );
        }
        let mut doc = Doc::default();
        doc.messages = doc.messages.replace(
            r#"<fixr:groupRef id="2000"/>"#,
            r#"<fixr:groupRef id="4294967296"/>"#,
        );
        assert_eq!(
            load_err(&doc.xml()),
            DictionaryError::InvalidOrchestraId {
                element: "groupRef".to_owned(),
                value: "4294967296".to_owned(),
            }
        );
        // The largest u32 is a valid id.
        let doc = Doc::with_fields(r#"<fixr:field id="4294967295" name="Max" type="String"/>"#);
        assert!(load(&doc.xml()).dictionary().get_field(u32::MAX).is_some());
    }

    #[test]
    fn test_dangling_references_are_rejected() {
        let cases = [
            (
                r#"<fixr:fieldRef id="44"/>"#,
                r#"<fixr:fieldRef id="999"/>"#,
                OrchestraKind::Field,
                999,
            ),
            (
                r#"<fixr:groupRef id="2000"/>"#,
                r#"<fixr:groupRef id="2999"/>"#,
                OrchestraKind::Group,
                2999,
            ),
            (
                r#"<fixr:componentRef id="1003" presence="required"/>"#,
                r#"<fixr:componentRef id="1999"/>"#,
                OrchestraKind::Component,
                1999,
            ),
        ];
        for (from, to, kind, id) in cases {
            let mut doc = Doc::default();
            doc.messages = doc.messages.replace(from, to);
            assert_eq!(
                load_err(&doc.xml()),
                DictionaryError::UnknownOrchestraReference {
                    kind,
                    id,
                    owner: "message NewOrderSingle".to_owned(),
                },
                "{to}"
            );
        }
        let mut doc = Doc::default();
        doc.groups = doc.groups.replace(
            r#"<fixr:numInGroup id="453"/>"#,
            r#"<fixr:numInGroup id="999"/>"#,
        );
        assert_eq!(
            load_err(&doc.xml()),
            DictionaryError::UnknownOrchestraReference {
                kind: OrchestraKind::Field,
                id: 999,
                owner: "group Parties".to_owned(),
            }
        );
    }

    #[test]
    fn test_duplicate_definitions_are_rejected() {
        let doc = Doc::with_fields(r#"<fixr:field id="11" name="Other" type="String"/>"#);
        assert_eq!(
            load_err(&doc.xml()),
            DictionaryError::DuplicateFieldTag {
                tag: 11,
                existing: "ClOrdID".to_owned(),
                duplicate: "Other".to_owned(),
            }
        );
        let doc = Doc::with_fields(r#"<fixr:field id="5000" name="ClOrdID" type="String"/>"#);
        assert_eq!(
            load_err(&doc.xml()),
            DictionaryError::DuplicateDefinition {
                kind: DefinitionKind::Field,
                name: "ClOrdID".to_owned(),
            }
        );

        let duplicate =
            |kind: OrchestraKind, key: &str| DictionaryError::DuplicateOrchestraDefinition {
                kind,
                key: key.to_owned(),
            };
        let mut doc = Doc::default();
        doc.datatypes.push_str(r#"<fixr:datatype name="int"/>"#);
        assert_eq!(
            load_err(&doc.xml()),
            duplicate(OrchestraKind::Datatype, "int")
        );

        let mut doc = Doc::default();
        doc.code_sets
            .push_str(r#"<fixr:codeSet id="55" name="SideCodeSet" type="char"/>"#);
        assert_eq!(
            load_err(&doc.xml()),
            duplicate(OrchestraKind::CodeSet, "SideCodeSet")
        );
        let mut doc = Doc::default();
        doc.code_sets
            .push_str(r#"<fixr:codeSet id="54" name="OtherCodeSet" type="char"/>"#);
        assert_eq!(
            load_err(&doc.xml()),
            duplicate(OrchestraKind::CodeSet, "54")
        );
        // Datatypes and code sets share the names field types refer to.
        let mut doc = Doc::default();
        doc.code_sets
            .push_str(r#"<fixr:codeSet id="56" name="String" type="char"/>"#);
        assert_eq!(
            load_err(&doc.xml()),
            duplicate(OrchestraKind::CodeSet, "String")
        );

        let mut doc = Doc::default();
        doc.code_sets = doc
            .code_sets
            .replace(r#"name="Sell" value="2""#, r#"name="Sell" value="1""#);
        assert_eq!(
            load_err(&doc.xml()),
            duplicate(OrchestraKind::Code, "SideCodeSet value 1")
        );

        let mut doc = Doc::default();
        doc.components.push_str(
            r#"<fixr:component id="1003" name="Other"><fixr:fieldRef id="55"/></fixr:component>"#,
        );
        assert_eq!(
            load_err(&doc.xml()),
            duplicate(OrchestraKind::Component, "1003")
        );
        let mut doc = Doc::default();
        doc.components.push_str(
            r#"<fixr:component id="1004" name="Instrument"><fixr:fieldRef id="55"/></fixr:component>"#,
        );
        assert_eq!(
            load_err(&doc.xml()),
            DictionaryError::DuplicateDefinition {
                kind: DefinitionKind::Component,
                name: "Instrument".to_owned(),
            }
        );

        let mut doc = Doc::default();
        doc.groups.push_str(
            r#"<fixr:group id="2000" name="Other"><fixr:numInGroup id="453"/><fixr:fieldRef id="448"/></fixr:group>"#,
        );
        assert_eq!(
            load_err(&doc.xml()),
            duplicate(OrchestraKind::Group, "2000")
        );
        let mut doc = Doc::default();
        doc.groups.push_str(
            r#"<fixr:group id="2001" name="Parties"><fixr:numInGroup id="453"/><fixr:fieldRef id="448"/></fixr:group>"#,
        );
        assert_eq!(
            load_err(&doc.xml()),
            duplicate(OrchestraKind::Group, "Parties")
        );

        let mut doc = Doc::default();
        doc.messages.push_str(
            r#"<fixr:message id="14" name="Other" msgType="Z"><fixr:structure/></fixr:message>"#,
        );
        assert_eq!(
            load_err(&doc.xml()),
            duplicate(OrchestraKind::Message, "14")
        );
        let mut doc = Doc::default();
        doc.messages.push_str(
            r#"<fixr:message id="99" name="Other" msgType="D"><fixr:structure/></fixr:message>"#,
        );
        assert_eq!(
            load_err(&doc.xml()),
            DictionaryError::DuplicateDefinition {
                kind: DefinitionKind::Message,
                name: "D".to_owned(),
            }
        );
    }

    #[test]
    fn test_component_cycles_are_rejected() {
        let mut doc = Doc::default();
        doc.components.push_str(
            r#"<fixr:component id="1100" name="A"><fixr:componentRef id="1101"/></fixr:component>
               <fixr:component id="1101" name="B"><fixr:componentRef id="1100"/></fixr:component>"#,
        );
        assert!(matches!(
            load_err(&doc.xml()),
            DictionaryError::ComponentCycle(_)
        ));
        let mut doc = Doc::default();
        doc.components.push_str(
            r#"<fixr:component id="1100" name="Selfish"><fixr:componentRef id="1100"/></fixr:component>"#,
        );
        assert_eq!(
            load_err(&doc.xml()),
            DictionaryError::ComponentCycle("Selfish".to_owned())
        );
    }

    #[test]
    fn test_group_cycles_are_rejected() {
        let mut doc = Doc::default();
        doc.groups = doc.groups.replace(
            r#"<fixr:fieldRef id="447"/>"#,
            r#"<fixr:fieldRef id="447"/><fixr:groupRef id="2000"/>"#,
        );
        assert_eq!(
            load_err(&doc.xml()),
            DictionaryError::GroupCycle("Parties".to_owned())
        );

        let mut doc = Doc::default();
        doc.groups = doc.groups.replace(
            r#"<fixr:fieldRef id="447"/>"#,
            r#"<fixr:fieldRef id="447"/><fixr:groupRef id="2001"/>"#,
        );
        doc.groups.push_str(
            r#"<fixr:group id="2001" name="Other"><fixr:numInGroup id="453"/><fixr:fieldRef id="448"/><fixr:groupRef id="2000"/></fixr:group>"#,
        );
        assert!(matches!(
            load_err(&doc.xml()),
            DictionaryError::GroupCycle(_)
        ));

        // Through a component: the group expands into the component, which
        // the component graph check then finds referencing itself.
        let mut doc = Doc::default();
        doc.groups = doc.groups.replace(
            r#"<fixr:fieldRef id="447"/>"#,
            r#"<fixr:fieldRef id="447"/><fixr:componentRef id="1003"/>"#,
        );
        doc.components = doc.components.replace(
            r#"<fixr:fieldRef id="55"/>"#,
            r#"<fixr:fieldRef id="55"/><fixr:groupRef id="2000"/>"#,
        );
        assert_eq!(
            load_err(&doc.xml()),
            DictionaryError::ComponentCycle("Instrument".to_owned())
        );
    }

    #[test]
    fn test_unknown_datatypes_and_code_sets_are_rejected() {
        let doc = Doc::with_fields(r#"<fixr:field id="5000" name="Odd" type="NoSuchType"/>"#);
        assert_eq!(
            load_err(&doc.xml()),
            DictionaryError::UnknownFieldType {
                field: "Odd".to_owned(),
                field_type: "NoSuchType".to_owned(),
            }
        );
        // A FIX type name that the repository does not declare.
        let doc = Doc::with_fields(r#"<fixr:field id="5000" name="Odd" type="UTCTimestamp"/>"#);
        assert!(matches!(
            load_err(&doc.xml()),
            DictionaryError::UnknownFieldType { .. }
        ));
        // A declared datatype that is not a FIX type and has no base type.
        let mut doc = Doc::with_fields(r#"<fixr:field id="5000" name="Odd" type="Venue"/>"#);
        doc.datatypes.push_str(r#"<fixr:datatype name="Venue"/>"#);
        assert!(matches!(
            load_err(&doc.xml()),
            DictionaryError::UnknownFieldType { .. }
        ));
        // A base-type cycle ends at the hop limit.
        let mut doc = Doc::with_fields(r#"<fixr:field id="5000" name="Odd" type="Ping"/>"#);
        doc.datatypes.push_str(
            r#"<fixr:datatype name="Ping" baseType="Pong"/><fixr:datatype name="Pong" baseType="Ping"/>"#,
        );
        assert!(matches!(
            load_err(&doc.xml()),
            DictionaryError::UnknownFieldType { .. }
        ));
        // A code set whose type maps to no FIX type.
        let mut doc = Doc::default();
        doc.code_sets
            .push_str(r#"<fixr:codeSet id="77" name="OddCodeSet" type="NoSuchType"/>"#);
        assert_eq!(
            load_err(&doc.xml()),
            DictionaryError::UnknownDatatype {
                owner: "code set OddCodeSet".to_owned(),
                datatype: "NoSuchType".to_owned(),
            }
        );
    }

    #[test]
    fn test_derived_datatype_maps_through_its_base_type() {
        let mut doc =
            Doc::with_fields(r#"<fixr:field id="5000" name="VenuePrice" type="TickPrice"/>"#);
        doc.datatypes
            .push_str(r#"<fixr:datatype name="TickPrice" baseType="Price"/>"#);
        let import = load(&doc.xml());
        assert_eq!(
            some(import.dictionary().get_field(5000), "VenuePrice").field_type,
            FieldType::Price
        );
    }

    #[test]
    fn test_group_without_count_field_or_members_is_rejected() {
        let mut doc = Doc::default();
        doc.groups = doc.groups.replace(r#"<fixr:numInGroup id="453"/>"#, "");
        assert_eq!(
            load_err(&doc.xml()),
            DictionaryError::MissingCountField("Parties".to_owned())
        );
        let mut doc = Doc::default();
        doc.groups = doc
            .groups
            .replace(r#"<fixr:fieldRef id="448"/>"#, "")
            .replace(r#"<fixr:fieldRef id="447"/>"#, "");
        assert_eq!(
            load_err(&doc.xml()),
            DictionaryError::EmptyGroup("NoPartyIDs".to_owned())
        );
    }

    #[test]
    fn test_group_delimiter_is_its_first_member_through_a_component() {
        let mut doc = Doc::default();
        doc.groups = doc.groups.replace(
            r#"<fixr:fieldRef id="448"/>"#,
            r#"<fixr:componentRef id="1003"/><fixr:fieldRef id="448"/>"#,
        );
        let import = load(&doc.xml());
        let order = some(import.dictionary().get_message("D"), "NewOrderSingle");
        // Instrument's first field, Symbol(55).
        assert_eq!(order.groups()[0].delimiter_tag, 55);
    }

    #[test]
    fn test_truncated_documents_are_rejected_without_panicking() {
        let xml = Doc::default().xml();
        let end = xml.rfind("</fixr:repository>").unwrap_or(xml.len());
        for cut in (0..end).step_by(7) {
            let Some(prefix) = xml.get(..cut) else {
                continue;
            };
            assert!(
                Dictionary::from_orchestra_xml(prefix).is_err(),
                "a document cut at byte {cut} loaded"
            );
        }
    }

    #[test]
    fn test_deep_element_nesting_is_rejected() {
        let open: String = (0..MAX_NESTING_DEPTH).map(|_| "<x:deep>").collect();
        let close: String = (0..MAX_NESTING_DEPTH).map(|_| "</x:deep>").collect();
        let doc = Doc {
            extra: format!(r#"<x:ext xmlns:x="urn:example">{open}{close}</x:ext>"#),
            ..Doc::default()
        };
        assert_eq!(
            load_err(&doc.xml()),
            DictionaryError::NestingTooDeep {
                element: "deep".to_owned(),
                limit: MAX_NESTING_DEPTH,
            }
        );
    }

    /// Groups `2100..2100 + count`, each holding the next `refs` times, the
    /// last holding a field, with their count fields; a message holds the
    /// first.
    fn group_chain(count: u32, refs: usize) -> Doc {
        group_chain_to(count, refs, 55)
    }

    /// [`group_chain`], with field `leaf` in the last group.
    fn group_chain_to(count: u32, refs: usize, leaf: u32) -> Doc {
        let mut doc = Doc::default();
        for level in 0..count {
            let id = 2100 + level;
            let count_id = 6000 + level;
            doc.fields.push_str(&format!(
                r#"<fixr:field id="{count_id}" name="NoLevel{level}" type="NumInGroup"/>"#
            ));
            let members = if level + 1 == count {
                format!(r#"<fixr:fieldRef id="{leaf}"/>"#)
            } else {
                format!(r#"<fixr:groupRef id="{}"/>"#, id + 1).repeat(refs)
            };
            doc.groups.push_str(&format!(
                r#"<fixr:group id="{id}" name="Level{level}"><fixr:numInGroup id="{count_id}"/>{members}</fixr:group>"#
            ));
        }
        doc.messages.push_str(
            r#"<fixr:message id="99" name="Deep" msgType="U9"><fixr:structure><fixr:groupRef id="2100"/></fixr:structure></fixr:message>"#,
        );
        doc
    }

    #[test]
    fn test_deep_group_nesting_is_rejected() {
        // A message holding 31 nested groups loads, as in the QuickFIX
        // loader (the message is level 1).
        let deepest = u32::try_from(MAX_NESTING_DEPTH - 1).unwrap_or(u32::MAX);
        assert!(Dictionary::from_orchestra_xml(&group_chain(deepest, 1).xml()).is_ok());
        assert_eq!(
            load_err(&group_chain(deepest + 1, 1).xml()),
            DictionaryError::NestingTooDeep {
                element: format!("Level{deepest}"),
                limit: MAX_NESTING_DEPTH,
            }
        );
    }

    #[test]
    fn test_exponential_group_expansion_is_rejected() {
        // 20 levels, each referencing the next twice: 2^20 expansions from
        // a document of a few kilobytes.
        let doc = group_chain(20, 2);
        assert!(doc.xml().len() < 16 * 1024);
        assert_eq!(
            load_err(&doc.xml()),
            DictionaryError::TooManyMembers {
                limit: MAX_ORCHESTRA_MEMBERS,
            }
        );
    }

    #[test]
    fn test_envelope_component_is_only_referenced_by_messages() {
        let mut doc = Doc::default();
        doc.components = doc.components.replace(
            r#"<fixr:fieldRef id="55"/>"#,
            r#"<fixr:fieldRef id="55"/><fixr:componentRef id="1024"/>"#,
        );
        assert_eq!(
            load_err(&doc.xml()),
            DictionaryError::EnvelopeReference {
                component: "StandardHeader".to_owned(),
                owner: "component Instrument".to_owned(),
            }
        );
    }

    #[test]
    fn test_component_in_the_header_is_expanded_in_place() {
        let mut doc = Doc::default();
        doc.components = doc.components.replace(
            r#"<fixr:fieldRef id="35" presence="required"/>"#,
            r#"<fixr:fieldRef id="35" presence="required"/><fixr:componentRef id="1003"/><fixr:groupRef id="2000"/>"#,
        );
        let import = load(&doc.xml());
        let dict = import.dictionary();
        let header: Vec<u32> = dict.header.iter().map(|field| field.tag).collect();
        assert_eq!(header, [8, 9, 35, 55]);
        assert_eq!(dict.header_groups.len(), 1);
        assert_eq!(dict.header_groups[0].count_tag, 453);
    }

    #[test]
    fn test_missing_message_type_is_rejected() {
        let mut doc = Doc::default();
        doc.messages = doc.messages.replace(r#" msgType="D""#, "");
        assert_eq!(
            load_err(&doc.xml()),
            DictionaryError::MissingAttribute {
                element: "message".to_owned(),
                attribute: "msgType".to_owned(),
            }
        );
    }

    #[test]
    fn test_malformed_xml_is_rejected() {
        let doc = Doc::with_fields(r#"<fixr:field id="5000" name="&custom;" type="String"/>"#);
        assert!(matches!(load_err(&doc.xml()), DictionaryError::Xml(_)));

        let doc = Doc {
            extra: "<fixr:fields></fixr:groups>".to_owned(),
            ..Doc::default()
        };
        assert!(matches!(load_err(&doc.xml()), DictionaryError::Xml(_)));

        let after = format!(
            "{}<fixr:repository xmlns:fixr=\"{ORCHESTRA_NAMESPACE}\"/>",
            Doc::default().xml()
        );
        assert!(matches!(load_err(&after), DictionaryError::Xml(_)));
    }

    #[test]
    fn test_content_outside_the_repository_is_rejected() {
        let xml = Doc::default().xml();
        let xml_error = |message: &str| DictionaryError::Xml(message.to_owned());
        // Issue #117: text after the root was read past, and the repository
        // loaded from the document's first part.
        assert_eq!(
            load_err(&format!("{xml}TRAILING_CORRUPTION")),
            xml_error("text `TRAILING_CORRUPTION` after the root element")
        );
        assert_eq!(
            load_err(&format!("{xml}<other/>")),
            xml_error("an element <other> after the root element")
        );
        assert_eq!(
            load_err(&format!("{xml}<![CDATA[x]]>")),
            xml_error("a CDATA section after the root element")
        );
        assert_eq!(
            load_err(&format!("{xml}&amp;")),
            xml_error("the reference `&amp;` after the root element")
        );
        assert_eq!(
            load_err(&format!("{xml}<!DOCTYPE repository>")),
            xml_error("a document type declaration after the root element")
        );
        // The prolog: before the declaration, then between it and the root.
        assert_eq!(
            load_err(&format!("JUNK{xml}")),
            xml_error("text `JUNK` before the root element")
        );
        let (declaration, rest) = some(xml.split_once('\n'), "the document has two lines");
        assert_eq!(
            load_err(&format!("{declaration}\nJUNK\n{rest}")),
            xml_error("text `JUNK` before the root element")
        );
        assert_eq!(
            load_err(&format!(" {xml}")),
            xml_error("an XML declaration that does not start the document")
        );
        assert_eq!(
            load_err("<!-- no root -->"),
            xml_error("unexpected end of file")
        );
    }

    #[test]
    fn test_misc_outside_the_repository_is_accepted() {
        let xml = Doc::default().xml();
        let (declaration, rest) = some(xml.split_once('\n'), "the document has two lines");
        let padded = format!(
            "{declaration}\n<!-- before -->\n<?pi before?>\n<!DOCTYPE repository>\n{rest}\
             \n<!-- after -->\n<?pi after?>\n \t\r\n"
        );
        let import = load(&padded);
        assert_eq!(import.dictionary().version, Version::Fix44);
        assert!(import.report().is_empty(), "{:?}", import.report());
        assert!(import.dictionary().get_message("D").is_some());
        // Without a declaration, whitespace may lead the document.
        let undeclared = format!("\n  {rest}");
        assert!(load(&undeclared).dictionary().get_message("D").is_some());
    }

    #[test]
    fn test_report_lists_what_the_dictionary_cannot_hold() {
        let mut doc = Doc {
            extra: r#"
  <fixr:metadata><dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">t</dc:title></fixr:metadata>
  <fixr:categories><fixr:category name="Session"/></fixr:categories>
  <fixr:annotation><fixr:documentation>About.</fixr:documentation></fixr:annotation>
  <fixr:actors><fixr:actor name="Trader"/></fixr:actors>
  <fixr:concepts/>
  <ext:custom xmlns:ext="urn:example"/>"#
                .to_owned(),
            ..Doc::default()
        };
        doc.datatypes.push_str(
            r#"<fixr:datatype name="UTCTimestamp" baseType="String"><fixr:mappedDatatype standard="XML" base="xs:dateTime"/></fixr:datatype>"#,
        );
        doc.code_sets.push_str(
            r#"<fixr:codeSet id="40" name="OrdTypeCodeSet" type="char" default="1">
                 <fixr:code id="40001" name="Market" value="1" supported="supported"/>
                 <fixr:code id="40002" name="Limit" value="2" scenario="Equity"/>
                 <fixr:code id="40003" name="Stop" value="3" supported="forbidden"/>
               </fixr:codeSet>
               <fixr:codeSet id="41" name="VenueCodeSet" type="char" scenario="Venue"/>"#,
        );
        doc.fields.push_str(
            r#"<fixr:field id="40" name="OrdType" type="OrdTypeCodeSet"/>
               <fixr:field id="60" name="TransactTime" type="UTCTimestamp">
                 <fixr:rule name="WhenOpen"><fixr:when>OrdType == ^Limit &amp;&amp; OrderQty &gt; 0<!-- note --></fixr:when></fixr:rule>
                 <fixr:annotation><fixr:documentation>Time.</fixr:documentation></fixr:annotation>
               </fixr:field>
               <fixr:field id="38" name="OrderQty" type="float" minInclusive="0" custom="x"/>
               <fixr:field id="38" name="OrderQty" type="Qty" scenario="Equity"/>
               <other:field xmlns:other="urn:example"/>
               <fixr:fieldz/>"#,
        );
        doc.components.push_str(
            r#"<fixr:component id="1100" name="Extra" scenario="Venue"><fixr:fieldRef id="55"/></fixr:component>"#,
        );
        doc.groups.push_str(
            r#"<fixr:group id="2100" name="Venue" scenario="Venue"><fixr:numInGroup id="453"/><fixr:fieldRef id="448"/></fixr:group>"#,
        );
        doc.messages = doc.messages.replace(
            r#"<fixr:fieldRef id="44"/>"#,
            r#"<fixr:fieldRef id="44" presence="forbidden"/>
               <fixr:fieldRef id="40" presence="constant" value="2"/>
               <fixr:fieldRef id="60" presence="ignored" value="later">
                 <fixr:rule name="Late" presence="required"><fixr:when>y</fixr:when></fixr:rule>
                 <fixr:assign>z</fixr:assign>
               </fixr:fieldRef>
               <fixr:fieldRef id="38" scenario="Equity"/>"#,
        );
        doc.messages.push_str(
            r#"<fixr:message id="15" name="Cancel" msgType="F" scenario="Venue"><fixr:structure/></fixr:message>
               <fixr:message id="16" name="Status" msgType="H">
                 <fixr:structure which="oneOf"><fixr:fieldRef id="11" value="X"/></fixr:structure>
                 <fixr:responses><fixr:response/></fixr:responses>
               </fixr:message>"#,
        );
        let import = load(&doc.xml());

        let attribute = |location: &str, name: &str, value: &str| UnmappedConstruct::Attribute {
            location: location.to_owned(),
            name: name.to_owned(),
            value: value.to_owned(),
        };
        let scenario = |kind, name: &str, scenario: &str| UnmappedConstruct::Scenario {
            kind,
            name: name.to_owned(),
            scenario: scenario.to_owned(),
        };
        let element = |location: &str| UnmappedConstruct::Element {
            location: location.to_owned(),
        };
        let expected = vec![
            attribute("code set OrdTypeCodeSet", "default", "1"),
            scenario(OrchestraKind::Code, "OrdTypeCodeSet.Limit", "Equity"),
            attribute(
                "code set OrdTypeCodeSet/code Stop",
                "supported",
                "forbidden",
            ),
            scenario(OrchestraKind::CodeSet, "VenueCodeSet", "Venue"),
            UnmappedConstruct::Rule {
                location: "field TransactTime".to_owned(),
                name: Some("WhenOpen".to_owned()),
                presence: None,
                condition: Some("OrdType == ^Limit && OrderQty > 0".to_owned()),
            },
            attribute("field OrderQty", "minInclusive", "0"),
            attribute("field OrderQty", "custom", "x"),
            scenario(OrchestraKind::Field, "OrderQty", "Equity"),
            element("fields/other:field"),
            element("fields/fixr:fieldz"),
            scenario(OrchestraKind::Component, "Extra", "Venue"),
            scenario(OrchestraKind::Group, "Venue", "Venue"),
            UnmappedConstruct::Presence {
                location: "message NewOrderSingle/fieldRef 44".to_owned(),
                presence: "forbidden".to_owned(),
                value: None,
            },
            UnmappedConstruct::Presence {
                location: "message NewOrderSingle/fieldRef 40".to_owned(),
                presence: "constant".to_owned(),
                value: Some("2".to_owned()),
            },
            // The value is reported once, with the presence.
            UnmappedConstruct::Presence {
                location: "message NewOrderSingle/fieldRef 60".to_owned(),
                presence: "ignored".to_owned(),
                value: Some("later".to_owned()),
            },
            UnmappedConstruct::Rule {
                location: "message NewOrderSingle/fieldRef 60".to_owned(),
                name: Some("Late".to_owned()),
                presence: Some("required".to_owned()),
                condition: Some("y".to_owned()),
            },
            element("message NewOrderSingle/fieldRef 60/fixr:assign"),
            UnmappedConstruct::ScenarioReference {
                location: "message NewOrderSingle/fieldRef 38".to_owned(),
                scenario: "Equity".to_owned(),
            },
            scenario(OrchestraKind::Message, "Cancel", "Venue"),
            attribute("message Status/structure", "which", "oneOf"),
            attribute("message Status/fieldRef 11", "value", "X"),
            element("message Status/fixr:responses"),
            element("repository/fixr:actors"),
            element("repository/fixr:concepts"),
            element("repository/ext:custom"),
        ];
        assert_eq!(import.report().entries(), expected.as_slice());
        for entry in import.report().entries() {
            assert!(!entry.to_string().is_empty());
        }

        let dict = import.dictionary();
        let order = some(dict.get_message("D"), "NewOrderSingle");
        // Forbidden Price(44) and the Equity OrderQty(38) are left out; the
        // constant and ignored members are kept, optional.
        assert_eq!(
            listed(order.members()),
            [
                "field 11 (required)",
                "group NoPartyIDs",
                "component Instrument (required)",
                "field 54 (required)",
                "field 40",
                "field 60",
            ]
        );
        assert!(dict.get_message("F").is_none());
        assert!(dict.get_component("Extra").is_none());
        // The base OrderQty is a float; the Equity one is not loaded.
        assert_eq!(
            some(dict.get_field(38), "OrderQty").field_type,
            FieldType::Float
        );
        // The Equity code is left out; the forbidden one is reported but kept.
        let values = some(
            some(dict.get_field(40), "OrdType").values.as_ref(),
            "OrdType values",
        );
        let mut keys: Vec<&str> = values.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["1", "3"]);
    }

    #[test]
    fn test_names_longer_than_the_limit_are_rejected() {
        let long = "A".repeat(MAX_ORCHESTRA_NAME_LEN + 1);
        let doc = Doc::with_fields(&format!(
            r#"<fixr:field id="5000" name="{long}" type="String"/>"#
        ));
        assert_eq!(
            load_err(&doc.xml()),
            DictionaryError::NameTooLong {
                what: "the value of attribute `name` of <fixr:field>".to_owned(),
                len: MAX_ORCHESTRA_NAME_LEN + 1,
                limit: MAX_ORCHESTRA_NAME_LEN,
            }
        );
        // An unmapped attribute's value is kept in the report: bounded too.
        let doc = Doc::with_fields(&format!(
            r#"<fixr:field id="5000" name="Odd" type="String" minInclusive="{long}"/>"#
        ));
        assert!(matches!(
            load_err(&doc.xml()),
            DictionaryError::NameTooLong { .. }
        ));
        let doc = Doc::with_fields(&format!(
            r#"<fixr:field id="5000" name="Odd" type="String" {long}="x"/>"#
        ));
        assert_eq!(
            load_err(&doc.xml()),
            DictionaryError::NameTooLong {
                what: "an attribute name of <fixr:field>".to_owned(),
                len: MAX_ORCHESTRA_NAME_LEN + 1,
                limit: MAX_ORCHESTRA_NAME_LEN,
            }
        );
        let doc = Doc::with_fields(&format!(r#"<x:{long} xmlns:x="urn:example"/>"#));
        assert_eq!(
            load_err(&doc.xml()),
            DictionaryError::NameTooLong {
                what: "an element name".to_owned(),
                len: MAX_ORCHESTRA_NAME_LEN + 3,
                limit: MAX_ORCHESTRA_NAME_LEN,
            }
        );
        // At the limit, a name loads; a descriptive attribute the loader
        // does not keep is bounded only by MAX_ORCHESTRA_ATTRIBUTES_LEN.
        let name = "A".repeat(MAX_ORCHESTRA_NAME_LEN);
        let doc = Doc::with_fields(&format!(
            r#"<fixr:field id="5000" name="{name}" type="String" abbrName="{long}{long}"/>"#
        ));
        let import = load(&doc.xml());
        assert_eq!(
            some(import.dictionary().get_field(5000), "the long field").name,
            name
        );
        assert!(import.report().is_empty());
    }

    #[test]
    fn test_report_is_bounded() {
        // One report entry per unmapped element, up to the limit.
        let at_limit = Doc::with_fields(&"<fixr:x/>".repeat(MAX_ORCHESTRA_REPORT_ENTRIES));
        assert_eq!(
            load(&at_limit.xml()).report().len(),
            MAX_ORCHESTRA_REPORT_ENTRIES
        );
        let past = Doc::with_fields(&"<fixr:x/>".repeat(MAX_ORCHESTRA_REPORT_ENTRIES + 1));
        assert_eq!(
            load_err(&past.xml()),
            DictionaryError::TooManyUnmapped {
                limit: MAX_ORCHESTRA_REPORT_ENTRIES,
            }
        );
        // Unmapped attributes count the same.
        let attributes: String = (0..1_000).map(|i| format!(" a{i}=\"x\"")).collect();
        let fields: String = (0..66)
            .map(|i| {
                format!(
                    r#"<fixr:field id="{}" name="F{i}" type="String"{attributes}/>"#,
                    7000 + i
                )
            })
            .collect();
        assert_eq!(
            load_err(&Doc::with_fields(&fields).xml()),
            DictionaryError::TooManyUnmapped {
                limit: MAX_ORCHESTRA_REPORT_ENTRIES,
            }
        );
    }

    #[test]
    fn test_fixt_repository_must_declare_fixt11() {
        let session = Doc {
            version: "FIX.5.0SP2_EP247".to_owned(),
            ..Doc::default()
        }
        .xml()
        .replace(r#"name="FIX.4.4""#, r#"name="FIXT""#);
        assert_eq!(
            load_err(&session),
            DictionaryError::UnsupportedVersion("FIX.5.0SP2_EP247 (repository FIXT)".to_owned())
        );
        let transport = Doc {
            version: "FIXT.1.1".to_owned(),
            ..Doc::default()
        }
        .xml()
        .replace(r#"name="FIX.4.4""#, r#"name="FIXT""#);
        assert_eq!(load(&transport).dictionary().version, Version::Fixt11);
    }

    #[test]
    fn test_unreferenced_groups_are_checked_and_reported() {
        let unreferenced = |group: &str| {
            let mut doc = Doc::default();
            doc.groups.push_str(group);
            doc.xml()
        };
        assert_eq!(
            load_err(&unreferenced(
                r#"<fixr:group id="2200" name="Loose"><fixr:fieldRef id="448"/></fixr:group>"#
            )),
            DictionaryError::MissingCountField("Loose".to_owned())
        );
        assert_eq!(
            load_err(&unreferenced(
                r#"<fixr:group id="2200" name="Loose"><fixr:numInGroup id="453"/><fixr:fieldRef id="999"/></fixr:group>"#
            )),
            DictionaryError::UnknownOrchestraReference {
                kind: OrchestraKind::Field,
                id: 999,
                owner: "group Loose".to_owned(),
            }
        );
        assert_eq!(
            load_err(&unreferenced(
                r#"<fixr:group id="2200" name="Loose"><fixr:numInGroup id="999"/><fixr:fieldRef id="448"/></fixr:group>"#
            )),
            DictionaryError::UnknownOrchestraReference {
                kind: OrchestraKind::Field,
                id: 999,
                owner: "group Loose".to_owned(),
            }
        );
        assert_eq!(
            load_err(&unreferenced(
                r#"<fixr:group id="2200" name="Loose"><fixr:numInGroup id="453"/><fixr:componentRef id="1999"/></fixr:group>"#
            )),
            DictionaryError::UnknownOrchestraReference {
                kind: OrchestraKind::Component,
                id: 1999,
                owner: "group Loose".to_owned(),
            }
        );
        assert_eq!(
            load_err(&unreferenced(
                r#"<fixr:group id="2200" name="Loose"><fixr:numInGroup id="453"/></fixr:group>"#
            )),
            DictionaryError::EmptyGroup("NoPartyIDs".to_owned())
        );

        // A valid group nothing reaches, and one reached only through it,
        // load and are reported; so is a code set no field names.
        let mut doc = Doc::default();
        doc.groups.push_str(
            r#"<fixr:group id="2200" name="Loose"><fixr:numInGroup id="453"/><fixr:groupRef id="2201"/></fixr:group>
               <fixr:group id="2201" name="Inner"><fixr:numInGroup id="453"/><fixr:fieldRef id="448"/></fixr:group>"#,
        );
        doc.code_sets
            .push_str(r#"<fixr:codeSet id="77" name="SpareCodeSet" type="char"/>"#);
        let import = load(&doc.xml());
        assert_eq!(
            import.report().entries(),
            [
                UnmappedConstruct::Unreferenced {
                    kind: OrchestraKind::Group,
                    name: "Loose".to_owned(),
                },
                UnmappedConstruct::Unreferenced {
                    kind: OrchestraKind::Group,
                    name: "Inner".to_owned(),
                },
                UnmappedConstruct::Unreferenced {
                    kind: OrchestraKind::CodeSet,
                    name: "SpareCodeSet".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn test_member_value_is_reported_once() {
        let mut doc = Doc::default();
        doc.messages = doc.messages.replace(
            r#"<fixr:fieldRef id="44"/>"#,
            r#"<fixr:fieldRef id="44" value="1"/><fixr:fieldRef id="55" presence="forbidden" value="2"/>"#,
        );
        let import = load(&doc.xml());
        assert_eq!(
            import.report().entries(),
            [
                UnmappedConstruct::Attribute {
                    location: "message NewOrderSingle/fieldRef 44".to_owned(),
                    name: "value".to_owned(),
                    value: "1".to_owned(),
                },
                UnmappedConstruct::Presence {
                    location: "message NewOrderSingle/fieldRef 55".to_owned(),
                    presence: "forbidden".to_owned(),
                    value: Some("2".to_owned()),
                },
            ]
        );
    }

    #[test]
    fn test_component_chain_without_fields_is_walked_once() {
        // 32 components, each holding the next twice and the last nothing,
        // ahead of a group's first field: without a cache, finding the
        // group's delimiter walks 2^31 paths.
        let mut doc = Doc::default();
        for level in 0..32u32 {
            let members = if level == 31 {
                String::new()
            } else {
                format!(r#"<fixr:componentRef id="{}"/>"#, 1201 + level).repeat(2)
            };
            doc.components.push_str(&format!(
                r#"<fixr:component id="{}" name="Hollow{level}">{members}</fixr:component>"#,
                1200 + level
            ));
        }
        doc.groups = doc.groups.replace(
            r#"<fixr:fieldRef id="448"/>"#,
            r#"<fixr:componentRef id="1200"/><fixr:fieldRef id="448"/>"#,
        );
        let import = load(&doc.xml());
        let order = some(import.dictionary().get_message("D"), "NewOrderSingle");
        assert_eq!(order.groups()[0].delimiter_tag, 448);
    }

    #[test]
    fn test_member_budget_holds_with_names_at_the_limit() {
        // The longest name the loader keeps, copied into every member that
        // expansion produces: 17 levels of doubled group references make
        // 196 607 members, under MAX_ORCHESTRA_MEMBERS; 18 levels pass it.
        // tests/orchestra_memory.rs measures the heap this takes.
        let leaf = "L".repeat(MAX_ORCHESTRA_NAME_LEN);
        let field = format!(r#"<fixr:field id="7000" name="{leaf}" type="String"/>"#);
        let mut doc = group_chain_to(17, 2, 7000);
        doc.fields.push_str(&field);
        let import = load(&doc.xml());
        let deep = some(import.dictionary().get_message("U9"), "Deep");
        let mut group = &deep.groups()[0];
        for _ in 1..17 {
            group = &group.groups()[0];
        }
        assert_eq!(group.fields()[0].name, leaf);

        let mut doc = group_chain_to(18, 2, 7000);
        doc.fields.push_str(&field);
        assert!(doc.xml().len() < 16 * 1024);
        assert_eq!(
            load_err(&doc.xml()),
            DictionaryError::TooManyMembers {
                limit: MAX_ORCHESTRA_MEMBERS,
            }
        );
    }

    #[test]
    fn test_field_values_copied_from_shared_code_sets_are_bounded() {
        // One code set of 1 024 codes, named by `fields` fields: each field
        // holds its own copy of the 1 024 values.
        let shared = |fields: u32| {
            let codes: String = (0..1024)
                .map(|i| {
                    format!(
                        r#"<fixr:code id="{}" name="C{i}" value="V{i}"/>"#,
                        90_000 + i
                    )
                })
                .collect();
            let mut doc = Doc::default();
            doc.code_sets.push_str(&format!(
                r#"<fixr:codeSet id="77" name="WideCodeSet" type="String">{codes}</fixr:codeSet>"#
            ));
            for i in 0..fields {
                doc.fields.push_str(&format!(
                    r#"<fixr:field id="{}" name="Wide{i}" type="WideCodeSet"/>"#,
                    8000 + i
                ));
            }
            doc.xml()
        };
        // The default document's Side copies 2 values: 255 fields plus Side
        // stay under the limit, 256 more pass it.
        let fit = (MAX_ORCHESTRA_FIELD_VALUES - 2) / 1024;
        let fit = u32::try_from(fit).unwrap_or(u32::MAX);
        let import = load(&shared(fit));
        let copied: usize = import
            .dictionary()
            .fields()
            .filter_map(|field| field.values.as_ref())
            .map(HashMap::len)
            .sum();
        assert!(copied <= MAX_ORCHESTRA_FIELD_VALUES);
        assert_eq!(
            load_err(&shared(fit + 1)),
            DictionaryError::TooManyFieldValues {
                limit: MAX_ORCHESTRA_FIELD_VALUES,
            }
        );
    }

    #[test]
    fn test_mapped_section_attributes_are_read_and_reported() {
        let doc = Doc {
            extra: r#"<fixr:groups custom="y" latestEP="312" xml:base="x"/>"#.to_owned(),
            ..Doc::default()
        };
        let xml = doc
            .xml()
            .replace("<fixr:fields>", r#"<fixr:fields custom="x">"#);
        let import = load(&xml);
        assert_eq!(
            import.report().entries(),
            [
                UnmappedConstruct::Attribute {
                    location: "fields".to_owned(),
                    name: "custom".to_owned(),
                    value: "x".to_owned(),
                },
                UnmappedConstruct::Attribute {
                    location: "groups".to_owned(),
                    name: "custom".to_owned(),
                    value: "y".to_owned(),
                },
            ]
        );
        // A section's attributes are bounded like any element's.
        let big = "x".repeat(MAX_ORCHESTRA_ATTRIBUTES_LEN);
        let xml = Doc::default()
            .xml()
            .replace("<fixr:codeSets>", &format!(r#"<fixr:codeSets a="{big}">"#));
        assert!(matches!(
            load_err(&xml),
            DictionaryError::AttributesTooLong { .. }
        ));
        let long = "x".repeat(MAX_ORCHESTRA_NAME_LEN + 1);
        let xml = Doc::default()
            .xml()
            .replace("<fixr:messages>", &format!(r#"<fixr:messages a="{long}">"#));
        assert!(matches!(
            load_err(&xml),
            DictionaryError::NameTooLong { .. }
        ));
    }

    #[test]
    fn test_duplicate_code_ids_in_a_code_set_are_rejected() {
        let mut doc = Doc::default();
        doc.code_sets = doc.code_sets.replace(
            r#"<fixr:code id="54002" name="Sell" value="2"/>"#,
            r#"<fixr:code id="54002" name="Sell" value="2"/><fixr:code id="54001" name="Cross" value="8"/>"#,
        );
        assert_eq!(
            load_err(&doc.xml()),
            DictionaryError::DuplicateOrchestraDefinition {
                kind: OrchestraKind::Code,
                key: "SideCodeSet id 54001".to_owned(),
            }
        );
        // A code of another scenario may reuse a base code's id.
        let mut doc = Doc::default();
        doc.code_sets = doc.code_sets.replace(
            r#"<fixr:code id="54002" name="Sell" value="2"/>"#,
            r#"<fixr:code id="54002" name="Sell" value="2"/><fixr:code id="54001" name="Cross" value="8" scenario="Equity"/>"#,
        );
        let import = load(&doc.xml());
        let values = some(
            some(import.dictionary().get_field(54), "Side")
                .values
                .as_ref(),
            "Side values",
        );
        assert_eq!(values.len(), 2);
    }

    #[test]
    fn test_optional_envelope_component_keeps_its_members_optional() {
        let header = |reference: &str| {
            let mut doc = Doc::default();
            doc.groups = doc.groups.replace(
                r#"<fixr:fieldRef id="448"/>"#,
                r#"<fixr:fieldRef id="448" presence="required"/>"#,
            );
            doc.components.push_str(
                r#"<fixr:component id="1004" name="Routing">
                     <fixr:fieldRef id="55" presence="required"/>
                     <fixr:groupRef id="2000" presence="required"/>
                   </fixr:component>
                   <fixr:component id="1005" name="Outer">
                     <fixr:componentRef id="1004" presence="required"/>
                   </fixr:component>"#,
            );
            doc.components = doc.components.replace(
                r#"<fixr:fieldRef id="35" presence="required"/>"#,
                &format!(r#"<fixr:fieldRef id="35" presence="required"/>{reference}"#),
            );
            load(&doc.xml())
        };
        let flags = |import: &OrchestraImport| {
            let dict = import.dictionary();
            let symbol = some(dict.header.iter().find(|f| f.tag == 55), "Symbol");
            let group = some(dict.header_groups.first(), "NoPartyIDs");
            let party_id = some(group.fields().iter().find(|f| f.tag == 448), "PartyID");
            (symbol.required, group.required, party_id.required)
        };
        // An optional block: its members are required only with it, but a
        // group entry's members stay required within the entry.
        assert_eq!(
            flags(&header(r#"<fixr:componentRef id="1004"/>"#)),
            (false, false, true)
        );
        // Through a required component inside the optional one.
        assert_eq!(
            flags(&header(r#"<fixr:componentRef id="1005"/>"#)),
            (false, false, true)
        );
        // A required block keeps them required.
        assert_eq!(
            flags(&header(
                r#"<fixr:componentRef id="1005" presence="required"/>"#
            )),
            (true, true, true)
        );
    }

    /// The default document plus `count` groups nothing references, each
    /// holding the next `refs` times (the last a field), and, when
    /// `cycle`, the last holding the first.
    fn loose_chain(count: u32, refs: usize, cycle: bool) -> Doc {
        let mut doc = Doc::default();
        for level in 0..count {
            let id = 2300 + level;
            let members = if level + 1 == count {
                if cycle {
                    r#"<fixr:groupRef id="2300"/>"#.to_owned()
                } else {
                    r#"<fixr:fieldRef id="448"/>"#.to_owned()
                }
            } else {
                format!(r#"<fixr:groupRef id="{}"/>"#, id + 1).repeat(refs)
            };
            doc.groups.push_str(&format!(
                r#"<fixr:group id="{id}" name="Loose{level}"><fixr:numInGroup id="453"/>{members}</fixr:group>"#
            ));
        }
        doc
    }

    #[test]
    fn test_unreferenced_group_graph_is_checked() {
        // A group holding itself, and a cycle of two, though nothing
        // references them.
        assert_eq!(
            load_err(&loose_chain(1, 1, true).xml()),
            DictionaryError::GroupCycle("Loose0".to_owned())
        );
        assert!(matches!(
            load_err(&loose_chain(2, 1, true).xml()),
            DictionaryError::GroupCycle(_)
        ));
        // A chain no message could hold, though nothing references it.
        let deepest = u32::try_from(MAX_NESTING_DEPTH - 1).unwrap_or(u32::MAX);
        assert!(matches!(
            load_err(&loose_chain(deepest + 1, 1, false).xml()),
            DictionaryError::NestingTooDeep { .. }
        ));
        // A chain that fits loads, reported unreferenced; doubled references
        // are checked once each (2^30 paths otherwise).
        let import = load(&loose_chain(deepest, 2, false).xml());
        let unreferenced = import
            .report()
            .entries()
            .iter()
            .filter(|entry| matches!(entry, UnmappedConstruct::Unreferenced { .. }))
            .count();
        assert_eq!(unreferenced, MAX_NESTING_DEPTH - 1);
    }
}
