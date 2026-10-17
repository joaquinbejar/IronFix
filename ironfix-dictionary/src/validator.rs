/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 12/7/26
******************************************************************************/

//! Dictionary-driven message validation.
//!
//! [`Validator`] checks a parsed [`RawMessage`] against a [`Dictionary`], or
//! against a [`SessionDictionary`] that composes a FIXT.1.1 transport
//! dictionary with an application dictionary:
//!
//! - for a [`SessionDictionary`] only, `BeginString(8)` must be the
//!   transport's (`FIXT.1.1`)
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
//! - every entry of a well-formed group must carry the entry's required
//!   members (see [Required members of each entry](#required-members-of-each-entry))
//!
//! # Which dictionary answers which tag
//!
//! A validator built with [`Validator::new`] answers everything from its one
//! dictionary. One built with [`Validator::for_session`] follows
//! QuickFIX-like FIXT.1.1 semantics:
//!
//! - a message type the transport dictionary defines with `msgcat='admin'`
//!   (Logon, Heartbeat, ...) is validated entirely against the transport
//!   dictionary;
//! - every other message type must be defined by the application dictionary.
//!   The tags of the transport dictionary's header and trailer (members of
//!   header and trailer groups included) resolve against the transport
//!   dictionary; every other tag resolves against the application
//!   dictionary.
//!
//! ## Differences from QuickFIX
//!
//! - **No `ApplVerID`-based dictionary selection.** QuickFIX picks the
//!   application dictionary per message from `ApplVerID(1128)`, falling back
//!   to the session's `DefaultApplVerID(1137)`. Here the
//!   [`SessionDictionary`] names exactly one application dictionary and
//!   neither tag is consulted.
//! - **Admin routing follows the transport dictionary's `msgcat`.** QuickFIX
//!   decides "admin" with a fixed list (`Message::isAdminMsgType`: `0`, `A`,
//!   `1` to `5`). Here any message type the transport defines with
//!   `msgcat='admin'` is admin, so `XMLnonFIX` (`35=n`, `msgcat='admin'` in
//!   `FIXT11.xml`) is validated against the transport, whereas QuickFIX
//!   would look it up in the application dictionary.
//! - **Every error is returned.** QuickFIX stops at the first rejection
//!   (an unsupported `BeginString` included); [`Validator::validate`]
//!   collects all of them, up to [`MAX_VALIDATION_ERRORS`].
//! - **Field order is not enforced.** QuickFIX rejects a header field after
//!   the body or a body field after the trailer ("tag specified out of
//!   required order"); this validator does not check position.
//! - **Group entries are checked more strictly.** QuickFIX (C++ and Java,
//!   `addXMLGroup`) enforces an entry's required fields only when the group
//!   itself is `required='Y'`, and QuickFIX C++ ignores the required fields
//!   of components referenced inside a group. This validator applies the FIX
//!   rule instead: a required member is required in every entry of every
//!   group instance present, required group or not, components included.
//!   A message a QuickFIX counterparty accepts can therefore be rejected
//!   here, for example FIX 4.4 `PosUndInstrmtGrp` / `NoUnderlyings(711)`
//!   entries without `UnderlyingSettlPrice(732)`, FIX 4.2 Allocation
//!   `NoAllocs(78)` entries without `AllocShares(80)`, and in FIX 5.0 SP2 the
//!   ten optional groups (fifteen group definitions) that declare required
//!   fields directly, `NoOrders(73)` and `NoSides(552)` among them.
//! - **Structural errors come first.** QuickFIX checks required fields, per
//!   entry included, before group counts, so for a message with both
//!   problems it rejects with `SessionRejectReason(373)=1` (required tag
//!   missing); this validator reports the group's structural error and
//!   suppresses that group's per-entry errors.
//! - **Missing tags are reported in dictionary order.** QuickFIX reports the
//!   lowest missing tag number first; this validator reports them in the
//!   order the dictionary declares them (see the error order below).
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
//! ## Required members of each entry
//!
//! Every entry of a group instance is also checked for its required
//! members, reported as [`ValidationError::MissingRequiredFieldInGroupEntry`]
//! with the entry's **0-based** index (the first entry after the count field
//! is entry `0`). An entry's required set is what the dictionary marks
//! required, applied per the FIX rule that a required member is required in
//! every entry of every group instance present, whether or not the group
//! itself is required (stricter than QuickFIX, see above):
//!
//! - every member field marked `required='Y'`;
//! - every nested group marked `required='Y'`, reported with the nested
//!   group's count tag when the entry lacks it; nested groups are checked
//!   entry by entry in turn, within the existing [`MAX_SCOPE_DEPTH`] bound;
//! - the required members of a component referenced as `required='Y'`, at
//!   any depth of component nesting. The required members of a component
//!   referenced as `required='N'`, nested groups included, are **not**
//!   enforced, even when another member of that component appears in the
//!   entry.
//!
//! A tag required more than once (directly and through a component) is
//! reported once per entry. The delimiter is never reported missing, since it
//! is what opens an entry; when the delimiter is itself a nested group's
//! count tag, that nested group counts as present. A group instance with a
//! structural error (a delimiter mismatch, a tag repeated within an entry, an
//! unparseable count, or a count that does not match the entries found) gets
//! no per-entry errors, its nested groups' included: the group already
//! carries a structural error. A malformed *nested* group suppresses only its
//! own per-entry errors, not those of the entry that encloses it. A count of
//! `0` with no entries checks nothing.
//!
//! Error order: within an entry, missing fields in dictionary order, then
//! missing nested groups by count tag; across entries, in the order entries
//! close, so a nested group's entries come before the entry that encloses
//! them. All per-entry errors follow the message's structural errors.
//!
//! **Behaviour change.** Before per-entry checking existed, a message whose
//! group entries lacked required members validated; it is now rejected, so
//! validation is stricter than it was, and stricter than QuickFIX: a message
//! a QuickFIX counterparty accepts can be rejected here (see "Differences
//! from QuickFIX").
//!
//! # Bounded output
//!
//! A single call collects at most [`MAX_VALIDATION_ERRORS`] errors. When the
//! limit is reached, collection stops and a final
//! [`ValidationError::ErrorLimitReached`] is appended, so a hostile message
//! cannot turn validation into an allocation proportional to its size.
//!
//! Notes:
//! - `CheckSum(10)` presence is not re-checked: the tag-value decoder
//!   already consumes and verifies it, so it never appears among the
//!   parsed fields.
//! - The validator is a standalone, opt-in facility. It is not invoked by
//!   the codec or by the engine.

use crate::composition::SessionDictionary;
use crate::schema::{
    ComponentRef, Dictionary, FieldDef, FieldType, GroupDef, MessageCategory, MessageDef,
};
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

/// Maximum number of errors one [`Validator::validate`] call collects.
///
/// Past this many, collection stops and the list ends with
/// [`ValidationError::ErrorLimitReached`]. Without a cap, a hostile message
/// within the codec's default 1 MiB frame limit can fail a check on almost
/// every field: a ListStatus (35=N) of 200,000 one-field `NoOrders` entries
/// yields a million per-entry errors. 1024 still lists every problem of any
/// realistic message, while a reject or a log line needs only the first few.
pub const MAX_VALIDATION_ERRORS: usize = 1024;

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
    /// `BeginString(8)` is not the transport dictionary's.
    ///
    /// Reported only by a validator built with [`Validator::for_session`],
    /// where the transport is FIXT.1.1 and so tag 8 must be `FIXT.1.1`.
    /// [`Validator::new`] does not check tag 8.
    #[error("BeginString(8) is `{found}`, but the transport dictionary requires `{expected}`")]
    BeginStringMismatch {
        /// The BeginString the transport dictionary's version requires.
        expected: String,
        /// The BeginString the message carries.
        found: String,
    },
    /// A required member is missing from one entry of a repeating group.
    ///
    /// `entry` is the **0-based** index of the entry within its group
    /// instance: the first entry after the count field is entry `0`. `tag` and
    /// `name` identify the missing field or, when a required *nested group* is
    /// absent from the entry, that nested group's count tag and name.
    ///
    /// Only a structurally sound group instance is checked entry by entry
    /// (its count matches the entries found and every entry is led by the
    /// delimiter): a malformed group already carries a structural error.
    #[error("missing required field {name}({tag}) in entry {entry} of group {group}({count_tag})")]
    MissingRequiredFieldInGroupEntry {
        /// Count field tag (NumInGroup) of the group.
        count_tag: u32,
        /// Group name.
        group: String,
        /// 0-based index of the entry the member is missing from.
        entry: u64,
        /// Tag of the missing field, or count tag of the missing nested group.
        tag: u32,
        /// Name of the missing field or nested group.
        name: String,
    },
    /// The validation stopped collecting errors at [`MAX_VALIDATION_ERRORS`].
    ///
    /// When present it is the last element of the returned list, after at
    /// most `limit` other errors; the message has further errors that were
    /// not recorded.
    #[error("validation stopped after {limit} errors; further errors were not recorded")]
    ErrorLimitReached {
        /// The error ceiling that was reached.
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

    /// Returns every tag that may appear at this level or inside any group
    /// entry below it.
    ///
    /// Iterative, so its depth is not bounded by the call stack; the tree it
    /// walks is itself bounded by [`MAX_SCOPE_DEPTH`] and [`MAX_SCOPE_NODES`].
    fn all_tags(&self) -> HashSet<u32> {
        let mut tags = HashSet::new();
        let mut pending: Vec<&Self> = vec![self];
        while let Some(level) = pending.pop() {
            tags.extend(level.allowed.iter().copied());
            pending.extend(level.groups.values().map(|group| &group.entry));
        }
        tags
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

/// The expanded schema of one message.
#[derive(Debug)]
struct Scope {
    /// The message level: header, trailer, and body merged.
    level: Level,
    /// Every tag the header and trailer contribute, members of header and
    /// trailer groups included. These resolve against the transport
    /// dictionary.
    envelope: HashSet<u32>,
}

/// Expands a [`MessageDef`] into the level tree the walker validates against.
struct ScopeBuilder<'d> {
    /// The dictionary component references currently resolve against: the
    /// transport while the header and trailer are expanded, then the
    /// dictionary that defines the message body.
    dict: &'d Dictionary,
    budget: usize,
    errors: Vec<ValidationError>,
}

impl<'d> ScopeBuilder<'d> {
    /// Expands `msg_def` with its header and trailer from `transport` and its
    /// body components resolved against `body`, returning the scope and every
    /// schema error met on the way (ceilings, undefined components).
    ///
    /// For a single-dictionary validator `transport` and `body` are the same
    /// dictionary.
    fn expand(
        transport: &'d Dictionary,
        body: &'d Dictionary,
        msg_def: &MessageDef,
    ) -> (Scope, Vec<ValidationError>) {
        let mut builder = Self {
            dict: transport,
            budget: MAX_SCOPE_NODES,
            errors: Vec::new(),
        };
        let scope = builder.build(transport, body, msg_def);
        (scope, builder.errors)
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

    /// Builds the message level: header and trailer from `transport`, then
    /// body fields, groups, and directly referenced components from `body`.
    fn build(
        &mut self,
        transport: &'d Dictionary,
        body: &'d Dictionary,
        msg_def: &MessageDef,
    ) -> Scope {
        let mut level = Level::default();
        let mut path = HashSet::new();

        self.dict = transport;
        for field in &transport.header {
            level.add_field(field.tag, &field.name, field.required);
        }
        for group in &transport.header_groups {
            self.add_group(&mut level, group, group.required, true, 0, &mut path);
        }
        for field in &transport.trailer {
            level.add_field(field.tag, &field.name, field.required);
        }
        for group in &transport.trailer_groups {
            self.add_group(&mut level, group, group.required, true, 0, &mut path);
        }
        let envelope = level.all_tags();

        self.dict = body;
        for field in &msg_def.fields {
            level.add_field(field.tag, &field.name, field.required);
        }
        for group in &msg_def.groups {
            self.add_group(&mut level, group, group.required, true, 0, &mut path);
        }
        for component in &msg_def.components {
            self.add_component(&mut level, component, true, 0, &mut path);
        }

        Scope { level, envelope }
    }

    /// Adds a group to `level` and builds the level formed by one entry.
    ///
    /// The group's component references resolve against `self.dict`.
    /// `required` and `collect_required` decide only whether the group itself
    /// must appear at `level`. The entry level always collects its members'
    /// required flags, because per the FIX rule they apply to every entry of
    /// every group instance present, whether or not the group is required:
    /// required fields, nested groups marked required, and the required
    /// members of components referenced as required. The required members of
    /// a component referenced as *optional* are never collected, even when
    /// some other member of that component appears in the entry. This is
    /// stricter than QuickFIX, which collects an entry's required fields only
    /// for a required group, and (in C++) none from components inside a group.
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
            entry.add_field(field.tag, &field.name, field.required);
        }
        for nested in &group.groups {
            self.add_group(&mut entry, nested, nested.required, true, depth + 1, path);
        }
        for component in &group.components {
            self.add_component(&mut entry, component, true, depth + 1, path);
        }
        // Each required tag is kept once, in its first (dictionary) position,
        // so the per-entry check is linear in the required set. The delimiter
        // is dropped: it opens every entry, so it can never be missing.
        let mut unique: HashSet<u32> = HashSet::with_capacity(entry.required.len());
        entry
            .required
            .retain(|(tag, _)| *tag != group.delimiter_tag && unique.insert(*tag));

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
    /// The reference resolves against `self.dict`. `collect_required` says
    /// whether requiredness is meaningful where the reference sits; combined
    /// with the reference's own flag it gives the effective requiredness, so a
    /// component's required members can only make a message invalid when the
    /// reference that pulled it in was itself required.
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

/// Answers which [`FieldDef`] a tag of the message being validated has.
///
/// Envelope tags (the header and trailer of the transport dictionary)
/// resolve against `transport`; every other tag against `body`, the
/// dictionary that defines the message type.
struct TagResolver<'d, 's> {
    transport: &'d Dictionary,
    body: &'d Dictionary,
    envelope: &'s HashSet<u32>,
}

impl<'d> TagResolver<'d, '_> {
    /// Returns the definition of `tag`, or `None` if the dictionary that
    /// answers it does not define it.
    fn field(&self, tag: u32) -> Option<&'d FieldDef> {
        if self.envelope.contains(&tag) {
            self.transport.get_field(tag)
        } else {
            self.body.get_field(tag)
        }
    }
}

/// Validates parsed messages against a [`Dictionary`], or against a
/// [`SessionDictionary`] composing a transport and an application dictionary.
#[derive(Debug, Clone, Copy)]
pub struct Validator<'d> {
    /// Answers the standard header and trailer and the admin messages.
    transport: &'d Dictionary,
    /// Answers application message bodies. The same dictionary as
    /// `transport` for a validator built with [`Validator::new`].
    application: &'d Dictionary,
    /// The `BeginString(8)` every message must carry, when it is checked.
    /// `None` for [`Validator::new`], which does not check tag 8.
    begin_string: Option<&'static str>,
}

impl<'d> Validator<'d> {
    /// Creates a validator for the given dictionary.
    ///
    /// The one dictionary answers the header, the trailer, and every message
    /// body. Use it for a FIX 4.x dictionary on a FIX 4.x session, which
    /// carries all three; for a FIXT.1.1 session (a FIX 5.0 family
    /// application dictionary, whose header and trailer are empty, or a FIX
    /// 4.x application carried over FIXT.1.1), use [`Validator::for_session`].
    ///
    /// `BeginString(8)` is **not** checked against the dictionary's version
    /// here: a FIX 4.4 dictionary accepts a message with `8=FIX.4.2`. That is
    /// a known gap of this constructor; [`Validator::for_session`] does check
    /// tag 8.
    #[must_use]
    pub const fn new(dict: &'d Dictionary) -> Self {
        Self {
            transport: dict,
            application: dict,
            begin_string: None,
        }
    }

    /// Creates a validator for a FIXT.1.1 transport dictionary composed with
    /// an application dictionary.
    ///
    /// Admin messages the transport dictionary defines are validated against
    /// it alone; application messages take their header and trailer from the
    /// transport dictionary and their body from the application dictionary.
    /// The semantics are QuickFIX-like, not identical: see the
    /// [module docs](crate::validator) for the exact resolution rules and the
    /// differences from QuickFIX.
    ///
    /// Additionally, every message must carry `BeginString(8)` equal to the
    /// transport's [`begin_string`](crate::Version::begin_string)
    /// (`FIXT.1.1`); anything else is
    /// [`ValidationError::BeginStringMismatch`].
    ///
    /// Notes:
    /// - A tag that one dictionary of the pair defines but the dictionary
    ///   answering it does not (for example `ClOrdID(11)`, defined by FIX 5.0
    ///   SP2, in a Heartbeat answered by FIXT 1.1) is reported as
    ///   [`ValidationError::UnknownTag`]. A session reject would map that to
    ///   `SessionRejectReason(373)=0` (invalid tag number), although `2` (tag
    ///   not defined for this message type) describes it better; mapping
    ///   validation errors to 373 values is future work (#84).
    /// - The embedded FIXT 1.1 transport ([`Dictionary::fixt11`]) does not
    ///   define the Logon `NoMsgTypes(384)` group, an upstream QuickFIX
    ///   deviation, so a Logon carrying it is reported. Compose a FIXT 1.1
    ///   dictionary that defines the group, loaded with
    ///   [`Dictionary::from_quickfix_xml`], to accept it.
    ///
    /// # Examples
    ///
    /// ```
    /// use ironfix_dictionary::{Dictionary, SessionDictionary, Validator};
    ///
    /// let session = SessionDictionary::new(Dictionary::fixt11()?, Dictionary::fix50sp2()?)?;
    /// let validator = Validator::for_session(&session);
    /// # let _ = validator;
    /// # Ok::<(), ironfix_dictionary::DictionaryError>(())
    /// ```
    #[must_use]
    pub const fn for_session(session: &SessionDictionary<'d>) -> Self {
        let transport = session.transport();
        Self {
            transport,
            application: session.application(),
            begin_string: Some(transport.version.begin_string()),
        }
    }

    /// Resolves a message type to its definition and to the dictionary that
    /// answers its body.
    ///
    /// An admin message the transport dictionary defines wins; otherwise the
    /// application dictionary must define the message type.
    fn resolve(&self, msg_type: &str) -> Option<(&'d MessageDef, &'d Dictionary)> {
        if let Some(def) = self.transport.get_message(msg_type)
            && def.category == MessageCategory::Admin
        {
            return Some((def, self.transport));
        }
        self.application
            .get_message(msg_type)
            .map(|def| (def, self.application))
    }

    /// Validates a parsed message against the dictionary.
    ///
    /// # Arguments
    /// * `msg` - The decoded message to validate
    ///
    /// # Errors
    /// Returns every [`ValidationError`] found, up to
    /// [`MAX_VALIDATION_ERRORS`]; past that, collection stops and the list
    /// ends with [`ValidationError::ErrorLimitReached`]. `Ok(())` means the
    /// message passed all checks.
    pub fn validate(&self, msg: &RawMessage<'_>) -> Result<(), Vec<ValidationError>> {
        let fields: Vec<_> = msg.fields().collect();
        let mut sink = ErrorSink::default();

        // A missing BeginString(8) is reported as a missing required header
        // field below; only a present, wrong value is a mismatch.
        if let Some(expected) = self.begin_string
            && let Some(begin_string) = fields.iter().find(|field| field.tag == 8)
        {
            let found = String::from_utf8_lossy(begin_string.value);
            if found != expected {
                sink.push(ValidationError::BeginStringMismatch {
                    expected: expected.to_string(),
                    found: found.into_owned(),
                });
            }
        }

        let msg_type = msg.msg_type().as_str().to_string();
        let Some((msg_def, body)) = self.resolve(&msg_type) else {
            sink.push(ValidationError::UnknownMsgType { msg_type });
            return sink.finish();
        };

        let (Scope { level, envelope }, scope_errors) =
            ScopeBuilder::expand(self.transport, body, msg_def);
        for error in scope_errors {
            sink.push(error);
        }
        let tags = TagResolver {
            transport: self.transport,
            body,
            envelope: &envelope,
        };

        // Value-level checks apply wherever a field sits.
        for field in &fields {
            check_value(&tags, field, &mut sink);
        }

        // Structural walk over the message level. Per-entry errors of every
        // well-formed group instance collect in `entry_errors` and follow the
        // structural ones.
        let mut seen: HashSet<u32> = HashSet::new();
        let mut entry_errors: Vec<ValidationError> = Vec::new();
        let mut index = 0;
        while let Some(field) = fields.get(index) {
            let tag = field.tag;
            let Some(def) = tags.field(tag) else {
                // Already reported as UnknownTag by the value pass.
                index += 1;
                continue;
            };
            if !seen.insert(tag) {
                sink.push(ValidationError::DuplicateTag {
                    tag,
                    name: def.name.clone(),
                });
            }
            if let Some(group) = level.groups.get(&tag) {
                index = walk_group(&tags, &fields, index, group, &mut sink, &mut entry_errors);
                continue;
            }
            if !level.allowed.contains(&tag) {
                sink.push(ValidationError::FieldNotAllowedForMessage {
                    tag,
                    msg_type: msg_type.clone(),
                });
            }
            index += 1;
        }
        sink.accept(&mut entry_errors);

        // Required fields. CheckSum(10) is consumed by the decoder and never
        // appears among the parsed fields, so it is skipped here.
        for (tag, name) in &level.required {
            if *tag != 10 && !seen.contains(tag) {
                sink.push(ValidationError::MissingRequiredField {
                    tag: *tag,
                    name: name.clone(),
                });
            }
        }

        for group in level.groups.values() {
            if group.required && !seen.contains(&group.count_tag) {
                sink.push(ValidationError::MissingRequiredGroup {
                    count_tag: group.count_tag,
                    name: group.name.clone(),
                });
            }
        }

        sink.finish()
    }
}

/// Collects the errors of one [`Validator::validate`] call, up to
/// [`MAX_VALIDATION_ERRORS`].
///
/// Per-entry errors wait in pending buffers until their group instance is
/// known to be well-formed. They count against the limit while they wait, and
/// give their room back if their group turns out malformed and they are
/// dropped. Once an error has been refused, collection stops for good, so the
/// result is a prefix of what an unbounded run would report.
#[derive(Debug, Default)]
struct ErrorSink {
    /// Errors accepted into the result.
    errors: Vec<ValidationError>,
    /// Errors counted against the limit: accepted ones plus pending ones not
    /// yet accepted or dropped.
    held: usize,
    /// Whether an error has been refused because the limit was reached.
    truncated: bool,
}

impl ErrorSink {
    /// Takes room for one more error, or records that the limit is reached.
    fn reserve(&mut self) -> bool {
        if self.truncated || self.held >= MAX_VALIDATION_ERRORS {
            self.truncated = true;
            return false;
        }
        self.held += 1;
        true
    }

    /// Records an error directly in the result.
    fn push(&mut self, error: ValidationError) {
        if self.reserve() {
            self.errors.push(error);
        }
    }

    /// Records a per-entry error in a pending buffer.
    fn hold(&mut self, pending: &mut Vec<ValidationError>, error: ValidationError) {
        if self.reserve() {
            pending.push(error);
        }
    }

    /// Moves pending errors into the result; they already hold their room.
    fn accept(&mut self, pending: &mut Vec<ValidationError>) {
        self.errors.append(pending);
    }

    /// Drops pending errors and gives their room back.
    fn release(&mut self, pending: Vec<ValidationError>) {
        debug_assert!(self.held >= pending.len(), "pending errors were counted");
        if let Some(held) = self.held.checked_sub(pending.len()) {
            self.held = held;
        }
    }

    /// Ends the call: `Ok` when nothing was found, otherwise the errors,
    /// closed by [`ValidationError::ErrorLimitReached`] if any was refused.
    fn finish(mut self) -> Result<(), Vec<ValidationError>> {
        if self.truncated {
            self.errors.push(ValidationError::ErrorLimitReached {
                limit: MAX_VALIDATION_ERRORS,
            });
        }
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(self.errors)
        }
    }
}

/// Checks that a field is defined, well-formed for its type, and — when
/// enumerated — carries a defined value.
fn check_value(
    tags: &TagResolver<'_, '_>,
    field: &ironfix_core::field::FieldRef<'_>,
    errors: &mut ErrorSink,
) {
    let Some(def) = tags.field(field.tag) else {
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
/// Structural errors (count, delimiter, a tag repeated inside an entry) go
/// straight to `sink`. Per-entry errors, the required members missing from an
/// entry of this group or of any group nested in it, are produced by
/// [`check_entry_required`] at every entry boundary and held back: they are
/// appended to `entry_errors` only if this group instance turns out
/// well-formed (every entry delimiter-led, no tag repeated within an entry,
/// and the declared count equal to the entries found). Otherwise they are
/// dropped, because the group already carries a structural error.
///
/// Nothing here is sized from the declared count: entries are counted as
/// they are found, so a count of `99999999999` costs no more than the fields
/// actually present.
///
/// Returns the index of the first field after the group.
fn walk_group(
    tags: &TagResolver<'_, '_>,
    fields: &[&ironfix_core::field::FieldRef<'_>],
    index: usize,
    group: &GroupNode,
    sink: &mut ErrorSink,
    entry_errors: &mut Vec<ValidationError>,
) -> usize {
    let Some(count_field) = fields.get(index) else {
        return index;
    };
    let count_value = String::from_utf8_lossy(count_field.value);
    let declared = match count_value.parse::<u64>() {
        Ok(declared) => Some(declared),
        Err(_) => {
            sink.push(ValidationError::InvalidGroupCount {
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
    let mut pending: Vec<ValidationError> = Vec::new();

    while let Some(field) = fields.get(cursor) {
        let tag = field.tag;
        if tag == group.delimiter_tag {
            let Some(next) = entries.checked_add(1) else {
                break;
            };
            // The delimiter closes the entry in progress, if any, and opens
            // the next one.
            if let Some(closed) = entries.checked_sub(1) {
                check_entry_required(group, closed, &seen_in_entry, &mut |error| {
                    sink.hold(&mut pending, error);
                });
            }
            entries = next;
            seen_in_entry.clear();
            seen_in_entry.insert(tag);
            // The delimiter is the entry's first field, and that field can
            // itself be the count tag of a nested group: FIX 5.0 SP2
            // NoAsgnReqs(1499) entries open with NoPartyIDs(453). The nested
            // group's members follow it, so it has to be walked from here,
            // not stepped over like a plain field. The delimiter is recorded
            // as seen above, so a required nested group that is the delimiter
            // counts as present in the entry it opens.
            cursor = match group.entry.groups.get(&tag) {
                Some(nested) => walk_group(tags, fields, cursor, nested, sink, &mut pending),
                None => cursor + 1,
            };
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
            sink.push(ValidationError::GroupDelimiterMismatch {
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
            sink.push(ValidationError::RepeatedTagInGroupEntry {
                count_tag: group.count_tag,
                group: group.name.clone(),
                tag,
                name: tags
                    .field(tag)
                    .map_or_else(String::new, |def| def.name.clone()),
            });
            unparseable = true;
        }
        cursor = match group.entry.groups.get(&tag) {
            // A nested group's per-entry errors join this group's pending
            // ones, so they are dropped too if this group is malformed. A
            // malformed nested group drops only its own.
            Some(nested) => walk_group(tags, fields, cursor, nested, sink, &mut pending),
            None => cursor + 1,
        };
    }

    // The run has ended: close the last entry, if one was opened.
    if let Some(closed) = entries.checked_sub(1) {
        check_entry_required(group, closed, &seen_in_entry, &mut |error| {
            sink.hold(&mut pending, error);
        });
    }

    if let Some(declared) = declared
        && !unparseable
        && declared != entries
    {
        sink.push(ValidationError::GroupCountMismatch {
            count_tag: group.count_tag,
            name: group.name.clone(),
            declared,
            actual: entries,
            delimiter_tag: group.delimiter_tag,
        });
    }

    if !unparseable && declared == Some(entries) {
        entry_errors.append(&mut pending);
    } else {
        sink.release(pending);
    }

    cursor
}

/// End-of-entry hook: reports, through `report`, the required members
/// missing from one closed entry of `group`.
///
/// `entry` is the closed entry's 0-based index and `seen` the tags that
/// appeared in it at its own level (a nested group's count tag included, its
/// members not). Reported, in this order: every required field of the entry
/// level in dictionary order (fields of the group itself and of components
/// referenced as required, each tag once, the delimiter excluded when the
/// scope was built), then every nested group marked required whose count tag
/// is absent, by ascending count tag.
///
/// [`walk_group`] calls this at every entry boundary. It is kept apart from
/// the walk, and reports through a callback rather than into a collector of
/// its own, so that another reader of group entries can apply the same check
/// at its own entry boundaries.
fn check_entry_required(
    group: &GroupNode,
    entry: u64,
    seen: &HashSet<u32>,
    report: &mut dyn FnMut(ValidationError),
) {
    let missing = |tag: u32, name: &str| ValidationError::MissingRequiredFieldInGroupEntry {
        count_tag: group.count_tag,
        group: group.name.clone(),
        entry,
        tag,
        name: name.to_string(),
    };

    for (tag, name) in &group.entry.required {
        if !seen.contains(tag) {
            report(missing(*tag, name));
        }
    }

    let mut absent: Vec<&GroupNode> = group
        .entry
        .groups
        .values()
        .filter(|nested| nested.required && !seen.contains(&nested.count_tag))
        .collect();
    absent.sort_by_key(|nested| nested.count_tag);
    for nested in absent {
        report(missing(nested.count_tag, &nested.name));
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

    #[track_caller]
    fn fix42() -> &'static Dictionary {
        ok(Dictionary::fix42(), "embedded FIX 4.2 dictionary loads")
    }

    #[track_caller]
    fn fixt11() -> &'static Dictionary {
        ok(Dictionary::fixt11(), "embedded FIXT 1.1 dictionary loads")
    }

    #[track_caller]
    fn fix50sp2() -> &'static Dictionary {
        ok(
            Dictionary::fix50sp2(),
            "embedded FIX 5.0 SP2 dictionary loads",
        )
    }

    /// The embedded FIXT 1.1 transport composed with FIX 5.0 SP2.
    #[track_caller]
    fn fixt11_fix50sp2() -> SessionDictionary<'static> {
        ok(
            SessionDictionary::new(fixt11(), fix50sp2()),
            "FIXT 1.1 + FIX 5.0 SP2 compose",
        )
    }

    /// Decodes a message built from `fields` and validates it with
    /// `validator`.
    #[track_caller]
    fn validate_using(
        validator: Validator<'_>,
        fields: &[&str],
    ) -> Result<(), Vec<ValidationError>> {
        let msg = build(fields);
        let mut decoder = Decoder::new(msg.as_bytes()).with_checksum_validation(false);
        let raw = ok(decoder.decode(), "test message decodes");
        validator.validate(&raw)
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
        validate_using(Validator::new(dict), fields)
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

    /// Expands every message `body` defines, with its header and trailer
    /// from `transport`, and asserts no expansion reaches a validator
    /// ceiling: a message whose own schema exhausted the depth or node
    /// budget would be reported as invalid on every occurrence.
    #[track_caller]
    fn assert_scope_expansion_fits(transport: &Dictionary, body: &Dictionary) {
        for msg_def in body.messages() {
            let (_, errors) = ScopeBuilder::expand(transport, body, msg_def);
            assert_eq!(
                errors,
                Vec::new(),
                "expanding {} ({}) exhausted a validator ceiling",
                msg_def.name,
                body.version
            );
        }
    }

    #[test]
    fn test_scope_expansion_fits_every_fix44_message() {
        assert_scope_expansion_fits(fix44(), fix44());
    }

    #[test]
    fn test_scope_expansion_fits_every_fix42_message() {
        assert_scope_expansion_fits(fix42(), fix42());
    }

    #[test]
    fn test_scope_expansion_fits_every_fixt11_message() {
        assert_scope_expansion_fits(fixt11(), fixt11());
    }

    #[test]
    fn test_scope_expansion_fits_every_fix50sp2_message_under_fixt11() {
        // The FIX 5.0 SP2 bodies are expanded with the FIXT 1.1 header and
        // trailer, exactly as `Validator::for_session` expands them.
        assert_scope_expansion_fits(fixt11(), fix50sp2());
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

    // --- FIX 4.2 -----------------------------------------------------------

    /// The FIX 4.2 standard header for a message of type `msg_type`.
    fn fix42_header(msg_type: &'static str) -> Vec<&'static str> {
        vec![
            "8=FIX.4.2",
            "9=100",
            msg_type,
            "49=SENDER",
            "56=TARGET",
            "34=1",
            "52=20260712-10:00:00",
        ]
    }

    #[test]
    fn test_validate_fix42_new_order_single_passes() {
        let mut fields = fix42_header("35=D");
        fields.extend([
            "11=ORDER-1",
            "21=1",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "38=100",
            "40=2",
            "44=1.2345",
            "10=000",
        ]);
        assert_eq!(validate_with(fix42(), &fields), Ok(()));
    }

    #[test]
    fn test_validate_fix42_new_order_single_missing_handl_inst_is_reported() {
        // HandlInst(21) is required in FIX 4.2 NewOrderSingle (it is not in
        // FIX 4.4), so the answer has to come from the FIX 4.2 dictionary.
        let mut fields = fix42_header("35=D");
        fields.extend([
            "11=ORDER-1",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
            "10=000",
        ]);
        let found = errors(validate_with(fix42(), &fields));
        assert_eq!(
            found,
            vec![ValidationError::MissingRequiredField {
                tag: 21,
                name: "HandlInst".to_string(),
            }]
        );
    }

    #[test]
    fn test_validate_fix42_execution_report_passes() {
        let mut fields = fix42_header("35=8");
        fields.extend([
            "37=ORDER-1",
            "17=EXEC-1",
            "20=0",
            "150=0",
            "39=0",
            "55=EURUSD",
            "54=1",
            "38=100",
            "151=100",
            "14=0",
            "6=0",
            "10=000",
        ]);
        assert_eq!(validate_with(fix42(), &fields), Ok(()));
    }

    #[test]
    fn test_validate_fix42_utcdate_field_is_checked_as_a_date() {
        // MDEntryDate(272) is declared `UTCDATE` in the FIX 4.2 dictionary,
        // loaded as UtcDateOnly: YYYYMMDD passes, an ISO date does not.
        let snapshot = |date: &'static str| {
            let mut fields = fix42_header("35=W");
            fields.extend(["55=EURUSD", "268=1", "269=0", "270=1.2345", date, "10=000"]);
            fields
        };
        assert_eq!(validate_with(fix42(), &snapshot("272=20260712")), Ok(()));
        let found = errors(validate_with(fix42(), &snapshot("272=2026-07-12")));
        assert_eq!(
            found,
            vec![ValidationError::InvalidFieldFormat {
                tag: 272,
                name: "MDEntryDate".to_string(),
                value: "2026-07-12".to_string(),
                field_type: FieldType::UtcDateOnly,
            }]
        );
    }

    // --- FIXT 1.1 + FIX 5.0 SP2 ----------------------------------------------

    /// The FIXT 1.1 standard header for a message of type `msg_type`.
    fn fixt11_header(msg_type: &'static str) -> Vec<&'static str> {
        vec![
            "8=FIXT.1.1",
            "9=100",
            msg_type,
            "49=SENDER",
            "56=TARGET",
            "34=1",
            "52=20260712-10:00:00.123456",
        ]
    }

    /// A FIX 5.0 SP2 NewOrderSingle carried in a FIXT 1.1 header.
    fn fix50sp2_new_order_single() -> Vec<&'static str> {
        let mut fields = fixt11_header("35=D");
        fields.extend([
            "1128=9",
            "11=ORDER-1",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00.123456",
            "38=100",
            "40=2",
            "44=1.2345",
            "10=000",
        ]);
        fields
    }

    /// Validates `fields` against the embedded FIXT 1.1 + FIX 5.0 SP2 pair.
    #[track_caller]
    fn validate_session(fields: &[&str]) -> Result<(), Vec<ValidationError>> {
        validate_using(Validator::for_session(&fixt11_fix50sp2()), fields)
    }

    #[test]
    fn test_validate_for_session_fixt_logon_with_default_appl_ver_id_passes() {
        let mut fields = fixt11_header("35=A");
        fields.extend(["98=0", "108=30", "1137=9", "10=000"]);
        assert_eq!(validate_session(&fields), Ok(()));
    }

    #[test]
    fn test_validate_for_session_fixt_logon_without_default_appl_ver_id_is_reported() {
        // DefaultApplVerID(1137) is required by the FIXT 1.1 Logon.
        let mut fields = fixt11_header("35=A");
        fields.extend(["98=0", "108=30", "10=000"]);
        let found = errors(validate_session(&fields));
        assert_eq!(
            found,
            vec![ValidationError::MissingRequiredField {
                tag: 1137,
                name: "DefaultApplVerID".to_string(),
            }]
        );
    }

    #[test]
    fn test_validate_for_session_logon_with_no_msg_types_follows_the_vendored_file() {
        // The vendored FIXT 1.1 file defines MsgTypeGrp with no members and
        // never defines NoMsgTypes(384). The dictionary answers, unpatched:
        // a Logon carrying the group is reported, member tags included.
        let mut fields = fixt11_header("35=A");
        fields.extend(["98=0", "108=30", "384=1", "372=D", "1137=9", "10=000"]);
        let found = errors(validate_session(&fields));
        assert_eq!(
            found,
            vec![
                ValidationError::UnknownTag { tag: 384 },
                ValidationError::FieldNotAllowedForMessage {
                    tag: 372,
                    msg_type: "A".to_string(),
                },
            ]
        );
    }

    #[test]
    fn test_validate_for_session_admin_message_resolves_against_the_transport_only() {
        // Heartbeat is a FIXT 1.1 admin message, so its body is answered by
        // FIXT 1.1: ClOrdID(11) exists only in FIX 5.0 SP2 and is unknown
        // here, even though the application dictionary defines it.
        let mut fields = fixt11_header("35=0");
        fields.push("10=000");
        assert_eq!(validate_session(&fields), Ok(()));

        let mut fields = fixt11_header("35=0");
        fields.extend(["11=ORDER-1", "10=000"]);
        let found = errors(validate_session(&fields));
        assert_eq!(found, vec![ValidationError::UnknownTag { tag: 11 }]);
    }

    #[test]
    fn test_validate_for_session_fix50sp2_new_order_single_passes() {
        // Header and trailer from FIXT 1.1, body from FIX 5.0 SP2.
        assert_eq!(validate_session(&fix50sp2_new_order_single()), Ok(()));
    }

    #[test]
    fn test_validate_for_session_missing_transport_header_field_is_reported() {
        // SendingTime(52) is required by the FIXT 1.1 header; FIX 5.0 SP2
        // has no header of its own to require it.
        let fields: Vec<&str> = fix50sp2_new_order_single()
            .into_iter()
            .filter(|field| !field.starts_with("52="))
            .collect();
        let found = errors(validate_session(&fields));
        assert_eq!(
            found,
            vec![ValidationError::MissingRequiredField {
                tag: 52,
                name: "SendingTime".to_string(),
            }]
        );
    }

    #[test]
    fn test_validate_for_session_missing_application_body_field_is_reported() {
        let fields: Vec<&str> = fix50sp2_new_order_single()
            .into_iter()
            .filter(|field| !field.starts_with("40="))
            .collect();
        let found = errors(validate_session(&fields));
        assert_eq!(
            found,
            vec![ValidationError::MissingRequiredField {
                tag: 40,
                name: "OrdType".to_string(),
            }]
        );
    }

    #[test]
    fn test_validate_for_session_unknown_application_msg_type_is_rejected() {
        let mut fields = fixt11_header("35=U9");
        fields.push("10=000");
        let found = errors(validate_session(&fields));
        assert_eq!(
            found,
            vec![ValidationError::UnknownMsgType {
                msg_type: "U9".to_string(),
            }]
        );
    }

    #[test]
    fn test_validate_fix50sp2_alone_flags_the_header_tags() {
        // FIX 5.0 SP2 has an empty header and trailer: on its own it cannot
        // place a single header tag, which is why it has to be composed.
        let found = errors(validate_with(fix50sp2(), &fix50sp2_new_order_single()));
        for tag in [8, 9, 35, 49, 56, 34, 52, 1128] {
            assert!(
                found.contains(&ValidationError::FieldNotAllowedForMessage {
                    tag,
                    msg_type: "D".to_string(),
                }),
                "header tag {tag} was not flagged: {found:?}"
            );
        }
    }

    /// Builds a hand-made transport/application pair in which tag 9000 is a
    /// header field typed INT by the transport and STRING by the application,
    /// and tag 9001 a body field typed STRING by the transport and INT by the
    /// application. Which dictionary answered is then visible in the result.
    fn dialects_with_conflicting_definitions() -> (Dictionary, Dictionary) {
        let field_ref = |tag: u32, name: &str, required: bool| SchemaFieldRef {
            tag,
            name: name.to_string(),
            required,
        };

        let mut transport = Dictionary::new(crate::schema::Version::Fixt11);
        for (tag, name, field_type) in [
            (8, "BeginString", FieldType::String),
            (9, "BodyLength", FieldType::Length),
            (10, "CheckSum", FieldType::String),
            (35, "MsgType", FieldType::String),
            (9000, "EnvelopeTag", FieldType::Int),
            (9001, "BodyTag", FieldType::String),
        ] {
            transport.add_field(FieldDef::new(tag, name, field_type));
        }
        transport.header = vec![
            field_ref(8, "BeginString", true),
            field_ref(9, "BodyLength", true),
            field_ref(35, "MsgType", true),
            field_ref(9000, "EnvelopeTag", false),
        ];
        transport.trailer = vec![field_ref(10, "CheckSum", true)];

        let mut application = Dictionary::new(crate::schema::Version::Fix50Sp2);
        for (tag, name, field_type) in [
            (9000, "EnvelopeTag", FieldType::String),
            (9001, "BodyTag", FieldType::Int),
        ] {
            application.add_field(FieldDef::new(tag, name, field_type));
        }
        application.add_message(MessageDef {
            msg_type: "U1".to_string(),
            name: "Probe".to_string(),
            category: MessageCategory::App,
            fields: vec![field_ref(9001, "BodyTag", false)],
            groups: Vec::new(),
            components: Vec::new(),
        });
        (transport, application)
    }

    #[test]
    fn test_validate_for_session_header_tag_resolves_against_the_transport() {
        let (transport, application) = dialects_with_conflicting_definitions();
        let session = ok(
            SessionDictionary::new(&transport, &application),
            "hand-built pair composes",
        );
        let found = errors(validate_using(
            Validator::for_session(&session),
            &["8=FIXT.1.1", "9=100", "35=U1", "9000=abc", "10=000"],
        ));
        assert_eq!(
            found,
            vec![ValidationError::InvalidFieldFormat {
                tag: 9000,
                name: "EnvelopeTag".to_string(),
                value: "abc".to_string(),
                field_type: FieldType::Int,
            }]
        );
    }

    #[test]
    fn test_validate_for_session_body_tag_resolves_against_the_application() {
        let (transport, application) = dialects_with_conflicting_definitions();
        let session = ok(
            SessionDictionary::new(&transport, &application),
            "hand-built pair composes",
        );
        let found = errors(validate_using(
            Validator::for_session(&session),
            &["8=FIXT.1.1", "9=100", "35=U1", "9001=abc", "10=000"],
        ));
        assert_eq!(
            found,
            vec![ValidationError::InvalidFieldFormat {
                tag: 9001,
                name: "BodyTag".to_string(),
                value: "abc".to_string(),
                field_type: FieldType::Int,
            }]
        );
    }

    // --- Review follow-ups: FIX 4.x over FIXT, BeginString, admin routing ---

    #[test]
    fn test_validate_for_session_fix44_new_order_single_over_fixt11_passes() {
        // FIXT.1.1 carries FIX 4.x application messages (ApplVerID 6 is FIX
        // 4.4): header and trailer from FIXT 1.1, body from FIX 4.4.
        let session = ok(
            SessionDictionary::new(fixt11(), fix44()),
            "FIXT 1.1 + FIX 4.4 compose",
        );
        let mut fields = fixt11_header("35=D");
        fields.extend([
            "1128=6",
            "11=ORDER-1",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
            "10=000",
        ]);
        assert_eq!(
            validate_using(Validator::for_session(&session), &fields),
            Ok(())
        );
    }

    #[test]
    fn test_validate_for_session_begin_string_mismatch_is_reported() {
        // FIX.5.0SP2 names the application version; on the wire tag 8 of a
        // FIXT.1.1 session is always FIXT.1.1.
        let fields: Vec<&str> = fix50sp2_new_order_single()
            .into_iter()
            .map(|field| {
                if field.starts_with("8=") {
                    "8=FIX.5.0SP2"
                } else {
                    field
                }
            })
            .collect();
        let found = errors(validate_session(&fields));
        assert_eq!(
            found,
            vec![ValidationError::BeginStringMismatch {
                expected: "FIXT.1.1".to_string(),
                found: "FIX.5.0SP2".to_string(),
            }]
        );
    }

    #[test]
    fn test_validate_for_session_begin_string_mismatch_is_reported_with_unknown_msg_type() {
        // Every error is returned: the mismatch is not lost behind an
        // unknown message type.
        let mut fields = fixt11_header("35=U9");
        if let Some(begin) = fields.first_mut() {
            *begin = "8=FIX.4.4";
        }
        fields.push("10=000");
        let found = errors(validate_session(&fields));
        assert_eq!(
            found,
            vec![
                ValidationError::BeginStringMismatch {
                    expected: "FIXT.1.1".to_string(),
                    found: "FIX.4.4".to_string(),
                },
                ValidationError::UnknownMsgType {
                    msg_type: "U9".to_string(),
                },
            ]
        );
    }

    #[test]
    fn test_validate_new_does_not_check_begin_string() {
        // Pins the documented gap of `Validator::new`: tag 8 is not compared
        // with the dictionary's version.
        let mut fields = with_header(&[
            "11=ORDER-1",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
        ]);
        if let Some(begin) = fields.first_mut() {
            *begin = "8=FIX.4.2";
        }
        assert_eq!(validate(&fields), Ok(()));
    }

    #[test]
    fn test_validate_for_session_routes_every_fixt11_admin_message_to_the_transport() {
        // Each admin message type with its minimal required body validates;
        // adding ClOrdID(11), which only FIX 5.0 SP2 defines, is UnknownTag,
        // proving the body was answered by FIXT 1.1 and not the application.
        let cases: [(&'static str, &[&'static str]); 8] = [
            ("35=0", &[]),
            ("35=1", &["112=TEST-1"]),
            ("35=2", &["7=1", "16=0"]),
            ("35=3", &["45=1"]),
            ("35=4", &["36=10"]),
            ("35=5", &[]),
            ("35=A", &["98=0", "108=30", "1137=9"]),
            ("35=n", &[]),
        ];
        for (msg_type, body) in cases {
            let mut fields = fixt11_header(msg_type);
            fields.extend_from_slice(body);
            let mut passing = fields.clone();
            passing.push("10=000");
            assert_eq!(validate_session(&passing), Ok(()), "{msg_type}");

            fields.extend(["11=ORDER-1", "10=000"]);
            assert_eq!(
                validate_session(&fields),
                Err(vec![ValidationError::UnknownTag { tag: 11 }]),
                "{msg_type} was not answered by the transport"
            );
        }
    }

    #[test]
    fn test_fixt11_admin_message_set_is_exactly_the_session_messages() {
        let admin: HashSet<&str> = fixt11()
            .messages()
            .filter(|def| def.category == MessageCategory::Admin)
            .map(|def| def.msg_type.as_str())
            .collect();
        let expected: HashSet<&str> = ["0", "1", "2", "3", "4", "5", "A", "n"]
            .into_iter()
            .collect();
        assert_eq!(admin, expected);
    }

    #[test]
    fn test_validate_for_session_application_message_with_signature_trailer_passes() {
        // SignatureLength(93) / Signature(89) are FIXT 1.1 trailer fields;
        // they resolve against the transport even on an application message.
        let fields: Vec<&str> = fix50sp2_new_order_single()
            .into_iter()
            .flat_map(|field| {
                if field.starts_with("10=") {
                    vec!["93=4", "89=abcd", field]
                } else {
                    vec![field]
                }
            })
            .collect();
        assert_eq!(validate_session(&fields), Ok(()));
    }

    #[test]
    fn test_validate_xml_non_fix_passes_standalone_and_for_session() {
        // XMLnonFIX (35=n) is a self-closing definition in both FIX44.xml and
        // FIXT11.xml; it must validate under either validator.
        let mut fix44_fields: Vec<&str> = HEADER.to_vec();
        if let Some(msg_type) = fix44_fields.get_mut(2) {
            *msg_type = "35=n";
        }
        fix44_fields.push("10=000");
        assert_eq!(validate(&fix44_fields), Ok(()));

        let mut session_fields = fixt11_header("35=n");
        session_fields.push("10=000");
        assert_eq!(validate_session(&session_fields), Ok(()));
    }

    #[test]
    fn test_validate_for_session_logon_accepts_any_default_appl_ver_id_value() {
        // Pins a documented gap: FIXT11.xml declares DefaultApplVerID(1137)
        // as a STRING with no enumeration, so a value that names no
        // application version is not rejected.
        let mut fields = fixt11_header("35=A");
        fields.extend(["98=0", "108=30", "1137=NOT-A-VERSION", "10=000"]);
        assert_eq!(validate_session(&fields), Ok(()));
    }

    #[test]
    fn test_validate_for_session_fixt11_defining_msg_type_grp_accepts_no_msg_types() {
        // The documented workaround for the upstream MsgTypeGrp deviation:
        // load a FIXT 1.1 dictionary that defines the group. The vendored
        // file is not touched; the variant is built in memory.
        let vendored = include_str!("../spec/FIXT11.xml");
        let empty_component = "<component name='MsgTypeGrp' />";
        let fields_end = " </fields>";
        assert_eq!(vendored.matches(empty_component).count(), 1);
        assert_eq!(vendored.matches(fields_end).count(), 1);
        let patched = vendored
            .replacen(
                empty_component,
                "<component name='MsgTypeGrp'>\
                 <group name='NoMsgTypes' required='N'>\
                 <field name='RefMsgType' required='N' />\
                 <field name='MsgDirection' required='N' />\
                 <field name='RefApplVerID' required='N' />\
                 <field name='RefApplExtID' required='N' />\
                 <field name='RefCstmApplVerID' required='N' />\
                 <field name='DefaultVerIndicator' required='N' />\
                 </group></component>",
                1,
            )
            .replacen(
                fields_end,
                "<field number='384' name='NoMsgTypes' type='NUMINGROUP' />\
                 <field number='385' name='MsgDirection' type='CHAR'>\
                 <value enum='R' description='RECEIVE' />\
                 <value enum='S' description='SEND' /></field>\
                 <field number='1410' name='DefaultVerIndicator' type='BOOLEAN' />\
                 </fields>",
                1,
            );
        let transport = ok(
            Dictionary::from_quickfix_xml(&patched),
            "FIXT 1.1 with MsgTypeGrp loads",
        );
        let session = ok(
            SessionDictionary::new(&transport, fix50sp2()),
            "patched FIXT 1.1 + FIX 5.0 SP2 compose",
        );
        let mut fields = fixt11_header("35=A");
        fields.extend([
            "98=0", "108=30", "384=2", "372=D", "385=S", "372=8", "385=R", "1137=9", "10=000",
        ]);
        assert_eq!(
            validate_using(Validator::for_session(&session), &fields),
            Ok(())
        );
    }

    // --- A group whose delimiter is a nested group's count tag ---------------

    /// A FIX 5.0 SP2 StreamAssignmentRequest (35=CC) under a FIXT 1.1 header.
    ///
    /// Its NoAsgnReqs(1499) entries open with the `Parties` component, whose
    /// first member is the NoPartyIDs(453) group, so the loader derives 453
    /// as the NoAsgnReqs delimiter: every entry starts with a nested group.
    fn stream_assignment_request<'a>(groups: &[&'a str]) -> Vec<&'a str> {
        let mut fields = fixt11_header("35=CC");
        fields.extend(["1128=9", "1497=REQ-1", "1498=1"]);
        fields.extend_from_slice(groups);
        fields.push("10=000");
        fields
    }

    #[test]
    fn test_fix50sp2_no_asgn_reqs_is_delimited_by_a_nested_group() {
        let session = fixt11_fix50sp2();
        let message = match session.application().get_message("CC") {
            Some(message) => message,
            None => panic!("StreamAssignmentRequest is defined"),
        };
        let component = match message.components.first() {
            Some(reference) => reference.name.as_str(),
            None => panic!("StreamAssignmentRequest references StrmAsgnReqGrp"),
        };
        let group = session
            .application()
            .get_component(component)
            .and_then(|def| def.groups.iter().find(|group| group.count_tag == 1499));
        match group {
            Some(group) => assert_eq!(group.delimiter_tag, 453),
            None => panic!("NoAsgnReqs(1499) is defined in {component}"),
        }
    }

    #[test]
    fn test_validate_for_session_group_led_by_a_nested_group_passes() {
        // Before the fix the delimiter 453 was stepped over like a plain
        // field, so the party fields fell outside the group and were
        // reported as not allowed for the message.
        let fields = stream_assignment_request(&["1499=1", "453=1", "448=P", "447=D", "452=1"]);
        assert_eq!(validate_session(&fields), Ok(()));
    }

    #[test]
    fn test_validate_for_session_group_led_by_a_nested_group_with_two_entries_passes() {
        let fields = stream_assignment_request(&[
            "1499=2", "453=1", "448=P1", "447=D", "452=1", "453=2", "448=P2", "447=D", "452=1",
            "448=P3", "447=D", "452=3",
        ]);
        assert_eq!(validate_session(&fields), Ok(()));
    }

    #[test]
    fn test_validate_for_session_nested_group_delimiter_count_mismatch_is_reported() {
        // `453=1` declares one party entry and none follows. Before the fix
        // the nested group was never walked, so the mismatch went unseen.
        let fields = stream_assignment_request(&["1499=1", "453=1"]);
        assert_eq!(
            validate_session(&fields),
            Err(vec![ValidationError::GroupCountMismatch {
                count_tag: 453,
                name: "NoPartyIDs".to_string(),
                declared: 1,
                actual: 0,
                delimiter_tag: 448,
            }])
        );
    }

    /// A minimal QuickFIX dialect whose groups are delimited by a nested
    /// group, directly (`U6`: NoOuter(100) opens with NoInner(110)) and
    /// through a component (`U7`: NoWrapped(120) opens with the component
    /// `Lead`, whose first member is NoInner(110)).
    const NESTED_DELIMITER_XML: &str = r"<fix type='FIX' major='4' minor='4'>
        <header>
            <field name='BeginString' required='Y'/>
            <field name='BodyLength' required='Y'/>
            <field name='MsgType' required='Y'/>
        </header>
        <trailer><field name='CheckSum' required='Y'/></trailer>
        <messages>
            <message name='Direct' msgtype='U6' msgcat='app'>
                <group name='NoOuter' required='N'>
                    <group name='NoInner' required='N'>
                        <field name='InnerKey' required='N'/>
                    </group>
                    <field name='OuterField' required='N'/>
                </group>
            </message>
            <message name='Wrapped' msgtype='U7' msgcat='app'>
                <group name='NoWrapped' required='N'>
                    <component name='Lead' required='N'/>
                    <field name='OuterField' required='N'/>
                </group>
            </message>
            <message name='Led' msgtype='U8' msgcat='app'>
                <group name='NoLed' required='N'>
                    <group name='NoLead' required='Y'>
                        <field name='LeadKey' required='Y'/>
                        <field name='LeadReq' required='Y'/>
                    </group>
                    <field name='LedReq' required='Y'/>
                </group>
            </message>
        </messages>
        <components>
            <component name='Lead'>
                <group name='NoInner' required='N'>
                    <field name='InnerKey' required='N'/>
                </group>
            </component>
        </components>
        <fields>
            <field number='8' name='BeginString' type='STRING'/>
            <field number='9' name='BodyLength' type='LENGTH'/>
            <field number='10' name='CheckSum' type='STRING'/>
            <field number='35' name='MsgType' type='STRING'/>
            <field number='100' name='NoOuter' type='NUMINGROUP'/>
            <field number='110' name='NoInner' type='NUMINGROUP'/>
            <field number='120' name='NoWrapped' type='NUMINGROUP'/>
            <field number='140' name='NoLed' type='NUMINGROUP'/>
            <field number='150' name='NoLead' type='NUMINGROUP'/>
            <field number='201' name='OuterField' type='STRING'/>
            <field number='210' name='InnerKey' type='STRING'/>
            <field number='250' name='LeadKey' type='STRING'/>
            <field number='251' name='LeadReq' type='STRING'/>
            <field number='252' name='LedReq' type='STRING'/>
        </fields>
    </fix>";

    /// Validates `body` as a message of type `msg_type` in the dialect.
    #[track_caller]
    fn validate_nested_delimiter(
        msg_type: &str,
        body: &[&str],
    ) -> Result<(), Vec<ValidationError>> {
        let dict = ok(
            Dictionary::from_quickfix_xml(NESTED_DELIMITER_XML),
            "nested-delimiter dialect loads",
        );
        let mut fields = vec!["8=FIX.4.4", "9=100", msg_type];
        fields.extend_from_slice(body);
        fields.push("10=000");
        validate_with(&dict, &fields)
    }

    #[test]
    fn test_nested_delimiter_dialect_derives_the_nested_count_tag_as_delimiter() {
        let dict = ok(
            Dictionary::from_quickfix_xml(NESTED_DELIMITER_XML),
            "nested-delimiter dialect loads",
        );
        for (msg_type, count_tag) in [("U6", 100), ("U7", 120)] {
            let group = dict
                .get_message(msg_type)
                .and_then(|message| message.groups.iter().find(|g| g.count_tag == count_tag));
            match group {
                Some(group) => assert_eq!(group.delimiter_tag, 110, "{msg_type}"),
                None => panic!("{msg_type} carries group {count_tag}"),
            }
        }
    }

    #[test]
    fn test_validate_group_led_by_a_nested_group_passes() {
        for (msg_type, count) in [("35=U6", "100=2"), ("35=U7", "120=2")] {
            assert_eq!(
                validate_nested_delimiter(
                    msg_type,
                    &[count, "110=1", "210=a", "201=x", "110=2", "210=b", "210=c"],
                ),
                Ok(()),
                "{msg_type}"
            );
        }
    }

    #[test]
    fn test_validate_group_led_by_a_nested_group_reports_the_nested_mismatch() {
        // The outer entry is sound; the nested NoInner(110) declares two
        // entries and carries one.
        for (msg_type, count) in [("35=U6", "100=1"), ("35=U7", "120=1")] {
            assert_eq!(
                validate_nested_delimiter(msg_type, &[count, "110=2", "210=a", "201=x"]),
                Err(vec![ValidationError::GroupCountMismatch {
                    count_tag: 110,
                    name: "NoInner".to_string(),
                    declared: 2,
                    actual: 1,
                    delimiter_tag: 210,
                }]),
                "{msg_type}"
            );
        }
    }

    #[test]
    fn test_validate_group_led_by_a_nested_group_counts_its_own_entries() {
        // Two outer entries declared, one present: the nested group's fields
        // are inside the single entry, not extra outer entries.
        assert_eq!(
            validate_nested_delimiter("35=U6", &["100=2", "110=2", "210=a", "210=b"]),
            Err(vec![ValidationError::GroupCountMismatch {
                count_tag: 100,
                name: "NoOuter".to_string(),
                declared: 2,
                actual: 1,
                delimiter_tag: 110,
            }])
        );
    }

    // --- Required members of each group entry (#74) ------------------------

    /// A FIX 4.4 message of type `msg_type` with the standard header.
    fn fix44_message<'a>(msg_type: &'a str, body: &[&'a str]) -> Vec<&'a str> {
        let mut fields: Vec<&str> = HEADER.to_vec();
        if let Some(slot) = fields.get_mut(2) {
            *slot = msg_type;
        }
        fields.extend_from_slice(body);
        fields.push("10=000");
        fields
    }

    /// The missing-member error for entry `entry` of FIX 4.4 NoOrders(73).
    fn no_orders_missing(entry: u64, tag: u32, name: &str) -> ValidationError {
        ValidationError::MissingRequiredFieldInGroupEntry {
            count_tag: 73,
            group: "NoOrders".to_string(),
            entry,
            tag,
            name: name.to_string(),
        }
    }

    // The issue suggests NewOrderSingle with NoPartyIDs missing PartyID, but
    // no NoPartyIDs entry can fail this check, for two reasons. Every member
    // of NoPartyIDs is optional in the vendored FIX44.xml (`Parties`, lines
    // 2508-2514). And PartyID(448) is the group's delimiter: an entry without
    // it is a GroupDelimiterMismatch, and the delimiter is never reported
    // missing. NewOrderList (35=E) is the real case: its NoOrders(73) entries
    // (`ListOrdGrp`, FIX44.xml lines 2943-2981) require ClOrdID(11), which is
    // also the delimiter, ListSeqNo(67) and Side(54).

    #[test]
    fn test_validate_group_entries_with_their_required_fields_pass() {
        let fields = fix44_message(
            "35=E",
            &[
                "66=LIST-1",
                "394=1",
                "68=2",
                "73=2",
                "11=ORDER-1",
                "67=1",
                "55=EURUSD",
                "54=1",
                "11=ORDER-2",
                "67=2",
                "55=GBPUSD",
                "54=2",
            ],
        );
        assert_eq!(validate(&fields), Ok(()));
    }

    #[test]
    fn test_validate_group_entry_missing_required_field_reports_its_entry_index() {
        // The second entry (0-based index 1) lacks ListSeqNo(67).
        let fields = fix44_message(
            "35=E",
            &[
                "66=LIST-1",
                "394=1",
                "68=2",
                "73=2",
                "11=ORDER-1",
                "67=1",
                "55=EURUSD",
                "54=1",
                "11=ORDER-2",
                "55=GBPUSD",
                "54=2",
            ],
        );
        assert_eq!(
            validate(&fields),
            Err(vec![no_orders_missing(1, 67, "ListSeqNo")])
        );
    }

    #[test]
    fn test_validate_group_entries_missing_required_fields_are_each_reported() {
        // Entry 0 lacks Side(54), entry 1 lacks ListSeqNo(67).
        let fields = fix44_message(
            "35=E",
            &[
                "66=LIST-1",
                "394=1",
                "68=2",
                "73=2",
                "11=ORDER-1",
                "67=1",
                "55=EURUSD",
                "11=ORDER-2",
                "55=GBPUSD",
                "54=2",
            ],
        );
        assert_eq!(
            validate(&fields),
            Err(vec![
                no_orders_missing(0, 54, "Side"),
                no_orders_missing(1, 67, "ListSeqNo"),
            ])
        );
    }

    #[test]
    fn test_validate_group_count_zero_runs_no_entry_checks() {
        let fields = fix44_message("35=E", &["66=LIST-1", "394=1", "68=0", "73=0"]);
        assert_eq!(validate(&fields), Ok(()));
    }

    #[test]
    fn test_validate_malformed_group_delimiter_mismatch_raises_no_entry_errors() {
        // The entry opens with ListSeqNo(67) instead of the delimiter
        // ClOrdID(11). The group is malformed, so the absent delimiter is not
        // also reported as a missing required member.
        let fields = fix44_message(
            "35=E",
            &[
                "66=LIST-1",
                "394=1",
                "68=1",
                "73=1",
                "67=1",
                "55=EURUSD",
                "54=1",
            ],
        );
        assert_eq!(
            validate(&fields),
            Err(vec![ValidationError::GroupDelimiterMismatch {
                count_tag: 73,
                name: "NoOrders".to_string(),
                expected: 11,
                found: 67,
            }])
        );
    }

    #[test]
    fn test_validate_malformed_group_count_mismatch_raises_no_entry_errors() {
        // Three entries declared, two present, and the second lacks 67: only
        // the count mismatch is reported.
        let fields = fix44_message(
            "35=E",
            &[
                "66=LIST-1",
                "394=1",
                "68=3",
                "73=3",
                "11=ORDER-1",
                "67=1",
                "55=EURUSD",
                "54=1",
                "11=ORDER-2",
                "55=GBPUSD",
                "54=2",
            ],
        );
        assert_eq!(
            validate(&fields),
            Err(vec![ValidationError::GroupCountMismatch {
                count_tag: 73,
                name: "NoOrders".to_string(),
                declared: 3,
                actual: 2,
                delimiter_tag: 11,
            }])
        );
    }

    #[test]
    fn test_validate_huge_group_count_allocates_nothing_sized_from_it() {
        // Entries are counted as they are found; nothing is pre-sized from
        // the declared count. An allocation sized from these counts would
        // abort the test process (out of memory or capacity overflow) rather
        // than return the mismatch.
        for (count, declared) in [
            ("453=99999999999", 99_999_999_999_u64),
            ("453=18446744073709551615", u64::MAX),
        ] {
            let found = errors(validate(&with_header(&[
                "11=ORDER-1",
                count,
                "448=BROKER-A",
                "55=EURUSD",
                "54=1",
                "60=20260712-10:00:00",
                "40=1",
            ])));
            assert_eq!(
                found,
                vec![ValidationError::GroupCountMismatch {
                    count_tag: 453,
                    name: "NoPartyIDs".to_string(),
                    declared,
                    actual: 1,
                    delimiter_tag: 448,
                }]
            );
        }
    }

    #[test]
    fn test_validate_for_session_group_entry_missing_required_field_is_reported() {
        // FIX 5.0 SP2 NoOrders entries require ListSeqNo(67) as well; the
        // body is answered by FIX 5.0 SP2 under a FIXT 1.1 header. NoOrders
        // is required='N' in FIX50SP2.xml, so QuickFIX, which enforces entry
        // fields only for a required group, would not raise this; IronFix
        // applies the FIX rule (a required member is required in every entry
        // of a present group).
        let mut fields = fixt11_header("35=E");
        fields.extend([
            "1128=9",
            "66=LIST-1",
            "394=1",
            "68=1",
            "73=1",
            "11=ORDER-1",
            "55=EURUSD",
            "54=1",
            "10=000",
        ]);
        assert_eq!(
            validate_session(&fields),
            Err(vec![no_orders_missing(0, 67, "ListSeqNo")])
        );

        let mut valid = fixt11_header("35=E");
        valid.extend([
            "1128=9",
            "66=LIST-1",
            "394=1",
            "68=1",
            "73=1",
            "11=ORDER-1",
            "67=1",
            "55=EURUSD",
            "54=1",
            "10=000",
        ]);
        assert_eq!(validate_session(&valid), Ok(()));
    }

    /// A hand-built dialect for the per-entry rules FIX 4.4 has no real case
    /// for. Message `U5` carries the optional group NoOuter(100), delimited by
    /// OuterKey(200). Each entry requires:
    ///
    /// - OuterReq(201) directly, and again through `ReqBlock` (so it must be
    ///   reported once);
    /// - ReqField(300), through the component `ReqBlock`, referenced as
    ///   required;
    /// - the nested group NoReqNested(120), delimited by NestedKey(220),
    ///   itself marked required.
    ///
    /// It may also carry the component `OptBlock`, referenced as optional,
    /// whose OptReq(301) and nested group NoOptNested(130) (delimited by
    /// OptNestedKey(230)) are required inside it and OptOther(302) is not,
    /// and the optional nested group NoInner(110), delimited by InnerKey(210),
    /// whose entries require InnerReq(211).
    fn dialect_with_group_entry_rules() -> Dictionary {
        let mut dict = dialect_with_optional_component();
        for (tag, name, field_type) in [
            (100, "NoOuter", FieldType::NumInGroup),
            (110, "NoInner", FieldType::NumInGroup),
            (120, "NoReqNested", FieldType::NumInGroup),
            (130, "NoOptNested", FieldType::NumInGroup),
            (200, "OuterKey", FieldType::String),
            (201, "OuterReq", FieldType::String),
            (210, "InnerKey", FieldType::String),
            (211, "InnerReq", FieldType::String),
            (220, "NestedKey", FieldType::String),
            (230, "OptNestedKey", FieldType::String),
            (300, "ReqField", FieldType::String),
            (301, "OptReq", FieldType::String),
            (302, "OptOther", FieldType::String),
        ] {
            dict.add_field(FieldDef::new(tag, name, field_type));
        }
        let field_ref = |tag: u32, name: &str, required: bool| SchemaFieldRef {
            tag,
            name: name.to_string(),
            required,
        };
        dict.add_component(ComponentDef {
            name: "ReqBlock".to_string(),
            fields: vec![
                field_ref(300, "ReqField", true),
                field_ref(201, "OuterReq", true),
            ],
            groups: Vec::new(),
            components: Vec::new(),
        });
        dict.add_component(ComponentDef {
            name: "OptBlock".to_string(),
            fields: vec![
                field_ref(301, "OptReq", true),
                field_ref(302, "OptOther", false),
            ],
            groups: vec![GroupDef {
                count_tag: 130,
                name: "NoOptNested".to_string(),
                delimiter_tag: 230,
                fields: vec![field_ref(230, "OptNestedKey", true)],
                groups: Vec::new(),
                components: Vec::new(),
                required: true,
            }],
            components: Vec::new(),
        });
        let inner = GroupDef {
            count_tag: 110,
            name: "NoInner".to_string(),
            delimiter_tag: 210,
            fields: vec![
                field_ref(210, "InnerKey", true),
                field_ref(211, "InnerReq", true),
            ],
            groups: Vec::new(),
            components: Vec::new(),
            required: false,
        };
        let req_nested = GroupDef {
            count_tag: 120,
            name: "NoReqNested".to_string(),
            delimiter_tag: 220,
            fields: vec![field_ref(220, "NestedKey", true)],
            groups: Vec::new(),
            components: Vec::new(),
            required: true,
        };
        let outer = GroupDef {
            count_tag: 100,
            name: "NoOuter".to_string(),
            delimiter_tag: 200,
            fields: vec![
                field_ref(200, "OuterKey", true),
                field_ref(201, "OuterReq", true),
            ],
            groups: vec![inner, req_nested],
            components: vec![
                ComponentRef::new("ReqBlock", true),
                ComponentRef::new("OptBlock", false),
            ],
            required: false,
        };
        dict.add_message(MessageDef {
            msg_type: "U5".to_string(),
            name: "Groups".to_string(),
            category: MessageCategory::App,
            fields: Vec::new(),
            groups: vec![outer],
            components: Vec::new(),
        });
        dict
    }

    /// Validates a `U5` message whose body is `body` against the dialect.
    #[track_caller]
    fn validate_u5(body: &[&str]) -> Result<(), Vec<ValidationError>> {
        let mut fields = vec![
            "8=FIX.4.4",
            "9=100",
            "35=U5",
            "49=SENDER",
            "56=TARGET",
            "34=1",
        ];
        fields.extend_from_slice(body);
        fields.push("10=000");
        validate_with(&dialect_with_group_entry_rules(), &fields)
    }

    /// The missing-member error for entry `entry` of `group(count_tag)`.
    fn entry_missing(
        count_tag: u32,
        group: &str,
        entry: u64,
        tag: u32,
        name: &str,
    ) -> ValidationError {
        ValidationError::MissingRequiredFieldInGroupEntry {
            count_tag,
            group: group.to_string(),
            entry,
            tag,
            name: name.to_string(),
        }
    }

    #[test]
    fn test_validate_dialect_group_entry_with_every_required_member_passes() {
        assert_eq!(
            validate_u5(&["100=1", "200=A", "201=x", "300=y", "120=1", "220=k"]),
            Ok(())
        );
    }

    #[test]
    fn test_validate_group_entry_required_component_is_enforced() {
        // ReqBlock is referenced as required, so its ReqField(300) is.
        assert_eq!(
            validate_u5(&["100=1", "200=A", "201=x", "120=1", "220=k"]),
            Err(vec![entry_missing(100, "NoOuter", 0, 300, "ReqField")])
        );
    }

    #[test]
    fn test_validate_group_entry_optional_component_is_not_enforced() {
        // OptBlock is referenced as optional: its OptReq(301) is not
        // required, whether OptBlock is absent or partly present (OptOther
        // without OptReq). QuickFIX does not enforce it either.
        assert_eq!(
            validate_u5(&["100=1", "200=A", "201=x", "300=y", "120=1", "220=k"]),
            Ok(())
        );
        assert_eq!(
            validate_u5(&[
                "100=1", "200=A", "201=x", "300=y", "302=z", "120=1", "220=k"
            ]),
            Ok(())
        );
    }

    #[test]
    fn test_validate_nested_group_entry_missing_required_field_reports_the_nested_group() {
        // NoInner's second entry (index 1) lacks InnerReq(211); the error
        // names the nested group and its own entry index.
        assert_eq!(
            validate_u5(&[
                "100=1", "200=A", "201=x", "300=y", "110=2", "210=a", "211=b", "210=c", "120=1",
                "220=k",
            ]),
            Err(vec![entry_missing(110, "NoInner", 1, 211, "InnerReq")])
        );
    }

    #[test]
    fn test_validate_group_entry_missing_required_nested_group_is_reported() {
        // The first outer entry has NoReqNested(120); the second does not.
        assert_eq!(
            validate_u5(&[
                "100=2", "200=A", "201=x", "300=y", "120=1", "220=k", "200=B", "201=x", "300=y",
            ]),
            Err(vec![entry_missing(100, "NoOuter", 1, 120, "NoReqNested")])
        );
    }

    #[test]
    fn test_validate_malformed_outer_group_suppresses_nested_entry_errors() {
        // The outer count says 2 but one entry follows, and its nested
        // NoInner entry lacks InnerReq(211): only the outer mismatch is
        // reported, because the outer entry boundaries cannot be trusted.
        assert_eq!(
            validate_u5(&[
                "100=2", "200=A", "201=x", "300=y", "110=1", "210=a", "120=1", "220=k",
            ]),
            Err(vec![ValidationError::GroupCountMismatch {
                count_tag: 100,
                name: "NoOuter".to_string(),
                declared: 2,
                actual: 1,
                delimiter_tag: 200,
            }])
        );
    }

    #[test]
    fn test_validate_repeated_tag_in_group_entry_raises_no_entry_errors() {
        // OuterReq(201) appears twice in one entry and ReqField(300) is
        // missing: the repeat makes the group unparseable, so the missing
        // member is not reported on top of it.
        assert_eq!(
            validate_u5(&["100=1", "200=A", "201=x", "201=x", "120=1", "220=k"]),
            Err(vec![ValidationError::RepeatedTagInGroupEntry {
                count_tag: 100,
                group: "NoOuter".to_string(),
                tag: 201,
                name: "OuterReq".to_string(),
            }])
        );
    }

    // --- Review follow-ups for #74 -------------------------------------------

    #[test]
    fn test_validate_required_nested_group_in_optional_component_is_not_reported() {
        // NoOptNested(130) is required inside OptBlock, but OptBlock is
        // referenced as optional, so the entry does not need it.
        assert_eq!(
            validate_u5(&[
                "100=1", "200=A", "201=x", "300=y", "301=o", "120=1", "220=k"
            ]),
            Ok(())
        );
    }

    #[test]
    fn test_validate_malformed_nested_group_keeps_its_enclosing_entry_errors() {
        // NoInner(110) declares two entries and carries one, a structural
        // error of its own; the enclosing NoOuter entry, which lacks
        // ReqField(300), is still checked and reported.
        assert_eq!(
            validate_u5(&[
                "100=1", "200=A", "201=x", "110=2", "210=a", "211=b", "120=1", "220=k",
            ]),
            Err(vec![
                ValidationError::GroupCountMismatch {
                    count_tag: 110,
                    name: "NoInner".to_string(),
                    declared: 2,
                    actual: 1,
                    delimiter_tag: 210,
                },
                entry_missing(100, "NoOuter", 0, 300, "ReqField"),
            ])
        );
    }

    #[test]
    fn test_validate_tag_required_directly_and_through_a_component_is_reported_once() {
        // OuterReq(201) is required by NoOuter itself and again by ReqBlock;
        // an entry lacking it reports it once, in dictionary order before
        // ReqField(300).
        assert_eq!(
            validate_u5(&["100=1", "200=A", "120=1", "220=k"]),
            Err(vec![
                entry_missing(100, "NoOuter", 0, 201, "OuterReq"),
                entry_missing(100, "NoOuter", 0, 300, "ReqField"),
            ])
        );
    }

    #[test]
    fn test_validate_required_nested_group_that_is_the_delimiter_counts_as_present() {
        // NoLed(140) entries open with the required nested group NoLead(150),
        // so 150 is NoLed's delimiter. It is never reported missing, and the
        // nested entries are still checked: a nested entry's error comes
        // before its enclosing entry's (entries are reported as they close).
        assert_eq!(
            validate_nested_delimiter("35=U8", &["140=1", "150=1", "250=a", "251=b", "252=c"]),
            Ok(())
        );
        assert_eq!(
            validate_nested_delimiter(
                "35=U8",
                &[
                    "140=2", "150=1", "250=a", "251=b", "252=c", "150=1", "250=d"
                ],
            ),
            Err(vec![
                ValidationError::MissingRequiredFieldInGroupEntry {
                    count_tag: 150,
                    group: "NoLead".to_string(),
                    entry: 0,
                    tag: 251,
                    name: "LeadReq".to_string(),
                },
                ValidationError::MissingRequiredFieldInGroupEntry {
                    count_tag: 140,
                    group: "NoLed".to_string(),
                    entry: 1,
                    tag: 252,
                    name: "LedReq".to_string(),
                },
            ])
        );
    }

    #[test]
    fn test_validate_hostile_list_status_stops_at_the_error_limit() {
        // A ListStatus (35=N) of 200,000 NoOrders(73) entries carrying only
        // the delimiter ClOrdID(11), about 1 MB: the default FixCodec frame
        // limit. Each entry lacks five required members (14, 39, 151, 84, 6),
        // a million errors uncapped; the report stops at the limit.
        let mut body: Vec<&str> = vec![
            "66=LIST-1",
            "429=1",
            "82=1",
            "431=1",
            "83=1",
            "68=200000",
            "73=200000",
        ];
        body.extend(std::iter::repeat_n("11=a", 200_000));
        let found = errors(validate(&fix44_message("35=N", &body)));

        assert_eq!(found.len(), MAX_VALIDATION_ERRORS + 1);
        assert_eq!(
            found.last(),
            Some(&ValidationError::ErrorLimitReached {
                limit: MAX_VALIDATION_ERRORS,
            })
        );
        assert_eq!(found.first(), Some(&no_orders_missing(0, 14, "CumQty")));
        assert!(
            found
                .iter()
                .take(MAX_VALIDATION_ERRORS)
                .all(|error| matches!(
                    error,
                    ValidationError::MissingRequiredFieldInGroupEntry { count_tag: 73, .. }
                ))
        );
    }

    #[test]
    fn test_validate_below_the_error_limit_reports_no_limit_marker() {
        // Twenty entries, five missing members each: well under the limit.
        let mut body: Vec<&str> = vec![
            "66=LIST-1",
            "429=1",
            "82=1",
            "431=1",
            "83=1",
            "68=20",
            "73=20",
        ];
        body.extend(std::iter::repeat_n("11=a", 20));
        let found = errors(validate(&fix44_message("35=N", &body)));
        assert_eq!(found.len(), 100);
        assert!(
            !found
                .iter()
                .any(|error| matches!(error, ValidationError::ErrorLimitReached { .. }))
        );
    }
}
