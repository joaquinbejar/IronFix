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
//! - a field both dictionaries enumerate admits the values of either: the
//!   union of the two enumerations. A FIXT.1.1 transport may list only the
//!   session message types for `MsgType(35)` and `RefMsgType(372)` (the FIX
//!   Orchestra FIXT repository does), and the application's message types
//!   are still valid there. The field's type and form come from the
//!   dictionary that answers the tag, as above.
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
//! - **Missing tags are not reported lowest first.** QuickFIX reports the
//!   lowest missing tag number first. This validator reports missing fields
//!   in the order its expanded schema lists them, and missing groups by
//!   ascending count tag after every missing field (see "Error order" below).
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
//! One boundary is settled by the enclosing scope. Once a group holds every
//! entry its count declares (at once, for a count of `0`), a field that would
//! open another entry, or lead one without its delimiter, ends the group if
//! the enclosing scope (the entry the group is nested in, or the message
//! level) also accepts that tag: `110=0|300=X`, where `300` is a member of
//! both the nested group and the enclosing entry, is an empty group followed
//! by the enclosing entry's `300`. A field only the group accepts still opens
//! an entry, so a group with more entries than it declares is still a
//! [`ValidationError::GroupCountMismatch`].
//!
//! The walk is the one the repeating-group reader ([`crate::group`]) uses,
//! so the two agree on entry boundaries and on which group instances are
//! malformed. A count must be one or more ASCII digits fitting in a `u64`:
//! a sign (`+1` included, which [`str::parse`] would accept), a decimal point
//! or an overflowing value is [`ValidationError::InvalidGroupCount`].
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
//! Order of per-entry errors. Within an entry: first the group's own required
//! fields, in declaration order; then the required members contributed by
//! components referenced as required, component by component in declaration
//! order (a component's own fields, then the components it references, depth
//! first); then missing required nested groups by ascending count tag. Each
//! tag is reported once, at its first position. A field declared *after* a
//! component is therefore reported before that component's members:
//! [`GroupDef`](crate::schema::GroupDef) keeps a group's fields, groups and
//! components in separate lists, so their interleaving in the XML is not
//! available to the validator. Across entries, errors come in the order
//! entries close, so a nested group's entries come before the entry that
//! encloses them.
//!
//! # Error order
//!
//! [`Validator::validate`] reports errors in a fixed order, the same on every
//! run and for every load of the same dictionary, under [`Validator::new`] and
//! [`Validator::for_session`] alike:
//!
//! 1. [`ValidationError::BeginStringMismatch`] (for a session only).
//! 2. [`ValidationError::UnknownMsgType`], after which nothing else is checked.
//! 3. Schema errors of the message's expanded schema
//!    ([`ValidationError::SchemaTooDeep`], [`ValidationError::SchemaTooLarge`],
//!    [`ValidationError::UnknownComponent`]), in expansion order.
//! 4. Value errors ([`ValidationError::UnknownTag`],
//!    [`ValidationError::InvalidFieldFormat`],
//!    [`ValidationError::InvalidEnumValue`]), at most one per field, in wire
//!    order.
//! 5. Structural errors, in the order a single walk over the message meets
//!    them: [`ValidationError::DuplicateTag`] and
//!    [`ValidationError::FieldNotAllowedForMessage`] at the message level,
//!    and for each group instance its count, delimiter and repeated-tag
//!    errors as they appear, with its count mismatch when the instance ends
//!    (a nested group's before its enclosing group's).
//! 6. Per-entry errors ([`ValidationError::MissingRequiredFieldInGroupEntry`])
//!    of the well-formed group instances, in the order above.
//! 7. [`ValidationError::MissingRequiredField`] in schema order: header
//!    fields, trailer fields, the message's own fields, then the members of
//!    required components, depth first, each in declaration order.
//! 8. [`ValidationError::MissingRequiredGroup`] by ascending count tag.
//! 9. [`ValidationError::ErrorLimitReached`], last, when the output was
//!    capped.
//!
//! **Behaviour change.** Before per-entry checking existed, a message whose
//! group entries lacked required members validated; it is now rejected, so
//! validation is stricter than it was, and stricter than QuickFIX: a message
//! a QuickFIX counterparty accepts can be rejected here (see "Differences
//! from QuickFIX").
//!
//! # Bounded output
//!
//! A single call returns at most [`MAX_VALIDATION_ERRORS`] errors. When the
//! limit is reached, collection stops and a final
//! [`ValidationError::ErrorLimitReached`] is appended, so a hostile message
//! cannot turn validation into an allocation proportional to its size.
//!
//! Per-entry errors are provisional until their group is known to be
//! well-formed, and they never take room from the result while provisional.
//! A structural error that replaces them (a count or delimiter mismatch) is
//! therefore always recorded while the result has room: a group whose
//! provisional per-entry errors alone would exceed the limit, and which then
//! turns out malformed, reports its structural error and no limit marker.
//!
//! Notes:
//! - `CheckSum(10)` presence is not re-checked: the tag-value decoder
//!   already consumes and verifies it, so it never appears among the
//!   parsed fields.
//! - The validator is opt-in. The codec never invokes it; `ironfix-engine`
//!   invokes it on inbound application messages only when a session is
//!   given one through `InboundValidation` with a policy other than `Off`
//!   (issue #84, ADR-0031). [`Validator`], [`Dictionary`] and
//!   [`SessionDictionary`] implement [`InboundValidator`] for that, and
//!   [`ValidationError::inbound_rejection`] maps an error to the
//!   `SessionRejectReason` (373) the engine answers with.

use crate::composition::SessionDictionary;
use crate::group::GroupSpec;
use crate::schema::{Dictionary, FieldDef, FieldType, MessageCategory, MessageDef};
use crate::scope::{LayoutGroup, Scope, ScopeBuilder};
use crate::walk::{self, EntryTags};
use ironfix_core::message::RawMessage;
use ironfix_core::validation::{InboundDefect, InboundRejection, InboundValidator};
use std::collections::HashSet;

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

/// Answers which [`FieldDef`] a tag of the message being validated has.
///
/// Envelope tags (the header and trailer of the transport dictionary)
/// resolve against `transport`; every other tag against `body`, the
/// dictionary that defines the message type.
struct TagResolver<'d, 's> {
    transport: &'d Dictionary,
    body: &'d Dictionary,
    /// The application dictionary of a composed session; the same
    /// dictionary as `transport` for a validator built with
    /// [`Validator::new`].
    application: &'d Dictionary,
    /// Sorted and unique.
    envelope: &'s [u32],
}

impl<'d> TagResolver<'d, '_> {
    /// Returns the definition of `tag`, or `None` if the dictionary that
    /// answers it does not define it.
    fn field(&self, tag: u32) -> Option<&'d FieldDef> {
        if self.envelope.binary_search(&tag).is_ok() {
            self.transport.get_field(tag)
        } else {
            self.body.get_field(tag)
        }
    }

    /// Whether `value` is in the enumeration of `tag` as the other side of
    /// a composed session defines it: the application dictionary for a
    /// field the transport answers, and the transport dictionary for one
    /// the application answers. Under composition a field both sides
    /// enumerate takes the union of the two enumerations, so a transport
    /// that lists only the session message types for `MsgType(35)` still
    /// admits the application's. Always `false` with a single dictionary.
    fn other_side_admits(&self, tag: u32, answered: &FieldDef, value: &str) -> bool {
        if std::ptr::eq(self.transport, self.application) {
            return false;
        }
        let other = match self.transport.get_field(tag) {
            Some(transport) if std::ptr::eq(transport, answered) => self.application,
            _ => self.transport,
        };
        other
            .get_field(tag)
            .and_then(|def| def.values.as_ref())
            .is_some_and(|values| values.contains_key(value))
    }
}

/// Resolves a message type to its definition and to the dictionary that
/// answers its body.
///
/// An admin message the transport dictionary defines wins; otherwise the
/// application dictionary must define the message type. With a single
/// dictionary, pass it as both.
pub(crate) fn resolve<'d>(
    transport: &'d Dictionary,
    application: &'d Dictionary,
    msg_type: &str,
) -> Option<(&'d MessageDef, &'d Dictionary)> {
    if let Some(def) = transport.get_message(msg_type)
        && def.category == MessageCategory::Admin
    {
        return Some((def, transport));
    }
    application
        .get_message(msg_type)
        .map(|def| (def, application))
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
    ///   [`ValidationError::UnknownTag`], which
    ///   [`ValidationError::inbound_rejection`] maps to
    ///   `SessionRejectReason(373)=0` (invalid tag number), following
    ///   QuickFIX/J, although `2` (tag not defined for this message type)
    ///   would describe it better.
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

    /// Builds the group layout this validator would walk `msg_type` with.
    #[cfg(test)]
    pub(crate) fn layout(
        &self,
        msg_type: &str,
    ) -> Result<crate::group::MessageLayout, crate::group::GroupError> {
        crate::group::MessageLayout::resolved(self.transport, self.application, msg_type)
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
        let fields = msg.field_slice();
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
        let Some((msg_def, body)) = resolve(self.transport, self.application, &msg_type) else {
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
            application: self.application,
            envelope: &envelope,
        };

        // Value-level checks apply wherever a field sits.
        for field in fields {
            check_value(&tags, field, &mut sink);
        }

        // Structural walk over the message level. Per-entry errors of every
        // well-formed group instance stay provisional in `checks.accepted`
        // until the walk ends, and then follow the structural ones.
        let mut checks = Checks {
            tags: &tags,
            sink,
            stack: Vec::new(),
            accepted: Pending::default(),
        };
        let mut seen: HashSet<u32> = HashSet::new();
        let mut index = 0;
        while let Some(field) = fields.get(index) {
            let tag = field.tag;
            let Some(def) = tags.field(tag) else {
                // Already reported as UnknownTag by the value pass.
                index += 1;
                continue;
            };
            if !seen.insert(tag) {
                checks.sink.push(ValidationError::DuplicateTag {
                    tag,
                    name: def.name.clone(),
                });
            }
            if let Some(group) = level.group(tag) {
                index = walk::walk_group(
                    fields,
                    index,
                    GroupSpec::from_layout(group),
                    0,
                    &level.members,
                    &mut checks,
                );
                continue;
            }
            if !level.allows(tag) {
                checks
                    .sink
                    .push(ValidationError::FieldNotAllowedForMessage {
                        tag,
                        msg_type: msg_type.clone(),
                    });
            }
            index += 1;
        }
        let Checks {
            mut sink, accepted, ..
        } = checks;
        sink.commit(accepted);

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

        for group in &level.groups {
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

impl ValidationError {
    /// Maps this error to the version-neutral [`InboundRejection`] a session
    /// engine answers it with (issue #84, ADR-0031).
    ///
    /// The mapping follows QuickFIX/J's choice of `SessionRejectReason`
    /// (373) and `RefTagID` (371):
    ///
    /// | Error | Defect (373 in FIX 4.4) | `RefTagID` |
    /// |---|---|---|
    /// | `UnknownMsgType` | `InvalidMsgType` (11) | 35 |
    /// | `MissingRequiredField` | `RequiredTagMissing` (1) | the field |
    /// | `MissingRequiredGroup` | `RequiredTagMissing` (1) | the count tag |
    /// | `MissingRequiredFieldInGroupEntry` | `RequiredTagMissing` (1) | the missing member |
    /// | `UnknownTag` | `InvalidTagNumber` (0) | the tag |
    /// | `FieldNotAllowedForMessage` | `TagNotDefinedForMessageType` (2) | the tag |
    /// | `InvalidEnumValue` | `ValueIncorrect` (5) | the field |
    /// | `InvalidFieldFormat` | `IncorrectDataFormat` (6) | the field |
    /// | `InvalidGroupCount` | `IncorrectDataFormat` (6) | the count tag |
    /// | `DuplicateTag`, `RepeatedTagInGroupEntry` | `TagAppearsMoreThanOnce` (13) | the tag |
    /// | `GroupDelimiterMismatch` | `RepeatingGroupFieldsOutOfOrder` (15) | the tag found |
    /// | `GroupCountMismatch` | `IncorrectNumInGroupCount` (16) | the count tag |
    /// | `BeginStringMismatch` | `ValueIncorrect` (5) | 8 |
    /// | `UnknownComponent`, `SchemaTooDeep`, `SchemaTooLarge`, `ErrorLimitReached` | `Other` (99) | none |
    ///
    /// The text names tags, dictionary names and entry positions only, never
    /// a value: unlike this error's [`Display`](std::fmt::Display), which
    /// quotes values and must not reach the wire or a log line.
    #[must_use]
    pub fn inbound_rejection(&self) -> InboundRejection {
        use InboundDefect as D;
        let (defect, ref_tag, text) = match self {
            Self::UnknownMsgType { .. } => (
                D::InvalidMsgType,
                Some(35),
                "message type not defined in the dictionary".to_string(),
            ),
            Self::MissingRequiredField { tag, name } => (
                D::RequiredTagMissing,
                Some(*tag),
                format!("required tag missing: {name}({tag})"),
            ),
            Self::MissingRequiredGroup { count_tag, name } => (
                D::RequiredTagMissing,
                Some(*count_tag),
                format!("required group missing: {name}({count_tag})"),
            ),
            Self::MissingRequiredFieldInGroupEntry {
                count_tag,
                group,
                entry,
                tag,
                name,
            } => (
                D::RequiredTagMissing,
                Some(*tag),
                format!(
                    "required tag missing: {name}({tag}) in entry {entry} of group {group}({count_tag})"
                ),
            ),
            Self::UnknownTag { tag } => (
                D::InvalidTagNumber,
                Some(*tag),
                format!("tag {tag} is not defined in the dictionary"),
            ),
            Self::FieldNotAllowedForMessage { tag, .. } => (
                D::TagNotDefinedForMessageType,
                Some(*tag),
                format!("tag {tag} is not defined for this message type"),
            ),
            Self::InvalidEnumValue { tag, name, .. } => (
                D::ValueIncorrect,
                Some(*tag),
                format!("value is incorrect for {name}({tag})"),
            ),
            Self::InvalidFieldFormat { tag, name, .. } => (
                D::IncorrectDataFormat,
                Some(*tag),
                format!("incorrect data format for {name}({tag})"),
            ),
            Self::InvalidGroupCount { tag, name, .. } => (
                D::IncorrectDataFormat,
                Some(*tag),
                format!("incorrect data format for group count {name}({tag})"),
            ),
            Self::DuplicateTag { tag, name } => (
                D::TagAppearsMoreThanOnce,
                Some(*tag),
                format!("tag {name}({tag}) appears more than once"),
            ),
            Self::RepeatedTagInGroupEntry {
                count_tag,
                group,
                tag,
                name,
            } => (
                D::TagAppearsMoreThanOnce,
                Some(*tag),
                format!(
                    "tag {name}({tag}) appears more than once in an entry of group {group}({count_tag})"
                ),
            ),
            Self::GroupDelimiterMismatch {
                count_tag,
                name,
                expected,
                found,
            } => (
                D::RepeatingGroupFieldsOutOfOrder,
                Some(*found),
                format!(
                    "group {name}({count_tag}) entries must start with tag {expected}, found tag {found}"
                ),
            ),
            Self::GroupCountMismatch {
                count_tag, name, ..
            } => (
                D::IncorrectNumInGroupCount,
                Some(*count_tag),
                format!("incorrect NumInGroup count for group {name}({count_tag})"),
            ),
            Self::BeginStringMismatch { .. } => (
                D::ValueIncorrect,
                Some(8),
                "BeginString(8) is not the transport dictionary's".to_string(),
            ),
            Self::UnknownComponent { .. }
            | Self::SchemaTooDeep { .. }
            | Self::SchemaTooLarge { .. } => (
                D::Other,
                None,
                "the dictionary cannot validate this message type".to_string(),
            ),
            Self::ErrorLimitReached { .. } => {
                (D::Other, None, "too many validation errors".to_string())
            }
        };
        InboundRejection::new(defect, ref_tag, text)
    }
}

/// The first error of a failed validation, as an [`InboundRejection`].
///
/// [`Validator::validate`] orders its errors deterministically (see "Error
/// order" in the module docs), so the same message always yields the same
/// rejection.
fn first_rejection(errors: &[ValidationError]) -> InboundRejection {
    match errors.first() {
        Some(error) => error.inbound_rejection(),
        // `validate` never fails with an empty list; this keeps a failure a
        // failure should that ever change.
        None => InboundRejection::new(InboundDefect::Other, None, "validation failed"),
    }
}

/// Validates against the validator's dictionary or session pair; the first
/// error, in the validator's deterministic order, decides the rejection.
///
/// A session engine holds the validator as `Arc<dyn InboundValidator>`,
/// which needs a `Validator<'static>`: build it over an embedded dictionary
/// ([`Dictionary::fix44`] and the others return `&'static Dictionary`), or
/// share an owned [`Dictionary`] instead, which implements the trait too.
impl InboundValidator for Validator<'_> {
    fn validate(&self, msg: &RawMessage<'_>) -> Result<(), InboundRejection> {
        Validator::validate(self, msg).map_err(|errors| first_rejection(&errors))
    }
}

/// Validates against this one dictionary, as [`Validator::new`] does: an
/// `Arc<Dictionary>` loaded at run time can be handed to a session engine
/// as its `Arc<dyn InboundValidator>`.
impl InboundValidator for Dictionary {
    fn validate(&self, msg: &RawMessage<'_>) -> Result<(), InboundRejection> {
        InboundValidator::validate(&Validator::new(self), msg)
    }
}

/// Validates against the composed FIXT.1.1 transport and application pair,
/// as [`Validator::for_session`] does.
impl InboundValidator for SessionDictionary<'_> {
    fn validate(&self, msg: &RawMessage<'_>) -> Result<(), InboundRejection> {
        InboundValidator::validate(&Validator::for_session(self), msg)
    }
}

/// Collects the errors of one [`Validator::validate`] call, up to
/// [`MAX_VALIDATION_ERRORS`].
///
/// Two kinds of error are kept apart:
///
/// - **Committed** errors are in the result: structural and message-level
///   errors go straight there, and per-entry errors once their group instance
///   is known to be well-formed. At most [`MAX_VALIDATION_ERRORS`] are kept;
///   the first one refused marks the result as truncated.
/// - **Provisional** errors are per-entry errors waiting in a [`Pending`]
///   buffer for their group instance to finish. They never take committed
///   room, so a structural error that replaces them (a count mismatch, a
///   delimiter mismatch) is always recorded while committed room remains.
///   Their own number is bounded by the committed room left, which is all
///   that could ever be committed; a provisional error refused for that reason
///   only truncates the result if its buffer is eventually committed.
///
/// Memory stays bounded: committed plus provisional errors never exceed twice
/// [`MAX_VALIDATION_ERRORS`].
#[derive(Debug, Default)]
struct ErrorSink {
    /// Committed errors: the result.
    errors: Vec<ValidationError>,
    /// Provisional errors outstanding across every pending buffer.
    provisional: usize,
    /// Whether an error that belonged in the result was refused.
    truncated: bool,
}

/// Provisional per-entry errors of one group instance, and of the
/// well-formed groups nested in it.
#[derive(Debug, Default)]
struct Pending {
    /// The errors, in the order they were produced.
    errors: Vec<ValidationError>,
    /// Whether an error was refused for lack of room while held here.
    overflowed: bool,
}

impl ErrorSink {
    /// Commits an error to the result, or records that the result is full.
    fn push(&mut self, error: ValidationError) {
        if self.errors.len() < MAX_VALIDATION_ERRORS {
            self.errors.push(error);
        } else {
            self.truncated = true;
        }
    }

    /// Holds a per-entry error provisionally in `pending`.
    ///
    /// Refused, and `pending` marked as overflowed, once committed and
    /// provisional errors together fill [`MAX_VALIDATION_ERRORS`]: no more
    /// than that could ever reach the result.
    fn hold(&mut self, pending: &mut Pending, error: ValidationError) {
        let in_use = self.errors.len().checked_add(self.provisional);
        if in_use.is_some_and(|in_use| in_use < MAX_VALIDATION_ERRORS) {
            self.provisional += 1;
            pending.errors.push(error);
        } else {
            pending.overflowed = true;
        }
    }

    /// Moves a finished, well-formed nested group's provisional errors into
    /// the enclosing group's buffer; they stay provisional.
    fn adopt(parent: &mut Pending, mut child: Pending) {
        parent.errors.append(&mut child.errors);
        parent.overflowed |= child.overflowed;
    }

    /// Commits a well-formed top-level group's provisional errors, as many as
    /// committed room allows.
    fn commit(&mut self, pending: Pending) {
        self.forget(pending.errors.len());
        if pending.overflowed {
            self.truncated = true;
        }
        for error in pending.errors {
            self.push(error);
        }
    }

    /// Drops a malformed group's provisional errors; its structural error
    /// stands in for them.
    fn release(&mut self, pending: Pending) {
        self.forget(pending.errors.len());
    }

    /// Stops counting `count` provisional errors.
    fn forget(&mut self, count: usize) {
        debug_assert!(self.provisional >= count, "provisional errors were counted");
        if let Some(provisional) = self.provisional.checked_sub(count) {
            self.provisional = provisional;
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
    let admits =
        |token: &str| values.contains_key(token) || tags.other_side_admits(field.tag, def, token);
    let valid = if def.field_type.is_multi_value() {
        value.split(' ').all(admits)
    } else {
        admits(value.as_ref())
    };
    if !valid {
        errors.push(ValidationError::InvalidEnumValue {
            tag: field.tag,
            name: def.name.clone(),
            value: value.into_owned(),
        });
    }
}

/// Turns the events of the shared group walk ([`walk::walk_group`]) into
/// validation errors.
///
/// Structural errors (count, delimiter, a tag repeated inside an entry) are
/// committed to `sink` straight away. Per-entry errors, the required members
/// missing from an entry, are produced by [`check_entry_required`] at every
/// entry boundary and held provisionally in the [`Pending`] buffer of the
/// group being walked. When a group instance ends, its buffer moves into the
/// enclosing group's (or, for a top-level group, into `accepted`) if the
/// instance is well-formed (every entry delimiter-led, no tag repeated within
/// an entry, and the declared count equal to the entries found); otherwise it
/// is dropped, because the group already carries a structural error.
///
/// Nothing here is sized from a declared count: the walk counts entries as it
/// finds them, so a count of `99999999999` costs no more than the fields
/// actually present.
struct Checks<'v, 'd, 'e> {
    tags: &'v TagResolver<'d, 'e>,
    sink: ErrorSink,
    /// One buffer per group instance being walked, innermost last.
    stack: Vec<Pending>,
    /// Per-entry errors of the well-formed top-level groups, still
    /// provisional.
    accepted: Pending,
}

/// Returns a group's name for an error message.
fn group_name(group: GroupSpec<'_>) -> String {
    group
        .layout()
        .map_or_else(String::new, |layout| layout.name.clone())
}

impl<'s> walk::Visitor<'s> for Checks<'_, '_, '_> {
    fn enter_group(&mut self, _group: GroupSpec<'s>) {
        self.stack.push(Pending::default());
    }

    fn invalid_count(&mut self, group: GroupSpec<'s>, value: &[u8]) {
        self.sink.push(ValidationError::InvalidGroupCount {
            tag: group.count_tag(),
            name: group_name(group),
            value: String::from_utf8_lossy(value).into_owned(),
        });
    }

    fn delimiter_mismatch(&mut self, group: GroupSpec<'s>, found: u32) {
        self.sink.push(ValidationError::GroupDelimiterMismatch {
            count_tag: group.count_tag(),
            name: group_name(group),
            expected: group.delimiter_tag(),
            found,
        });
    }

    fn repeated_tag(&mut self, group: GroupSpec<'s>, tag: u32) {
        self.sink.push(ValidationError::RepeatedTagInGroupEntry {
            count_tag: group.count_tag(),
            group: group_name(group),
            tag,
            name: self
                .tags
                .field(tag)
                .map_or_else(String::new, |def| def.name.clone()),
        });
    }

    fn entry_closed(&mut self, group: GroupSpec<'s>, entry: u64, seen: &EntryTags<'s>) {
        let Some(layout) = group.layout() else {
            return;
        };
        let sink = &mut self.sink;
        let Some(pending) = self.stack.last_mut() else {
            return;
        };
        check_entry_required(layout, entry, seen, &mut |error| {
            sink.hold(pending, error);
        });
    }

    fn count_mismatch(&mut self, group: GroupSpec<'s>, declared: u64, actual: u64) {
        self.sink.push(ValidationError::GroupCountMismatch {
            count_tag: group.count_tag(),
            name: group_name(group),
            declared,
            actual,
            delimiter_tag: group.delimiter_tag(),
        });
    }

    fn too_deep(&mut self, group: GroupSpec<'s>) {
        // A layout built by the scope expansion never nests past the limit;
        // this reports a walk that would.
        self.sink.push(ValidationError::SchemaTooDeep {
            name: group_name(group),
            limit: MAX_SCOPE_DEPTH,
        });
    }

    fn leave_group(&mut self, _group: GroupSpec<'s>, well_formed: bool, _entries: u64) {
        let Some(pending) = self.stack.pop() else {
            return;
        };
        if !well_formed {
            self.sink.release(pending);
            return;
        }
        // A nested group's per-entry errors join the enclosing group's, so
        // they are dropped too if that group is malformed. A malformed nested
        // group drops only its own.
        match self.stack.last_mut() {
            Some(parent) => ErrorSink::adopt(parent, pending),
            None => ErrorSink::adopt(&mut self.accepted, pending),
        }
    }
}

/// End-of-entry hook: reports, through `report`, the required members
/// missing from one closed entry of `group`.
///
/// `entry` is the closed entry's 0-based index and `seen` the tags that
/// appeared in it at its own level (a nested group's count tag included, its
/// members not). Reported, in this order: every required field of the entry
/// level in schema order (the group's own fields in declaration order, then
/// those of components referenced as required, component by component and
/// depth first; each tag once, the delimiter excluded when the scope was
/// built), then every nested group marked required whose count tag is
/// absent, by ascending count tag.
///
/// The shared walk calls it, through [`Checks`], at every entry boundary
/// ([`walk::Visitor::entry_closed`]). It reports through a callback rather
/// than into a collector of its own, so another reader of group entries can
/// apply the same check at its own entry boundaries.
fn check_entry_required(
    group: &LayoutGroup,
    entry: u64,
    seen: &EntryTags<'_>,
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
        if !seen.contains(*tag) {
            report(missing(*tag, name));
        }
    }

    // `groups` is sorted by count tag, so missing nested groups are reported
    // in ascending count-tag order.
    for nested in &group.entry.groups {
        if nested.required && !seen.contains(nested.count_tag) {
            report(missing(nested.count_tag, &nested.name));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // `FieldRef` is ambiguous across the workspace, so the schema one is
    // always spelled with a qualifier here; `ironfix_core::field::FieldRef`
    // appears in full above.
    use crate::schema::FieldRef as SchemaFieldRef;
    use crate::schema::{
        ComponentDef, ComponentRef, Dictionary, FieldDef, GroupDef, Member, MessageCategory,
    };
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
        let result = validator.validate(&raw);
        assert_reader_agrees(validator, &raw, &result);
        result
    }

    /// Count tags of `group` and of every group nested in it, at any depth.
    fn subtree_count_tags(group: GroupSpec<'_>) -> Vec<u32> {
        let mut tags = Vec::new();
        let mut pending = vec![group];
        while let Some(spec) = pending.pop() {
            tags.push(spec.count_tag());
            pending.extend(spec.nested_groups().iter());
        }
        tags
    }

    /// Asserts that the group reader agrees with the validator on every
    /// top-level group of `raw`.
    ///
    /// Every validator test goes through [`validate_using`], so this sweeps
    /// every validator fixture. For each group the message's layout can open
    /// at its top level: the reader rejects it exactly when the validator
    /// reports a structural error (count, delimiter, repeated tag, duplicate
    /// count field) for it or for a group nested in it; when the reader
    /// accepts it, it yields as many entries as the count declares, each led
    /// by the delimiter. A structural error whose count tag lies under two
    /// top-level groups present in the message cannot be attributed, so it
    /// neither requires nor forbids a rejection.
    #[track_caller]
    fn assert_reader_agrees(
        validator: Validator<'_>,
        raw: &RawMessage<'_>,
        result: &Result<(), Vec<ValidationError>>,
    ) {
        let errors: &[ValidationError] = match result {
            Ok(()) => &[],
            Err(errors) => errors,
        };
        if errors
            .iter()
            .any(|error| matches!(error, ValidationError::ErrorLimitReached { .. }))
        {
            // A truncated report may lack the structural error.
            return;
        }
        let Ok(layout) = validator.layout(raw.msg_type().as_str()) else {
            return;
        };
        let present: Vec<(GroupSpec<'_>, Vec<u32>)> = layout
            .groups()
            .iter()
            .filter(|group| matches!(layout.read(raw, group.count_tag()), Ok(Some(_)) | Err(_)))
            .map(|group| (group, subtree_count_tags(group)))
            .collect();
        let owners = |tag: u32| {
            present
                .iter()
                .filter(|(_, tags)| tags.contains(&tag))
                .count()
        };

        for group in layout.groups().iter() {
            let count_tag = group.count_tag();
            let read = layout.read(raw, count_tag);
            let subtree = subtree_count_tags(group);
            let mut attributed = false;
            let mut ambiguous = false;
            for error in errors {
                let tag = match error {
                    ValidationError::InvalidGroupCount { tag, .. } => *tag,
                    ValidationError::GroupCountMismatch { count_tag, .. }
                    | ValidationError::GroupDelimiterMismatch { count_tag, .. }
                    | ValidationError::RepeatedTagInGroupEntry { count_tag, .. } => *count_tag,
                    ValidationError::DuplicateTag { tag, .. } if *tag == count_tag => *tag,
                    _ => continue,
                };
                if !subtree.contains(&tag) {
                    continue;
                }
                if owners(tag) > 1 {
                    ambiguous = true;
                } else {
                    attributed = true;
                }
            }
            match read {
                Err(error) => assert!(
                    attributed || ambiguous,
                    "reader rejected group {count_tag} ({error}) but the validator reported \
                     no structural error for it: {errors:?}"
                ),
                Ok(Some(entries)) => {
                    assert!(
                        !attributed,
                        "reader accepted group {count_tag} but the validator reported a \
                         structural error for it: {errors:?}"
                    );
                    let declared = raw
                        .field_slice()
                        .iter()
                        .find(|field| field.tag == count_tag)
                        .and_then(|field| walk::parse_count(field.value));
                    let mut seen: u64 = 0;
                    for entry in entries {
                        assert_eq!(entry.index(), seen);
                        assert_eq!(
                            entry.fields().first().map(|field| field.tag),
                            Some(group.delimiter_tag()),
                            "entry {seen} of group {count_tag} is not delimiter-led"
                        );
                        seen += 1;
                    }
                    if !ambiguous {
                        assert_eq!(Some(seen), declared, "group {count_tag} entry count");
                    }
                }
                Ok(None) => assert!(
                    !raw.field_slice().iter().any(|field| field.tag == count_tag) || !attributed,
                    "reader found no top-level group {count_tag}: {errors:?}"
                ),
            }
        }
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
        // ExecInst(18) is a multiple-value string in the embedded FIX 4.4
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
        // `f` is not among the ExecInst values the embedded dictionary
        // defines, so the list is rejected even though `1` is valid.
        let found = errors(validate(&with_header(&[
            "11=ORDER-1",
            "18=1 f",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
        ])));
        assert!(found.contains(&ValidationError::InvalidEnumValue {
            tag: 18,
            name: "ExecInst".to_string(),
            value: "1 f".to_string(),
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

    #[test]
    fn test_validate_signed_group_count_is_an_invalid_count() {
        // `+1` parses as a Rust u64 but is not a FIX NumInGroup: the value
        // check reports its form and the group walk refuses it as a count,
        // as the group reader does.
        let found = errors(validate(&with_header(&[
            "11=ORDER-1",
            "453=+1",
            "448=BROKER-A",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
        ])));
        assert_eq!(
            found,
            vec![
                ValidationError::InvalidFieldFormat {
                    tag: 453,
                    name: "NoPartyIDs".to_string(),
                    value: "+1".to_string(),
                    field_type: FieldType::NumInGroup,
                },
                ValidationError::InvalidGroupCount {
                    tag: 453,
                    name: "NoPartyIDs".to_string(),
                    value: "+1".to_string(),
                },
            ]
        );
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
        let group = |count_tag: u32, name: &str| {
            GroupDef::new(
                count_tag,
                name.to_string(),
                200,
                false,
                vec![Member::Field(member.clone())],
            )
        };
        dict.add_message(MessageDef::new(
            "U4",
            "TwoGroups",
            MessageCategory::App,
            vec![
                Member::Group(group(100, "NoFirst")),
                Member::Group(group(101, "NoSecond")),
            ],
        ));
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

    /// A MarketDataRequest (35=V) without its two required groups,
    /// NoRelatedSym(146) and NoMDEntryTypes(267).
    const MARKET_DATA_REQUEST_WITHOUT_GROUPS: [&str; 11] = [
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
    ];

    /// The two missing-group errors, in their documented order: ascending
    /// count tag.
    fn missing_market_data_groups() -> Vec<ValidationError> {
        vec![
            ValidationError::MissingRequiredGroup {
                count_tag: 146,
                name: "NoRelatedSym".to_string(),
            },
            ValidationError::MissingRequiredGroup {
                count_tag: 267,
                name: "NoMDEntryTypes".to_string(),
            },
        ]
    }

    #[test]
    fn test_validate_missing_required_group_is_reported() {
        // Both groups are named, in ascending count-tag order, and the order
        // is the same on every run.
        let first = validate(&MARKET_DATA_REQUEST_WITHOUT_GROUPS);
        assert_eq!(first, Err(missing_market_data_groups()));
        for _ in 0..16 {
            assert_eq!(validate(&MARKET_DATA_REQUEST_WITHOUT_GROUPS), first);
        }
    }

    #[test]
    fn test_validate_error_order_is_identical_across_runs_and_dictionary_reloads() {
        // One error of each kind the order documents, from one message: a
        // value error (263=9 is not a SubscriptionRequestType), a structural
        // error (Symbol(55) is not a MarketDataRequest field), a missing field
        // (MDReqID(262)) and two missing groups. Each fresh load of the same
        // XML builds its own hash maps, so a hash-ordered error list would
        // differ between loads.
        let message = [
            "8=FIX.4.4",
            "9=100",
            "35=V",
            "49=SENDER",
            "56=TARGET",
            "34=1",
            "52=20260712-10:00:00",
            "263=9",
            "264=1",
            "55=EURUSD",
            "10=000",
        ];
        let mut expected = vec![
            ValidationError::InvalidEnumValue {
                tag: 263,
                name: "SubscriptionRequestType".to_string(),
                value: "9".to_string(),
            },
            ValidationError::FieldNotAllowedForMessage {
                tag: 55,
                msg_type: "V".to_string(),
            },
            ValidationError::MissingRequiredField {
                tag: 262,
                name: "MDReqID".to_string(),
            },
        ];
        expected.extend(missing_market_data_groups());
        let expected = Err(expected);

        assert_eq!(validate(&message), expected);
        for _ in 0..4 {
            let reloaded = ok(
                Dictionary::from_quickfix_xml(include_str!("../tests/fixtures/quickfix/FIX44.xml")),
                "FIX 4.4 reloads",
            );
            for _ in 0..4 {
                assert_eq!(validate_with(&reloaded, &message), expected);
            }
        }
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
        dict.add_component(ComponentDef::new(
            "Instrument",
            vec![Member::Field(required(55, "Symbol"))],
        ));
        dict.add_component(ComponentDef::new(
            "PriceBlock",
            vec![Member::Field(required(44, "Price"))],
        ));
        dict.add_message(MessageDef::new(
            "U1",
            "Ping",
            MessageCategory::App,
            vec![
                Member::Component(ComponentRef::new("Instrument", true)),
                Member::Component(ComponentRef::new("PriceBlock", false)),
            ],
        ));
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
        dict.add_message(MessageDef::new(
            "U2",
            "Pong",
            MessageCategory::App,
            vec![Member::Component(ComponentRef::new("Nope", true))],
        ));
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
            dict.add_component(ComponentDef::new(
                format!("C{index}"),
                vec![Member::Component(ComponentRef::new(
                    format!("C{}", index + 1),
                    true,
                ))],
            ));
        }
        dict.add_component(ComponentDef::new(format!("C{links}"), Vec::new()));
        dict.add_message(MessageDef::new(
            "U3",
            "Deep",
            MessageCategory::App,
            vec![Member::Component(ComponentRef::new("C0", true))],
        ));

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
        dict.add_message(MessageDef::new(
            "U3",
            "Wide",
            MessageCategory::App,
            (0..=MAX_SCOPE_NODES)
                .map(|_| Member::Component(ComponentRef::new("Instrument", false))),
        ));

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
        dict.add_component(ComponentDef::new(
            "Loop",
            vec![Member::Component(ComponentRef::new("Loop", true))],
        ));
        dict.add_message(MessageDef::new(
            "U3",
            "Looping",
            MessageCategory::App,
            vec![Member::Component(ComponentRef::new("Loop", true))],
        ));
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
    fn test_validate_for_session_logon_with_no_msg_types_passes() {
        // The embedded FIXT 1.1 dictionary defines the Logon NoMsgTypes(384)
        // group; RefMsgType(372) names an application message type, which
        // the composed validator admits (the union of both enumerations).
        let mut fields = fixt11_header("35=A");
        fields.extend(["98=0", "108=30", "384=1", "372=D", "1137=9", "10=000"]);
        assert_eq!(validate_session(&fields), Ok(()));
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
    fn test_validate_fix50sp2_alone_validates_a_complete_message() {
        // The embedded FIX 5.0 SP2 dictionary is derived from FIX Latest,
        // which defines the standard header and trailer: validated on its
        // own, the whole message passes.
        assert_eq!(
            validate_with(fix50sp2(), &fix50sp2_new_order_single()),
            Ok(())
        );
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
        application.add_message(MessageDef::new(
            "U1",
            "Probe",
            MessageCategory::App,
            vec![Member::Field(field_ref(9001, "BodyTag", false))],
        ));
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
    fn test_validate_for_session_logon_rejects_an_undefined_default_appl_ver_id() {
        // The embedded FIXT 1.1 dictionary enumerates DefaultApplVerID(1137),
        // so a value that names no application version is rejected.
        let mut fields = fixt11_header("35=A");
        fields.extend(["98=0", "108=30", "1137=NOT-A-VERSION", "10=000"]);
        assert_eq!(
            validate_session(&fields),
            Err(vec![ValidationError::InvalidEnumValue {
                tag: 1137,
                name: "DefaultApplVerID".to_string(),
                value: "NOT-A-VERSION".to_string(),
            }])
        );
    }

    #[test]
    fn test_validate_for_session_fixt11_defining_msg_type_grp_accepts_no_msg_types() {
        // The QuickFIX FIXT 1.1 file lacks the NoMsgTypes group: loaded with
        // the group added, it accepts it. The fixture
        // file is not touched; the variant is built in memory.
        let vendored = include_str!("../tests/fixtures/quickfix/FIXT11.xml");
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
        // Orchestra holds StrmAsgnReqGrp as a group on the message.
        let group = message
            .groups()
            .iter()
            .find(|group| group.count_tag == 1499);
        match group {
            Some(group) => assert_eq!(group.delimiter_tag, 453),
            None => panic!("NoAsgnReqs(1499) is defined on StreamAssignmentRequest"),
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
                .and_then(|message| message.groups().iter().find(|g| g.count_tag == count_tag));
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
        dict.add_component(ComponentDef::new(
            "ReqBlock",
            vec![
                Member::Field(field_ref(300, "ReqField", true)),
                Member::Field(field_ref(201, "OuterReq", true)),
            ],
        ));
        dict.add_component(ComponentDef::new(
            "OptBlock",
            vec![
                Member::Field(field_ref(301, "OptReq", true)),
                Member::Field(field_ref(302, "OptOther", false)),
                Member::Group(GroupDef::new(
                    130,
                    "NoOptNested",
                    230,
                    true,
                    vec![Member::Field(field_ref(230, "OptNestedKey", true))],
                )),
            ],
        ));
        let inner = GroupDef::new(
            110,
            "NoInner",
            210,
            false,
            vec![
                Member::Field(field_ref(210, "InnerKey", true)),
                Member::Field(field_ref(211, "InnerReq", true)),
            ],
        );
        let req_nested = GroupDef::new(
            120,
            "NoReqNested",
            220,
            true,
            vec![Member::Field(field_ref(220, "NestedKey", true))],
        );
        let outer = GroupDef::new(
            100,
            "NoOuter",
            200,
            false,
            vec![
                Member::Field(field_ref(200, "OuterKey", true)),
                Member::Field(field_ref(201, "OuterReq", true)),
                Member::Group(inner),
                Member::Group(req_nested),
                Member::Component(ComponentRef::new("ReqBlock", true)),
                Member::Component(ComponentRef::new("OptBlock", false)),
            ],
        );
        dict.add_message(MessageDef::new(
            "U5",
            "Groups",
            MessageCategory::App,
            vec![Member::Group(outer)],
        ));
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
        // an entry lacking it reports it once, at its first position: as one
        // of the group's own fields, before ReqBlock's ReqField(300).
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

    /// A FIX 4.4 ListStatus (35=N) declaring `declared` NoOrders(73) entries
    /// and carrying `entries` of them, each only the delimiter `11=a`: every
    /// entry lacks five required members (14, 39, 151, 84, 6).
    fn delimiter_only_list_status(declared: &str, entries: usize) -> Vec<&str> {
        let mut body: Vec<&str> = vec![
            "66=LIST-1",
            "429=1",
            "82=1",
            "431=1",
            "83=1",
            "68=1",
            declared,
        ];
        body.extend(std::iter::repeat_n("11=a", entries));
        fix44_message("35=N", &body)
    }

    #[test]
    fn test_validate_structural_error_replaces_provisional_errors_past_the_limit() {
        // 205 entries x 5 missing members = 1025 provisional per-entry
        // errors, one more than the limit, but the count says 206: the group
        // is malformed, so its per-entry errors are dropped and the count
        // mismatch alone is reported. Provisional errors never take room from
        // the result, so the mismatch cannot be crowded out.
        let found = errors(validate(&delimiter_only_list_status("73=206", 205)));
        assert_eq!(
            found,
            vec![ValidationError::GroupCountMismatch {
                count_tag: 73,
                name: "NoOrders".to_string(),
                declared: 206,
                actual: 205,
                delimiter_tag: 11,
            }]
        );
    }

    #[test]
    fn test_validate_committed_errors_past_the_limit_end_with_the_marker() {
        // The same 205 entries with a matching count: the group is
        // well-formed, its 1025 per-entry errors are committed, and the
        // result stops at the limit with the marker last.
        let found = errors(validate(&delimiter_only_list_status("73=205", 205)));
        assert_eq!(found.len(), MAX_VALIDATION_ERRORS + 1);
        assert_eq!(
            found.last(),
            Some(&ValidationError::ErrorLimitReached {
                limit: MAX_VALIDATION_ERRORS,
            })
        );
        assert_eq!(found.first(), Some(&no_orders_missing(0, 14, "CumQty")));
    }

    #[test]
    fn test_validate_committed_structural_errors_past_the_limit_end_with_the_marker() {
        // Structural errors alone can fill the result too: 1100 undefined
        // tags give 1024 UnknownTag errors and the marker.
        let tags: Vec<String> = (0..1100)
            .map(|index| format!("{}=x", 20_000 + index))
            .collect();
        let mut body: Vec<&str> = vec![
            "11=ORDER-1",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
        ];
        body.extend(tags.iter().map(String::as_str));
        let found = errors(validate(&with_header(&body)));
        assert_eq!(found.len(), MAX_VALIDATION_ERRORS + 1);
        assert_eq!(
            found.last(),
            Some(&ValidationError::ErrorLimitReached {
                limit: MAX_VALIDATION_ERRORS,
            })
        );
        assert_eq!(
            found.first(),
            Some(&ValidationError::UnknownTag { tag: 20_000 })
        );
    }

    /// A dialect whose NoX(100) entries interleave a direct field with a
    /// component: `Key` (delimiter), then the required component `Block`
    /// (with required `Inside`), then the required field `After`.
    const INTERLEAVED_XML: &str = r"<fix type='FIX' major='4' minor='4'>
        <header>
            <field name='BeginString' required='Y'/>
            <field name='BodyLength' required='Y'/>
            <field name='MsgType' required='Y'/>
        </header>
        <trailer><field name='CheckSum' required='Y'/></trailer>
        <messages>
            <message name='Interleaved' msgtype='U9' msgcat='app'>
                <group name='NoX' required='N'>
                    <field name='Key' required='Y'/>
                    <component name='Block' required='Y'/>
                    <field name='After' required='Y'/>
                </group>
            </message>
        </messages>
        <components>
            <component name='Block'>
                <field name='Inside' required='Y'/>
            </component>
        </components>
        <fields>
            <field number='8' name='BeginString' type='STRING'/>
            <field number='9' name='BodyLength' type='LENGTH'/>
            <field number='10' name='CheckSum' type='STRING'/>
            <field number='35' name='MsgType' type='STRING'/>
            <field number='100' name='NoX' type='NUMINGROUP'/>
            <field number='200' name='Key' type='STRING'/>
            <field number='300' name='Inside' type='STRING'/>
            <field number='400' name='After' type='STRING'/>
        </fields>
    </fix>";

    #[test]
    fn test_validate_group_entry_reports_direct_fields_before_component_members() {
        // In the XML, Block (and its Inside(300)) comes before After(400).
        // The schema keeps a group's fields and components in separate lists,
        // so the group's own field After is reported first, then Block's
        // Inside: the documented order, not the XML interleaving.
        let dict = ok(
            Dictionary::from_quickfix_xml(INTERLEAVED_XML),
            "interleaved dialect loads",
        );
        let found = errors(validate_with(
            &dict,
            &["8=FIX.4.4", "9=100", "35=U9", "100=1", "200=k", "10=000"],
        ));
        assert_eq!(
            found,
            vec![
                entry_missing(100, "NoX", 0, 400, "After"),
                entry_missing(100, "NoX", 0, 300, "Inside"),
            ]
        );
    }

    /// NoOuter(102) entries (delimiter Shared(200), optional Extra(300))
    /// nest the optional NoInner(110), whose entries (delimiter InnerKey(210))
    /// may carry Extra(300) as well.
    const EMPTY_CHILD_XML: &str = r"<fix type='FIX' major='4' minor='4'>
        <header>
            <field name='BeginString' required='Y'/>
            <field name='BodyLength' required='Y'/>
            <field name='MsgType' required='Y'/>
        </header>
        <trailer><field name='CheckSum' required='Y'/></trailer>
        <messages>
            <message name='Nesting' msgtype='U5' msgcat='app'>
                <group name='NoOuter' required='N'>
                    <field name='Shared' required='Y'/>
                    <field name='Extra' required='N'/>
                    <group name='NoInner' required='N'>
                        <field name='InnerKey' required='Y'/>
                        <field name='Extra' required='N'/>
                    </group>
                </group>
            </message>
        </messages>
        <fields>
            <field number='8' name='BeginString' type='STRING'/>
            <field number='9' name='BodyLength' type='LENGTH'/>
            <field number='10' name='CheckSum' type='STRING'/>
            <field number='35' name='MsgType' type='STRING'/>
            <field number='102' name='NoOuter' type='NUMINGROUP'/>
            <field number='110' name='NoInner' type='NUMINGROUP'/>
            <field number='200' name='Shared' type='STRING'/>
            <field number='210' name='InnerKey' type='STRING'/>
            <field number='300' name='Extra' type='STRING'/>
        </fields>
    </fix>";

    #[track_caller]
    fn validate_empty_child(body: &[&str]) -> Result<(), Vec<ValidationError>> {
        let dict = ok(
            Dictionary::from_quickfix_xml(EMPTY_CHILD_XML),
            "empty-child dialect loads",
        );
        let mut fields = vec!["8=FIX.4.4", "9=100", "35=U5"];
        fields.extend_from_slice(body);
        fields.push("10=000");
        validate_with(&dict, &fields)
    }

    #[test]
    fn test_validate_empty_nested_group_followed_by_an_enclosing_field_passes() {
        // NoInner is empty; Extra(300) belongs to both NoInner and NoOuter,
        // and with a count of 0 it is the enclosing NoOuter entry's field.
        assert_eq!(
            validate_empty_child(&["102=1", "200=A", "110=0", "300=OWN"]),
            Ok(())
        );
    }

    #[test]
    fn test_validate_empty_nested_group_with_its_own_entry_is_still_malformed() {
        // InnerKey(210) can only open a NoInner entry, which a count of 0
        // does not declare.
        assert_eq!(
            validate_empty_child(&["102=1", "200=A", "110=0", "210=X"]),
            Err(vec![ValidationError::GroupCountMismatch {
                count_tag: 110,
                name: "NoInner".to_string(),
                declared: 0,
                actual: 1,
                delimiter_tag: 210,
            }])
        );
    }

    // ---- InboundValidator adapter (issue #84) ----

    /// Validates `fields` through the `InboundValidator` trait object.
    #[track_caller]
    fn inbound(validator: &dyn InboundValidator, fields: &[&str]) -> Result<(), InboundRejection> {
        let msg = build(fields);
        let mut decoder = Decoder::new(msg.as_bytes()).with_checksum_validation(false);
        let raw = ok(decoder.decode(), "test message decodes");
        validator.validate(&raw)
    }

    #[track_caller]
    fn rejection(result: Result<(), InboundRejection>) -> InboundRejection {
        match result {
            Ok(()) => panic!("expected the message to be rejected, but it validated"),
            Err(rejection) => rejection,
        }
    }

    #[test]
    fn test_inbound_validator_passes_a_valid_new_order_single() {
        let fields = with_header(&[
            "11=ORDER-1",
            "55=EURUSD",
            "54=1",
            "60=20260712-10:00:00",
            "40=1",
        ]);
        assert_eq!(inbound(&Validator::new(fix44()), &fields), Ok(()));
        assert_eq!(inbound(fix44(), &fields), Ok(()));
    }

    #[test]
    fn test_inbound_validator_missing_side_names_tag_54() {
        let fields = with_header(&["11=ORDER-1", "55=EURUSD", "60=20260712-10:00:00", "40=1"]);
        let found = rejection(inbound(&Validator::new(fix44()), &fields));
        assert_eq!(found.defect(), InboundDefect::RequiredTagMissing);
        assert_eq!(found.ref_tag(), Some(54));
        assert_eq!(found.text(), "required tag missing: Side(54)");
        // The owned dictionary answers the same.
        assert_eq!(rejection(inbound(fix44(), &fields)), found);
    }

    #[test]
    fn test_inbound_validator_undefined_msg_type_is_a_failure() {
        let mut fields: Vec<&str> = HEADER.to_vec();
        fields[2] = "35=ZZ";
        fields.push("10=000");
        let found = rejection(inbound(&Validator::new(fix44()), &fields));
        assert_eq!(found.defect(), InboundDefect::InvalidMsgType);
        assert_eq!(found.ref_tag(), Some(35));
        assert!(!found.text().contains("ZZ"));
    }

    #[test]
    fn test_inbound_validator_bad_enum_text_carries_no_value() {
        let fields = with_header(&[
            "11=ORDER-1",
            "55=EURUSD",
            "54=X",
            "60=20260712-10:00:00",
            "40=1",
        ]);
        let found = rejection(inbound(&Validator::new(fix44()), &fields));
        assert_eq!(found.defect(), InboundDefect::ValueIncorrect);
        assert_eq!(found.ref_tag(), Some(54));
        assert!(!found.text().contains('X'), "{}", found.text());
    }

    #[test]
    fn test_inbound_validator_session_dictionary_validates_the_pair() {
        let session = fixt11_fix50sp2();
        let valid = fix50sp2_new_order_single();
        assert_eq!(inbound(&session, &valid), Ok(()));
        assert_eq!(inbound(&Validator::for_session(&session), &valid), Ok(()));
        let missing_side: Vec<&str> = valid
            .iter()
            .copied()
            .filter(|field| !field.starts_with("54="))
            .collect();
        let found = rejection(inbound(&session, &missing_side));
        assert_eq!(found.defect(), InboundDefect::RequiredTagMissing);
        assert_eq!(found.ref_tag(), Some(54));
    }

    #[test]
    fn test_inbound_rejection_maps_every_error_variant() {
        use InboundDefect as D;
        let name = || "Name".to_string();
        let secret = || "SECRET".to_string();
        let cases: Vec<(ValidationError, D, Option<u32>)> = vec![
            (
                ValidationError::UnknownMsgType { msg_type: secret() },
                D::InvalidMsgType,
                Some(35),
            ),
            (
                ValidationError::MissingRequiredField {
                    tag: 54,
                    name: name(),
                },
                D::RequiredTagMissing,
                Some(54),
            ),
            (
                ValidationError::UnknownTag { tag: 9999 },
                D::InvalidTagNumber,
                Some(9999),
            ),
            (
                ValidationError::FieldNotAllowedForMessage {
                    tag: 44,
                    msg_type: secret(),
                },
                D::TagNotDefinedForMessageType,
                Some(44),
            ),
            (
                ValidationError::InvalidFieldFormat {
                    tag: 38,
                    name: name(),
                    value: secret(),
                    field_type: FieldType::Qty,
                },
                D::IncorrectDataFormat,
                Some(38),
            ),
            (
                ValidationError::InvalidEnumValue {
                    tag: 54,
                    name: name(),
                    value: secret(),
                },
                D::ValueIncorrect,
                Some(54),
            ),
            (
                ValidationError::DuplicateTag {
                    tag: 11,
                    name: name(),
                },
                D::TagAppearsMoreThanOnce,
                Some(11),
            ),
            (
                ValidationError::RepeatedTagInGroupEntry {
                    count_tag: 78,
                    group: name(),
                    tag: 79,
                    name: name(),
                },
                D::TagAppearsMoreThanOnce,
                Some(79),
            ),
            (
                ValidationError::InvalidGroupCount {
                    tag: 78,
                    name: name(),
                    value: secret(),
                },
                D::IncorrectDataFormat,
                Some(78),
            ),
            (
                ValidationError::GroupCountMismatch {
                    count_tag: 78,
                    name: name(),
                    declared: 7_777_777,
                    actual: 1,
                    delimiter_tag: 79,
                },
                D::IncorrectNumInGroupCount,
                Some(78),
            ),
            (
                ValidationError::GroupDelimiterMismatch {
                    count_tag: 78,
                    name: name(),
                    expected: 79,
                    found: 80,
                },
                D::RepeatingGroupFieldsOutOfOrder,
                Some(80),
            ),
            (
                ValidationError::MissingRequiredGroup {
                    count_tag: 78,
                    name: name(),
                },
                D::RequiredTagMissing,
                Some(78),
            ),
            (
                ValidationError::UnknownComponent { name: secret() },
                D::Other,
                None,
            ),
            (
                ValidationError::SchemaTooDeep {
                    name: secret(),
                    limit: 32,
                },
                D::Other,
                None,
            ),
            (
                ValidationError::SchemaTooLarge { limit: 4096 },
                D::Other,
                None,
            ),
            (
                ValidationError::BeginStringMismatch {
                    expected: secret(),
                    found: secret(),
                },
                D::ValueIncorrect,
                Some(8),
            ),
            (
                ValidationError::MissingRequiredFieldInGroupEntry {
                    count_tag: 78,
                    group: name(),
                    entry: 2,
                    tag: 80,
                    name: name(),
                },
                D::RequiredTagMissing,
                Some(80),
            ),
            (
                ValidationError::ErrorLimitReached { limit: 1024 },
                D::Other,
                None,
            ),
        ];
        for (error, defect, ref_tag) in cases {
            let found = error.inbound_rejection();
            assert_eq!(found.defect(), defect, "{error:?}");
            assert_eq!(found.ref_tag(), ref_tag, "{error:?}");
            assert!(!found.text().is_empty(), "{error:?}");
            assert!(
                !found.text().contains("SECRET"),
                "{error:?}: {}",
                found.text()
            );
            assert!(
                !found.text().contains("7777777"),
                "{error:?}: {}",
                found.text()
            );
        }
    }

    #[test]
    fn test_inbound_rejection_group_entry_text_names_the_entry() {
        let found = ValidationError::MissingRequiredFieldInGroupEntry {
            count_tag: 78,
            group: "NoAllocs".to_string(),
            entry: 2,
            tag: 80,
            name: "AllocQty".to_string(),
        }
        .inbound_rejection();
        assert_eq!(
            found.text(),
            "required tag missing: AllocQty(80) in entry 2 of group NoAllocs(78)"
        );
    }
}
