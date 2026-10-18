/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Zero-copy, dictionary-driven repeating-group reader.
//!
//! A decoded [`RawMessage`] is a flat list of fields in wire order; this
//! module reads its repeating groups as borrowed views. The structure comes
//! from the dictionary only: build a [`MessageLayout`] once per message type
//! (that is where allocation happens), then read any number of messages with
//! it:
//!
//! ```
//! use ironfix_dictionary::{Dictionary, MessageLayout};
//! use ironfix_tagvalue::Decoder;
//!
//! // NewOrderSingle with two NoPartyIDs(453) entries.
//! let body = "35=D\x0149=S\x0156=T\x0134=1\x0152=20260712-10:00:00\x0111=ORDER-1\x01\
//!             453=2\x01448=BROKER-A\x01447=D\x01452=1\x01448=BROKER-B\x01447=D\x01452=3\x01\
//!             55=EURUSD\x0154=1\x0160=20260712-10:00:00\x0140=1\x01";
//! let frame = format!("8=FIX.4.4\x019={}\x01{body}10=000\x01", body.len());
//! let mut decoder = Decoder::new(frame.as_bytes()).with_checksum_validation(false);
//! let message = decoder.decode()?;
//!
//! let layout = MessageLayout::new(Dictionary::fix44()?, "D")?;
//! let Some(parties) = layout.read(&message, 453)? else {
//!     return Ok(());
//! };
//! let ids: Vec<&[u8]> = parties
//!     .filter_map(|entry| entry.get(448).map(|field| field.value))
//!     .collect();
//! assert_eq!(ids, [&b"BROKER-A"[..], &b"BROKER-B"[..]]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Guarantees
//!
//! - **Whole-group check, never a partial view.** Reading a group walks its
//!   whole instance first, nested groups included, with the same positional
//!   walk the [`Validator`](crate::Validator) uses. A count that does not
//!   match the entries, an entry not led by the delimiter, a tag repeated
//!   inside an entry, or an unparseable count is a [`GroupError`]; an
//!   absent group is `Ok(None)`.
//! - **Top-level means top-level.** [`MessageLayout::read`] finds the count
//!   field at the message level only: the same tag inside another group's
//!   entries is skipped with that group.
//! - **No allocation on the read path.** Reading, iterating entries, looking
//!   up fields and reading nested groups borrow ranges of the message's field
//!   list and allocate nothing, for every group whose entry level has at most
//!   1024 member tags (every group of the embedded dictionaries).
//!   `tests/group_reader_allocations.rs` proves it with a counting allocator.
//! - **Counts are digits.** A count is one or more ASCII digits fitting in a
//!   `u64`; `+1`, `-1`, `abc` and overflowing values are
//!   [`GroupError::InvalidCount`].
//!
//! # Static layouts
//!
//! [`GroupSpec::new`] and [`GroupSet::new`] are `const fn`s over sorted
//! `&'static [u32]` tag lists, so generated code can describe a message's
//! groups as `static` data, with no dictionary at run time, and read them the
//! same way. Their arguments are checked at construction, so a mistake in
//! generated tables is a compile-time error.

use crate::composition::SessionDictionary;
use crate::schema::Dictionary;
use crate::scope::{LayoutGroup, ScopeBuilder};
use crate::validator::{MAX_SCOPE_DEPTH, ValidationError, resolve};
use crate::walk::{self, Skip, Visitor};
use ironfix_core::field::FieldRef;
use ironfix_core::message::RawMessage;
use std::iter::FusedIterator;

/// Why a group cannot be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GroupError {
    /// The dictionary does not define the message type a layout was asked for.
    #[error("message type `{msg_type}` is not defined in the dictionary")]
    UnknownMsgType {
        /// The message type asked for.
        msg_type: String,
    },
    /// The message's schema could not be expanded (it nests too deep, is too
    /// large, or references an undefined component).
    #[error("message schema cannot be laid out: {0}")]
    InvalidSchema(ValidationError),
    /// The layout describes another message type than the message read.
    #[error("layout is for message type `{expected}`, but the message is `{found}`")]
    MsgTypeMismatch {
        /// The layout's message type.
        expected: String,
        /// The message's type.
        found: String,
    },
    /// The group asked for is not part of the layout (or, for a nested read,
    /// not nested in the entry's group).
    #[error("group {count_tag} is not part of this layout")]
    NotInLayout {
        /// The count tag asked for.
        count_tag: u32,
    },
    /// The group's count field appears more than once at the message level.
    #[error("group {count_tag} appears more than once at the message level")]
    DuplicateGroup {
        /// Count tag of the group.
        count_tag: u32,
    },
    /// A count field does not hold one or more ASCII digits fitting a `u64`.
    #[error("count field {count_tag} does not hold a non-negative integer")]
    InvalidCount {
        /// Count tag of the group (the read group or one nested in it).
        count_tag: u32,
    },
    /// A group declares a different number of entries than follow it.
    #[error("group {count_tag} declares {declared} entries but {actual} follow it")]
    CountMismatch {
        /// Count tag of the group (the read group or one nested in it).
        count_tag: u32,
        /// Declared entry count.
        declared: u64,
        /// Entries found.
        actual: u64,
    },
    /// An entry does not start with the group's delimiter tag.
    #[error("group {count_tag} entries must start with tag {expected}, found tag {found}")]
    DelimiterMismatch {
        /// Count tag of the group (the read group or one nested in it).
        count_tag: u32,
        /// The delimiter tag.
        expected: u32,
        /// The tag found where an entry should have started.
        found: u32,
    },
    /// A tag appears more than once in one entry.
    #[error("tag {tag} appears more than once in an entry of group {count_tag}")]
    RepeatedTag {
        /// Count tag of the group (the read group or one nested in it).
        count_tag: u32,
        /// The repeated tag.
        tag: u32,
    },
    /// Groups nest deeper than [`MAX_SCOPE_DEPTH`].
    #[error("group {count_tag} nests deeper than the limit of {limit}")]
    TooDeep {
        /// Count tag of the group at which the limit was reached.
        count_tag: u32,
        /// The nesting limit.
        limit: usize,
    },
}

/// Why a [`GroupSpec`] or [`GroupSet`] cannot be built from static tables.
///
/// `Copy` and drop-free, so the constructors can run in a `const` context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SpecError {
    /// The member tags are not strictly ascending.
    #[error("members of group {count_tag} are not strictly ascending")]
    UnsortedMembers {
        /// Count tag of the group.
        count_tag: u32,
    },
    /// The delimiter is not one of the member tags.
    #[error("delimiter {delimiter_tag} of group {count_tag} is not one of its members")]
    DelimiterNotMember {
        /// Count tag of the group.
        count_tag: u32,
        /// The delimiter tag.
        delimiter_tag: u32,
    },
    /// The nested groups are not strictly ascending by count tag.
    #[error("nested groups of group {count_tag} are not strictly ascending by count tag")]
    UnsortedNested {
        /// Count tag of the group.
        count_tag: u32,
    },
    /// A nested group's count tag is not one of the member tags.
    #[error("nested group {nested_count_tag} of group {count_tag} is not one of its members")]
    NestedNotMember {
        /// Count tag of the group.
        count_tag: u32,
        /// Count tag of the nested group.
        nested_count_tag: u32,
    },
    /// The groups of a set are not strictly ascending by count tag.
    #[error("the groups of a set are not strictly ascending by count tag")]
    UnsortedGroups,
}

/// Returns true if `tags` is strictly ascending.
const fn strictly_ascending(tags: &[u32]) -> bool {
    let mut rest = tags;
    let mut previous: Option<u32> = None;
    while let [head, tail @ ..] = rest {
        if let Some(previous) = previous
            && *head <= previous
        {
            return false;
        }
        previous = Some(*head);
        rest = tail;
    }
    true
}

/// Returns true if `tag` is in `tags`.
const fn contains(tags: &[u32], tag: u32) -> bool {
    let mut rest = tags;
    while let [head, tail @ ..] = rest {
        if *head == tag {
            return true;
        }
        rest = tail;
    }
    false
}

/// Returns true if `groups` is strictly ascending by count tag.
const fn groups_ascending(groups: &[GroupSpec<'_>]) -> bool {
    let mut rest = groups;
    let mut previous: Option<u32> = None;
    while let [head, tail @ ..] = rest {
        let tag = head.count_tag();
        if let Some(previous) = previous
            && tag <= previous
        {
            return false;
        }
        previous = Some(tag);
        rest = tail;
    }
    true
}

/// How a [`GroupSpec`] is stored.
#[derive(Debug, Clone, Copy)]
enum SpecRepr<'s> {
    /// Built from static tables.
    Static {
        count_tag: u32,
        delimiter_tag: u32,
        members: &'s [u32],
        nested: &'s [GroupSpec<'s>],
    },
    /// Borrowed from a [`MessageLayout`] built from a dictionary.
    Layout(&'s LayoutGroup),
}

/// The structure of one repeating group: its count tag, its delimiter, the
/// tags that may appear at an entry's own level, and the groups nested in an
/// entry.
///
/// Borrowed from a [`MessageLayout`], or built from static tables with
/// [`GroupSpec::new`]. Cheap to copy.
#[derive(Debug, Clone, Copy)]
pub struct GroupSpec<'s> {
    repr: SpecRepr<'s>,
}

impl<'s> GroupSpec<'s> {
    /// Describes a group from static tables.
    ///
    /// # Arguments
    /// * `count_tag` - Tag of the count field (NumInGroup)
    /// * `delimiter_tag` - Tag every entry starts with
    /// * `members` - Every tag that may appear at an entry's own level,
    ///   strictly ascending: the delimiter, the member fields (those of
    ///   components included), and the count tags of nested groups. Not the
    ///   members of nested groups, which belong to their own specs.
    /// * `nested` - The groups nested in an entry, strictly ascending by
    ///   count tag
    ///
    /// # Errors
    /// Returns a [`SpecError`] if `members` is not strictly ascending, does
    /// not contain the delimiter or a nested group's count tag, or if `nested`
    /// is not strictly ascending. In a `const` item, matching the error to a
    /// `panic!` turns a bad table into a compile error.
    ///
    /// # Examples
    ///
    /// ```
    /// use ironfix_dictionary::{GroupSpec, SpecError};
    ///
    /// // FIX 4.4 NoPartySubIDs(802), nested in NoPartyIDs(453).
    /// const SUB_IDS: GroupSpec<'static> = match GroupSpec::new(802, 523, &[523, 803], &[]) {
    ///     Ok(spec) => spec,
    ///     Err(_) => panic!("bad NoPartySubIDs table"),
    /// };
    /// const PARTIES: GroupSpec<'static> =
    ///     match GroupSpec::new(453, 448, &[447, 448, 452, 802], &[SUB_IDS]) {
    ///         Ok(spec) => spec,
    ///         Err(_) => panic!("bad NoPartyIDs table"),
    ///     };
    /// assert_eq!(PARTIES.nested(802).map(|spec| spec.delimiter_tag()), Some(523));
    /// assert_eq!(
    ///     GroupSpec::new(453, 448, &[452, 448], &[]).err(),
    ///     Some(SpecError::UnsortedMembers { count_tag: 453 })
    /// );
    /// ```
    pub const fn new(
        count_tag: u32,
        delimiter_tag: u32,
        members: &'s [u32],
        nested: &'s [GroupSpec<'s>],
    ) -> Result<Self, SpecError> {
        if !strictly_ascending(members) {
            return Err(SpecError::UnsortedMembers { count_tag });
        }
        if !contains(members, delimiter_tag) {
            return Err(SpecError::DelimiterNotMember {
                count_tag,
                delimiter_tag,
            });
        }
        if !groups_ascending(nested) {
            return Err(SpecError::UnsortedNested { count_tag });
        }
        let mut rest = nested;
        while let [head, tail @ ..] = rest {
            let nested_count_tag = head.count_tag();
            if !contains(members, nested_count_tag) {
                return Err(SpecError::NestedNotMember {
                    count_tag,
                    nested_count_tag,
                });
            }
            rest = tail;
        }
        Ok(Self {
            repr: SpecRepr::Static {
                count_tag,
                delimiter_tag,
                members,
                nested,
            },
        })
    }

    /// Borrows a group of a dictionary-built layout.
    pub(crate) const fn from_layout(group: &'s LayoutGroup) -> Self {
        Self {
            repr: SpecRepr::Layout(group),
        }
    }

    /// Returns the layout node this spec borrows, if it came from a
    /// dictionary.
    pub(crate) const fn layout(&self) -> Option<&'s LayoutGroup> {
        match self.repr {
            SpecRepr::Layout(group) => Some(group),
            SpecRepr::Static { .. } => None,
        }
    }

    /// Returns the tag of the count field (NumInGroup).
    #[must_use]
    pub const fn count_tag(&self) -> u32 {
        match self.repr {
            SpecRepr::Static { count_tag, .. } => count_tag,
            SpecRepr::Layout(group) => group.count_tag,
        }
    }

    /// Returns the tag every entry starts with.
    #[must_use]
    pub const fn delimiter_tag(&self) -> u32 {
        match self.repr {
            SpecRepr::Static { delimiter_tag, .. } => delimiter_tag,
            SpecRepr::Layout(group) => group.delimiter_tag,
        }
    }

    /// Returns the tags that may appear at an entry's own level, ascending:
    /// the delimiter, the member fields, and the count tags of nested groups.
    #[must_use]
    pub fn members(&self) -> &'s [u32] {
        match self.repr {
            SpecRepr::Static { members, .. } => members,
            SpecRepr::Layout(group) => &group.entry.members,
        }
    }

    /// Returns true if `tag` may appear at an entry's own level.
    #[must_use]
    pub fn is_member(&self, tag: u32) -> bool {
        self.members().binary_search(&tag).is_ok()
    }

    /// Returns the group nested in an entry whose count field is `count_tag`.
    #[must_use]
    pub fn nested(&self, count_tag: u32) -> Option<GroupSpec<'s>> {
        self.nested_groups().get(count_tag)
    }

    /// Returns the groups nested in an entry.
    #[must_use]
    pub fn nested_groups(&self) -> GroupSet<'s> {
        match self.repr {
            SpecRepr::Static { nested, .. } => GroupSet {
                repr: SetRepr::Static(nested),
            },
            SpecRepr::Layout(group) => GroupSet {
                repr: SetRepr::Layout(&group.entry.groups),
            },
        }
    }
}

/// How a [`GroupSet`] is stored.
#[derive(Debug, Clone, Copy)]
enum SetRepr<'s> {
    Static(&'s [GroupSpec<'s>]),
    Layout(&'s [LayoutGroup]),
}

/// Sibling groups, searchable by count tag: the groups that may open at a
/// message's top level, or the groups nested in one entry.
#[derive(Debug, Clone, Copy)]
pub struct GroupSet<'s> {
    repr: SetRepr<'s>,
}

impl<'s> GroupSet<'s> {
    /// Describes a message's top-level groups from static tables.
    ///
    /// # Errors
    /// Returns [`SpecError::UnsortedGroups`] unless `groups` is strictly
    /// ascending by count tag.
    pub const fn new(groups: &'s [GroupSpec<'s>]) -> Result<Self, SpecError> {
        if groups_ascending(groups) {
            Ok(Self {
                repr: SetRepr::Static(groups),
            })
        } else {
            Err(SpecError::UnsortedGroups)
        }
    }

    /// Returns the number of groups in the set.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self.repr {
            SetRepr::Static(groups) => groups.len(),
            SetRepr::Layout(groups) => groups.len(),
        }
    }

    /// Returns true if the set has no group.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the group whose count field is `count_tag`.
    #[must_use]
    pub fn get(&self, count_tag: u32) -> Option<GroupSpec<'s>> {
        match self.repr {
            SetRepr::Static(groups) => groups
                .binary_search_by_key(&count_tag, GroupSpec::count_tag)
                .ok()
                .and_then(|index| groups.get(index))
                .copied(),
            SetRepr::Layout(groups) => groups
                .binary_search_by_key(&count_tag, |group| group.count_tag)
                .ok()
                .and_then(|index| groups.get(index))
                .map(GroupSpec::from_layout),
        }
    }

    /// Returns the groups, ascending by count tag.
    pub fn iter(&self) -> impl Iterator<Item = GroupSpec<'s>> + 's {
        let (statics, layouts): (&'s [GroupSpec<'s>], &'s [LayoutGroup]) = match self.repr {
            SetRepr::Static(groups) => (groups, &[]),
            SetRepr::Layout(groups) => (&[], groups),
        };
        statics
            .iter()
            .copied()
            .chain(layouts.iter().map(GroupSpec::from_layout))
    }

    /// Reads the group whose count field is `count_tag` at the message level
    /// of `msg`.
    ///
    /// The count field is looked for at the message level only: the runs of
    /// the other groups of the set are skipped, so the same tag inside one of
    /// their entries is not taken for it. The whole instance is then checked,
    /// nested groups included, before any view is handed out.
    ///
    /// # Errors
    /// [`GroupError::NotInLayout`] if `count_tag` is not a group of the set,
    /// [`GroupError::DuplicateGroup`] if its count field appears twice at the
    /// message level, and the structural errors of [`GroupError`] for a
    /// malformed instance.
    pub fn read<'m, 'a>(
        &self,
        msg: &'m RawMessage<'a>,
        count_tag: u32,
    ) -> Result<Option<GroupEntries<'m, 'a, 's>>, GroupError> {
        let Some(spec) = self.get(count_tag) else {
            return Err(GroupError::NotInLayout { count_tag });
        };
        let fields = msg.field_slice();
        let mut found: Option<usize> = None;
        let mut index = 0;
        while let Some(field) = fields.get(index) {
            let Some(group) = self.get(field.tag) else {
                index += 1;
                continue;
            };
            if field.tag == count_tag {
                if found.is_some() {
                    return Err(GroupError::DuplicateGroup { count_tag });
                }
                found = Some(index);
            }
            index = walk::walk_group(fields, index, group, 0, &mut Skip);
        }
        match found {
            Some(index) => GroupEntries::checked(fields, index, spec, 0).map(Some),
            None => Ok(None),
        }
    }
}

/// The repeating-group structure of one message type, built once from a
/// dictionary.
///
/// Building allocates (the dictionary's schema is expanded and indexed);
/// reading with it does not. Components are flattened, so every group a
/// message can carry at its top level is found by its count tag, whichever
/// component declares it. Header and trailer groups (for example `NoHops`)
/// are included.
#[derive(Debug, Clone)]
pub struct MessageLayout {
    msg_type: String,
    groups: Vec<LayoutGroup>,
}

impl MessageLayout {
    /// Builds the layout of `msg_type` from one dictionary, which supplies the
    /// header, the trailer and the body.
    ///
    /// # Errors
    /// [`GroupError::UnknownMsgType`] if the dictionary does not define
    /// `msg_type`, [`GroupError::InvalidSchema`] if its schema cannot be
    /// expanded.
    pub fn new(dict: &Dictionary, msg_type: &str) -> Result<Self, GroupError> {
        Self::resolved(dict, dict, msg_type)
    }

    /// Builds the layout of `msg_type` for a FIXT.1.1 session: the header and
    /// trailer from the transport dictionary, the body from the dictionary
    /// that defines the message type (the transport for an admin message the
    /// transport defines, the application dictionary otherwise), exactly as
    /// [`Validator::for_session`](crate::Validator::for_session) resolves it.
    ///
    /// # Errors
    /// As [`MessageLayout::new`].
    pub fn for_session(
        session: &SessionDictionary<'_>,
        msg_type: &str,
    ) -> Result<Self, GroupError> {
        Self::resolved(session.transport(), session.application(), msg_type)
    }

    /// Builds the layout of `msg_type` with the header and trailer from
    /// `transport` and the body from the dictionary that defines it, as the
    /// validator resolves it. With a single dictionary, pass it as both.
    pub(crate) fn resolved(
        transport: &Dictionary,
        application: &Dictionary,
        msg_type: &str,
    ) -> Result<Self, GroupError> {
        let (msg_def, body) = resolve(transport, application, msg_type).ok_or_else(|| {
            GroupError::UnknownMsgType {
                msg_type: msg_type.to_string(),
            }
        })?;
        let (scope, errors) = ScopeBuilder::expand(transport, body, msg_def);
        if let Some(error) = errors.into_iter().next() {
            return Err(GroupError::InvalidSchema(error));
        }
        Ok(Self {
            msg_type: msg_type.to_string(),
            groups: scope.level.groups,
        })
    }

    /// Returns the message type this layout describes.
    #[must_use]
    pub fn msg_type(&self) -> &str {
        &self.msg_type
    }

    /// Returns the groups that may open at the message level.
    #[must_use]
    pub fn groups(&self) -> GroupSet<'_> {
        GroupSet {
            repr: SetRepr::Layout(&self.groups),
        }
    }

    /// Finds a group that may open at the message level by its count tag,
    /// wherever a component placed it.
    #[must_use]
    pub fn group(&self, count_tag: u32) -> Option<GroupSpec<'_>> {
        self.groups().get(count_tag)
    }

    /// Reads the group whose count field is `count_tag` at the message level
    /// of `msg`. See [`GroupSet::read`].
    ///
    /// # Errors
    /// [`GroupError::MsgTypeMismatch`] if `msg` is not of this layout's
    /// message type, and the errors of [`GroupSet::read`].
    pub fn read<'m, 'a>(
        &self,
        msg: &'m RawMessage<'a>,
        count_tag: u32,
    ) -> Result<Option<GroupEntries<'m, 'a, '_>>, GroupError> {
        let found = msg.msg_type().as_str();
        if found != self.msg_type {
            return Err(GroupError::MsgTypeMismatch {
                expected: self.msg_type.clone(),
                found: found.to_string(),
            });
        }
        self.groups().read(msg, count_tag)
    }
}

/// Records the first structural error of a walk.
#[derive(Default)]
struct FirstError {
    error: Option<GroupError>,
}

impl FirstError {
    fn record(&mut self, error: GroupError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }
}

impl<'s> Visitor<'s> for FirstError {
    fn invalid_count(&mut self, group: GroupSpec<'s>, _value: &[u8]) {
        self.record(GroupError::InvalidCount {
            count_tag: group.count_tag(),
        });
    }

    fn delimiter_mismatch(&mut self, group: GroupSpec<'s>, found: u32) {
        self.record(GroupError::DelimiterMismatch {
            count_tag: group.count_tag(),
            expected: group.delimiter_tag(),
            found,
        });
    }

    fn repeated_tag(&mut self, group: GroupSpec<'s>, tag: u32) {
        self.record(GroupError::RepeatedTag {
            count_tag: group.count_tag(),
            tag,
        });
    }

    fn count_mismatch(&mut self, group: GroupSpec<'s>, declared: u64, actual: u64) {
        self.record(GroupError::CountMismatch {
            count_tag: group.count_tag(),
            declared,
            actual,
        });
    }

    fn too_deep(&mut self, group: GroupSpec<'s>) {
        self.record(GroupError::TooDeep {
            count_tag: group.count_tag(),
            limit: MAX_SCOPE_DEPTH,
        });
    }
}

/// The entries of one checked group instance, in wire order.
///
/// Yields a [`GroupEntry`] per entry. Each step walks one entry; nothing is
/// collected or allocated.
#[derive(Debug, Clone)]
pub struct GroupEntries<'m, 'a, 's> {
    /// The message's fields.
    fields: &'m [FieldRef<'a>],
    spec: GroupSpec<'s>,
    /// Index of the next entry's delimiter.
    cursor: usize,
    /// Index just past the group's run.
    end: usize,
    /// Index of the next entry within the group.
    next_index: u64,
    /// Entries not yet yielded.
    remaining: usize,
    /// Nesting depth of the group.
    depth: usize,
}

impl<'m, 'a, 's> GroupEntries<'m, 'a, 's> {
    /// Checks the group instance whose count field is at `index` and, if it
    /// is well-formed, returns its entries.
    fn checked(
        fields: &'m [FieldRef<'a>],
        index: usize,
        spec: GroupSpec<'s>,
        depth: usize,
    ) -> Result<Self, GroupError> {
        let mut check = FirstError::default();
        let end = walk::walk_group(fields, index, spec, depth, &mut check);
        if let Some(error) = check.error {
            return Err(error);
        }
        let declared = fields
            .get(index)
            .and_then(|field| walk::parse_count(field.value))
            .ok_or(GroupError::InvalidCount {
                count_tag: spec.count_tag(),
            })?;
        // A well-formed group has exactly `declared` entries, each holding at
        // least its delimiter field, so the count fits in `usize`.
        let remaining = usize::try_from(declared).map_err(|_| GroupError::CountMismatch {
            count_tag: spec.count_tag(),
            declared,
            actual: 0,
        })?;
        Ok(Self {
            fields,
            spec,
            cursor: index + 1,
            end,
            next_index: 0,
            remaining,
            depth,
        })
    }

    /// Returns the group's structure.
    #[must_use]
    pub const fn spec(&self) -> GroupSpec<'s> {
        self.spec
    }

    /// Returns the tag of the group's count field.
    #[must_use]
    pub const fn count_tag(&self) -> u32 {
        self.spec.count_tag()
    }
}

impl<'m, 'a, 's> Iterator for GroupEntries<'m, 'a, 's> {
    type Item = GroupEntry<'m, 'a, 's>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.end || self.remaining == 0 {
            return None;
        }
        let start = self.cursor;
        let stop = walk::entry_end(self.fields, start, self.spec, self.depth);
        let entry_fields = self.fields.get(start..stop)?;
        let entry = GroupEntry {
            fields: entry_fields,
            spec: self.spec,
            index: self.next_index,
            depth: self.depth,
        };
        self.cursor = stop;
        self.next_index += 1;
        self.remaining -= 1;
        Some(entry)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for GroupEntries<'_, '_, '_> {}

impl FusedIterator for GroupEntries<'_, '_, '_> {}

/// One entry of a repeating group: a borrowed range of the message's fields.
#[derive(Debug, Clone, Copy)]
pub struct GroupEntry<'m, 'a, 's> {
    /// The entry's fields, its nested groups' included, in wire order.
    fields: &'m [FieldRef<'a>],
    spec: GroupSpec<'s>,
    index: u64,
    depth: usize,
}

impl<'m, 'a, 's> GroupEntry<'m, 'a, 's> {
    /// Returns the entry's 0-based index within its group instance.
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Returns the group's structure.
    #[must_use]
    pub const fn spec(&self) -> GroupSpec<'s> {
        self.spec
    }

    /// Returns the entry's fields in wire order, starting with its delimiter,
    /// the fields of groups nested in it included.
    #[must_use]
    pub const fn fields(&self) -> &'m [FieldRef<'a>] {
        self.fields
    }

    /// Returns the field `tag` at the entry's own level: a field of a group
    /// nested in the entry is not returned, even if it carries the same tag.
    #[must_use]
    pub fn get(&self, tag: u32) -> Option<&'m FieldRef<'a>> {
        self.find(tag).and_then(|index| self.fields.get(index))
    }

    /// Reads the group nested in this entry whose count field is `count_tag`.
    ///
    /// The nested instance was checked with the entry's group, so it cannot
    /// be malformed; it is `Ok(None)` when the entry does not carry it.
    ///
    /// # Errors
    /// [`GroupError::NotInLayout`] if no group with that count tag is nested
    /// in this entry's group.
    pub fn group(&self, count_tag: u32) -> Result<Option<GroupEntries<'m, 'a, 's>>, GroupError> {
        let Some(nested) = self.spec.nested(count_tag) else {
            return Err(GroupError::NotInLayout { count_tag });
        };
        match self.find(count_tag) {
            Some(index) => {
                GroupEntries::checked(self.fields, index, nested, self.depth + 1).map(Some)
            }
            None => Ok(None),
        }
    }

    /// Returns the position, within the entry, of `tag` at its own level.
    fn find(&self, tag: u32) -> Option<usize> {
        let mut index = 0;
        while let Some(field) = self.fields.get(index) {
            if field.tag == tag {
                return Some(index);
            }
            index = match self.spec.nested(field.tag) {
                Some(nested) => {
                    walk::walk_group(self.fields, index, nested, self.depth + 1, &mut Skip)
                }
                None => index + 1,
            };
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{ComponentDef, ComponentRef, MessageCategory, MessageDef, Version};
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

    /// Builds a frame of message type `msg_type` whose body is `body`, with
    /// a BodyLength (9) that matches it.
    fn frame(msg_type: &str, body: &[&str]) -> String {
        let mut text = format!("35={msg_type}{SOH}49=S{SOH}56=T{SOH}34=1{SOH}");
        for field in body {
            text.push_str(field);
            text.push(SOH);
        }
        format!("8=FIX.4.4{SOH}9={}{SOH}{text}10=000{SOH}", text.len())
    }

    /// Decodes a frame built by [`frame`].
    #[track_caller]
    fn decode(frame: &str) -> RawMessage<'_> {
        let mut decoder = Decoder::new(frame.as_bytes()).with_checksum_validation(false);
        ok(decoder.decode(), "test frame decodes")
    }

    #[track_caller]
    fn fix44_layout(msg_type: &str) -> MessageLayout {
        let dict = ok(Dictionary::fix44(), "FIX 4.4 loads");
        ok(MessageLayout::new(dict, msg_type), "FIX 4.4 layout builds")
    }

    /// The values of `tag` at the own level of every entry.
    fn values<'m>(entries: GroupEntries<'m, '_, '_>, tag: u32) -> Vec<&'m [u8]> {
        entries
            .map(|entry| entry.get(tag).map_or(&b""[..], |field| field.value))
            .collect()
    }

    /// A NewOrderSingle body carrying `parties` between ClOrdID and Symbol.
    fn order_with<'b>(parties: &[&'b str]) -> Vec<&'b str> {
        let mut body = vec!["11=ORDER-1"];
        body.extend_from_slice(parties);
        body.extend(["55=EURUSD", "54=1", "60=20260712-10:00:00", "40=1"]);
        body
    }

    #[test]
    fn test_read_single_group_yields_each_entry() {
        let layout = fix44_layout("D");
        let frame = frame(
            "D",
            &order_with(&[
                "453=2",
                "448=BROKER-A",
                "447=D",
                "452=1",
                "448=BROKER-B",
                "447=D",
                "452=3",
            ]),
        );
        let msg = decode(&frame);
        let Some(entries) = ok(layout.read(&msg, 453), "NoPartyIDs reads") else {
            panic!("NoPartyIDs is present");
        };
        assert_eq!(entries.len(), 2);
        assert_eq!(entries.count_tag(), 453);
        let collected: Vec<GroupEntry<'_, '_, '_>> = entries.collect();
        let (Some(first), Some(second)) = (collected.first(), collected.get(1)) else {
            panic!("two entries");
        };
        assert_eq!(collected.len(), 2);
        assert_eq!((first.index(), second.index()), (0, 1));
        assert_eq!(
            first.get(448).map(|field| field.value),
            Some(&b"BROKER-A"[..])
        );
        assert_eq!(second.get(452).map(|field| field.value), Some(&b"3"[..]));
        let tags: Vec<u32> = first.fields().iter().map(|field| field.tag).collect();
        assert_eq!(tags, vec![448, 447, 452]);
        // A tag outside the entry is not found in it.
        assert!(first.get(55).is_none());
        assert_eq!(first.spec().count_tag(), 453);
    }

    #[test]
    fn test_read_nested_group_through_its_component() {
        // NoPartySubIDs(802) is nested in NoPartyIDs through PtysSubGrp.
        let layout = fix44_layout("D");
        let frame = frame(
            "D",
            &order_with(&[
                "453=2",
                "448=BROKER-A",
                "447=D",
                "452=1",
                "802=2",
                "523=SUB-1",
                "803=1",
                "523=SUB-2",
                "803=2",
                "448=BROKER-B",
            ]),
        );
        let msg = decode(&frame);
        let Some(mut parties) = ok(layout.read(&msg, 453), "NoPartyIDs reads") else {
            panic!("NoPartyIDs is present");
        };
        let Some(first) = parties.next() else {
            panic!("first party");
        };
        let Some(sub_ids) = ok(first.group(802), "NoPartySubIDs reads") else {
            panic!("the first party carries NoPartySubIDs");
        };
        assert_eq!(values(sub_ids, 523), vec![&b"SUB-1"[..], &b"SUB-2"[..]]);
        // The nested fields belong to the entry's fields, not to its own level.
        assert_eq!(first.fields().len(), 8);
        assert!(first.get(523).is_none());
        let Some(second) = parties.next() else {
            panic!("second party");
        };
        assert!(ok(second.group(802), "absent nested group").is_none());
        assert!(parties.next().is_none());
        assert_eq!(
            first.group(9999).err(),
            Some(GroupError::NotInLayout { count_tag: 9999 })
        );
    }

    #[test]
    fn test_read_empty_group_yields_no_entry() {
        let layout = fix44_layout("D");
        let frame = frame("D", &order_with(&["453=0"]));
        let msg = decode(&frame);
        let Some(entries) = ok(layout.read(&msg, 453), "empty NoPartyIDs reads") else {
            panic!("NoPartyIDs is present with a count of 0");
        };
        assert_eq!(entries.len(), 0);
        assert_eq!(entries.count(), 0);
    }

    #[test]
    fn test_read_absent_group_is_none() {
        let layout = fix44_layout("D");
        let frame = frame("D", &order_with(&[]));
        let msg = decode(&frame);
        assert!(ok(layout.read(&msg, 453), "absent NoPartyIDs").is_none());
    }

    #[test]
    fn test_read_count_mismatch_is_a_typed_error() {
        let layout = fix44_layout("D");
        let frame = frame("D", &order_with(&["453=2", "448=BROKER-A", "447=D"]));
        let msg = decode(&frame);
        assert_eq!(
            layout.read(&msg, 453).err(),
            Some(GroupError::CountMismatch {
                count_tag: 453,
                declared: 2,
                actual: 1,
            })
        );
    }

    #[test]
    fn test_read_nested_count_mismatch_fails_the_whole_group() {
        // The outer group is fine; its nested NoPartySubIDs is not. The whole
        // group is checked up front, so no partial view is handed out.
        let layout = fix44_layout("D");
        let frame = frame(
            "D",
            &order_with(&["453=1", "448=BROKER-A", "802=2", "523=SUB-1"]),
        );
        let msg = decode(&frame);
        assert_eq!(
            layout.read(&msg, 453).err(),
            Some(GroupError::CountMismatch {
                count_tag: 802,
                declared: 2,
                actual: 1,
            })
        );
    }

    #[test]
    fn test_read_malformed_counts_are_typed_errors() {
        // A count is digits only. `+1` is refused even though `str::parse`
        // would take it, and so are a minus sign, a decimal point, letters,
        // and a value past u64::MAX.
        let layout = fix44_layout("D");
        for count in [
            "453=abc",
            "453=+1",
            "453=-1",
            "453=1.0",
            "453=18446744073709551616",
        ] {
            let frame = frame("D", &order_with(&[count, "448=BROKER-A"]));
            let msg = decode(&frame);
            assert_eq!(
                layout.read(&msg, 453).err(),
                Some(GroupError::InvalidCount { count_tag: 453 }),
                "{count}"
            );
        }
    }

    #[test]
    fn test_read_delimiter_mismatch_is_a_typed_error() {
        let layout = fix44_layout("D");
        let frame = frame("D", &order_with(&["453=1", "452=1", "448=BROKER-A"]));
        let msg = decode(&frame);
        assert_eq!(
            layout.read(&msg, 453).err(),
            Some(GroupError::DelimiterMismatch {
                count_tag: 453,
                expected: 448,
                found: 452,
            })
        );
    }

    #[test]
    fn test_read_repeated_tag_in_an_entry_is_a_typed_error() {
        let layout = fix44_layout("D");
        let frame = frame(
            "D",
            &order_with(&["453=2", "448=BROKER-A", "447=D", "447=D", "448=BROKER-B"]),
        );
        let msg = decode(&frame);
        assert_eq!(
            layout.read(&msg, 453).err(),
            Some(GroupError::RepeatedTag {
                count_tag: 453,
                tag: 447,
            })
        );
    }

    #[test]
    fn test_read_duplicate_top_level_group_is_a_typed_error() {
        let layout = fix44_layout("D");
        let frame = frame(
            "D",
            &[
                "11=ORDER-1",
                "453=1",
                "448=BROKER-A",
                "55=EURUSD",
                "453=1",
                "448=BROKER-B",
                "54=1",
            ],
        );
        let msg = decode(&frame);
        assert_eq!(
            layout.read(&msg, 453).err(),
            Some(GroupError::DuplicateGroup { count_tag: 453 })
        );
    }

    #[test]
    fn test_read_rejects_another_message_type_and_unknown_groups() {
        let layout = fix44_layout("D");
        let other = frame("8", &["453=0"]);
        let msg = decode(&other);
        assert_eq!(
            layout.read(&msg, 453).err(),
            Some(GroupError::MsgTypeMismatch {
                expected: "D".to_string(),
                found: "8".to_string(),
            })
        );

        let order = frame("D", &order_with(&[]));
        let msg = decode(&order);
        assert_eq!(
            layout.read(&msg, 9999).err(),
            Some(GroupError::NotInLayout { count_tag: 9999 })
        );
    }

    #[test]
    fn test_layout_unknown_message_type_is_a_typed_error() {
        let dict = ok(Dictionary::fix44(), "FIX 4.4 loads");
        assert_eq!(
            MessageLayout::new(dict, "U9").err(),
            Some(GroupError::UnknownMsgType {
                msg_type: "U9".to_string(),
            })
        );
    }

    #[test]
    fn test_layout_finds_groups_through_components_and_the_header() {
        let layout = fix44_layout("D");
        assert_eq!(layout.msg_type(), "D");
        // NoPartyIDs comes from the Parties component, NoHops from the header.
        assert_eq!(
            layout.group(453).map(|spec| spec.delimiter_tag()),
            Some(448)
        );
        assert_eq!(
            layout.group(627).map(|spec| spec.delimiter_tag()),
            Some(628)
        );
        // A nested group is not a top-level one.
        assert!(layout.group(802).is_none());
        assert_eq!(
            layout
                .group(453)
                .and_then(|spec| spec.nested(802))
                .map(|spec| spec.delimiter_tag()),
            Some(523)
        );
        let tags: Vec<u32> = layout
            .groups()
            .iter()
            .map(|spec| spec.count_tag())
            .collect();
        let mut sorted = tags.clone();
        sorted.sort_unstable();
        assert_eq!(tags, sorted);
        assert_eq!(layout.groups().len(), tags.len());
        assert!(!layout.groups().is_empty());
    }

    /// A dialect for the cases FIX 4.4 has no real message for.
    ///
    /// - `U4`: NoFirst(100) and NoSecond(101) share the delimiter 200.
    /// - `U5`: NoOuter(102) entries (delimiter 200, member Extra(300)) nest
    ///   NoInner(110) (delimiter 210, member Extra(300)), and NoInner may
    ///   also open at the message level.
    const DIALECT_XML: &str = r"<fix type='FIX' major='4' minor='4'>
        <header>
            <field name='BeginString' required='Y'/>
            <field name='BodyLength' required='Y'/>
            <field name='MsgType' required='Y'/>
        </header>
        <trailer><field name='CheckSum' required='Y'/></trailer>
        <messages>
            <message name='TwoGroups' msgtype='U4' msgcat='app'>
                <group name='NoFirst' required='N'>
                    <field name='Shared' required='Y'/>
                </group>
                <group name='NoSecond' required='N'>
                    <field name='Shared' required='Y'/>
                </group>
            </message>
            <message name='Nesting' msgtype='U5' msgcat='app'>
                <field name='Plain' required='N'/>
                <group name='NoOuter' required='N'>
                    <field name='Shared' required='Y'/>
                    <field name='Extra' required='N'/>
                    <group name='NoInner' required='N'>
                        <field name='InnerKey' required='Y'/>
                        <field name='Extra' required='N'/>
                    </group>
                </group>
                <group name='NoInner' required='N'>
                    <field name='InnerKey' required='Y'/>
                    <field name='Extra' required='N'/>
                </group>
            </message>
        </messages>
        <fields>
            <field number='8' name='BeginString' type='STRING'/>
            <field number='9' name='BodyLength' type='LENGTH'/>
            <field number='10' name='CheckSum' type='STRING'/>
            <field number='35' name='MsgType' type='STRING'/>
            <field number='55' name='Plain' type='STRING'/>
            <field number='100' name='NoFirst' type='NUMINGROUP'/>
            <field number='101' name='NoSecond' type='NUMINGROUP'/>
            <field number='102' name='NoOuter' type='NUMINGROUP'/>
            <field number='110' name='NoInner' type='NUMINGROUP'/>
            <field number='200' name='Shared' type='STRING'/>
            <field number='210' name='InnerKey' type='STRING'/>
            <field number='300' name='Extra' type='STRING'/>
        </fields>
    </fix>";

    #[track_caller]
    fn dialect_layout(msg_type: &str) -> MessageLayout {
        let dict = ok(Dictionary::from_quickfix_xml(DIALECT_XML), "dialect loads");
        ok(MessageLayout::new(&dict, msg_type), "dialect layout builds")
    }

    #[test]
    fn test_read_two_groups_sharing_a_delimiter_are_kept_apart() {
        let layout = dialect_layout("U4");
        let frame = frame(
            "U4",
            &[
                "100=1",
                "200=FIRST",
                "101=2",
                "200=SECOND-A",
                "200=SECOND-B",
            ],
        );
        let msg = decode(&frame);
        let Some(first) = ok(layout.read(&msg, 100), "NoFirst reads") else {
            panic!("NoFirst is present");
        };
        assert_eq!(values(first, 200), vec![&b"FIRST"[..]]);
        let Some(second) = ok(layout.read(&msg, 101), "NoSecond reads") else {
            panic!("NoSecond is present");
        };
        assert_eq!(
            values(second, 200),
            vec![&b"SECOND-A"[..], &b"SECOND-B"[..]]
        );
    }

    #[test]
    fn test_read_top_level_lookup_ignores_the_tag_inside_a_group() {
        let layout = dialect_layout("U5");
        // NoInner(110) appears only nested in a NoOuter entry.
        let nested_only = frame("U5", &["102=1", "200=A", "110=1", "210=NESTED"]);
        let msg = decode(&nested_only);
        assert!(ok(layout.read(&msg, 110), "top-level NoInner").is_none());

        // After the outer group ends (at Plain(55)), a top-level NoInner
        // follows; the nested one is still not taken for it.
        let both = frame(
            "U5",
            &[
                "102=1",
                "200=A",
                "110=1",
                "210=NESTED",
                "55=P",
                "110=1",
                "210=TOP",
            ],
        );
        let msg = decode(&both);
        let Some(top) = ok(layout.read(&msg, 110), "top-level NoInner") else {
            panic!("the top-level NoInner is present");
        };
        assert_eq!(values(top, 210), vec![&b"TOP"[..]]);
    }

    #[test]
    fn test_entry_get_ignores_a_nested_group_field_with_the_same_tag() {
        // Extra(300) is a member of both NoOuter and NoInner: in this entry
        // only the nested NoInner carries it, so the entry's own level lacks
        // it.
        let layout = dialect_layout("U5");
        let frame = frame("U5", &["102=1", "200=A", "110=1", "210=X", "300=NESTED"]);
        let msg = decode(&frame);
        let Some(mut outer) = ok(layout.read(&msg, 102), "NoOuter reads") else {
            panic!("NoOuter is present");
        };
        let Some(entry) = outer.next() else {
            panic!("one NoOuter entry");
        };
        assert!(entry.get(300).is_none());
        let Some(inner) = ok(entry.group(110), "nested NoInner reads") else {
            panic!("the entry carries NoInner");
        };
        assert_eq!(values(inner, 300), vec![&b"NESTED"[..]]);
    }

    #[test]
    fn test_read_group_led_by_a_nested_group_fix50sp2() {
        // FIX 5.0 SP2 StreamAssignmentRequest (35=CC): NoAsgnReqs(1499)
        // entries open with NoPartyIDs(453), its delimiter.
        let fixt11 = ok(Dictionary::fixt11(), "FIXT 1.1 loads");
        let fix50sp2 = ok(Dictionary::fix50sp2(), "FIX 5.0 SP2 loads");
        let session = ok(SessionDictionary::new(fixt11, fix50sp2), "pair composes");
        let composed = ok(
            MessageLayout::for_session(&session, "CC"),
            "CC layout builds",
        );
        let standalone = ok(MessageLayout::new(fix50sp2, "CC"), "CC layout builds");
        let requests_frame = frame(
            "CC",
            &[
                "1497=REQ-1",
                "1498=1",
                "1499=2",
                "453=1",
                "448=P1",
                "447=D",
                "452=1",
                "453=2",
                "448=P2",
                "447=D",
                "452=1",
                "448=P3",
                "447=D",
                "452=3",
            ],
        );
        let msg = decode(&requests_frame);
        for layout in [&composed, &standalone] {
            assert_eq!(
                layout.group(1499).map(|spec| spec.delimiter_tag()),
                Some(453)
            );
            let Some(requests) = ok(layout.read(&msg, 1499), "NoAsgnReqs reads") else {
                panic!("NoAsgnReqs is present");
            };
            let parties: Vec<Vec<&[u8]>> = requests
                .map(|entry| match entry.group(453) {
                    Ok(Some(parties)) => values(parties, 448),
                    _ => Vec::new(),
                })
                .collect();
            assert_eq!(
                parties,
                vec![vec![&b"P1"[..]], vec![&b"P2"[..], &b"P3"[..]]]
            );
        }

        let empty_frame = frame("CC", &["1497=REQ-1", "1498=1", "1499=1", "453=1"]);
        let msg = decode(&empty_frame);
        assert_eq!(
            composed.read(&msg, 1499).err(),
            Some(GroupError::CountMismatch {
                count_tag: 453,
                declared: 1,
                actual: 0,
            })
        );
    }

    /// FIX 4.4 NoPartySubIDs(802) and NoPartyIDs(453), as generated code
    /// would write them.
    const SUB_IDS: GroupSpec<'static> = match GroupSpec::new(802, 523, &[523, 803], &[]) {
        Ok(spec) => spec,
        Err(_) => panic!("bad NoPartySubIDs table"),
    };
    const PARTIES: GroupSpec<'static> =
        match GroupSpec::new(453, 448, &[447, 448, 452, 802], &[SUB_IDS]) {
            Ok(spec) => spec,
            Err(_) => panic!("bad NoPartyIDs table"),
        };
    const ORDER_GROUPS: GroupSet<'static> = match GroupSet::new(&[PARTIES]) {
        Ok(set) => set,
        Err(_) => panic!("bad NewOrderSingle group table"),
    };

    #[test]
    fn test_static_specs_read_like_the_dictionary_layout() {
        let frame = frame(
            "D",
            &order_with(&[
                "453=2",
                "448=BROKER-A",
                "802=1",
                "523=SUB-1",
                "448=BROKER-B",
                "452=3",
            ]),
        );
        let msg = decode(&frame);
        let Some(entries) = ok(ORDER_GROUPS.read(&msg, 453), "static NoPartyIDs reads") else {
            panic!("NoPartyIDs is present");
        };
        assert_eq!(
            values(entries, 448),
            vec![&b"BROKER-A"[..], &b"BROKER-B"[..]]
        );
        let layout = fix44_layout("D");
        let Some(from_layout) = ok(layout.read(&msg, 453), "layout NoPartyIDs reads") else {
            panic!("NoPartyIDs is present");
        };
        assert_eq!(
            values(from_layout, 448),
            vec![&b"BROKER-A"[..], &b"BROKER-B"[..]]
        );
        assert_eq!(ORDER_GROUPS.len(), 1);
        assert_eq!(PARTIES.members(), &[447, 448, 452, 802]);
        assert!(PARTIES.is_member(802));
        assert!(!PARTIES.is_member(523));
        assert_eq!(PARTIES.nested_groups().len(), 1);
    }

    #[test]
    fn test_static_spec_construction_errors() {
        assert_eq!(
            GroupSpec::new(453, 448, &[448, 447], &[]).err(),
            Some(SpecError::UnsortedMembers { count_tag: 453 })
        );
        assert_eq!(
            GroupSpec::new(453, 448, &[447, 448, 448], &[]).err(),
            Some(SpecError::UnsortedMembers { count_tag: 453 })
        );
        assert_eq!(
            GroupSpec::new(453, 448, &[447, 452], &[]).err(),
            Some(SpecError::DelimiterNotMember {
                count_tag: 453,
                delimiter_tag: 448,
            })
        );
        assert_eq!(
            GroupSpec::new(453, 448, &[448], &[SUB_IDS]).err(),
            Some(SpecError::NestedNotMember {
                count_tag: 453,
                nested_count_tag: 802,
            })
        );
        let Ok(other) = GroupSpec::new(700, 701, &[701], &[]) else {
            panic!("a one-member spec is valid");
        };
        assert_eq!(
            GroupSpec::new(453, 448, &[448, 700, 802], &[SUB_IDS, other]).err(),
            Some(SpecError::UnsortedNested { count_tag: 453 })
        );
        assert_eq!(
            GroupSet::new(&[SUB_IDS, PARTIES]).err(),
            Some(SpecError::UnsortedGroups)
        );
    }

    /// A chain of `depth` static groups, each nesting the next: group `k` has
    /// count tag `1000 + k` and delimiter `2000 + k`. The tables are leaked so
    /// they live as long as a `static` would.
    fn chain(depth: u32) -> Option<GroupSpec<'static>> {
        let mut spec: Option<GroupSpec<'static>> = None;
        for level in (0..depth).rev() {
            let delimiter = 2000 + level;
            let (members, nested): (Vec<u32>, Vec<GroupSpec<'static>>) = match spec {
                Some(child) => (vec![child.count_tag(), delimiter], vec![child]),
                None => (vec![delimiter], Vec::new()),
            };
            let members: &'static [u32] = Box::leak(members.into_boxed_slice());
            let nested: &'static [GroupSpec<'static>] = Box::leak(nested.into_boxed_slice());
            spec = GroupSpec::new(1000 + level, delimiter, members, nested).ok();
        }
        spec
    }

    /// One single-entry instance per level of a [`chain`].
    fn chain_body(depth: u32) -> Vec<String> {
        (0..depth)
            .flat_map(|level| [format!("{}=1", 1000 + level), format!("{}=x", 2000 + level)])
            .collect()
    }

    #[test]
    fn test_read_static_chain_past_the_depth_limit_is_a_typed_error() {
        let limit = u32::try_from(MAX_SCOPE_DEPTH).unwrap_or(u32::MAX);
        for (depth, expected) in [
            (limit + 1, None),
            (
                limit + 2,
                Some(GroupError::TooDeep {
                    count_tag: 1000 + limit + 1,
                    limit: MAX_SCOPE_DEPTH,
                }),
            ),
        ] {
            let Some(top) = chain(depth) else {
                panic!("the chain builds");
            };
            let groups = [top];
            let Ok(set) = GroupSet::new(&groups) else {
                panic!("a one-group set is valid");
            };
            let body = chain_body(depth);
            let body: Vec<&str> = body.iter().map(String::as_str).collect();
            let frame = frame("U1", &body);
            let msg = decode(&frame);
            assert_eq!(set.read(&msg, 1000).err(), expected, "depth {depth}");
        }
    }

    #[test]
    fn test_layout_of_a_schema_past_the_depth_limit_is_a_typed_error() {
        // Hand-built: the loader would refuse a component chain this deep.
        let mut dict = Dictionary::new(Version::Fix44);
        let links = MAX_SCOPE_DEPTH + 5;
        for index in 0..links {
            dict.add_component(ComponentDef {
                name: format!("C{index}"),
                fields: Vec::new(),
                groups: Vec::new(),
                components: vec![ComponentRef::new(format!("C{}", index + 1), true)],
            });
        }
        dict.add_message(MessageDef {
            msg_type: "U1".to_string(),
            name: "Deep".to_string(),
            category: MessageCategory::App,
            fields: Vec::new(),
            groups: Vec::new(),
            components: vec![ComponentRef::new("C0", true)],
        });
        assert!(matches!(
            MessageLayout::new(&dict, "U1").err(),
            Some(GroupError::InvalidSchema(
                ValidationError::SchemaTooDeep { .. }
            ))
        ));
    }

    #[test]
    fn test_parse_count_accepts_digits_only() {
        assert_eq!(walk::parse_count(b"0"), Some(0));
        assert_eq!(walk::parse_count(b"007"), Some(7));
        assert_eq!(walk::parse_count(b"18446744073709551615"), Some(u64::MAX));
        for bad in [
            &b""[..],
            b"+1",
            b"-1",
            b" 1",
            b"1 ",
            b"1e3",
            b"18446744073709551616",
        ] {
            assert_eq!(walk::parse_count(bad), None, "{bad:?}");
        }
    }
}
