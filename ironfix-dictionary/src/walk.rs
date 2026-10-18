/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! The positional repeating-group walk shared by the validator and the reader.
//!
//! A group instance starts at its count field. [`walk_group`] consumes the
//! run of fields that belong to the group: an entry opens at every delimiter
//! tag, a field that is not a member of the group's entry level ends the run,
//! and a member that is a nested group's count tag hands over to a nested
//! walk, which consumes that group's own run (also when the nested group is
//! the delimiter that opens the entry). The walk reports what it finds to a
//! [`Visitor`]; the validator turns the events into
//! [`ValidationError`](crate::ValidationError)s, the reader into a
//! [`GroupError`](crate::GroupError) or a pass, so both agree on entry
//! boundaries by construction.
//!
//! The walk allocates nothing for a group whose entry level has at most
//! [`INLINE_MEMBERS`] members (every group of the embedded dictionaries; the
//! widest, FIX 5.0 SP2 `NoMDEntries`, has 412): the tags seen in an entry are
//! tracked in a fixed bitset on the stack, indexed by the tag's rank in the
//! group's sorted member list, and only the words a group uses are cleared
//! per entry. A wider group spills that bitset to the heap, one allocation
//! per group instance walked. Recursion is bounded by [`MAX_SCOPE_DEPTH`].

use crate::group::GroupSpec;
use crate::validator::MAX_SCOPE_DEPTH;
use ironfix_core::field::FieldRef;

/// Entry-level members a group may have before its seen-tag set spills to
/// the heap.
///
/// 512 covers the widest group of the embedded dictionaries (412 members)
/// with room to spare, in 64 bytes of stack per nested walk.
pub(crate) const INLINE_MEMBERS: usize = 512;

/// Words of the inline seen-tag bitset.
const INLINE_WORDS: usize = INLINE_MEMBERS / 64;

/// Events of one walk. Every method defaults to doing nothing.
pub(crate) trait Visitor<'s> {
    /// Whether the walk tracks the tags of each entry. A visitor that only
    /// needs entry boundaries turns it off, which also skips repeated-tag
    /// detection and [`Visitor::entry_closed`]'s seen set.
    const TRACK: bool = true;

    /// A group instance starts.
    fn enter_group(&mut self, _group: GroupSpec<'s>) {}
    /// The count field does not hold a non-negative integer.
    fn invalid_count(&mut self, _group: GroupSpec<'s>, _value: &[u8]) {}
    /// A member appears before any delimiter.
    fn delimiter_mismatch(&mut self, _group: GroupSpec<'s>, _found: u32) {}
    /// A tag appears twice in one entry.
    fn repeated_tag(&mut self, _group: GroupSpec<'s>, _tag: u32) {}
    /// An entry ended; `seen` holds the tags at its own level.
    fn entry_closed(&mut self, _group: GroupSpec<'s>, _entry: u64, _seen: &EntryTags<'s>) {}
    /// The declared count is not the number of entries found.
    fn count_mismatch(&mut self, _group: GroupSpec<'s>, _declared: u64, _actual: u64) {}
    /// The group nests past [`MAX_SCOPE_DEPTH`]; it is not walked.
    fn too_deep(&mut self, _group: GroupSpec<'s>) {}
    /// The group instance ended, well-formed or not, after `entries`
    /// entries. When it is well-formed, `entries` is its declared count.
    fn leave_group(&mut self, _group: GroupSpec<'s>, _well_formed: bool, _entries: u64) {}
}

/// A visitor that only wants entry boundaries.
pub(crate) struct Skip;

impl Visitor<'_> for Skip {
    const TRACK: bool = false;
}

/// Storage of an [`EntryTags`] set.
#[derive(Debug)]
enum Bits {
    /// Up to [`INLINE_MEMBERS`] members, on the stack.
    Inline([u64; INLINE_WORDS]),
    /// A wider group, on the heap.
    Heap(Vec<u64>),
}

/// The tags seen at one entry's own level, as a bitset indexed by each tag's
/// rank in the group's sorted member list.
#[derive(Debug)]
pub(crate) struct EntryTags<'s> {
    group: GroupSpec<'s>,
    bits: Bits,
    /// Words the group's member count needs: the only ones ever touched.
    used: usize,
}

impl<'s> EntryTags<'s> {
    fn new(group: GroupSpec<'s>) -> Self {
        let members = group.members().len();
        let used = members.div_ceil(64);
        let bits = if members <= INLINE_MEMBERS {
            Bits::Inline([0; INLINE_WORDS])
        } else {
            Bits::Heap(vec![0; used])
        };
        Self { group, bits, used }
    }

    fn words(&self) -> &[u64] {
        let words: &[u64] = match &self.bits {
            Bits::Inline(words) => words,
            Bits::Heap(words) => words,
        };
        words.get(..self.used).unwrap_or(words)
    }

    fn words_mut(&mut self) -> &mut [u64] {
        let used = self.used;
        let words: &mut [u64] = match &mut self.bits {
            Bits::Inline(words) => words,
            Bits::Heap(words) => words,
        };
        let len = words.len();
        match words.get_mut(..used.min(len)) {
            Some(words) => words,
            None => &mut [],
        }
    }

    fn clear(&mut self) {
        self.words_mut().fill(0);
    }

    /// Word index and bit mask of the member ranked `rank`.
    const fn slot(rank: usize) -> (usize, u64) {
        (rank / 64, 1 << (rank % 64))
    }

    /// Records the member ranked `rank`, returning false if it was already
    /// recorded.
    fn insert_rank(&mut self, rank: usize) -> bool {
        let (word, mask) = Self::slot(rank);
        match self.words_mut().get_mut(word) {
            Some(bits) if *bits & mask != 0 => false,
            Some(bits) => {
                *bits |= mask;
                true
            }
            None => true,
        }
    }

    /// Returns true if `tag` appeared at the entry's own level.
    pub(crate) fn contains(&self, tag: u32) -> bool {
        let Ok(rank) = self.group.members().binary_search(&tag) else {
            return false;
        };
        let (word, mask) = Self::slot(rank);
        self.words().get(word).is_some_and(|bits| bits & mask != 0)
    }
}

/// Parses a group count: one or more ASCII digits, fitting in a `u64`.
///
/// A sign is refused, `+` included even though [`str::parse`] would take it:
/// a FIX `NumInGroup` is a non-negative integer of digits only.
pub(crate) fn parse_count(value: &[u8]) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    let mut count: u64 = 0;
    for byte in value {
        if !byte.is_ascii_digit() {
            return None;
        }
        count = count.checked_mul(10)?.checked_add(u64::from(byte - b'0'))?;
    }
    Some(count)
}

/// Walks one group instance, starting at its count field at `index`, and
/// returns the index of the first field after the group.
///
/// `depth` is the group's nesting depth (0 for a group at the message level);
/// past [`MAX_SCOPE_DEPTH`] the group is reported through
/// [`Visitor::too_deep`] and only its count field is consumed.
pub(crate) fn walk_group<'s, V: Visitor<'s>>(
    fields: &[FieldRef<'_>],
    index: usize,
    group: GroupSpec<'s>,
    depth: usize,
    visitor: &mut V,
) -> usize {
    let Some(count_field) = fields.get(index) else {
        return index;
    };
    if depth > MAX_SCOPE_DEPTH {
        visitor.too_deep(group);
        return index + 1;
    }
    visitor.enter_group(group);
    let declared = parse_count(count_field.value);
    if declared.is_none() {
        visitor.invalid_count(group, count_field.value);
    }

    let delimiter = group.delimiter_tag();
    let mut seen = if V::TRACK {
        Some(EntryTags::new(group))
    } else {
        None
    };
    let mut cursor = index + 1;
    let mut entries: u64 = 0;
    let mut unparseable = false;

    // Members ahead of any delimiter: the first entry is not delimiter-led,
    // so the group cannot be split into entries unambiguously. They are
    // walked as one entry so the run still ends where it would.
    if let Some(field) = fields.get(cursor)
        && field.tag != delimiter
        && group.is_member(field.tag)
    {
        visitor.delimiter_mismatch(group, field.tag);
        unparseable = true;
        cursor = scan_entry(
            fields,
            cursor,
            group,
            depth,
            visitor,
            seen.as_mut(),
            &mut unparseable,
        );
        if let Some(seen) = &seen {
            visitor.entry_closed(group, entries, seen);
        }
        entries = 1;
    }

    while let Some(field) = fields.get(cursor) {
        if field.tag != delimiter {
            // The previous entry ended at a field that is not a member: the
            // group ends here, and whatever follows belongs to the outer
            // level.
            break;
        }
        let Some(next) = entries.checked_add(1) else {
            break;
        };
        cursor = scan_entry(
            fields,
            cursor,
            group,
            depth,
            visitor,
            seen.as_mut(),
            &mut unparseable,
        );
        if let Some(seen) = &seen {
            visitor.entry_closed(group, entries, seen);
        }
        entries = next;
    }

    let mut well_formed = !unparseable;
    match declared {
        Some(declared) if declared != entries => {
            if !unparseable {
                visitor.count_mismatch(group, declared, entries);
            }
            well_formed = false;
        }
        Some(_) => {}
        None => well_formed = false,
    }
    visitor.leave_group(group, well_formed, entries);
    cursor
}

/// Returns the index just past the entry that starts at `start` (its
/// delimiter), walking the group's nested groups on the way.
///
/// Only for a group already known to be well-formed: nothing is reported.
pub(crate) fn entry_end(
    fields: &[FieldRef<'_>],
    start: usize,
    group: GroupSpec<'_>,
    depth: usize,
) -> usize {
    let mut unparseable = false;
    scan_entry(
        fields,
        start,
        group,
        depth,
        &mut Skip,
        None,
        &mut unparseable,
    )
}

/// Consumes one entry starting at `start`: its own fields, and the runs of
/// the groups nested in it. Stops at the next delimiter (the next entry) or
/// at the first field that is not a member (the end of the group).
fn scan_entry<'s, V: Visitor<'s>>(
    fields: &[FieldRef<'_>],
    start: usize,
    group: GroupSpec<'s>,
    depth: usize,
    visitor: &mut V,
    mut seen: Option<&mut EntryTags<'s>>,
    unparseable: &mut bool,
) -> usize {
    if let Some(seen) = seen.as_deref_mut() {
        seen.clear();
    }
    let members = group.members();
    let delimiter = group.delimiter_tag();
    let nested_groups = group.nested_groups();
    let has_nested = !nested_groups.is_empty();
    let mut cursor = start;
    while let Some(field) = fields.get(cursor) {
        let tag = field.tag;
        // One search answers both "is it a member" and its bitset slot.
        let Ok(rank) = members.binary_search(&tag) else {
            break;
        };
        if cursor > start && tag == delimiter {
            break;
        }
        if let Some(seen) = seen.as_deref_mut()
            && !seen.insert_rank(rank)
        {
            visitor.repeated_tag(group, tag);
            *unparseable = true;
        }
        let nested = if has_nested {
            nested_groups.get(tag)
        } else {
            None
        };
        cursor = match nested {
            // The delimiter can itself be a nested group's count tag (FIX 5.0
            // SP2 NoAsgnReqs(1499) entries open with NoPartyIDs(453)): its
            // members follow it, so it is walked like any nested group.
            Some(nested) => walk_group(fields, cursor, nested, depth + 1, visitor),
            None => cursor + 1,
        };
    }
    cursor
}
