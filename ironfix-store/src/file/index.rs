/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! The in-memory index of a [`FileStore`](super::FileStore) journal: where
//! the record of each filed frame is.
//!
//! The index is the store's only per-message state. It is **dense** by
//! default: one 12-byte slot per sequence number, holding the record's file
//! offset and body length, all zeros for a number with nothing filed (a
//! hole). The slots live in fixed chunks of [`CHUNK_SLOTS`] (48 KiB each),
//! keyed by `seq - start`, `start` being the first number of the first chunk.
//! Filing a number past the last chunk allocates one new chunk and never
//! moves the slots already there, so a frame filed under the next number
//! costs no copy of the index; the list of chunks itself holds one pointer per
//! chunk. A lookup is a shift, a mask and two bounds-checked accesses.
//!
//! # Memory per outbound message
//!
//! 12 bytes per sequence number from the first number of the chunk holding
//! the lowest number filed to the last number of the chunk holding the
//! highest, filed or not: 12 bytes per number, plus at most two partly used
//! chunks (96 KiB) and 8 bytes per chunk for the list of chunks. The engine
//! files every sequenced outbound frame under consecutive numbers, so holes
//! are rare: a number spent without being filed (a failed write under
//! `StoreFailurePolicy::Continue`, a jump in an explicit seed).
//!
//! # Bounded against sequence jumps
//!
//! A jump in the numbers filed (a hostile journal, or a seed far from the
//! numbers already filed) must not make the store allocate a slot for every
//! number skipped. Between its lowest and its highest number the dense index
//! therefore holds at most [`MAX_DENSE_HOLES`] holes (768 KiB of them), in
//! either direction: a frame filed below the lowest number prepends chunks
//! within the same bound. A frame that would take it past that bound
//! switches the index to a **sparse** map (a `BTreeMap`, estimated at 40 to
//! 50 bytes per filed frame and nothing per hole) until the journal is next
//! reset, compacted or reloaded. Either way the memory is bounded by the
//! number of records in the journal, plus the hole bound.

use crate::file::format::IndexEntry;
use std::collections::btree_map;
use std::collections::{BTreeMap, VecDeque};

/// Slots per chunk: 4 096 (48 KiB). A power of two, so a number's chunk and
/// its place in it are a shift and a mask.
pub(crate) const CHUNK_SLOTS: usize = 4096;

/// `log2(CHUNK_SLOTS)`.
const CHUNK_SHIFT: u32 = CHUNK_SLOTS.trailing_zeros();

/// `CHUNK_SLOTS - 1`, as a mask on a position.
const CHUNK_MASK: u64 = CHUNK_SLOTS as u64 - 1;

const _: () = assert!(CHUNK_SLOTS.is_power_of_two());

/// Most holes (sequence numbers with nothing filed) the dense index holds
/// between its lowest and its highest number, 65 536: 768 KiB of slots. A
/// frame that would need more switches the index to the sparse map.
pub(crate) const MAX_DENSE_HOLES: u64 = 65_536;

/// One dense slot: a record's file offset, split in two halves so a slot is
/// 12 bytes with no padding, and its body length. All zeros is a hole: no
/// record starts at offset 0 (the journal header is there) and no record body
/// is empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Slot {
    /// Low 32 bits of the record's file offset.
    offset_low: u32,
    /// High 32 bits of the record's file offset.
    offset_high: u32,
    /// Length of the record body, in bytes; 0 for a hole.
    body_len: u32,
}

impl Slot {
    /// A sequence number with nothing filed.
    const HOLE: Self = Self {
        offset_low: 0,
        offset_high: 0,
        body_len: 0,
    };

    /// The slot for a record.
    const fn new(entry: IndexEntry) -> Self {
        Self {
            // Truncation to the low half is the point.
            offset_low: entry.offset as u32,
            offset_high: (entry.offset >> 32) as u32,
            body_len: entry.body_len,
        }
    }

    /// The record this slot points at, or `None` for a hole.
    const fn entry(self) -> Option<IndexEntry> {
        if self.body_len == 0 {
            return None;
        }
        Some(IndexEntry {
            offset: ((self.offset_high as u64) << 32) | self.offset_low as u64,
            body_len: self.body_len,
        })
    }
}

/// A fresh chunk of holes, allocated on the heap directly.
fn new_chunk() -> Box<[Slot]> {
    vec![Slot::HOLE; CHUNK_SLOTS].into_boxed_slice()
}

/// The dense representation: chunks of slots from `start` on.
#[derive(Debug, Default)]
struct Dense {
    /// The sequence number of the first slot of the first chunk, a multiple
    /// of [`CHUNK_SLOTS`].
    start: u64,
    /// The chunks, each [`CHUNK_SLOTS`] long.
    chunks: VecDeque<Box<[Slot]>>,
    /// The lowest number filed, when `filed` is not 0.
    lowest: u64,
    /// The highest number filed, when `filed` is not 0.
    highest: u64,
    /// How many numbers are filed.
    filed: u64,
}

/// Why a frame cannot go into the dense index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NotDense;

impl Dense {
    /// The chunk and the place in it of `seq`, if `seq` is not before
    /// `start`. The chunk may not exist yet.
    fn position(&self, seq: u64) -> Option<(usize, usize)> {
        let at = seq.checked_sub(self.start)?;
        let chunk = usize::try_from(at >> CHUNK_SHIFT).ok()?;
        let offset = usize::try_from(at & CHUNK_MASK).ok()?;
        Some((chunk, offset))
    }

    /// The slot of `seq`, if its chunk exists.
    fn slot(&self, seq: u64) -> Option<Slot> {
        let (chunk, offset) = self.position(seq)?;
        self.chunks.get(chunk)?.get(offset).copied()
    }

    /// The slot of `seq`, mutably, if its chunk exists.
    fn slot_mut(&mut self, seq: u64) -> Option<&mut Slot> {
        let (chunk, offset) = self.position(seq)?;
        self.chunks.get_mut(chunk)?.get_mut(offset)
    }

    /// The record filed under `seq`, if any.
    #[cfg(test)]
    fn get(&self, seq: u64) -> Option<IndexEntry> {
        if self.filed == 0 || seq < self.lowest || seq > self.highest {
            return None;
        }
        self.slot(seq).and_then(Slot::entry)
    }

    /// Files `entry` under `seq`, returning the entry it replaced, or
    /// [`NotDense`] if that would take the index past the hole bound. On
    /// [`NotDense`] nothing changed.
    fn insert(&mut self, seq: u64, entry: IndexEntry) -> Result<Option<IndexEntry>, NotDense> {
        if self.filed == 0 {
            self.start = seq & !CHUNK_MASK;
            self.chunks.clear();
            self.chunks.push_back(new_chunk());
            *self.slot_mut(seq).ok_or(NotDense)? = Slot::new(entry);
            self.lowest = seq;
            self.highest = seq;
            self.filed = 1;
            return Ok(None);
        }
        if (self.lowest..=self.highest).contains(&seq) {
            let previous = self.slot(seq).ok_or(NotDense)?.entry();
            let filed = if previous.is_none() {
                self.filed.checked_add(1).ok_or(NotDense)?
            } else {
                self.filed
            };
            *self.slot_mut(seq).ok_or(NotDense)? = Slot::new(entry);
            self.filed = filed;
            return Ok(previous);
        }
        // Outside the span: the numbers between become holes, within the
        // bound, checked before anything is allocated.
        let (lowest, highest) = if seq < self.lowest {
            (seq, self.highest)
        } else {
            (self.lowest, seq)
        };
        let filed = self.filed.checked_add(1).ok_or(NotDense)?;
        let holes = highest
            .checked_sub(lowest)
            .and_then(|span| span.checked_add(1))
            .and_then(|span| span.checked_sub(filed))
            .ok_or(NotDense)?;
        if holes > MAX_DENSE_HOLES {
            return Err(NotDense);
        }
        // Chunks in front, down to the one holding `seq`; at most
        // MAX_DENSE_HOLES / CHUNK_SLOTS + 1 of them.
        let first = seq & !CHUNK_MASK;
        while self.start > first {
            self.start = self.start.checked_sub(CHUNK_SLOTS as u64).ok_or(NotDense)?;
            self.chunks.push_front(new_chunk());
        }
        // Chunks behind, up to the one holding `seq`.
        let (chunk, _) = self.position(seq).ok_or(NotDense)?;
        while self.chunks.len() <= chunk {
            self.chunks.push_back(new_chunk());
        }
        *self.slot_mut(seq).ok_or(NotDense)? = Slot::new(entry);
        self.lowest = lowest;
        self.highest = highest;
        self.filed = filed;
        Ok(None)
    }

    /// Every filed frame, as a sparse map.
    fn to_map(&self) -> BTreeMap<u64, IndexEntry> {
        Range::dense(self, 0, u64::MAX).collect()
    }
}

/// Where each filed frame's record is, by sequence number: dense, falling
/// back to sparse (see the [module documentation](self)).
#[derive(Debug)]
pub(crate) struct Index {
    /// The current representation.
    repr: Repr,
}

/// The two representations of an [`Index`].
#[derive(Debug)]
enum Repr {
    /// Chunks of slots, from the chunk of the lowest number filed to that of
    /// the highest.
    Dense(Dense),
    /// A map holding only the numbers filed.
    Sparse(BTreeMap<u64, IndexEntry>),
}

impl Index {
    /// An empty, dense index.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            repr: Repr::Dense(Dense::default()),
        }
    }

    /// Files `entry` under `seq`, returning the entry it replaces, if any.
    /// Switches to the sparse map if the dense index cannot take it.
    pub(crate) fn insert(&mut self, seq: u64, entry: IndexEntry) -> Option<IndexEntry> {
        match &mut self.repr {
            Repr::Sparse(map) => map.insert(seq, entry),
            Repr::Dense(dense) => match dense.insert(seq, entry) {
                Ok(previous) => previous,
                Err(NotDense) => {
                    let mut map = dense.to_map();
                    let previous = map.insert(seq, entry);
                    self.repr = Repr::Sparse(map);
                    previous
                }
            },
        }
    }

    /// The record filed under `seq`, if any.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn get(&self, seq: u64) -> Option<IndexEntry> {
        match &self.repr {
            Repr::Dense(dense) => dense.get(seq),
            Repr::Sparse(map) => map.get(&seq).copied(),
        }
    }

    /// The filed frames in `begin..=end`, in ascending order. Empty if
    /// `begin` is above `end`.
    #[must_use]
    pub(crate) fn range(&self, begin: u64, end: u64) -> Range<'_> {
        match &self.repr {
            Repr::Dense(dense) => Range::dense(dense, begin, end),
            Repr::Sparse(map) if begin <= end => Range {
                inner: Frames::Sparse(map.range(begin..=end)),
            },
            Repr::Sparse(_) => Range::EMPTY,
        }
    }

    /// Every filed frame, in ascending order.
    #[must_use]
    pub(crate) fn iter(&self) -> Range<'_> {
        self.range(0, u64::MAX)
    }

    /// How many frames are filed.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        match &self.repr {
            Repr::Dense(dense) => usize::try_from(dense.filed).unwrap_or(usize::MAX),
            Repr::Sparse(map) => map.len(),
        }
    }

    /// Whether nothing is filed.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the index is dense.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn is_dense(&self) -> bool {
        matches!(self.repr, Repr::Dense(_))
    }

    /// How many dense chunks are allocated (0 when sparse).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn dense_chunks(&self) -> usize {
        match &self.repr {
            Repr::Dense(dense) => dense.chunks.len(),
            Repr::Sparse(_) => 0,
        }
    }

    /// The address of the first slot of the first dense chunk, to show that
    /// growing the index does not move it.
    #[cfg(test)]
    #[must_use]
    fn first_chunk_address(&self) -> Option<*const Slot> {
        match &self.repr {
            Repr::Dense(dense) => dense.chunks.front().map(|chunk| chunk.as_ptr()),
            Repr::Sparse(_) => None,
        }
    }
}

impl Default for Index {
    fn default() -> Self {
        Self::new()
    }
}

/// The filed frames of an [`Index`] over a range of numbers, ascending.
#[derive(Debug)]
pub(crate) struct Range<'a> {
    /// Where the frames come from.
    inner: Frames<'a>,
}

/// The source of a [`Range`].
#[derive(Debug)]
enum Frames<'a> {
    /// Nothing.
    Empty,
    /// Dense slots, from `next` to `last` inclusive.
    Dense {
        /// The index.
        dense: &'a Dense,
        /// The next number to look at.
        next: u64,
        /// The last number to look at.
        last: u64,
        /// Whether `last` has been looked at.
        done: bool,
    },
    /// A range of the sparse map.
    Sparse(btree_map::Range<'a, u64, IndexEntry>),
}

impl<'a> Range<'a> {
    /// Nothing.
    const EMPTY: Self = Self {
        inner: Frames::Empty,
    };

    /// The dense slots for `begin..=end`, within what is filed.
    fn dense(dense: &'a Dense, begin: u64, end: u64) -> Self {
        let next = begin.max(dense.lowest);
        let last = end.min(dense.highest);
        if dense.filed == 0 || next > last {
            return Self::EMPTY;
        }
        Self {
            inner: Frames::Dense {
                dense,
                next,
                last,
                done: false,
            },
        }
    }
}

impl Iterator for Range<'_> {
    type Item = (u64, IndexEntry);

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            Frames::Empty => None,
            Frames::Sparse(range) => range.next().map(|(seq, entry)| (*seq, *entry)),
            Frames::Dense {
                dense,
                next,
                last,
                done,
            } => {
                while !*done {
                    let seq = *next;
                    // The number after `last` is never computed, so `last`
                    // can be `u64::MAX`.
                    match seq.checked_add(1).filter(|_| seq < *last) {
                        Some(after) => *next = after,
                        None => *done = true,
                    }
                    if let Some(entry) = dense.slot(seq).and_then(Slot::entry) {
                        return Some((seq, entry));
                    }
                }
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(offset: u64) -> IndexEntry {
        IndexEntry {
            offset,
            body_len: 40,
        }
    }

    fn seqs(index: &Index, begin: u64, end: u64) -> Vec<u64> {
        index.range(begin, end).map(|(seq, _)| seq).collect()
    }

    #[test]
    fn test_index_slot_is_twelve_bytes_and_round_trips_wide_offsets() {
        assert_eq!(std::mem::size_of::<Slot>(), 12);
        for offset in [12_288, u64::from(u32::MAX) + 7, u64::MAX - 1] {
            assert_eq!(Slot::new(entry(offset)).entry(), Some(entry(offset)));
        }
        assert_eq!(Slot::HOLE.entry(), None);
    }

    #[test]
    fn test_index_dense_insert_get_and_range() {
        let mut index = Index::new();
        for seq in 5..=9 {
            assert_eq!(index.insert(seq, entry(seq * 100)), None);
        }
        assert!(index.is_dense());
        assert_eq!(index.len(), 5);
        assert_eq!(index.get(7), Some(entry(700)));
        assert_eq!(index.get(4), None);
        assert_eq!(index.get(10), None);
        assert_eq!(seqs(&index, 1, u64::MAX), vec![5, 6, 7, 8, 9]);
        assert_eq!(seqs(&index, 6, 8), vec![6, 7, 8]);
        assert!(seqs(&index, 10, u64::MAX).is_empty());
        assert!(seqs(&index, 1, 4).is_empty());
        assert!(seqs(&index, 8, 6).is_empty());
        // Replacing returns what was there, and the count does not move.
        assert_eq!(index.insert(7, entry(7_000)), Some(entry(700)));
        assert_eq!(index.len(), 5);
        assert_eq!(index.get(7), Some(entry(7_000)));
    }

    #[test]
    fn test_index_dense_holes_are_skipped_and_filled() {
        let mut index = Index::new();
        index.insert(1, entry(100));
        index.insert(4, entry(400));
        assert!(index.is_dense());
        assert_eq!(index.len(), 2);
        assert_eq!(seqs(&index, 1, 10), vec![1, 4]);
        assert_eq!(index.insert(3, entry(300)), None);
        assert_eq!(index.len(), 3);
        assert_eq!(seqs(&index, 2, 4), vec![3, 4]);
    }

    #[test]
    fn test_index_growing_allocates_chunks_and_never_moves_the_slots() {
        let mut index = Index::new();
        index.insert(1, entry(1));
        let first = index.first_chunk_address();
        // Chunks start at multiples of CHUNK_SLOTS: 0 to 12 287 is three.
        let count = 3 * CHUNK_SLOTS as u64 - 1;
        for seq in 2..=count {
            index.insert(seq, entry(seq));
        }
        assert_eq!(index.dense_chunks(), 3);
        assert_eq!(index.first_chunk_address(), first, "no slot was copied");
        assert_eq!(index.len() as u64, count);
        assert_eq!(index.get(count), Some(entry(count)));
        assert_eq!(seqs(&index, 4095, 4097), vec![4095, 4096, 4097]);
    }

    #[test]
    fn test_index_huge_jump_falls_back_to_sparse_without_allocating_the_gap() {
        let mut index = Index::new();
        index.insert(1, entry(100));
        index.insert(2, entry(200));
        // A jump of 10^15 numbers would be 12 PB of slots.
        assert_eq!(index.insert(1_000_000_000_000_000, entry(300)), None);
        assert!(!index.is_dense());
        assert_eq!(index.dense_chunks(), 0);
        assert_eq!(index.len(), 3);
        assert_eq!(seqs(&index, 1, u64::MAX), vec![1, 2, 1_000_000_000_000_000]);
        assert_eq!(index.get(2), Some(entry(200)));
        // The sparse map keeps its replace semantics.
        assert_eq!(index.insert(2, entry(222)), Some(entry(200)));
    }

    #[test]
    fn test_index_hole_bound_is_exact() {
        let mut index = Index::new();
        index.insert(1, entry(100));
        let at_bound = 2 + MAX_DENSE_HOLES;
        index.insert(at_bound, entry(200));
        assert!(index.is_dense(), "exactly MAX_DENSE_HOLES holes stay dense");
        index.insert(at_bound + 2, entry(300));
        assert!(!index.is_dense(), "one more hole switches to sparse");
        assert_eq!(seqs(&index, 1, u64::MAX), vec![1, at_bound, at_bound + 2]);
    }

    #[test]
    fn test_index_frame_below_the_lowest_moves_the_base_down_within_the_bound() {
        let mut index = Index::new();
        index.insert(200_000, entry(2));
        index.insert(200_001, entry(3));
        // Chunks start at multiples of CHUNK_SLOTS: 200 000 is in the one
        // from 196 608, 190 000 in the one from 188 416, two chunks below.
        assert_eq!(index.insert(190_000, entry(1)), None);
        assert!(index.is_dense());
        assert_eq!(index.dense_chunks(), 3);
        assert_eq!(seqs(&index, 1, u64::MAX), vec![190_000, 200_000, 200_001]);
        assert_eq!(index.get(190_000), Some(entry(1)));
        // Past the bound below the highest: sparse.
        index.insert(200_001 - MAX_DENSE_HOLES - 10, entry(0));
        assert!(!index.is_dense());
        assert_eq!(index.len(), 4);
    }

    #[test]
    fn test_index_numbers_at_both_ends_of_u64() {
        let mut index = Index::new();
        index.insert(u64::MAX - 1, entry(100));
        index.insert(u64::MAX, entry(200));
        assert!(index.is_dense());
        assert_eq!(seqs(&index, 1, u64::MAX), vec![u64::MAX - 1, u64::MAX]);
        assert_eq!(seqs(&index, u64::MAX, u64::MAX), vec![u64::MAX]);

        let mut index = Index::new();
        index.insert(1, entry(100));
        index.insert(0, entry(50));
        assert!(index.is_dense());
        assert_eq!(seqs(&index, 0, 5), vec![0, 1]);
    }

    #[test]
    fn test_index_iter_visits_every_frame_in_order() {
        let mut index = Index::default();
        for seq in [3, 1, 2] {
            index.insert(seq, entry(seq));
        }
        assert!(index.is_dense());
        assert_eq!(
            index.iter().map(|(seq, _)| seq).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert!(Index::new().iter().next().is_none());
    }
}
