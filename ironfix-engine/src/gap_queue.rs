/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 19/10/26
******************************************************************************/

//! The gap queue: messages received above the expected `MsgSeqNum` (34) while
//! a gap is open, kept under
//! [`GapPolicy::Queue`] and released in
//! order once the gap is filled (issue #71, ADR-0027).
//!
//! This module is the bookkeeping only: a map keyed by `MsgSeqNum`, bounded by
//! a message count and a byte count. The reactor decides what goes in and
//! acts on what comes out. Nothing here reads a clock, touches a store or
//! writes to the socket.
//!
//! An empty queue allocates nothing ([`BTreeMap::new`] does not), so a session
//! that never sees a gap pays one map lookup per inbound frame for it.

use bytes::Bytes;
use ironfix_session::GapPolicy;
use std::collections::BTreeMap;

/// One message held above a gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Gapped {
    /// A frame not yet acted on: an application message, or a
    /// `SequenceReset`-GapFill. Released through the in-sequence path.
    Frame(Bytes),
    /// An administrative message already acted on when it arrived (a
    /// TestRequest answered, a ResendRequest served): only its number is
    /// left to consume.
    Processed,
}

impl Gapped {
    /// The bytes this entry counts against the byte bound.
    #[must_use]
    fn len(&self) -> usize {
        match self {
            Self::Frame(frame) => frame.len(),
            Self::Processed => 0,
        }
    }
}

/// The result of [`GapQueue::insert`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Insert {
    /// The message is held.
    Queued,
    /// A message with this number is already held; the new one is dropped,
    /// so no number is ever released twice.
    Duplicate,
    /// Holding it would exceed a bound; it is dropped, as under
    /// [`GapPolicy::Discard`].
    Overflow,
}

/// What [`GapQueue::take_ready`] found at the expectation.
#[derive(Debug, Default)]
pub(crate) struct Ready {
    /// Held messages below the expectation, dropped: something else (a gap
    /// fill, a held Logon, a sequence reset) moved the expectation past them.
    pub(crate) superseded: usize,
    /// The held message whose number is the expectation, if any.
    pub(crate) next: Option<Gapped>,
}

/// The messages held above a gap, bounded by count and by bytes.
#[derive(Debug)]
pub(crate) struct GapQueue {
    /// Held messages, keyed by `MsgSeqNum`.
    entries: BTreeMap<u64, Gapped>,
    /// The sum of [`Gapped::len`] over `entries`.
    bytes: usize,
    /// Most messages held at once.
    max_messages: usize,
    /// Most bytes held at once.
    max_bytes: usize,
    /// Whether an overflow has been reported since the queue last emptied, so
    /// a flood is logged once rather than per message.
    overflow_reported: bool,
}

impl GapQueue {
    /// The queue a policy asks for: `None` under
    /// [`GapPolicy::Discard`].
    #[must_use]
    pub(crate) fn for_policy(policy: GapPolicy) -> Option<Self> {
        match policy {
            GapPolicy::Queue {
                max_messages,
                max_bytes,
            } => Some(Self {
                entries: BTreeMap::new(),
                bytes: 0,
                max_messages,
                max_bytes,
                overflow_reported: false,
            }),
            _ => None,
        }
    }

    /// Holds `entry` under `seq`.
    ///
    /// A number already held keeps its first copy ([`Insert::Duplicate`]): a
    /// possible-duplicate retransmission of it is the same message. Past
    /// either bound the entry is refused ([`Insert::Overflow`]) and what is
    /// held stays: the counterparty's resend covers everything from the gap
    /// start, so a refused message is delivered from it.
    pub(crate) fn insert(&mut self, seq: u64, entry: Gapped) -> Insert {
        if self.entries.contains_key(&seq) {
            return Insert::Duplicate;
        }
        let Some(bytes) = self.bytes.checked_add(entry.len()) else {
            return Insert::Overflow;
        };
        if self.entries.len() >= self.max_messages || bytes > self.max_bytes {
            return Insert::Overflow;
        }
        self.entries.insert(seq, entry);
        self.bytes = bytes;
        Insert::Queued
    }

    /// Whether this overflow is the first since the queue last emptied, and
    /// so the one to log.
    pub(crate) fn first_overflow(&mut self) -> bool {
        !std::mem::replace(&mut self.overflow_reported, true)
    }

    /// Drops every held message below `expected` and takes the one held at
    /// `expected`, if any.
    pub(crate) fn take_ready(&mut self, expected: u64) -> Ready {
        let mut ready = Ready::default();
        while let Some(entry) = self.entries.first_entry() {
            let seq = *entry.key();
            if seq > expected {
                break;
            }
            let held = entry.remove();
            self.bytes = match self.bytes.checked_sub(held.len()) {
                Some(bytes) => bytes,
                None => {
                    // `bytes` is the sum of the held lengths, so it always
                    // covers the one removed. Were it ever short, the count
                    // restarts from what is still held rather than wrap.
                    debug_assert!(false, "gap queue byte count below a held frame");
                    let recount = self
                        .entries
                        .values()
                        .try_fold(0_usize, |total, held| total.checked_add(held.len()));
                    match recount {
                        Some(total) => total,
                        // The recount cannot overflow either (every held
                        // frame is in memory at once). Were it to, the
                        // count is pinned at the top, which refuses every
                        // further insert as an overflow: fail closed.
                        None => usize::MAX,
                    }
                }
            };
            if seq == expected {
                ready.next = Some(held);
                break;
            }
            ready.superseded = match ready.superseded.checked_add(1) {
                Some(count) => count,
                // Bounded by `max_messages`, far below `usize::MAX`.
                None => usize::MAX,
            };
        }
        if self.entries.is_empty() {
            self.overflow_reported = false;
        }
        ready
    }

    /// Drops everything held; returns how many messages that was.
    pub(crate) fn clear(&mut self) -> usize {
        let dropped = self.entries.len();
        self.entries.clear();
        self.bytes = 0;
        self.overflow_reported = false;
        dropped
    }

    /// Whether nothing is held.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many messages are held.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// How many frame bytes are held.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn bytes(&self) -> usize {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queue(max_messages: usize, max_bytes: usize) -> GapQueue {
        match GapQueue::for_policy(GapPolicy::Queue {
            max_messages,
            max_bytes,
        }) {
            Some(queue) => queue,
            None => panic!("a Queue policy must build a queue"),
        }
    }

    fn frame(len: usize) -> Gapped {
        Gapped::Frame(Bytes::from(vec![b'x'; len]))
    }

    #[test]
    fn test_discard_policy_has_no_queue() {
        assert!(GapQueue::for_policy(GapPolicy::Discard).is_none());
    }

    #[test]
    fn test_take_ready_releases_only_the_expected_number() {
        let mut q = queue(8, 1024);
        assert_eq!(q.insert(6, frame(10)), Insert::Queued);
        assert_eq!(q.insert(5, frame(10)), Insert::Queued);
        let ready = q.take_ready(4);
        assert_eq!((ready.superseded, ready.next), (0, None));
        let ready = q.take_ready(5);
        assert_eq!(ready.next, Some(frame(10)));
        assert_eq!(q.len(), 1);
        assert_eq!(q.bytes(), 10);
        let ready = q.take_ready(6);
        assert_eq!(ready.next, Some(frame(10)));
        assert!(q.is_empty());
        assert_eq!(q.bytes(), 0);
    }

    #[test]
    fn test_take_ready_drops_numbers_the_expectation_jumped_past() {
        let mut q = queue(8, 1024);
        q.insert(5, frame(3));
        q.insert(6, Gapped::Processed);
        q.insert(9, frame(4));
        let ready = q.take_ready(8);
        assert_eq!(ready.superseded, 2);
        assert_eq!(ready.next, None);
        assert_eq!(q.len(), 1);
        assert_eq!(q.bytes(), 4);
    }

    #[test]
    fn test_a_held_number_keeps_its_first_copy() {
        let mut q = queue(8, 1024);
        assert_eq!(q.insert(5, frame(3)), Insert::Queued);
        assert_eq!(q.insert(5, frame(7)), Insert::Duplicate);
        assert_eq!(q.bytes(), 3);
        assert_eq!(q.take_ready(5).next, Some(frame(3)));
    }

    #[test]
    fn test_overflow_by_count_keeps_what_is_held() {
        let mut q = queue(2, 1024);
        assert_eq!(q.insert(5, frame(1)), Insert::Queued);
        assert_eq!(q.insert(6, Gapped::Processed), Insert::Queued);
        assert_eq!(q.insert(7, frame(1)), Insert::Overflow);
        assert_eq!(q.len(), 2);
        assert!(q.first_overflow());
        assert!(!q.first_overflow());
    }

    #[test]
    fn test_overflow_by_bytes_keeps_what_is_held() {
        let mut q = queue(8, 10);
        assert_eq!(q.insert(5, frame(6)), Insert::Queued);
        assert_eq!(q.insert(6, frame(5)), Insert::Overflow);
        assert_eq!(q.insert(6, Gapped::Processed), Insert::Queued);
        assert_eq!(q.insert(7, frame(4)), Insert::Queued);
        assert_eq!(q.bytes(), 10);
    }

    #[test]
    fn test_clear_empties_and_rearms_the_overflow_report() {
        let mut q = queue(1, 1024);
        q.insert(5, frame(1));
        assert_eq!(q.insert(6, frame(1)), Insert::Overflow);
        assert!(q.first_overflow());
        assert_eq!(q.clear(), 1);
        assert!(q.is_empty());
        assert_eq!(q.bytes(), 0);
        assert!(q.first_overflow());
    }
}
