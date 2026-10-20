/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! Sans-IO core, stage 3: the decisions of a resend replay.
//!
//! Answering a `ResendRequest` (2), or the opening replay a counterparty's
//! `NextExpectedMsgSeqNum` (789) asks for (ADR-0021), is a conversation
//! between this core and its driver. The core never reads the store, never
//! rebuilds a frame and never runs the application's replay gate: it asks the
//! driver to, and decides what the answer means.
//!
//! - [`decide_resend_request`] validates `BeginSeqNo` (7) and `EndSeqNo` (16)
//!   against what the session has sent, reading the version's "to infinity"
//!   value through [`EndSeqNoInfinity`] (issue #137), and returns the range
//!   to replay. [`decide_opening_replay`] checks a 789 range the same way.
//! - [`ResendReplay`] walks one range. The driver polls it
//!   ([`ResendReplay::poll_store`]) and gets a [`ReplayStep`]: read a page
//!   ([`PageRequest`], answered with [`ResendReplay::on_page`]), or the
//!   replay is complete, with the trailing gap fill it still owes. For each
//!   stored entry of a page the driver asks [`ResendReplay::screen_entry`]
//!   whether it is a candidate (in range and not administrative), rebuilds
//!   and gates the candidates, and reports the outcome as a [`ReplayVerdict`]
//!   to [`ResendReplay::decide_entry`], which answers with a [`ReplayAction`].
//!   A veto from the replay gate (issue #133), a frame that does not rebuild,
//!   an administrative message and a number the store never held are all the
//!   same to the core: nothing is written for them, and a run of them becomes
//!   one `SequenceReset` (4) GapFill, written before the next replayed
//!   message or at the end.
//! - [`replay_step_continues`], [`reads_yield_to_replay`],
//!   [`replay_queue_full`] and [`hold_full`] are the bounds of issues #126
//!   and #128: how much one step of the driver feeds, how many inbound frames
//!   are read before a step, how many resends queue, and how much output is
//!   held back behind a resend before reading stops.
//! - [`replay_field`] and [`orig_sending_time`] are the rebuild decisions:
//!   which header fields a replayed frame drops, reinserts or restamps, and
//!   where its `OrigSendingTime` (122) comes from (`PossDupFlag` (43) = Y is
//!   always set).
//!
//! The replay never allocates a sender sequence number: a replayed message
//! re-occupies the number it was first sent under, and a gap fill occupies the
//! range it replaces.

use ironfix_core::FixVersion;

/// Most stored messages one store read returns (one page).
///
/// A `ResendRequest` with `EndSeqNo` (16) = 0 asks for the whole session, so
/// the replay reads in bounded pages rather than all at once.
pub const REPLAY_PAGE_LIMIT: usize = 256;

/// Most frames one replay step feeds to the driver's output, whatever their
/// size (issue #126).
pub const REPLAY_STEP_MAX_FRAMES: usize = 64;

/// Output, in bytes, at or above which a replay step stops feeding frames
/// (issue #126).
pub const REPLAY_STEP_MAX_BYTES: usize = 64 * 1024;

/// Most inbound frames the driver handles in a row while a replay has room
/// to write, before it gives the replay a step (issue #126).
pub const MAX_READS_PER_REPLAY_STEP: u32 = 16;

/// Most resends a session queues, the one under way included. Past this, a
/// new one is merged into the last queued one ([`ResendReplay::widen`]).
pub const MAX_QUEUED_REPLAYS: usize = 64;

// The merge widens the last queued resend, which must not be the one under way.
const _: () = assert!(MAX_QUEUED_REPLAYS >= 2);

/// Most messages held back behind a resend before reading stops (issue #128).
pub const MAX_HELD_SENDS: usize = 1_024;

/// Most bytes held back behind a resend before reading stops (issue #128).
pub const MAX_HELD_BYTES: usize = 4 * 1024 * 1024;

/// How a session writes and reads the open-ended ("to infinity") `EndSeqNo`
/// (16) of a `ResendRequest` (2), decided by its FIX version (issue #137).
///
/// FIX 4.0 and FIX 4.1 define infinity as `999999`; FIX 4.2 replaced it with
/// `0`, which every later version (FIXT.1.1 included) keeps
/// (`doc/fix_operations.md`, "Resend Request").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EndSeqNoInfinity {
    /// `16=999999`: FIX 4.0 and FIX 4.1.
    Nines,
    /// `16=0`: FIX 4.2 and later.
    Zero,
}

impl EndSeqNoInfinity {
    /// The FIX 4.0 / 4.1 open-ended `EndSeqNo`.
    pub const NINES: u64 = 999_999;

    /// Returns the convention a session in `version` uses.
    ///
    /// The match names every version, so a new [`FixVersion`] does not
    /// compile until it has been given a convention.
    #[inline]
    #[must_use]
    pub const fn for_version(version: FixVersion) -> Self {
        match version {
            FixVersion::Fix40 | FixVersion::Fix41 => Self::Nines,
            FixVersion::Fix42
            | FixVersion::Fix43
            | FixVersion::Fix44
            | FixVersion::Fix50
            | FixVersion::Fix50Sp1
            | FixVersion::Fix50Sp2
            | FixVersion::Fixt11 => Self::Zero,
        }
    }

    /// The `EndSeqNo` this session writes for an open-ended request.
    #[inline]
    #[must_use]
    pub const fn sentinel(self) -> u64 {
        match self {
            Self::Nines => Self::NINES,
            Self::Zero => 0,
        }
    }

    /// Whether an inbound `EndSeqNo` means "to infinity".
    ///
    /// On FIX 4.0 / 4.1 both `999999` and `0` do: a literal `0` cannot name a
    /// range there (it is below every valid `BeginSeqNo`), so reading it as
    /// the later versions' sentinel answers rather than rejects a peer that
    /// mixes conventions. On FIX 4.2 and later only `0` does; `999999` stays a
    /// literal bound, which the reply clamps to the next outbound number
    /// anyway.
    #[inline]
    #[must_use]
    pub const fn is_open_ended(self, end_seq: u64) -> bool {
        match self {
            Self::Nines => end_seq == Self::NINES || end_seq == 0,
            Self::Zero => end_seq == 0,
        }
    }
}

/// What an inbound `ResendRequest` (2) asks of the session.
///
/// Deliberately not `#[non_exhaustive]`, like the other decisions of the
/// core: a driver matches every outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResendRequestDecision {
    /// `BeginSeqNo` (7) is absent or not a number: a session Reject,
    /// reason 1, `RefTagID` 7.
    MissingBeginSeqNo,
    /// `EndSeqNo` (16) is absent or not a number: a session Reject, reason
    /// 1, `RefTagID` 16.
    MissingEndSeqNo,
    /// `BeginSeqNo` is 0 or not below the next sender number: nothing in the
    /// range was sent. A session Reject, reason 5, `RefTagID` 7.
    BeginSeqNoOutsideSent {
        /// The requested `BeginSeqNo`.
        begin_seq: u64,
        /// The next number this session sends.
        next_sender: u64,
    },
    /// A bounded `EndSeqNo` below `BeginSeqNo`: a session Reject, reason 5,
    /// `RefTagID` 16.
    EndSeqNoBelowBegin {
        /// The requested `BeginSeqNo`.
        begin_seq: u64,
        /// The requested `EndSeqNo`.
        end_seq: u64,
    },
    /// Replay `begin_seq..new_seq` (`new_seq` exclusive), which is never
    /// empty.
    Replay {
        /// The first number replayed.
        begin_seq: u64,
        /// The first number not covered: `EndSeqNo` + 1, clamped to the next
        /// sender number.
        new_seq: u64,
    },
}

/// Decides what a `ResendRequest` (2) with `BeginSeqNo` (7) `begin_seq` and
/// `EndSeqNo` (16) `end_seq` asks, given the next number this session sends
/// and its version's [`EndSeqNoInfinity`].
///
/// `None` stands for a field that is absent or does not parse as a number.
/// The reply never reaches beyond `EndSeqNo` + 1 nor beyond what has been
/// sent, so the counterparty is never advanced past what it asked for.
#[must_use]
pub const fn decide_resend_request(
    begin_seq: Option<u64>,
    end_seq: Option<u64>,
    next_sender: u64,
    infinity: EndSeqNoInfinity,
) -> ResendRequestDecision {
    let Some(begin_seq) = begin_seq else {
        return ResendRequestDecision::MissingBeginSeqNo;
    };
    let Some(end_seq) = end_seq else {
        return ResendRequestDecision::MissingEndSeqNo;
    };
    if begin_seq == 0 || begin_seq >= next_sender {
        return ResendRequestDecision::BeginSeqNoOutsideSent {
            begin_seq,
            next_sender,
        };
    }
    let open_ended = infinity.is_open_ended(end_seq);
    if !open_ended && end_seq < begin_seq {
        return ResendRequestDecision::EndSeqNoBelowBegin { begin_seq, end_seq };
    }
    let new_seq = if open_ended {
        next_sender
    } else {
        match end_seq.checked_add(1) {
            Some(bound) if bound < next_sender => bound,
            // Clamped to what was sent; `end_seq` = u64::MAX has no bound
            // below infinity.
            Some(_) | None => next_sender,
        }
    };
    ResendRequestDecision::Replay { begin_seq, new_seq }
}

/// What the opening replay a counterparty's `NextExpectedMsgSeqNum` (789)
/// asked for (ADR-0021) comes to, once the session is Active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpeningReplay {
    /// Replay `begin_seq..new_seq`, as the answer to a `ResendRequest` for
    /// exactly that range.
    Replay {
        /// The first number replayed: the counterparty's 789.
        begin_seq: u64,
        /// The first number not replayed: this session's own Logon or
        /// acknowledgement.
        new_seq: u64,
    },
    /// The range is empty or reaches past the next sender number: nothing is
    /// sent.
    OutsideSent,
}

/// Checks the opening replay `begin_seq..new_seq` the Logon exchange planned
/// against `next_sender`, the next number this session sends.
#[must_use]
pub const fn decide_opening_replay(
    begin_seq: u64,
    new_seq: u64,
    next_sender: u64,
) -> OpeningReplay {
    if begin_seq == 0 || begin_seq >= new_seq || new_seq > next_sender {
        OpeningReplay::OutsideSent
    } else {
        OpeningReplay::Replay { begin_seq, new_seq }
    }
}

/// A `SequenceReset` (4) GapFill the driver writes, numbered `at` with
/// `NewSeqNo` (36) `new_seq`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapFillRange {
    /// The `MsgSeqNum` (34) of the fill: the first number it covers.
    pub at: u64,
    /// The `NewSeqNo` (36): the first number it does not cover.
    pub new_seq: u64,
}

/// A store read the core asks the driver for: up to `limit` stored messages
/// numbered `from..=through`, in ascending order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageRequest {
    /// The first number to read.
    pub from: u64,
    /// The last number to read (inclusive).
    pub through: u64,
    /// Most messages to return: [`REPLAY_PAGE_LIMIT`].
    pub limit: usize,
}

/// The driver's answer to a [`PageRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PageRead {
    /// The read returned `len` messages, the last of them numbered
    /// `furthest` (`None` for an empty page).
    Read {
        /// How many messages the page holds.
        len: usize,
        /// The number of the last message of the page.
        furthest: Option<u64>,
    },
    /// The read failed, overran its timeout, or there is no store: what is
    /// left of the range is gap-filled. A store that reports itself corrupted
    /// is the driver's to close the session on, not this.
    Failed,
}

/// What [`ResendReplay::poll_store`] asks of the driver once the page it
/// holds is spent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReplayStep {
    /// Read this page and report it with [`ResendReplay::on_page`]. A page
    /// read ends the driver's step.
    ReadPage(PageRequest),
    /// The store has nothing left for the range and no read is needed. Like
    /// a read, this ends the driver's step.
    StoreExhausted,
    /// The replay is complete once the driver writes `gap_fill`, if any: the
    /// trailing run the replay did not cover (admin messages, holes, vetoes,
    /// or the whole range without a store), so the counterparty's
    /// expectation lands exactly on the end of the range.
    Complete {
        /// The trailing fill, if the replay owes one.
        gap_fill: Option<GapFillRange>,
    },
}

/// Whether a stored entry is a candidate for replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryScreen {
    /// Rebuild it and ask the replay gate, then report the outcome to
    /// [`ResendReplay::decide_entry`].
    Candidate,
    /// Not replayed and not rebuilt: outside what the reply still owes (a
    /// store must not move the reply), or an administrative message, which
    /// is gap-filled (`doc/fix_operations.md`, "Resend Request", item 3).
    Skip,
}

/// The outcome of rebuilding and gating a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReplayVerdict {
    /// The frame rebuilt and the replay gate let it through.
    Replay,
    /// The frame did not rebuild, or the replay gate vetoed it (issue #133):
    /// its number is gap-filled.
    GapFill,
}

/// What the driver writes for a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReplayAction {
    /// Nothing: the number joins the gap fill written before the next
    /// replayed message, or the trailing one, so a run of them is one fill.
    Skip,
    /// Write the rebuilt frame of `seq` now.
    Replay {
        /// The number of the replayed message.
        seq: u64,
    },
    /// Write `gap_fill` (everything between the reply cursor and `seq`) and
    /// then, on the driver's next feed, the rebuilt frame of `seq`.
    GapFillThenReplay {
        /// The fill covering the run before `seq`.
        gap_fill: GapFillRange,
        /// The number of the replayed message.
        seq: u64,
    },
}

/// The decision state of one resend this session owes the counterparty: what
/// is left of `begin_seq..new_seq`.
///
/// The driver keeps the page it read and the rebuilt frames; this keeps the
/// numbers. The reply cursor counts the frames as decided, so the driver
/// writes what [`ResendReplay::decide_entry`] and
/// [`ResendReplay::poll_store`] return, in order, before it asks again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResendReplay {
    new_seq: u64,
    end_seq: u64,
    reply_cursor: u64,
    read_from: u64,
    store_done: bool,
}

impl ResendReplay {
    /// The replay of `begin_seq..new_seq`, or `None` for an empty range (or a
    /// `begin_seq` of 0). Without a store (`has_store` false) the store is
    /// done from the start: the whole range is one gap fill.
    #[must_use]
    pub const fn new(begin_seq: u64, new_seq: u64, has_store: bool) -> Option<Self> {
        if begin_seq == 0 || begin_seq >= new_seq {
            return None;
        }
        let Some(end_seq) = new_seq.checked_sub(1) else {
            return None;
        };
        Some(Self {
            new_seq,
            end_seq,
            reply_cursor: begin_seq,
            read_from: begin_seq,
            store_done: !has_store,
        })
    }

    /// The first number not covered by the reply (exclusive end).
    #[must_use]
    pub const fn new_seq(&self) -> u64 {
        self.new_seq
    }

    /// The last number the reply may replay: `new_seq - 1`.
    #[must_use]
    pub const fn end_seq(&self) -> u64 {
        self.end_seq
    }

    /// The next number the reply still owes the counterparty.
    #[must_use]
    pub const fn reply_cursor(&self) -> u64 {
        self.reply_cursor
    }

    /// The next number to read a page from.
    #[must_use]
    pub const fn read_from(&self) -> u64 {
        self.read_from
    }

    /// Whether the store has nothing more to give for this range.
    #[must_use]
    pub const fn store_done(&self) -> bool {
        self.store_done
    }

    /// Widens a replay that has written nothing yet to also cover `other`'s
    /// range: from the lower start to the higher end.
    pub fn widen(&mut self, other: &Self) {
        let begin_seq = self.reply_cursor.min(other.reply_cursor);
        self.reply_cursor = begin_seq;
        self.read_from = begin_seq;
        self.new_seq = self.new_seq.max(other.new_seq);
        self.end_seq = self.end_seq.max(other.end_seq);
    }

    /// What the replay needs once the driver's page is spent and no rebuilt
    /// frame is waiting: a page read, nothing more from the store, or the
    /// end, with the trailing gap fill.
    pub const fn poll_store(&mut self) -> ReplayStep {
        if !self.store_done {
            if self.read_from > self.end_seq {
                self.store_done = true;
                return ReplayStep::StoreExhausted;
            }
            return ReplayStep::ReadPage(PageRequest {
                from: self.read_from,
                through: self.end_seq,
                limit: REPLAY_PAGE_LIMIT,
            });
        }
        let gap_fill = if self.reply_cursor < self.new_seq {
            Some(GapFillRange {
                at: self.reply_cursor,
                new_seq: self.new_seq,
            })
        } else {
            None
        };
        self.reply_cursor = self.new_seq;
        ReplayStep::Complete { gap_fill }
    }

    /// Records the answer to the last [`PageRequest`].
    ///
    /// Pages are ascending and bounded to the range, so the last number is
    /// the furthest the page reached: a full page means there may be more,
    /// read from just past it; a short or empty page, or a failed read, ends
    /// the store's part.
    pub const fn on_page(&mut self, read: PageRead) {
        match read {
            PageRead::Failed | PageRead::Read { furthest: None, .. } => self.store_done = true,
            PageRead::Read { len, .. } if len < REPLAY_PAGE_LIMIT => self.store_done = true,
            PageRead::Read {
                furthest: Some(furthest),
                ..
            } => match furthest.checked_add(1) {
                Some(next) if next <= self.end_seq => self.read_from = next,
                Some(_) | None => self.store_done = true,
            },
        }
    }

    /// Screens the stored entry numbered `seq`: a candidate, or skipped
    /// because it lies outside what the reply still owes or is an
    /// administrative message (`is_admin`).
    #[must_use]
    pub const fn screen_entry(&self, seq: u64, is_admin: bool) -> EntryScreen {
        if seq < self.reply_cursor || seq > self.end_seq || is_admin {
            EntryScreen::Skip
        } else {
            EntryScreen::Candidate
        }
    }

    /// Decides what the driver writes for the candidate numbered `seq`,
    /// given whether it rebuilt and passed the replay gate.
    ///
    /// A `seq` that does not screen as a candidate is skipped as well.
    pub fn decide_entry(&mut self, seq: u64, verdict: ReplayVerdict) -> ReplayAction {
        if matches!(verdict, ReplayVerdict::GapFill)
            || matches!(self.screen_entry(seq, false), EntryScreen::Skip)
        {
            return ReplayAction::Skip;
        }
        let gap_fill = (seq > self.reply_cursor).then_some(GapFillRange {
            at: self.reply_cursor,
            new_seq: seq,
        });
        // `seq <= end_seq < new_seq <= u64::MAX`, so this cannot overflow; it
        // is checked rather than assumed because a wrapped sequence number
        // would corrupt the session it is meant to repair.
        self.reply_cursor = match seq.checked_add(1) {
            Some(next) => next,
            None => {
                debug_assert!(false, "a replayed number below new_seq cannot be u64::MAX");
                self.new_seq
            }
        };
        match gap_fill {
            Some(gap_fill) => ReplayAction::GapFillThenReplay { gap_fill, seq },
            None => ReplayAction::Replay { seq },
        }
    }
}

/// Whether a replay step that has fed `frames_fed` frames, leaving
/// `buffered_bytes` waiting in the output, goes on feeding (issue #126): below
/// [`REPLAY_STEP_MAX_FRAMES`] frames and [`REPLAY_STEP_MAX_BYTES`] bytes.
#[must_use]
pub const fn replay_step_continues(frames_fed: usize, buffered_bytes: usize) -> bool {
    frames_fed < REPLAY_STEP_MAX_FRAMES && buffered_bytes < REPLAY_STEP_MAX_BYTES
}

/// Whether `reads_since_step` inbound frames handled since the last replay
/// step mean the next pass gives the replay its step instead of reading
/// (issue #126).
#[must_use]
pub const fn reads_yield_to_replay(reads_since_step: u32) -> bool {
    reads_since_step >= MAX_READS_PER_REPLAY_STEP
}

/// Whether a queue of `queued` resends is full: a new one is merged into the
/// last queued one ([`ResendReplay::widen`]) instead of joining it.
#[must_use]
pub const fn replay_queue_full(queued: usize) -> bool {
    queued >= MAX_QUEUED_REPLAYS
}

/// Whether the output held back behind a resend (`held` messages, `held_bytes`
/// bytes) has reached either bound of issue #128: reading stops until the
/// resend is done.
#[must_use]
pub const fn hold_full(held: usize, held_bytes: usize) -> bool {
    held >= MAX_HELD_SENDS || held_bytes >= MAX_HELD_BYTES
}

/// What rebuilding a stored frame as a replay does with a field of tag `tag`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReplayField {
    /// `BeginString` (8) or `BodyLength` (9): stamped again when the frame is
    /// framed.
    Framing,
    /// `PossDupFlag` (43) or `OrigSendingTime` (122): dropped where it stands
    /// and written again in its header position, so a resend of a resend
    /// does not carry it twice.
    Reinserted,
    /// `SendingTime` (52): written as `43=Y`, `52=<now>`, then
    /// `122=<`[`orig_sending_time`]`>`, in that order.
    SendingTime,
    /// Every other field: copied verbatim, in its original order.
    Copied,
}

/// What rebuilding a stored frame as a replay does with a field of tag `tag`
/// (`doc/fix_operations.md`, "Resend Request", items 2 and 4).
#[must_use]
pub const fn replay_field(tag: u32) -> ReplayField {
    match tag {
        8 | 9 => ReplayField::Framing,
        43 | 122 => ReplayField::Reinserted,
        52 => ReplayField::SendingTime,
        _ => ReplayField::Copied,
    }
}

/// The `OrigSendingTime` (122) a replayed frame carries: the frame's own 122
/// when it has one (a resend of a resend, where 52 is only the prior
/// replay's time), otherwise its `SendingTime` (52).
#[must_use]
pub fn orig_sending_time<'a>(stored_122: Option<&'a str>, stored_52: &'a str) -> &'a str {
    stored_122.unwrap_or(stored_52)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// One frame the driver writes, as the tests record it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Out {
        Fill { at: u64, new_seq: u64 },
        Replay(u64),
    }

    /// A fake store: the numbers it holds, each admin or not.
    #[derive(Default)]
    struct FakeStore {
        entries: BTreeMap<u64, bool>,
        fail_from: Option<u64>,
    }

    impl FakeStore {
        fn with(apps: &[u64], admins: &[u64]) -> Self {
            let mut entries = BTreeMap::new();
            for seq in apps {
                entries.insert(*seq, false);
            }
            for seq in admins {
                entries.insert(*seq, true);
            }
            Self {
                entries,
                fail_from: None,
            }
        }

        fn page(&self, request: PageRequest) -> Option<Vec<(u64, bool)>> {
            if self.fail_from.is_some_and(|at| request.from >= at) {
                return None;
            }
            Some(
                self.entries
                    .range(request.from..=request.through)
                    .take(request.limit)
                    .map(|(seq, admin)| (*seq, *admin))
                    .collect(),
            )
        }
    }

    /// How a driver step ended, as the reactor reports it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Progress {
        Wrote,
        ReadPage,
        Done,
    }

    /// A synchronous driver: page and pending frame kept outside the core,
    /// as the reactor keeps them.
    struct Driver {
        core: ResendReplay,
        page: std::vec::IntoIter<(u64, bool)>,
        pending: Option<u64>,
    }

    impl Driver {
        fn new(core: ResendReplay) -> Self {
            Self {
                core,
                page: Vec::new().into_iter(),
                pending: None,
            }
        }

        /// The reactor's `advance_resend`, over the core.
        fn advance(
            &mut self,
            store: Option<&FakeStore>,
            gate: &dyn Fn(u64) -> ReplayVerdict,
            out: &mut Vec<Out>,
        ) -> Progress {
            loop {
                if let Some(seq) = self.pending.take() {
                    out.push(Out::Replay(seq));
                    return Progress::Wrote;
                }
                if let Some((seq, admin)) = self.page.next() {
                    if self.core.screen_entry(seq, admin) == EntryScreen::Skip {
                        continue;
                    }
                    match self.core.decide_entry(seq, gate(seq)) {
                        ReplayAction::Skip => continue,
                        ReplayAction::Replay { seq } => {
                            out.push(Out::Replay(seq));
                            return Progress::Wrote;
                        }
                        ReplayAction::GapFillThenReplay { gap_fill, seq } => {
                            out.push(Out::Fill {
                                at: gap_fill.at,
                                new_seq: gap_fill.new_seq,
                            });
                            self.pending = Some(seq);
                            return Progress::Wrote;
                        }
                    }
                }
                match self.core.poll_store() {
                    ReplayStep::ReadPage(request) => {
                        let read = store.and_then(|store| store.page(request));
                        match read {
                            Some(page) => {
                                self.core.on_page(PageRead::Read {
                                    len: page.len(),
                                    furthest: page.last().map(|(seq, _)| *seq),
                                });
                                self.page = page.into_iter();
                            }
                            None => self.core.on_page(PageRead::Failed),
                        }
                        return Progress::ReadPage;
                    }
                    ReplayStep::StoreExhausted => return Progress::ReadPage,
                    ReplayStep::Complete { gap_fill } => {
                        if let Some(fill) = gap_fill {
                            out.push(Out::Fill {
                                at: fill.at,
                                new_seq: fill.new_seq,
                            });
                        }
                        return Progress::Done;
                    }
                }
            }
        }
    }

    /// Runs a whole replay of `begin..new_seq` and returns what was written
    /// and how many page reads it took.
    fn run(
        begin: u64,
        new_seq: u64,
        store: Option<&FakeStore>,
        gate: &dyn Fn(u64) -> ReplayVerdict,
    ) -> (Vec<Out>, usize) {
        let Some(core) = ResendReplay::new(begin, new_seq, store.is_some()) else {
            return (Vec::new(), 0);
        };
        let mut driver = Driver::new(core);
        let mut out = Vec::new();
        let mut reads = 0;
        for _ in 0..100_000 {
            match driver.advance(store, gate, &mut out) {
                Progress::Wrote => {}
                Progress::ReadPage => reads += 1,
                Progress::Done => return (out, reads),
            }
        }
        panic!("the replay never completed");
    }

    fn allow(_: u64) -> ReplayVerdict {
        ReplayVerdict::Replay
    }

    /// Asserts the frames cover `begin..new_seq` exactly once, in order.
    fn assert_covers(out: &[Out], begin: u64, new_seq: u64) {
        let mut cursor = begin;
        for frame in out {
            match *frame {
                Out::Fill { at, new_seq } => {
                    assert_eq!(at, cursor, "a fill starts at the cursor: {out:?}");
                    assert!(new_seq > at, "a fill covers something: {out:?}");
                    cursor = new_seq;
                }
                Out::Replay(seq) => {
                    assert_eq!(seq, cursor, "a replay is at the cursor: {out:?}");
                    cursor = seq + 1;
                }
            }
        }
        assert_eq!(cursor, new_seq, "the reply lands on new_seq: {out:?}");
        let fills: Vec<_> = out
            .windows(2)
            .filter(|w| matches!(w, [Out::Fill { .. }, Out::Fill { .. }]))
            .collect();
        assert!(fills.is_empty(), "adjacent fills are coalesced: {out:?}");
    }

    #[test]
    fn test_new_refuses_an_empty_range() {
        assert!(ResendReplay::new(5, 5, true).is_none());
        assert!(ResendReplay::new(6, 5, true).is_none());
        assert!(ResendReplay::new(0, 5, true).is_none());
        let Some(job) = ResendReplay::new(3, 6, false) else {
            panic!("3..6 is not empty");
        };
        assert_eq!((job.reply_cursor(), job.read_from()), (3, 3));
        assert_eq!((job.end_seq(), job.new_seq()), (5, 6));
        assert!(
            job.store_done(),
            "without a store the range is one gap fill"
        );
    }

    #[test]
    fn test_widen_covers_both_ranges() {
        let (Some(mut job), Some(other)) = (
            ResendReplay::new(10, 20, true),
            ResendReplay::new(4, 30, true),
        ) else {
            panic!("both ranges are valid");
        };
        job.widen(&other);
        assert_eq!((job.reply_cursor(), job.read_from()), (4, 4));
        assert_eq!((job.end_seq(), job.new_seq()), (29, 30));
    }

    #[test]
    fn test_no_store_is_one_gap_fill() {
        let (out, reads) = run(3, 10, None, &allow);
        assert_eq!(out, vec![Out::Fill { at: 3, new_seq: 10 }]);
        assert_eq!(reads, 0, "no store is never read");
    }

    #[test]
    fn test_holes_and_admin_messages_coalesce_into_one_fill() {
        // 1 admin (Logon), 2 app, 3 hole, 4 admin, 5 app, 6..7 holes.
        let store = FakeStore::with(&[2, 5], &[1, 4]);
        let (out, _) = run(1, 8, Some(&store), &allow);
        assert_eq!(
            out,
            vec![
                Out::Fill { at: 1, new_seq: 2 },
                Out::Replay(2),
                Out::Fill { at: 3, new_seq: 5 },
                Out::Replay(5),
                Out::Fill { at: 6, new_seq: 8 },
            ]
        );
        assert_covers(&out, 1, 8);
    }

    #[test]
    fn test_veto_at_the_start_coalesces_with_the_fill_before() {
        let store = FakeStore::with(&[1, 2, 3, 4], &[]);
        let veto = |seq| {
            if seq <= 2 {
                ReplayVerdict::GapFill
            } else {
                ReplayVerdict::Replay
            }
        };
        let (out, _) = run(1, 5, Some(&store), &veto);
        assert_eq!(
            out,
            vec![
                Out::Fill { at: 1, new_seq: 3 },
                Out::Replay(3),
                Out::Replay(4)
            ]
        );
    }

    #[test]
    fn test_veto_in_the_middle_joins_a_hole_into_one_fill() {
        // 3 vetoed, 4 a hole, 5 vetoed: one fill 3..6.
        let store = FakeStore::with(&[1, 2, 3, 5, 6], &[]);
        let veto = |seq| {
            if seq == 3 || seq == 5 {
                ReplayVerdict::GapFill
            } else {
                ReplayVerdict::Replay
            }
        };
        let (out, _) = run(1, 7, Some(&store), &veto);
        assert_eq!(
            out,
            vec![
                Out::Replay(1),
                Out::Replay(2),
                Out::Fill { at: 3, new_seq: 6 },
                Out::Replay(6),
            ]
        );
    }

    #[test]
    fn test_veto_at_the_end_is_the_trailing_fill() {
        let store = FakeStore::with(&[1, 2, 3, 4], &[]);
        let veto = |seq| {
            if seq >= 3 {
                ReplayVerdict::GapFill
            } else {
                ReplayVerdict::Replay
            }
        };
        let (out, _) = run(1, 5, Some(&store), &veto);
        assert_eq!(
            out,
            vec![
                Out::Replay(1),
                Out::Replay(2),
                Out::Fill { at: 3, new_seq: 5 }
            ]
        );
    }

    #[test]
    fn test_everything_vetoed_is_one_fill() {
        let store = FakeStore::with(&[1, 2, 3, 4], &[]);
        let (out, _) = run(1, 5, Some(&store), &|_| ReplayVerdict::GapFill);
        assert_eq!(out, vec![Out::Fill { at: 1, new_seq: 5 }]);
    }

    #[test]
    fn test_a_failed_read_gap_fills_the_rest() {
        let mut store = FakeStore::with(&(1..=600).collect::<Vec<_>>(), &[]);
        store.fail_from = Some(257);
        let (out, reads) = run(1, 601, Some(&store), &allow);
        assert_eq!(out.len(), 257, "256 replays and one trailing fill");
        assert_eq!(
            out.last(),
            Some(&Out::Fill {
                at: 257,
                new_seq: 601
            })
        );
        assert_eq!(reads, 2);
    }

    #[test]
    fn test_pages_are_bounded_and_resume_past_the_furthest_key() {
        let all: Vec<u64> = (1..=600).collect();
        let store = FakeStore::with(&all, &[]);
        let (out, reads) = run(1, 601, Some(&store), &allow);
        assert_eq!(
            out,
            all.iter().map(|seq| Out::Replay(*seq)).collect::<Vec<_>>()
        );
        // 256 + 256 + 88: the short third page ends the store's part.
        assert_eq!(reads, 3);

        let Some(mut job) = ResendReplay::new(1, 601, true) else {
            panic!("valid range");
        };
        assert_eq!(
            job.poll_store(),
            ReplayStep::ReadPage(PageRequest {
                from: 1,
                through: 600,
                limit: REPLAY_PAGE_LIMIT
            })
        );
        job.on_page(PageRead::Read {
            len: REPLAY_PAGE_LIMIT,
            furthest: Some(300),
        });
        assert_eq!(
            job.read_from(),
            301,
            "the next page reads past the furthest key"
        );
        assert!(!job.store_done());
        job.on_page(PageRead::Read {
            len: REPLAY_PAGE_LIMIT,
            furthest: Some(600),
        });
        assert!(
            job.store_done(),
            "a full page reaching the end ends the store's part"
        );
    }

    #[test]
    fn test_a_full_page_at_u64_max_ends_the_store() {
        let Some(mut job) = ResendReplay::new(u64::MAX - 1, u64::MAX, true) else {
            panic!("valid range");
        };
        job.on_page(PageRead::Read {
            len: REPLAY_PAGE_LIMIT,
            furthest: Some(u64::MAX),
        });
        assert!(job.store_done(), "no wrap past u64::MAX");
    }

    #[test]
    fn test_a_store_outside_the_range_never_moves_the_reply() {
        let Some(job) = ResendReplay::new(5, 8, true) else {
            panic!("valid range");
        };
        assert_eq!(job.screen_entry(4, false), EntryScreen::Skip);
        assert_eq!(job.screen_entry(8, false), EntryScreen::Skip);
        assert_eq!(job.screen_entry(6, true), EntryScreen::Skip);
        assert_eq!(job.screen_entry(6, false), EntryScreen::Candidate);
        let mut job = job;
        assert_eq!(
            job.decide_entry(9, ReplayVerdict::Replay),
            ReplayAction::Skip
        );
        assert_eq!(job.reply_cursor(), 5);
    }

    #[test]
    fn test_step_bounds() {
        assert!(replay_step_continues(1, 0));
        assert!(replay_step_continues(
            REPLAY_STEP_MAX_FRAMES - 1,
            REPLAY_STEP_MAX_BYTES - 1
        ));
        assert!(!replay_step_continues(REPLAY_STEP_MAX_FRAMES, 0));
        assert!(!replay_step_continues(1, REPLAY_STEP_MAX_BYTES));
        assert!(!reads_yield_to_replay(MAX_READS_PER_REPLAY_STEP - 1));
        assert!(reads_yield_to_replay(MAX_READS_PER_REPLAY_STEP));
        assert!(!replay_queue_full(MAX_QUEUED_REPLAYS - 1));
        assert!(replay_queue_full(MAX_QUEUED_REPLAYS));
        assert!(!hold_full(MAX_HELD_SENDS - 1, MAX_HELD_BYTES - 1));
        assert!(hold_full(MAX_HELD_SENDS, 0));
        assert!(hold_full(0, MAX_HELD_BYTES));
    }

    /// The old reactor step loop, over the new `advance`: frames fed per step
    /// stop at 64, or once the output reaches 64 KiB.
    #[test]
    fn test_a_step_feeds_at_most_64_frames_or_64_kib() {
        let all: Vec<u64> = (1..=200).collect();
        let store = FakeStore::with(&all, &[]);
        let Some(core) = ResendReplay::new(1, 201, true) else {
            panic!("valid range");
        };
        let mut driver = Driver::new(core);
        let mut out = Vec::new();
        // First step: a page read.
        assert_eq!(
            driver.advance(Some(&store), &allow, &mut out),
            Progress::ReadPage
        );
        // Second step: 64 frames of 10 bytes each.
        let mut fed = 0;
        loop {
            assert_eq!(
                driver.advance(Some(&store), &allow, &mut out),
                Progress::Wrote
            );
            fed += 1;
            if !replay_step_continues(fed, fed * 10) {
                break;
            }
        }
        assert_eq!(fed, REPLAY_STEP_MAX_FRAMES);
        // Frames of 4 KiB: the byte bound ends the step first.
        let mut fed = 0;
        loop {
            assert_eq!(
                driver.advance(Some(&store), &allow, &mut out),
                Progress::Wrote
            );
            fed += 1;
            if !replay_step_continues(fed, fed * 4096) {
                break;
            }
        }
        assert_eq!(fed, 16);
    }

    /// The pre-stage-3 `advance_resend`, transcribed with the fake store, for
    /// the equivalence test.
    fn reference(
        begin: u64,
        new_seq: u64,
        store: Option<&FakeStore>,
        gate: &dyn Fn(u64) -> ReplayVerdict,
    ) -> Vec<Out> {
        if begin == 0 || begin >= new_seq {
            return Vec::new();
        }
        let end_seq = new_seq - 1;
        let mut cursor = begin;
        let mut read_from = begin;
        let mut store_done = store.is_none();
        let mut page: std::vec::IntoIter<(u64, bool)> = Vec::new().into_iter();
        let mut pending: Option<u64> = None;
        let mut out = Vec::new();
        loop {
            if let Some(seq) = pending.take() {
                out.push(Out::Replay(seq));
                cursor = seq.checked_add(1).unwrap_or(new_seq);
                continue;
            }
            if let Some((seq, admin)) = page.next() {
                if seq < cursor || seq > end_seq || admin {
                    continue;
                }
                if gate(seq) == ReplayVerdict::GapFill {
                    continue;
                }
                if seq > cursor {
                    out.push(Out::Fill {
                        at: cursor,
                        new_seq: seq,
                    });
                    cursor = seq;
                    pending = Some(seq);
                    continue;
                }
                out.push(Out::Replay(seq));
                cursor = seq.checked_add(1).unwrap_or(new_seq);
                continue;
            }
            if !store_done {
                let Some(store) = store else {
                    store_done = true;
                    continue;
                };
                if read_from > end_seq {
                    store_done = true;
                    continue;
                }
                let request = PageRequest {
                    from: read_from,
                    through: end_seq,
                    limit: REPLAY_PAGE_LIMIT,
                };
                match store.page(request) {
                    None => store_done = true,
                    Some(read) => {
                        match read.last().map(|(seq, _)| *seq) {
                            None => store_done = true,
                            Some(_) if read.len() < REPLAY_PAGE_LIMIT => store_done = true,
                            Some(furthest) => match furthest.checked_add(1) {
                                Some(next) if next <= end_seq => read_from = next,
                                _ => store_done = true,
                            },
                        }
                        page = read.into_iter();
                    }
                }
                continue;
            }
            if cursor < new_seq {
                out.push(Out::Fill {
                    at: cursor,
                    new_seq,
                });
            }
            return out;
        }
    }

    #[test]
    fn test_equivalent_to_the_old_reactor_logic() {
        // Deterministic mix of apps, admins, holes and vetoes over ranges
        // that cross page boundaries.
        let mut cases = 0;
        for seed in 0_u64..40 {
            let mut apps = Vec::new();
            let mut admins = Vec::new();
            for seq in 1..=700_u64 {
                match (seq * 7 + seed * 13) % 11 {
                    0 | 1 => {}
                    2 => admins.push(seq),
                    _ => apps.push(seq),
                }
            }
            let mut store = FakeStore::with(&apps, &admins);
            if seed % 5 == 4 {
                store.fail_from = Some(300 + seed);
            }
            let vetoed: BTreeSet<u64> = (1..=700).filter(|seq| (seq + seed) % 9 == 0).collect();
            let gate = |seq: u64| {
                if vetoed.contains(&seq) {
                    ReplayVerdict::GapFill
                } else {
                    ReplayVerdict::Replay
                }
            };
            for (begin, new_seq) in [
                (1, 701),
                (seed + 1, 260 + seed),
                (255, 258),
                (5, 5),
                (600, 650),
            ] {
                for with_store in [true, false] {
                    let store = with_store.then_some(&store);
                    let (new, _) = run(begin, new_seq, store, &gate);
                    assert_eq!(
                        new,
                        reference(begin, new_seq, store, &gate),
                        "seed {seed} {begin}..{new_seq}"
                    );
                    if begin < new_seq {
                        assert_covers(&new, begin, new_seq);
                    }
                    cases += 1;
                }
            }
        }
        assert_eq!(cases, 400);
    }

    #[test]
    fn test_end_seq_no_infinity_on_each_version() {
        let versions = [
            (FixVersion::Fix40, EndSeqNoInfinity::Nines),
            (FixVersion::Fix41, EndSeqNoInfinity::Nines),
            (FixVersion::Fix42, EndSeqNoInfinity::Zero),
            (FixVersion::Fix43, EndSeqNoInfinity::Zero),
            (FixVersion::Fix44, EndSeqNoInfinity::Zero),
            (FixVersion::Fix50, EndSeqNoInfinity::Zero),
            (FixVersion::Fix50Sp1, EndSeqNoInfinity::Zero),
            (FixVersion::Fix50Sp2, EndSeqNoInfinity::Zero),
            (FixVersion::Fixt11, EndSeqNoInfinity::Zero),
        ];
        for (version, expected) in versions {
            let infinity = EndSeqNoInfinity::for_version(version);
            assert_eq!(infinity, expected, "{version:?}");
            // 0 is infinity on every version.
            assert_eq!(
                decide_resend_request(Some(3), Some(0), 10, infinity),
                ResendRequestDecision::Replay {
                    begin_seq: 3,
                    new_seq: 10
                },
                "{version:?}"
            );
            // 999999 is infinity only before FIX 4.2, and a literal bound
            // (clamped to what was sent) after; both answer 3..10 here.
            assert_eq!(
                decide_resend_request(Some(3), Some(999_999), 10, infinity),
                ResendRequestDecision::Replay {
                    begin_seq: 3,
                    new_seq: 10
                },
                "{version:?}"
            );
            // Past 999999 sent, the difference shows.
            let decision = decide_resend_request(Some(3), Some(999_999), 2_000_000, infinity);
            let new_seq = if expected == EndSeqNoInfinity::Nines {
                2_000_000
            } else {
                1_000_000
            };
            assert_eq!(
                decision,
                ResendRequestDecision::Replay {
                    begin_seq: 3,
                    new_seq
                },
                "{version:?}"
            );
            assert_eq!(
                infinity.sentinel(),
                if expected == EndSeqNoInfinity::Nines {
                    999_999
                } else {
                    0
                }
            );
        }
    }

    #[test]
    fn test_decide_resend_request_refusals_and_bounds() {
        let zero = EndSeqNoInfinity::Zero;
        assert_eq!(
            decide_resend_request(None, Some(0), 10, zero),
            ResendRequestDecision::MissingBeginSeqNo
        );
        assert_eq!(
            decide_resend_request(Some(1), None, 10, zero),
            ResendRequestDecision::MissingEndSeqNo
        );
        assert_eq!(
            decide_resend_request(Some(0), Some(0), 10, zero),
            ResendRequestDecision::BeginSeqNoOutsideSent {
                begin_seq: 0,
                next_sender: 10
            }
        );
        assert_eq!(
            decide_resend_request(Some(10), Some(0), 10, zero),
            ResendRequestDecision::BeginSeqNoOutsideSent {
                begin_seq: 10,
                next_sender: 10
            }
        );
        assert_eq!(
            decide_resend_request(Some(5), Some(4), 10, zero),
            ResendRequestDecision::EndSeqNoBelowBegin {
                begin_seq: 5,
                end_seq: 4
            }
        );
        assert_eq!(
            decide_resend_request(Some(5), Some(6), 10, zero),
            ResendRequestDecision::Replay {
                begin_seq: 5,
                new_seq: 7
            }
        );
        assert_eq!(
            decide_resend_request(Some(5), Some(5), 10, zero),
            ResendRequestDecision::Replay {
                begin_seq: 5,
                new_seq: 6
            }
        );
        assert_eq!(
            decide_resend_request(Some(5), Some(u64::MAX), 10, zero),
            ResendRequestDecision::Replay {
                begin_seq: 5,
                new_seq: 10
            },
            "EndSeqNo u64::MAX is clamped, never wrapped"
        );
        // FIX 4.0/4.1 read a literal 0 as infinity rather than below begin.
        assert_eq!(
            decide_resend_request(Some(5), Some(0), 10, EndSeqNoInfinity::Nines),
            ResendRequestDecision::Replay {
                begin_seq: 5,
                new_seq: 10
            }
        );
    }

    #[test]
    fn test_opening_replay_789() {
        assert_eq!(
            decide_opening_replay(2, 5, 6),
            OpeningReplay::Replay {
                begin_seq: 2,
                new_seq: 5
            }
        );
        assert_eq!(
            decide_opening_replay(2, 6, 6),
            OpeningReplay::Replay {
                begin_seq: 2,
                new_seq: 6
            }
        );
        assert_eq!(decide_opening_replay(0, 5, 6), OpeningReplay::OutsideSent);
        assert_eq!(decide_opening_replay(5, 5, 6), OpeningReplay::OutsideSent);
        assert_eq!(decide_opening_replay(2, 7, 6), OpeningReplay::OutsideSent);
        // The 789 range is replayed like any ResendRequest: stops before the
        // session's own Logon (5), admin Logon at 1 gap-filled.
        let store = FakeStore::with(&[2, 3], &[1, 4]);
        let (out, _) = run(2, 5, Some(&store), &allow);
        assert_eq!(
            out,
            vec![
                Out::Replay(2),
                Out::Replay(3),
                Out::Fill { at: 4, new_seq: 5 }
            ]
        );
    }

    #[test]
    fn test_rebuild_field_decisions() {
        assert_eq!(replay_field(8), ReplayField::Framing);
        assert_eq!(replay_field(9), ReplayField::Framing);
        assert_eq!(replay_field(43), ReplayField::Reinserted);
        assert_eq!(replay_field(122), ReplayField::Reinserted);
        assert_eq!(replay_field(52), ReplayField::SendingTime);
        assert_eq!(replay_field(35), ReplayField::Copied);
        assert_eq!(replay_field(554), ReplayField::Copied);
        assert_eq!(
            orig_sending_time(None, "20261020-10:00:00"),
            "20261020-10:00:00"
        );
        assert_eq!(
            orig_sending_time(Some("20261019-09:00:00"), "20261020-10:00:00"),
            "20261019-09:00:00",
            "a resend of a resend keeps the first transmission's time"
        );
    }
}
