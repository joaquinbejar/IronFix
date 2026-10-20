/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! Sans-IO core, stages 6a and 6b: the session state object the core owns.
//!
//! Stages 1 to 5 moved the reactor's protocol *decisions* into free
//! functions; the state those decisions read and update still lived in the
//! Tokio reactor's own fields. [`SessionCore`] takes that state over: the
//! outstanding `ResendRequest` (2) recovery, the Logon held behind a
//! `NextExpectedMsgSeqNum` (789) gap, the `PossDupFlag` (43) spanning
//! re-request mark, the counterparty's owed Logout (5), whether this
//! session's own Logout has been fed and why, the `TestReqID` (112) of a
//! TestRequest (1) not yet written whole, and the read budget between replay
//! steps (stage 6a).
//!
//! Stage 6b moves the queues themselves in: the messages held behind a
//! resend ([`HeldEntry`]), the resends this session owes ([`ReplayJob`]),
//! and the messages queued above a gap ([`GapEntry`]). Their payloads are the
//! driver's: the core cannot name a frame type (it depends on `ironfix-core`
//! only), so a driver describes its payloads once with [`SessionPayloads`]
//! and the core stores them opaquely, counting what the bounds need.
//!
//! Like the rest of the core it performs no I/O, reads no clock and never
//! awaits: every method that starts or checks a clock takes `now` from the
//! driver. The driver keeps what only it can do: build, encode and write
//! frames, read the store, call the application, and its own transport
//! bookkeeping.

use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

use crate::config::{GapPolicy, SessionConfig};
use crate::gap_queue::{GapAdmission, GapEntry, GapQueue, GapReady, Insert};
use crate::logout::{LogoutPhase, OwedLogout, PeerLogoutDecision, decide_peer_logout};
use crate::phase::SessionPhase;
use crate::replay::{ResendReplay, hold_full, reads_yield_to_replay, replay_queue_full};
use crate::sans_io::{
    GapRequest, LivenessGate, RecoveryProgress, ResendState, StallAction, decide_gap_request,
    decide_stall, merged_high_water, note_inbound_progress, spanned_rerequest,
};

/// What to do with a Logon held behind a `NextExpectedMsgSeqNum` (789) gap,
/// given the next number the session expects
/// ([`SessionCore::decide_held_logon_release`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HeldLogonRelease {
    /// No Logon is held, or the gap below it is still open: nothing to do.
    Wait,
    /// The gap was filled past the held Logon's number (its answer covered
    /// it): the hold is dropped and nothing is consumed.
    Passed {
        /// The held Logon's `MsgSeqNum` (34).
        logon_seq: u64,
    },
    /// The gap below the held Logon is filled: the driver consumes its number
    /// now (persist, then advance the target counter). The hold is dropped.
    Consume {
        /// The held Logon's `MsgSeqNum` (34).
        logon_seq: u64,
    },
}

/// The driver's payload types, which the core stores without reading.
///
/// `ironfix-session` depends on `ironfix-core` only, so it cannot name a
/// frame, a store record or an engine receipt. A driver implements this once
/// (usually on a unit type) and the core holds its values opaquely, asking
/// only for the byte counts its bounds need. Each count is the driver's to
/// define; it is asked once when an entry goes in and once when it comes
/// out, so it must return the same value for the same entry.
pub trait SessionPayloads {
    /// A message that takes a new sequence number, held behind a resend
    /// ([`HeldEntry::Message`]).
    type Held: fmt::Debug;
    /// A frame received above a gap and queued ([`GapEntry::Frame`]).
    type Gapped: fmt::Debug;
    /// What the driver keeps for one owed resend besides the core's
    /// [`ResendReplay`]: the stored page it is replaying, a rebuilt frame.
    type Replay: fmt::Debug;
    /// Why this session sent its own Logout, reported when the exchange ends.
    type LogoutCause: fmt::Debug;

    /// What a held entry counts against
    /// [`MAX_HELD_BYTES`](crate::MAX_HELD_BYTES), the `ResendRequest` marker
    /// included.
    fn held_bytes(entry: &HeldEntry<Self::Held>) -> usize;

    /// What a queued frame counts against the gap queue's byte bound.
    fn gapped_bytes(frame: &Self::Gapped) -> usize;
}

/// No payloads: every type is `()` and every entry counts zero bytes, so only
/// the count bounds apply. For a driver that queues nothing, and for tests.
impl SessionPayloads for () {
    type Held = ();
    type Gapped = ();
    type Replay = ();
    type LogoutCause = ();

    fn held_bytes(_: &HeldEntry<()>) -> usize {
        0
    }

    fn gapped_bytes((): &()) -> usize {
        0
    }
}

/// One entry held behind a resend this session owes: written, in order, once
/// the resend is done ([`SessionCore::unhold`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeldEntry<M> {
    /// A message built when it was asked for (a Heartbeat answering a
    /// TestRequest, a session Reject), with whatever the driver tracks for it.
    Message(M),
    /// The `ResendRequest` (2) for the gap being recovered. It is built when
    /// it is written, from the gap as it stands then
    /// ([`SessionCore::resend_expected`]), and skipped if the gap closed
    /// meanwhile. At most one is held ([`SessionCore::hold_resend_request`]).
    ResendRequest,
}

/// One resend this session owes the counterparty: the core's
/// [`ResendReplay`] and the driver's payload for it.
#[derive(Debug)]
pub struct ReplayJob<R> {
    replay: ResendReplay,
    payload: R,
}

impl<R> ReplayJob<R> {
    /// The decision state of the replay.
    #[must_use]
    pub const fn replay(&self) -> &ResendReplay {
        &self.replay
    }

    /// The decision state of the replay, to advance it.
    pub const fn replay_mut(&mut self) -> &mut ResendReplay {
        &mut self.replay
    }

    /// The driver's payload.
    #[must_use]
    pub const fn payload(&self) -> &R {
        &self.payload
    }

    /// The driver's payload, to advance it.
    pub const fn payload_mut(&mut self) -> &mut R {
        &mut self.payload
    }
}

/// The session state the sans-IO core owns for one live session.
///
/// Stages 6a and 6b of issue #91 (ADR-0002). A driver creates one per
/// session once the Logon exchange is done, and routes every read and update
/// of that state through it. Fields are private: each method names the
/// protocol event it records or the decision it answers. `P` names the
/// driver's payloads ([`SessionPayloads`]).
pub struct SessionCore<P: SessionPayloads = ()> {
    resend: Option<ResendState>,
    held_logon: Option<u64>,
    logout_owed: Option<OwedLogout>,
    spanning_rerequested: Option<u64>,
    logout_sent: bool,
    logout_cause: Option<P::LogoutCause>,
    unwritten_test_request: Option<String>,
    reads_since_replay_step: u32,
    held: VecDeque<HeldEntry<P::Held>>,
    held_sends: usize,
    held_bytes: usize,
    replays: VecDeque<ReplayJob<P::Replay>>,
    gap_queue: Option<GapQueue<P>>,
}

impl<P: SessionPayloads> fmt::Debug for SessionCore<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Counts only for what may carry counterparty text or frames: the
        // owed Logout's `Text` (58), a `TestReqID` (112), queued frames.
        f.debug_struct("SessionCore")
            .field("resend", &self.resend)
            .field("held_logon", &self.held_logon)
            .field("logout_owed", &self.logout_owed.is_some())
            .field("spanning_rerequested", &self.spanning_rerequested)
            .field("logout_sent", &self.logout_sent)
            .field("logout_cause", &self.logout_cause.is_some())
            .field(
                "unwritten_test_request",
                &self.unwritten_test_request.is_some(),
            )
            .field("reads_since_replay_step", &self.reads_since_replay_step)
            .field("held", &(self.held_sends, self.held_bytes))
            .field("replays", &self.replays.len())
            .field(
                "gap_queue",
                &self
                    .gap_queue
                    .as_ref()
                    .map(|queue| (queue.len(), queue.bytes())),
            )
            .finish()
    }
}

impl<P: SessionPayloads> Default for SessionCore<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: SessionPayloads> SessionCore<P> {
    /// A session with no recovery, no hold, no Logout, no probe, no resend
    /// owed, and no gap queue (as under [`GapPolicy::Discard`]).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            resend: None,
            held_logon: None,
            logout_owed: None,
            spanning_rerequested: None,
            logout_sent: false,
            logout_cause: None,
            unwritten_test_request: None,
            reads_since_replay_step: 0,
            held: VecDeque::new(),
            held_sends: 0,
            held_bytes: 0,
            replays: VecDeque::new(),
            gap_queue: None,
        }
    }

    /// As [`Self::new`], queuing messages above a gap as `policy` says: under
    /// [`GapPolicy::Queue`] they are held and released in order once the gap
    /// is filled; under [`GapPolicy::Discard`] nothing is queued.
    #[must_use]
    pub fn with_gap_policy(policy: GapPolicy) -> Self {
        let mut core = Self::new();
        core.gap_queue = GapQueue::for_policy(policy);
        core
    }

    // --- Gap recovery -----------------------------------------------------

    /// The outstanding recovery, if a gap is being recovered.
    #[must_use]
    pub const fn resend(&self) -> Option<&ResendState> {
        self.resend.as_ref()
    }

    /// Whether a gap is being recovered.
    #[must_use]
    pub const fn recovering(&self) -> bool {
        self.resend.is_some()
    }

    /// Whether a gap at `expected` reaching `high_water` needs a new
    /// `ResendRequest` (2); raises the water mark of the recovery already
    /// armed ([`decide_gap_request`]).
    pub const fn decide_gap_request(&mut self, expected: u64, high_water: u64) -> GapRequest {
        decide_gap_request(self.resend.as_mut(), expected, high_water)
    }

    /// Records a `ResendRequest` from `expected` that went out at `now`: the
    /// recovery restarts with one attempt spent, keeping the highest water
    /// mark seen so far ([`ResendState::first`], [`merged_high_water`]).
    pub fn arm_requested(
        &mut self,
        expected: u64,
        high_water: u64,
        config: &SessionConfig,
        now: Instant,
    ) {
        let high_water = merged_high_water(self.resend.as_ref(), high_water);
        self.resend = Some(ResendState::first(expected, high_water, config, now));
    }

    /// Records a `ResendRequest` from `expected` held behind a resend of
    /// this session: recovery is armed with no attempt spent, and the attempt
    /// is charged when the request is written ([`Self::take_resend_charge`]).
    pub fn arm_held_request(
        &mut self,
        expected: u64,
        high_water: u64,
        config: &SessionConfig,
        now: Instant,
    ) {
        let high_water = merged_high_water(self.resend.as_ref(), high_water);
        let mut state = ResendState::implied(expected, high_water, config, now);
        state.charge_held_request();
        self.resend = Some(state);
    }

    /// Arms recovery from `expected` for a request not charged against the
    /// retry budget: recovery already armed keeps its attempts and restarts
    /// its clock at `now`; otherwise it starts implied.
    pub fn arm_uncharged(
        &mut self,
        expected: u64,
        high_water: u64,
        config: &SessionConfig,
        now: Instant,
    ) {
        match self.resend.as_mut() {
            Some(state) => state.rearm_uncharged(expected, high_water, now),
            None => {
                self.resend = Some(ResendState::implied(expected, high_water, config, now));
            }
        }
    }

    /// Holds the counterparty's gapped Logon (or acknowledgement) numbered
    /// `logon_seq`: the gap from `expected` below it is one the counterparty
    /// resends on its own (both sides declared 789), so it is armed as an
    /// implied recovery and no request is sent.
    pub fn hold_logon(
        &mut self,
        expected: u64,
        logon_seq: u64,
        config: &SessionConfig,
        now: Instant,
    ) {
        self.resend = Some(ResendState::implied(expected, logon_seq, config, now));
        self.held_logon = Some(logon_seq);
    }

    /// A real `ResendRequest` went out: a held Logon is left to its answer.
    /// Returns the held Logon's number, if one was held, for the driver's
    /// log.
    pub const fn release_held_logon_to_request(&mut self) -> Option<u64> {
        self.held_logon.take()
    }

    /// The held Logon's `MsgSeqNum` (34), if one is held.
    #[must_use]
    pub const fn held_logon(&self) -> Option<u64> {
        self.held_logon
    }

    /// What the held Logon needs now that the session expects `next_target`
    /// ([`HeldLogonRelease`]). Every answer but `Wait` drops the hold.
    pub const fn decide_held_logon_release(&mut self, next_target: u64) -> HeldLogonRelease {
        let Some(logon_seq) = self.held_logon else {
            return HeldLogonRelease::Wait;
        };
        if next_target < logon_seq {
            return HeldLogonRelease::Wait;
        }
        self.held_logon = None;
        if next_target > logon_seq {
            HeldLogonRelease::Passed { logon_seq }
        } else {
            HeldLogonRelease::Consume { logon_seq }
        }
    }

    /// Reconciles the recovery with in-order progress to `next_target` at
    /// `now` ([`note_inbound_progress`]).
    pub fn note_inbound_progress(&mut self, next_target: u64, now: Instant) -> RecoveryProgress {
        note_inbound_progress(&mut self.resend, next_target, now)
    }

    /// Whether a recovery that made no progress is retried or abandoned at
    /// `now` ([`decide_stall`]). `request_unwritten` says the last request is
    /// still in the driver's output, so its clock has not started.
    #[must_use]
    pub fn decide_stall(&self, now: Instant, request_unwritten: bool) -> StallAction {
        decide_stall(self.resend.as_ref(), now, request_unwritten)
    }

    /// A retried request went out at `now`: one more attempt is spent.
    pub fn record_retry(&mut self, now: Instant) {
        if let Some(state) = self.resend.as_mut() {
            state.record_retry(now);
        }
    }

    /// The last request was written whole at `now`: its stall clock starts.
    pub const fn restart_resend_clock(&mut self, now: Instant) {
        if let Some(state) = self.resend.as_mut() {
            state.restart_clock(now);
        }
    }

    /// Takes the charge a held request owes, if the recovery has one: the
    /// held request is consumed by the write that follows, whatever its
    /// outcome.
    pub const fn take_resend_charge(&mut self) -> bool {
        match self.resend.as_mut() {
            Some(state) => state.take_charge(),
            None => false,
        }
    }

    /// A held request was written at `now`: a charged one pays its attempt,
    /// an uncharged one only restarts the stall clock.
    pub fn note_held_request_written(&mut self, charged: bool, now: Instant) {
        if charged {
            self.record_retry(now);
        } else {
            self.restart_resend_clock(now);
        }
    }

    /// The gap start a held `ResendRequest` is built from when it is written,
    /// or `None` when the gap closed while it was held.
    #[must_use]
    pub fn resend_expected(&self) -> Option<u64> {
        self.resend.as_ref().map(ResendState::expected)
    }

    /// The re-request a possible-duplicate gap fill below `expected` with
    /// `NewSeqNo` (36) `new_seq_no` calls for, at most once per expected
    /// number ([`spanned_rerequest`]). `may_request` is false once this
    /// session's Logout is out.
    #[must_use]
    pub fn spanned_rerequest(
        &self,
        expected: u64,
        new_seq_no: Option<u64>,
        may_request: bool,
    ) -> Option<u64> {
        spanned_rerequest(expected, new_seq_no, may_request, self.spanning_rerequested)
    }

    /// Records a spanning re-request from `expected`.
    pub const fn note_spanned_rerequest(&mut self, expected: u64) {
        self.spanning_rerequested = Some(expected);
    }

    // --- Logout -----------------------------------------------------------

    /// This session's own Logout was fed to the output, for `cause`: recovery
    /// is over (a session on its way out processes no replay), a held Logon
    /// is dropped, and so is everything queued above a gap (a session on its
    /// way out releases nothing more). Returns how many queued messages were
    /// dropped, for the driver's log.
    pub fn note_local_logout_fed(&mut self, cause: P::LogoutCause) -> usize {
        self.resend = None;
        self.held_logon = None;
        self.logout_sent = true;
        self.logout_cause = Some(cause);
        self.clear_gap_queue()
    }

    /// Takes why this session sent its own Logout, recorded by
    /// [`Self::note_local_logout_fed`]; `None` if it was never fed or was
    /// already taken.
    pub const fn take_logout_cause(&mut self) -> Option<P::LogoutCause> {
        self.logout_cause.take()
    }

    /// Whether this session's own Logout has been fed.
    #[must_use]
    pub const fn logout_sent(&self) -> bool {
        self.logout_sent
    }

    /// What the counterparty's Logout at `now` means in `phase`
    /// ([`decide_peer_logout`]); an owed reply is recorded here, keeping the
    /// first arrival.
    pub fn decide_peer_logout(
        &mut self,
        phase: LogoutPhase,
        now: Instant,
        text: impl FnOnce() -> Option<String>,
        resend_in_progress: bool,
    ) -> PeerLogoutDecision {
        decide_peer_logout(phase, &mut self.logout_owed, now, text, resend_in_progress)
    }

    /// Whether a Logout reply is owed to the counterparty.
    #[must_use]
    pub const fn logout_owed(&self) -> bool {
        self.logout_owed.is_some()
    }

    /// Whether the owed Logout reply has waited `logout_timeout` by `now`.
    #[must_use]
    pub fn owed_logout_due(&self, now: Instant, logout_timeout: Duration) -> bool {
        self.logout_owed
            .as_ref()
            .is_some_and(|owed| owed.is_due(now, logout_timeout))
    }

    /// Takes the owed Logout to reply to it, returning the counterparty's
    /// bounded `Text` (58).
    pub fn take_owed_logout_text(&mut self) -> Option<String> {
        self.logout_owed.take().and_then(OwedLogout::into_text)
    }

    // --- TestRequest probe ------------------------------------------------

    /// A TestRequest with `test_req_id` was fed to the output: its reply
    /// deadline starts once it is written whole
    /// ([`Self::take_written_test_request`]).
    pub fn note_test_request_fed(&mut self, test_req_id: String) {
        self.unwritten_test_request = Some(test_req_id);
    }

    /// The TestRequest fed earlier was written whole: returns its
    /// `TestReqID` (112) so the driver starts its reply deadline.
    pub const fn take_written_test_request(&mut self) -> Option<String> {
        self.unwritten_test_request.take()
    }

    /// The liveness gate of a tick that may write: a TestRequest is not sent
    /// while one is still unwritten, and output waiting counts as traffic.
    #[must_use]
    pub const fn probe_gate(&self, output_waiting: bool) -> LivenessGate {
        LivenessGate::Probe {
            test_request_unwritten: self.unwritten_test_request.is_some(),
            output_waiting,
        }
    }

    // --- Replay pacing and the hold ---------------------------------------

    /// One inbound frame was read while a replay had room to write.
    pub const fn note_read_while_replaying(&mut self) {
        if let Some(reads) = self.reads_since_replay_step.checked_add(1) {
            self.reads_since_replay_step = reads;
        }
    }

    /// A replay step ran: the read budget starts over.
    pub const fn note_replay_step(&mut self) {
        self.reads_since_replay_step = 0;
    }

    /// Whether reading yields one pass to the replay
    /// ([`reads_yield_to_replay`]).
    #[must_use]
    pub const fn reads_yield_to_replay(&self) -> bool {
        reads_yield_to_replay(self.reads_since_replay_step)
    }

    // --- The hold behind a resend ----------------------------------------

    /// Holds `entry` behind the resend under way, counting it against
    /// [`MAX_HELD_SENDS`](crate::MAX_HELD_SENDS) and
    /// [`MAX_HELD_BYTES`](crate::MAX_HELD_BYTES)
    /// ([`SessionPayloads::held_bytes`]).
    pub fn hold(&mut self, entry: HeldEntry<P::Held>) {
        self.note_held(P::held_bytes(&entry));
        self.held.push_back(entry);
    }

    /// Holds a `ResendRequest` (2) behind the resend under way, unless one is
    /// already held: it is built when it is written, from the gap as it
    /// stands then. Returns whether one was added.
    pub fn hold_resend_request(&mut self) -> bool {
        if self
            .held
            .iter()
            .any(|held| matches!(held, HeldEntry::ResendRequest))
        {
            return false;
        }
        self.hold(HeldEntry::ResendRequest);
        true
    }

    /// Takes the oldest held entry, uncounting it.
    pub fn unhold(&mut self) -> Option<HeldEntry<P::Held>> {
        let entry = self.held.pop_front()?;
        self.note_unheld(P::held_bytes(&entry));
        Some(entry)
    }

    /// Takes every held entry, oldest first, leaving the hold empty and its
    /// counts at zero.
    pub fn drain_held(&mut self) -> std::collections::vec_deque::Drain<'_, HeldEntry<P::Held>> {
        self.held_sends = 0;
        self.held_bytes = 0;
        self.held.drain(..)
    }

    /// Counts one entry of `bytes` in.
    const fn note_held(&mut self, bytes: usize) {
        self.held_sends = match self.held_sends.checked_add(1) {
            Some(count) => count,
            None => {
                debug_assert!(false, "held entries overflowed usize");
                usize::MAX
            }
        };
        self.held_bytes = match self.held_bytes.checked_add(bytes) {
            Some(total) => total,
            // Unreachable while reading stops at MAX_HELD_BYTES; a full count
            // still stops reading.
            None => {
                debug_assert!(false, "held bytes overflowed usize");
                usize::MAX
            }
        };
    }

    /// Counts one entry of `bytes` out. The entry was counted in by
    /// [`Self::note_held`] with the same `bytes` (the payload's count is
    /// stable), so neither count can go below zero; were one to, it stops at
    /// zero (and a debug build asserts).
    const fn note_unheld(&mut self, bytes: usize) {
        self.held_sends = match self.held_sends.checked_sub(1) {
            Some(count) => count,
            None => {
                debug_assert!(false, "held entries underflowed");
                0
            }
        };
        self.held_bytes = match self.held_bytes.checked_sub(bytes) {
            Some(total) => total,
            None => {
                debug_assert!(false, "held bytes underflowed");
                0
            }
        };
    }

    /// The number of entries and bytes held behind a resend.
    #[must_use]
    pub const fn held(&self) -> (usize, usize) {
        (self.held_sends, self.held_bytes)
    }

    /// Whether the hold reached either bound ([`hold_full`]).
    #[must_use]
    pub const fn hold_full(&self) -> bool {
        hold_full(self.held_sends, self.held_bytes)
    }

    // --- Resends owed to the counterparty ---------------------------------

    /// Queues the resend of `begin_seq..new_seq` (`new_seq` exclusive) with
    /// the driver's `payload` for it. Without a store (`has_store` false) the
    /// whole range is one gap fill. An empty range queues nothing (returns
    /// `false`); past [`MAX_QUEUED_REPLAYS`](crate::MAX_QUEUED_REPLAYS) the
    /// range is merged into the last queued resend, which has not started
    /// yet (the head is the one under way), so the queue stays bounded and
    /// every number asked for is still answered.
    pub fn queue_replay(
        &mut self,
        begin_seq: u64,
        new_seq: u64,
        has_store: bool,
        payload: P::Replay,
    ) -> bool {
        let Some(replay) = ResendReplay::new(begin_seq, new_seq, has_store) else {
            return false;
        };
        if replay_queue_full(self.replays.len())
            && let Some(last) = self.replays.back_mut()
        {
            last.replay.widen(&replay);
            return true;
        }
        self.replays.push_back(ReplayJob { replay, payload });
        true
    }

    /// Whether a resend is queued or under way: until it is done, new
    /// messages that take a number wait.
    #[must_use]
    pub fn replaying(&self) -> bool {
        !self.replays.is_empty()
    }

    /// How many resends are queued, the one under way included.
    #[must_use]
    pub fn queued_replays(&self) -> usize {
        self.replays.len()
    }

    /// Takes the resend at the head of the queue to advance it; hand it back
    /// with [`Self::resume_replay`] if it is not done.
    ///
    /// # Contract
    ///
    /// - A job taken here is returned with [`Self::resume_replay`] to this
    ///   same `SessionCore`, or dropped because it is finished.
    /// - At most one job is checked out at a time.
    /// - While a job is checked out, the caller finishes or resumes it before
    ///   it admits more replays ([`Self::queue_replay`]) or queries the
    ///   replay state ([`Self::replaying`], [`Self::queued_replays`],
    ///   [`Self::replays`], [`Self::gap_release_paused`]).
    ///
    /// The core does not check this. If it is broken, the replay state is
    /// misreported: a checked-out job is not in the queue, so the queue can
    /// read as empty or shorter than it is, a new range can be queued or
    /// merged ahead of the one under way, and a job resumed into another
    /// core is answered there.
    pub fn take_replay(&mut self) -> Option<ReplayJob<P::Replay>> {
        self.replays.pop_front()
    }

    /// Puts back, at the head, a resend taken by [`Self::take_replay`] that
    /// is not done yet. `job` must be the one job checked out of this same
    /// `SessionCore`; see the contract on [`Self::take_replay`] and what
    /// breaking it misreports.
    pub fn resume_replay(&mut self, job: ReplayJob<P::Replay>) {
        self.replays.push_front(job);
    }

    /// The resends still owed, head first.
    pub fn replays(&self) -> impl Iterator<Item = &ReplayJob<P::Replay>> {
        self.replays.iter()
    }

    /// Drops every resend still owed: a Logout reply that could wait no
    /// longer cuts them short.
    pub fn clear_replays(&mut self) {
        self.replays.clear();
    }

    /// Whether releasing messages queued above a gap pauses: behind a resend
    /// a released message's reply is held too, so once the hold is full
    /// releasing waits for the resend to finish, as reading does.
    #[must_use]
    pub fn gap_release_paused(&self) -> bool {
        self.replaying() && self.hold_full()
    }

    // --- The gap queue ----------------------------------------------------

    /// Whether a gap queue is configured ([`GapPolicy::Queue`]).
    #[must_use]
    pub const fn queues_gaps(&self) -> bool {
        self.gap_queue.is_some()
    }

    /// Offers a message received above the expectation, numbered `seq`, to
    /// the gap queue ([`GapAdmission`]).
    ///
    /// Only an established session (`phase` Active) with no Logout reply
    /// owed queues: a session on its way out releases nothing more. Past a
    /// bound the message is not queued and is acted on as under
    /// [`GapPolicy::Discard`]; the open-ended `ResendRequest` covers it.
    pub fn queue_gapped(
        &mut self,
        phase: &SessionPhase,
        seq: u64,
        entry: GapEntry<P::Gapped>,
    ) -> GapAdmission {
        if !phase.is_active() || self.logout_owed.is_some() {
            return GapAdmission::Bypassed;
        }
        let Some(queue) = self.gap_queue.as_mut() else {
            return GapAdmission::Bypassed;
        };
        match queue.insert(seq, entry) {
            Insert::Queued => GapAdmission::Queued,
            Insert::Duplicate => GapAdmission::Duplicate,
            Insert::Overflow if queue.first_overflow() => GapAdmission::FirstOverflow,
            Insert::Overflow => GapAdmission::Overflow,
        }
    }

    /// Drops every queued message below `expected` and takes the one queued
    /// at `expected`, if any. `None` when no queue is configured or nothing
    /// is queued (one map lookup, no allocation).
    pub fn take_gap_ready(&mut self, expected: u64) -> Option<GapReady<P::Gapped>> {
        let queue = self.gap_queue.as_mut()?;
        if queue.is_empty() {
            return None;
        }
        Some(queue.take_ready(expected))
    }

    /// Drops everything queued above a gap; returns how many messages that
    /// was (0 with no queue).
    pub fn clear_gap_queue(&mut self) -> usize {
        self.gap_queue.as_mut().map_or(0, GapQueue::clear)
    }

    /// The number of messages and bytes queued above a gap; `None` with no
    /// queue configured.
    #[must_use]
    pub fn gap_queued(&self) -> Option<(usize, usize)> {
        self.gap_queue
            .as_ref()
            .map(|queue| (queue.len(), queue.bytes()))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::replay::{
        MAX_HELD_BYTES, MAX_HELD_SENDS, MAX_QUEUED_REPLAYS, MAX_READS_PER_REPLAY_STEP,
    };
    use crate::state::Session;

    /// Payloads that count bytes: a held message and a queued frame are
    /// byte vectors counted by length, the `ResendRequest` marker counts
    /// [`MARKER_BYTES`].
    #[derive(Debug)]
    pub(crate) struct TestPayloads;

    /// What the `ResendRequest` marker counts in [`TestPayloads`].
    const MARKER_BYTES: usize = 7;

    impl SessionPayloads for TestPayloads {
        type Held = Vec<u8>;
        type Gapped = Vec<u8>;
        type Replay = &'static str;
        type LogoutCause = &'static str;

        fn held_bytes(entry: &HeldEntry<Vec<u8>>) -> usize {
            match entry {
                HeldEntry::Message(message) => message.len(),
                HeldEntry::ResendRequest => MARKER_BYTES,
            }
        }

        fn gapped_bytes(frame: &Vec<u8>) -> usize {
            frame.len()
        }
    }

    fn active() -> SessionPhase {
        SessionPhase::Active(
            Session::new("S")
                .connect()
                .send_logon(Instant::now())
                .on_logon_ack(),
        )
    }

    fn queueing() -> SessionCore<TestPayloads> {
        SessionCore::with_gap_policy(GapPolicy::Queue {
            max_messages: 2,
            max_bytes: 1024,
        })
    }

    #[test]
    fn test_hold_owns_entries_in_order_and_counts_them() {
        let mut core = SessionCore::<TestPayloads>::new();
        core.hold(HeldEntry::Message(vec![1; 10]));
        assert!(core.hold_resend_request());
        assert!(!core.hold_resend_request(), "one marker at most");
        core.hold(HeldEntry::Message(vec![2; 20]));
        assert_eq!(core.held(), (3, 30 + MARKER_BYTES));
        assert_eq!(core.unhold(), Some(HeldEntry::Message(vec![1; 10])));
        assert_eq!(core.held(), (2, 20 + MARKER_BYTES));
        assert_eq!(core.unhold(), Some(HeldEntry::ResendRequest));
        assert!(core.hold_resend_request(), "the marker left, one may join");
        let drained: Vec<_> = core.drain_held().collect();
        assert_eq!(
            drained,
            vec![HeldEntry::Message(vec![2; 20]), HeldEntry::ResendRequest]
        );
        assert_eq!(core.held(), (0, 0));
        assert_eq!(core.unhold(), None);
    }

    #[test]
    fn test_hold_full_by_bytes_with_owned_entries() {
        let mut core = SessionCore::<TestPayloads>::new();
        core.hold(HeldEntry::Message(vec![0; MAX_HELD_BYTES]));
        assert!(core.hold_full());
        let _ = core.unhold();
        assert!(!core.hold_full());
    }

    #[test]
    fn test_replay_queue_refuses_empty_ranges() {
        let mut core = SessionCore::<TestPayloads>::new();
        assert!(!core.queue_replay(5, 5, true, "a"));
        assert!(!core.queue_replay(6, 5, true, "a"));
        assert!(!core.queue_replay(0, 5, true, "a"));
        assert!(!core.replaying());
        assert!(core.queue_replay(3, 6, false, "b"));
        assert!(core.replaying());
        let Some(job) = core.take_replay() else {
            panic!("3..6 is a range")
        };
        assert_eq!(
            (job.replay().reply_cursor(), job.replay().read_from()),
            (3, 3)
        );
        assert_eq!((job.replay().end_seq(), job.replay().new_seq()), (5, 6));
        assert!(
            job.replay().store_done(),
            "without a store the range is one gap fill"
        );
        assert_eq!(*job.payload(), "b");
        assert!(!core.replaying());
        core.resume_replay(job);
        assert_eq!(core.queued_replays(), 1);
        core.clear_replays();
        assert!(!core.replaying());
    }

    #[test]
    fn test_replay_queue_merges_past_the_cap_into_the_last_unstarted_job() {
        let mut core = SessionCore::<TestPayloads>::new();
        let cap = u64::try_from(MAX_QUEUED_REPLAYS).unwrap_or(u64::MAX);
        for seq in 2..2 + cap + 6 {
            assert!(core.queue_replay(seq, seq + 1, true, "j"));
        }
        assert_eq!(core.queued_replays(), MAX_QUEUED_REPLAYS);
        let Some(head) = core.replays().next() else {
            panic!("the queue is not empty")
        };
        assert_eq!(
            (head.replay().reply_cursor(), head.replay().new_seq()),
            (2, 3)
        );
        let Some(last) = core.replays().last() else {
            panic!("the queue is not empty")
        };
        assert_eq!(last.replay().reply_cursor(), cap + 1);
        assert_eq!(last.replay().new_seq(), cap + 8);
    }

    #[test]
    fn test_gap_release_pauses_only_behind_a_full_hold() {
        let mut core = SessionCore::<TestPayloads>::new();
        core.hold(HeldEntry::Message(vec![0; MAX_HELD_BYTES]));
        assert!(!core.gap_release_paused(), "no resend under way");
        assert!(core.queue_replay(1, 2, true, "r"));
        assert!(core.gap_release_paused());
    }

    #[test]
    fn test_gap_queue_admission_rules() {
        let now = Instant::now();
        let mut discard = SessionCore::<TestPayloads>::new();
        assert!(!discard.queues_gaps());
        assert_eq!(
            discard.queue_gapped(&active(), 5, GapEntry::Processed),
            GapAdmission::Bypassed
        );
        assert_eq!(discard.take_gap_ready(5).map(|r| r.superseded), None);
        assert_eq!(discard.clear_gap_queue(), 0);

        let mut core = queueing();
        assert!(core.queues_gaps());
        let queued =
            SessionPhase::LogoutQueued(Session::new("S").connect().send_logon(now).on_logon_ack());
        assert_eq!(
            core.queue_gapped(&queued, 5, GapEntry::Processed),
            GapAdmission::Bypassed,
            "a session on its way out queues nothing"
        );
        assert_eq!(
            core.queue_gapped(&active(), 5, GapEntry::Frame(vec![1])),
            GapAdmission::Queued
        );
        assert_eq!(
            core.queue_gapped(&active(), 5, GapEntry::Processed),
            GapAdmission::Duplicate
        );
        assert_eq!(
            core.queue_gapped(&active(), 6, GapEntry::Processed),
            GapAdmission::Queued
        );
        assert_eq!(
            core.queue_gapped(&active(), 7, GapEntry::Processed),
            GapAdmission::FirstOverflow
        );
        assert_eq!(
            core.queue_gapped(&active(), 8, GapEntry::Processed),
            GapAdmission::Overflow
        );
        assert_eq!(core.gap_queued(), Some((2, 1)));
        let Some(ready) = core.take_gap_ready(5) else {
            panic!("something is queued")
        };
        assert_eq!(ready.next, Some(GapEntry::Frame(vec![1])));
        assert_eq!(core.clear_gap_queue(), 1);
        assert!(
            core.take_gap_ready(6).is_none(),
            "an empty queue is skipped"
        );
    }

    #[test]
    fn test_gap_queue_bypassed_while_a_logout_reply_is_owed() {
        let mut core = queueing();
        let _ = core.decide_peer_logout(LogoutPhase::Active, Instant::now(), || None, true);
        assert!(core.logout_owed());
        assert_eq!(
            core.queue_gapped(&active(), 5, GapEntry::Processed),
            GapAdmission::Bypassed
        );
    }

    #[test]
    fn test_local_logout_records_cause_and_drops_the_gap_queue() {
        let mut core = queueing();
        let _ = core.queue_gapped(&active(), 5, GapEntry::Frame(vec![1, 2]));
        assert_eq!(core.note_local_logout_fed("asked"), 1);
        assert!(core.logout_sent());
        assert_eq!(core.gap_queued(), Some((0, 0)));
        assert_eq!(core.take_logout_cause(), Some("asked"));
        assert_eq!(core.take_logout_cause(), None);
        assert!(core.logout_sent(), "taking the cause keeps the fact");
    }

    fn config() -> SessionConfig {
        let (Ok(sender), Ok(target)) = (
            ironfix_core::types::CompId::new("CLIENT"),
            ironfix_core::types::CompId::new("VENUE"),
        ) else {
            unreachable!("CLIENT and VENUE are valid CompIDs")
        };
        SessionConfig::new(sender, target, "FIX.4.4")
    }

    #[test]
    fn test_new_is_empty() {
        let core = SessionCore::<()>::new();
        assert_eq!(
            format!("{core:?}"),
            format!("{:?}", SessionCore::<()>::default())
        );
        assert!(!core.replaying());
        assert_eq!(core.gap_queued(), None);
        assert!(!core.recovering());
        assert!(!core.logout_sent());
        assert!(!core.logout_owed());
        assert_eq!(core.held(), (0, 0));
        assert!(!core.hold_full());
        assert_eq!(core.held_logon(), None);
    }

    #[test]
    fn test_gap_request_then_already_requested() {
        let now = Instant::now();
        let mut core = SessionCore::<()>::new();
        assert_eq!(core.decide_gap_request(5, 9), GapRequest::Request);
        core.arm_requested(5, 9, &config(), now);
        assert_eq!(core.resend().map(ResendState::attempts), Some(1));
        assert_eq!(core.decide_gap_request(5, 12), GapRequest::AlreadyRequested);
        assert_eq!(core.resend().map(ResendState::high_water), Some(12));
        // A new gap start re-requests and never narrows the water mark.
        assert_eq!(core.decide_gap_request(7, 8), GapRequest::Request);
        core.arm_requested(7, 8, &config(), now);
        assert_eq!(core.resend_expected(), Some(7));
        assert_eq!(core.resend().map(ResendState::high_water), Some(12));
    }

    #[test]
    fn test_held_request_charges_on_write() {
        let now = Instant::now();
        let mut core = SessionCore::<()>::new();
        core.arm_held_request(5, 9, &config(), now);
        assert_eq!(core.resend().map(ResendState::attempts), Some(0));
        let charged = core.take_resend_charge();
        assert!(charged);
        core.note_held_request_written(charged, now);
        assert_eq!(core.resend().map(ResendState::attempts), Some(1));
        // The charge is taken once.
        assert!(!core.take_resend_charge());
    }

    #[test]
    fn test_uncharged_rearm_keeps_attempts() {
        let now = Instant::now();
        let mut core = SessionCore::<()>::new();
        core.arm_uncharged(5, 9, &config(), now);
        assert_eq!(core.resend().map(ResendState::attempts), Some(0));
        core.arm_requested(5, 9, &config(), now);
        core.arm_uncharged(6, 9, &config(), now);
        assert_eq!(core.resend().map(ResendState::attempts), Some(1));
        assert_eq!(core.resend_expected(), Some(6));
    }

    #[test]
    fn test_held_logon_release_paths() {
        let now = Instant::now();
        let mut core = SessionCore::<()>::new();
        assert_eq!(core.decide_held_logon_release(10), HeldLogonRelease::Wait);
        core.hold_logon(4, 8, &config(), now);
        assert!(core.recovering());
        assert_eq!(core.decide_held_logon_release(6), HeldLogonRelease::Wait);
        assert_eq!(core.held_logon(), Some(8));
        assert_eq!(
            core.decide_held_logon_release(8),
            HeldLogonRelease::Consume { logon_seq: 8 }
        );
        assert_eq!(core.held_logon(), None);

        core.hold_logon(4, 8, &config(), now);
        assert_eq!(
            core.decide_held_logon_release(9),
            HeldLogonRelease::Passed { logon_seq: 8 }
        );

        core.hold_logon(4, 8, &config(), now);
        assert_eq!(core.release_held_logon_to_request(), Some(8));
        assert_eq!(core.release_held_logon_to_request(), None);
    }

    #[test]
    fn test_progress_closes_recovery_past_water_mark() {
        let now = Instant::now();
        let mut core = SessionCore::<()>::new();
        assert_eq!(
            core.note_inbound_progress(3, now),
            RecoveryProgress::NoRecovery
        );
        core.arm_requested(5, 6, &config(), now);
        assert_eq!(
            core.note_inbound_progress(6, now),
            RecoveryProgress::Advanced
        );
        assert_eq!(core.note_inbound_progress(7, now), RecoveryProgress::Closed);
        assert!(!core.recovering());
    }

    #[test]
    fn test_stall_retry_then_abandon() {
        let start = Instant::now();
        let cfg = config();
        let mut core = SessionCore::<()>::new();
        assert_eq!(core.decide_stall(start, false), StallAction::Wait);
        core.arm_requested(5, 9, &cfg, start);
        let late = start + cfg.resend_timeout + Duration::from_millis(1);
        // A request still unwritten has no clock yet.
        assert_eq!(core.decide_stall(late, true), StallAction::Wait);
        let mut now = late;
        while let StallAction::Retry { expected } = core.decide_stall(now, false) {
            assert_eq!(expected, 5);
            core.record_retry(now);
            now += cfg.resend_timeout + Duration::from_millis(1);
        }
        assert!(matches!(
            core.decide_stall(now, false),
            StallAction::Abandon { expected: 5, .. }
        ));
    }

    #[test]
    fn test_spanning_rerequest_once_per_expected() {
        let mut core = SessionCore::<()>::new();
        assert_eq!(core.spanned_rerequest(5, Some(9), true), Some(9));
        core.note_spanned_rerequest(5);
        assert_eq!(core.spanned_rerequest(5, Some(9), true), None);
        assert_eq!(core.spanned_rerequest(6, Some(9), false), None);
    }

    #[test]
    fn test_local_logout_ends_recovery() {
        let now = Instant::now();
        let mut core = SessionCore::<()>::new();
        core.hold_logon(4, 8, &config(), now);
        assert_eq!(core.note_local_logout_fed(()), 0);
        assert!(!core.recovering());
        assert_eq!(core.held_logon(), None);
        assert!(core.logout_sent());
    }

    #[test]
    fn test_owed_logout_keeps_first_arrival() {
        let start = Instant::now();
        let timeout = Duration::from_secs(10);
        let mut core = SessionCore::<()>::new();
        let decision =
            core.decide_peer_logout(LogoutPhase::Active, start, || Some("first".into()), true);
        assert_eq!(decision, PeerLogoutDecision::AwaitResend);
        let later = start + Duration::from_secs(5);
        let _ = core.decide_peer_logout(LogoutPhase::Active, later, || Some("second".into()), true);
        assert!(core.logout_owed());
        assert!(!core.owed_logout_due(later, timeout));
        assert!(core.owed_logout_due(start + timeout, timeout));
        assert_eq!(core.take_owed_logout_text().as_deref(), Some("first"));
        assert!(!core.logout_owed());
    }

    #[test]
    fn test_probe_gate_tracks_unwritten_test_request() {
        let mut core = SessionCore::<()>::new();
        assert_eq!(
            core.probe_gate(true),
            LivenessGate::Probe {
                test_request_unwritten: false,
                output_waiting: true
            }
        );
        core.note_test_request_fed("T1".into());
        assert_eq!(
            core.probe_gate(false),
            LivenessGate::Probe {
                test_request_unwritten: true,
                output_waiting: false
            }
        );
        assert_eq!(core.take_written_test_request().as_deref(), Some("T1"));
        assert_eq!(core.take_written_test_request(), None);
    }

    #[test]
    fn test_reads_yield_after_budget() {
        let mut core = SessionCore::<()>::new();
        for _ in 0..MAX_READS_PER_REPLAY_STEP {
            assert!(!core.reads_yield_to_replay());
            core.note_read_while_replaying();
        }
        assert!(core.reads_yield_to_replay());
        core.note_replay_step();
        assert!(!core.reads_yield_to_replay());
    }

    #[test]
    fn test_hold_accounting_and_bounds() {
        let mut core = SessionCore::<()>::new();
        for _ in 0..MAX_HELD_SENDS {
            assert!(!core.hold_full());
            core.hold(HeldEntry::Message(()));
        }
        assert_eq!(core.held(), (MAX_HELD_SENDS, 0));
        assert!(core.hold_full());
        let _ = core.unhold();
        assert!(!core.hold_full());
        assert_eq!(core.drain_held().count(), MAX_HELD_SENDS - 1);
        assert_eq!(core.held(), (0, 0));
    }
}
