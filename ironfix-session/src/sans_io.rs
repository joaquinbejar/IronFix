/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! Sans-IO session core: the protocol decisions a driver acts on.
//!
//! ADR-0002 (option 2) moves the decisions the Tokio reactor in
//! `ironfix-engine` makes into a core that performs no I/O, reads no clock
//! and never awaits. A driver feeds it what it observed (the time, the state
//! of its output) and gets back what to do; the driver then encodes the
//! intent, writes it and runs the callbacks. The Tokio reactor is one such
//! driver. Issue #91 builds the core in stages, one handler family at a time.
//!
//! # Where it lives
//!
//! The core is a module of `ironfix-session`, not a new crate: it needs
//! nothing but `ironfix-core` and the session's own state, and the session
//! crate already is the "pure protocol logic, no I/O" layer. Because this
//! crate must not depend on `ironfix-tagvalue`, the core decides *what* to
//! send (an [`LivenessAction`]) and the driver builds and encodes the frame.
//!
//! # Stage 1: heartbeat, TestRequest and the logout deadline
//!
//! This stage extracts the liveness family, the periodic checks a driver runs
//! on every tick:
//!
//! - [`decide_liveness`]: whether the session has timed out waiting for the
//!   counterparty, owes a TestRequest (1) after inbound silence, or owes an
//!   idle Heartbeat (0), given what the driver's output looks like
//!   ([`LivenessGate`]).
//! - [`logout_timed_out`]: whether a Logout the session sent has waited past
//!   the logout timeout for its acknowledgement.
//! - [`test_request_reply_id`]: the `TestReqID` (112) a Heartbeat answering a
//!   TestRequest echoes.
//!
//! # Stage 2: sequence validation and gap recovery
//!
//! - [`classify_inbound`]: an inbound `MsgSeqNum` (34) is in sequence, a
//!   `PossDupFlag` (43) duplicate to ignore, too low (the session ends) or
//!   beyond a gap ([`InboundSequence`]).
//! - [`ResendState`]: the bookkeeping of one outstanding `ResendRequest` (2):
//!   gap start, water mark, attempts and the stall clock, every clock start
//!   taken from the driver's `now`.
//! - [`decide_gap_request`], [`merged_high_water`]: whether a gap needs a new
//!   request or is already requested, without ever narrowing the range.
//! - [`note_inbound_progress`]: in-order progress advances or closes the
//!   recovery ([`RecoveryProgress`]).
//! - [`decide_stall`]: a gap that made no progress for the resend timeout is
//!   retried or, with its attempts spent, abandoned ([`StallAction`]).
//! - [`spanned_rerequest`], [`spanned_high_water`]: a duplicate
//!   `SequenceReset` (4) GapFill below the expectation whose `NewSeqNo` (36)
//!   spans numbers still missing.
//!
//! # Stage 3: resend replay
//!
//! - [`decide_resend_request`] and [`EndSeqNoInfinity`]: what a
//!   `ResendRequest` (2) asks, with the version's "to infinity" `EndSeqNo`
//!   (16); [`decide_opening_replay`] checks the range a
//!   `NextExpectedMsgSeqNum` (789) asks for.
//! - [`ResendReplay`]: one replay as request/response steps with the driver,
//!   which reads the store ([`PageRequest`], [`PageRead`]), rebuilds each
//!   candidate and runs the replay gate ([`ReplayVerdict`]); the core answers
//!   with what to write ([`ReplayAction`], [`ReplayStep`]), coalescing
//!   administrative messages, holes, unrebuildable frames and vetoes into one
//!   `SequenceReset` (4) GapFill per run.
//! - [`replay_step_continues`], [`reads_yield_to_replay`],
//!   [`replay_queue_full`], [`hold_full`]: the step, queue and hold bounds.
//! - [`replay_field`], [`orig_sending_time`]: the `PossDupFlag` (43) and
//!   `OrigSendingTime` (122) rebuild decisions.
//!
//! # Stage 4: the Logout handshake
//!
//! - [`check_logout_text`]: the `Text` (58) a caller may ask for.
//! - [`decide_local_logout`], [`LocalLogoutReason`]: whether this session's
//!   Logout may start (only the first counts) and the `Text` it carries;
//!   [`LogoutPhase`] summarises the driver's phase, `Queued` until the Logout
//!   is written whole ([`decide_logout_advance`]) and `Pending` after, where
//!   the logout timeout runs ([`logout_timed_out`]).
//! - [`decide_peer_logout`], [`OwedLogout`], [`owed_logout_due`]: the
//!   counterparty's Logout completes ours (crossed or acknowledged) or is
//!   owed a reply, which waits behind a resend of ours within the logout
//!   timeout.
//! - [`LogoutClose`], [`reply_close`], [`settle_close`], [`close_resets`]:
//!   the close-reason family of the exchange, the graceful rule (this
//!   session's own Logout written whole) and the `reset_on_logout` gate,
//!   which only a graceful close passes.
//!
//! # Stage 5: the two Logon handshakes
//!
//! - [`decide_logon_refusal`], [`LogonStage`]: who gets a reply to a refused
//!   Logon, in the authentication order of ADR-0017 (the store is never
//!   touched before `from_admin` accepts); [`default_appl_ver_id_required`]
//!   is the `DefaultApplVerID` (1137) rule of each [`LogonRole`].
//! - [`reset_flag_contradicts`], [`initiator_resets`], [`acceptor_resets`],
//!   [`owes_reset_durably`], [`decide_ack_reset`]: `ResetSeqNumFlag` (141)
//!   and the owed reset of issue #111; [`classify_logon_seq`] and
//!   [`decide_logon_gap`]: the reset rule and the gapped Logon.
//! - [`negotiate_logon_interval`], [`interval_change`],
//!   [`AckHeartBtIntDefect`]: `HeartBtInt` (108).
//! - [`declared_next_expected`], [`screen_next_expected`],
//!   [`plan_next_expected`]: `NextExpectedMsgSeqNum` (789, ADR-0021).
//! - [`decide_seed_source`], [`seed_from_initial`], [`initial_below_store`],
//!   [`seed_from_store`], [`provisional_counters`], [`inbound_loss_span`]:
//!   the starting counters and the start report of issue #105.
//! - [`mismatch_report_applies`], [`LogonCounters`],
//!   [`compare_logon_sequences`]: the sequence-mismatch report of issue #80
//!   (ADR-0015) over the effective startup counters.
//! - [`logon_deadline`], [`logon_timed_out`], [`logon_ack_deadline`]: the
//!   logon timeout.
//!
//! The driver keeps every effect: parsing the Logon's fields, `from_admin`,
//! the store calls, the writes, the callbacks and the typestate transitions.
//!
//! # Stage 6a: the core-owned session state
//!
//! - [`SessionCore`]: the state the decisions above read and update, owned by
//!   the core instead of the driver: the outstanding recovery, the held
//!   Logon ([`HeldLogonRelease`]), the spanning re-request mark, the owed
//!   Logout, whether this session's Logout was fed, the unwritten
//!   TestRequest, the read budget between replay steps and the hold count.
//!
//! # Stage 6b: the phase and the payload queues
//!
//! - [`SessionPhase`]: the phase of a live session (established, own Logout
//!   queued, own Logout pending), wrapping the typestate session so a driver
//!   moves it only through the consuming transitions.
//! - [`SessionPayloads`]: the driver's payload types, stored opaquely. With
//!   it [`SessionCore`] owns the hold behind a resend ([`HeldEntry`]), the
//!   resends owed ([`ReplayJob`]), the gap queue ([`GapEntry`],
//!   [`GapAdmission`], [`GapReady`]) and why this session logged out.
//!   The driver keeps the frames' construction and encoding, the store, the
//!   socket, the callbacks and its own transport bookkeeping.
//!
//! # Time
//!
//! Every function takes `now` from the driver (ADR-0002, "Time source
//! contract"). The Tokio driver passes its own clock, converted at the
//! boundary, so a paused-clock test drives these decisions deterministically.

pub use crate::gap_queue::{GapAdmission, GapEntry, GapReady};
pub use crate::logon::{
    ADOPTED_RESET_NEXT_SENDER, ADOPTED_RESET_NEXT_TARGET, ADOPTED_RESET_STORED_TARGET,
    AckHeartBtIntDefect, AckReset, LogonCounters, LogonGapAction, LogonInboundMismatch,
    LogonOutboundComparison, LogonRefusal, LogonRole, LogonSequenceComparison, LogonStage,
    NEXT_EXPECTED_AFTER_RESET, NextExpectedAhead, NextExpectedBasis, NextExpectedPlan,
    ScreenedNextExpected, SeedSource, StoreSeed, acceptor_resets, classify_logon_seq,
    compare_logon_inbound, compare_logon_outbound, compare_logon_sequences, decide_ack_reset,
    decide_logon_gap, decide_logon_refusal, decide_seed_source, declared_next_expected,
    default_appl_ver_id_required, inbound_loss_span, initial_below_store, initial_seed_applies,
    initiator_resets, interval_change, logon_ack_deadline, logon_deadline, logon_timed_out,
    mismatch_report_applies, negotiate_logon_interval, owes_reset_durably, plan_next_expected,
    provisional_counters, reset_flag_contradicts, screen_next_expected, seed_from_initial,
    seed_from_store,
};
pub use crate::logout::{
    LocalLogoutDecision, LocalLogoutReason, LogoutClose, LogoutPhase, LogoutReplyWrite,
    LogoutTextError, MAX_LOGOUT_TEXT_LEN, OwedLogout, PeerLogoutDecision, check_logout_text,
    close_resets, decide_local_logout, decide_logout_advance, decide_peer_logout, owed_logout_due,
    reply_close, resend_stalled_text, settle_close,
};
pub use crate::phase::SessionPhase;
pub use crate::replay::{
    EndSeqNoInfinity, EntryScreen, GapFillRange, MAX_HELD_BYTES, MAX_HELD_SENDS,
    MAX_QUEUED_REPLAYS, MAX_READS_PER_REPLAY_STEP, OpeningReplay, PageRead, PageRequest,
    REPLAY_PAGE_LIMIT, REPLAY_STEP_MAX_BYTES, REPLAY_STEP_MAX_FRAMES, ReplayAction, ReplayField,
    ReplayStep, ReplayVerdict, ResendReplay, ResendRequestDecision, decide_opening_replay,
    decide_resend_request, hold_full, orig_sending_time, reads_yield_to_replay, replay_field,
    replay_queue_full, replay_step_continues,
};
pub use crate::session_core::{
    HeldEntry, HeldLogonRelease, ReplayJob, SessionCore, SessionPayloads,
};

use crate::config::SessionConfig;
use crate::heartbeat::HeartbeatManager;
use crate::sequence::{SequenceManager, SequenceResult};
use crate::state::{LogoutPending, Session};
use std::time::{Duration, Instant};

/// What the driver's output allows a liveness check to add to it.
///
/// The core does not see the driver's write buffer; the driver summarises it
/// here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LivenessGate {
    /// Only the deadline may be checked; nothing new is written. A driver
    /// uses this while a resend it owes is under way (resent frames are
    /// traffic, so no probe is due) and while its output is saturated (a
    /// stream that never completes a write must stop making progress, so the
    /// write timeout can close the session).
    DeadlinesOnly,
    /// A probe may be written if one is due.
    Probe {
        /// A TestRequest has been handed to the output and not yet written
        /// whole. Its reply deadline has not started, and no second one is
        /// sent meanwhile.
        test_request_unwritten: bool,
        /// Output is waiting to be written. That output is traffic the
        /// counterparty is about to receive, so an idle Heartbeat is not due.
        output_waiting: bool,
    },
}

/// What a liveness check tells the driver to do.
///
/// Deliberately not `#[non_exhaustive]`: a driver matches every action, so a
/// new one is a compile error in each driver rather than an arm that silently
/// does nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LivenessAction {
    /// Nothing is due.
    Idle,
    /// A TestRequest went unanswered past its deadline: the session ends with
    /// a heartbeat timeout.
    CloseHeartbeatTimeout,
    /// Inbound has been silent past the heartbeat interval plus the grace:
    /// send a TestRequest (1). The driver generates the `TestReqID` (112) and
    /// starts its reply deadline once the frame is written whole
    /// ([`HeartbeatManager::on_test_request_sent`]).
    SendTestRequest,
    /// Nothing has been sent for the heartbeat interval: send a Heartbeat (0)
    /// without a `TestReqID`.
    SendHeartbeat,
}

/// Decides the periodic liveness step at `now`.
///
/// The timeout is checked first and wins over everything else. Under
/// [`LivenessGate::Probe`], a due TestRequest is sent unless one is already
/// waiting to be written; when no TestRequest is sent, a due Heartbeat is
/// sent unless output is already waiting. With `HeartBtInt` (108) = 0 the
/// manager reports nothing due, so this returns [`LivenessAction::Idle`].
#[must_use]
pub fn decide_liveness(
    heartbeat: &HeartbeatManager,
    now: Instant,
    gate: LivenessGate,
) -> LivenessAction {
    if heartbeat.is_timed_out(now) {
        return LivenessAction::CloseHeartbeatTimeout;
    }
    match gate {
        LivenessGate::DeadlinesOnly => LivenessAction::Idle,
        LivenessGate::Probe {
            test_request_unwritten,
            output_waiting,
        } => {
            if heartbeat.should_send_test_request(now) && !test_request_unwritten {
                LivenessAction::SendTestRequest
            } else if heartbeat.should_send_heartbeat(now) && !output_waiting {
                LivenessAction::SendHeartbeat
            } else {
                LivenessAction::Idle
            }
        }
    }
}

/// Whether the Logout `session` sent has waited at least `logout_timeout`
/// for the counterparty's Logout by `now`.
///
/// The deadline runs from [`Session::sent_at`], the instant the Logout was
/// written whole. A `now` earlier than that instant counts as no time
/// elapsed.
#[must_use]
pub fn logout_timed_out(
    session: &Session<LogoutPending>,
    now: Instant,
    logout_timeout: Duration,
) -> bool {
    let waited = now
        .checked_duration_since(session.sent_at())
        .unwrap_or(Duration::ZERO);
    waited >= logout_timeout
}

/// The `TestReqID` (112) a Heartbeat answering a TestRequest echoes, from the
/// TestRequest's own 112.
///
/// A `112=` with no value is a malformed TestRequest: there is nothing to
/// echo, and an empty field has no legal wire form, so the Heartbeat goes
/// without a `TestReqID` rather than the session ending over the peer's
/// mistake.
#[must_use]
pub fn test_request_reply_id(test_req_id: Option<&str>) -> Option<&str> {
    test_req_id.filter(|id| !id.is_empty())
}

// Stage 2: sequence validation and gap recovery.

/// How an inbound `MsgSeqNum` (34) stands against the session's expectation,
/// with `PossDupFlag` (43) already applied to a number that is too low.
///
/// Deliberately not `#[non_exhaustive]`, like [`LivenessAction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InboundSequence {
    /// The number is the one expected: the message is consumed.
    InSequence,
    /// Below the expectation and flagged `PossDupFlag` (43) = Y: a duplicate
    /// delivery of a number already consumed, which FIX requires be ignored.
    Duplicate {
        /// The number the session expected.
        expected: u64,
        /// The number the message carried.
        received: u64,
    },
    /// Below the expectation without `PossDupFlag` (43) = Y: the streams have
    /// diverged, and the session ends with a Logout.
    TooLow {
        /// The number the session expected.
        expected: u64,
        /// The number the message carried.
        received: u64,
    },
    /// Above the expectation: the numbers from `expected` are missing and are
    /// requested with a `ResendRequest` (2). The message is not consumed.
    Gap {
        /// The number the session expected: the start of the gap.
        expected: u64,
        /// The number the message carried.
        received: u64,
    },
}

/// Classifies inbound `MsgSeqNum` (34) `seq` against `sequences`.
///
/// `poss_dup` reports whether the message carries `PossDupFlag` (43) = Y. It
/// is called only for a number below the expectation, so a driver that reads
/// the flag by scanning the message pays for the scan only then.
#[must_use]
pub fn classify_inbound(
    sequences: &SequenceManager,
    seq: u64,
    poss_dup: impl FnOnce() -> bool,
) -> InboundSequence {
    match sequences.validate_incoming(seq) {
        SequenceResult::Ok => InboundSequence::InSequence,
        SequenceResult::TooLow { expected, received } => {
            if poss_dup() {
                InboundSequence::Duplicate { expected, received }
            } else {
                InboundSequence::TooLow { expected, received }
            }
        }
        SequenceResult::Gap { expected, received } => InboundSequence::Gap { expected, received },
    }
}

/// Whether a duplicate `SequenceReset` (4) GapFill below the expectation must
/// be followed by a re-request of the numbers it spans.
///
/// The fill itself is ignored, as FIX requires of a possible duplicate below
/// the expectation. A `NewSeqNo` (36) past `expected` says the counterparty
/// sent numbers this session still lacks, so they are requested from
/// `expected`: at most once per expected number (`last_rerequested`), and
/// only while the session may still ask (`may_request`: it is Active and has
/// not sent its own Logout). Returns the `NewSeqNo` the re-request covers.
#[must_use]
pub fn spanned_rerequest(
    expected: u64,
    new_seq_no: Option<u64>,
    may_request: bool,
    last_rerequested: Option<u64>,
) -> Option<u64> {
    new_seq_no
        .filter(|new_seq| *new_seq > expected)
        .filter(|_| may_request && last_rerequested != Some(expected))
}

/// The top of the range a [`spanned_rerequest`] covers: `new_seq - 1`, never
/// below `expected`.
#[must_use]
pub fn spanned_high_water(expected: u64, new_seq: u64) -> u64 {
    new_seq.checked_sub(1).unwrap_or(expected).max(expected)
}

/// Recovery bookkeeping for one outstanding `ResendRequest` (2).
///
/// A resend that is never satisfied must not keep the session open forever:
/// gapped frames refresh the heartbeat clock, so the heartbeat timeout never
/// fires while the inbound expectation sits pinned. This tracks the gap so a
/// driver can retry the request and, once the attempts are spent, log the
/// session out ([`decide_stall`]). The request is open-ended, so the gap is
/// closed only once the expectation passes [`ResendState::high_water`].
///
/// Every method that starts or restarts the stall clock takes `now` from the
/// driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResendState {
    expected: u64,
    high_water: u64,
    requested_at: Instant,
    attempts: u32,
    limit: u32,
    timeout: Duration,
    charge_on_write: bool,
}

impl ResendState {
    /// Opens recovery for a gap at `expected`, with `high_water` the highest
    /// number outstanding, counting the request sent at `now` as the first
    /// attempt. The attempt ceiling is [`SessionConfig::resend_attempt_limit`]
    /// and the stall timeout [`SessionConfig::resend_timeout`].
    #[must_use]
    pub const fn first(
        expected: u64,
        high_water: u64,
        config: &SessionConfig,
        now: Instant,
    ) -> Self {
        Self {
            expected,
            high_water,
            requested_at: now,
            attempts: 1,
            limit: config.resend_attempt_limit(),
            timeout: config.resend_timeout,
            charge_on_write: false,
        }
    }

    /// Opens recovery for a gap with **no** `ResendRequest` charged
    /// (attempts 0): one a `NextExpectedMsgSeqNum` (789) already asked the
    /// counterparty to fill, or one whose request waits behind a resend of
    /// ours. A stall still gets one real request, which a limit of one
    /// allows.
    #[must_use]
    pub const fn implied(
        expected: u64,
        high_water: u64,
        config: &SessionConfig,
        now: Instant,
    ) -> Self {
        let mut state = Self::first(expected, high_water, config, now);
        state.attempts = 0;
        state
    }

    /// The next number the recovery waits to receive: the gap start.
    #[must_use]
    pub const fn expected(&self) -> u64 {
        self.expected
    }

    /// The highest number seen while the gap has been open. The expectation
    /// must pass it for the gap to close.
    #[must_use]
    pub const fn high_water(&self) -> u64 {
        self.high_water
    }

    /// How many requests have been charged to this gap, counting the first.
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }

    /// The attempt ceiling.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// When the stall clock last started.
    #[must_use]
    pub const fn requested_at(&self) -> Instant {
        self.requested_at
    }

    /// Whether a request held behind a resend of ours costs an attempt when
    /// it is written (issue #128).
    #[must_use]
    pub const fn charge_on_write(&self) -> bool {
        self.charge_on_write
    }

    /// Whether the gap has made no progress for its timeout by `now`. A
    /// `now` earlier than the clock start counts as no time elapsed.
    #[must_use]
    pub fn is_stalled(&self, now: Instant) -> bool {
        let waited = now
            .checked_duration_since(self.requested_at)
            .unwrap_or(Duration::ZERO);
        waited >= self.timeout
    }

    /// Whether another request may still be charged to this gap.
    #[must_use]
    pub const fn can_retry(&self) -> bool {
        self.attempts < self.limit
    }

    /// Raises the water mark to `high_water` if that is higher; the range is
    /// never narrowed.
    pub const fn raise_high_water(&mut self, high_water: u64) {
        if high_water > self.high_water {
            self.high_water = high_water;
        }
    }

    /// Marks the request held behind a resend of ours as charged once it is
    /// written.
    pub const fn charge_held_request(&mut self) {
        self.charge_on_write = true;
    }

    /// Takes the charge a held request owes, leaving none behind.
    pub const fn take_charge(&mut self) -> bool {
        std::mem::replace(&mut self.charge_on_write, false)
    }

    /// Restarts the stall clock at `now`, for a request not charged against
    /// the budget.
    pub const fn restart_clock(&mut self, now: Instant) {
        self.requested_at = now;
    }

    /// Re-arms the gap from `expected` at `now` for an uncharged request: the
    /// gap start moves, the water mark only rises, the attempts are kept.
    pub const fn rearm_uncharged(&mut self, expected: u64, high_water: u64, now: Instant) {
        self.expected = expected;
        self.raise_high_water(high_water);
        self.restart_clock(now);
    }

    /// Records another charged request for this gap, sent at `now`.
    pub fn record_retry(&mut self, now: Instant) {
        self.requested_at = now;
        // Any charged request settles what a held one owed: a later held
        // request in this gap is charged only if armed again (issue #128).
        self.charge_on_write = false;
        // `attempts` never passes `limit` (a u32) by more than the one
        // request `can_retry` allowed, so this cannot overflow; if it ever
        // did, the count stays at its ceiling, which already refuses a retry.
        match self.attempts.checked_add(1) {
            Some(attempts) => self.attempts = attempts,
            None => debug_assert!(false, "ResendRequest attempt count overflowed u32"),
        }
    }

    /// Records in-order progress at `now`: the gap start is now `expected`,
    /// the stall clock restarts and the budget resets, since a peer feeding
    /// the gap is responsive. An implied gap stays implied, so a stall after
    /// partial progress still gets its one real request.
    pub fn record_progress(&mut self, expected: u64, now: Instant) {
        self.expected = expected;
        self.requested_at = now;
        self.attempts = self.attempts.min(1);
    }
}

/// The water mark a request for a gap reaching `high_water` carries, given
/// the recovery already armed: the higher of the two, so a later, lower frame
/// never narrows the range.
#[must_use]
pub fn merged_high_water(current: Option<&ResendState>, high_water: u64) -> u64 {
    current.map_or(high_water, |state| state.high_water.max(high_water))
}

/// Whether a gap needs a new `ResendRequest` (2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GapRequest {
    /// A request from this gap start is already outstanding: nothing is sent.
    AlreadyRequested,
    /// Send an open-ended `ResendRequest` (2) from the gap start.
    Request,
}

/// Decides whether a gap at `expected` reaching `high_water` needs a new
/// `ResendRequest` (2), raising the water mark of the recovery already armed.
///
/// A frame that reaches beyond an open gap only raises its water mark; it
/// does not emit a second, overlapping request.
#[must_use]
pub const fn decide_gap_request(
    current: Option<&mut ResendState>,
    expected: u64,
    high_water: u64,
) -> GapRequest {
    match current {
        Some(state) => {
            state.raise_high_water(high_water);
            if state.expected == expected {
                GapRequest::AlreadyRequested
            } else {
                GapRequest::Request
            }
        }
        None => GapRequest::Request,
    }
}

/// What in-order progress did to the recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecoveryProgress {
    /// No recovery was armed.
    NoRecovery,
    /// The expectation passed the water mark: the gap is closed and the
    /// recovery cleared.
    Closed,
    /// The gap start advanced; the gap is still open.
    Advanced,
}

/// Reconciles `recovery` with the expectation having advanced in order to
/// `next_target` at `now`.
///
/// Recovery clears only once the expectation has passed the whole
/// outstanding range; until then its gap start advances and its stall clock
/// and budget reset ([`ResendState::record_progress`]).
pub fn note_inbound_progress(
    recovery: &mut Option<ResendState>,
    next_target: u64,
    now: Instant,
) -> RecoveryProgress {
    let Some(state) = recovery.as_mut() else {
        return RecoveryProgress::NoRecovery;
    };
    if next_target > state.high_water {
        *recovery = None;
        RecoveryProgress::Closed
    } else {
        state.record_progress(next_target, now);
        RecoveryProgress::Advanced
    }
}

/// What the stall check tells the driver to do about an outstanding gap.
///
/// Deliberately not `#[non_exhaustive]`, like [`LivenessAction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StallAction {
    /// No gap has stalled, or its request is not yet written whole.
    Wait,
    /// Retry the `ResendRequest` (2) from `expected`; once it goes out the
    /// driver calls [`ResendState::record_retry`].
    Retry {
        /// The gap start to request from.
        expected: u64,
    },
    /// The attempts are spent: the session logs out.
    Abandon {
        /// The gap start that never filled.
        expected: u64,
        /// The requests charged to the gap.
        attempts: u32,
    },
}

/// Decides whether an outstanding gap has stalled at `now`.
///
/// A request still waiting to be written (`request_unwritten`) has not
/// reached the counterparty: its clock starts once it is written whole, so
/// it does not stall meanwhile.
#[must_use]
pub fn decide_stall(
    recovery: Option<&ResendState>,
    now: Instant,
    request_unwritten: bool,
) -> StallAction {
    match recovery {
        Some(state) if !request_unwritten && state.is_stalled(now) => {
            if state.can_retry() {
                StallAction::Retry {
                    expected: state.expected,
                }
            } else {
                StallAction::Abandon {
                    expected: state.expected,
                    attempts: state.attempts,
                }
            }
        }
        Some(_) | None => StallAction::Wait,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heartbeat::HeartbeatManager;

    const INTERVAL: Duration = Duration::from_secs(30);

    fn probe(test_request_unwritten: bool, output_waiting: bool) -> LivenessGate {
        LivenessGate::Probe {
            test_request_unwritten,
            output_waiting,
        }
    }

    /// A manager whose last send and receive were both at `t0`.
    fn manager(t0: Instant) -> HeartbeatManager {
        HeartbeatManager::new(INTERVAL, t0)
    }

    /// A manager with a TestRequest sent at `t0 + INTERVAL + grace` after
    /// inbound silence, so its reply deadline runs from there.
    fn probing(t0: Instant) -> (HeartbeatManager, Instant) {
        let mut hb = manager(t0);
        let sent = t0 + INTERVAL + hb.test_request_grace();
        hb.on_test_request_sent("TR1".to_owned(), sent);
        (hb, sent)
    }

    #[test]
    fn test_nothing_is_due_right_after_traffic() {
        let t0 = Instant::now();
        let hb = manager(t0);
        assert_eq!(
            decide_liveness(&hb, t0, probe(false, false)),
            LivenessAction::Idle
        );
    }

    #[test]
    fn test_heartbeat_is_due_after_an_idle_interval() {
        let t0 = Instant::now();
        let mut hb = manager(t0);
        // Inbound kept arriving, so only the send side is idle.
        hb.on_message_received(false, None, t0 + INTERVAL);
        assert_eq!(
            decide_liveness(&hb, t0 + INTERVAL, probe(false, false)),
            LivenessAction::SendHeartbeat
        );
    }

    #[test]
    fn test_heartbeat_waits_while_output_is_waiting() {
        let t0 = Instant::now();
        let mut hb = manager(t0);
        hb.on_message_received(false, None, t0 + INTERVAL);
        assert_eq!(
            decide_liveness(&hb, t0 + INTERVAL, probe(false, true)),
            LivenessAction::Idle
        );
    }

    #[test]
    fn test_test_request_is_due_after_inbound_silence_and_grace() {
        let t0 = Instant::now();
        let hb = manager(t0);
        let at = t0 + INTERVAL + hb.test_request_grace();
        assert_eq!(
            decide_liveness(&hb, at, probe(false, false)),
            LivenessAction::SendTestRequest
        );
        // Before the grace has run, the silence alone only makes a
        // Heartbeat due (nothing was sent either).
        assert_eq!(
            decide_liveness(&hb, t0 + INTERVAL, probe(false, false)),
            LivenessAction::SendHeartbeat
        );
    }

    #[test]
    fn test_unwritten_test_request_falls_back_to_the_heartbeat_check() {
        let t0 = Instant::now();
        let hb = manager(t0);
        let at = t0 + INTERVAL + hb.test_request_grace();
        assert_eq!(
            decide_liveness(&hb, at, probe(true, false)),
            LivenessAction::SendHeartbeat
        );
        assert_eq!(
            decide_liveness(&hb, at, probe(true, true)),
            LivenessAction::Idle
        );
    }

    #[test]
    fn test_unanswered_test_request_times_out_under_every_gate() {
        let t0 = Instant::now();
        let (hb, sent) = probing(t0);
        let late = sent + INTERVAL;
        assert!(hb.is_timed_out(late));
        for gate in [
            LivenessGate::DeadlinesOnly,
            probe(false, false),
            probe(true, true),
        ] {
            assert_eq!(
                decide_liveness(&hb, late, gate),
                LivenessAction::CloseHeartbeatTimeout
            );
        }
    }

    #[test]
    fn test_answered_test_request_does_not_time_out() {
        let t0 = Instant::now();
        let (mut hb, sent) = probing(t0);
        hb.on_message_received(true, Some("TR1"), sent + Duration::from_secs(1));
        assert_ne!(
            decide_liveness(&hb, sent + INTERVAL, LivenessGate::DeadlinesOnly),
            LivenessAction::CloseHeartbeatTimeout
        );
    }

    #[test]
    fn test_deadlines_only_never_probes() {
        let t0 = Instant::now();
        let hb = manager(t0);
        let at = t0 + INTERVAL + hb.test_request_grace();
        assert_eq!(
            decide_liveness(&hb, at, LivenessGate::DeadlinesOnly),
            LivenessAction::Idle
        );
    }

    #[test]
    fn test_zero_interval_never_acts() {
        let t0 = Instant::now();
        let hb = HeartbeatManager::new(Duration::ZERO, t0);
        let later = t0 + Duration::from_secs(3600);
        assert_eq!(
            decide_liveness(&hb, later, probe(false, false)),
            LivenessAction::Idle
        );
    }

    #[test]
    fn test_logout_timeout_runs_from_sent_at() {
        let t0 = Instant::now();
        let timeout = Duration::from_secs(10);
        let session = Session::new("S")
            .connect()
            .send_logon(t0)
            .on_logon_ack()
            .initiate_logout(t0);
        assert!(!logout_timed_out(
            &session,
            t0 + Duration::from_secs(9),
            timeout
        ));
        assert!(logout_timed_out(&session, t0 + timeout, timeout));
        assert!(logout_timed_out(
            &session,
            t0 + Duration::from_secs(11),
            timeout
        ));
    }

    #[test]
    fn test_logout_timeout_treats_an_earlier_now_as_no_time_elapsed() {
        let t0 = Instant::now();
        let sent = t0 + Duration::from_secs(5);
        let session = Session::new("S")
            .connect()
            .send_logon(t0)
            .on_logon_ack()
            .initiate_logout(sent);
        assert!(!logout_timed_out(&session, t0, Duration::from_secs(1)));
        assert!(logout_timed_out(&session, t0, Duration::ZERO));
    }

    #[test]
    fn test_test_request_reply_echoes_a_non_empty_id() {
        assert_eq!(test_request_reply_id(Some("ABC")), Some("ABC"));
        assert_eq!(test_request_reply_id(Some("")), None);
        assert_eq!(test_request_reply_id(None), None);
    }

    // Stage 2: sequence validation and gap recovery.

    const RESEND_TIMEOUT: Duration = Duration::from_secs(10);

    fn config(limit: u32) -> SessionConfig {
        let (Ok(sender), Ok(target)) = (
            ironfix_core::types::CompId::new("CLIENT"),
            ironfix_core::types::CompId::new("VENUE"),
        ) else {
            unreachable!("CLIENT and VENUE are valid CompIDs")
        };
        let mut config =
            SessionConfig::new(sender, target, "FIX.4.4").with_max_resend_requests(limit);
        config.resend_timeout = RESEND_TIMEOUT;
        config
    }

    fn sequences_expecting(next: u64) -> SequenceManager {
        let sequences = SequenceManager::new();
        sequences.set_target_seq(next);
        sequences
    }

    /// The reactor's classification before stage 2, kept as the oracle.
    fn old_classify(sequences: &SequenceManager, seq: u64, poss_dup: bool) -> InboundSequence {
        match sequences.validate_incoming(seq) {
            SequenceResult::Ok => InboundSequence::InSequence,
            SequenceResult::TooLow { expected, received } if poss_dup => {
                InboundSequence::Duplicate { expected, received }
            }
            SequenceResult::TooLow { expected, received } => {
                InboundSequence::TooLow { expected, received }
            }
            SequenceResult::Gap { expected, received } => {
                InboundSequence::Gap { expected, received }
            }
        }
    }

    #[test]
    fn test_classify_matches_the_old_logic() {
        let sequences = sequences_expecting(5);
        for seq in 1..=9 {
            for poss_dup in [false, true] {
                assert_eq!(
                    classify_inbound(&sequences, seq, || poss_dup),
                    old_classify(&sequences, seq, poss_dup),
                    "seq {seq} poss_dup {poss_dup}"
                );
            }
        }
    }

    #[test]
    fn test_classify_reads_poss_dup_only_below_the_expectation() {
        let sequences = sequences_expecting(5);
        let mut asked = 0_u32;
        let mut flag = || {
            asked += 1;
            true
        };
        assert_eq!(
            classify_inbound(&sequences, 5, &mut flag),
            InboundSequence::InSequence
        );
        assert_eq!(
            classify_inbound(&sequences, 7, &mut flag),
            InboundSequence::Gap {
                expected: 5,
                received: 7
            }
        );
        assert_eq!(asked, 0);
        assert_eq!(
            classify_inbound(&sequences, 3, || true),
            InboundSequence::Duplicate {
                expected: 5,
                received: 3
            }
        );
        assert_eq!(
            classify_inbound(&sequences, 3, || false),
            InboundSequence::TooLow {
                expected: 5,
                received: 3
            }
        );
    }

    #[test]
    fn test_spanned_rerequest_only_past_the_expectation_once() {
        assert_eq!(spanned_rerequest(5, Some(8), true, None), Some(8));
        assert_eq!(spanned_rerequest(5, Some(5), true, None), None);
        assert_eq!(spanned_rerequest(5, None, true, None), None);
        assert_eq!(spanned_rerequest(5, Some(8), false, None), None);
        assert_eq!(spanned_rerequest(5, Some(8), true, Some(5)), None);
        assert_eq!(spanned_rerequest(5, Some(8), true, Some(4)), Some(8));
        assert_eq!(spanned_high_water(5, 8), 7);
        assert_eq!(spanned_high_water(5, 6), 5);
        assert_eq!(spanned_high_water(3, 0), 3);
    }

    #[test]
    fn test_resend_state_first_and_implied() {
        let t0 = Instant::now();
        let config = config(1);
        let first = ResendState::first(3, 6, &config, t0);
        assert_eq!(
            (first.expected(), first.high_water(), first.attempts()),
            (3, 6, 1)
        );
        assert_eq!(first.limit(), 1);
        assert_eq!(first.requested_at(), t0);
        assert!(!first.charge_on_write());
        assert!(!first.can_retry());
        let implied = ResendState::implied(3, 6, &config, t0);
        assert_eq!(implied.attempts(), 0);
        assert!(
            implied.can_retry(),
            "a limit of one still allows the real one"
        );
        let zero = ResendState::first(3, 6, &self::config(0), t0);
        assert_eq!(zero.limit(), 1, "a limit of 0 reads as 1");
    }

    #[test]
    fn test_resend_state_stall_clock_uses_the_given_now() {
        let t0 = Instant::now();
        let mut state = ResendState::first(3, 6, &config(3), t0);
        assert!(!state.is_stalled(t0));
        assert!(!state.is_stalled(t0 + RESEND_TIMEOUT - Duration::from_millis(1)));
        assert!(state.is_stalled(t0 + RESEND_TIMEOUT));
        // A `now` before the clock start counts as no time elapsed.
        let later = t0 + Duration::from_secs(5);
        state.restart_clock(later);
        assert!(!state.is_stalled(t0));
        assert!(state.is_stalled(later + RESEND_TIMEOUT));
    }

    #[test]
    fn test_resend_state_record_retry_counts_and_settles_the_charge() {
        let t0 = Instant::now();
        let mut state = ResendState::first(3, 6, &config(3), t0);
        state.charge_held_request();
        let t1 = t0 + Duration::from_secs(1);
        state.record_retry(t1);
        assert!(!state.charge_on_write());
        assert_eq!(state.requested_at(), t1);
        state.record_retry(t1);
        assert_eq!(state.attempts(), 3);
        assert!(!state.can_retry());
    }

    #[test]
    fn test_resend_state_take_charge_takes_it_once() {
        let mut state = ResendState::implied(3, 6, &config(3), Instant::now());
        assert!(!state.take_charge());
        state.charge_held_request();
        assert!(state.take_charge());
        assert!(!state.take_charge());
    }

    #[test]
    fn test_resend_state_progress_keeps_an_implied_gap_implied() {
        let t0 = Instant::now();
        let config = config(1);
        let mut implied = ResendState::implied(3, 6, &config, t0);
        let t1 = t0 + Duration::from_secs(2);
        implied.record_progress(4, t1);
        assert_eq!(implied.expected(), 4);
        assert_eq!(implied.attempts(), 0);
        assert_eq!(implied.requested_at(), t1);

        let mut real = ResendState::first(3, 6, &config, t0);
        real.record_retry(t0);
        real.record_progress(4, t0);
        assert_eq!(
            real.attempts(),
            1,
            "progress resets a real request's budget"
        );
    }

    #[test]
    fn test_rearm_uncharged_keeps_attempts_and_the_higher_mark() {
        let t0 = Instant::now();
        let mut state = ResendState::first(3, 9, &config(3), t0);
        let t1 = t0 + Duration::from_secs(4);
        state.rearm_uncharged(5, 7, t1);
        assert_eq!(
            (state.expected(), state.high_water(), state.attempts()),
            (5, 9, 1)
        );
        assert_eq!(state.requested_at(), t1);
        state.rearm_uncharged(6, 12, t1);
        assert_eq!(state.high_water(), 12);
    }

    #[test]
    fn test_gap_request_suppresses_the_same_gap_start_and_raises_the_mark() {
        let t0 = Instant::now();
        assert_eq!(decide_gap_request(None, 3, 6), GapRequest::Request);
        let mut state = ResendState::first(3, 6, &config(3), t0);
        assert_eq!(
            decide_gap_request(Some(&mut state), 3, 9),
            GapRequest::AlreadyRequested
        );
        assert_eq!(state.high_water(), 9);
        assert_eq!(
            decide_gap_request(Some(&mut state), 3, 4),
            GapRequest::AlreadyRequested
        );
        assert_eq!(state.high_water(), 9, "never narrowed");
        assert_eq!(
            decide_gap_request(Some(&mut state), 4, 5),
            GapRequest::Request
        );
        assert_eq!(merged_high_water(Some(&state), 5), 9);
        assert_eq!(merged_high_water(Some(&state), 11), 11);
        assert_eq!(merged_high_water(None, 5), 5);
    }

    #[test]
    fn test_inbound_progress_clears_only_past_the_mark() {
        let t0 = Instant::now();
        let mut none = None;
        assert_eq!(
            note_inbound_progress(&mut none, 4, t0),
            RecoveryProgress::NoRecovery
        );
        let mut recovery = Some(ResendState::first(3, 6, &config(3), t0));
        let t1 = t0 + Duration::from_secs(3);
        assert_eq!(
            note_inbound_progress(&mut recovery, 6, t1),
            RecoveryProgress::Advanced
        );
        assert_eq!(
            recovery.map(|state| (state.expected(), state.requested_at())),
            Some((6, t1))
        );
        assert_eq!(
            note_inbound_progress(&mut recovery, 7, t1),
            RecoveryProgress::Closed
        );
        assert!(recovery.is_none());
    }

    #[test]
    fn test_stall_waits_retries_then_abandons() {
        let t0 = Instant::now();
        let late = t0 + RESEND_TIMEOUT;
        assert_eq!(decide_stall(None, late, false), StallAction::Wait);
        let mut state = ResendState::first(3, 6, &config(2), t0);
        assert_eq!(decide_stall(Some(&state), t0, false), StallAction::Wait);
        assert_eq!(
            decide_stall(Some(&state), late, true),
            StallAction::Wait,
            "an unwritten request does not stall"
        );
        assert_eq!(
            decide_stall(Some(&state), late, false),
            StallAction::Retry { expected: 3 }
        );
        state.record_retry(late);
        assert_eq!(decide_stall(Some(&state), late, false), StallAction::Wait);
        assert_eq!(
            decide_stall(Some(&state), late + RESEND_TIMEOUT, false),
            StallAction::Abandon {
                expected: 3,
                attempts: 2
            }
        );
    }
}
