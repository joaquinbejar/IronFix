/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! Sans-IO core, stage 6a: the session state object the core owns.
//!
//! Stages 1 to 5 moved the reactor's protocol *decisions* into free
//! functions; the state those decisions read and update still lived in the
//! Tokio reactor's own fields. [`SessionCore`] takes that state over: the
//! outstanding `ResendRequest` (2) recovery, the Logon held behind a
//! `NextExpectedMsgSeqNum` (789) gap, the `PossDupFlag` (43) spanning
//! re-request mark, the counterparty's owed Logout (5), whether this
//! session's own Logout has been fed, the `TestReqID` (112) of a TestRequest
//! (1) not yet written whole, the read budget between replay steps, and the
//! count of what is held behind a resend.
//!
//! Like the rest of the core it performs no I/O, reads no clock and never
//! awaits: every method that starts or checks a clock takes `now` from the
//! driver. The driver keeps what only it can hold: the typestate session in
//! its phase, the frames themselves (held messages, the gap queue, the replay
//! pages), the store, the socket and the callbacks.

use std::time::{Duration, Instant};

use crate::config::SessionConfig;
use crate::logout::{LogoutPhase, OwedLogout, PeerLogoutDecision, decide_peer_logout};
use crate::replay::{hold_full, reads_yield_to_replay};
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

/// The session state the sans-IO core owns for one live session.
///
/// Stage 6a of issue #91 (ADR-0002). A driver creates one per session
/// once the Logon exchange is done, and routes every read and update of that
/// state through it. Fields are private: each method names the protocol
/// event it records or the decision it answers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionCore {
    resend: Option<ResendState>,
    held_logon: Option<u64>,
    logout_owed: Option<OwedLogout>,
    spanning_rerequested: Option<u64>,
    logout_sent: bool,
    unwritten_test_request: Option<String>,
    reads_since_replay_step: u32,
    held_sends: usize,
    held_bytes: usize,
}

impl SessionCore {
    /// A session with no recovery, no hold, no Logout and no probe.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            resend: None,
            held_logon: None,
            logout_owed: None,
            spanning_rerequested: None,
            logout_sent: false,
            unwritten_test_request: None,
            reads_since_replay_step: 0,
            held_sends: 0,
            held_bytes: 0,
        }
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

    /// This session's own Logout was fed to the output: recovery is over (a
    /// session on its way out processes no replay) and a held Logon is
    /// dropped.
    pub const fn note_local_logout_fed(&mut self) {
        self.resend = None;
        self.held_logon = None;
        self.logout_sent = true;
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

    /// One entry of `bytes` was held behind a resend.
    pub const fn note_held(&mut self, bytes: usize) {
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

    /// One held entry of `bytes` was taken back out.
    ///
    /// # Preconditions
    ///
    /// - The entry was noted earlier with [`Self::note_held`] and has not
    ///   been taken out since (nor dropped by [`Self::clear_held`]).
    /// - `bytes` is exactly the count passed to [`Self::note_held`] for that
    ///   entry.
    ///
    /// A violation is a driver bug. Only an aggregate underflow is detected:
    /// in debug builds it trips a `debug_assert`. Pairing each call with its
    /// entry and passing that entry's exact byte count remain the driver's
    /// responsibility, and a mismatch that does not underflow goes
    /// undetected. In release builds the count that would go below zero
    /// stops at zero instead: an entry taken out with none noted leaves the
    /// entry count at 0, and `bytes` above the noted total leaves the byte
    /// count at 0. The two counts are handled independently. A count that
    /// stops at zero then reads lower than what the driver actually holds,
    /// so [`Self::hold_full`] can report room the hold does not have until
    /// the next [`Self::clear_held`].
    pub const fn note_unheld(&mut self, bytes: usize) {
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

    /// Everything held was dropped.
    pub const fn clear_held(&mut self) {
        self.held_sends = 0;
        self.held_bytes = 0;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::{MAX_HELD_BYTES, MAX_HELD_SENDS, MAX_READS_PER_REPLAY_STEP};

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
        let core = SessionCore::new();
        assert_eq!(core, SessionCore::default());
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
        let mut core = SessionCore::new();
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
        let mut core = SessionCore::new();
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
        let mut core = SessionCore::new();
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
        let mut core = SessionCore::new();
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
        let mut core = SessionCore::new();
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
        let mut core = SessionCore::new();
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
        let mut core = SessionCore::new();
        assert_eq!(core.spanned_rerequest(5, Some(9), true), Some(9));
        core.note_spanned_rerequest(5);
        assert_eq!(core.spanned_rerequest(5, Some(9), true), None);
        assert_eq!(core.spanned_rerequest(6, Some(9), false), None);
    }

    #[test]
    fn test_local_logout_ends_recovery() {
        let now = Instant::now();
        let mut core = SessionCore::new();
        core.hold_logon(4, 8, &config(), now);
        core.note_local_logout_fed();
        assert!(!core.recovering());
        assert_eq!(core.held_logon(), None);
        assert!(core.logout_sent());
    }

    #[test]
    fn test_owed_logout_keeps_first_arrival() {
        let start = Instant::now();
        let timeout = Duration::from_secs(10);
        let mut core = SessionCore::new();
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
        let mut core = SessionCore::new();
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
        let mut core = SessionCore::new();
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
        let mut core = SessionCore::new();
        core.note_held(10);
        core.note_held(20);
        assert_eq!(core.held(), (2, 30));
        core.note_unheld(10);
        assert_eq!(core.held(), (1, 20));
        core.clear_held();
        assert_eq!(core.held(), (0, 0));
        core.note_held(MAX_HELD_BYTES);
        assert!(core.hold_full());
        core.clear_held();
        for _ in 0..MAX_HELD_SENDS {
            core.note_held(0);
        }
        assert!(core.hold_full());
    }
}
