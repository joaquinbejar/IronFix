/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! # IronFix Session
//!
//! FIX session layer protocol implementation for the IronFix engine.
//!
//! This crate is **pure protocol logic**: it performs no I/O, encodes no bytes
//! and persists nothing. Its only IronFix dependency is `ironfix-core`.
//!
//! This crate provides:
//! - **State machine**: a sealed typestate session FSM
//!   (`Disconnected` → `Connecting` → `LogonSent`/`LogonReceived` → `Active` →
//!   `Resending`/`LogoutPending`), so illegal transitions do not compile
//! - **Sequence management**: [`SequenceManager`] with checked arithmetic —
//!   exhaustion is a typed error, never a silent wrap. Gap *detection*
//!   ([`SequenceResult::Gap`]) lives here; the recovery that follows
//!   (ResendRequest, SequenceReset, gap fill) is orchestrated by
//!   `ironfix-engine`, which owns the socket
//! - **Heartbeat handling**: [`HeartbeatManager`], `Instant`-based timing for
//!   heartbeat and TestRequest deadlines and `HeartBtInt` negotiation
//! - **No clock reads**: nothing in this crate reads a clock (ADR-0002,
//!   "Time source contract"). Every time-dependent method and every
//!   timestamping transition takes `now` from the caller, and
//!   [`generate_test_req_id`] takes the wall-clock time it encodes, so the
//!   same logic runs under any driver and is deterministic in tests. A guard
//!   test (`tests/no_clock_reads.rs`) fails the build if a clock read creeps
//!   back into `src/`
//! - **Configuration**: [`SessionConfig`] and its validating
//!   [`config::SessionConfigBuilder`], including the opt-in
//!   [`GarbledFrameLimit`] on garbled inbound frames and, on a FIX 5.0
//!   session, the application versions accepted from the counterparty
//!   ([`SessionConfig::accepts_appl_version`]), and the opt-in use of
//!   `NextExpectedMsgSeqNum` (789) on the Logon exchange
//!   ([`SessionConfig::send_next_expected_msg_seq_num`], FIX.4.4 and
//!   FIXT.1.1 only); all enforced by `ironfix-engine`
//! - **Sans-IO core** ([`sans_io`]): the protocol decisions a driver acts on,
//!   with no I/O, no clock read and no `.await` (ADR-0002, issue #91). Stage 1
//!   holds the liveness family ([`decide_liveness`], [`logout_timed_out`],
//!   [`test_request_reply_id`]); stage 2 the sequence classification and gap
//!   recovery decisions ([`classify_inbound`], [`ResendState`],
//!   [`decide_gap_request`], [`decide_stall`]); stage 3 the resend replay
//!   ([`decide_resend_request`], [`ResendReplay`], [`EndSeqNoInfinity`]);
//!   stage 4 the Logout handshake ([`decide_local_logout`],
//!   [`decide_peer_logout`], [`OwedLogout`], [`LogoutClose`],
//!   [`close_resets`]); stage 5 the two Logon handshakes
//!   ([`decide_logon_refusal`], [`classify_logon_seq`],
//!   [`plan_next_expected`], [`decide_seed_source`],
//!   [`compare_logon_sequences`], [`logon_deadline`]); stage 6a the
//!   session state object the core owns ([`SessionCore`],
//!   [`HeldLogonRelease`]); stage 6b the session phase and the payload
//!   queues ([`SessionPhase`], [`SessionPayloads`], [`HeldEntry`],
//!   [`ReplayJob`], [`GapEntry`]); stage 6c the outbound throttle's token
//!   buckets and the messages they hold, owned by the session core
//!   ([`Throttle`], [`TokenBucketSpec`]); the Tokio reactor in
//!   `ironfix-engine` is its first driver
//!
//! Note that the `Resending` state is only the FSM marker for "a resend is in
//! progress". The decisions of answering a `ResendRequest` (which range, what
//! is replayed and what is gap-filled) live in [`sans_io`]; reading the store,
//! rebuilding and encoding the frames and running the replay gate live in
//! `ironfix-engine`, because they need the wire layer, the store and the
//! application.

pub mod config;
mod gap_queue;
pub mod heartbeat;
mod logon;
mod logout;
mod phase;
mod replay;
pub mod sans_io;
pub mod sequence;
mod session_core;
pub mod state;
mod throttle;

pub use config::{
    GapPolicy, GarbledFrameLimit, SessionConfig, SessionConfigBuilder, SessionConfigError,
};
pub use heartbeat::{
    HeartbeatIntervalError, HeartbeatManager, MAX_HEARTBEAT_INTERVAL_SECS, TestRequestOutcome,
    generate_test_req_id, negotiate_interval,
};
pub use sans_io::{
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
pub use sans_io::{
    DEFAULT_BUDGET, Throttle, ThrottleAdmission, ThrottleDrain, ThrottleRelease, TokenBucketSpec,
};
pub use sans_io::{
    EndSeqNoInfinity, EntryScreen, GapFillRange, MAX_HELD_BYTES, MAX_HELD_SENDS,
    MAX_QUEUED_REPLAYS, MAX_READS_PER_REPLAY_STEP, OpeningReplay, PageRead, PageRequest,
    REPLAY_PAGE_LIMIT, REPLAY_STEP_MAX_BYTES, REPLAY_STEP_MAX_FRAMES, ReplayAction, ReplayField,
    ReplayStep, ReplayVerdict, ResendReplay, ResendRequestDecision, decide_opening_replay,
    decide_resend_request, hold_full, orig_sending_time, reads_yield_to_replay, replay_field,
    replay_queue_full, replay_step_continues,
};
pub use sans_io::{
    GapAdmission, GapEntry, GapReady, HeldEntry, HeldLogonRelease, ReplayJob, SessionCore,
    SessionPayloads, SessionPhase, TickDecision, TickInput,
};
pub use sans_io::{
    GapDisposition, GapRequest, InboundRoute, InboundSequence, LivenessAction, LivenessGate,
    RecoveryProgress, ResendState, StallAction, classify_inbound, decide_gap_request,
    decide_liveness, decide_stall, logout_timed_out, merged_high_water, note_inbound_progress,
    route_inbound, spanned_high_water, spanned_rerequest, test_request_reply_id,
};
pub use sans_io::{
    LocalLogoutDecision, LocalLogoutReason, LogoutClose, LogoutPhase, LogoutReplyWrite,
    LogoutTextError, MAX_LOGOUT_TEXT_LEN, OwedLogout, PeerLogoutDecision, check_logout_text,
    close_resets, decide_local_logout, decide_logout_advance, decide_peer_logout, owed_logout_due,
    reply_close, resend_stalled_text, settle_close,
};
pub use sequence::{SequenceCounter, SequenceExhausted, SequenceManager, SequenceResult};
pub use state::{
    Active, Connecting, Disconnected, LogonReceived, LogonSent, LogoutPending, Resending, Session,
    SessionState,
};
