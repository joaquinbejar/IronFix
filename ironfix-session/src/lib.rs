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
//!   [`decide_gap_request`], [`decide_stall`]); the Tokio reactor in
//!   `ironfix-engine` is its first driver
//!
//! Note that the `Resending` state is only the FSM marker for "a resend is in
//! progress". The actual `ResendRequest` / `SequenceReset` / gap-fill message
//! handling lives in `ironfix-engine`, because it requires the wire layer.

pub mod config;
pub mod heartbeat;
pub mod sans_io;
pub mod sequence;
pub mod state;

pub use config::{
    GapPolicy, GarbledFrameLimit, SessionConfig, SessionConfigBuilder, SessionConfigError,
};
pub use heartbeat::{
    HeartbeatIntervalError, HeartbeatManager, MAX_HEARTBEAT_INTERVAL_SECS, TestRequestOutcome,
    generate_test_req_id, negotiate_interval,
};
pub use sans_io::{
    GapRequest, InboundSequence, LivenessAction, LivenessGate, RecoveryProgress, ResendState,
    StallAction, classify_inbound, decide_gap_request, decide_liveness, decide_stall,
    logout_timed_out, merged_high_water, note_inbound_progress, spanned_high_water,
    spanned_rerequest, test_request_reply_id,
};
pub use sequence::{SequenceCounter, SequenceExhausted, SequenceManager, SequenceResult};
pub use state::{
    Active, Connecting, Disconnected, LogonReceived, LogonSent, LogoutPending, Resending, Session,
    SessionState,
};
