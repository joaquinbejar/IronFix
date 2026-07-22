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
//! - **Configuration**: [`SessionConfig`] and its validating
//!   [`config::SessionConfigBuilder`]
//!
//! Note that the `Resending` state is only the FSM marker for "a resend is in
//! progress". The actual `ResendRequest` / `SequenceReset` / gap-fill message
//! handling lives in `ironfix-engine`, because it requires the wire layer.

pub mod config;
pub mod heartbeat;
pub mod sequence;
pub mod state;

pub use config::{SessionConfig, SessionConfigBuilder, SessionConfigError};
pub use heartbeat::{
    HeartbeatIntervalError, HeartbeatManager, MAX_HEARTBEAT_INTERVAL_SECS, TestRequestOutcome,
    generate_test_req_id, negotiate_interval,
};
pub use sequence::{SequenceCounter, SequenceExhausted, SequenceManager, SequenceResult};
pub use state::{
    Active, Connecting, Disconnected, LogonReceived, LogonSent, LogoutPending, Resending, Session,
    SessionState,
};
