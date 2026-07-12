/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! # IronFix Session
//!
//! FIX session layer protocol implementation for the IronFix engine.
//!
//! This crate provides:
//! - **State machine**: Typestate-based session FSM with compile-time state checks
//! - **Sequence management**: Atomic sequence number handling
//! - **Heartbeat handling**: Heartbeat/TestRequest logic
//! - **Recovery**: Gap fill and ResendRequest processing
//! - **Configuration**: Session configuration options

pub mod config;
pub mod heartbeat;
pub mod sequence;
pub mod state;

pub use config::SessionConfig;
pub use heartbeat::HeartbeatManager;
pub use sequence::{SequenceCounter, SequenceExhausted, SequenceManager};
pub use state::{
    Active, Connecting, Disconnected, LogonReceived, LogonSent, LogoutPending, Resending, Session,
    SessionState,
};
