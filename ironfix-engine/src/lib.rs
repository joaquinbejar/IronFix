/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! # IronFix Engine
//!
//! High-level FIX engine facade for the IronFix protocol implementation.
//!
//! This crate provides:
//! - **Initiator**: Client-side FIX engine for connecting to counterparties
//! - **Acceptor**: Server-side FIX engine for accepting connections
//! - **Application trait**: Callback interface for handling FIX messages
//! - **Builder API**: Fluent configuration for engine setup

pub mod application;
pub mod builder;
pub mod connection;
pub mod error;
pub mod initiator;
pub mod outbound;
mod wire;

pub use application::{Application, NoOpApplication, RejectReason, SessionId};
pub use builder::EngineBuilder;
pub use connection::Connection;
pub use error::EngineError;
pub use initiator::Initiator;
pub use outbound::OutboundMessage;

// Re-exported for convenience: the per-session configuration consumed by
// [`Initiator`].
pub use ironfix_session::SessionConfig;
