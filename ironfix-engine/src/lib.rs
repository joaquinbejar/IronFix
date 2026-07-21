/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! # IronFix Engine
//!
//! High-level FIX engine facade for the IronFix protocol implementation.
//!
//! This is the composition root: the only crate permitted to combine the
//! session layer, the store, the transport codec and the tag=value codec.
//!
//! This crate provides:
//! - **[`Initiator`]**: the client-side engine. [`Initiator::connect`] dials
//!   the counterparty over TCP, runs the Logon handshake, and hands the socket
//!   to a background reactor that owns framing, heartbeats and TestRequests,
//!   CompID validation, sequence-gap detection, `ResendRequest` /
//!   `SequenceReset` / gap fill, `PossDupFlag` and `OrigSendingTime`,
//!   `ResetSeqNumFlag`, and session-level `Reject`.
//! - **[`Connection`]**: a cheap-clone handle returned by
//!   [`Initiator::connect`] — send, logout, await close, read sequence numbers.
//! - **[`OutboundMessage`]**: the body you hand to [`Connection::send`]; the
//!   engine stamps the header, `MsgSeqNum` and trailer.
//! - **[`Application`]**: the QuickFIX-shaped callback trait
//!   (`on_create` / `on_logon` / `on_logout` / `to_admin` / `from_admin` /
//!   `to_app` / `from_app`), plus [`NoOpApplication`].
//!
//! ## Current limitations
//!
//! - **There is no acceptor.** This crate is client-side only; nothing here
//!   listens for inbound connections. The server-side examples under
//!   `ironfix-example/examples/` hand-roll their own accept loop using
//!   `Decoder` and `Encoder` directly.
//! - **[`EngineBuilder`] has no terminal method.** It accumulates sessions,
//!   timeouts and reconnect settings, but there is no `build()` and it does not
//!   produce a running engine. Use [`Initiator::new`] followed by
//!   [`Initiator::connect`].
//! - **The engine does not use `ironfix-store`.** Outbound messages are not
//!   persisted and sequence numbers are not durable, so an inbound
//!   `ResendRequest` is answered with a gap fill rather than with the original
//!   messages.
//! - **There is no TLS**, and no dictionary validation: `ironfix-dictionary`'s
//!   `Validator` is never invoked on the session path.

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
