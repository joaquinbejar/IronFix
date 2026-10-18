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
//!   `ResetSeqNumFlag`, resend-from-store replay, and session-level `Reject`.
//! - **[`Acceptor`]**: the server-side engine. [`Acceptor::serve`] runs the
//!   acceptor half of the Logon handshake on an inbound connection and hands the
//!   socket to the same reactor.
//! - **[`Connection`]**: a cheap-clone handle returned by both engines — send,
//!   logout, await close, read sequence numbers.
//! - **[`OutboundMessage`]**: the body you hand to [`Connection::send`]; the
//!   engine stamps the header, `MsgSeqNum` and trailer.
//! - **[`Application`]**: the QuickFIX-shaped callback trait
//!   (`on_create` / `on_logon` / `on_logout` / `to_admin` / `from_admin` /
//!   `to_app` / `from_app`), plus [`NoOpApplication`].
//! - **[`EngineBuilder`]**: fluent configuration that terminates in a
//!   ready-to-run [`Initiator`] or [`Acceptor`].
//!
//! Both engines share the same internal session reactor (`reactor`): once
//! a Logon handshake completes, the inbound-frame contract — sequence
//! validation, gap recovery, identity and clock checks, heartbeating, and the
//! Logout handshake — is identical for the two roles.
//!
//! Both also frame their socket with garbled-frame recovery on
//! ([`ironfix_transport::FixCodec::with_garbled_recovery`], anchored on the
//! session's own BeginString). A garbled inbound frame, including one whose
//! header frames but does not decode (`MsgType` not third), is ignored as FIX
//! requires: it consumes no `MsgSeqNum`, does not refresh the heartbeat clock,
//! is logged as a count and never as bytes, and the gap it leaves is recovered
//! by the usual `ResendRequest`. A message whose body does not decode behind a
//! sound header is not garbled: it is dropped with a warning, as before, and
//! not counted. During the Logon handshake both kinds are skipped, so a
//! counterparty that never sends an intact Logon ends in
//! [`EngineError::LogonTimeout`]. The optional
//! [`SessionConfig::garbled_frame_limit`] logs out a session whose link keeps
//! garbling. Only a frame above `max_message_size` (after a Logout saying so)
//! or an I/O error still ends the session at the codec.
//!
//! ## Current limitations
//!
//! - **There is no TLS**, and no dictionary validation: `ironfix-dictionary`'s
//!   `Validator` is never invoked on the session path.
//! - **The store is opt-in and in-memory.** Attaching an
//!   [`ironfix_store::MemoryStore`] with [`Initiator::with_store`] enables
//!   resend-from-store replay, but there is no persistent implementation yet;
//!   the acceptor attaches no store, so its resends are gap-filled.

pub mod acceptor;
pub mod application;
pub mod builder;
pub mod connection;
pub mod error;
mod garbled;
pub mod initiator;
pub mod outbound;
mod reactor;
mod wire;

pub use acceptor::Acceptor;
pub use application::{Application, NoOpApplication, RejectReason, SessionId};
pub use builder::EngineBuilder;
pub use connection::Connection;
pub use error::EngineError;
pub use initiator::Initiator;
pub use outbound::{OutboundField, OutboundMessage};

// Re-exported for convenience: the per-session configuration consumed by
// [`Initiator`].
pub use ironfix_session::SessionConfig;
