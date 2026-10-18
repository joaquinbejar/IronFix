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
//! - **[`Acceptor`]**: the server-side engine for one configured session.
//!   [`Acceptor::serve`] runs the acceptor half of the Logon handshake on an
//!   inbound connection and hands the socket to the same reactor.
//! - **[`AcceptorRegistry`]**: many acceptor sessions on one listener.
//!   [`AcceptorRegistry::serve`] reads the inbound Logon once, routes it by
//!   the CompIDs (and configured sub and location IDs) it claims, read from
//!   the standard header and bounded before anything is looked up, to a
//!   registered [`Acceptor`] or one a [`SessionLookup`] admits, and runs that
//!   session's handshake on it. A Logon that cannot be routed is closed
//!   without a reply, touching no store and running no callback. A session
//!   the lookup admits is kept only once a Logon for it gets past
//!   `from_admin`, and [`AcceptorRegistry::with_max_sessions`] caps how many
//!   it holds. Each session keeps its own sequence numbers, store and
//!   heartbeat.
//! - **[`Connection`]**: a cheap-clone handle returned by both engines — send,
//!   logout, await close, read sequence numbers and, on a FIX 5.0 session,
//!   the counterparty's declared default application version.
//! - **[`OutboundMessage`]**: the body you hand to [`Connection::send`]; the
//!   engine stamps the header, `MsgSeqNum` and trailer.
//! - **[`Application`]**: the QuickFIX-shaped callback trait
//!   (`on_create` / `on_logon` / `on_logout` / `to_admin` / `from_admin` /
//!   `to_app` / `from_app`), plus [`NoOpApplication`].
//! - **[`EngineBuilder`]**: fluent configuration that terminates in a
//!   ready-to-run [`Initiator`], [`Acceptor`] or [`AcceptorRegistry`].
//!
//! Both engines share the same internal session reactor (`reactor`): once
//! a Logon handshake completes, the inbound-frame contract — sequence
//! validation, gap recovery, identity and clock checks, heartbeating, and the
//! Logout handshake — is identical for the two roles.
//!
//! On a FIX 5.0 session (framed as FIXT.1.1) both roles also check the
//! application version: the acceptor requires the Logon's `DefaultApplVerID`
//! (1137) to name a version the session accepts
//! ([`SessionConfig::accepts_appl_version`]), the initiator holds an
//! acknowledgement's 1137 to the same rule when present, and an inbound
//! application message whose `ApplVerID` (1128) names any other version is
//! rejected (`SessionRejectReason` 18) without reaching `from_app`.
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
//! - **The store is opt-in.** Attaching one with [`Initiator::with_store`],
//!   [`Acceptor::with_store`] or [`EngineBuilder::with_store`] enables
//!   resend-from-store replay and seeds each session's counters in both roles.
//!   [`ironfix_store::MemoryStore`] keeps them in memory only;
//!   [`ironfix_store::FileStore`] keeps them in a journal file, so they
//!   survive a restart as durably as its sync policy promises (only
//!   `SyncPolicy::EveryWrite` covers an OS crash or power loss for every
//!   write, and only under [`StoreFailurePolicy::CloseSession`] does a failed
//!   write keep its frame off the wire). A store belongs to exactly one
//!   engine. The acceptor touches its store only once the peer is
//!   authenticated (`from_admin` accepted it), and resets it only for a Logon
//!   that passes every check. Store writes are ordered and fallible, and
//!   [`StoreFailurePolicy`] decides whether a failed one is tolerated or
//!   closes the session (see [`persistence`]); either way a failed write owes
//!   the next session a sequence reset. A store that reports itself corrupted
//!   while a resend is read closes the session instead of gap-filling the
//!   request. Inbound application messages are delivered at most once: a
//!   crash, or a close whose application queue does not drain in time, loses
//!   the messages still queued.

pub mod acceptor;
pub mod application;
pub mod builder;
pub mod connection;
pub mod error;
mod garbled;
pub mod initiator;
mod next_expected;
pub mod outbound;
pub mod persistence;
mod reactor;
pub mod registry;
mod wire;

pub use acceptor::Acceptor;
pub use application::{Application, NoOpApplication, RejectReason, SessionId};
pub use builder::EngineBuilder;
pub use connection::Connection;
pub use error::EngineError;
pub use initiator::Initiator;
pub use outbound::{OutboundField, OutboundMessage};
pub use persistence::StoreFailurePolicy;
pub use registry::{AcceptorRegistry, LogonIdentity, LookupError, SessionLookup};

// Re-exported for convenience: the per-session configuration consumed by
// [`Initiator`].
pub use ironfix_session::SessionConfig;
