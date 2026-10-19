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
//!   the counterparty over TCP ([`Initiator::establish`] takes a stream the
//!   caller connected instead), runs the Logon handshake, and hands the
//!   stream to a background reactor that owns framing, heartbeats and
//!   TestRequests, CompID validation, sequence-gap detection, `ResendRequest` /
//!   `SequenceReset` / gap fill, `PossDupFlag` and `OrigSendingTime`,
//!   `ResetSeqNumFlag`, resend-from-store replay, and session-level `Reject`.
//! - **[`Acceptor`]**: the server-side engine for one configured session.
//!   [`Acceptor::serve`] runs the acceptor half of the Logon handshake on an
//!   inbound TCP connection ([`Acceptor::serve_stream`] on any accepted
//!   stream) and hands it to the same reactor.
//! - **[`AcceptorRegistry`]**: many acceptor sessions on one listener.
//!   [`AcceptorRegistry::serve`] (or [`AcceptorRegistry::serve_stream`]) reads
//!   the inbound Logon once, routes it by the CompIDs (and configured sub and
//!   location IDs) it claims, read from the standard header and bounded
//!   before anything is looked up, to a registered [`Acceptor`] or one a
//!   [`SessionLookup`] admits, and runs that session's handshake on it. A
//!   Logon that cannot be routed is closed without a reply, touching no store
//!   and running no callback. A session the lookup admits is kept only once a
//!   Logon for it gets past `from_admin`, and
//!   [`AcceptorRegistry::with_max_sessions`] caps how many it holds. Each
//!   session keeps its own sequence numbers, store and heartbeat.
//! - **[`Connection`]**: a cheap-clone handle returned by both engines — send,
//!   logout, await close, read sequence numbers and, on a FIX 5.0 session,
//!   the counterparty's declared default application version.
//!   [`Connection::send_tracked`] waits for one message's fate and reports it
//!   as a [`SendOutcome`] (see [`outcome`]): `Sent` with the `MsgSeqNum`,
//!   the `SendingTime` and whether the store filed it, once the frame is
//!   flushed; `NotSent` with a [`NotSentReason`] when no byte of it reached
//!   the stream and no number was spent; or `Unknown` with the spent number
//!   when the frame was buffered (or being filed) and no completed flush
//!   covered it, an order that may be live and must be reconciled, not
//!   blindly resubmitted. [`Connection::send`] stays fire-and-forget.
//! - **[`OutboundMessage`]**: the body you hand to [`Connection::send`]; the
//!   engine stamps the header, `MsgSeqNum` and trailer.
//! - **[`Application`]**: the QuickFIX-shaped callback trait
//!   (`on_create` / `on_logon` / `on_logout` / `to_admin` / `from_admin` /
//!   `to_app` / `from_app`), plus [`NoOpApplication`].
//!   [`Application::to_app_checked`] is the outbound gate every new
//!   application message passes, whichever `send` it came through: its
//!   default runs `to_app` and sends, and an override can veto the message
//!   (the equivalent of QuickFIX's `DoNotSend`) through the [`SendVerdict`]
//!   it returns, before a `MsgSeqNum` is spent or the store is touched; a
//!   verdict decided at once ([`SendVerdict::ready`]) allocates nothing. A replay of a filed frame (the answer to a
//!   `ResendRequest`, the 789 resend) is resent as filed and is not gated,
//!   unlike QuickFIX. Administrative messages (Logon, Logout, Heartbeat,
//!   TestRequest, ResendRequest, SequenceReset, Reject, XmlMessage) go
//!   through `to_admin` and cannot be vetoed. See
//!   `doc/adr/0023-outbound-veto-and-send-outcomes.md`.
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
//! With [`SessionConfig::send_next_expected_msg_seq_num`] set (FIX.4.4 and
//! FIXT.1.1 sessions only), both roles use `NextExpectedMsgSeqNum` (789) on the
//! Logon exchange: each declares the next `MsgSeqNum` it expects, resends once
//! Active what the counterparty's 789 says it missed (the range below its own
//! Logon, through the same replay a `ResendRequest` gets), and refuses a Logon
//! whose 789 claims messages never sent with
//! [`EngineError::NextExpectedMsgSeqNum`], before `on_logon`. A gapped Logon
//! from a counterparty that declared 789 too is held rather than answered with
//! a `ResendRequest`, which would cross the counterparty's own resend; its
//! number is consumed once that resend fills the gap. 789 is bilateral: both
//! sides must enable it.
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
//! ## Transports
//!
//! A session runs over any byte stream that is
//! `AsyncRead + AsyncWrite + Unpin + Send + 'static`, not only TCP. The TCP
//! entry points ([`Initiator::connect`], [`Acceptor::serve`] and
//! [`Acceptor::accept`], [`AcceptorRegistry::serve`] and
//! [`AcceptorRegistry::accept`]) dial or accept a `TcpStream` and set
//! `TCP_NODELAY` on it. [`Initiator::establish`], [`Acceptor::serve_stream`]
//! and [`AcceptorRegistry::serve_stream`] take a stream the caller has already
//! connected or accepted: a TLS stream built with the TLS stack of the
//! caller's choice, a Unix socket, a proxied connection, or an in-memory
//! [`tokio::io::duplex`] pipe (see the example on [`Initiator::establish`]).
//! Everything else is the same on both paths: the handshake checks and their
//! order, the logon and write timeouts, the store order, and the reactor. Only
//! socket options are not: the engine cannot reach one through an arbitrary
//! stream, so those are the caller's. A TLS handshake the caller runs before
//! handing the stream over is outside the engine's logon timeout.
//!
//! No public type gains a stream type parameter, [`Connection`] included. The
//! TCP path is unaffected by the seam: its socket is held by value, with no
//! allocation and no dynamic call. A caller's stream is boxed once, when the
//! session starts; each outbound frame written in one piece then costs three
//! dynamic calls (`is_write_vectored`, `poll_write_vectored`, `poll_flush`)
//! and each read poll one, the `Pending` poll on every wakeup included.
//! Nothing has measured that cost. The decision is recorded in ADR-0007
//! (`doc/adr/0007-engine-over-any-stream.md`).
//!
//! ## Current limitations
//!
//! - **There is no TLS** in the workspace: no TLS dependency and no TLS
//!   setting. A caller that needs it builds the TLS stream itself, with the
//!   TLS stack and crypto provider of its choice, and hands it to
//!   [`Initiator::establish`] or [`Acceptor::serve_stream`].
//! - **There is no dictionary validation**: `ironfix-dictionary`'s
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
pub mod outcome;
pub mod persistence;
mod reactor;
pub mod registry;
mod stream;
mod wire;

pub use acceptor::Acceptor;
pub use application::{Application, NoOpApplication, RejectReason, SendVerdict, SessionId};
pub use builder::EngineBuilder;
pub use connection::Connection;
pub use error::EngineError;
pub use initiator::Initiator;
pub use outbound::{OutboundField, OutboundMessage};
pub use outcome::{NotSentReason, SendOutcome, UnknownReason};
pub use persistence::StoreFailurePolicy;
pub use registry::{AcceptorRegistry, LogonIdentity, LookupError, SessionLookup};

// Re-exported for convenience: the per-session configuration consumed by
// [`Initiator`].
pub use ironfix_session::SessionConfig;
