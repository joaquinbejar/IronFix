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
//! - **[`close`]**: why a session ended. Every close path reports a typed
//!   [`CloseReason`] (a Logout of ours or the counterparty's, with its
//!   `Text` (58), a logout or heartbeat or write timeout, the transport
//!   closing or failing, a MsgSeqNum too low, the garbled-frame limit, an
//!   identity or `SendingTime` problem, a store failure, and more) to
//!   [`Application::on_session_closed`], whose default forwards to
//!   `on_logout` for a session that reached Active, and to
//!   [`Connection::close_reason`]. [`CloseReason::is_graceful`] is the flag
//!   `reset_on_logout` follows. [`Connection::logout_with_text`] sends a
//!   Logout carrying a checked `Text` (58). See
//!   `doc/adr/0025-typed-close-reason.md`.
//! - **[`loss`]**: the inbound loss report. Inbound application delivery is
//!   at most once; what a crash or an aborted dispatcher may have kept from
//!   `from_app` is reported as an [`InboundLoss`] span through
//!   [`Application::on_inbound_lost`], never redelivered. See
//!   `doc/adr/0030-inbound-loss-report.md`.
//! - **[`mismatch`]**: the Logon sequence mismatch report. When the
//!   counterparty's Logon `MsgSeqNum` (34) or `NextExpectedMsgSeqNum` (789)
//!   disagrees with the counters the session started from, a
//!   [`SequenceMismatch`] is reported through
//!   [`Application::on_sequence_mismatch`] before `on_logon`; it moves no
//!   counter. See `doc/adr/0015-standby-session-resume.md` and
//!   `doc/standby_resume.md`.
//! - **[`OutboundMessage`]**: the body you hand to [`Connection::send`]; the
//!   engine stamps the header, `MsgSeqNum` and trailer.
//!   [`Connection::acquire`] takes one from the session's bounded pool, to
//!   which it returns, cleared but with its storage kept, when it is dropped,
//!   sent or not: a body built with the copying push methods then allocates
//!   nothing. A send still boxes the `#[async_trait]` `to_app` future the
//!   default [`Application::to_app_checked`] awaits (see
//!   `doc/adr/0008-pooled-outbound-messages.md`).
//! - **[`Application`]**: the QuickFIX-shaped callback trait
//!   (`on_create` / `on_logon` / `on_logout` / `to_admin` / `from_admin` /
//!   `to_app` / `from_app`), plus [`NoOpApplication`].
//!   [`Application::to_app_checked`] is the outbound gate every new
//!   application message passes, whichever `send` it came through: its
//!   default runs `to_app` and sends, and an override can veto the message
//!   (the equivalent of QuickFIX's `DoNotSend`) through the [`SendVerdict`]
//!   it returns, before a `MsgSeqNum` is spent or the store is touched; a
//!   verdict decided at once ([`SendVerdict::ready`]) allocates nothing. A
//!   replay of a filed application frame (the answer to a `ResendRequest`,
//!   the 789 resend) goes through [`Application::to_app_resend`] instead,
//!   whose default allows it and whose veto gap-fills it, as QuickFIX does.
//!   Administrative messages (Logon, Logout, Heartbeat, TestRequest,
//!   ResendRequest, SequenceReset, Reject, XmlMessage) go through
//!   `to_admin` and cannot be vetoed. See
//!   `doc/adr/0023-outbound-veto-and-send-outcomes.md`.
//! - **[`throttle`]**: an optional per-session rate limit on new outbound
//!   application messages, attached with `with_throttle` on the
//!   [`Initiator`], the [`Acceptor`] or the [`EngineBuilder`]. A
//!   [`ThrottleConfig`] holds one or more token-bucket budgets
//!   ([`ThrottleBudget`]: a rate per window and a burst) and an optional
//!   classifier that puts each message in one, so cancels can have a budget
//!   of their own. A message that finds no token is held, in order, up to a
//!   bounded depth, or refused, per the budget's [`ThrottlePolicy`]; a
//!   refusal reports [`NotSentReason::Throttled`], before a `MsgSeqNum` is
//!   spent or the store touched, and a held message goes through
//!   `to_app_checked` only when it is released. Administrative messages and
//!   resends are never throttled; this session's Logout goes out at once and
//!   what the throttle holds then reports
//!   [`NotSentReason::DiscardedByThrottle`]. [`Connection::inbound_app_messages`]
//!   counts the counterparty's application messages, so an application can
//!   refuse over-rate ones in `from_app`. See
//!   `doc/adr/0024-outbound-throttle.md`.
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
//! sound header is not garbled: in session it gets a session Reject that
//! consumes its `MsgSeqNum`, and it is not counted; a message with no header
//! `MsgSeqNum` gets a Logout and a disconnect. During the Logon handshake both kinds are skipped, so a
//! counterparty that never sends an intact Logon ends in
//! [`EngineError::LogonTimeout`]. The optional
//! [`SessionConfig::garbled_frame_limit`] logs out a session whose link keeps
//! garbling. Only a frame above `max_message_size` (after a Logout saying so)
//! or an I/O error still ends the session at the codec.
//!
//! ## Frame capture
//!
//! [`Initiator::with_frame_observer`], [`Acceptor::with_frame_observer`] and
//! [`EngineBuilder::with_frame_observer`] attach a [`FrameObserver`]: a
//! synchronous capture hook that receives the exact bytes of every inbound
//! frame once framed and every outbound frame once built, with an
//! [`Observation`], then an [`OutboundResult`] per outbound frame. It runs
//! inline on the session's task, must be cheap and must not panic, and it
//! receives raw bytes, credentials included: redaction is its own
//! responsibility. See [`observer`] and ADR-0026
//! (`doc/adr/0026-frame-observer.md`).
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
//! ## TLS
//!
//! With the `tls` feature (off by default), `Initiator::connect_tls`,
//! `Acceptor::serve_tls` and `AcceptorRegistry::serve_tls` run the TLS
//! handshake themselves over rustls (through tokio-rustls), under their own
//! timeout ([`DEFAULT_TLS_HANDSHAKE_TIMEOUT`] unless set with
//! `with_tls_handshake_timeout`), with a `rustls::ClientConfig` or
//! `rustls::ServerConfig` the caller builds (mutual TLS included). IronFix
//! enables no crypto provider: the caller's configuration carries one. FIX
//! framing is unchanged inside TLS, and `EncryptMethod` (98) stays 0. With
//! the feature off, no TLS crate is in the dependency graph.
//!
//! Whichever features are on, [`Application::authorize_peer`] receives the
//! counterparty's certificate chain as a [`PeerInfo`] before any FIX message
//! is exchanged, so an application can bind a certificate to a CompID; the
//! `*_with_peer` stream entry points ([`Initiator::establish_with_peer`],
//! [`Acceptor::serve_stream_with_peer`],
//! [`AcceptorRegistry::serve_stream_with_peer`]) bring a chain from a TLS
//! stack of the caller's own. A TLS failure is [`EngineError::Tls`] and, after
//! `on_create`, [`CloseReason::Tls`]. See [`tls`] and ADR-0009
//! (`doc/adr/0009-tls.md`).
//!
//! ## FIXP over SOFH
//!
//! With the `fixp` feature (off by default), the `fixp` module runs the
//! FIX Performance Session Layer v1.1 core of `ironfix-fixp` over SOFH
//! framing (`ironfix-sofh`) in both roles: `fixp::FixpInitiator` and
//! `fixp::FixpAcceptor`, over TCP or any caller stream, each transport in
//! its own driver task, separate from the tag=value reactor. With the
//! feature off neither crate, nor `ironsbe-core`, is in the dependency
//! graph. See the module and `doc/fixp_operations.md`.
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
//! - **TLS is opt-in and has no builder knob.** It needs the `tls` feature,
//!   the TLS entry points take rustls types (a rustls major release is a
//!   breaking change of that surface), and `EngineBuilder` has no TLS
//!   setting: call `connect_tls` / `serve_tls` on the engine it builds. The
//!   TLS stream is boxed like any caller stream, and nothing has measured
//!   the cost.
//! - **Dictionary validation is opt-in and covers application messages
//!   only.** With an [`InboundValidation`] whose policy is not `Off`, every
//!   in-sequence inbound application message is checked before `from_app`,
//!   and logged or rejected on failure (see [`validation`], ADR-0031). The
//!   engine names only `ironfix_core::InboundValidator`; the validator is
//!   supplied by `ironfix-dictionary` or by the caller. Administrative
//!   messages are not validated against a dictionary, and the validator is
//!   not chosen per `ApplVerID` (1128).
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
//!   the messages still queued, and the loss is reported (see [`loss`]).

pub mod acceptor;
pub mod application;
pub mod builder;
pub mod close;
pub mod connection;
pub mod error;
#[cfg(feature = "fixp")]
pub mod fixp;
mod garbled;
pub mod initiator;
pub mod loss;
pub mod mismatch;
mod next_expected;
pub mod observer;
pub mod outbound;
pub mod outcome;
pub mod persistence;
mod reactor;
pub mod registry;
mod stream;
pub mod sync_application;
pub mod throttle;
pub mod tls;
pub mod validation;
mod wire;

pub use acceptor::Acceptor;
pub use application::{Application, NoOpApplication, RejectReason, SendVerdict, SessionId};
pub use builder::EngineBuilder;
pub use close::{CloseReason, LogoutCause, LogoutInitiator};
pub use connection::Connection;
pub use error::EngineError;
pub use initiator::Initiator;
pub use loss::{InboundLoss, InboundLossCause};
pub use mismatch::{InboundMismatch, OutboundMismatch, SequenceMismatch};
pub use observer::{Direction, FrameKind, FrameObserver, Observation, OutboundResult};
pub use outbound::{OutboundField, OutboundMessage};
pub use outcome::{NotSentReason, SendOutcome, UnknownReason};
pub use persistence::StoreFailurePolicy;
pub use registry::{AcceptorRegistry, LogonIdentity, LookupError, SessionLookup};
pub use sync_application::{SyncApplication, SyncApplicationAdapter};
pub use throttle::{
    BudgetId, ThrottleBudget, ThrottleConfig, ThrottleConfigBuilder, ThrottleConfigError,
    ThrottlePolicy,
};
pub use tls::{DEFAULT_TLS_HANDSHAKE_TIMEOUT, PeerInfo, TlsError, TlsFailure};
pub use validation::{InboundValidation, ValidationPolicy, ValidationRejectMessage};

// Re-exported for convenience: the per-session configuration consumed by
// [`Initiator`].
pub use ironfix_session::{GapPolicy, SessionConfig};
