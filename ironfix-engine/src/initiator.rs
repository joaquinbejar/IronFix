/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 14/7/26
******************************************************************************/

//! Client-side (initiator) FIX engine: TCP dial or a caller's stream,
//! framing, and a live session reactor.
//!
//! [`Initiator::connect`] dials the counterparty over TCP, frames the byte
//! stream with [`ironfix_transport::FixCodec`], drives the
//! [`ironfix_session`] typestate machine through
//! `connect() -> send_logon() -> on_logon_ack()`, and spawns a background
//! reactor task that owns the stream. The returned [`Connection`] handle is
//! the outbound message sink and exposes `wait_closed()` / `is_timed_out()`.
//!
//! [`Initiator::establish`] does the same on a stream the caller has already
//! connected, of any type that is `AsyncRead + AsyncWrite + Unpin + Send +
//! 'static`: a TLS stream, a Unix socket, a proxied connection, an in-memory
//! [`tokio::io::duplex`] pipe. `connect` is the TCP dial (with `TCP_NODELAY`
//! set) followed by exactly the handshake `establish` runs.
//!
//! Reconnection is deliberately out of scope: the consumer owns supervision
//! and backoff, and calls [`Initiator::connect`] (or
//! [`Initiator::establish`]) again for a new session.
//!
//! # Inbound conformance
//!
//! Every inbound frame is checked in this order: decode, `MsgSeqNum` (34)
//! presence, counterparty identity (49/56, plus 50/57 and 142/143 when
//! configured), `SendingTime` (52) accuracy, then heartbeat bookkeeping, then
//! sequence validation. Identity and clock come before the heartbeat
//! bookkeeping deliberately — traffic from the wrong counterparty, or from one
//! whose clock is wrong, must not keep the session alive, reach the
//! [`Application`], or move sequence state.
//!
//! Both of those failures end the session after a Reject and a Logout, because
//! both are systemic rather than per-message: a peer that is cross-wired, or
//! whose clock is two minutes out, will be so on its next message too.
//!
//! A *garbled* frame, by contrast, is per-message and is ignored: the codec
//! skips it, or the engine does when its header frames but does not decode
//! (see the crate-level docs). It consumes no `MsgSeqNum`, and the gap is
//! recovered by `ResendRequest`. While waiting for the Logon ack, a garbled ack
//! is skipped, and so is one whose body does not decode; the wait continues
//! against the same [`SessionConfig::logon_timeout`], so an ack that never
//! arrives intact ends in [`EngineError::LogonTimeout`].
//!
//! # Bounded recovery
//!
//! A gap is answered with a `ResendRequest` (2), and a request that goes
//! unanswered does not wait forever: it is retried every
//! [`SessionConfig::resend_timeout`] up to
//! [`SessionConfig::resend_attempt_limit`] attempts, after which the session is
//! logged out. Without that bound a peer that keeps sending gapped frames holds
//! a session open indefinitely — the frames refresh the heartbeat clock, so
//! nothing times out, while the inbound expectation never moves and nothing
//! reaches the application.
//!
//! # Heartbeats
//!
//! The `HeartBtInt` (108) confirmed on the Logon ack wins, but it is
//! counterparty-controlled and drives every liveness timer, so it is bounded
//! by [`ironfix_session::heartbeat::negotiate_interval`]: a confirmed interval
//! above [`ironfix_session::heartbeat::MAX_HEARTBEAT_INTERVAL_SECS`] that is
//! not simply an echo of what this side requested fails the handshake with a
//! Reject (reason 5, `RefTagID` 108) and a Logout. `108=0` is legal and means
//! "do not heartbeat": the reactor then emits no Heartbeat, sends no
//! TestRequest, and never times the session out.
//!
//! Once a TestRequest is outstanding, **any** inbound frame the session
//! accepts stops the timeout countdown; a Heartbeat echoing the `TestReqID` is
//! the positive confirmation. See the `ironfix_session::heartbeat` module
//! documentation for why the rule is that broad.
//!
//! Sequence recovery follows `doc/fix_operations.md`: a `SequenceReset` with
//! `GapFillFlag` (123) = Y is an ordinary sequenced message and is validated
//! against its own `MsgSeqNum`, while Reset mode alone may ignore it; an
//! inbound `ResendRequest` is answered within the bound set by `EndSeqNo`.
//!
//! # Application versions (FIX 5.0)
//!
//! A FIX 5.0 session is framed as FIXT.1.1. The Logon declares this session's
//! version in `DefaultApplVerID` (1137), and an acknowledgement that declares
//! one too must name, once, a version the session accepts
//! ([`SessionConfig::accepts_appl_version`]); otherwise the handshake fails
//! with a Reject (reason 18, `RefTagID` 1137) and a Logout, as
//! [`EngineError::ApplVersion`]. An acknowledgement without 1137 is accepted.
//! Once Active, an inbound application message whose `ApplVerID` (1128) names
//! a version the session does not accept is rejected (reason 18, `RefTagID`
//! 1128), its number consumed, and never reaches `from_app`. FIX 4.x
//! sessions carry neither field and check neither.
//!
//! # `NextExpectedMsgSeqNum` (789)
//!
//! With [`SessionConfig::send_next_expected_msg_seq_num`] set (FIX.4.4 and
//! FIXT.1.1 only), the Logon declares in 789 the next `MsgSeqNum` expected from
//! the acceptor (1 when it declares `ResetSeqNumFlag` (141)), and the
//! acknowledgement's 789 is held against this session's counters, those of a
//! reset the acknowledgement declares included, before that reset reaches the
//! store: a value above the next number this session sends fails the handshake
//! with a Logout and [`EngineError::NextExpectedMsgSeqNum`]; a value that is
//! 0, not a number or repeated with a Reject (`RefTagID` 789) and a Logout; a
//! value below this session's Logon makes the session resend that range, up to
//! but not including the Logon, once Active, as it would answer a
//! `ResendRequest`. When the acknowledgement declares 789 too and arrives with
//! a gap below it, no `ResendRequest` is sent: the acceptor resends that gap on
//! its own because of this Logon's 789, so the acknowledgement is held and its
//! number consumed once the gap is filled. One `ResendRequest` goes out only
//! when the gap makes no progress for [`SessionConfig::resend_timeout`], a
//! resend that stalls partway included.
//! Without the flag no 789 is sent and the acknowledgement's is ignored. 789 is
//! bilateral: both sides must enable it.
//!
//! # Resend and the message store
//!
//! [`Initiator::with_store`] attaches a [`MessageStore`]. Every sequenced
//! outbound frame is then filed under its `MsgSeqNum` before it goes on the
//! wire, and an inbound `ResendRequest` replays the stored application
//! messages with `PossDupFlag` (43) = Y and their original `SendingTime` in
//! `OrigSendingTime` (122). Administrative messages in the range, and any
//! sequence number the store cannot produce, are covered by
//! `SequenceReset`-GapFill, so the counterparty's expectation always lands
//! exactly where the request asked it to.
//!
//! **Without a store nothing can be replayed** and the whole requested range
//! is answered with one gap fill.
//!
//! Store writes are ordered (frame and next sender number before the bytes;
//! next target number before an inbound message is acted on) and fallible.
//! [`Initiator::with_store_failure_policy`] chooses what a failed write means:
//! carry on with a warning (the default), or fail closed, writing nothing the
//! store has not accepted. See the [`persistence`](crate::persistence) module.
//!
//! All sequence arithmetic goes through the checked
//! [`SequenceManager::try_allocate_sender_seq`](ironfix_session::SequenceManager::try_allocate_sender_seq) /
//! [`SequenceManager::try_increment_target_seq`](ironfix_session::SequenceManager::try_increment_target_seq);
//! an exhausted counter tears the session down rather than wrapping. A sender
//! number is spent only once
//! the frame that carries it exists, so a body with no legal wire form is a
//! dropped message rather than a hole the counterparty must resend over.
//!
//! # What blocks the reactor, and what does not
//!
//! The reactor is a single task owning the socket. Two things used to be able
//! to park it indefinitely, and neither can now:
//!
//! - **A stalled peer.** A counterparty that stops reading closes its receive
//!   window and would park a socket write forever. The reactor never waits
//!   inside a write: frames are appended to the write buffer, which one
//!   branch of the loop writes out while it goes on reading, so two sides
//!   writing to each other at once keep draining each other. Output the
//!   stream accepts none of for [`Initiator::with_write_timeout`] closes the
//!   session, the same verdict heartbeat detection would have reached,
//!   reached in bounded time.
//! - **A slow `from_app`.** Inbound application messages are handed to a
//!   separate dispatcher task over a bounded queue
//!   ([`Initiator::with_app_queue_capacity`]), so an application handler never
//!   delays a socket read, a heartbeat, or timeout detection.
//!
//! `to_admin`, `to_app_checked` (and through it `to_app`) and `from_admin`
//! still run inline, because each one's result decides what the reactor does
//! next. See [`Application`] for the
//! ordering that buys and the ordering it costs.
//!
//! So do the calls to an attached store: whether a frame may be written, or a
//! message acted on, depends on the store accepting the write first. A slow
//! store therefore delays the session for as long as each call takes. Every
//! call is bounded by [`Initiator::with_store_timeout`], and an overrun is a
//! failed write under the [`StoreFailurePolicy`].
//!
//! # Example
//!
//! ```no_run
//! use ironfix_core::message::MsgType;
//! use ironfix_core::types::CompId;
//! use ironfix_engine::application::NoOpApplication;
//! use ironfix_engine::{Initiator, OutboundMessage};
//! use ironfix_session::SessionConfig;
//! use std::sync::Arc;
//!
//! # async fn run() -> Result<(), ironfix_engine::EngineError> {
//! let config = SessionConfig::new(
//!     CompId::new("CLIENT").unwrap(),
//!     CompId::new("VENUE").unwrap(),
//!     "FIX.4.4",
//! );
//! let initiator = Initiator::new(config, Arc::new(NoOpApplication));
//! let connection = initiator.connect("127.0.0.1:9876").await?;
//!
//! let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
//! order.push_str(11, "ORDER-1");
//! connection.send(order).await?;
//!
//! connection.logout().await?;
//! connection.wait_closed().await;
//! # Ok(())
//! # }
//! ```

use crate::application::{Application, NoOpApplication, RejectReason, SessionId};
use crate::close::CloseReason;
use crate::connection::{Connection, SessionRuntime, report_handshake};
use crate::error::EngineError;
use crate::mismatch::SequenceMismatch;
use crate::next_expected::{self, NextExpectedPlan};
use crate::observer::{Capture, FrameObserver};
use crate::outbound::OutboundPool;
use crate::persistence::{
    PersistedCounters, SeedPlan, Seeded, StoreAttachment, StoreFailurePolicy, seed_session,
};
use crate::reactor::{
    DEFAULT_APP_QUEUE_CAPACITY, DEFAULT_OUTBOUND_CAPACITY, DEFAULT_WRITE_TIMEOUT, HandshakeRead,
    SessionParams, TICK_INTERVAL, lock_heartbeat, read_handshake_frame, refuse_handshake,
    send_handshake_admin, session_codec, spawn_session,
};
use crate::stream::SessionStream;
use crate::throttle::ThrottleConfig;
use crate::tls::{self, DEFAULT_TLS_HANDSHAKE_TIMEOUT, PeerInfo};
use crate::validation::InboundValidation;
use crate::wire::HeaderReject as _;
use crate::wire::{
    self, ApplVersionGuard, MessageFactory, PeerIdentity, SendingTimeGuard, UnsupportedVersion,
};
use ironfix_core::error::DecodeError;
use ironfix_core::message::MsgType;
use ironfix_core::version::FixVersion;
use ironfix_session::config::SessionConfigError;
use ironfix_session::header::check_encrypt_method;
use ironfix_session::sequence::{SequenceCounter, SequenceExhausted, SequenceResult};
use ironfix_session::{
    ADOPTED_RESET_NEXT_SENDER, ADOPTED_RESET_NEXT_TARGET, ADOPTED_RESET_STORED_TARGET,
    AckHeartBtIntDefect, AckReset, Connecting, Disconnected, HeartbeatManager, LogonCounters,
    LogonGapAction, LogonRole, NextExpectedBasis, ScreenedNextExpected, Session, SessionConfig,
    classify_logon_seq, decide_ack_reset, decide_logon_gap, declared_next_expected,
    default_appl_ver_id_required, initial_seed_applies, initiator_resets, interval_change,
    logon_ack_deadline, mismatch_report_applies, negotiate_logon_interval, owes_reset_durably,
    reset_flag_contradicts, screen_next_expected, seed_from_initial,
};
use ironfix_store::MessageStore;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::time::timeout;
use tokio_util::codec::Framed;

/// Client-side FIX engine.
///
/// Owns the session configuration and the [`Application`] callbacks. Each
/// call to [`Initiator::connect`] or [`Initiator::establish`] establishes one
/// live session and returns a [`Connection`] handle for it.
pub struct Initiator<A: Application = NoOpApplication> {
    /// Session configuration.
    config: SessionConfig,
    /// Application callbacks.
    application: Arc<A>,
    /// Session identifier derived from the configuration.
    session_id: SessionId,
    /// The configured FIX version, or why it cannot be framed. Resolved once
    /// at construction and reported by [`Initiator::connect`] before dialling.
    version: Result<FixVersion, UnsupportedVersion>,
    /// Whether the configuration is usable. Resolved once at construction and
    /// reported by [`Initiator::connect`] before dialling, so a knob that
    /// would corrupt the session's own messages never reaches a socket.
    config_check: Result<(), SessionConfigError>,
    /// TCP connect timeout.
    connect_timeout: Duration,
    /// Bound on the TLS handshake of `Initiator::connect_tls`.
    tls_handshake_timeout: Duration,
    /// The write timeout: bound on a handshake write, and on how long an
    /// established session's output may make no progress.
    write_timeout: Duration,
    /// Initial (sender, target) sequence numbers for session continuity.
    initial_sequences: Option<(u64, u64)>,
    /// Capacity of the outbound command queue.
    outbound_capacity: usize,
    /// Capacity of the inbound application queue.
    app_queue_capacity: usize,
    /// The optional message store, its failure policy, its call timeout and
    /// the owed-reset record: outbound frames are filed in the store and
    /// replayed from it when the counterparty asks for a resend.
    store: StoreAttachment,
    /// The outbound throttle each session gets its own budgets from, if any.
    throttle: Option<ThrottleConfig>,
    /// The frame observer every session of this engine reports to, if any.
    observer: Option<Arc<dyn FrameObserver>>,
    /// Dictionary validation of inbound application messages, if any.
    validation: Option<InboundValidation>,
}

/// Written by hand rather than derived: `dyn MessageStore` is not `Debug`, and
/// requiring it of every implementation to print one field is the wrong trade.
impl<A: Application> std::fmt::Debug for Initiator<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Initiator")
            .field("config", &self.config)
            .field("session_id", &self.session_id)
            .field("version", &self.version)
            .field("connect_timeout", &self.connect_timeout)
            .field("tls_handshake_timeout", &self.tls_handshake_timeout)
            .field("write_timeout", &self.write_timeout)
            .field("initial_sequences", &self.initial_sequences)
            .field("outbound_capacity", &self.outbound_capacity)
            .field("app_queue_capacity", &self.app_queue_capacity)
            .field("store", &self.store)
            .field("store_timeout", &self.store.timeout(self.write_timeout))
            .field("throttle", &self.throttle)
            .field("frame_observer", &self.observer.is_some())
            .field("inbound_validation", &self.validation)
            .finish_non_exhaustive()
    }
}

impl<A: Application + 'static> Initiator<A> {
    /// Creates a new initiator.
    ///
    /// The configuration is validated here and the verdict is reported by
    /// [`Initiator::connect`], which refuses to dial with an unusable one.
    /// Building it through [`ironfix_session::SessionConfigBuilder`] surfaces
    /// the same errors earlier.
    ///
    /// # Arguments
    /// * `config` - The session configuration
    /// * `application` - The application callback handler
    #[must_use]
    pub fn new(config: SessionConfig, application: Arc<A>) -> Self {
        let mut session_id = SessionId::new(
            config.begin_string.clone(),
            config.sender_comp_id.as_str(),
            config.target_comp_id.as_str(),
        );
        if let Some(sub) = &config.sender_sub_id {
            session_id = session_id.with_sender_sub_id(sub.clone());
        }
        if let Some(sub) = &config.target_sub_id {
            session_id = session_id.with_target_sub_id(sub.clone());
        }
        let version = wire::wire_version(&config.begin_string);
        let config_check = config.validate();

        Self {
            config,
            application,
            session_id,
            version,
            config_check,
            connect_timeout: Duration::from_secs(30),
            tls_handshake_timeout: DEFAULT_TLS_HANDSHAKE_TIMEOUT,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            initial_sequences: None,
            outbound_capacity: DEFAULT_OUTBOUND_CAPACITY,
            app_queue_capacity: DEFAULT_APP_QUEUE_CAPACITY,
            store: StoreAttachment::default(),
            throttle: None,
            observer: None,
            validation: None,
        }
    }

    /// Attaches a message store to the session.
    ///
    /// With a store the engine files every sequenced outbound frame under its
    /// `MsgSeqNum` and, on an inbound `ResendRequest` (35=2), replays the
    /// stored **application** messages with `PossDupFlag` (43) = Y and the
    /// original `SendingTime` in `OrigSendingTime` (122). Administrative
    /// messages, and any sequence number the store cannot produce, are covered
    /// by `SequenceReset`-GapFill instead — see
    /// [`Initiator::connect`](Initiator::connect) and
    /// `doc/fix_operations.md`, "Resend Request".
    ///
    /// Without a store the engine has nothing to replay and answers the whole
    /// requested range with one gap fill.
    ///
    /// The store also carries sequence numbers: unless `reset_on_logon` is set
    /// or [`Initiator::with_initial_sequences`] is called, the session starts
    /// from the counters the store reports, and both counters are persisted
    /// back into it as the session runs, in the order described in the
    /// [`persistence`](crate::persistence) module. With a
    /// [`FileStore`](ironfix_store::FileStore) the counters and the filed
    /// frames survive a restart, as durably as its
    /// [`SyncPolicy`](ironfix_store::SyncPolicy) promises; a
    /// [`MemoryStore`](ironfix_store::MemoryStore) holds them in memory only.
    ///
    /// **One store, one engine.** The store must belong to this initiator
    /// alone: two engines, or two processes, writing to one store would
    /// interleave two sequence streams in it. The record of a reset owed to the
    /// next session is held by the initiator and mirrored by a durable marker
    /// in the store ([`MessageStore::set_reset_owed`]), so a restart over the
    /// same store still makes and declares it (#111, ADR-0029). Call [`Initiator::connect`] again only
    /// once the previous session's [`Connection::wait_closed`] has returned.
    ///
    /// A failed write to the store is handled by
    /// [`Initiator::with_store_failure_policy`]; the default carries on with a
    /// warning. Every store call is bounded by
    /// [`Initiator::with_store_timeout`].
    #[must_use]
    pub fn with_store(mut self, store: Arc<dyn MessageStore>) -> Self {
        self.store.attach(store);
        self
    }

    /// Sets what a failed write to the attached store means (default
    /// [`StoreFailurePolicy::Continue`]).
    ///
    /// With [`StoreFailurePolicy::CloseSession`] the engine never puts a frame
    /// on the wire, or acts on an inbound message, that the store has not
    /// accepted: a failure during the Logon handshake makes
    /// [`Initiator::connect`] return [`EngineError::Store`], and one during the
    /// session closes it without writing the frame concerned. Without a store
    /// this has no effect.
    ///
    /// # Arguments
    /// * `policy` - The policy for store write failures
    #[must_use]
    pub const fn with_store_failure_policy(mut self, policy: StoreFailurePolicy) -> Self {
        self.store.set_policy(policy);
        self
    }

    /// Sets how long a single call to the attached store may take before it
    /// counts as failed (default: the write timeout, see
    /// [`Initiator::with_write_timeout`]).
    ///
    /// The session awaits every store call inline, so a store that stalls
    /// stalls the session with it: no socket read, no heartbeat and no timeout
    /// detection until the call returns. The bound turns a stall into
    /// [`StoreError::Timeout`](ironfix_core::error::StoreError::Timeout). A
    /// write that overruns is handled by the [`StoreFailurePolicy`] like any
    /// other failed write; a reset or refresh that overruns fails the connect
    /// with [`EngineError::Store`], whatever the policy; and a resend read
    /// that overruns is answered with a gap fill. Without a store this has no
    /// effect.
    ///
    /// A write that overruns may still land later, so it also leaves a reset
    /// owed: the next session resets the store and logs on with
    /// `ResetSeqNumFlag` (141) = Y. Reusing the store is safe only if it
    /// applies its mutations in call order even when a call is dropped (see
    /// the [`persistence`](crate::persistence) module).
    ///
    /// A zero timeout is raised to one tick, as for the write timeout: a call
    /// given no time at all can never succeed.
    ///
    /// # Arguments
    /// * `timeout` - Maximum duration of one store call
    #[must_use]
    pub fn with_store_timeout(mut self, timeout: Duration) -> Self {
        self.store.set_timeout(timeout.max(TICK_INTERVAL));
        self
    }

    /// Sets the TCP connect timeout (default 30s).
    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Sets the bound on the TLS handshake of `Initiator::connect_tls`
    /// (`tls` feature), [`DEFAULT_TLS_HANDSHAKE_TIMEOUT`] by default.
    ///
    /// It starts once the TCP connection is up (the connect timeout bounds
    /// the dial) and ends with the handshake; the logon timeout starts after
    /// it. Expiry fails the connect with [`EngineError::Tls`] carrying
    /// [`TlsError::HandshakeTimeout`](crate::TlsError::HandshakeTimeout).
    /// No other entry point runs a TLS handshake, so none reads it.
    #[must_use]
    pub const fn with_tls_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.tls_handshake_timeout = timeout;
        self
    }

    /// The bound on the TLS handshake of `Initiator::connect_tls`.
    #[must_use]
    pub const fn tls_handshake_timeout(&self) -> Duration {
        self.tls_handshake_timeout
    }

    /// Sets the write timeout (default 10s): how long the session's output
    /// may wait while the stream accepts none of it.
    ///
    /// A counterparty that stops reading closes its TCP receive window, and a
    /// write into a closed window never completes. During the Logon handshake
    /// a write that takes longer than this fails `connect` / `establish` with
    /// [`EngineError::WriteTimeout`]. Once the session is established the
    /// reactor never waits inside a write: output waits in the write buffer
    /// while the reactor goes on reading, and the session is closed once the
    /// stream has accepted none of that output for this long. The time a
    /// whole resend or burst takes does not count, only time without
    /// progress.
    ///
    /// "Progress" means bytes the local stream accepted: for TCP, bytes
    /// copied into the kernel's send buffer, not bytes the counterparty
    /// received. A stream that buffers on its own (TLS, for instance) accepts
    /// bytes it has not sent yet, and so hides a counterparty that stopped
    /// reading until its own buffer is full. The check runs on the reactor's
    /// 100 ms tick, so a stall is detected about two ticks after the timeout,
    /// later if the reactor is inside an inline await (a store call, a
    /// callback) when the timeout runs out.
    ///
    /// A zero timeout is raised to one tick: a write that is given no time at
    /// all can never succeed.
    ///
    /// # Arguments
    /// * `timeout` - Longest a handshake write may take, and longest the
    ///   session's output may wait without the stream accepting any of it
    #[must_use]
    pub fn with_write_timeout(mut self, timeout: Duration) -> Self {
        self.write_timeout = timeout.max(TICK_INTERVAL);
        self
    }

    /// Sets the capacity of the inbound application queue (default 1024).
    ///
    /// Inbound application messages are handed to a dispatcher task over this
    /// queue so that a slow [`Application::from_app`] cannot stall socket
    /// reads or heartbeat generation. Messages are delivered in ascending
    /// `MsgSeqNum` order.
    ///
    /// **Lag policy:** when the queue is full the session is closed rather than
    /// the message silently dropped. The frame is offered to the dispatcher
    /// *before* the inbound sequence expectation advances past it, so the close
    /// leaves the counterparty free to resend from that number. Raise the
    /// capacity for an application that legitimately bursts.
    ///
    /// **Memory:** the bound is on message count, not bytes, and each queued
    /// frame retains up to [`SessionConfig::max_message_size`]. The worst-case
    /// retained memory is `capacity * max_message_size` — with the default
    /// capacity of 1024 that is 1 GiB at the default 1 MiB frame size and 64 GiB
    /// at the 64 MiB ceiling — so raise this and `max_message_size` together
    /// with that product in mind.
    ///
    /// # Arguments
    /// * `capacity` - Queue depth in messages, at least 1
    #[must_use]
    pub fn with_app_queue_capacity(mut self, capacity: usize) -> Self {
        self.app_queue_capacity = capacity.max(1);
        self
    }

    /// Seeds the session with initial sequence numbers, for continuity with
    /// a previous session (e.g. after a reconnect supervised by the
    /// consumer). Ignored when `reset_on_logon` is set.
    ///
    /// Both values must be at least 1: FIX numbers messages from 1, and a
    /// seeded `MsgSeqNum` (34) of 0 would be rejected by every conforming
    /// counterparty. A zero seed that would actually be used is refused by
    /// [`Initiator::connect`] with [`EngineError::InvalidInitialSequence`],
    /// before the socket is dialled.
    ///
    /// The seed outranks the counters an attached store reports. Under
    /// [`StoreFailurePolicy::CloseSession`], though, a sender seed below the
    /// store's next sender number is refused with
    /// [`EngineError::InitialSequenceBelowStore`], before anything is written:
    /// the store has frames filed at those numbers, so the counterparty has
    /// seen them, and reusing one would send a different message under a
    /// `MsgSeqNum` it already holds.
    ///
    /// # Arguments
    /// * `sender_seq` - Next outgoing sequence number, `>= 1`
    /// * `target_seq` - Next expected incoming sequence number, `>= 1`
    #[must_use]
    pub fn with_initial_sequences(mut self, sender_seq: u64, target_seq: u64) -> Self {
        self.initial_sequences = Some((sender_seq, target_seq));
        self
    }

    /// Sets the capacity of the outbound message queue (default 1024).
    #[must_use]
    pub fn with_outbound_capacity(mut self, capacity: usize) -> Self {
        self.outbound_capacity = capacity.max(1);
        self
    }

    /// Attaches an outbound throttle to the session: an optional per-session rate
    /// limit on new outbound application messages (see [`crate::throttle`]).
    ///
    /// Each session gets its own budgets from `throttle`, full when it
    /// becomes Active. A new application message takes a token from the
    /// budget the classifier puts it in; one that finds none is held, in
    /// order, or refused, as the budget's [`ThrottlePolicy`](crate::ThrottlePolicy)
    /// says, and a refusal reports
    /// [`NotSentReason::Throttled`](crate::NotSentReason::Throttled) through
    /// [`Connection::send_tracked`]. A held message goes through
    /// `to_app_checked`, takes its `MsgSeqNum` and is filed only when it is
    /// released. Administrative messages (Heartbeats, the replies to
    /// TestRequests, ResendRequests, Rejects, Logouts) and resends of filed
    /// frames are never throttled. This session's own Logout goes out at
    /// once, and what the throttle still holds then reports
    /// [`NotSentReason::DiscardedByThrottle`](crate::NotSentReason::DiscardedByThrottle).
    ///
    /// Without a throttle (the default) messages are framed as fast as they
    /// are queued.
    ///
    /// # Arguments
    /// * `throttle` - The budgets and classifier, checked by
    ///   [`ThrottleConfigBuilder::build`](crate::ThrottleConfigBuilder::build)
    #[must_use]
    pub fn with_throttle(mut self, throttle: ThrottleConfig) -> Self {
        self.throttle = Some(throttle);
        self
    }

    /// Returns the outbound throttle attached with `with_throttle`, if any.
    #[must_use]
    pub const fn throttle(&self) -> Option<&ThrottleConfig> {
        self.throttle.as_ref()
    }

    /// Attaches a capture hook that sees every frame each session of this
    /// engine reads and writes, handshake included, with its write result
    /// (issue #70).
    ///
    /// The observer runs synchronously on the session's task: it must be
    /// cheap, must not block and must not panic (the release profile aborts
    /// on a panic). It receives **raw bytes, credentials included**
    /// (`Password` (554), `NewPassword` (925), `RawData` (96)); redacting
    /// them is the observer's responsibility. See [`crate::observer`] for
    /// what is observed and when.
    ///
    /// Without an observer (the default) a frame costs one branch.
    ///
    /// # Arguments
    /// * `observer` - The capture hook
    #[must_use]
    pub fn with_frame_observer(mut self, observer: Arc<dyn FrameObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Returns whether a frame observer is attached.
    #[must_use]
    pub const fn has_frame_observer(&self) -> bool {
        self.observer.is_some()
    }

    /// Validates the inbound application messages of every session of this engine
    /// against a schema before `from_app` (issue #84, ADR-0031).
    ///
    /// Each in-sequence application message is checked with the
    /// validation's validator, typically an `ironfix_dictionary`
    /// `Validator`, `Dictionary` or `SessionDictionary`, and a failure is
    /// logged ([`ValidationPolicy::Log`](crate::ValidationPolicy::Log))
    /// or answered with a Reject that consumes the message's number and
    /// keeps it from `from_app`
    /// ([`ValidationPolicy::Reject`](crate::ValidationPolicy::Reject)).
    /// Administrative messages are not validated. See
    /// [`crate::validation`] for where the check sits and what the Reject
    /// carries.
    ///
    /// Without one, or under
    /// [`ValidationPolicy::Off`](crate::ValidationPolicy::Off) (the
    /// default), the validator is never called.
    ///
    /// # Arguments
    /// * `validation` - The validator and its policy
    #[must_use]
    pub fn with_inbound_validation(mut self, validation: InboundValidation) -> Self {
        self.validation = Some(validation);
        self
    }

    /// Returns the inbound validation attached with
    /// `with_inbound_validation`, if any.
    #[must_use]
    pub const fn inbound_validation(&self) -> Option<&InboundValidation> {
        self.validation.as_ref()
    }

    /// The attached frame observer bound to `session_id`, if any.
    #[must_use]
    fn capture(&self, session_id: &SessionId) -> Option<Capture> {
        Capture::bind(self.observer.as_ref(), session_id)
    }

    /// How this connect decides its starting sequence numbers (see
    /// [`seed_session`]).
    ///
    /// `reset` is set by `reset_on_logon` or by a reset an earlier session of
    /// this `Initiator` owes (a close-time reset, or the reset for a
    /// counterparty's `ResetSeqNumFlag` (141), that failed). Either way the
    /// Logon declares `ResetSeqNumFlag` = Y and starts at 1, so both sides
    /// restart the sequence together. The reset is paid once that Logon is
    /// acknowledged, not here: a connect that fails before then still owes
    /// it, and a store write that fails during the handshake owes another.
    #[must_use]
    fn seed_plan(&self, reset: bool) -> SeedPlan<'_> {
        self.store.seed_plan(
            &self.session_id,
            reset,
            self.initial_sequences,
            self.write_timeout,
        )
    }

    /// Returns the session configuration.
    #[must_use]
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Returns the session identifier.
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Dials the counterparty, completes the Logon handshake, and spawns
    /// the session reactor.
    ///
    /// `TCP_NODELAY` is set on the dialled socket, and the socket is held by
    /// value. To run the session over a stream you opened yourself, see
    /// [`Initiator::establish`].
    ///
    /// On success the session is Active: `on_logon` has fired and the
    /// returned [`Connection`] can send application messages. The reactor
    /// owns the socket and handles heartbeats, TestRequests, sequence
    /// validation, and admin replies until the session closes.
    ///
    /// # Dropping the handle logs out
    ///
    /// The reactor stops when the last [`Connection`] clone is dropped: it
    /// reads that as "nobody can drive this session any more" and performs a
    /// graceful Logout rather than leaving a task holding a socket forever.
    /// A consumer that wants the session to outlive its handle must keep one
    /// alive — typically by holding it until [`Connection::wait_closed`]
    /// returns.
    ///
    /// # One session at a time, with a store
    ///
    /// With a store attached, call `connect` again only once the previous
    /// session's [`Connection::wait_closed`] has returned. Until then the
    /// closing session still writes to the store (the close-time reset of
    /// `reset_on_logout` / `reset_on_disconnect` and the last counter values)
    /// and may record a reset owed to the next session; a session started
    /// beside it would share the store with it and could miss that record.
    /// The engine does not enforce this.
    ///
    /// # Arguments
    /// * `addr` - The counterparty address to dial
    ///
    /// # Errors
    /// Returns an [`EngineError`] if the dial, framing, or Logon handshake
    /// fails. An ack that never arrives intact within
    /// [`SessionConfig::logon_timeout`], including one that arrives only
    /// garbled, is [`EngineError::LogonTimeout`]. Beyond timeouts and
    /// transport failures that includes
    /// [`EngineError::IdentityMismatch`], when the ack's CompIDs do not match
    /// the configured session, and [`EngineError::SequenceExhausted`], when a
    /// sequence counter has reached `u64::MAX` and the session must be reset
    /// before it can number another message; and, on a FIX 5.0 session,
    /// [`EngineError::ApplVersion`], when the ack carries a `DefaultApplVerID`
    /// (1137) the session does not accept; and, with
    /// [`SessionConfig::send_next_expected_msg_seq_num`] set,
    /// [`EngineError::NextExpectedMsgSeqNum`], when the ack's
    /// `NextExpectedMsgSeqNum` (789) is malformed or above the next number
    /// this session sends. A `BeginString` this engine
    /// cannot frame conformantly is refused up front with
    /// [`EngineError::UnsupportedVersion`], an unusable configuration with
    /// [`EngineError::Config`], and a zero initial sequence seed with
    /// [`EngineError::InvalidInitialSequence`], all before the socket is
    /// dialled.
    pub async fn connect(&self, addr: impl ToSocketAddrs) -> Result<Connection, EngineError> {
        // Refused before dialling: nothing is worth a connection with a
        // configuration, version or seed the session cannot run on.
        let version = self.preflight()?;

        let session_id = self.session_id.clone();
        self.application.on_create(&session_id).await;

        // Typestate: Disconnected -> Connecting.
        let session = Session::<Disconnected>::new(session_id.to_string()).connect();
        let (session, stream) = self.dial(session, addr).await?;

        // The only way to a TCP session: it sets TCP_NODELAY.
        let result = self
            .logon(version, session, SessionStream::tcp(stream))
            .await;
        // `on_create` has run: a failure from here is reported to the
        // application as well as returned.
        report_handshake(&*self.application, &session_id, result).await
    }

    /// Dials the counterparty over TCP, bounded by the connect timeout.
    ///
    /// `on_create` has run, so a failed dial is reported to
    /// [`Application::on_session_closed`] as [`CloseReason::ConnectFailed`]
    /// here, as well as returned.
    ///
    /// # Errors
    /// [`EngineError::ConnectTimeout`], or [`EngineError::Io`] for a failed
    /// dial.
    async fn dial(
        &self,
        session: Session<Connecting>,
        addr: impl ToSocketAddrs,
    ) -> Result<(Session<Connecting>, TcpStream), EngineError> {
        let (reason, err) = match timeout(self.connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok((session, stream)),
            Err(_) => (
                CloseReason::ConnectFailed {
                    kind: None,
                    timed_out: true,
                },
                EngineError::ConnectTimeout(self.connect_timeout),
            ),
            Ok(Err(err)) => (
                CloseReason::ConnectFailed {
                    kind: Some(err.kind()),
                    timed_out: false,
                },
                err.into(),
            ),
        };
        let _ = session.disconnect();
        self.application
            .on_session_closed(&self.session_id, &reason)
            .await;
        Err(err)
    }

    /// Dials the counterparty, completes a TLS handshake over the socket,
    /// then the Logon handshake inside TLS, and spawns the session reactor.
    ///
    /// Available with the `tls` feature. `config` is the caller's: it carries
    /// the crypto provider, the protocol versions and cipher suites, the
    /// roots the server certificate is verified against, and, for mutual
    /// TLS, the client certificate. `server_name` is the name the server
    /// certificate must be valid for. Build both against
    /// [`crate::tls::rustls`], the rustls version this crate is built
    /// against. See ADR-0009 (`doc/adr/0009-tls.md`).
    ///
    /// The order is: the configuration checks, `on_create`, the TCP dial
    /// (bounded by the connect timeout; `TCP_NODELAY` is set on the socket),
    /// the TLS handshake (bounded by
    /// [`Initiator::with_tls_handshake_timeout`]),
    /// [`Application::authorize_peer`] with the server's certificate chain,
    /// and only then the Logon, so credentials stamped on it by `to_admin`
    /// are written to a server that proved its identity and the application
    /// accepted. From the Logon on, everything is as on
    /// [`Initiator::connect`]: FIX framing is unchanged inside TLS, and
    /// `EncryptMethod` (98) stays 0. The TLS stream is boxed once, as on
    /// [`Initiator::establish`].
    ///
    /// # Errors
    /// Every error [`Initiator::connect`] documents, and
    /// [`EngineError::Tls`] when the handshake fails (an untrusted or expired
    /// certificate, a name mismatch, no common protocol), times out, or
    /// `authorize_peer` refuses the server. A TLS failure is reported to
    /// [`Application::on_session_closed`] as [`CloseReason::Tls`].
    #[cfg(feature = "tls")]
    pub async fn connect_tls(
        &self,
        addr: impl ToSocketAddrs,
        config: Arc<crate::tls::rustls::ClientConfig>,
        server_name: crate::tls::rustls::pki_types::ServerName<'static>,
    ) -> Result<Connection, EngineError> {
        let version = self.preflight()?;

        let session_id = self.session_id.clone();
        self.application.on_create(&session_id).await;

        // Typestate: Disconnected -> Connecting. The Logon is not sent until
        // TLS is up and the server is authorized.
        let session = Session::<Disconnected>::new(session_id.to_string()).connect();
        let (session, stream) = self.dial(session, addr).await?;

        let result = match crate::tls::handshake::connect(
            stream,
            config,
            server_name,
            self.tls_handshake_timeout,
        )
        .await
        {
            Err(err) => {
                let _ = session.disconnect();
                Err(err.into())
            }
            Ok((stream, peer)) => {
                self.logon_with_peer(version, session, SessionStream::erased(stream), &peer)
                    .await
            }
        };
        report_handshake(&*self.application, &session_id, result).await
    }

    /// Establishes a session on a byte stream the caller has already
    /// connected: runs the Logon handshake over it and spawns the session
    /// reactor, exactly as [`Initiator::connect`] does once it has dialled.
    ///
    /// This is the seam for any transport the engine does not open itself: a
    /// TLS stream built with the TLS stack of your choice, a Unix socket, a
    /// connection through a proxy, or an in-memory [`tokio::io::duplex`] pipe
    /// for tests. Everything after the dial is the same as on
    /// [`Initiator::connect`]: the configuration, version and seed checks, the
    /// Logon and its acknowledgement checks, the logon timeout, the write
    /// timeout, the store order and the reactor. Only the dial is missing, so
    /// [`Initiator::with_connect_timeout`] does not apply, and no socket option
    /// is set: `TCP_NODELAY`, which [`Initiator::connect`] sets, is the
    /// caller's to set on a TCP socket under the stream.
    ///
    /// The session owns the stream from here on and closes it when the
    /// session ends; on an error the stream is dropped, which closes it. The
    /// logon and write timeouts bound only what happens from this call on: a
    /// TLS handshake, or anything else, run on the stream before it is not
    /// bounded by them and is the caller's to bound.
    ///
    /// The stream must be a well-behaved [`AsyncRead`]: `poll_read` fills the
    /// `ReadBuf` it is handed and never swaps it for another one. The framing
    /// layer (tokio-util) asserts this, and a stream that breaks it panics the
    /// task reading it (the whole process, under `panic = "abort"`).
    ///
    /// The stream is boxed once, here, and the TCP path of
    /// [`Initiator::connect`] is not: it holds its socket by value. Each
    /// outbound frame written in one piece then costs three dynamic calls
    /// (`is_write_vectored`, `poll_write_vectored`, `poll_flush`), and each
    /// read poll one, the `Pending` poll on every wakeup included. Nothing has
    /// measured that cost. Pass the stream's concrete type: a stream that is
    /// already boxed (`Box<dyn ...>`, `Pin<Box<dyn ...>>`) is boxed again, for
    /// two allocations and two vtable hops on every call.
    ///
    /// Everything [`Initiator::connect`] says about the returned
    /// [`Connection`] (dropping every handle logs out) and about one session
    /// at a time with a store applies here too.
    ///
    /// # Arguments
    /// * `stream` - A connected byte stream to the counterparty
    ///
    /// # Errors
    /// Every error [`Initiator::connect`] documents except
    /// [`EngineError::ConnectTimeout`] and a dial failure. A stream that
    /// closes before the Logon acknowledgement arrives is
    /// [`EngineError::Closed`], or [`EngineError::Codec`] carrying the I/O
    /// error when it closes partway through a frame or a write or read on it
    /// fails. The configuration, version and seed are checked before the
    /// stream is written to.
    ///
    /// # Examples
    ///
    /// Both roles over an in-memory pipe, with no socket at all:
    ///
    /// ```
    /// use ironfix_core::types::CompId;
    /// use ironfix_engine::{Acceptor, Initiator, NoOpApplication, SessionConfig};
    /// use std::sync::Arc;
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = SessionConfig::new(CompId::new("CLIENT")?, CompId::new("VENUE")?, "FIX.4.4");
    /// let venue = SessionConfig::new(CompId::new("VENUE")?, CompId::new("CLIENT")?, "FIX.4.4");
    ///
    /// let (client_io, venue_io) = tokio::io::duplex(64 * 1024);
    /// let acceptor = Acceptor::new(venue, Arc::new(NoOpApplication));
    /// let served = tokio::spawn(async move { acceptor.serve_stream(venue_io).await });
    ///
    /// let initiator = Initiator::new(client, Arc::new(NoOpApplication));
    /// let connection = initiator.establish(client_io).await?;
    /// let venue_connection = served.await??;
    /// assert_eq!(connection.next_sender_seq(), 2);
    ///
    /// connection.logout().await?;
    /// connection.wait_closed().await;
    /// venue_connection.wait_closed().await;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn establish<S>(&self, stream: S) -> Result<Connection, EngineError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Refused before the stream is written to, as `connect` refuses
        // before dialling.
        let version = self.preflight()?;

        let session_id = self.session_id.clone();
        self.application.on_create(&session_id).await;

        // Typestate: Disconnected -> Connecting. The transport is already
        // connected; what `Connecting` means is that the Logon is not sent.
        let session = Session::<Disconnected>::new(session_id.to_string()).connect();

        let result = self
            .logon(version, session, SessionStream::erased(stream))
            .await;
        report_handshake(&*self.application, &session_id, result).await
    }

    /// [`Initiator::establish`] on a stream whose counterparty the caller's
    /// transport has proved, typically a TLS stream from a TLS stack of the
    /// caller's choice, with the certificates the peer presented.
    ///
    /// Runs [`Application::authorize_peer`] with `peer` after `on_create`
    /// and before the Logon is written; everything else is
    /// [`Initiator::establish`], unchanged. This is how a peer reaches the
    /// application without a new bound on the stream type (ADR-0007 froze
    /// it). The engine trusts `peer` as given: verifying the chain is the
    /// caller's TLS stack's job.
    ///
    /// # Arguments
    /// * `stream` - A connected byte stream to the counterparty
    /// * `peer` - What the transport proved about the counterparty
    ///
    /// # Errors
    /// Every error [`Initiator::establish`] documents, and
    /// [`EngineError::Tls`] carrying
    /// [`TlsError::PeerRejected`](crate::TlsError::PeerRejected) when
    /// `authorize_peer` refuses the peer; nothing is written to the stream
    /// then.
    pub async fn establish_with_peer<S>(
        &self,
        stream: S,
        peer: PeerInfo,
    ) -> Result<Connection, EngineError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let version = self.preflight()?;

        let session_id = self.session_id.clone();
        self.application.on_create(&session_id).await;

        // Typestate: Disconnected -> Connecting.
        let session = Session::<Disconnected>::new(session_id.to_string()).connect();

        let result = self
            .logon_with_peer(version, session, SessionStream::erased(stream), &peer)
            .await;
        report_handshake(&*self.application, &session_id, result).await
    }

    /// [`Initiator::logon`] for a counterparty the transport proved:
    /// [`Application::authorize_peer`] first, and nothing is written to the
    /// stream if it refuses.
    ///
    /// # Errors
    /// [`EngineError::Tls`] for a refused peer, then every error of
    /// [`Initiator::logon`].
    async fn logon_with_peer(
        &self,
        version: FixVersion,
        session: Session<Connecting>,
        stream: SessionStream,
        peer: &PeerInfo,
    ) -> Result<Connection, EngineError> {
        if let Err(err) = tls::authorize(&*self.application, &self.session_id, peer).await {
            let _ = session.disconnect();
            return Err(err);
        }
        self.logon(version, session, stream).await
    }

    /// The checks [`Initiator::connect`] and [`Initiator::establish`] make
    /// before they touch a transport.
    ///
    /// # Errors
    /// [`EngineError::Config`], [`EngineError::UnsupportedVersion`] and
    /// [`EngineError::InvalidInitialSequence`].
    fn preflight(&self) -> Result<FixVersion, EngineError> {
        // A knob outside its documented range corrupts the session's own
        // messages: an identity string carrying SOH breaks every header, and
        // a fractional HeartBtInt negotiates one interval while the local
        // timers run another.
        if let Err(err) = &self.config_check {
            return Err(EngineError::Config(err.clone()));
        }

        // An unsupported version cannot produce a conforming Logon, and
        // guessing one would put a fabricated version on the wire.
        let version = match &self.version {
            Ok(version) => *version,
            Err(err) => {
                return Err(EngineError::UnsupportedVersion {
                    version: err.version.clone(),
                    detail: err.detail.clone(),
                });
            }
        };

        // A seeded sequence number of zero would put MsgSeqNum (34) = 0 on
        // the wire, which every conforming counterparty rejects. The seed is
        // ignored entirely when the Logon declares a reset (reset_on_logon,
        // or a reset owed by an earlier session), so a zero is only refused
        // when it would actually be used. The validated seed is applied by
        // `seed_session`, which reads the same fields; this is only the
        // guard.
        if let Some(initial) = self.initial_sequences
            && initial_seed_applies(self.config.reset_on_logon, self.store.reset_is_owed())
        {
            seed_from_initial(initial)
                .map_err(|counter| EngineError::InvalidInitialSequence { counter })?;
        }
        Ok(version)
    }

    /// The initiator half of the Logon handshake on a connected stream, up to
    /// the spawned reactor. Shared by [`Initiator::connect`] and
    /// [`Initiator::establish`], so a session is checked, persisted and run
    /// the same way whichever transport it came over.
    ///
    /// # Errors
    /// Every handshake error [`Initiator::connect`] documents after the dial.
    async fn logon(
        &self,
        version: FixVersion,
        session: Session<Connecting>,
        stream: SessionStream,
    ) -> Result<Connection, EngineError> {
        let session_id = self.session_id.clone();
        let mut framed = Framed::new(stream, session_codec(&self.config, version));

        // Seeding fails closed: a store that cannot be reset or refreshed leaves
        // the session unable to vouch for its own counters, so it is refused
        // here rather than started from a number that could collide with a
        // stream still on file.
        // Inbound messages the previous session accepted but may not have
        // delivered are reported before anything else touches the store: a
        // reset would erase the numbers (issue #105, ADR-0030).
        if let Err(err) = self
            .store
            .report_inbound_loss(self.application.as_ref(), &session_id, self.write_timeout)
            .await
        {
            let _ = session.disconnect();
            return Err(err.into());
        }
        let reset_logon = initiator_resets(self.config.reset_on_logon, self.store.reset_is_owed());
        // Owed from before the reset until the Logon declaring it is
        // acknowledged: a connect dropped while the reset is pending leaves it
        // owed, and so does one that fails later. The ticket pays only this
        // reset: a store write that fails during the handshake owes another.
        //
        // The intent is made durable in the store before the reset is acted
        // on (ADR-0029): a crash from here until the Logon is acknowledged
        // leaves the store's marker set, and the next session, in this
        // process or a restarted one, resets and declares the reset again.
        let reset_ticket = if owes_reset_durably(reset_logon, self.store.store().is_some()) {
            match self
                .store
                .owe_durably(&session_id, self.write_timeout)
                .await
            {
                Ok(ticket) => Some(ticket),
                Err(err) => {
                    let _ = session.disconnect();
                    return Err(err.into());
                }
            }
        } else {
            None
        };
        let Seeded {
            sequences,
            persisted,
            stored,
        } = match seed_session(self.seed_plan(reset_logon)).await {
            Ok(seeded) => seeded,
            Err(err) => {
                let _ = session.disconnect();
                return Err(err);
            }
        };
        let runtime = Arc::new(SessionRuntime::new(
            sequences,
            HeartbeatManager::new(self.config.heartbeat_interval, crate::reactor::driver_now()),
        ));
        let mut factory = MessageFactory::new(&self.config, version);
        let identity = PeerIdentity::new(&self.config);
        let sending_time = SendingTimeGuard::new(&self.config);
        let appl_version = ApplVersionGuard::new(&self.config, version);
        let write_timeout = self.write_timeout;
        let store_timeout = self.store.timeout(write_timeout);
        // Every handshake write goes through this binding, which also records
        // the counter values written, for the reactor to start from.
        let mut store = self.store.handshake(persisted, write_timeout);

        // Typestate: Connecting -> LogonSent.
        //
        // `to_admin` runs on the message before it is framed, so a stamped
        // Username/Password reaches the wire — the callback's whole purpose.
        // A reset the store owes is declared like a configured one, so the
        // counterparty restarts the sequence with us instead of reading our
        // MsgSeqNum 1 as too low.
        //
        // With NextExpectedMsgSeqNum (789) on, the Logon declares the next
        // number expected from the acceptor: the seeded target counter, which
        // is 1 when the Logon declares a reset.
        let logon_seq = runtime.sequences.next_sender_seq().value();
        // The effective startup target, the baseline of the mismatch report
        // (ADR-0015): the number the ack is expected to carry.
        let startup_target = runtime.sequences.next_target_seq().value();
        let next_expected = declared_next_expected(&self.config, &runtime.sequences);
        let logon = factory.logon(
            self.config.heartbeat_interval_secs(),
            reset_logon,
            next_expected,
        );
        if let Err(err) = send_handshake_admin(
            self.application.as_ref(),
            &session_id,
            &mut framed,
            &mut factory,
            &runtime.sequences,
            store.as_mut(),
            write_timeout,
            self.capture(&session_id).as_ref(),
            logon,
        )
        .await
        {
            let _ = session.disconnect();
            return Err(err);
        }
        let logon_sent_at = crate::reactor::driver_now();
        lock_heartbeat(&runtime).on_message_sent(logon_sent_at);
        let session = session.send_logon(logon_sent_at);

        // Await the Logon acknowledgement. Garbled frames are skipped, and the
        // logon timeout covers the whole wait, so an ack that never arrives
        // intact is a LogonTimeout.
        // The wait runs from the instant the Logon was sent, the typestate's
        // `sent_at` (the sans-IO core's logon deadline, issue #91 stage 5).
        let ack = match read_handshake_frame(
            &mut framed,
            logon_ack_deadline(&session, self.config.logon_timeout),
            &session_id,
            self.capture(&session_id).as_ref(),
        )
        .await
        {
            HandshakeRead::Frame(frame) => frame,
            HandshakeRead::TimedOut => {
                let _ = session.on_logon_reject();
                return Err(EngineError::LogonTimeout(self.config.logon_timeout));
            }
            HandshakeRead::Closed => {
                let _ = session.on_logon_reject();
                return Err(EngineError::Closed);
            }
            HandshakeRead::Codec(err) => {
                let _ = session.on_logon_reject();
                return Err(err.into());
            }
        };

        // (gap start, high-water) of a gap detected in the Logon ack itself.
        let mut pending_resend: Option<(u64, u64)> = None;
        // (first, first not resent) of what the ack's NextExpectedMsgSeqNum
        // (789) says the acceptor missed.
        let mut opening_replay: Option<(u64, u64)> = None;
        // (gap start, ack MsgSeqNum) of a gapped ack held instead of
        // requested, when both sides declared 789.
        let mut held_logon: Option<(u64, u64)> = None;
        {
            let raw = wire::decode_frame(&ack)?;
            match raw.msg_type() {
                MsgType::Logon => {}
                MsgType::Logout | MsgType::Reject => {
                    let reason = raw
                        .get_field_str(58)
                        .unwrap_or("logon rejected by counterparty")
                        .to_string();
                    let _ = session.on_logon_reject();
                    return Err(EngineError::LogonRejected { reason });
                }
                other => {
                    let msg_type = other.as_str().to_string();
                    let _ = session.on_logon_reject();
                    return Err(EngineError::UnexpectedMessage { msg_type });
                }
            }

            // BeginString before anything else the ack claims: an
            // acknowledgement in a different FIX dialect than this session was
            // configured for is not our acknowledgement, no matter what its
            // CompIDs or MsgSeqNum say. The configured transport BeginString is
            // the value used for outbound framing -- FIXT.1.1 for a 5.0
            // session -- so that, not FIX.5.0*, is what a conforming ack
            // carries. A mismatch aborts the handshake with a typed error
            // rather than taking the session Active under the wrong protocol
            // version.
            match raw.begin_string() {
                Ok(begin_string) if begin_string == version.begin_string() => {}
                Ok(begin_string) => {
                    let received = begin_string.to_string();
                    let _ = session.on_logon_reject();
                    return Err(EngineError::BeginStringMismatch {
                        expected: version.begin_string().to_string(),
                        received,
                    });
                }
                Err(err) => {
                    let _ = session.on_logon_reject();
                    return Err(err.into());
                }
            }

            // Positional: MsgSeqNum (34) must be in the standard header, the
            // same contract the CompID check enforces on 49/56 and the acceptor
            // handshake already applies. A 34 that appears only after the body
            // is treated as a missing header field rather than accepted as the
            // ack sequence number.
            let Some(ack_seq) = wire::header_seq_num(&raw) else {
                let _ = session.on_logon_reject();
                return Err(EngineError::Sequence(
                    "Logon ack has no valid MsgSeqNum (34) in the standard header".to_string(),
                ));
            };

            // Identity before anything else: a cross-wired acceptor must not
            // be allowed to establish a session or move sequence state.
            if let Err(mismatch) = identity.validate(&raw) {
                let detail = mismatch.to_string();
                let reason = RejectReason::new(9, detail.clone()).with_ref_tag(mismatch.tag);
                let reject = factory.session_reject(ack_seq, MsgType::Logon.as_str(), &reason);
                let logout = factory.logout(Some(&detail));
                let refused = refuse_handshake(
                    self.application.as_ref(),
                    &session_id,
                    &mut framed,
                    &mut factory,
                    &runtime.sequences,
                    store.as_mut(),
                    write_timeout,
                    self.capture(&session_id).as_ref(),
                    &detail,
                    [reject, logout],
                )
                .await;
                let _ = session.on_logon_reject();
                refused?;
                return Err(EngineError::IdentityMismatch { detail });
            }

            // The clock is checked on the ack for the same reason it is checked
            // on every later frame: a peer whose SendingTime is wildly skewed
            // cannot be trusted to sequence a session, and the handshake is the
            // cheapest place to refuse it.
            if let Err(problem) = sending_time.validate(&raw, wire::wall_clock_millis()) {
                let detail = problem.to_string();
                let reason = problem.reject_reason();
                let reject = factory.session_reject(ack_seq, MsgType::Logon.as_str(), &reason);
                let logout = factory.logout(Some(&detail));
                let refused = refuse_handshake(
                    self.application.as_ref(),
                    &session_id,
                    &mut framed,
                    &mut factory,
                    &runtime.sequences,
                    store.as_mut(),
                    write_timeout,
                    self.capture(&session_id).as_ref(),
                    &detail,
                    [reject, logout],
                )
                .await;
                let _ = session.on_logon_reject();
                refused?;
                return Err(EngineError::SendingTime { detail });
            }

            if let Err(reason) = self.application.from_admin(&raw, &session_id).await {
                let logout = factory.logout(Some(&reason.text));
                let refused = refuse_handshake(
                    self.application.as_ref(),
                    &session_id,
                    &mut framed,
                    &mut factory,
                    &runtime.sequences,
                    store.as_mut(),
                    write_timeout,
                    self.capture(&session_id).as_ref(),
                    &reason.text,
                    [logout],
                )
                .await;
                let _ = session.on_logon_reject();
                refused?;
                return Err(EngineError::LogonRejected {
                    reason: reason.text,
                });
            }

            // The ack is accepted: compare its numbers with the state this
            // session started from, and report a disagreement before the
            // engine acts on it (issue #80, ADR-0015). Not for an exchange
            // that carries 141=Y in either direction, and it moves nothing.
            // A malformed 789 counts as not declared here; it is refused
            // below as before.
            if mismatch_report_applies(reset_logon, raw.get_field_str(141) == Some("Y")) {
                let peer_next_expected = if self.config.send_next_expected_msg_seq_num {
                    next_expected::read_next_expected(&raw)
                        .ok()
                        .flatten()
                        .map(NonZeroU64::get)
                } else {
                    None
                };
                let counters = LogonCounters::initiator(
                    logon_seq,
                    startup_target,
                    runtime.sequences.next_sender_seq().value(),
                );
                if let Some(mismatch) = SequenceMismatch::compare(
                    (counters.next_sender, counters.next_target),
                    stored,
                    ack_seq,
                    peer_next_expected,
                    counters.next_outbound,
                ) {
                    self.application
                        .on_sequence_mismatch(&session_id, &mismatch)
                        .await;
                }
            }

            // DefaultApplVerID (1137) on the ack: on a FIXT.1.1 session, a
            // 1137 the acceptor declares must name, once, an application
            // version this session accepts. By default an ack without 1137
            // is accepted (issue #67: "when present"); its application
            // messages without ApplVerID (1128) then count as this session's
            // own version. In strict mode
            // (`require_ack_default_appl_ver_id`) a missing 1137 is refused.
            // Refused like the ack's other field problems: a Reject
            // (reason 18; 13 for a repeated 1137; 1 for a missing one in
            // strict mode; RefTagID 1137) and a Logout.
            match appl_version.check_logon(
                &raw,
                default_appl_ver_id_required(
                    LogonRole::Initiator,
                    self.config.require_ack_default_appl_ver_id,
                ),
            ) {
                Ok(Some(declared)) => {
                    tracing::debug!(
                        session = %session_id,
                        default_appl_version = %declared,
                        "counterparty declared its default application version"
                    );
                    runtime.record_counterparty_default_appl_version(declared);
                }
                Ok(None) => {}
                Err(problem) => {
                    let detail = problem.to_string();
                    let reason = problem.reject_reason();
                    let reject = factory.session_reject(ack_seq, MsgType::Logon.as_str(), &reason);
                    let logout = factory.logout(Some(&detail));
                    let refused = refuse_handshake(
                        self.application.as_ref(),
                        &session_id,
                        &mut framed,
                        &mut factory,
                        &runtime.sequences,
                        store.as_mut(),
                        write_timeout,
                        self.capture(&session_id).as_ref(),
                        &detail,
                        [reject, logout],
                    )
                    .await;
                    let _ = session.on_logon_reject();
                    refused?;
                    return Err(EngineError::ApplVersion { detail });
                }
            }

            // EncryptMethod (98) is a required field of the Logon, and IronFix
            // implements no encryption: an acknowledgement without it, or
            // naming another method, is refused with a session Reject
            // (RefTagID 98) and a Logout, as the acceptor refuses a Logon.
            if let Err(problem) = check_encrypt_method(&raw) {
                let detail = problem.to_string();
                let reason = RejectReason::new(problem.reject_code(), detail.clone())
                    .with_ref_tag(problem.ref_tag());
                let reject = factory.session_reject(ack_seq, MsgType::Logon.as_str(), &reason);
                let logout = factory.logout(Some(&detail));
                let refused = refuse_handshake(
                    self.application.as_ref(),
                    &session_id,
                    &mut framed,
                    &mut factory,
                    &runtime.sequences,
                    store.as_mut(),
                    write_timeout,
                    self.capture(&session_id).as_ref(),
                    &detail,
                    [reject, logout],
                )
                .await;
                let _ = session.on_logon_reject();
                refused?;
                return Err(EngineError::LogonRejected { reason: detail });
            }

            // Honor the heartbeat interval confirmed by the counterparty, but
            // only within the bound `negotiate_interval` enforces: 108 is
            // counterparty-controlled and drives every liveness timer in the
            // session. Resolved before the lock is taken, because refusing it
            // has to send a Reject and a Logout.
            //
            // HeartBtInt (108) is a *required* field of the Logon
            // (`doc/fix_operations.md`, "Logon"). An ack that omits it or
            // carries a non-numeric value gives the two sides nothing to agree
            // liveness timing on, so the handshake fails rather than silently
            // establishing the session on the locally configured interval.
            let secs: u64 = match raw.get_field_as::<u64>(108) {
                Ok(secs) => secs,
                Err(err) => {
                    // SessionRejectReason 1 (Required tag missing) for an
                    // absent 108, 6 (Incorrect data format for value) for a
                    // present-but-unparseable one.
                    let (defect, detail) =
                        if matches!(err, DecodeError::MissingRequiredField { .. }) {
                            (
                                AckHeartBtIntDefect::Missing,
                                "Logon acknowledgement omitted the required HeartBtInt (108)"
                                    .to_string(),
                            )
                        } else {
                            (AckHeartBtIntDefect::Malformed, err.to_string())
                        };
                    let reason = RejectReason::new(defect.session_reject_reason(), detail.clone())
                        .with_ref_tag(108);
                    let reject = factory.session_reject(ack_seq, MsgType::Logon.as_str(), &reason);
                    let logout = factory.logout(Some(&detail));
                    let refused = refuse_handshake(
                        self.application.as_ref(),
                        &session_id,
                        &mut framed,
                        &mut factory,
                        &runtime.sequences,
                        store.as_mut(),
                        write_timeout,
                        self.capture(&session_id).as_ref(),
                        &detail,
                        [reject, logout],
                    )
                    .await;
                    let _ = session.on_logon_reject();
                    refused?;
                    return Err(EngineError::HeartbeatInterval { detail });
                }
            };
            let negotiated = match negotiate_logon_interval(
                LogonRole::Initiator,
                self.config.heartbeat_interval,
                secs,
            ) {
                Ok(interval) => interval,
                Err(err) => {
                    let detail = err.to_string();
                    let reason = RejectReason::new(
                        AckHeartBtIntDefect::OutOfRange.session_reject_reason(),
                        detail.clone(),
                    )
                    .with_ref_tag(108);
                    let reject = factory.session_reject(ack_seq, MsgType::Logon.as_str(), &reason);
                    let logout = factory.logout(Some(&detail));
                    let refused = refuse_handshake(
                        self.application.as_ref(),
                        &session_id,
                        &mut framed,
                        &mut factory,
                        &runtime.sequences,
                        store.as_mut(),
                        write_timeout,
                        self.capture(&session_id).as_ref(),
                        &detail,
                        [reject, logout],
                    )
                    .await;
                    let _ = session.on_logon_reject();
                    refused?;
                    return Err(EngineError::HeartbeatInterval { detail });
                }
            };
            {
                let mut heartbeat = lock_heartbeat(&runtime);
                let now = crate::reactor::driver_now();
                heartbeat.on_message_received(false, None, now);
                if let Some(interval) = interval_change(heartbeat.interval(), negotiated) {
                    tracing::info!(
                        session = %session_id,
                        heartbeat_secs = interval.as_secs(),
                        "using heartbeat interval confirmed by counterparty"
                    );
                    *heartbeat = HeartbeatManager::new(interval, now);
                }
            }

            // ResetSeqNumFlag (141) on the ack is a counterparty-driven
            // reset and must be honored before MsgSeqNum is validated,
            // otherwise the ack's 34=1 reads as fatally too low against
            // continuity-seeded counters.
            let ack_resets = raw.get_field_str(141) == Some("Y");
            // FIX requires MsgSeqNum = 1 on a Logon carrying ResetSeqNumFlag =
            // Y: the reset and the number it arrives under have to agree. A
            // peer that declares a reset and then numbers the message anything
            // else is describing two different streams, so the handshake fails
            // rather than guessing which half to believe.
            if reset_flag_contradicts(ack_resets, ack_seq) {
                let _ = session.on_logon_reject();
                return Err(EngineError::Sequence(format!(
                    "Logon ack set ResetSeqNumFlag=Y but carried MsgSeqNum {ack_seq}, not 1"
                )));
            }

            // NextExpectedMsgSeqNum (789), when this session uses it: the
            // next number the acceptor expects from us, computed once it had
            // our Logon. Compared with the counters the ack's own reset sets,
            // if it declares one (our Logon is then message 1 of the new
            // stream, and 2 goes next), and decided before that reset is made,
            // so a refused ack never resets the store. A value above the next
            // number we send claims messages never sent: Logout, and no
            // session. A value below our Logon names messages the acceptor
            // missed: resent once Active. 789 moves no counter.
            let mut ack_declares_789 = false;
            if self.config.send_next_expected_msg_seq_num {
                let basis = NextExpectedBasis::initiator(
                    ack_resets,
                    logon_seq,
                    runtime.sequences.next_sender_seq().value(),
                );
                let declared = next_expected::read_next_expected(&raw);
                ack_declares_789 = matches!(declared, Ok(Some(_)));
                // A reset this side declared that the ack does not echo: under
                // the reset rule the ack is the acceptor's message 1 whatever
                // its number, and its 789 may describe the stream the reset
                // discards, so a well-formed value is ignored, as the acceptor
                // ignores the Logon's 789 for a reset it drives alone. A
                // malformed value is still refused, and an ack that echoes 141
                // knew of the reset, so its 789 is still checked.
                let declared = declared.map(|declared| {
                    match screen_next_expected(declared, reset_logon, ack_resets) {
                        // 2 is what an acceptor that took our Logon as message
                        // 1 of a new stream expects. Anything else says it kept
                        // its old stream: it will read our next message (2) as
                        // too low.
                        ScreenedNextExpected::Ignored {
                            declared,
                            matches_reset: true,
                        } => {
                            tracing::debug!(
                                session = %session_id,
                                declared = declared.get(),
                                "ignoring the Logon ack's NextExpectedMsgSeqNum: it does not \
                                 echo the sequence reset this session declared"
                            );
                            None
                        }
                        ScreenedNextExpected::Ignored {
                            declared,
                            matches_reset: false,
                        } => {
                            tracing::warn!(
                                session = %session_id,
                                declared = declared.get(),
                                "the Logon ack does not echo the sequence reset this session \
                                 declared and its NextExpectedMsgSeqNum is not 2: the acceptor \
                                 likely kept its old stream and will refuse this session's next \
                                 message (MsgSeqNum 2) as too low"
                            );
                            None
                        }
                        screened => screened.usable(),
                    }
                });
                let decided = declared.and_then(|declared| {
                    declared
                        .map(|declared| next_expected::plan_basis(declared, basis))
                        .transpose()
                });
                match decided {
                    Ok(plan) => opening_replay = plan.and_then(NextExpectedPlan::replay_range),
                    Err(problem) => {
                        let detail = problem.to_string();
                        tracing::warn!(
                            session = %session_id,
                            detail = %detail,
                            "refusing the Logon ack's NextExpectedMsgSeqNum"
                        );
                        let logout = factory.logout(Some(&detail));
                        // A malformed 789 is Rejected like the ack's other
                        // malformed fields; one above what was sent gets the
                        // Logout alone.
                        let refused = match problem.reject_reason() {
                            Some(reason) => {
                                let reject = factory.session_reject(
                                    ack_seq,
                                    MsgType::Logon.as_str(),
                                    &reason,
                                );
                                refuse_handshake(
                                    self.application.as_ref(),
                                    &session_id,
                                    &mut framed,
                                    &mut factory,
                                    &runtime.sequences,
                                    store.as_mut(),
                                    write_timeout,
                                    self.capture(&session_id).as_ref(),
                                    &detail,
                                    [reject, logout],
                                )
                                .await
                            }
                            None => {
                                refuse_handshake(
                                    self.application.as_ref(),
                                    &session_id,
                                    &mut framed,
                                    &mut factory,
                                    &runtime.sequences,
                                    store.as_mut(),
                                    write_timeout,
                                    self.capture(&session_id).as_ref(),
                                    &detail,
                                    [logout],
                                )
                                .await
                            }
                        };
                        let _ = session.on_logon_reject();
                        refused?;
                        return Err(EngineError::NextExpectedMsgSeqNum { detail });
                    }
                }
            }

            let ack_reset = decide_ack_reset(reset_logon, ack_resets);
            if !matches!(ack_reset, AckReset::None) {
                tracing::info!(
                    session = %session_id,
                    "counterparty set ResetSeqNumFlag on the Logon ack: resetting sequence numbers"
                );
                // Our Logon did not ask for the reset, so the store still holds
                // the previous stream and its counters. It is reset now and set
                // to the new stream's counters (our Logon and this ack are each
                // side's message 1), in one call, before the session goes
                // Active and before `on_logon`: a connect that fails from here
                // on must not leave a store that a later session would replay
                // the previous stream's frames from into this one.
                //
                // A failure refuses the session whatever the policy, as the
                // other resets do: carrying on would let a resend in the new
                // stream replay the previous stream's frames under the numbers
                // the new one uses. The reset is then owed, so the next connect
                // makes it and declares ResetSeqNumFlag itself.
                if matches!(ack_reset, AckReset::Adopt)
                    && let Some(handshake) = store.as_mut()
                {
                    // Owed before the call and paid only once it has
                    // succeeded: a caller that drops this connect while the
                    // reset is pending runs no error branch, and the next
                    // connect must still make the reset and declare it.
                    // The intent is durable before the reset is made: a crash
                    // before the reset lands, or before the marker is cleared,
                    // makes the next session reset and declare it.
                    let ticket = match self.store.owe_durably(&session_id, write_timeout).await {
                        Ok(ticket) => ticket,
                        Err(err) => {
                            let _ = session.on_logon_reject();
                            return Err(err.into());
                        }
                    };
                    if let Err(err) = handshake
                        .reset_to(
                            &session_id,
                            ADOPTED_RESET_NEXT_SENDER,
                            ADOPTED_RESET_STORED_TARGET,
                        )
                        .await
                    {
                        let _ = session.on_logon_reject();
                        return Err(err.into());
                    }
                    self.store.reset_paid(ticket);
                }
                runtime.sequences.set_target_seq(ADOPTED_RESET_NEXT_TARGET);
                // The Logon already on the wire is message 1 of the reset
                // outbound stream; rewinding the sender counter to 1 would
                // re-emit a MsgSeqNum the counterparty has already seen.
                runtime.sequences.set_sender_seq(ADOPTED_RESET_NEXT_SENDER);
            }

            // The reset rule both roles share: in a Logon exchange that resets
            // the sequence, each side's Logon or acknowledgement is message 1
            // of its new stream. A reset this side declared therefore takes the
            // ack as the counterparty's message 1 whatever positive MsgSeqNum it
            // carries, and expects 2 next; an ack that declares a reset itself
            // was held to 34=1 above. 0 names no message, so an ack numbered 0
            // is validated as usual and refused as too low.
            match classify_logon_seq(reset_logon, ack_seq, &runtime.sequences) {
                SequenceResult::Ok => {
                    // The receive cursor includes the ack before the session
                    // goes Active on it and before the in-memory expectation
                    // moves, as for every later inbound message.
                    if let Some(handshake) = store.as_mut() {
                        let expected = runtime.sequences.next_target_seq().value();
                        let Some(next) = expected.checked_add(1) else {
                            let _ = session.on_logon_reject();
                            return Err(SequenceExhausted {
                                counter: SequenceCounter::Target,
                            }
                            .into());
                        };
                        if let Err(err) = handshake.persist_target(&session_id, next).await {
                            let _ = session.on_logon_reject();
                            return Err(err.into());
                        }
                    }
                    if let Err(err) = runtime.sequences.try_increment_target_seq() {
                        let _ = session.on_logon_reject();
                        return Err(err.into());
                    }
                }
                SequenceResult::TooLow { expected, received } => {
                    let _ = session.on_logon_reject();
                    return Err(EngineError::Sequence(format!(
                        "logon ack MsgSeqNum too low: expected {expected}, received {received}"
                    )));
                }
                // Both sides declared 789: our Logon named `expected` as the
                // next number we expect, so the acceptor resends the gap below
                // its ack on its own. The ack is held, its number consumed
                // once that gap is filled, and no ResendRequest crosses the
                // resend (QuickFIX/C++ does the same). Otherwise the gap is
                // requested as the reactor's first act.
                SequenceResult::Gap { expected, received } => match decide_logon_gap(
                    self.config.send_next_expected_msg_seq_num,
                    ack_declares_789,
                ) {
                    LogonGapAction::Hold => held_logon = Some((expected, received)),
                    LogonGapAction::Request => pending_resend = Some((expected, received)),
                },
            }
        }

        // The Logon that declared the reset has been acknowledged: that reset
        // is paid, and the store's durable marker is cleared unless something
        // is still owed. A store write that failed during this handshake was
        // owed after the ticket was taken, and stays owed.
        if let Err(err) = self
            .store
            .settle(&session_id, reset_ticket, write_timeout)
            .await
        {
            let _ = session.on_logon_reject();
            return Err(err.into());
        }

        // Typestate: LogonSent -> Active.
        let session = session.on_logon_ack();
        self.application.on_logon(&session_id).await;
        tracing::info!(session = %session_id, "FIX session established");

        // Hand the framed socket to the shared reactor. The initiator carries no
        // admission guard, so the guard is `()`. A gap in the Logon ack is
        // requested by the reactor as its first act, so that once `on_logon`
        // has run, a failure to send the request closes the session through
        // the reactor's close path (`on_logout`, the close-time reset, the
        // counters) like any other.
        let params = SessionParams {
            framed,
            session,
            runtime: Arc::clone(&runtime),
            factory,
            identity,
            sending_time,
            appl_version,
            config: self.config.clone(),
            application: Arc::clone(&self.application),
            session_id: session_id.clone(),
            store: self.store.store().cloned(),
            store_policy: self.store.policy(),
            store_timeout,
            persisted: store
                .map_or_else(PersistedCounters::default, |handshake| handshake.persisted),
            reset_owed: self.store.owed_record(),
            opening_gap: pending_resend,
            opening_replay,
            held_logon,
            write_timeout,
            outbound_capacity: self.outbound_capacity,
            app_queue_capacity: self.app_queue_capacity,
            throttle: self.throttle.clone(),
            capture: self.capture(&session_id),
            validation: self.validation.clone(),
        };
        let (command_tx, closed_rx) = spawn_session(params, ());

        Ok(Connection {
            session_id,
            commands: command_tx,
            closed: closed_rx,
            runtime,
            pool: OutboundPool::new(self.outbound_capacity),
        })
    }
}
