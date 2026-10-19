/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 22/7/26
******************************************************************************/

//! Server-side (acceptor) FIX engine: inbound connections, framing, and the
//! acceptor half of the Logon handshake.
//!
//! [`Acceptor::serve`] takes an already-accepted [`TcpStream`], frames it with
//! [`ironfix_transport::FixCodec`], drives the [`ironfix_session`] typestate
//! machine through `accept() -> on_logon_received() -> accept_logon()`, and
//! hands the socket to the same background session reactor the
//! [`Initiator`](crate::Initiator) uses (see `crate::reactor`). The returned
//! [`Connection`] handle is the outbound message sink and exposes
//! `wait_closed()` / `is_timed_out()`. [`Acceptor::accept`] is the convenience
//! wrapper that pulls the next connection off a [`TcpListener`] and hands it to
//! `serve`. [`Acceptor::serve_stream`] runs the same handshake on a stream the
//! caller has already accepted, of any type that is `AsyncRead + AsyncWrite +
//! Unpin + Send + 'static` (a TLS stream, a Unix socket, an in-memory
//! [`tokio::io::duplex`] pipe); `serve` is `TCP_NODELAY` followed by exactly
//! that handshake.
//!
//! The accept loop and its supervision are the consumer's, exactly as
//! reconnection is the consumer's for the initiator: an `Acceptor` is a single
//! configured session (one expected counterparty), and each accepted
//! connection becomes its own live session with its own sequence state. A
//! server that fronts several counterparties on one listener registers one
//! `Acceptor` per counterparty in an
//! [`AcceptorRegistry`](crate::AcceptorRegistry), which reads each inbound
//! Logon once, routes it by the CompIDs it claims, and runs the routed
//! `Acceptor`'s handshake on it, the same handshake `serve` runs.
//!
//! # Handshake conformance
//!
//! The inbound Logon is validated in the order set out in
//! `doc/fix_operations.md` ("Logon"): it must decode and be a Logon; its
//! `BeginString` (8) must match this session's version and its `EncryptMethod`
//! (98) must be 0 (None); it must carry `MsgSeqNum` (34) **in the standard
//! header**; then counterparty identity (49/56, plus 50/57 and 142/143 when
//! configured) is checked and the single admission slot is claimed — a second concurrent Logon
//! for the same counterparty is refused rather than allowed to fork the session;
//! then `SendingTime` (52) accuracy and the `from_admin` authentication hook;
//! then, on a FIX 5.0 session (framed as FIXT.1.1), the Logon must declare
//! once, in `DefaultApplVerID` (1137), an application version the session
//! accepts ([`SessionConfig::accepts_appl_version`]);
//! then a `ResetSeqNumFlag` (141) Logon must carry `MsgSeqNum` 1; then the
//! `HeartBtInt` (108) the initiator requested is bounded; then, with
//! [`SessionConfig::send_next_expected_msg_seq_num`] set, the Logon's
//! `NextExpectedMsgSeqNum` (789) is read, and must be 1 on a 141 Logon; only
//! then is an attached store reset (for 141, the local `reset_on_logon`, or an
//! owed reset) or refreshed; then 789 is compared with the number the ack will
//! take (above it, the initiator claims messages never sent; below it, the
//! missed range is resent, up to but not including the ack, once Active); and
//! finally `MsgSeqNum` is validated and the ack, mirroring 141, echoing 108 and
//! declaring its own 789 when the flag is set, is sent. Waiting for the inbound Logon is
//! bounded by [`SessionConfig::logon_timeout`]; a garbled frame that arrives
//! first (a bad CheckSum or BodyLength, bytes before `8=`, or a frame whose
//! MsgType (35) is not third) is skipped and the wait goes on against the same
//! timeout. So is a frame whose header decodes but whose body does not: it is
//! not garbled, but it cannot be read as a Logon either. A Logon that never
//! arrives intact ends in [`EngineError::LogonTimeout`]. A gap in the Logon
//! completes the handshake and immediately issues a `ResendRequest` (2),
//! unless both sides declared `NextExpectedMsgSeqNum` (789): the initiator then
//! resends the gap on its own, so the Logon is held and its number consumed
//! once the gap is filled. One `ResendRequest` goes out only when the gap
//! makes no progress for [`SessionConfig::resend_timeout`], a resend that
//! stalls partway included.
//!
//! A refused Logon drives the typestate to `reject_logon` and the connection
//! is dropped without reaching Active. What the peer is sent first depends on
//! who it is:
//!
//! - **An unauthenticated peer** (wrong version or encryption, wrong CompIDs,
//!   a `SendingTime` out of tolerance, credentials that `from_admin`
//!   refuses): with a store attached, nothing, and the store is not touched;
//!   without one, a Reject (reason 9 for identity, 10 for the clock) and/or a
//!   Logout as before. Matching CompIDs authenticate nobody: they are
//!   caller-supplied, so a peer that knows them but not the credentials must
//!   not be able to write to the journal or move the session's counters.
//!   While this session is live, a Logon refused for its version, encryption
//!   or CompIDs gets nothing in either mode, as a duplicate does: anything it
//!   could be sent would be numbered from a stream the live session owns.
//! - **A Logon without a valid `MsgSeqNum`** (absent, outside the header, or
//!   0): nothing, in either mode.
//! - **A duplicate Logon** for a session already live: nothing, in either
//!   mode. The live session owns the sequence stream.
//! - **An authenticated peer** (`from_admin` accepted it) refused by its
//!   `DefaultApplVerID` (1137: missing, repeated, not a code, or not accepted),
//!   a 141 Logon not numbered 1, its `HeartBtInt`, its
//!   `NextExpectedMsgSeqNum` (789, when used: malformed, or above what was
//!   sent), or a `MsgSeqNum` too low: a
//!   Logout carrying the reason, sent like every session frame, numbered from
//!   the store's refreshed counters (or the seed) and filed when a store is
//!   attached. Such a refusal never resets the store.
//!
//! `HeartBtInt` (108) is counterparty-controlled and drives a `Duration` on the
//! heartbeat clock, so it is bounded at the handshake: a value large enough to
//! overflow `interval + grace` would otherwise abort the process under
//! `panic = "abort"`. `ResetSeqNumFlag` (141) is reconciled coherently — the
//! acceptor resets when the peer asks *or* when it is locally configured to, and
//! whichever drives the reset the ack carries `141=Y` so the peer resets in
//! lockstep instead of silently desyncing.
//!
//! The reset rule is the one both roles share: in a Logon exchange that resets
//! the sequence, each side's Logon or acknowledgement is message 1 of its new
//! stream. After a reset the acceptor's ack goes out at 1 and 2 is expected
//! next from the peer, whatever `MsgSeqNum` its Logon carried: a peer that did
//! not ask for the reset is told to make it by the ack's `141=Y`, and no gap is
//! opened for the numbers of its old stream.
//!
//! Every handshake frame goes through the same peek-then-spend path the reactor
//! uses (`send_handshake_admin`): the `to_admin` callback runs
//! on the message before it is framed, the body is re-checked, and the sender
//! sequence number is spent only once the frame has been built. Once the session
//! is Active the shared session reactor runs identically for both roles.
//!
//! # Resend and the message store
//!
//! [`Acceptor::with_store`] attaches a [`MessageStore`], with the same contract
//! as [`Initiator::with_store`](crate::Initiator::with_store): every sequenced
//! outbound frame, the Logon acknowledgement included, is filed under its
//! `MsgSeqNum` and the next sender number persisted before the frame is
//! written; the next target number is persisted before an inbound message is
//! acted on; and an inbound `ResendRequest` replays the stored application
//! messages with `PossDupFlag` (43) = Y and their original `SendingTime` in
//! `OrigSendingTime` (122), gap-filling administrative messages and anything
//! the store cannot produce. A session starts from the store's counters unless
//! it starts a new stream (`ResetSeqNumFlag` (141) on the Logon,
//! `reset_on_logon`, or a reset owed by an earlier session), in which case the
//! store is reset before the acknowledgement is filed. See the
//! [`persistence`](crate::persistence) module for the write order and
//! [`StoreFailurePolicy`] for what a failed write means.
//!
//! **Nothing reaches the store before the peer is authenticated.** The
//! version, encryption, `MsgSeqNum`, identity, admission, `SendingTime` and
//! `from_admin` checks all come first, so an unauthenticated peer or a
//! duplicate Logon never touches the store. A refusal after authentication is
//! numbered from a refresh of the store and filed, and only a Logon that passes
//! every check can reset the store, so a refused `141=Y` Logon cannot clear the
//! outbound journal.
//!
//! All sequence arithmetic goes through the checked
//! [`SequenceManager::try_allocate_sender_seq`](ironfix_session::SequenceManager::try_allocate_sender_seq) /
//! [`SequenceManager::try_increment_target_seq`](ironfix_session::SequenceManager::try_increment_target_seq);
//! an exhausted counter refuses the session rather than wrapping.
//!
//! # Example
//!
//! ```no_run
//! use ironfix_core::types::CompId;
//! use ironfix_engine::application::NoOpApplication;
//! use ironfix_engine::Acceptor;
//! use ironfix_session::SessionConfig;
//! use std::sync::Arc;
//! use tokio::net::TcpListener;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! // Sender is the acceptor itself; target is the initiator it expects.
//! let config = SessionConfig::new(
//!     CompId::new("VENUE").unwrap(),
//!     CompId::new("CLIENT").unwrap(),
//!     "FIX.4.4",
//! );
//! let acceptor = Arc::new(Acceptor::new(config, Arc::new(NoOpApplication)));
//! let listener = TcpListener::bind("127.0.0.1:9876").await?;
//!
//! loop {
//!     let (stream, _) = listener.accept().await?;
//!     let acceptor = Arc::clone(&acceptor);
//!     tokio::spawn(async move {
//!         if let Ok(connection) = acceptor.serve(stream).await {
//!             connection.wait_closed().await;
//!         }
//!     });
//! }
//! # }
//! ```

use crate::application::{Application, NoOpApplication, RejectReason, SessionId};
use crate::connection::{Connection, SessionRuntime, report_handshake};
use crate::error::EngineError;
use crate::next_expected;
use crate::observer::{Capture, FrameKind, FrameObserver};
use crate::persistence::{
    PersistedCounters, SeedPlan, Seeded, StoreAttachment, StoreFailurePolicy, seed_session,
    seeded_counters,
};
use crate::reactor::{
    DEFAULT_APP_QUEUE_CAPACITY, DEFAULT_OUTBOUND_CAPACITY, DEFAULT_WRITE_TIMEOUT, FixFramed,
    HandshakeRead, SessionParams, TICK_INTERVAL, lock_heartbeat, read_handshake_frame,
    refuse_handshake, send_handshake_admin, session_codec, spawn_session,
};
use crate::stream::SessionStream;
use crate::throttle::ThrottleConfig;
use crate::wire::{
    self, ApplVersionGuard, MessageFactory, PeerIdentity, PendingMessage, SendingTimeGuard,
    UnsupportedVersion,
};
use bytes::BytesMut;
use ironfix_core::message::MsgType;
use ironfix_core::version::FixVersion;
use ironfix_session::config::SessionConfigError;
use ironfix_session::sequence::{SequenceCounter, SequenceExhausted, SequenceResult};
use ironfix_session::{
    Connecting, Disconnected, HeartbeatManager, SequenceManager, Session, SessionConfig,
};
use ironfix_store::MessageStore;
use ironfix_transport::CodecError;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

/// RAII claim on the one live session an [`Acceptor`] admits at a time for a
/// given configured counterparty.
///
/// An `Acceptor` is a single configured session (one expected initiator), so
/// two connections that both pass the handshake would otherwise each build an
/// independent [`SequenceManager`] and both reach Active at sequence 1,
/// silently forking the session. The guard is claimed once the inbound Logon's
/// identity is validated and is then moved into the reactor task, so it is held
/// for the whole life of the session and released on **every** close path when
/// the reactor task ends — after which the counterparty may reconnect.
struct AdmissionGuard {
    /// The set of currently-admitted sessions, shared with the [`Acceptor`].
    admitted: Arc<Mutex<HashSet<SessionId>>>,
    /// The session this guard admitted.
    session_id: SessionId,
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        // A poisoned lock means a previous holder panicked; the admission set is
        // a plain set of identifiers with no invariant a panic could leave
        // half-applied, so the guard is recovered rather than propagated. Under
        // `panic = "abort"` refusing to free the slot would strand the session
        // forever.
        let mut admitted = self.admitted.lock().unwrap_or_else(PoisonError::into_inner);
        admitted.remove(&self.session_id);
    }
}

/// Server-side FIX engine.
///
/// Owns the session configuration and the [`Application`] callbacks. Each
/// accepted connection ([`Acceptor::accept`] / [`Acceptor::serve`] /
/// [`Acceptor::serve_stream`]) establishes one live session and returns a
/// [`Connection`] handle for it. Cloning the application is cheap, so an
/// `Acceptor` is typically wrapped in an [`Arc`] and shared across the tasks
/// serving each connection.
///
/// The configuration is stated from the acceptor's point of view: its
/// `sender_comp_id` is the acceptor's own CompID and its `target_comp_id` is
/// the initiator it expects — the reverse of what the peer stamps on the wire,
/// which is exactly what the inbound-identity check validates against.
pub struct Acceptor<A: Application = NoOpApplication> {
    /// Session configuration.
    config: SessionConfig,
    /// Application callbacks.
    application: Arc<A>,
    /// Session identifier derived from the configuration.
    session_id: SessionId,
    /// The configured FIX version, or why it cannot be framed. Resolved once
    /// at construction and reported before the handshake begins.
    version: Result<FixVersion, UnsupportedVersion>,
    /// Whether the configuration is usable. Resolved once at construction and
    /// reported before a connection is taken or a handshake run, so a knob
    /// that would corrupt the session's own messages never reaches a socket.
    config_check: Result<(), SessionConfigError>,
    /// Initial (sender, target) sequence numbers for session continuity.
    initial_sequences: Option<(u64, u64)>,
    /// Capacity of the outbound command queue.
    outbound_capacity: usize,
    /// The write timeout: bound on a handshake write, and on how long an
    /// established session's output may make no progress.
    write_timeout: Duration,
    /// Capacity of each session's inbound application queue.
    app_queue_capacity: usize,
    /// The optional message store, its failure policy, its call timeout and
    /// the owed-reset record, shared by every session this acceptor admits,
    /// one at a time.
    store: StoreAttachment,
    /// Sessions currently live on this acceptor, one entry per admitted
    /// counterparty. Shared across every [`Acceptor::serve`] call so a second
    /// concurrent Logon for a session already established is refused rather than
    /// forking it. See [`AdmissionGuard`].
    admitted: Arc<Mutex<HashSet<SessionId>>>,
    /// The outbound throttle each admitted session gets its own budgets
    /// from, if any.
    throttle: Option<ThrottleConfig>,
    /// The frame observer every session of this engine reports to, if any.
    observer: Option<Arc<dyn FrameObserver>>,
}

/// Written by hand rather than derived: `dyn MessageStore` is not `Debug`, and
/// requiring it of every implementation to print one field is the wrong trade.
impl<A: Application> std::fmt::Debug for Acceptor<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Acceptor")
            .field("config", &self.config)
            .field("session_id", &self.session_id)
            .field("version", &self.version)
            .field("config_check", &self.config_check)
            .field("initial_sequences", &self.initial_sequences)
            .field("outbound_capacity", &self.outbound_capacity)
            .field("write_timeout", &self.write_timeout)
            .field("app_queue_capacity", &self.app_queue_capacity)
            .field("store", &self.store)
            .field("store_timeout", &self.store.timeout(self.write_timeout))
            .field("throttle", &self.throttle)
            .field("frame_observer", &self.observer.is_some())
            .finish_non_exhaustive()
    }
}

impl<A: Application + 'static> Acceptor<A> {
    /// Creates a new acceptor.
    ///
    /// The configuration is validated here and the verdict is reported by
    /// [`Acceptor::accept`] and [`Acceptor::serve`], which refuse to take a
    /// connection or run a handshake with an unusable one. Building it through
    /// [`ironfix_session::SessionConfigBuilder`] surfaces the same errors
    /// earlier.
    ///
    /// # Arguments
    /// * `config` - The session configuration (sender = this acceptor's CompID,
    ///   target = the initiator it expects)
    /// * `application` - The application callback handler
    #[must_use]
    pub fn new(config: SessionConfig, application: Arc<A>) -> Self {
        let session_id = wire::session_id_from_config(&config);
        let version = wire::wire_version(&config.begin_string);
        let config_check = config.validate();

        Self {
            config,
            application,
            session_id,
            version,
            config_check,
            initial_sequences: None,
            outbound_capacity: DEFAULT_OUTBOUND_CAPACITY,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            app_queue_capacity: DEFAULT_APP_QUEUE_CAPACITY,
            store: StoreAttachment::default(),
            admitted: Arc::new(Mutex::new(HashSet::new())),
            throttle: None,
            observer: None,
        }
    }

    /// Claims the admission slot for this acceptor's configured session.
    ///
    /// Returns `Some(guard)` when the slot was free — the caller then owns the
    /// only live session for this counterparty until the guard drops — or `None`
    /// when a session is already established, in which case the caller must
    /// refuse the connection. The check and the claim are one atomic step under
    /// the lock, so two concurrent Logons cannot both succeed.
    fn try_admit(&self) -> Option<AdmissionGuard> {
        let mut admitted = self.admitted.lock().unwrap_or_else(PoisonError::into_inner);
        if !admitted.insert(self.session_id.clone()) {
            return None;
        }
        Some(AdmissionGuard {
            admitted: Arc::clone(&self.admitted),
            session_id: self.session_id.clone(),
        })
    }

    /// Whether this acceptor's session is live: its admission slot is held.
    ///
    /// Read without claiming the slot, for a refusal decided before the
    /// claim: while the session is live, nothing an unauthenticated newcomer
    /// could be sent belongs to the sequence stream.
    fn session_is_live(&self) -> bool {
        self.admitted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&self.session_id)
    }

    /// The address of the attached store, if any, so a registry can tell
    /// whether two acceptors share one store. Compared, never dereferenced.
    pub(crate) fn store_address(&self) -> Option<*const ()> {
        self.store
            .store()
            .map(|store| Arc::as_ptr(store).cast::<()>())
    }

    /// Attaches a message store to every session this acceptor admits.
    ///
    /// With a store the acceptor files every sequenced outbound frame under
    /// its `MsgSeqNum`, the Logon acknowledgement included, and on an inbound
    /// `ResendRequest` (35=2) replays the stored **application** messages with
    /// `PossDupFlag` (43) = Y and the original `SendingTime` in
    /// `OrigSendingTime` (122). Administrative messages, and any sequence
    /// number the store cannot produce, are covered by `SequenceReset`-GapFill.
    /// Without a store the engine has nothing to replay and answers the whole
    /// requested range with one gap fill.
    ///
    /// The store also carries sequence numbers: unless the session starts a new
    /// stream (the Logon carries `ResetSeqNumFlag` (141) = Y, `reset_on_logon`
    /// is set, or a reset is owed) or [`Acceptor::with_initial_sequences`] is
    /// called, each session starts from the counters the store reports, and
    /// both counters are persisted back into it as the session runs, in the
    /// order described in the [`persistence`](crate::persistence) module. With
    /// a [`FileStore`](ironfix_store::FileStore) the counters and the filed
    /// frames survive a restart, as durably as its
    /// [`SyncPolicy`](ironfix_store::SyncPolicy) promises; a
    /// [`MemoryStore`](ironfix_store::MemoryStore) holds them in memory only.
    ///
    /// **One store, one engine.** The store must belong to this acceptor alone:
    /// two engines, or two processes, writing to one store would interleave two
    /// sequence streams in it. The record of a reset owed to the next session
    /// is held in memory by the acceptor, not in the store, so a restart
    /// forgets it (#111).
    ///
    /// **Nothing reaches the store before the Logon is authenticated.** A Logon
    /// refused before `from_admin` has accepted it (wrong version, encryption,
    /// `MsgSeqNum`, CompIDs, `SendingTime` or credentials) or for a session
    /// already live gets no reply and never touches the store: matching
    /// CompIDs authenticate nobody. A Logon refused after authentication (a
    /// `DefaultApplVerID` the session does not accept, a malformed
    /// `ResetSeqNumFlag` or `HeartBtInt`, a `MsgSeqNum` too low) is answered
    /// with a filed Logout, numbered from the store's counters, and never
    /// resets the store; see [`Acceptor::serve`].
    ///
    /// **One session at a time.** The admission slot is held until a session's
    /// task has ended: past its close-time store writes, the drain of its
    /// application queue (up to 5 s) and `on_logout`. Two sessions therefore
    /// never write to the store at once, and a Logon that arrives while the
    /// previous session is still closing is refused as a duplicate, without a
    /// reply.
    ///
    /// A failed write to the store is handled by
    /// [`Acceptor::with_store_failure_policy`]; the default carries on with a
    /// warning. Every store call is bounded by
    /// [`Acceptor::with_store_timeout`].
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
    /// [`Acceptor::serve`] return [`EngineError::Store`], and one during the
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
    /// [`Acceptor::with_write_timeout`]).
    ///
    /// The session awaits every store call inline, so a store that stalls
    /// stalls the session with it. The bound turns a stall into
    /// [`StoreError::Timeout`](ironfix_core::error::StoreError::Timeout). A
    /// write that overruns is handled by the [`StoreFailurePolicy`] like any
    /// other failed write; a reset or refresh that overruns fails the
    /// handshake with [`EngineError::Store`], whatever the policy; and a
    /// resend read that overruns is answered with a gap fill. Without a store
    /// this has no effect.
    ///
    /// A write that overruns may still land later, so it also leaves a reset
    /// owed: the next accepted Logon gets the store reset and an
    /// acknowledgement at 1 declaring `ResetSeqNumFlag` (141) = Y. Reusing the
    /// store is safe only if it applies its mutations in call order even when a
    /// call is dropped (see the [`persistence`](crate::persistence) module).
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

    /// Sets the write timeout (default 10s): how long a session's output may
    /// wait while the stream accepts none of it.
    ///
    /// A counterparty that stops reading closes its TCP receive window, and a
    /// write into a closed window never completes. During the Logon handshake
    /// a write that takes longer than this fails the call with
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
    /// * `timeout` - Longest a handshake write may take, and longest a
    ///   session's output may wait without the stream accepting any of it
    #[must_use]
    pub fn with_write_timeout(mut self, timeout: Duration) -> Self {
        self.write_timeout = timeout.max(TICK_INTERVAL);
        self
    }

    /// Sets the capacity of each session's inbound application queue (default
    /// 1024).
    ///
    /// Inbound application messages are handed to a dispatcher task over this
    /// queue so that a slow [`Application::from_app`] cannot stall socket
    /// reads or heartbeat generation. Messages are delivered in ascending
    /// `MsgSeqNum` order.
    ///
    /// **Lag policy:** when the queue is full the session is closed rather than
    /// the message silently dropped, with the message's sequence number
    /// unspent, so the counterparty stays free to resend from it.
    ///
    /// **Memory:** the bound is on message count, not bytes, and each queued
    /// frame retains up to [`SessionConfig::max_message_size`]. The worst-case
    /// retained memory is `capacity * max_message_size`.
    ///
    /// # Arguments
    /// * `capacity` - Queue depth in messages, at least 1
    #[must_use]
    pub fn with_app_queue_capacity(mut self, capacity: usize) -> Self {
        self.app_queue_capacity = capacity.max(1);
        self
    }

    /// Seeds each accepted session with initial sequence numbers, for
    /// continuity with a previous session. Ignored when the session starts a
    /// new stream: the inbound Logon carries `ResetSeqNumFlag` (141) = Y,
    /// `reset_on_logon` is set, or a store reset is owed.
    ///
    /// Both values must be at least 1: FIX numbers messages from 1. A zero
    /// seed that would actually be used makes [`Acceptor::serve`] fail with
    /// [`EngineError::InvalidInitialSequence`] once the Logon is
    /// authenticated (it used to be raised to 1 silently).
    ///
    /// The seed outranks the counters an attached store reports. Under
    /// [`StoreFailurePolicy::CloseSession`], though, a sender seed below the
    /// store's next sender number is refused with
    /// [`EngineError::InitialSequenceBelowStore`]: the store has frames filed
    /// at those numbers, so the counterparty has seen them.
    ///
    /// # Arguments
    /// * `sender_seq` - Next outgoing sequence number, `>= 1`
    /// * `target_seq` - Next expected incoming sequence number, `>= 1`
    #[must_use]
    pub fn with_initial_sequences(mut self, sender_seq: u64, target_seq: u64) -> Self {
        self.initial_sequences = Some((sender_seq, target_seq));
        self
    }

    /// Sets the capacity of each session's outbound message queue (default
    /// 1024).
    #[must_use]
    pub fn with_outbound_capacity(mut self, capacity: usize) -> Self {
        self.outbound_capacity = capacity.max(1);
        self
    }

    /// Attaches an outbound throttle to every session this acceptor admits: an optional per-session rate
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
    /// are queued. A session routed by an
    /// [`AcceptorRegistry`](crate::AcceptorRegistry) gets the throttle of the
    /// `Acceptor` it is routed to: the registry holds no throttle of its own.
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

    /// The attached frame observer bound to `session_id`, if any.
    #[must_use]
    fn capture(&self, session_id: &SessionId) -> Option<Capture> {
        Capture::bind(self.observer.as_ref(), session_id)
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

    /// The checks that need no connection: a usable configuration and a FIX
    /// version this engine can frame.
    ///
    /// # Errors
    /// [`EngineError::Config`] for an unusable configuration, and
    /// [`EngineError::UnsupportedVersion`] for a `BeginString` this engine
    /// cannot frame conformantly.
    pub(crate) fn preflight(&self) -> Result<FixVersion, EngineError> {
        if let Err(err) = &self.config_check {
            return Err(EngineError::Config(err.clone()));
        }
        // An unsupported version cannot produce a conforming Logon reply, and
        // guessing one would put a fabricated version on the wire.
        match &self.version {
            Ok(version) => Ok(*version),
            Err(err) => Err(EngineError::UnsupportedVersion {
                version: err.version.clone(),
                detail: err.detail.clone(),
            }),
        }
    }

    /// The inputs to [`seed_session`] for a session of this acceptor.
    #[must_use]
    fn seed_plan(&self, reset: bool) -> SeedPlan<'_> {
        self.store.seed_plan(
            &self.session_id,
            reset,
            self.initial_sequences,
            self.write_timeout,
        )
    }

    /// The counters a store-less acceptor numbers its refusal of an unknown
    /// peer from: the seed [`seed_session`] would use, or 1 (also when the seed
    /// is zero, which a session refuses once the peer is authenticated).
    #[must_use]
    fn provisional_sequences(&self) -> SequenceManager {
        match self.initial_sequences {
            Some(initial) if !self.config.reset_on_logon => {
                seeded_counters(initial).unwrap_or_else(|_| SequenceManager::new())
            }
            _ => SequenceManager::new(),
        }
    }

    /// Refuses a Logon that has not been authenticated: its version,
    /// encryption method, CompIDs, `SendingTime` or credentials (`from_admin`)
    /// failed.
    ///
    /// Matching CompIDs authenticate nobody: they are caller-supplied. Without
    /// a store the refusal frames are sent, numbered from the provisional
    /// counters, as the acceptor always has. With a store attached nothing is
    /// sent and the store is not touched: a frame could neither be filed (that
    /// would let a peer that knows the CompIDs, but not the credentials, write
    /// to the outbound journal and advance the session's counters) nor be
    /// numbered without reusing, with different content, a number the
    /// session's stream already holds.
    ///
    /// `before_admission` marks a refusal decided before this connection
    /// claimed the admission slot (version, encryption, CompIDs). If the slot
    /// is held then, the session is live on another connection and nothing is
    /// sent in either mode, as for a duplicate Logon: the live session owns
    /// the sequence stream, and a refusal numbered from the provisional
    /// counters would reuse one of its numbers.
    async fn refuse_unauthenticated<const N: usize>(
        &self,
        session_id: &SessionId,
        framed: &mut FixFramed,
        factory: &mut MessageFactory,
        before_admission: bool,
        refusal: &str,
        messages: [PendingMessage; N],
    ) {
        if before_admission && self.session_is_live() {
            tracing::warn!(
                session = %session_id,
                refusal,
                "refusing a Logon without a reply: the session is live on another connection"
            );
            return;
        }
        if self.store.store().is_some() {
            tracing::warn!(
                session = %session_id,
                refusal,
                "refusing an unauthenticated Logon without a reply: with a store attached, \
                 nothing is written before the peer is authenticated"
            );
            return;
        }
        // Without a store nothing is filed, so the only possible failure is
        // the transport's, which `refuse_handshake` logs.
        let provisional = self.provisional_sequences();
        let _ = refuse_handshake(
            self.application.as_ref(),
            session_id,
            framed,
            factory,
            &provisional,
            None,
            self.write_timeout,
            self.capture(session_id).as_ref(),
            refusal,
            messages,
        )
        .await;
    }

    /// Refuses a Logon that `from_admin` has accepted: its `DefaultApplVerID`,
    /// `ResetSeqNumFlag`, `HeartBtInt` or `NextExpectedMsgSeqNum` check failed
    /// before the store was touched.
    ///
    /// The peer is authenticated, so it gets the refusal (the Logout's text),
    /// sent like every frame of the session: numbered from a seed that never
    /// resets (the store's refreshed counters, or the configured seed), and
    /// filed before it is written when a store is attached. A refused Logon
    /// therefore cannot clear the outbound journal, whatever it declares.
    ///
    /// # Errors
    /// The seeding error (a refresh that fails, a zero seed), or the store
    /// error that stopped the refusal under
    /// [`StoreFailurePolicy::CloseSession`]; the caller reports it in place of
    /// the refusal's own.
    async fn refuse_authenticated<const N: usize>(
        &self,
        session_id: &SessionId,
        framed: &mut FixFramed,
        factory: &mut MessageFactory,
        refusal: &str,
        messages: [PendingMessage; N],
    ) -> Result<(), EngineError> {
        let Seeded {
            sequences,
            persisted,
        } = seed_session(self.seed_plan(false)).await?;
        let mut store = self.store.handshake(persisted, self.write_timeout);
        refuse_handshake(
            self.application.as_ref(),
            session_id,
            framed,
            factory,
            &sequences,
            store.as_mut(),
            self.write_timeout,
            self.capture(session_id).as_ref(),
            refusal,
            messages,
        )
        .await?;
        Ok(())
    }

    /// Accepts the next inbound connection on `listener` and establishes a
    /// session on it.
    ///
    /// This is a thin convenience over [`Acceptor::serve`]: it awaits one TCP
    /// connection and hands the stream to the handshake. For concurrent
    /// handshakes, run the accept loop yourself and spawn a `serve` per
    /// connection (see the module example). An unusable configuration or FIX
    /// version is reported before a connection is taken off the listener.
    ///
    /// # Arguments
    /// * `listener` - A bound [`TcpListener`]
    ///
    /// # Errors
    /// [`EngineError::Config`] or [`EngineError::UnsupportedVersion`] before
    /// any connection is taken; [`EngineError::Io`] if the TCP accept fails;
    /// otherwise any error [`Acceptor::serve`] can produce.
    pub async fn accept(&self, listener: &TcpListener) -> Result<Connection, EngineError> {
        self.preflight()?;
        let (stream, _addr) = listener.accept().await?;
        self.serve(stream).await
    }

    /// Establishes a session on an already-accepted [`TcpStream`], completing
    /// the acceptor-side Logon handshake and spawning the session reactor.
    ///
    /// `TCP_NODELAY` is set on the socket before the handshake, and the
    /// socket is held by value: this path pays no allocation and no dynamic
    /// call per poll. For any other kind of stream, see
    /// [`Acceptor::serve_stream`].
    ///
    /// On success the session is Active: `on_logon` has fired and the returned
    /// [`Connection`] can send application messages. The reactor owns the
    /// socket and handles heartbeats, TestRequests, sequence validation, and
    /// admin replies until the session closes.
    ///
    /// A refused Logon is answered according to who sent it:
    ///
    /// - **An unauthenticated peer** (a wrong `BeginString` (8) or
    ///   `EncryptMethod` (98), the wrong CompIDs, a `SendingTime` (52) out of
    ///   tolerance, or credentials `from_admin` refuses). With a store attached
    ///   the connection is closed without a reply and the store is not touched;
    ///   without one a Reject (373 = 9 or 10) and/or Logout is sent, as before,
    ///   unless this session is live, in which case a Logon refused for its
    ///   version, encryption or CompIDs gets no reply either. Matching CompIDs
    ///   authenticate nobody.
    /// - **A Logon without a valid `MsgSeqNum` (34)** (absent, outside the
    ///   standard header, or 0) is closed without a reply in either mode.
    /// - **A second Logon for a session already live** is closed without a
    ///   reply, with or without a store: the live session owns the sequence
    ///   stream, and nothing the newcomer could be sent belongs to it.
    /// - **An authenticated peer** (`from_admin` accepted it), refused, on a
    ///   FIX 5.0 session, by a `DefaultApplVerID` (1137) that is missing,
    ///   repeated, not an application-version code, or not a version the
    ///   session accepts; by a `ResetSeqNumFlag` (141) Logon not numbered 1; a
    ///   missing or out of range `HeartBtInt` (108); a `NextExpectedMsgSeqNum`
    ///   (789) that is malformed or above the number the ack would take, when
    ///   [`SessionConfig::send_next_expected_msg_seq_num`] is set; or a
    ///   `MsgSeqNum` below the expected one: the Logout is sent like every
    ///   session frame, numbered
    ///   from the store's refreshed counters (or the seed) and filed when a
    ///   store is attached. Such a refusal never resets the store.
    ///
    /// An attached store is touched first once the Logon is authenticated.
    /// From then on every frame the handshake sends is filed, and the Logon's
    /// number persisted, in the order the [`persistence`](crate::persistence)
    /// module describes.
    ///
    /// # Arguments
    /// * `stream` - An accepted TCP connection from the counterparty
    ///
    /// # Errors
    /// Returns an [`EngineError`] if framing or the Logon handshake fails. That
    /// includes [`EngineError::LogonTimeout`] when no intact Logon arrives
    /// within [`SessionConfig::logon_timeout`] (garbled ones are skipped),
    /// [`EngineError::UnexpectedMessage`] when
    /// the first frame is not a Logon, [`EngineError::IdentityMismatch`] when
    /// the Logon's CompIDs do not match the configured counterparty, and
    /// [`EngineError::SequenceExhausted`] when a sequence counter has reached
    /// `u64::MAX`. [`EngineError::LogonRejected`] covers the acceptor-side
    /// refusals: the `from_admin` authentication hook, a `BeginString` (8) that
    /// does not match this session's version, an unsupported `EncryptMethod`
    /// (98), a `HeartBtInt` (108) that is missing, non-numeric, or out of range,
    /// and a second concurrent Logon for a session already established.
    /// [`EngineError::ApplVersion`] is a FIX 5.0 Logon's `DefaultApplVerID`
    /// (1137) refused as above, and [`EngineError::NextExpectedMsgSeqNum`] its
    /// `NextExpectedMsgSeqNum` (789). A
    /// `BeginString` this engine cannot frame *at all* is refused up front with
    /// [`EngineError::UnsupportedVersion`], an unusable configuration with
    /// [`EngineError::Config`], and a zero initial seed that would be used with
    /// [`EngineError::InvalidInitialSequence`]. With a store,
    /// [`EngineError::Store`] when the store cannot be reset or refreshed for
    /// the session (whatever the policy), or a handshake write fails under
    /// [`StoreFailurePolicy::CloseSession`]; and
    /// [`EngineError::InitialSequenceBelowStore`] for a sender seed below the
    /// store under [`StoreFailurePolicy::CloseSession`].
    pub async fn serve(&self, stream: TcpStream) -> Result<Connection, EngineError> {
        // The only way to a TCP session: it sets TCP_NODELAY.
        self.serve_session_stream(SessionStream::tcp(stream)).await
    }

    /// Establishes a session on a byte stream the caller has already
    /// accepted, completing the acceptor-side Logon handshake and spawning the
    /// session reactor, exactly as [`Acceptor::serve`] does on a
    /// [`TcpStream`].
    ///
    /// This is the seam for any transport the engine does not accept itself:
    /// a TLS stream built with the TLS stack of your choice on top of an
    /// accepted socket, a Unix socket, a connection through a proxy, or an
    /// in-memory [`tokio::io::duplex`] pipe for tests. The handshake is the
    /// one [`Acceptor::serve`] runs, unchanged: the same checks in the same
    /// order, the same logon timeout, the same refusal groups, the same rule
    /// that nothing reaches an attached store before the peer is
    /// authenticated, the same `NextExpectedMsgSeqNum` (789) handling, and the
    /// same reactor and write timeout once Active. Only `TCP_NODELAY`, which
    /// [`Acceptor::serve`] sets, is not set: the engine cannot reach a socket
    /// option through an arbitrary stream, so that is the caller's.
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
    /// [`Acceptor::serve`] is not: it holds its socket by value. Each outbound
    /// frame written in one piece then costs three dynamic calls
    /// (`is_write_vectored`, `poll_write_vectored`, `poll_flush`), and each
    /// read poll one, the `Pending` poll on every wakeup included. Nothing has
    /// measured that cost. Pass the stream's concrete type: a stream that is
    /// already boxed (`Box<dyn ...>`, `Pin<Box<dyn ...>>`) is boxed again, for
    /// two allocations and two vtable hops on every call.
    ///
    /// See [`Initiator::establish`](crate::Initiator::establish) for an
    /// example running both roles over [`tokio::io::duplex`].
    ///
    /// # Arguments
    /// * `stream` - An accepted byte stream from the counterparty
    ///
    /// # Errors
    /// Every error [`Acceptor::serve`] documents. A stream that closes before
    /// an intact Logon arrives is [`EngineError::Closed`], or
    /// [`EngineError::Codec`] carrying the I/O error when it closes partway
    /// through a frame or fails.
    pub async fn serve_stream<S>(&self, stream: S) -> Result<Connection, EngineError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.serve_session_stream(SessionStream::erased(stream))
            .await
    }

    /// [`Acceptor::serve`] and [`Acceptor::serve_stream`] on the session's
    /// stream, TCP or erased: reads the inbound Logon and runs the handshake
    /// on it.
    ///
    /// # Errors
    /// Every error [`Acceptor::serve`] documents.
    async fn serve_session_stream(&self, stream: SessionStream) -> Result<Connection, EngineError> {
        let version = self.preflight()?;

        let session_id = self.session_id.clone();
        self.application.on_create(&session_id).await;

        // Typestate: Disconnected -> Connecting (acceptor side).
        let session = Session::<Disconnected>::new(session_id.to_string()).accept();

        let mut framed = Framed::new(stream, session_codec(&self.config, version));

        // Await the inbound Logon. Garbled frames are skipped, and the logon
        // timeout covers the whole wait, so a Logon that never arrives intact
        // is a LogonTimeout.
        // `on_create` has run: a failure from here is reported to the
        // application as well as returned.
        let result = match read_handshake_frame(
            &mut framed,
            self.config.logon_timeout,
            &session_id,
            self.capture(&session_id).as_ref(),
        )
        .await
        {
            HandshakeRead::Frame(logon_frame) => {
                self.complete_handshake(version, session, framed, logon_frame, None)
                    .await
            }
            HandshakeRead::TimedOut => {
                let _ = session.disconnect();
                Err(EngineError::LogonTimeout(self.config.logon_timeout))
            }
            HandshakeRead::Closed => {
                let _ = session.disconnect();
                Err(EngineError::Closed)
            }
            HandshakeRead::Codec(err) => {
                let _ = session.disconnect();
                Err(err.into())
            }
        };
        report_handshake(&*self.application, &session_id, result).await
    }

    /// Runs this session's handshake on a Logon that was read, and routed to
    /// this acceptor, by an [`AcceptorRegistry`](crate::AcceptorRegistry).
    ///
    /// Everything [`Acceptor::serve`] does after the Logon has arrived is done
    /// here unchanged: the same checks in the same order, the same refusal
    /// policy, the same store order and the same reactor. What differs is only
    /// what came before. The configuration check and `on_create` run now, once
    /// the session is known, rather than before the read; the socket's codec
    /// is replaced by this session's own (its message-size ceiling, checksum
    /// setting and resync anchor), which governs every frame after the Logon;
    /// and the Logon, framed under the registry's ceiling, is held to this
    /// session's `max_message_size` too, so a frame this session's codec would
    /// have refused is refused here, without a reply.
    ///
    /// `authenticated`, when given, is set once `from_admin` has accepted the
    /// Logon, whatever happens after: the registry keeps a session its lookup
    /// admitted only if a handshake got that far.
    ///
    /// # Errors
    /// [`EngineError::Codec`] for a Logon above this session's
    /// `max_message_size`; otherwise any error [`Acceptor::serve`] can produce
    /// once the Logon has been read.
    pub(crate) async fn serve_logon(
        &self,
        mut framed: FixFramed,
        logon_frame: BytesMut,
        authenticated: Option<&AtomicBool>,
    ) -> Result<Connection, EngineError> {
        let version = self.preflight()?;

        let session_id = self.session_id.clone();
        self.application.on_create(&session_id).await;

        // Typestate: Disconnected -> Connecting (acceptor side).
        let session = Session::<Disconnected>::new(session_id.to_string()).accept();

        // From here on the socket is this session's: frames after the Logon
        // are framed under its own settings, exactly as on `serve`. The codec
        // holds no partial frame (it settles whenever it returns one), and any
        // bytes already read stay in the `Framed` buffer for the new codec.
        *framed.codec_mut() = session_codec(&self.config, version);
        // The registry read the Logon before it knew the session: it is
        // observed now, by the session it was routed to.
        if let Some(capture) = self.capture(&session_id) {
            capture.inbound(&logon_frame, FrameKind::Handshake);
        }
        let max_size = self.config.max_message_size;
        let result = if logon_frame.len() > max_size {
            let _ = session.disconnect();
            Err(CodecError::MessageTooLarge {
                size: logon_frame.len(),
                max_size,
            }
            .into())
        } else {
            self.complete_handshake(version, session, framed, logon_frame, authenticated)
                .await
        };
        // `on_create` has run: a failure from here is reported to the
        // application as well as returned.
        report_handshake(&*self.application, &session_id, result).await
    }

    /// The acceptor half of the Logon handshake, from a Logon frame that has
    /// already been read (and decoded once) on `framed`, up to the spawned
    /// reactor.
    ///
    /// Shared by [`Acceptor::serve`] and the registry path
    /// ([`Acceptor::serve_logon`]), so a routed session is checked, refused,
    /// persisted and run exactly as a session served directly.
    ///
    /// `authenticated`, when given, is set as soon as `from_admin` accepts the
    /// Logon.
    ///
    /// # Errors
    /// Every handshake error [`Acceptor::serve`] documents after the read.
    async fn complete_handshake(
        &self,
        version: FixVersion,
        session: Session<Connecting>,
        mut framed: FixFramed,
        logon_frame: BytesMut,
        authenticated: Option<&AtomicBool>,
    ) -> Result<Connection, EngineError> {
        let session_id = self.session_id.clone();

        let mut factory = MessageFactory::new(&self.config, version);
        let identity = PeerIdentity::new(&self.config);
        let sending_time = SendingTimeGuard::new(&self.config);
        let appl_version = ApplVersionGuard::new(&self.config, version);
        let write_timeout = self.write_timeout;
        let store_timeout = self.store.timeout(write_timeout);

        // Typestate: Connecting -> LogonReceived.
        let session = session.on_logon_received();

        // (gap start, high-water) of a gap detected in the inbound Logon.
        let mut pending_resend: Option<(u64, u64)> = None;
        // (first, first not resent) of what the Logon's NextExpectedMsgSeqNum
        // (789) says the initiator missed.
        let mut opening_replay: Option<(u64, u64)> = None;
        // (gap start, Logon MsgSeqNum) of a gapped Logon held instead of
        // requested, when both sides declared 789.
        let mut held_logon: Option<(u64, u64)> = None;
        // The admission claim is taken once identity is validated and moved into
        // the reactor task on success; on any handshake failure after the claim
        // this local drops and frees the slot. These are assigned on the
        // fall-through path out of the block below; every path before an
        // assignment returns first.
        let admission;
        let runtime;
        let mut store;
        let reset;
        let reset_ticket;
        {
            let raw = match wire::decode_frame(&logon_frame) {
                Ok(raw) => raw,
                Err(err) => {
                    let _ = session.reject_logon();
                    return Err(err.into());
                }
            };

            match raw.msg_type() {
                MsgType::Logon => {}
                other => {
                    let msg_type = other.as_str().to_string();
                    let _ = session.reject_logon();
                    return Err(EngineError::UnexpectedMessage { msg_type });
                }
            }

            // BeginString (8): a peer speaking a different FIX version cannot be
            // given a conforming ack in this session's version, so it must not
            // reach Active in ours. Compared against the wire BeginString the
            // header stamper uses, which is `FIXT.1.1` for every 5.0 session.
            let inbound_begin_string = raw.begin_string().unwrap_or_default();
            if inbound_begin_string != version.begin_string() {
                let detail = format!(
                    "Logon BeginString (8) '{}' does not match the configured '{}'",
                    inbound_begin_string.chars().take(16).collect::<String>(),
                    version.begin_string()
                );
                let logout = factory.logout(Some(&detail));
                self.refuse_unauthenticated(
                    &session_id,
                    &mut framed,
                    &mut factory,
                    true,
                    &detail,
                    [logout],
                )
                .await;
                let _ = session.reject_logon();
                return Err(EngineError::LogonRejected { reason: detail });
            }

            // EncryptMethod (98): IronFix implements no encryption, so only 0
            // (None) can be honoured. A missing or non-zero method is refused
            // rather than silently accepted as if it were plaintext.
            let encrypt_method = raw.get_field_str(98);
            if encrypt_method != Some("0") {
                let shown = encrypt_method
                    .map_or_else(|| "<absent>".to_string(), |v| v.chars().take(16).collect());
                let detail =
                    format!("unsupported EncryptMethod (98) '{shown}'; only 0 (None) is supported");
                let logout = factory.logout(Some(&detail));
                self.refuse_unauthenticated(
                    &session_id,
                    &mut framed,
                    &mut factory,
                    true,
                    &detail,
                    [logout],
                )
                .await;
                let _ = session.reject_logon();
                return Err(EngineError::LogonRejected { reason: detail });
            }

            // MsgSeqNum (34) must sit in the standard header: a body-only 34 is
            // not the session sequence number, exactly as the identity check
            // requires 49/56 in the header. 0 names no message (FIX numbers from
            // 1), so it is no number either; refusing it here also keeps it away
            // from the reset rule, which takes a positive number of an old
            // stream as message 1. No reply, and the store is not touched:
            // nothing can reference a Logon that has no number.
            let logon_seq = match wire::header_seq_num(&raw).filter(|seq| *seq > 0) {
                Some(seq) => seq,
                None => {
                    let _ = session.reject_logon();
                    return Err(EngineError::Sequence(
                        "Logon has no valid MsgSeqNum (34) in the standard header".to_string(),
                    ));
                }
            };

            // Identity before anything else: a cross-wired initiator must not
            // be allowed to establish a session or move sequence state.
            if let Err(mismatch) = identity.validate(&raw) {
                let detail = mismatch.to_string();
                let reason = RejectReason::new(9, detail.clone()).with_ref_tag(mismatch.tag);
                let reject = factory.session_reject(logon_seq, MsgType::Logon.as_str(), &reason);
                let logout = factory.logout(Some(&detail));
                self.refuse_unauthenticated(
                    &session_id,
                    &mut framed,
                    &mut factory,
                    true,
                    &detail,
                    [reject, logout],
                )
                .await;
                let _ = session.reject_logon();
                return Err(EngineError::IdentityMismatch { detail });
            }

            // Identity is proven: claim the single admission slot. A second
            // concurrent Logon for this same counterparty is refused here rather
            // than allowed to fork the session into two independent sequence
            // streams both starting at 1. Policy: the live session is preserved
            // and the newcomer's connection is closed without a reply, with or
            // without a store: the live session owns the sequence stream, so
            // nothing the newcomer could be sent belongs to it.
            admission = match self.try_admit() {
                Some(guard) => guard,
                None => {
                    let detail = format!("session already active for {session_id}");
                    tracing::warn!(
                        session = %session_id,
                        "refusing a duplicate concurrent Logon without a reply"
                    );
                    let _ = session.reject_logon();
                    return Err(EngineError::LogonRejected { reason: detail });
                }
            };

            // The clock is checked next, before the heartbeat is set: an
            // initiator whose SendingTime is wildly skewed cannot be trusted to
            // sequence a session, and the handshake is the cheapest place to
            // refuse it. The peer is not authenticated yet (matching CompIDs
            // prove nothing), so with a store attached it gets no reply.
            if let Err(problem) = sending_time.validate(&raw) {
                let detail = problem.to_string();
                let reason = problem.reject_reason();
                let reject = factory.session_reject(logon_seq, MsgType::Logon.as_str(), &reason);
                let logout = factory.logout(Some(&detail));
                self.refuse_unauthenticated(
                    &session_id,
                    &mut framed,
                    &mut factory,
                    false,
                    &detail,
                    [reject, logout],
                )
                .await;
                let _ = session.reject_logon();
                return Err(EngineError::SendingTime { detail });
            }

            // Authentication hook: the application inspects the Logon (Username
            // 553 / Password 554 and the like) and may refuse it. A refused
            // peer is not authenticated, so with a store attached it gets no
            // reply and the store is not touched: knowing the CompIDs must not
            // be enough to write to the journal or move the session's
            // counters.
            if let Err(reason) = self.application.from_admin(&raw, &session_id).await {
                let logout = factory.logout(Some(&reason.text));
                self.refuse_unauthenticated(
                    &session_id,
                    &mut framed,
                    &mut factory,
                    false,
                    &reason.text,
                    [logout],
                )
                .await;
                let _ = session.reject_logon();
                return Err(EngineError::LogonRejected {
                    reason: reason.text,
                });
            }

            // Authenticated from here on: a refusal is sent like any session
            // frame, filed when a store is attached.
            if let Some(authenticated) = authenticated {
                authenticated.store(true, Ordering::Release);
            }

            // DefaultApplVerID (1137): on a FIXT.1.1 session the Logon must
            // declare, once, a default application version this session
            // accepts (its own, or one in `allowed_appl_versions`); it is a
            // required field of the FIXT.1.1 Logon. Otherwise every
            // application message without ApplVerID (1128) would reach the
            // application in a version nobody agreed to. The peer is
            // authenticated, so the refusal is a Logout saying why, filed
            // like the other authenticated refusals; it is checked before the
            // store is reset, so a refused Logon never resets it. A FIX 4.x
            // Logon carries no 1137 and is not checked.
            // The declared version is kept for the session's runtime once it
            // exists (`Connection::counterparty_default_appl_version`).
            let declared_appl_version = match appl_version.check_logon(&raw, true) {
                Ok(declared) => {
                    if let Some(declared) = declared {
                        tracing::debug!(
                            session = %session_id,
                            default_appl_version = %declared,
                            "counterparty declared its default application version"
                        );
                    }
                    declared
                }
                Err(problem) => {
                    let detail = problem.to_string();
                    tracing::warn!(session = %session_id, detail = %detail, "rejecting Logon DefaultApplVerID");
                    let logout = factory.logout(Some(&detail));
                    let refused = self
                        .refuse_authenticated(
                            &session_id,
                            &mut framed,
                            &mut factory,
                            &detail,
                            [logout],
                        )
                        .await;
                    let _ = session.reject_logon();
                    refused?;
                    return Err(EngineError::ApplVersion { detail });
                }
            };

            // ResetSeqNumFlag (141): FIX requires MsgSeqNum = 1 on a Logon that
            // itself carries ResetSeqNumFlag = Y: the reset and the number
            // carrying it have to describe the same stream. Checked before the
            // store is touched, so a contradictory Logon cannot reset it.
            let inbound_reset = raw.get_field_str(141) == Some("Y");
            if inbound_reset && logon_seq != 1 {
                let detail =
                    format!("Logon set ResetSeqNumFlag=Y but carried MsgSeqNum {logon_seq}, not 1");
                let logout = factory.logout(Some(&detail));
                let refused = self
                    .refuse_authenticated(&session_id, &mut framed, &mut factory, &detail, [logout])
                    .await;
                let _ = session.reject_logon();
                refused?;
                return Err(EngineError::Sequence(detail));
            }

            // HeartBtInt (108): the acceptor adopts the interval the initiator
            // requested and echoes it back on the reply. The value is
            // counterparty-controlled and drives a Duration on the heartbeat
            // clock, so it is bounded here — a missing, non-numeric, or
            // over-range 108 fails the handshake rather than being defaulted or,
            // at u64::MAX, overflowing the clock and aborting the process. It is
            // checked before the store is reset, so a refused Logon never resets
            // it.
            let requested_heartbeat_secs = match wire::parse_heartbeat_interval(&raw) {
                Ok(secs) => secs,
                Err(problem) => {
                    let detail = problem.to_string();
                    tracing::warn!(session = %session_id, detail = %detail, "rejecting Logon HeartBtInt");
                    let logout = factory.logout(Some(&detail));
                    let refused = self
                        .refuse_authenticated(
                            &session_id,
                            &mut framed,
                            &mut factory,
                            &detail,
                            [logout],
                        )
                        .await;
                    let _ = session.reject_logon();
                    refused?;
                    return Err(EngineError::LogonRejected { reason: detail });
                }
            };

            // NextExpectedMsgSeqNum (789), when this session uses it: the next
            // number the initiator expects from us. A malformed value (repeated,
            // 0, not a number) is refused like the Logon's other fields, before
            // the store is touched. Whether the value asks for a resend, or for
            // messages never sent, depends on the counters, so it is decided
            // below.
            let declared_next_expected = if self.config.send_next_expected_msg_seq_num {
                match next_expected::read_next_expected(&raw) {
                    Ok(declared) => declared,
                    Err(problem) => {
                        let detail = problem.to_string();
                        tracing::warn!(session = %session_id, detail = %detail, "rejecting Logon NextExpectedMsgSeqNum");
                        let logout = factory.logout(Some(&detail));
                        let refused = self
                            .refuse_authenticated(
                                &session_id,
                                &mut framed,
                                &mut factory,
                                &detail,
                                [logout],
                            )
                            .await;
                        let _ = session.reject_logon();
                        refused?;
                        return Err(EngineError::NextExpectedMsgSeqNum { detail });
                    }
                }
            } else {
                None
            };

            // The Logon is accepted: only now is the store reset. The session
            // starts a new stream when the peer asks (141=Y), when it is
            // locally configured to (`reset_on_logon`), or when an earlier
            // session left a reset owed. A reset clears the store (one
            // `reset_to` call) before the acknowledgement is filed; otherwise
            // the counters come from the seed or the refreshed store. Either
            // fails closed whatever the policy. A reset is owed from before it
            // is awaited until the acknowledgement declaring it is sent, so a
            // serve dropped or failed in between leaves it owed.
            reset = inbound_reset || self.config.reset_on_logon || self.store.reset_is_owed();

            // A 789 describes the stream the initiator expects to continue. A
            // reset it did not ask for (`reset_on_logon`, an owed reset)
            // discards that stream, and the ack's 141=Y tells the initiator to
            // restart too, so its 789 asks for nothing. A reset it asked for
            // (141=Y) makes our ack message 1 of the new stream: its 789 must
            // be 1, and that is known before the store is reset, so a refused
            // Logon never resets it.
            let declared_next_expected = match declared_next_expected {
                Some(declared) if reset && !inbound_reset => {
                    tracing::debug!(
                        session = %session_id,
                        declared = declared.get(),
                        "ignoring the Logon's NextExpectedMsgSeqNum: this session resets the \
                         sequence the counterparty did not ask to reset"
                    );
                    None
                }
                other => other,
            };
            if reset
                && let Some(declared) = declared_next_expected
                && let Err(problem) = next_expected::plan(declared, 1, 1)
            {
                let detail = problem.to_string();
                tracing::warn!(session = %session_id, detail = %detail, "rejecting Logon NextExpectedMsgSeqNum");
                let logout = factory.logout(Some(&detail));
                let refused = self
                    .refuse_authenticated(&session_id, &mut framed, &mut factory, &detail, [logout])
                    .await;
                let _ = session.reject_logon();
                refused?;
                return Err(EngineError::NextExpectedMsgSeqNum { detail });
            }

            // The ticket pays only this reset: a store write that fails while
            // the acknowledgement is filed owes another.
            reset_ticket = (reset && self.store.store().is_some()).then(|| self.store.owe_reset());
            let Seeded {
                sequences,
                persisted,
            } = match seed_session(self.seed_plan(reset)).await {
                Ok(seeded) => seeded,
                Err(err) => {
                    let _ = session.reject_logon();
                    return Err(err);
                }
            };
            if reset {
                tracing::info!(
                    session = %session_id,
                    inbound_reset,
                    "resetting sequence numbers on Logon"
                );
            }
            runtime = Arc::new(SessionRuntime::new(
                sequences,
                HeartbeatManager::new(self.config.heartbeat_interval),
            ));
            if let Some(declared) = declared_appl_version {
                runtime.record_counterparty_default_appl_version(declared);
            }
            // Every frame from here on goes through this binding: filed, and its
            // number persisted, before it is written.
            store = self.store.handshake(persisted, write_timeout);

            {
                let mut heartbeat = lock_heartbeat(&runtime);
                heartbeat.on_message_received(false, None);
                if Duration::from_secs(requested_heartbeat_secs) != heartbeat.interval() {
                    tracing::info!(
                        session = %session_id,
                        heartbeat_secs = requested_heartbeat_secs,
                        "honoring HeartBtInt requested by counterparty"
                    );
                    *heartbeat =
                        HeartbeatManager::new(Duration::from_secs(requested_heartbeat_secs));
                }
            }
            let reply_heartbeat_secs = requested_heartbeat_secs;

            // NextExpectedMsgSeqNum (789) against the counters the session now
            // runs on: the ack takes the next sender number, so a 789 above it
            // claims messages never sent, and one below it names messages the
            // initiator missed, resent once Active. Decided before the Logon's
            // own MsgSeqNum is validated, so a refused Logon is not consumed;
            // the Logout is numbered from those counters and filed, as for a
            // Logon too low. After a reset the ack is 1 and a 789 above 1 was
            // refused before the store was reset, so this never refuses then.
            if let Some(declared) = declared_next_expected {
                let ack_seq = runtime.sequences.next_sender_seq().value();
                match next_expected::plan(declared, ack_seq, ack_seq) {
                    Ok(plan) => opening_replay = plan.replay_range(),
                    Err(problem) => {
                        let detail = problem.to_string();
                        tracing::warn!(session = %session_id, detail = %detail, "rejecting Logon NextExpectedMsgSeqNum");
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
                            [logout],
                        )
                        .await;
                        let _ = session.reject_logon();
                        refused?;
                        return Err(EngineError::NextExpectedMsgSeqNum { detail });
                    }
                }
            }

            // The reset rule both roles share: in a Logon exchange that resets
            // the sequence, each side's Logon or acknowledgement is message 1
            // of its new stream. After a reset, the peer's Logon is therefore
            // taken as its message 1 whatever MsgSeqNum it carries (a peer that
            // did not ask for the reset is told to make it by the ack's 141=Y),
            // and 2 is expected next: no gap is opened for the old stream's
            // numbers. Without a reset the Logon is validated as usual.
            let validation = if reset && logon_seq > 0 {
                SequenceResult::Ok
            } else {
                runtime.sequences.validate_incoming(logon_seq)
            };
            match validation {
                SequenceResult::Ok => {
                    // The receive cursor includes the Logon before the session
                    // goes Active on it and before the in-memory expectation
                    // moves, as for every later inbound message.
                    if let Some(handshake) = store.as_mut() {
                        let expected = runtime.sequences.next_target_seq().value();
                        let Some(next) = expected.checked_add(1) else {
                            let _ = session.reject_logon();
                            return Err(SequenceExhausted {
                                counter: SequenceCounter::Target,
                            }
                            .into());
                        };
                        if let Err(err) = handshake.persist_target(&session_id, next).await {
                            let _ = session.reject_logon();
                            return Err(err.into());
                        }
                    }
                    if let Err(err) = runtime.sequences.try_increment_target_seq() {
                        let _ = session.reject_logon();
                        return Err(err.into());
                    }
                }
                SequenceResult::TooLow { expected, received } => {
                    let detail = format!(
                        "logon MsgSeqNum too low: expected {expected}, received {received}"
                    );
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
                        [logout],
                    )
                    .await;
                    let _ = session.reject_logon();
                    refused?;
                    return Err(EngineError::Sequence(detail));
                }
                // Both sides declared 789: our ack names `expected` as the
                // next number we expect, so the initiator resends the gap
                // below its Logon on its own. The Logon is held, its number
                // consumed once that gap is filled, and no ResendRequest
                // crosses the resend (QuickFIX/C++ does the same). The
                // filtered 789 is used: it is None when this side drives a
                // reset. Otherwise the gap is requested as the reactor's first
                // act.
                SequenceResult::Gap { expected, received } => {
                    if self.config.send_next_expected_msg_seq_num
                        && declared_next_expected.is_some()
                    {
                        held_logon = Some((expected, received));
                    } else {
                        pending_resend = Some((expected, received));
                    }
                }
            }

            // Reply with the Logon acknowledgement, mirroring ResetSeqNumFlag:
            // whichever drove the reset, the ack carries 141=Y so the peer
            // resets in lockstep. `send_handshake_admin` frames it under the
            // next sender sequence number (1 after a reset), files it and
            // persists the next sender number when a store is attached, and
            // spends the number only then. With NextExpectedMsgSeqNum (789)
            // on, the ack declares the next number expected from the
            // initiator now that its Logon is processed: its number plus one
            // in sequence, 2 after a reset, and the first missing number when
            // the Logon opened a gap (a gapped Logon is not consumed).
            let next_expected = self
                .config
                .send_next_expected_msg_seq_num
                .then(|| runtime.sequences.next_target_seq().value());
            let logon_ack = factory.logon(reply_heartbeat_secs, reset, next_expected);
            if let Err(err) = send_handshake_admin(
                self.application.as_ref(),
                &session_id,
                &mut framed,
                &mut factory,
                &runtime.sequences,
                store.as_mut(),
                write_timeout,
                self.capture(&session_id).as_ref(),
                logon_ack,
            )
            .await
            {
                let _ = session.reject_logon();
                return Err(err);
            }
            lock_heartbeat(&runtime).on_message_sent();
        }

        // The acknowledgement that declared the reset is on the wire: that
        // reset is paid. A store write that failed during this handshake was
        // owed after the ticket was taken, and stays owed.
        if let Some(ticket) = reset_ticket {
            self.store.reset_paid(ticket);
        }

        // Typestate: LogonReceived -> Active.
        let session = session.accept_logon();
        self.application.on_logon(&session_id).await;
        tracing::info!(session = %session_id, "FIX session established (acceptor)");

        // Hand the framed socket to the shared reactor, the same one the
        // initiator uses. The admission guard rides the reactor task and frees
        // the slot when the task ends: after its close path (store writes
        // included), the drain of its application queue and `on_logout`. A gap
        // in the inbound Logon is requested by the reactor as its first act,
        // so that once `on_logon` has run, a failure to send the request
        // closes the session through the reactor's close path (`on_logout`
        // included) like any other.
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
        };
        let (command_tx, closed_rx) = spawn_session(params, admission);

        Ok(Connection {
            session_id,
            commands: command_tx,
            closed: closed_rx,
            runtime,
        })
    }
}
