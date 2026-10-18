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
//! `serve`.
//!
//! The accept loop and its supervision are the consumer's, exactly as
//! reconnection is the consumer's for the initiator: an `Acceptor` is a single
//! configured session (one expected counterparty), and each accepted
//! connection becomes its own live session with its own sequence state. A
//! server that fronts several counterparties runs one accept loop and matches
//! each inbound connection to the `Acceptor` configured for it.
//!
//! # Handshake conformance
//!
//! The inbound Logon is validated in the order set out in
//! `doc/fix_operations.md` ("Logon"): it must decode and be a Logon; its
//! `BeginString` (8) must match this session's version and its `EncryptMethod`
//! (98) must be 0 (None); it must carry `MsgSeqNum` (34) **in the standard
//! header**; then counterparty identity (49/56, plus 50/57 when configured) is
//! checked and the single admission slot is claimed — a second concurrent Logon
//! for the same counterparty is refused rather than allowed to fork the session;
//! then `SendingTime` (52) accuracy and the `from_admin` authentication hook;
//! then a `ResetSeqNumFlag` (141) Logon must carry `MsgSeqNum` 1; then the
//! `HeartBtInt` (108) the initiator requested is bounded; only then is an
//! attached store reset (for 141, the local `reset_on_logon`, or an owed
//! reset) or refreshed; and finally `MsgSeqNum` is validated and the ack,
//! mirroring 141 and echoing 108, is sent. Waiting for the inbound Logon is
//! bounded by [`SessionConfig::logon_timeout`]; a garbled frame that arrives
//! first (a bad CheckSum or BodyLength, bytes before `8=`, or a frame whose
//! MsgType (35) is not third) is skipped and the wait goes on against the same
//! timeout. So is a frame whose header decodes but whose body does not: it is
//! not garbled, but it cannot be read as a Logon either. A Logon that never
//! arrives intact ends in [`EngineError::LogonTimeout`]. A gap in the Logon
//! completes the handshake and immediately issues a `ResendRequest` (2).
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
//! - **A Logon without a valid `MsgSeqNum`** (absent, outside the header, or
//!   0): nothing, in either mode.
//! - **A duplicate Logon** for a session already live: nothing, in either
//!   mode. The live session owns the sequence stream.
//! - **An authenticated peer** (`from_admin` accepted it) refused by a 141
//!   Logon not numbered 1, by its `HeartBtInt`, or by a `MsgSeqNum` too low: a
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
use crate::connection::{Connection, SessionRuntime};
use crate::error::EngineError;
use crate::persistence::{
    PersistedCounters, SeedPlan, Seeded, StoreAttachment, StoreFailurePolicy, seed_session,
    seeded_counters,
};
use crate::reactor::{
    DEFAULT_APP_QUEUE_CAPACITY, DEFAULT_OUTBOUND_CAPACITY, DEFAULT_WRITE_TIMEOUT, FixFramed,
    HandshakeRead, SessionParams, TICK_INTERVAL, lock_heartbeat, read_handshake_frame,
    refuse_handshake, send_handshake_admin, session_codec, spawn_session,
};
use crate::wire::{
    self, MessageFactory, PeerIdentity, PendingMessage, SendingTimeGuard, UnsupportedVersion,
};
use ironfix_core::message::MsgType;
use ironfix_core::version::FixVersion;
use ironfix_session::config::SessionConfigError;
use ironfix_session::sequence::{SequenceCounter, SequenceExhausted, SequenceResult};
use ironfix_session::{Disconnected, HeartbeatManager, SequenceManager, Session, SessionConfig};
use ironfix_store::MessageStore;
use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
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
/// accepted connection ([`Acceptor::accept`] / [`Acceptor::serve`]) establishes
/// one live session and returns a [`Connection`] handle for it. Cloning the
/// application is cheap, so an `Acceptor` is typically wrapped in an [`Arc`]
/// and shared across the tasks serving each connection.
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
    /// Bound on a single socket write.
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
    /// order described in the [`persistence`](crate::persistence) module. Note
    /// that [`MemoryStore`](ironfix_store::MemoryStore) is the only
    /// implementation today and is **not** persistent, so this does not yet
    /// survive a restart.
    ///
    /// **One store, one engine.** The store must belong to this acceptor alone:
    /// two engines, or two processes, writing to one store would interleave two
    /// sequence streams in it. The record of a reset owed to the next session
    /// is held in memory by the acceptor, not in the store, so a restart
    /// forgets it (#78, #89).
    ///
    /// **Nothing reaches the store before the Logon is authenticated.** A Logon
    /// refused before `from_admin` has accepted it (wrong version, encryption,
    /// `MsgSeqNum`, CompIDs, `SendingTime` or credentials) or for a session
    /// already live gets no reply and never touches the store: matching
    /// CompIDs authenticate nobody. A Logon refused after authentication (a
    /// malformed `ResetSeqNumFlag` or `HeartBtInt`, a `MsgSeqNum` too low) is
    /// answered with a filed Logout, numbered from the store's counters, and
    /// never resets the store; see [`Acceptor::serve`].
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

    /// Sets how long a single socket write may take before the session is
    /// closed (default 10s).
    ///
    /// A counterparty that stops reading closes its TCP receive window, and a
    /// write into a closed window never completes. Without a bound the reactor
    /// parks inside that write with its liveness timers, so the session hangs
    /// instead of being declared dead. Expiry closes the session with
    /// [`EngineError::WriteTimeout`].
    ///
    /// A zero timeout is raised to one tick: a write that is given no time at
    /// all can never succeed.
    ///
    /// # Arguments
    /// * `timeout` - Maximum duration of one write
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
    fn preflight(&self) -> Result<FixVersion, EngineError> {
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
    async fn refuse_unauthenticated<const N: usize>(
        &self,
        session_id: &SessionId,
        framed: &mut FixFramed,
        factory: &mut MessageFactory,
        refusal: &str,
        messages: [PendingMessage; N],
    ) {
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
            refusal,
            messages,
        )
        .await;
    }

    /// Refuses a Logon that `from_admin` has accepted: its `ResetSeqNumFlag`
    /// or `HeartBtInt` check failed.
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
    ///   without one a Reject (373 = 9 or 10) and/or Logout is sent, as before.
    ///   Matching CompIDs authenticate nobody.
    /// - **A Logon without a valid `MsgSeqNum` (34)** (absent, outside the
    ///   standard header, or 0) is closed without a reply in either mode.
    /// - **A second Logon for a session already live** is closed without a
    ///   reply, with or without a store: the live session owns the sequence
    ///   stream, and nothing the newcomer could be sent belongs to it.
    /// - **An authenticated peer** (`from_admin` accepted it), refused by a
    ///   `ResetSeqNumFlag` (141) Logon not numbered 1, a missing or out of
    ///   range `HeartBtInt` (108), or a `MsgSeqNum` below the expected one: the
    ///   Logout is sent like every session frame, numbered from the store's
    ///   refreshed counters (or the seed) and filed when a store is attached.
    ///   Such a refusal never resets the store.
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
    /// and a second concurrent Logon for a session already established. A
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
        let version = self.preflight()?;

        let session_id = self.session_id.clone();
        self.application.on_create(&session_id).await;

        // Typestate: Disconnected -> Connecting (acceptor side).
        let session = Session::<Disconnected>::new(session_id.to_string()).accept();

        let _ = stream.set_nodelay(true);
        let mut framed = Framed::new(stream, session_codec(&self.config, version));

        let mut factory = MessageFactory::new(&self.config, version);
        let identity = PeerIdentity::new(&self.config);
        let sending_time = SendingTimeGuard::new(&self.config);
        let write_timeout = self.write_timeout;
        let store_timeout = self.store.timeout(write_timeout);

        // Await the inbound Logon. Garbled frames are skipped, and the logon
        // timeout covers the whole wait, so a Logon that never arrives intact
        // is a LogonTimeout.
        let logon_frame =
            match read_handshake_frame(&mut framed, self.config.logon_timeout, &session_id).await {
                HandshakeRead::Frame(frame) => frame,
                HandshakeRead::TimedOut => {
                    let _ = session.disconnect();
                    return Err(EngineError::LogonTimeout(self.config.logon_timeout));
                }
                HandshakeRead::Closed => {
                    let _ = session.disconnect();
                    return Err(EngineError::Closed);
                }
                HandshakeRead::Codec(err) => {
                    let _ = session.disconnect();
                    return Err(err.into());
                }
            };

        // Typestate: Connecting -> LogonReceived.
        let session = session.on_logon_received();

        // (gap start, high-water) of a gap detected in the inbound Logon.
        let mut pending_resend: Option<(u64, u64)> = None;
        // The admission claim is taken once identity is validated and moved into
        // the reactor task on success; on any handshake failure after the claim
        // this local drops and frees the slot. These are assigned on the
        // fall-through path out of the block below; every path before an
        // assignment returns first.
        let admission;
        let runtime;
        let mut store;
        let reset;
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
            if reset && self.store.store().is_some() {
                self.store.owe_reset();
            }
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
            runtime = Arc::new(SessionRuntime {
                sequences,
                heartbeat: Mutex::new(HeartbeatManager::new(self.config.heartbeat_interval)),
            });
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
                        &detail,
                        [logout],
                    )
                    .await;
                    let _ = session.reject_logon();
                    refused?;
                    return Err(EngineError::Sequence(detail));
                }
                SequenceResult::Gap { expected, received } => {
                    pending_resend = Some((expected, received));
                }
            }

            // Reply with the Logon acknowledgement, mirroring ResetSeqNumFlag:
            // whichever drove the reset, the ack carries 141=Y so the peer
            // resets in lockstep. `send_handshake_admin` frames it under the
            // next sender sequence number (1 after a reset), files it and
            // persists the next sender number when a store is attached, and
            // spends the number only then.
            let logon_ack = factory.logon(reply_heartbeat_secs, reset);
            if let Err(err) = send_handshake_admin(
                self.application.as_ref(),
                &session_id,
                &mut framed,
                &mut factory,
                &runtime.sequences,
                store.as_mut(),
                write_timeout,
                logon_ack,
            )
            .await
            {
                let _ = session.reject_logon();
                return Err(err);
            }
            lock_heartbeat(&runtime).on_message_sent();
        }

        // The acknowledgement that declared the reset is on the wire: no reset
        // is owed any more.
        if reset {
            self.store.reset_paid();
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
            write_timeout,
            outbound_capacity: self.outbound_capacity,
            app_queue_capacity: self.app_queue_capacity,
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
