/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 14/7/26
******************************************************************************/

//! Client-side (initiator) FIX engine: TCP dial, framing, and a live
//! session reactor.
//!
//! [`Initiator::connect`] dials the counterparty over TCP, frames the byte
//! stream with [`ironfix_transport::FixCodec`], drives the
//! [`ironfix_session`] typestate machine through
//! `connect() -> send_logon() -> on_logon_ack()`, and spawns a background
//! reactor task that owns the socket. The returned [`Connection`] handle is
//! the outbound message sink and exposes `wait_closed()` / `is_timed_out()`.
//!
//! Reconnection is deliberately out of scope: the consumer owns supervision
//! and backoff, and calls [`Initiator::connect`] again for a new session.
//!
//! # Inbound conformance
//!
//! Every inbound frame is checked in this order: decode, `MsgSeqNum` (34)
//! presence, counterparty identity (49/56, plus 50/57 when configured),
//! `SendingTime` (52) accuracy, then heartbeat bookkeeping, then sequence
//! validation. Identity and clock come before the heartbeat bookkeeping
//! deliberately — traffic from the wrong counterparty, or from one whose clock
//! is wrong, must not keep the session alive, reach the [`Application`], or
//! move sequence state.
//!
//! Both of those failures end the session after a Reject and a Logout, because
//! both are systemic rather than per-message: a peer that is cross-wired, or
//! whose clock is two minutes out, will be so on its next message too.
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
//! All sequence arithmetic goes through the checked
//! [`SequenceManager::try_allocate_sender_seq`] /
//! [`SequenceManager::try_increment_target_seq`]; an exhausted counter tears
//! the session down rather than wrapping. A sender number is spent only once
//! the frame that carries it exists, so a body with no legal wire form is a
//! dropped message rather than a hole the counterparty must resend over.
//!
//! # What blocks the reactor, and what does not
//!
//! The reactor is a single task owning the socket. Two things used to be able
//! to park it indefinitely, and neither can now:
//!
//! - **A stalled peer.** A counterparty that stops reading closes its receive
//!   window and parks a socket write forever. Every write is therefore bounded
//!   by [`Initiator::with_write_timeout`], and its expiry closes the session —
//!   the same verdict heartbeat detection would have reached, reached in
//!   bounded time.
//! - **A slow `from_app`.** Inbound application messages are handed to a
//!   separate dispatcher task over a bounded queue
//!   ([`Initiator::with_app_queue_capacity`]), so an application handler never
//!   delays a socket read, a heartbeat, or timeout detection.
//!
//! `to_admin`, `to_app` and `from_admin` still run inline, because each one's
//! result decides what the reactor does next. See [`Application`] for the
//! ordering that buys and the ordering it costs.
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
use crate::connection::{Connection, SessionRuntime};
use crate::error::EngineError;
use crate::reactor::{
    DEFAULT_APP_QUEUE_CAPACITY, DEFAULT_OUTBOUND_CAPACITY, DEFAULT_WRITE_TIMEOUT, ResendState,
    SessionParams, TICK_INTERVAL, lock_heartbeat, send_handshake_admin, spawn_session,
};
use crate::wire::{self, MessageFactory, PeerIdentity, SendingTimeGuard, UnsupportedVersion};
use futures_util::StreamExt;
use ironfix_core::error::DecodeError;
use ironfix_core::message::MsgType;
use ironfix_core::version::FixVersion;
use ironfix_session::config::SessionConfigError;
use ironfix_session::heartbeat::negotiate_interval;
use ironfix_session::sequence::{SequenceCounter, SequenceResult};
use ironfix_session::{Disconnected, HeartbeatManager, SequenceManager, Session, SessionConfig};
use ironfix_store::MessageStore;
use ironfix_transport::FixCodec;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::time::timeout;
use tokio_util::codec::Framed;

/// Client-side FIX engine.
///
/// Owns the session configuration and the [`Application`] callbacks. Each
/// call to [`Initiator::connect`] establishes one live session and returns
/// a [`Connection`] handle for it.
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
    /// Bound on a single socket write.
    write_timeout: Duration,
    /// Initial (sender, target) sequence numbers for session continuity.
    initial_sequences: Option<(u64, u64)>,
    /// Capacity of the outbound command queue.
    outbound_capacity: usize,
    /// Capacity of the inbound application queue.
    app_queue_capacity: usize,
    /// Optional message store: outbound frames are filed here and replayed
    /// from here when the counterparty asks for a resend.
    store: Option<Arc<dyn MessageStore>>,
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
            .field("write_timeout", &self.write_timeout)
            .field("initial_sequences", &self.initial_sequences)
            .field("outbound_capacity", &self.outbound_capacity)
            .field("app_queue_capacity", &self.app_queue_capacity)
            .field("store", &self.store.is_some())
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
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            initial_sequences: None,
            outbound_capacity: DEFAULT_OUTBOUND_CAPACITY,
            app_queue_capacity: DEFAULT_APP_QUEUE_CAPACITY,
            store: None,
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
    /// from the counters the store reports, and both counters are mirrored back
    /// into it as the session runs. Note that
    /// [`MemoryStore`](ironfix_store::MemoryStore) is the only implementation
    /// today and is **not** persistent, so this does not yet survive a restart.
    #[must_use]
    pub fn with_store(mut self, store: Arc<dyn MessageStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Sets the TCP connect timeout (default 30s).
    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
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

    /// Decides the sequence numbers this session starts from.
    ///
    /// Priority, highest first:
    ///
    /// 1. `reset_on_logon` — the Logon declares `ResetSeqNumFlag` (141) = Y, so
    ///    both counters start at 1 and the store is cleared. Keeping the old
    ///    messages would leave two different streams filed under the same
    ///    numbers, and a later `ResendRequest` could not tell them apart.
    /// 2. [`Initiator::with_initial_sequences`] — an explicit instruction from
    ///    the consumer outranks whatever the store remembers.
    /// 3. The store's own counters, refreshed from its backing medium first.
    /// 4. A fresh session at 1/1.
    ///
    /// # Errors
    /// Returns [`EngineError::Store`] if the store cannot be reset (case 1) or
    /// refreshed (case 3). Both are fatal for the handshake: starting at 1 with
    /// the previous stream still filed would let a later `ResendRequest` replay
    /// it, and starting against un-refreshed counters would reuse a `MsgSeqNum`
    /// the counterparty has already seen. The session is refused rather than
    /// silently started from a counter the store could not vouch for.
    async fn seed_sequences(&self) -> Result<SequenceManager, EngineError> {
        if self.config.reset_on_logon {
            if let Some(store) = &self.store
                && let Err(err) = store.reset().await
            {
                tracing::error!(
                    session = %self.session_id,
                    error = %err,
                    "cannot reset the store for a ResetSeqNumFlag logon: refusing the session \
                     rather than starting at 1 with the previous stream still filed"
                );
                return Err(EngineError::Store(err));
            }
            return Ok(SequenceManager::new());
        }

        if let Some((sender, target)) = self.initial_sequences {
            // A zero seed is refused before dialling, so both are non-zero here;
            // the floor keeps the conversion total.
            return Ok(SequenceManager::with_initial(
                NonZeroU64::new(sender).unwrap_or(NonZeroU64::MIN),
                NonZeroU64::new(target).unwrap_or(NonZeroU64::MIN),
            ));
        }

        let Some(store) = &self.store else {
            return Ok(SequenceManager::new());
        };
        if let Err(err) = store.refresh().await {
            tracing::error!(
                session = %self.session_id,
                error = %err,
                "cannot refresh the store: refusing the session rather than starting against \
                 unknown counters and risking a reused MsgSeqNum"
            );
            return Err(EngineError::Store(err));
        }
        // MsgSeqNum starts at 1, so a store reporting 0 is reporting a number
        // that names no message. Floor it rather than number a message 0.
        Ok(SequenceManager::with_initial(
            NonZeroU64::new(store.next_sender_seq().max(1)).unwrap_or(NonZeroU64::MIN),
            NonZeroU64::new(store.next_target_seq().max(1)).unwrap_or(NonZeroU64::MIN),
        ))
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
    /// # Arguments
    /// * `addr` - The counterparty address to dial
    ///
    /// # Errors
    /// Returns an [`EngineError`] if the dial, framing, or Logon handshake
    /// fails. Beyond timeouts and transport failures that includes
    /// [`EngineError::IdentityMismatch`], when the ack's CompIDs do not match
    /// the configured session, and [`EngineError::SequenceExhausted`], when a
    /// sequence counter has reached `u64::MAX` and the session must be reset
    /// before it can number another message. A `BeginString` this engine
    /// cannot frame conformantly is refused up front with
    /// [`EngineError::UnsupportedVersion`], an unusable configuration with
    /// [`EngineError::Config`], and a zero initial sequence seed with
    /// [`EngineError::InvalidInitialSequence`], all before the socket is
    /// dialled.
    pub async fn connect(&self, addr: impl ToSocketAddrs) -> Result<Connection, EngineError> {
        // Refuse before dialling: a knob outside its documented range corrupts
        // the session's own messages — an identity string carrying SOH breaks
        // every header, and a fractional HeartBtInt negotiates one interval
        // while the local timers run another.
        if let Err(err) = &self.config_check {
            return Err(EngineError::Config(err.clone()));
        }

        // Refuse before dialling: an unsupported version cannot produce a
        // conforming Logon, and guessing one would put a fabricated version on
        // the wire.
        let version = match &self.version {
            Ok(version) => *version,
            Err(err) => {
                return Err(EngineError::UnsupportedVersion {
                    version: err.version.clone(),
                    detail: err.detail.clone(),
                });
            }
        };

        // Refuse before dialling: a seeded sequence number of zero would put
        // MsgSeqNum (34) = 0 on the wire, which every conforming counterparty
        // rejects. The seed is ignored entirely when reset_on_logon is set, so
        // a zero is only refused when it would actually be used. The validated
        // seed is applied by `seed_sequences`, which reads the same field; this
        // is only the guard.
        if let Some((sender, target)) = self.initial_sequences
            && !self.config.reset_on_logon
        {
            NonZeroU64::new(sender).ok_or(EngineError::InvalidInitialSequence {
                counter: SequenceCounter::Sender,
            })?;
            NonZeroU64::new(target).ok_or(EngineError::InvalidInitialSequence {
                counter: SequenceCounter::Target,
            })?;
        }

        let session_id = self.session_id.clone();
        self.application.on_create(&session_id).await;

        // Typestate: Disconnected -> Connecting.
        let session = Session::<Disconnected>::new(session_id.to_string()).connect();

        let stream = match timeout(self.connect_timeout, TcpStream::connect(addr)).await {
            Err(_) => {
                let _ = session.disconnect();
                return Err(EngineError::ConnectTimeout(self.connect_timeout));
            }
            Ok(Err(err)) => {
                let _ = session.disconnect();
                return Err(err.into());
            }
            Ok(Ok(stream)) => stream,
        };
        let _ = stream.set_nodelay(true);

        let codec = FixCodec::new()
            .with_max_message_size(self.config.max_message_size)
            .with_checksum_validation(self.config.validate_checksum);
        let mut framed = Framed::new(stream, codec);

        // Seeding fails closed: a store that cannot be reset or refreshed leaves
        // the session unable to vouch for its own counters, so it is refused
        // here rather than started from a number that could collide with a
        // stream still on file.
        let sequences = match self.seed_sequences().await {
            Ok(sequences) => sequences,
            Err(err) => {
                let _ = session.disconnect();
                return Err(err);
            }
        };
        let runtime = Arc::new(SessionRuntime {
            sequences,
            heartbeat: Mutex::new(HeartbeatManager::new(self.config.heartbeat_interval)),
        });
        let mut factory = MessageFactory::new(&self.config, version);
        let identity = PeerIdentity::new(&self.config);
        let sending_time = SendingTimeGuard::new(&self.config);
        let write_timeout = self.write_timeout;
        let store = self.store.as_ref();

        // Typestate: Connecting -> LogonSent.
        //
        // `to_admin` runs on the message before it is framed, so a stamped
        // Username/Password reaches the wire — the callback's whole purpose.
        let logon = factory.logon(
            self.config.heartbeat_interval_secs(),
            self.config.reset_on_logon,
        );
        if let Err(err) = send_handshake_admin(
            self.application.as_ref(),
            &session_id,
            &mut framed,
            &mut factory,
            &runtime.sequences,
            store,
            write_timeout,
            logon,
        )
        .await
        {
            let _ = session.disconnect();
            return Err(err);
        }
        lock_heartbeat(&runtime).on_message_sent();
        let session = session.send_logon();

        // Await the Logon acknowledgement.
        let ack = match timeout(self.config.logon_timeout, framed.next()).await {
            Err(_) => {
                let _ = session.on_logon_reject();
                return Err(EngineError::LogonTimeout(self.config.logon_timeout));
            }
            Ok(None) => {
                let _ = session.on_logon_reject();
                return Err(EngineError::Closed);
            }
            Ok(Some(Err(err))) => {
                let _ = session.on_logon_reject();
                return Err(err.into());
            }
            Ok(Some(Ok(frame))) => frame,
        };

        // (gap start, high-water) of a gap detected in the Logon ack itself.
        let mut pending_resend: Option<(u64, u64)> = None;
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

            let ack_seq: u64 = raw.get_field_as(34)?;

            // Identity before anything else: a cross-wired acceptor must not
            // be allowed to establish a session or move sequence state.
            if let Err(mismatch) = identity.validate(&raw) {
                let detail = mismatch.to_string();
                let reason = RejectReason::new(9, detail.clone()).with_ref_tag(mismatch.tag);
                let reject = factory.session_reject(ack_seq, MsgType::Logon.as_str(), &reason);
                let _ = send_handshake_admin(
                    self.application.as_ref(),
                    &session_id,
                    &mut framed,
                    &mut factory,
                    &runtime.sequences,
                    store,
                    write_timeout,
                    reject,
                )
                .await;
                let logout = factory.logout(Some(&detail));
                let _ = send_handshake_admin(
                    self.application.as_ref(),
                    &session_id,
                    &mut framed,
                    &mut factory,
                    &runtime.sequences,
                    store,
                    write_timeout,
                    logout,
                )
                .await;
                let _ = session.on_logon_reject();
                return Err(EngineError::IdentityMismatch { detail });
            }

            // The clock is checked on the ack for the same reason it is checked
            // on every later frame: a peer whose SendingTime is wildly skewed
            // cannot be trusted to sequence a session, and the handshake is the
            // cheapest place to refuse it.
            if let Err(problem) = sending_time.validate(&raw) {
                let detail = problem.to_string();
                let reason = problem.reject_reason();
                let reject = factory.session_reject(ack_seq, MsgType::Logon.as_str(), &reason);
                let _ = send_handshake_admin(
                    self.application.as_ref(),
                    &session_id,
                    &mut framed,
                    &mut factory,
                    &runtime.sequences,
                    store,
                    write_timeout,
                    reject,
                )
                .await;
                let logout = factory.logout(Some(&detail));
                let _ = send_handshake_admin(
                    self.application.as_ref(),
                    &session_id,
                    &mut framed,
                    &mut factory,
                    &runtime.sequences,
                    store,
                    write_timeout,
                    logout,
                )
                .await;
                let _ = session.on_logon_reject();
                return Err(EngineError::SendingTime { detail });
            }

            if let Err(reason) = self.application.from_admin(&raw, &session_id).await {
                let logout = factory.logout(Some(&reason.text));
                if let Err(err) = send_handshake_admin(
                    self.application.as_ref(),
                    &session_id,
                    &mut framed,
                    &mut factory,
                    &runtime.sequences,
                    store,
                    write_timeout,
                    logout,
                )
                .await
                {
                    tracing::warn!(
                        session = %session_id,
                        error = %err,
                        "cannot send Logout after from_admin rejection"
                    );
                }
                let _ = session.on_logon_reject();
                return Err(EngineError::LogonRejected {
                    reason: reason.text,
                });
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
                    let (code, detail) = if matches!(err, DecodeError::MissingRequiredField { .. })
                    {
                        (
                            1,
                            "Logon acknowledgement omitted the required HeartBtInt (108)"
                                .to_string(),
                        )
                    } else {
                        (6, err.to_string())
                    };
                    let reason = RejectReason::new(code, detail.clone()).with_ref_tag(108);
                    let reject = factory.session_reject(ack_seq, MsgType::Logon.as_str(), &reason);
                    let _ = send_handshake_admin(
                        self.application.as_ref(),
                        &session_id,
                        &mut framed,
                        &mut factory,
                        &runtime.sequences,
                        store,
                        write_timeout,
                        reject,
                    )
                    .await;
                    let logout = factory.logout(Some(&detail));
                    let _ = send_handshake_admin(
                        self.application.as_ref(),
                        &session_id,
                        &mut framed,
                        &mut factory,
                        &runtime.sequences,
                        store,
                        write_timeout,
                        logout,
                    )
                    .await;
                    let _ = session.on_logon_reject();
                    return Err(EngineError::HeartbeatInterval { detail });
                }
            };
            let negotiated = match negotiate_interval(self.config.heartbeat_interval, secs) {
                Ok(interval) => interval,
                Err(err) => {
                    let detail = err.to_string();
                    let reason = RejectReason::new(5, detail.clone()).with_ref_tag(108);
                    let reject = factory.session_reject(ack_seq, MsgType::Logon.as_str(), &reason);
                    let _ = send_handshake_admin(
                        self.application.as_ref(),
                        &session_id,
                        &mut framed,
                        &mut factory,
                        &runtime.sequences,
                        store,
                        write_timeout,
                        reject,
                    )
                    .await;
                    let logout = factory.logout(Some(&detail));
                    let _ = send_handshake_admin(
                        self.application.as_ref(),
                        &session_id,
                        &mut framed,
                        &mut factory,
                        &runtime.sequences,
                        store,
                        write_timeout,
                        logout,
                    )
                    .await;
                    let _ = session.on_logon_reject();
                    return Err(EngineError::HeartbeatInterval { detail });
                }
            };
            {
                let mut heartbeat = lock_heartbeat(&runtime);
                heartbeat.on_message_received(false, None);
                if negotiated != heartbeat.interval() {
                    tracing::info!(
                        session = %session_id,
                        heartbeat_secs = negotiated.as_secs(),
                        "using heartbeat interval confirmed by counterparty"
                    );
                    *heartbeat = HeartbeatManager::new(negotiated);
                }
            }

            // ResetSeqNumFlag (141) on the ack is a counterparty-driven
            // reset and must be honored before MsgSeqNum is validated,
            // otherwise the ack's 34=1 reads as fatally too low against
            // continuity-seeded counters.
            if raw.get_field_str(141) == Some("Y") {
                // FIX requires MsgSeqNum = 1 on a Logon carrying
                // ResetSeqNumFlag = Y: the reset and the number it arrives
                // under have to agree. A peer that declares a reset and then
                // numbers the message anything else is describing two
                // different streams, so the handshake fails rather than
                // guessing which half to believe.
                if ack_seq != 1 {
                    let _ = session.on_logon_reject();
                    return Err(EngineError::Sequence(format!(
                        "Logon ack set ResetSeqNumFlag=Y but carried MsgSeqNum {ack_seq}, not 1"
                    )));
                }
                tracing::info!(
                    session = %session_id,
                    "counterparty set ResetSeqNumFlag on the Logon ack: resetting sequence numbers"
                );
                runtime.sequences.set_target_seq(1);
                // The Logon already on the wire is message 1 of the reset
                // outbound stream; rewinding the sender counter to 1 would
                // re-emit a MsgSeqNum the counterparty has already seen.
                runtime.sequences.set_sender_seq(2);
            }

            match runtime.sequences.validate_incoming(ack_seq) {
                SequenceResult::Ok => {
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
                SequenceResult::Gap { expected, received } => {
                    pending_resend = Some((expected, received));
                }
            }
        }

        // Typestate: LogonSent -> Active.
        let session = session.on_logon_ack();
        self.application.on_logon(&session_id).await;
        tracing::info!(session = %session_id, "FIX session established");

        // A gap in the Logon ack means we missed messages: request a resend.
        if let Some((expected, _high_water)) = pending_resend {
            let request = factory.resend_request(expected, 0);
            send_handshake_admin(
                self.application.as_ref(),
                &session_id,
                &mut framed,
                &mut factory,
                &runtime.sequences,
                store,
                write_timeout,
                request,
            )
            .await?;
            lock_heartbeat(&runtime).on_message_sent();
        }

        let resend = pending_resend
            .map(|(expected, high_water)| ResendState::first(expected, high_water, &self.config));
        // Hand the framed socket to the shared reactor. The initiator carries no
        // admission guard, so the guard is `()`.
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
            store: self.store.clone(),
            resend,
            write_timeout,
            outbound_capacity: self.outbound_capacity,
            app_queue_capacity: self.app_queue_capacity,
        };
        let (command_tx, closed_rx) = spawn_session(params, ());

        Ok(Connection {
            session_id,
            commands: command_tx,
            closed: closed_rx,
            runtime,
        })
    }
}
