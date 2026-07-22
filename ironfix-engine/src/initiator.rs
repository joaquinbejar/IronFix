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
//! presence, counterparty identity (49/56, plus 50/57 when configured), then
//! heartbeat bookkeeping, then sequence validation. Identity comes before the
//! heartbeat clock deliberately — traffic from the wrong counterparty must not
//! keep the session alive, reach the [`Application`], or move sequence state.
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
use crate::connection::{Command, Connection, SessionRuntime};
use crate::error::EngineError;
use crate::outbound;
use crate::wire::{self, MessageFactory, PeerIdentity, PendingMessage, UnsupportedVersion};
use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use ironfix_core::error::{DecodeError, EncodeError};
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::version::FixVersion;
use ironfix_session::config::SessionConfigError;
use ironfix_session::heartbeat::{generate_test_req_id, negotiate_interval};
use ironfix_session::sequence::{SequenceCounter, SequenceExhausted, SequenceResult};
use ironfix_session::{
    Active, Disconnected, HeartbeatManager, LogoutPending, SequenceManager, Session, SessionConfig,
    TestRequestOutcome,
};
use ironfix_store::MessageStore;
use ironfix_transport::FixCodec;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval, timeout};
use tokio_util::codec::Framed;

/// Framed TCP stream carrying FIX messages.
type FixFramed = Framed<TcpStream, FixCodec>;

/// Default capacity of the outbound command queue.
const DEFAULT_OUTBOUND_CAPACITY: usize = 1024;

/// Default capacity of the inbound application queue, in messages.
///
/// The queue is bounded by message **count**, not bytes, and each entry retains
/// its whole frame (a reference-counted [`Bytes`] up to
/// [`SessionConfig::max_message_size`]). The worst-case retained memory is
/// therefore `capacity * max_message_size`: with the defaults, 1024 * 1 MiB =
/// 1 GiB, and up to 1024 * 64 MiB = 64 GiB if `max_message_size` is raised to
/// its ceiling. See [`Initiator::with_app_queue_capacity`] to size it.
const DEFAULT_APP_QUEUE_CAPACITY: usize = 1024;

/// Default bound on a single socket write.
const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the reactor waits for the application dispatcher to finish the
/// messages already queued before it reports the session closed.
///
/// The dispatcher always terminates — its queue is closed when the reactor
/// drops the sender — so this only bounds how long `on_logout` waits to follow
/// the last `from_app` rather than run beside it.
const APP_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Reactor tick granularity for heartbeat/timeout checks.
const TICK_INTERVAL: Duration = Duration::from_millis(100);

/// Number of stored messages a resend reads from the store per page.
///
/// A `ResendRequest` with `EndSeqNo` (16) = 0 asks for the whole session, so the
/// replay reads in bounded batches and yields between them rather than
/// allocating and locking over the entire history at once. The value trades the
/// per-page allocation ceiling against how often the reactor yields; a few
/// hundred frames keeps both modest.
const RESEND_PAGE_LIMIT: usize = 256;

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

        let mut pending_resend = None;
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
                SequenceResult::Gap { expected, .. } => pending_resend = Some(expected),
            }
        }

        // Typestate: LogonSent -> Active.
        let session = session.on_logon_ack();
        self.application.on_logon(&session_id).await;
        tracing::info!(session = %session_id, "FIX session established");

        // A gap in the Logon ack means we missed messages: request a resend.
        if let Some(expected) = pending_resend {
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

        let (command_tx, command_rx) = mpsc::channel(self.outbound_capacity);
        let (closed_tx, closed_rx) = watch::channel(false);
        let (app_tx, app_rx) = mpsc::channel(self.app_queue_capacity);
        let (reject_tx, reject_rx) = mpsc::channel(self.app_queue_capacity);

        // The dispatcher stops when the reactor drops `app_tx`, which
        // `run_reactor` does on every exit path.
        let dispatcher = tokio::spawn(run_app_dispatcher(
            Arc::clone(&self.application),
            session_id.clone(),
            app_rx,
            reject_tx,
        ));

        let reactor = Reactor {
            factory,
            identity,
            runtime: Arc::clone(&runtime),
            config: self.config.clone(),
            application: Arc::clone(&self.application),
            session_id: session_id.clone(),
            store: self.store.clone(),
            pending_resend,
            write_timeout,
            app_tx,
        };
        reactor.sync_sequences();
        let channels = ReactorChannels {
            commands: command_rx,
            app_rejects: reject_rx,
            closed: closed_tx,
            dispatcher,
        };
        tokio::spawn(run_reactor(framed, channels, reactor, session));

        Ok(Connection {
            session_id,
            commands: command_tx,
            closed: closed_rx,
            runtime,
        })
    }
}

/// Runs `to_admin`, checks the body, and writes one administrative frame
/// during the handshake, before the reactor exists.
///
/// Every administrative message goes through the callback, including the ones
/// on the failure paths: now that a mutation is effective, a counterparty that
/// requires a stamped field requires it on the Reject and the Logout too. When
/// a store is attached the frame is filed and the sender counter mirrored, the
/// same as [`send_handshake`] does.
///
/// # Errors
/// The same as [`send_handshake`], plus [`EngineError::ReservedTag`] /
/// [`EngineError::InvalidField`] when the callback left a body the engine will
/// not frame.
#[allow(clippy::too_many_arguments)]
async fn send_handshake_admin<A: Application>(
    application: &A,
    session_id: &SessionId,
    framed: &mut FixFramed,
    factory: &mut MessageFactory,
    sequences: &SequenceManager,
    store: Option<&Arc<dyn MessageStore>>,
    write_timeout: Duration,
    mut pending: PendingMessage,
) -> Result<(), EngineError> {
    application
        .to_admin(pending.message_mut(), session_id)
        .await;
    outbound::check_body(pending.message())?;
    send_handshake(
        session_id,
        framed,
        factory,
        sequences,
        store,
        write_timeout,
        &pending,
    )
    .await
}

/// Encodes and writes one frame during the handshake, before the reactor
/// exists.
///
/// The sequence number is peeked, the frame is built, and only then is the
/// number spent — the same order the reactor uses. A body with no legal wire
/// form therefore costs nothing, instead of leaving a hole the counterparty
/// would have to resend over. When a store is attached the frame is filed under
/// its `MsgSeqNum` and the sender counter mirrored into it before it goes on the
/// wire, so a store reused across a reconnect can replay it and never reports a
/// number the peer has already seen.
///
/// # Errors
/// [`EngineError::Encode`] when the body has no legal wire form,
/// [`EngineError::SequenceExhausted`] when the sender counter has reached
/// `u64::MAX`, [`EngineError::WriteTimeout`] when the peer is not reading, and
/// the transport's own error otherwise.
async fn send_handshake(
    session_id: &SessionId,
    framed: &mut FixFramed,
    factory: &mut MessageFactory,
    sequences: &SequenceManager,
    store: Option<&Arc<dyn MessageStore>>,
    write_timeout: Duration,
    pending: &PendingMessage,
) -> Result<(), EngineError> {
    let seq = sequences.next_sender_seq().value();
    let frame = factory.encode(seq, pending)?;
    let allocated = sequences.try_allocate_sender_seq()?.value();
    if allocated != seq {
        return Err(EngineError::Sequence(format!(
            "sender sequence moved from {seq} to {allocated} while a frame was being built"
        )));
    }
    // File the frame and mirror the sender counter before it reaches the wire:
    // a message on the wire that was never stored is one this session can be
    // asked to replay and cannot.
    mirror_sender_seq(store, sequences);
    persist_outbound(store, session_id, seq, pending.msg_type(), frame).await;
    match timeout(write_timeout, framed.send(frame)).await {
        Err(_) => Err(EngineError::WriteTimeout(write_timeout)),
        Ok(Err(err)) => Err(err.into()),
        Ok(Ok(())) => Ok(()),
    }
}

/// Mirrors the sender sequence counter into the store, if one is attached.
///
/// The reactor mirrors both counters after every event through
/// [`Reactor::sync_sequences`], but the reactor does not exist yet during the
/// Logon handshake. This closes the window: it is called after each handshake
/// frame is numbered, before that frame reaches the wire, so a store reused
/// across a reconnect never reports a sender counter behind a `MsgSeqNum` the
/// counterparty has already seen. Only the sender counter is mirrored; the
/// target counter advances only once an inbound message is accepted, which the
/// reactor then mirrors.
fn mirror_sender_seq(store: Option<&Arc<dyn MessageStore>>, sequences: &SequenceManager) {
    if let Some(store) = store {
        store.set_next_sender_seq(sequences.next_sender_seq().value());
    }
}

/// Files one outbound frame under the sequence number it was sent with.
///
/// A store failure is logged and the session continues: a message that could
/// not be filed simply cannot be replayed, and the resend path already covers
/// an unavailable sequence number with a gap fill. Tearing a healthy session
/// down over it would be a worse outcome than a gap fill.
///
/// The frame body is **never** logged. A Logon carries `Password` (554) and
/// `NewPassword` (925), and any message may carry `RawData` (96); the log line
/// names the sequence number and the message type only.
async fn persist_outbound(
    store: Option<&Arc<dyn MessageStore>>,
    session_id: &SessionId,
    seq: u64,
    msg_type: &MsgType,
    frame: &[u8],
) {
    let Some(store) = store else {
        return;
    };
    if let Err(err) = store.store(seq, msg_type, frame).await {
        tracing::warn!(
            session = %session_id,
            seq,
            msg_type = msg_type.as_str(),
            error = %err,
            "cannot store outbound message: a resend of it will be gap-filled"
        );
    }
}

/// Locks the shared heartbeat manager.
///
/// A poisoned lock means a previous holder panicked. The heartbeat state is
/// plain timestamps with no invariant a panic could leave half-applied, so
/// the guard is recovered rather than propagated: the release profile is
/// `panic = "abort"`, and taking the consumer's process down over a
/// heartbeat timestamp is never the right trade.
fn lock_heartbeat(runtime: &SessionRuntime) -> std::sync::MutexGuard<'_, HeartbeatManager> {
    runtime
        .heartbeat
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Runtime session phase, wrapping the typestate session so the reactor can
/// transition it dynamically.
enum Phase {
    /// Session is established.
    Active(Session<Active>),
    /// A locally initiated Logout is awaiting acknowledgement.
    LogoutPending(Session<LogoutPending>),
}

/// Terminal outcome of the reactor loop.
struct SessionClosed {
    /// Human-readable close reason (logged).
    reason: String,
    /// True when the session ended through a Logout exchange.
    graceful: bool,
}

/// Builds a [`SessionClosed`] outcome.
fn closed(reason: impl Into<String>, graceful: bool) -> SessionClosed {
    SessionClosed {
        reason: reason.into(),
        graceful,
    }
}

/// Consumes a phase on an abnormal close, driving the typestate to
/// Disconnected.
fn teardown(phase: Phase) {
    match phase {
        Phase::Active(session) => {
            let _ = session.disconnect();
        }
        Phase::LogoutPending(session) => {
            let _ = session.on_timeout();
        }
    }
}

/// Tears the session down because a sequence counter is exhausted.
///
/// A wrapped MsgSeqNum corrupts a live session, so exhaustion is a terminal
/// condition rather than something to paper over.
fn exhausted(phase: Phase, err: SequenceExhausted) -> SessionClosed {
    teardown(phase);
    closed(err.to_string(), false)
}

/// One inbound application message on its way to the dispatcher task.
///
/// Carries the frame as [`Bytes`], which the reactor already owns, so handing
/// it over is a reference-count bump rather than a copy.
#[derive(Debug)]
struct AppFrame {
    /// The complete frame.
    frame: Bytes,
    /// Its `MsgSeqNum` (34), already validated by the reactor.
    seq: u64,
}

/// A rejection the application returned from `from_app`, on its way back to
/// the reactor as a session-level Reject.
#[derive(Debug)]
struct AppRejection {
    /// `RefSeqNum` (45): the MsgSeqNum of the rejected message.
    ref_seq: u64,
    /// `RefMsgType` (372).
    ref_msg_type: MsgType,
    /// The reason the application gave.
    reason: RejectReason,
}

/// Runs `from_app` off the reactor.
///
/// Messages arrive in the order the reactor validated them, and this task is
/// their only consumer, so the application sees them in ascending `MsgSeqNum`
/// order. A rejection travels back to the reactor, which numbers and sends the
/// session-level Reject; nothing here touches session state.
///
/// The task ends when the reactor drops the queue's sender, which every exit
/// path of [`run_reactor`] does.
async fn run_app_dispatcher<A: Application>(
    application: Arc<A>,
    session_id: SessionId,
    mut frames: mpsc::Receiver<AppFrame>,
    rejections: mpsc::Sender<AppRejection>,
) {
    while let Some(AppFrame { frame, seq }) = frames.recv().await {
        // The reactor decoded this frame already; a failure here cannot
        // happen, and inventing a session action for it is not this task's
        // job.
        let Ok(raw) = wire::decode_frame(&frame) else {
            tracing::warn!(
                session = %session_id,
                seq,
                "dropping an application message that no longer decodes"
            );
            continue;
        };
        if let Err(reason) = application.from_app(&raw, &session_id).await {
            let rejection = AppRejection {
                ref_seq: seq,
                ref_msg_type: raw.msg_type().clone(),
                reason,
            };
            if rejections.send(rejection).await.is_err() {
                // The reactor is gone; the session it would have rejected
                // into no longer exists.
                break;
            }
        }
    }
}

/// Everything the reactor loop owns besides the socket and the session.
struct ReactorChannels {
    /// Commands from [`Connection`] handles.
    commands: mpsc::Receiver<Command>,
    /// Rejections coming back from the application dispatcher.
    app_rejects: mpsc::Receiver<AppRejection>,
    /// Closed-flag channel observed by [`Connection::wait_closed`].
    closed: watch::Sender<bool>,
    /// The application dispatcher, joined on close so `on_logout` follows the
    /// last `from_app` rather than racing it.
    dispatcher: JoinHandle<()>,
}

/// Reactor state shared across event handlers.
struct Reactor<A: Application> {
    /// Outbound frame factory, holding the encoder reused for every message.
    factory: MessageFactory,
    /// Identity every inbound message must carry.
    identity: PeerIdentity,
    /// Shared session runtime (sequences + heartbeat).
    runtime: Arc<SessionRuntime>,
    /// Session configuration.
    config: SessionConfig,
    /// Application callbacks.
    application: Arc<A>,
    /// Session identifier.
    session_id: SessionId,
    /// Optional message store for outbound frames and resend replay.
    store: Option<Arc<dyn MessageStore>>,
    /// Expected sequence number a pending ResendRequest was issued for.
    ///
    /// The logout deadline is *not* tracked here: `Session<LogoutPending>`
    /// carries the instant the Logout went out, so the phase itself is the
    /// deadline.
    pending_resend: Option<u64>,
    /// Bound on a single socket write.
    write_timeout: Duration,
    /// Hand-off queue to the application dispatcher.
    app_tx: mpsc::Sender<AppFrame>,
}

/// The session reactor: owns the socket, multiplexes inbound frames,
/// outbound commands, application rejections, and heartbeat timers until the
/// session closes.
async fn run_reactor<A: Application + 'static>(
    mut framed: FixFramed,
    channels: ReactorChannels,
    mut ctx: Reactor<A>,
    session: Session<Active>,
) {
    let ReactorChannels {
        mut commands,
        mut app_rejects,
        closed: closed_tx,
        mut dispatcher,
    } = channels;
    let mut phase = Some(Phase::Active(session));
    let mut commands_open = true;
    let mut rejects_open = true;
    let mut tick = interval(TICK_INTERVAL);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let outcome = loop {
        // The phase is put back by every handler that does not close the
        // session, so it is always present here. Treating its absence as a
        // close keeps the reactor panic-free rather than relying on that.
        let Some(current) = phase.take() else {
            break closed("internal error: session phase lost", false);
        };
        let result = tokio::select! {
            inbound = framed.next() => match inbound {
                Some(Ok(frame)) => ctx.on_frame(&mut framed, current, frame).await,
                Some(Err(err)) => {
                    teardown(current);
                    Err(closed(format!("codec error: {err}"), false))
                }
                None => {
                    teardown(current);
                    Err(closed("transport closed by peer", false))
                }
            },
            command = commands.recv(), if commands_open => match command {
                Some(command) => ctx.on_command(&mut framed, current, command).await,
                None => {
                    // All handles dropped: log out gracefully.
                    commands_open = false;
                    ctx.on_command(&mut framed, current, Command::Logout).await
                }
            },
            rejection = app_rejects.recv(), if rejects_open => match rejection {
                Some(rejection) => {
                    let ref_msg_type = rejection.ref_msg_type.as_str().to_string();
                    ctx.send_session_reject(
                        &mut framed,
                        current,
                        rejection.ref_seq,
                        &ref_msg_type,
                        &rejection.reason,
                    )
                    .await
                }
                None => {
                    // The dispatcher stopped; nothing more can be rejected.
                    rejects_open = false;
                    Ok(current)
                }
            },
            _ = tick.tick() => ctx.on_tick(&mut framed, current).await,
        };
        match result {
            Ok(next) => phase = Some(next),
            Err(outcome) => break outcome,
        }
        // One place, after every handled event, so no path can advance a
        // counter without the store seeing it.
        ctx.sync_sequences();
    };

    if ctx.config.reset_on_disconnect || (outcome.graceful && ctx.config.reset_on_logout) {
        ctx.runtime.sequences.reset();
        // The stored messages go with the counters. Leaving them behind would
        // file the next session's messages on top of this one's, and a resend
        // request in that session could answer with traffic from this one.
        if let Some(store) = &ctx.store
            && let Err(err) = store.reset().await
        {
            tracing::warn!(
                session = %ctx.session_id,
                error = %err,
                "cannot clear the store after a session-closing sequence reset"
            );
        }
    }
    ctx.sync_sequences();

    // Closing the queue is what stops the dispatcher; joining it is what keeps
    // `on_logout` from running beside a `from_app` still in flight. A wedged
    // handler bounds the wait rather than the shutdown — and is then aborted, so
    // it cannot outlive `on_logout`/`wait_closed`. Awaiting `&mut dispatcher`
    // keeps ownership of the handle across the timeout: dropping it would only
    // detach the task, leaving the stuck handler running.
    drop(ctx.app_tx);
    if timeout(APP_DRAIN_TIMEOUT, &mut dispatcher).await.is_err() {
        dispatcher.abort();
        tracing::warn!(
            session = %ctx.session_id,
            "application dispatcher did not drain before the session closed; aborting it"
        );
    }

    ctx.application.on_logout(&ctx.session_id).await;
    let _ = closed_tx.send(true);
    if outcome.graceful {
        tracing::info!(session = %ctx.session_id, reason = %outcome.reason, "FIX session closed");
    } else {
        tracing::warn!(session = %ctx.session_id, reason = %outcome.reason, "FIX session closed");
    }
}

/// Why an outbound message never reached the transport.
enum WriteFailure {
    /// The body has no legal wire form. **No sequence number was spent**, so
    /// the session is intact and the message can simply be dropped.
    Encode(EncodeError),
    /// The session cannot continue.
    Fatal(EngineError),
}

/// Whether an outbound message actually reached the transport.
///
/// [`Reactor::send`] returning `Ok` used to conflate "sent" with "dropped
/// because a callback left the body unsendable". A caller that arms follow-on
/// state — the logout deadline, a pending TestRequest, a pending resend — must
/// distinguish the two, or it advances the session on a frame the peer never
/// saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sent {
    /// The frame went out and a sequence number was spent.
    Yes,
    /// The message was dropped before the wire: `to_admin`/`to_app` left it
    /// unframeable or dropped a required field. No sequence number was spent
    /// and the session is intact.
    Dropped,
}

impl<A: Application> Reactor<A> {
    /// Mirrors both sequence counters into the store.
    ///
    /// The counters are the store's other job: they are what lets a later
    /// session pick up where this one stopped. Both trait methods are
    /// synchronous, so this costs two atomic stores and holds no lock.
    fn sync_sequences(&self) {
        let Some(store) = &self.store else {
            return;
        };
        store.set_next_sender_seq(self.runtime.sequences.next_sender_seq().value());
        store.set_next_target_seq(self.runtime.sequences.next_target_seq().value());
    }

    /// Frames `pending` under an explicit `seq` and writes it, bounded by the
    /// write timeout. Spends no sequence number.
    ///
    /// When `persist` is set and a store is attached the frame is filed under
    /// `seq` before it goes on the wire. A gap fill passes `false`: it
    /// re-occupies a range it does not own, so filing it would overwrite a
    /// message under `seq` that is still resendable.
    ///
    /// # Errors
    /// [`WriteFailure::Encode`] leaves the session untouched — nothing was
    /// written and nothing was spent. [`WriteFailure::Fatal`] does not: a
    /// stalled or broken transport ends the session.
    async fn write_at(
        &mut self,
        framed: &mut FixFramed,
        seq: u64,
        pending: &PendingMessage,
        persist: bool,
    ) -> Result<(), WriteFailure> {
        let write_timeout = self.write_timeout;
        let frame = match self.factory.encode(seq, pending) {
            Ok(frame) => frame,
            Err(err) => return Err(WriteFailure::Encode(err)),
        };
        if persist {
            persist_outbound(
                self.store.as_ref(),
                &self.session_id,
                seq,
                pending.msg_type(),
                frame,
            )
            .await;
        }
        // A peer that stops reading parks this write forever once its receive
        // window closes, and the reactor's liveness timers park with it.
        match timeout(write_timeout, framed.send(frame)).await {
            Err(_) => Err(WriteFailure::Fatal(EngineError::WriteTimeout(
                write_timeout,
            ))),
            Ok(Err(err)) => Err(WriteFailure::Fatal(err.into())),
            Ok(Ok(())) => Ok(()),
        }
    }

    /// Runs the outbound application callback, checks the body, files the
    /// frame, frames the message under the next sender sequence number and
    /// writes it.
    ///
    /// `to_admin` or `to_app` is chosen by the MsgType, and each runs on the
    /// message **before** it is framed, so what the callback hands back is what
    /// goes on the wire.
    ///
    /// The sequence number is peeked to frame the message and spent only once
    /// the frame has actually gone out. A body with no legal wire form is
    /// therefore dropped with a warning and [`Sent::Dropped`] is returned: the
    /// session is intact and there is no hole for the counterparty to resend
    /// over. A caller that arms follow-on state — the logout deadline, a
    /// pending TestRequest, a pending resend — must act only on [`Sent::Yes`],
    /// or it advances the session on a frame the peer never saw. Only the
    /// reactor allocates sender sequence numbers and only this method writes, so
    /// nothing can take the peeked number in between — the mismatch branch
    /// exists so a wrong `MsgSeqNum` can never reach the wire, not because it is
    /// reachable.
    ///
    /// # Errors
    /// Every [`EngineError`] returned here is terminal for the session: an
    /// exhausted sender counter, a write timeout, or a transport failure.
    async fn send(
        &mut self,
        framed: &mut FixFramed,
        mut pending: PendingMessage,
    ) -> Result<Sent, EngineError> {
        if !self.prepare(&mut pending).await {
            return Ok(Sent::Dropped);
        }
        let seq = self.runtime.sequences.next_sender_seq().value();
        match self.write_at(framed, seq, &pending, true).await {
            Ok(()) => {}
            Err(WriteFailure::Encode(err)) => {
                tracing::warn!(
                    session = %self.session_id,
                    error = %err,
                    "dropping outbound message with no legal wire form; no sequence number spent"
                );
                return Ok(Sent::Dropped);
            }
            Err(WriteFailure::Fatal(err)) => return Err(err),
        }
        let allocated = self.runtime.sequences.try_allocate_sender_seq()?.value();
        if allocated != seq {
            return Err(EngineError::Sequence(format!(
                "sender sequence moved from {seq} to {allocated} while a frame was being built"
            )));
        }
        mirror_sender_seq(self.store.as_ref(), &self.runtime.sequences);
        lock_heartbeat(&self.runtime).on_message_sent();
        Ok(Sent::Yes)
    }

    /// Runs `to_admin` / `to_app` on `pending` and rechecks its body.
    ///
    /// Returns `false` when the callback left a body the engine will not
    /// frame — a tag the standard header already carries, or a value with no
    /// wire form. The message is then dropped; the warning names the tag and
    /// never the value, because an outbound Logon body carries `Password`
    /// (554).
    async fn prepare(&mut self, pending: &mut PendingMessage) -> bool {
        if pending.msg_type().is_admin() {
            self.application
                .to_admin(pending.message_mut(), &self.session_id)
                .await;
        } else {
            self.application
                .to_app(pending.message_mut(), &self.session_id)
                .await;
        }
        if let Err(err) = outbound::check_body(pending.message()) {
            tracing::warn!(
                session = %self.session_id,
                msg_type = %pending.msg_type(),
                error = %err,
                "dropping outbound message rejected after the application callback"
            );
            return false;
        }
        true
    }

    /// Writes an already-built replay frame to the socket, bounded by the write
    /// timeout.
    ///
    /// A replayed message keeps the sequence number and body it was first sent
    /// with, so nothing is allocated and nothing is re-filed. It already
    /// carries `PossDupFlag` (43) = Y and its original `OrigSendingTime` (122),
    /// both stamped by [`wire::resend_frame`], so it is written verbatim rather
    /// than run back through the callback path.
    ///
    /// # Errors
    /// [`EngineError::WriteTimeout`] when the peer is not reading, and the
    /// transport's own error otherwise. Both are terminal for the session.
    async fn send_replay(
        &self,
        framed: &mut FixFramed,
        frame: BytesMut,
    ) -> Result<(), EngineError> {
        let write_timeout = self.write_timeout;
        match timeout(write_timeout, framed.send(frame)).await {
            Err(_) => return Err(EngineError::WriteTimeout(write_timeout)),
            Ok(Err(err)) => return Err(err.into()),
            Ok(Ok(())) => {}
        }
        lock_heartbeat(&self.runtime).on_message_sent();
        Ok(())
    }

    /// Writes a SequenceReset-GapFill covering `at_seq..new_seq`, numbered with
    /// `at_seq`, without spending a sender sequence number.
    ///
    /// A gap fill re-occupies the range it replaces, so it is written at
    /// `at_seq` rather than through [`Reactor::send`], and is **not** filed:
    /// filing it would overwrite a message under `at_seq` that is still
    /// resendable.
    ///
    /// # Errors
    /// Only a fatal transport failure ([`EngineError::WriteTimeout`] or a
    /// transport error) is returned. A body the callback left unframeable is a
    /// hole the peer will re-request and is dropped rather than closing the
    /// session.
    async fn send_gap_fill(
        &mut self,
        framed: &mut FixFramed,
        at_seq: u64,
        new_seq: u64,
    ) -> Result<(), EngineError> {
        let mut gap_fill = self.factory.sequence_reset_gap_fill(new_seq);
        if !self.prepare(&mut gap_fill).await {
            return Ok(());
        }
        match self.write_at(framed, at_seq, &gap_fill, false).await {
            Ok(()) => {
                lock_heartbeat(&self.runtime).on_message_sent();
                Ok(())
            }
            Err(WriteFailure::Encode(err)) => {
                tracing::warn!(
                    session = %self.session_id,
                    error = %err,
                    "dropping SequenceReset-GapFill with no legal wire form"
                );
                Ok(())
            }
            Err(WriteFailure::Fatal(err)) => Err(err),
        }
    }

    /// Handles a command from a [`Connection`] handle.
    async fn on_command(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        command: Command,
    ) -> Result<Phase, SessionClosed> {
        match command {
            Command::Send(message) => {
                if matches!(phase, Phase::LogoutPending(_)) {
                    tracing::warn!(
                        session = %self.session_id,
                        msg_type = %message.msg_type(),
                        "dropping outbound message: logout pending"
                    );
                    return Ok(phase);
                }
                if let Err(err) = self
                    .send(framed, PendingMessage::application(message))
                    .await
                {
                    teardown(phase);
                    return Err(closed(format!("send failed: {err}"), false));
                }
                Ok(phase)
            }
            Command::Logout => match phase {
                Phase::LogoutPending(_) => Ok(phase),
                Phase::Active(session) => {
                    let logout = self.factory.logout(None);
                    match self.send(framed, logout).await {
                        Err(err) => {
                            let _ = session.disconnect();
                            Err(closed(format!("send failed: {err}"), false))
                        }
                        // The Logout never reached the wire — a `to_admin`
                        // callback left it unframeable. Staying Active is the
                        // honest verdict: arming the logout deadline for a frame
                        // the peer never saw would tear the session down over a
                        // Logout it was never told about.
                        Ok(Sent::Dropped) => Ok(Phase::Active(session)),
                        // Typestate: Active -> LogoutPending. The new state
                        // records when the Logout went out, which is what
                        // on_tick times.
                        Ok(Sent::Yes) => Ok(Phase::LogoutPending(session.initiate_logout())),
                    }
                }
            },
        }
    }

    /// Periodic heartbeat, TestRequest, and timeout checks.
    async fn on_tick(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
    ) -> Result<Phase, SessionClosed> {
        // The logout deadline lives in the typestate: LogoutPending is defined
        // by the instant its Logout was sent, so there is no second copy of it
        // to drift.
        if let Phase::LogoutPending(session) = &phase
            && session.sent_at().elapsed() >= self.config.logout_timeout
        {
            teardown(phase);
            return Err(closed("logout ack timeout", true));
        }

        let (timed_out, send_test_request, send_heartbeat) = {
            let heartbeat = lock_heartbeat(&self.runtime);
            (
                heartbeat.is_timed_out(),
                heartbeat.should_send_test_request(),
                heartbeat.should_send_heartbeat(),
            )
        };

        if timed_out {
            teardown(phase);
            return Err(closed(
                "heartbeat timeout: no response to TestRequest",
                false,
            ));
        }
        if send_test_request {
            let test_req_id = generate_test_req_id();
            let request = self.factory.test_request(&test_req_id);
            match self.send(framed, request).await {
                Err(err) => {
                    teardown(phase);
                    return Err(closed(format!("send failed: {err}"), false));
                }
                // Only a TestRequest that actually went out starts the timeout
                // countdown. Arming it for a dropped probe would time the
                // session out waiting for an answer to a frame never sent.
                Ok(Sent::Yes) => lock_heartbeat(&self.runtime).on_test_request_sent(test_req_id),
                Ok(Sent::Dropped) => {}
            }
        } else if send_heartbeat {
            let heartbeat = self.factory.heartbeat(None);
            if let Err(err) = self.send(framed, heartbeat).await {
                teardown(phase);
                return Err(closed(format!("send failed: {err}"), false));
            }
        }
        Ok(phase)
    }

    /// Sends a session-level Reject (35=3) and keeps the session running.
    async fn send_session_reject(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        ref_seq: u64,
        ref_msg_type: &str,
        reason: &RejectReason,
    ) -> Result<Phase, SessionClosed> {
        let reject = self.factory.session_reject(ref_seq, ref_msg_type, reason);
        if let Err(err) = self.send(framed, reject).await {
            teardown(phase);
            return Err(closed(format!("send failed: {err}"), false));
        }
        Ok(phase)
    }

    /// Requests retransmission from `expected` onwards, unless the same
    /// range is already outstanding.
    async fn request_resend(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        expected: u64,
    ) -> Result<Phase, SessionClosed> {
        if self.pending_resend == Some(expected) {
            return Ok(phase);
        }
        let request = self.factory.resend_request(expected, 0);
        match self.send(framed, request).await {
            Err(err) => {
                teardown(phase);
                return Err(closed(format!("send failed: {err}"), false));
            }
            // The ResendRequest never went out; leaving the range unmarked lets
            // the next frame on the same gap try again, instead of suppressing
            // it as already-requested against a request the peer never received.
            Ok(Sent::Dropped) => return Ok(phase),
            Ok(Sent::Yes) => {}
        }
        self.pending_resend = Some(expected);
        Ok(phase)
    }

    /// Terminates the session on an unrecoverable MsgSeqNum-too-low: a
    /// message below the expected number that is not flagged as a possible
    /// duplicate means the streams have diverged.
    async fn close_on_too_low(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        expected: u64,
        received: u64,
    ) -> SessionClosed {
        let reason = format!("MsgSeqNum too low: expected {expected}, received {received}");
        let logout = self.factory.logout(Some(&reason));
        let _ = self.send(framed, logout).await;
        teardown(phase);
        closed(reason, false)
    }

    /// Rejects an inbound message whose identity fields do not match the
    /// configured counterparty, then logs out and tears the session down.
    ///
    /// A cross-wired connection must not be allowed to advance sequence
    /// state or reach the application. The Reject carries
    /// `SessionRejectReason` 9, "CompID problem".
    async fn close_on_identity_mismatch(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        ref_seq: u64,
        ref_msg_type: &str,
        mismatch: wire::IdentityMismatch,
    ) -> SessionClosed {
        let detail = mismatch.to_string();
        tracing::warn!(session = %self.session_id, detail = %detail, "inbound identity mismatch");

        let reason = RejectReason::new(9, detail.clone()).with_ref_tag(mismatch.tag);
        let reject = self.factory.session_reject(ref_seq, ref_msg_type, &reason);
        let _ = self.send(framed, reject).await;
        let logout = self.factory.logout(Some(&detail));
        let _ = self.send(framed, logout).await;
        teardown(phase);
        closed(detail, false)
    }

    /// Consumes the MsgSeqNum of a `SequenceReset` that is being rejected.
    ///
    /// A Gap Fill participates in normal sequencing: it occupies the number it
    /// carries. If it is rejected without that number being consumed, the
    /// inbound expectation never moves past it and the session silently drops
    /// everything that follows. A Reset-mode message does not participate in
    /// sequencing, so nothing is consumed for it, and neither is anything
    /// consumed for a fill that was not in sequence to begin with.
    fn consume_if_in_sequence(&self, gap_fill: bool, seq: u64) -> Result<(), SequenceExhausted> {
        if !gap_fill || !self.runtime.sequences.validate_incoming(seq).is_ok() {
            return Ok(());
        }
        self.runtime
            .sequences
            .try_increment_target_seq()
            .map(|_| ())
    }

    /// Handles an inbound SequenceReset (35=4).
    ///
    /// `GapFillFlag` (123) selects the mode (`doc/fix_operations.md`,
    /// "Sequence Reset"): `123=Y` is a Gap Fill, which is an ordinary
    /// sequenced message and is validated against MsgSeqNum like any other;
    /// `123=N` or an absent 123 is a Reset, the only mode allowed to ignore
    /// MsgSeqNum. A present-but-malformed 123 (neither `Y` nor `N`) is a
    /// data-format error, rejected with reason 6 rather than silently taken as
    /// a Reset. Treating a Gap Fill as a Reset would let a gapped fill jump the
    /// target expectation past messages that were never received and will now
    /// never be requested.
    ///
    /// A Gap Fill's own MsgSeqNum is classified (gap / too-low duplicate / in
    /// sequence) **before** the `from_admin` callback runs, exactly as every
    /// other inbound message is sequence-checked before it reaches the
    /// application: a gapped fill must produce a ResendRequest even if the
    /// application would reject it, and a too-low duplicate must be dropped
    /// without the callback ever seeing it.
    async fn on_sequence_reset(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        raw: &RawMessage<'_>,
        seq: u64,
    ) -> Result<Phase, SessionClosed> {
        // Only Y and N are valid GapFillFlag Booleans. An absent 123 is Reset
        // mode per spec, but a present-but-malformed value is rejected with
        // reason 6 (incorrect data format) rather than guessing a mode from an
        // uninterpretable field. Reset mode's target jump is defined behaviour,
        // so a malformed value gains no extra power by being read as a Reset --
        // it is simply not a value we are entitled to interpret.
        let gap_fill = match raw.get_field_str(123) {
            Some("Y") => true,
            Some("N") | None => false,
            Some(other) => {
                let reason = RejectReason::new(
                    6,
                    format!("GapFillFlag (123) must be Y or N, got '{other}'"),
                )
                .with_ref_tag(123);
                return self
                    .send_session_reject(
                        framed,
                        phase,
                        seq,
                        MsgType::SequenceReset.as_str(),
                        &reason,
                    )
                    .await;
            }
        };

        // Classify a Gap Fill's MsgSeqNum before the application sees it. A
        // gapped fill cannot be trusted to describe the missing range, so it
        // triggers a ResendRequest -- never a Reject the application asked for
        // -- and a too-low duplicate is dropped without reaching from_admin.
        // Reset mode carries no meaningful MsgSeqNum and is not classified.
        if gap_fill {
            match self.runtime.sequences.validate_incoming(seq) {
                SequenceResult::Gap { expected, .. } => {
                    // The fill is itself gapped: it cannot be trusted to
                    // describe the missing range, so NewSeqNo is not applied
                    // and the range is requested instead.
                    return self.request_resend(framed, phase, expected).await;
                }
                SequenceResult::TooLow { expected, received } => {
                    if raw.get_field_str(43) == Some("Y") {
                        // Duplicate delivery of an already-applied fill.
                        return Ok(phase);
                    }
                    return Err(self
                        .close_on_too_low(framed, phase, expected, received)
                        .await);
                }
                SequenceResult::Ok => {}
            }
        }

        // The fill is in sequence (or this is Reset mode): the application may
        // now inspect it.
        if let Err(reason) = self.application.from_admin(raw, &self.session_id).await {
            // An in-sequence GapFill occupies its own MsgSeqNum. Rejecting it
            // without consuming that number leaves the inbound expectation
            // parked on it forever: every later message then looks gapped, is
            // deduplicated against the outstanding ResendRequest and dropped,
            // and the session goes on reporting itself healthy while it
            // silently discards traffic.
            if let Err(err) = self.consume_if_in_sequence(gap_fill, seq) {
                return Err(exhausted(phase, err));
            }
            return self
                .send_session_reject(framed, phase, seq, MsgType::SequenceReset.as_str(), &reason)
                .await;
        }

        let Some(new_seq) = raw.get_field_str(36).and_then(|s| s.parse::<u64>().ok()) else {
            let reason = RejectReason::new(1, "SequenceReset without a valid NewSeqNo (36)")
                .with_ref_tag(36);
            // Same hazard as the rejection path above: the fill still occupies
            // its sequence number even though its NewSeqNo is unusable.
            if let Err(err) = self.consume_if_in_sequence(gap_fill, seq) {
                return Err(exhausted(phase, err));
            }
            return self
                .send_session_reject(framed, phase, seq, MsgType::SequenceReset.as_str(), &reason)
                .await;
        };

        if gap_fill {
            // The fill was classified as in sequence above; a Gap Fill must
            // advance past the number it occupies itself.
            if new_seq <= seq {
                // The fill was in sequence, so consume it: repeating the
                // same number would deadlock the session on this message.
                if let Err(err) = self.runtime.sequences.try_increment_target_seq() {
                    return Err(exhausted(phase, err));
                }
                let reason = RejectReason::new(
                    5,
                    format!("GapFill NewSeqNo {new_seq} does not advance past MsgSeqNum {seq}"),
                )
                .with_ref_tag(36);
                return self
                    .send_session_reject(
                        framed,
                        phase,
                        seq,
                        MsgType::SequenceReset.as_str(),
                        &reason,
                    )
                    .await;
            }
        } else {
            let expected = self.runtime.sequences.next_target_seq().value();
            if new_seq < expected {
                let reason = RejectReason::new(
                    5,
                    format!("SequenceReset NewSeqNo {new_seq} is below the expected {expected}"),
                )
                .with_ref_tag(36);
                return self
                    .send_session_reject(
                        framed,
                        phase,
                        seq,
                        MsgType::SequenceReset.as_str(),
                        &reason,
                    )
                    .await;
            }
        }

        let expected_before = self.runtime.sequences.next_target_seq().value();
        self.runtime.sequences.set_target_seq(new_seq);
        // Only a reset that actually advances the expectation resolves an
        // outstanding ResendRequest. A reset landing on the number we already
        // expect changes nothing, and clearing the marker for it would let a
        // peer replay it to make the engine emit a fresh ResendRequest every
        // round -- sequence amplification with no progress.
        if new_seq > expected_before {
            self.pending_resend = None;
        }
        Ok(phase)
    }

    /// Answers an inbound ResendRequest (35=2).
    ///
    /// With a store attached (see [`Initiator::with_store`]) the reply is the
    /// requested **application** messages, replayed from the store with
    /// `PossDupFlag` (43) = Y and their original `SendingTime` in
    /// `OrigSendingTime` (122), interleaved with `SequenceReset`-GapFill
    /// messages covering everything that is not replayed: administrative
    /// messages, sequence numbers the store never held or has evicted, and
    /// stored frames that cannot be rebuilt. Without a store nothing can be
    /// replayed and the whole range is one gap fill.
    ///
    /// Either way the reply is bounded by `EndSeqNo` (16) so the counterparty
    /// is never advanced past what it asked for, and `16=0` means "up to
    /// infinity" (`doc/fix_operations.md`, "Resend Request").
    ///
    /// Nothing here allocates a sender sequence number. A replayed message
    /// re-occupies the number it was first sent under, and a gap fill occupies
    /// the range it replaces, so the session's own outbound numbering is
    /// unchanged by answering a resend.
    async fn on_resend_request(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        raw: &RawMessage<'_>,
        seq: u64,
    ) -> Result<Phase, SessionClosed> {
        let ref_msg_type = MsgType::ResendRequest.as_str();

        let Some(begin_seq) = raw.get_field_str(7).and_then(|s| s.parse::<u64>().ok()) else {
            let reason = RejectReason::new(1, "ResendRequest without a valid BeginSeqNo (7)")
                .with_ref_tag(7);
            return self
                .send_session_reject(framed, phase, seq, ref_msg_type, &reason)
                .await;
        };
        let Some(end_seq) = raw.get_field_str(16).and_then(|s| s.parse::<u64>().ok()) else {
            let reason = RejectReason::new(1, "ResendRequest without a valid EndSeqNo (16)")
                .with_ref_tag(16);
            return self
                .send_session_reject(framed, phase, seq, ref_msg_type, &reason)
                .await;
        };

        let next_sender = self.runtime.sequences.next_sender_seq().value();
        if begin_seq == 0 || begin_seq >= next_sender {
            let reason = RejectReason::new(
                5,
                format!("ResendRequest BeginSeqNo {begin_seq} is outside the sent range 1..{next_sender}"),
            )
            .with_ref_tag(7);
            return self
                .send_session_reject(framed, phase, seq, ref_msg_type, &reason)
                .await;
        }
        if end_seq != 0 && end_seq < begin_seq {
            let reason = RejectReason::new(
                5,
                format!("ResendRequest EndSeqNo {end_seq} is below BeginSeqNo {begin_seq}"),
            )
            .with_ref_tag(16);
            return self
                .send_session_reject(framed, phase, seq, ref_msg_type, &reason)
                .await;
        }

        // The reply covers begin_seq..new_seq, never beyond EndSeqNo + 1 and
        // never beyond what we have actually sent.
        let new_seq = match end_seq {
            0 => next_sender,
            _ => end_seq
                .checked_add(1)
                .map_or(next_sender, |bound| bound.min(next_sender)),
        };

        let cursor = match self.replay_range(framed, begin_seq, new_seq).await {
            Ok(cursor) => cursor,
            Err(err) => {
                teardown(phase);
                return Err(closed(format!("resend failed: {err}"), false));
            }
        };

        // Whatever the replay did not cover — a trailing run of admin messages,
        // holes, or the entire range when there is no store — is gap-filled, so
        // the counterparty's expectation always lands exactly on `new_seq`.
        if cursor < new_seq
            && let Err(err) = self.send_gap_fill(framed, cursor, new_seq).await
        {
            teardown(phase);
            return Err(closed(format!("send failed: {err}"), false));
        }
        Ok(phase)
    }

    /// Replays the stored application messages in `begin_seq..new_seq`.
    ///
    /// Returns the first sequence number the reply has **not** yet covered, so
    /// the caller can gap-fill from there to `new_seq`. With no store, or a
    /// store that cannot answer, that is `begin_seq` and the whole range is
    /// gap-filled — the degradation is always a gap fill, never a silent skip,
    /// because a skipped number leaves the counterparty expecting a message
    /// that will never arrive.
    ///
    /// The store is read in bounded pages of [`RESEND_PAGE_LIMIT`] rather than
    /// all at once: a `ResendRequest` with `EndSeqNo` (16) = 0 asks for the whole
    /// session, and materialising an arbitrarily long history in one read would
    /// allocate it all up front and stall the reactor for the duration of a
    /// single peer request. The reactor yields between pages so other sessions
    /// and this session's own inbound traffic keep making progress.
    ///
    /// # Errors
    /// Returns [`EngineError`] only if writing to the socket fails; the session
    /// is then closed by the caller. Every other failure — an unreadable store,
    /// an unrebuildable frame — degrades to a gap fill.
    async fn replay_range(
        &mut self,
        framed: &mut FixFramed,
        begin_seq: u64,
        new_seq: u64,
    ) -> Result<u64, EngineError> {
        // Cloned so the loop does not hold a borrow of `self.store` across the
        // `&mut self` replay/gap-fill calls below; an `Arc` clone is a
        // reference-count bump.
        let Some(store) = self.store.clone() else {
            return Ok(begin_seq);
        };
        // `new_seq` is the exclusive upper bound of the reply, so the last
        // replayable number is one below it. A `new_seq` of 0 is unreachable
        // (it is at least `begin_seq` >= 1), and an empty range needs no read.
        let Some(end_seq) = new_seq.checked_sub(1) else {
            return Ok(begin_seq);
        };
        if end_seq < begin_seq {
            return Ok(begin_seq);
        }

        // `reply_cursor` is the next number the reply still owes the peer; it
        // advances only past messages actually replayed, so holes, admin
        // messages and unrebuildable frames stay for the leading or trailing gap
        // fill. `read_from` is the next store key to page from, and advances
        // past everything a page yields so no message is read twice.
        let mut reply_cursor = begin_seq;
        let mut read_from = begin_seq;
        loop {
            let page = match store.get_page(read_from, end_seq, RESEND_PAGE_LIMIT).await {
                Ok(page) => page,
                Err(err) => {
                    tracing::warn!(
                        session = %self.session_id,
                        read_from,
                        end_seq,
                        error = %err,
                        "cannot read the resend range from the store: gap-filling the rest"
                    );
                    return Ok(reply_cursor);
                }
            };
            let page_len = page.len();
            // Ascending and bounded to `end_seq`: the last key is the furthest
            // this page reached, so the next page pages from just past it.
            let Some(furthest) = page.last().map(|message| message.seq_num()) else {
                break;
            };

            for message in page {
                let seq = message.seq_num();
                // A store handing back something outside the asked-for range
                // must not be allowed to move the reply.
                if seq < reply_cursor || seq > end_seq {
                    continue;
                }
                // Administrative messages are gap-filled, not replayed
                // (`doc/fix_operations.md`, "Resend Request", item 3): resending
                // a stale Heartbeat or Logon says nothing true about the session
                // now.
                if message.msg_type().is_admin() {
                    continue;
                }
                let frame = match wire::resend_frame(message.payload()) {
                    Ok(frame) => frame,
                    Err(err) => {
                        tracing::warn!(
                            session = %self.session_id,
                            seq,
                            error = %err,
                            "cannot rebuild a stored message as a resend: gap-filling it instead"
                        );
                        continue;
                    }
                };

                // Everything between the cursor and this message — holes, admin
                // messages, frames that would not rebuild — is one fill.
                if seq > reply_cursor {
                    self.send_gap_fill(framed, reply_cursor, seq).await?;
                }
                self.send_replay(framed, frame).await?;

                // `seq <= end_seq < new_seq <= next_sender <= u64::MAX`, so this
                // cannot overflow; it is checked rather than assumed because a
                // wrapped sequence number would corrupt the session it is meant
                // to repair.
                let Some(next) = seq.checked_add(1) else {
                    return Ok(new_seq);
                };
                reply_cursor = next;
            }

            // A short page means the range is exhausted; a full one means there
            // may be more, so page again from past the furthest key and yield
            // first so one resend cannot monopolise the reactor.
            if page_len < RESEND_PAGE_LIMIT {
                break;
            }
            let Some(next_read) = furthest.checked_add(1) else {
                break;
            };
            read_from = next_read;
            if read_from > end_seq {
                break;
            }
            tokio::task::yield_now().await;
        }
        Ok(reply_cursor)
    }

    /// Handles one inbound frame: identity validation, sequence validation,
    /// admin processing, and application callback dispatch.
    async fn on_frame(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        frame: BytesMut,
    ) -> Result<Phase, SessionClosed> {
        // Frozen once: handing an application message to the dispatcher is
        // then a reference-count bump on this buffer, not a copy of it.
        let frame = frame.freeze();
        let raw = match wire::decode_frame(&frame) {
            Ok(raw) => raw,
            Err(err) => {
                tracing::warn!(session = %self.session_id, error = %err, "dropping undecodable frame");
                return Ok(phase);
            }
        };
        let msg_type = raw.msg_type().clone();

        let Some(seq) = raw.get_field_str(34).and_then(|s| s.parse::<u64>().ok()) else {
            tracing::warn!(
                session = %self.session_id,
                msg_type = %msg_type,
                "dropping message without valid MsgSeqNum (34)"
            );
            return Ok(phase);
        };

        // Identity before session state: foreign traffic must not advance
        // sequence numbers, reach the application, or keep the heartbeat
        // clock alive.
        if let Err(mismatch) = self.identity.validate(&raw) {
            return Err(self
                .close_on_identity_mismatch(framed, phase, seq, msg_type.as_str(), mismatch)
                .await);
        }

        // The frame is well-formed, sequenced, and from the configured
        // counterparty: it proves the peer is alive. A sequence gap is a
        // recoverable condition, not evidence of a dead peer, so gapped
        // frames still count here — and so does any frame arriving while a
        // TestRequest is outstanding, which is what stops the countdown.
        let test_req_id = raw.get_field_str(112);
        let outcome = lock_heartbeat(&self.runtime)
            .on_message_received(msg_type == MsgType::Heartbeat, test_req_id);
        match outcome {
            TestRequestOutcome::Confirmed => tracing::debug!(
                session = %self.session_id,
                "TestRequest answered by Heartbeat with matching TestReqID"
            ),
            TestRequestOutcome::SupersededByTraffic => tracing::debug!(
                session = %self.session_id,
                msg_type = %msg_type,
                "pending TestRequest cleared by inbound traffic"
            ),
            TestRequestOutcome::NonePending => {}
        }

        if msg_type == MsgType::SequenceReset {
            return self.on_sequence_reset(framed, phase, &raw, seq).await;
        }

        match self.runtime.sequences.validate_incoming(seq) {
            SequenceResult::Ok => {
                if msg_type.is_admin() {
                    // Consume the number before the admin handler runs: any
                    // reply it sends is numbered against the advanced
                    // expectation, and admin messages never queue.
                    if let Err(err) = self.runtime.sequences.try_increment_target_seq() {
                        return Err(exhausted(phase, err));
                    }
                    self.pending_resend = None;
                    self.dispatch_admin(framed, phase, &raw, seq).await
                } else {
                    // Hand the frame to the dispatcher *before* the inbound
                    // expectation advances past it. A full queue is then a
                    // session close with the sequence number unspent, never a
                    // message dropped after its number was already consumed.
                    let phase = self.enqueue_app(phase, seq, &frame)?;
                    if let Err(err) = self.runtime.sequences.try_increment_target_seq() {
                        return Err(exhausted(phase, err));
                    }
                    self.pending_resend = None;
                    Ok(phase)
                }
            }
            SequenceResult::TooLow { expected, received } => {
                if raw.get_field_str(43) == Some("Y") {
                    // Duplicate delivery of an already-processed message.
                    return Ok(phase);
                }
                Err(self
                    .close_on_too_low(framed, phase, expected, received)
                    .await)
            }
            SequenceResult::Gap { expected, .. } => {
                let phase = self.request_resend(framed, phase, expected).await?;
                if msg_type.is_app() {
                    // Application messages inside a gap will be resent in
                    // order; admin messages are still processed below
                    // (without advancing the target sequence).
                    return Ok(phase);
                }
                self.dispatch_admin(framed, phase, &raw, seq).await
            }
        }
    }

    /// Hands one validated inbound application frame to the dispatcher task.
    ///
    /// The caller has not yet advanced the inbound expectation, so a full queue
    /// closes the session with the sequence number intact — the counterparty
    /// stays free to resend, rather than the message being silently lost past a
    /// number already consumed.
    fn enqueue_app(&self, phase: Phase, seq: u64, frame: &Bytes) -> Result<Phase, SessionClosed> {
        let queued = AppFrame {
            frame: frame.clone(),
            seq,
        };
        match self.app_tx.try_send(queued) {
            Ok(()) => Ok(phase),
            Err(mpsc::error::TrySendError::Full(_)) => {
                teardown(phase);
                Err(closed(
                    "application queue full: the application is not consuming inbound \
                     messages fast enough",
                    false,
                ))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                teardown(phase);
                Err(closed("application dispatcher stopped", false))
            }
        }
    }

    /// Runs `from_admin` and the admin reply for an administrative message whose
    /// sequence number has already been validated (and, on the in-sequence
    /// path, consumed).
    ///
    /// Application messages never reach here — they are handed to the dispatcher
    /// task by [`Reactor::enqueue_app`], so a slow `from_app` cannot delay the
    /// next socket read or the heartbeat clock.
    async fn dispatch_admin(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        raw: &RawMessage<'_>,
        seq: u64,
    ) -> Result<Phase, SessionClosed> {
        let msg_type = raw.msg_type();
        if let Err(reason) = self.application.from_admin(raw, &self.session_id).await {
            return self
                .send_session_reject(framed, phase, seq, msg_type.as_str(), &reason)
                .await;
        }

        match msg_type {
            MsgType::Heartbeat => Ok(phase),
            MsgType::TestRequest => {
                // `112=` with no value is a malformed TestRequest. There is
                // nothing to echo, and an empty field has no legal wire form,
                // so the Heartbeat is sent without TestReqID rather than the
                // session being torn down over the peer's mistake.
                let test_req_id = raw.get_field_str(112).filter(|id| !id.is_empty());
                let heartbeat = self.factory.heartbeat(test_req_id);
                if let Err(err) = self.send(framed, heartbeat).await {
                    teardown(phase);
                    return Err(closed(format!("send failed: {err}"), false));
                }
                Ok(phase)
            }
            MsgType::ResendRequest => self.on_resend_request(framed, phase, raw, seq).await,
            MsgType::Logon => {
                tracing::warn!(
                    session = %self.session_id,
                    "ignoring unexpected Logon on established session"
                );
                Ok(phase)
            }
            MsgType::Reject => {
                tracing::warn!(
                    session = %self.session_id,
                    text = raw.get_field_str(58).unwrap_or(""),
                    "session-level Reject received"
                );
                Ok(phase)
            }
            MsgType::Logout => match phase {
                Phase::LogoutPending(session) => {
                    // Typestate: LogoutPending -> Disconnected.
                    let _ = session.on_logout_ack();
                    Err(closed("logout complete", true))
                }
                Phase::Active(session) => {
                    let logout = self.factory.logout(None);
                    let _ = self.send(framed, logout).await;
                    let _ = session.disconnect();
                    let text = raw
                        .get_field_str(58)
                        .unwrap_or("logout initiated by counterparty");
                    Err(closed(format!("logout by counterparty: {text}"), true))
                }
            },
            // SequenceReset is handled before dispatch; every other admin
            // type is matched above.
            _ => Ok(phase),
        }
    }
}
