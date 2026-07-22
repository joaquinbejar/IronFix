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
//! Sequence recovery follows `doc/fix_operations.md`: a `SequenceReset` with
//! `GapFillFlag` (123) = Y is an ordinary sequenced message and is validated
//! against its own `MsgSeqNum`, while Reset mode alone may ignore it; an
//! inbound `ResendRequest` is answered with a `SequenceReset`-GapFill bounded
//! by `EndSeqNo`. **The engine does not use a message store for replay, so no
//! message is ever actually replayed** — a resend request is always answered
//! with a gap fill.
//!
//! All sequence arithmetic goes through the checked
//! [`SequenceManager::try_allocate_sender_seq`] /
//! [`SequenceManager::try_increment_target_seq`]; an exhausted counter tears
//! the session down rather than wrapping.
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
use crate::wire::{self, MessageFactory, PeerIdentity, UnsupportedVersion};
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::error::EncodeError;
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::version::FixVersion;
use ironfix_session::heartbeat::generate_test_req_id;
use ironfix_session::sequence::{SequenceExhausted, SequenceResult};
use ironfix_session::{
    Active, Disconnected, HeartbeatManager, LogoutPending, SequenceManager, Session, SessionConfig,
};
use ironfix_transport::FixCodec;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::sync::{mpsc, watch};
use tokio::time::{MissedTickBehavior, interval, timeout};
use tokio_util::codec::Framed;

/// Framed TCP stream carrying FIX messages.
type FixFramed = Framed<TcpStream, FixCodec>;

/// Default capacity of the outbound command queue.
const DEFAULT_OUTBOUND_CAPACITY: usize = 1024;

/// Reactor tick granularity for heartbeat/timeout checks.
const TICK_INTERVAL: Duration = Duration::from_millis(100);

/// Client-side FIX engine.
///
/// Owns the session configuration and the [`Application`] callbacks. Each
/// call to [`Initiator::connect`] establishes one live session and returns
/// a [`Connection`] handle for it.
#[derive(Debug)]
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
    /// TCP connect timeout.
    connect_timeout: Duration,
    /// Initial (sender, target) sequence numbers for session continuity.
    initial_sequences: Option<(u64, u64)>,
    /// Capacity of the outbound command queue.
    outbound_capacity: usize,
}

impl<A: Application + 'static> Initiator<A> {
    /// Creates a new initiator.
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

        Self {
            config,
            application,
            session_id,
            version,
            connect_timeout: Duration::from_secs(30),
            initial_sequences: None,
            outbound_capacity: DEFAULT_OUTBOUND_CAPACITY,
        }
    }

    /// Sets the TCP connect timeout (default 30s).
    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Seeds the session with initial sequence numbers, for continuity with
    /// a previous session (e.g. after a reconnect supervised by the
    /// consumer). Ignored when `reset_on_logon` is set.
    ///
    /// # Arguments
    /// * `sender_seq` - Next outgoing sequence number
    /// * `target_seq` - Next expected incoming sequence number
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
    /// [`EngineError::UnsupportedVersion`], before the socket is dialled.
    pub async fn connect(&self, addr: impl ToSocketAddrs) -> Result<Connection, EngineError> {
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

        let sequences = match self.initial_sequences {
            Some((sender, target)) if !self.config.reset_on_logon => {
                SequenceManager::with_initial(sender, target)
            }
            _ => SequenceManager::new(),
        };
        let runtime = Arc::new(SessionRuntime {
            sequences,
            heartbeat: Mutex::new(HeartbeatManager::new(self.config.heartbeat_interval)),
        });
        let factory = MessageFactory::new(&self.config, version);
        let identity = PeerIdentity::new(&self.config);

        // Typestate: Connecting -> LogonSent.
        let seq = match runtime.sequences.try_allocate_sender_seq() {
            Ok(seq) => seq.value(),
            Err(err) => {
                let _ = session.disconnect();
                return Err(err.into());
            }
        };
        let logon = factory.logon(
            seq,
            self.config.heartbeat_interval_secs(),
            self.config.reset_on_logon,
        )?;
        if let Ok(mut owned) = wire::owned_from_frame(&logon) {
            self.application.to_admin(&mut owned, &session_id).await;
        }
        framed.send(logon).await?;
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
                if let Ok(out_seq) = runtime.sequences.try_allocate_sender_seq()
                    && let Ok(reject) = factory.session_reject(
                        out_seq.value(),
                        ack_seq,
                        MsgType::Logon.as_str(),
                        &reason,
                    )
                {
                    let _ = framed.send(reject).await;
                }
                if let Ok(out_seq) = runtime.sequences.try_allocate_sender_seq()
                    && let Ok(logout) = factory.logout(out_seq.value(), Some(&detail))
                {
                    let _ = framed.send(logout).await;
                }
                let _ = session.on_logon_reject();
                return Err(EngineError::IdentityMismatch { detail });
            }

            if let Err(reason) = self.application.from_admin(&raw, &session_id).await {
                match runtime.sequences.try_allocate_sender_seq() {
                    Ok(seq) => match factory.logout(seq.value(), Some(&reason.text)) {
                        Ok(logout) => {
                            let _ = framed.send(logout).await;
                        }
                        Err(err) => tracing::warn!(
                            session = %session_id,
                            error = %err,
                            "cannot encode Logout after from_admin rejection"
                        ),
                    },
                    Err(err) => tracing::warn!(
                        session = %session_id,
                        error = %err,
                        "cannot send Logout after from_admin rejection"
                    ),
                }
                let _ = session.on_logon_reject();
                return Err(EngineError::LogonRejected {
                    reason: reason.text,
                });
            }

            // Honor the heartbeat interval confirmed by the counterparty.
            {
                let mut heartbeat = lock_heartbeat(&runtime);
                heartbeat.on_message_received(false, None);
                if let Some(secs) = raw.get_field_str(108).and_then(|s| s.parse::<u64>().ok())
                    && Duration::from_secs(secs) != heartbeat.interval()
                {
                    tracing::info!(
                        session = %session_id,
                        heartbeat_secs = secs,
                        "using heartbeat interval confirmed by counterparty"
                    );
                    *heartbeat = HeartbeatManager::new(Duration::from_secs(secs));
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
            let seq = runtime.sequences.try_allocate_sender_seq()?.value();
            let frame = factory.resend_request(seq, expected, 0)?;
            if let Ok(mut owned) = wire::owned_from_frame(&frame) {
                self.application.to_admin(&mut owned, &session_id).await;
            }
            framed.send(frame).await?;
            lock_heartbeat(&runtime).on_message_sent();
        }

        let (command_tx, command_rx) = mpsc::channel(self.outbound_capacity);
        let (closed_tx, closed_rx) = watch::channel(false);

        let reactor = Reactor {
            factory,
            identity,
            runtime: Arc::clone(&runtime),
            config: self.config.clone(),
            application: Arc::clone(&self.application),
            session_id: session_id.clone(),
            pending_resend,
            logout_deadline: None,
        };
        tokio::spawn(run_reactor(framed, command_rx, closed_tx, reactor, session));

        Ok(Connection {
            session_id,
            commands: command_tx,
            closed: closed_rx,
            runtime,
        })
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

/// Reactor state shared across event handlers.
struct Reactor<A: Application> {
    /// Outbound frame factory.
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
    /// Expected sequence number a pending ResendRequest was issued for.
    pending_resend: Option<u64>,
    /// Deadline for a locally initiated logout.
    logout_deadline: Option<Instant>,
}

/// The session reactor: owns the socket, multiplexes inbound frames,
/// outbound commands, and heartbeat timers until the session closes.
async fn run_reactor<A: Application + 'static>(
    mut framed: FixFramed,
    mut commands: mpsc::Receiver<Command>,
    closed_tx: watch::Sender<bool>,
    mut ctx: Reactor<A>,
    session: Session<Active>,
) {
    let mut phase = Some(Phase::Active(session));
    let mut commands_open = true;
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
            _ = tick.tick() => ctx.on_tick(&mut framed, current).await,
        };
        match result {
            Ok(next) => phase = Some(next),
            Err(outcome) => break outcome,
        }
    };

    if ctx.config.reset_on_disconnect || (outcome.graceful && ctx.config.reset_on_logout) {
        ctx.runtime.sequences.reset();
    }
    ctx.application.on_logout(&ctx.session_id).await;
    let _ = closed_tx.send(true);
    if outcome.graceful {
        tracing::info!(session = %ctx.session_id, reason = %outcome.reason, "FIX session closed");
    } else {
        tracing::warn!(session = %ctx.session_id, reason = %outcome.reason, "FIX session closed");
    }
}

impl<A: Application> Reactor<A> {
    /// Sends an admin frame, running the `to_admin` callback and updating
    /// heartbeat bookkeeping.
    async fn send_admin(
        &self,
        framed: &mut FixFramed,
        frame: Result<BytesMut, EncodeError>,
    ) -> Result<(), EngineError> {
        // The frame arrives as the encoder's result so every caller reports an
        // unencodable message through the path it already uses for a failed
        // send, rather than each deciding for itself.
        let frame = frame?;
        if let Ok(mut owned) = wire::owned_from_frame(&frame) {
            self.application
                .to_admin(&mut owned, &self.session_id)
                .await;
        }
        framed.send(frame).await?;
        lock_heartbeat(&self.runtime).on_message_sent();
        Ok(())
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
                // Build the frame against the sequence number that *would* be
                // allocated next, without consuming it. An application may hand
                // us a message with no legal wire form — an ordinary field
                // carrying SOH, an empty value, a DATA half without its LENGTH.
                // Validating before allocation makes that a clean drop that
                // leaves the session and the sequence counter intact, rather
                // than a teardown over a spent number the counterparty would
                // have to resend over. The reactor is the sole allocator of the
                // sender counter and does not await between this peek and the
                // commit below, so the number it commits is the one framed here.
                let seq = self.runtime.sequences.next_sender_seq().value();
                let frame = match self.factory.application_message(seq, &message) {
                    Ok(frame) => frame,
                    Err(err) => {
                        // The message never reached the wire and no number was
                        // spent. The value itself is not logged: it may carry a
                        // credential (554/925) or RawData.
                        tracing::warn!(
                            session = %self.session_id,
                            msg_type = %message.msg_type(),
                            error = %err,
                            "dropping outbound message: cannot encode"
                        );
                        return Ok(phase);
                    }
                };
                // The frame encoded; commit the sequence number it carries.
                if let Err(err) = self.runtime.sequences.try_allocate_sender_seq() {
                    return Err(exhausted(phase, err));
                }
                if let Ok(mut owned) = wire::owned_from_frame(&frame) {
                    self.application.to_app(&mut owned, &self.session_id).await;
                }
                if let Err(err) = framed.send(frame).await {
                    teardown(phase);
                    return Err(closed(format!("send failed: {err}"), false));
                }
                lock_heartbeat(&self.runtime).on_message_sent();
                Ok(phase)
            }
            Command::Logout => match phase {
                Phase::LogoutPending(_) => Ok(phase),
                Phase::Active(session) => {
                    let seq = match self.runtime.sequences.try_allocate_sender_seq() {
                        Ok(seq) => seq.value(),
                        Err(err) => {
                            let _ = session.disconnect();
                            return Err(closed(err.to_string(), false));
                        }
                    };
                    let frame = self.factory.logout(seq, None);
                    if let Err(err) = self.send_admin(framed, frame).await {
                        let _ = session.disconnect();
                        return Err(closed(format!("send failed: {err}"), false));
                    }
                    self.logout_deadline = Some(Instant::now() + self.config.logout_timeout);
                    // Typestate: Active -> LogoutPending.
                    Ok(Phase::LogoutPending(session.initiate_logout()))
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
        if let Some(deadline) = self.logout_deadline
            && Instant::now() >= deadline
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
            let seq = match self.runtime.sequences.try_allocate_sender_seq() {
                Ok(seq) => seq.value(),
                Err(err) => return Err(exhausted(phase, err)),
            };
            let frame = self.factory.test_request(seq, &test_req_id);
            if let Err(err) = self.send_admin(framed, frame).await {
                teardown(phase);
                return Err(closed(format!("send failed: {err}"), false));
            }
            lock_heartbeat(&self.runtime).on_test_request_sent(test_req_id);
        } else if send_heartbeat {
            let seq = match self.runtime.sequences.try_allocate_sender_seq() {
                Ok(seq) => seq.value(),
                Err(err) => return Err(exhausted(phase, err)),
            };
            let frame = self.factory.heartbeat(seq, None);
            if let Err(err) = self.send_admin(framed, frame).await {
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
        let out_seq = match self.runtime.sequences.try_allocate_sender_seq() {
            Ok(seq) => seq.value(),
            Err(err) => return Err(exhausted(phase, err)),
        };
        let frame = self
            .factory
            .session_reject(out_seq, ref_seq, ref_msg_type, reason);
        if let Err(err) = self.send_admin(framed, frame).await {
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
        let out_seq = match self.runtime.sequences.try_allocate_sender_seq() {
            Ok(seq) => seq.value(),
            Err(err) => return Err(exhausted(phase, err)),
        };
        let frame = self.factory.resend_request(out_seq, expected, 0);
        if let Err(err) = self.send_admin(framed, frame).await {
            teardown(phase);
            return Err(closed(format!("send failed: {err}"), false));
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
        if let Ok(out_seq) = self.runtime.sequences.try_allocate_sender_seq() {
            let frame = self.factory.logout(out_seq.value(), Some(&reason));
            let _ = self.send_admin(framed, frame).await;
        }
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
        if let Ok(out_seq) = self.runtime.sequences.try_allocate_sender_seq() {
            let frame =
                self.factory
                    .session_reject(out_seq.value(), ref_seq, ref_msg_type, &reason);
            let _ = self.send_admin(framed, frame).await;
        }
        if let Ok(out_seq) = self.runtime.sequences.try_allocate_sender_seq() {
            let frame = self.factory.logout(out_seq.value(), Some(&detail));
            let _ = self.send_admin(framed, frame).await;
        }
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
    /// The engine has no message store, so it cannot replay the requested
    /// messages: it answers the whole requested range with a single
    /// SequenceReset-GapFill. The reply is bounded by `EndSeqNo` (16) so the
    /// counterparty is never advanced past what it asked for, and `16=0`
    /// means "up to infinity" (`doc/fix_operations.md`, "Resend Request").
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

        // The fill covers begin_seq..new_seq, never beyond EndSeqNo + 1 and
        // never beyond what we have actually sent.
        let new_seq = match end_seq {
            0 => next_sender,
            _ => end_seq
                .checked_add(1)
                .map_or(next_sender, |bound| bound.min(next_sender)),
        };
        let frame = self.factory.sequence_reset_gap_fill(begin_seq, new_seq);
        if let Err(err) = self.send_admin(framed, frame).await {
            teardown(phase);
            return Err(closed(format!("send failed: {err}"), false));
        }
        Ok(phase)
    }

    /// Handles one inbound frame: identity validation, sequence validation,
    /// admin processing, and application callback dispatch.
    async fn on_frame(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        frame: BytesMut,
    ) -> Result<Phase, SessionClosed> {
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
        // frames still count here.
        let test_req_id = raw.get_field_str(112);
        lock_heartbeat(&self.runtime)
            .on_message_received(msg_type == MsgType::Heartbeat, test_req_id);

        if msg_type == MsgType::SequenceReset {
            return self.on_sequence_reset(framed, phase, &raw, seq).await;
        }

        match self.runtime.sequences.validate_incoming(seq) {
            SequenceResult::Ok => {
                if let Err(err) = self.runtime.sequences.try_increment_target_seq() {
                    return Err(exhausted(phase, err));
                }
                self.pending_resend = None;
            }
            SequenceResult::TooLow { expected, received } => {
                if raw.get_field_str(43) == Some("Y") {
                    // Duplicate delivery of an already-processed message.
                    return Ok(phase);
                }
                return Err(self
                    .close_on_too_low(framed, phase, expected, received)
                    .await);
            }
            SequenceResult::Gap { expected, .. } => {
                let phase = self.request_resend(framed, phase, expected).await?;
                if msg_type.is_app() {
                    // Application messages inside a gap will be resent in
                    // order; admin messages are still processed below
                    // (without advancing the target sequence).
                    return Ok(phase);
                }
                return self.dispatch(framed, phase, &raw, &msg_type, seq).await;
            }
        }

        self.dispatch(framed, phase, &raw, &msg_type, seq).await
    }

    /// Runs the application callback and the admin reply for a message whose
    /// sequence number has already been validated.
    async fn dispatch(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        raw: &RawMessage<'_>,
        msg_type: &MsgType,
        seq: u64,
    ) -> Result<Phase, SessionClosed> {
        if !msg_type.is_admin() {
            if let Err(reason) = self.application.from_app(raw, &self.session_id).await {
                return self
                    .send_session_reject(framed, phase, seq, msg_type.as_str(), &reason)
                    .await;
            }
            return Ok(phase);
        }

        if let Err(reason) = self.application.from_admin(raw, &self.session_id).await {
            return self
                .send_session_reject(framed, phase, seq, msg_type.as_str(), &reason)
                .await;
        }

        match msg_type {
            MsgType::Heartbeat => Ok(phase),
            MsgType::TestRequest => {
                let out_seq = match self.runtime.sequences.try_allocate_sender_seq() {
                    Ok(out_seq) => out_seq.value(),
                    Err(err) => return Err(exhausted(phase, err)),
                };
                // `112=` with no value is a malformed TestRequest. There is
                // nothing to echo, and an empty field has no legal wire form,
                // so the Heartbeat is sent without TestReqID rather than the
                // session being torn down over the peer's mistake.
                let test_req_id = raw.get_field_str(112).filter(|id| !id.is_empty());
                let frame = self.factory.heartbeat(out_seq, test_req_id);
                if let Err(err) = self.send_admin(framed, frame).await {
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
                    if let Ok(out_seq) = self.runtime.sequences.try_allocate_sender_seq() {
                        let frame = self.factory.logout(out_seq.value(), None);
                        let _ = self.send_admin(framed, frame).await;
                    }
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
