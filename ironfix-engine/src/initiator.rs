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

use crate::application::{Application, NoOpApplication, SessionId};
use crate::connection::{Command, Connection, SessionRuntime};
use crate::error::EngineError;
use crate::wire::{self, MessageFactory};
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::message::MsgType;
use ironfix_session::heartbeat::generate_test_req_id;
use ironfix_session::sequence::SequenceResult;
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
    /// Interned BeginString for the encoder.
    begin_string: &'static str,
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
        let begin_string = wire::static_begin_string(&config.begin_string);

        Self {
            config,
            application,
            session_id,
            begin_string,
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
    /// fails.
    pub async fn connect(&self, addr: impl ToSocketAddrs) -> Result<Connection, EngineError> {
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
        let factory = MessageFactory::new(&self.config, self.begin_string);

        // Typestate: Connecting -> LogonSent.
        let seq = runtime.sequences.allocate_sender_seq().value();
        let logon = factory.logon(
            seq,
            self.config.heartbeat_interval_secs(),
            self.config.reset_on_logon,
        );
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

            if let Err(reason) = self.application.from_admin(&raw, &session_id).await {
                let seq = runtime.sequences.allocate_sender_seq().value();
                let _ = framed.send(factory.logout(seq, Some(&reason.text))).await;
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

            let ack_seq: u64 = raw.get_field_as(34)?;
            match runtime.sequences.validate_incoming(ack_seq) {
                SequenceResult::Ok => runtime.sequences.increment_target_seq(),
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
            let seq = runtime.sequences.allocate_sender_seq().value();
            let frame = factory.resend_request(seq, expected, 0);
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
fn lock_heartbeat(runtime: &SessionRuntime) -> std::sync::MutexGuard<'_, HeartbeatManager> {
    runtime.heartbeat.lock().expect("heartbeat lock poisoned")
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

/// Reactor state shared across event handlers.
struct Reactor<A: Application> {
    /// Outbound frame factory.
    factory: MessageFactory,
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
        let current = phase.take().expect("session phase present");
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
    async fn send_admin(&self, framed: &mut FixFramed, frame: BytesMut) -> Result<(), EngineError> {
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
                let seq = self.runtime.sequences.allocate_sender_seq().value();
                let frame = self.factory.application_message(seq, &message);
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
                    let seq = self.runtime.sequences.allocate_sender_seq().value();
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
            let seq = self.runtime.sequences.allocate_sender_seq().value();
            let frame = self.factory.test_request(seq, &test_req_id);
            if let Err(err) = self.send_admin(framed, frame).await {
                teardown(phase);
                return Err(closed(format!("send failed: {err}"), false));
            }
            lock_heartbeat(&self.runtime).on_test_request_sent(test_req_id);
        } else if send_heartbeat {
            let seq = self.runtime.sequences.allocate_sender_seq().value();
            let frame = self.factory.heartbeat(seq, None);
            if let Err(err) = self.send_admin(framed, frame).await {
                teardown(phase);
                return Err(closed(format!("send failed: {err}"), false));
            }
        }
        Ok(phase)
    }

    /// Handles one inbound frame: sequence validation, admin processing,
    /// and application callback dispatch.
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
        let test_req_id = raw.get_field_str(112);
        lock_heartbeat(&self.runtime)
            .on_message_received(msg_type == MsgType::Heartbeat, test_req_id);

        let Some(seq) = raw.get_field_str(34).and_then(|s| s.parse::<u64>().ok()) else {
            tracing::warn!(
                session = %self.session_id,
                msg_type = %msg_type,
                "dropping message without valid MsgSeqNum (34)"
            );
            return Ok(phase);
        };

        // SequenceReset (including GapFill) jumps the target expectation
        // regardless of its own MsgSeqNum.
        if msg_type == MsgType::SequenceReset {
            let _ = self.application.from_admin(&raw, &self.session_id).await;
            match raw.get_field_str(36).and_then(|s| s.parse::<u64>().ok()) {
                Some(new_seq) => {
                    let expected = self.runtime.sequences.next_target_seq().value();
                    if new_seq >= expected {
                        self.runtime.sequences.set_target_seq(new_seq);
                        self.pending_resend = None;
                    } else {
                        tracing::warn!(
                            session = %self.session_id,
                            new_seq,
                            expected,
                            "ignoring SequenceReset that would decrease the target sequence"
                        );
                    }
                }
                None => tracing::warn!(
                    session = %self.session_id,
                    "ignoring SequenceReset without valid NewSeqNo (36)"
                ),
            }
            return Ok(phase);
        }

        match self.runtime.sequences.validate_incoming(seq) {
            SequenceResult::Ok => {
                self.runtime.sequences.increment_target_seq();
                self.pending_resend = None;
            }
            SequenceResult::TooLow { expected, received } => {
                if raw.get_field_str(43) == Some("Y") {
                    // Duplicate delivery of an already-processed message.
                    return Ok(phase);
                }
                let reason = format!("MsgSeqNum too low: expected {expected}, received {received}");
                let out_seq = self.runtime.sequences.allocate_sender_seq().value();
                let frame = self.factory.logout(out_seq, Some(&reason));
                let _ = self.send_admin(framed, frame).await;
                teardown(phase);
                return Err(closed(reason, false));
            }
            SequenceResult::Gap { expected, .. } => {
                if self.pending_resend != Some(expected) {
                    let out_seq = self.runtime.sequences.allocate_sender_seq().value();
                    let frame = self.factory.resend_request(out_seq, expected, 0);
                    if let Err(err) = self.send_admin(framed, frame).await {
                        teardown(phase);
                        return Err(closed(format!("send failed: {err}"), false));
                    }
                    self.pending_resend = Some(expected);
                }
                if msg_type.is_app() {
                    // Application messages inside a gap will be resent in
                    // order; admin messages are still processed below
                    // (without advancing the target sequence).
                    return Ok(phase);
                }
            }
        }

        if msg_type.is_admin() {
            if let Err(reason) = self.application.from_admin(&raw, &self.session_id).await {
                let out_seq = self.runtime.sequences.allocate_sender_seq().value();
                let frame = self
                    .factory
                    .session_reject(out_seq, seq, msg_type.as_str(), &reason);
                if let Err(err) = self.send_admin(framed, frame).await {
                    teardown(phase);
                    return Err(closed(format!("send failed: {err}"), false));
                }
                return Ok(phase);
            }
            match msg_type {
                MsgType::Heartbeat => Ok(phase),
                MsgType::TestRequest => {
                    let out_seq = self.runtime.sequences.allocate_sender_seq().value();
                    let frame = self.factory.heartbeat(out_seq, test_req_id);
                    if let Err(err) = self.send_admin(framed, frame).await {
                        teardown(phase);
                        return Err(closed(format!("send failed: {err}"), false));
                    }
                    Ok(phase)
                }
                MsgType::ResendRequest => {
                    // Answer with a GapFill jumping to our next sender
                    // sequence; message-by-message replay from a store is a
                    // consumer/session-layer concern.
                    let begin_seq = raw
                        .get_field_str(7)
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(1);
                    let new_seq = self.runtime.sequences.next_sender_seq().value();
                    let frame = self.factory.sequence_reset_gap_fill(begin_seq, new_seq);
                    if let Err(err) = self.send_admin(framed, frame).await {
                        teardown(phase);
                        return Err(closed(format!("send failed: {err}"), false));
                    }
                    Ok(phase)
                }
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
                        let out_seq = self.runtime.sequences.allocate_sender_seq().value();
                        let frame = self.factory.logout(out_seq, None);
                        let _ = self.send_admin(framed, frame).await;
                        let _ = session.disconnect();
                        let text = raw
                            .get_field_str(58)
                            .unwrap_or("logout initiated by counterparty");
                        Err(closed(format!("logout by counterparty: {text}"), true))
                    }
                },
                // All admin types are matched above.
                _ => Ok(phase),
            }
        } else {
            if let Err(reason) = self.application.from_app(&raw, &self.session_id).await {
                let out_seq = self.runtime.sequences.allocate_sender_seq().value();
                let frame = self
                    .factory
                    .session_reject(out_seq, seq, msg_type.as_str(), &reason);
                if let Err(err) = self.send_admin(framed, frame).await {
                    teardown(phase);
                    return Err(closed(format!("send failed: {err}"), false));
                }
            }
            Ok(phase)
        }
    }
}
