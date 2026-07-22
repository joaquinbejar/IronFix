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
//! [`Initiator`](crate::Initiator) uses (see [`crate::reactor`]). The returned
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
//! then the `HeartBtInt` (108) the initiator requested is bounded, honored, and
//! echoed, `ResetSeqNumFlag` (141) is reconciled with the local
//! `reset_on_logon` knob and mirrored on the ack, and finally `MsgSeqNum` is
//! validated. A failure at any step sends a session Reject (reason 9 for
//! identity, the `SendingTime` reason for a clock problem) and/or a Logout,
//! drives the typestate to `reject_logon`, and drops the connection without ever
//! reaching Active. Waiting for the inbound Logon is bounded by
//! [`SessionConfig::logon_timeout`]. A gap in the Logon completes the handshake
//! and immediately issues a `ResendRequest` (2).
//!
//! `HeartBtInt` (108) is counterparty-controlled and drives a `Duration` on the
//! heartbeat clock, so it is bounded at the handshake: a value large enough to
//! overflow `interval + grace` would otherwise abort the process under
//! `panic = "abort"`. `ResetSeqNumFlag` (141) is reconciled coherently — the
//! acceptor resets when the peer asks *or* when it is locally configured to, and
//! whichever drives the reset the ack carries `141=Y` so the peer resets in
//! lockstep instead of silently desyncing.
//!
//! Every handshake frame goes through the same peek-then-spend path the reactor
//! uses ([`send_handshake_admin`](crate::reactor)): the `to_admin` callback runs
//! on the message before it is framed, the body is re-checked, and the sender
//! sequence number is spent only once the frame has been built. Once the session
//! is Active the shared session reactor runs identically for both roles. All
//! sequence arithmetic goes through the checked
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
use crate::reactor::{
    DEFAULT_APP_QUEUE_CAPACITY, DEFAULT_OUTBOUND_CAPACITY, DEFAULT_WRITE_TIMEOUT, ResendState,
    SessionParams, lock_heartbeat, send_handshake_admin, spawn_session,
};
use crate::wire::{self, MessageFactory, PeerIdentity, SendingTimeGuard, UnsupportedVersion};
use futures_util::StreamExt;
use ironfix_core::message::MsgType;
use ironfix_core::version::FixVersion;
use ironfix_session::sequence::SequenceResult;
use ironfix_session::{Disconnected, HeartbeatManager, SequenceManager, Session, SessionConfig};
use ironfix_transport::FixCodec;
use std::collections::HashSet;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
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
#[derive(Debug)]
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
    /// Initial (sender, target) sequence numbers for session continuity.
    initial_sequences: Option<(u64, u64)>,
    /// Capacity of the outbound command queue.
    outbound_capacity: usize,
    /// Sessions currently live on this acceptor, one entry per admitted
    /// counterparty. Shared across every [`Acceptor::serve`] call so a second
    /// concurrent Logon for a session already established is refused rather than
    /// forking it. See [`AdmissionGuard`].
    admitted: Arc<Mutex<HashSet<SessionId>>>,
}

impl<A: Application + 'static> Acceptor<A> {
    /// Creates a new acceptor.
    ///
    /// # Arguments
    /// * `config` - The session configuration (sender = this acceptor's CompID,
    ///   target = the initiator it expects)
    /// * `application` - The application callback handler
    #[must_use]
    pub fn new(config: SessionConfig, application: Arc<A>) -> Self {
        let session_id = wire::session_id_from_config(&config);
        let version = wire::wire_version(&config.begin_string);

        Self {
            config,
            application,
            session_id,
            version,
            initial_sequences: None,
            outbound_capacity: DEFAULT_OUTBOUND_CAPACITY,
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

    /// Seeds each accepted session with initial sequence numbers, for
    /// continuity with a previous session. Ignored when the inbound Logon
    /// carries `ResetSeqNumFlag` (141) = Y, which resets both counters to 1.
    ///
    /// # Arguments
    /// * `sender_seq` - Next outgoing sequence number
    /// * `target_seq` - Next expected incoming sequence number
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

    /// Accepts the next inbound connection on `listener` and establishes a
    /// session on it.
    ///
    /// This is a thin convenience over [`Acceptor::serve`]: it awaits one TCP
    /// connection and hands the stream to the handshake. For concurrent
    /// handshakes, run the accept loop yourself and spawn a `serve` per
    /// connection (see the module example).
    ///
    /// # Arguments
    /// * `listener` - A bound [`TcpListener`]
    ///
    /// # Errors
    /// Returns [`EngineError::Io`] if the TCP accept fails, or any error
    /// [`Acceptor::serve`] can produce.
    pub async fn accept(&self, listener: &TcpListener) -> Result<Connection, EngineError> {
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
    /// # Arguments
    /// * `stream` - An accepted TCP connection from the counterparty
    ///
    /// # Errors
    /// Returns an [`EngineError`] if framing or the Logon handshake fails. That
    /// includes [`EngineError::LogonTimeout`] when no Logon arrives within
    /// [`SessionConfig::logon_timeout`], [`EngineError::UnexpectedMessage`] when
    /// the first frame is not a Logon, [`EngineError::IdentityMismatch`] when
    /// the Logon's CompIDs do not match the configured counterparty, and
    /// [`EngineError::SequenceExhausted`] when a sequence counter has reached
    /// `u64::MAX`. [`EngineError::LogonRejected`] covers the acceptor-side
    /// refusals: the `from_admin` authentication hook, a `BeginString` (8) that
    /// does not match this session's version, an unsupported `EncryptMethod`
    /// (98), a `HeartBtInt` (108) that is missing, non-numeric, or out of range,
    /// and a second concurrent Logon for a session already established. A
    /// `BeginString` this engine cannot frame *at all* is refused up front with
    /// [`EngineError::UnsupportedVersion`].
    pub async fn serve(&self, stream: TcpStream) -> Result<Connection, EngineError> {
        // Refuse before framing: an unsupported version cannot produce a
        // conforming Logon reply, and guessing one would put a fabricated
        // version on the wire.
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

        // Typestate: Disconnected -> Connecting (acceptor side).
        let session = Session::<Disconnected>::new(session_id.to_string()).accept();

        let _ = stream.set_nodelay(true);
        let codec = FixCodec::new()
            .with_max_message_size(self.config.max_message_size)
            .with_checksum_validation(self.config.validate_checksum);
        let mut framed = Framed::new(stream, codec);

        let sequences = match self.initial_sequences {
            Some((sender, target)) if !self.config.reset_on_logon => {
                // MsgSeqNum starts at 1, so a zero seed is floored to 1 rather
                // than numbering a message 0 that every counterparty rejects.
                SequenceManager::with_initial(
                    NonZeroU64::new(sender).unwrap_or(NonZeroU64::MIN),
                    NonZeroU64::new(target).unwrap_or(NonZeroU64::MIN),
                )
            }
            _ => SequenceManager::new(),
        };
        let runtime = Arc::new(SessionRuntime {
            sequences,
            heartbeat: Mutex::new(HeartbeatManager::new(self.config.heartbeat_interval)),
        });
        let mut factory = MessageFactory::new(&self.config, version);
        let identity = PeerIdentity::new(&self.config);
        let sending_time = SendingTimeGuard::new(&self.config);

        // Await the inbound Logon, bounded by logon_timeout.
        let logon_frame = match timeout(self.config.logon_timeout, framed.next()).await {
            Err(_) => {
                let _ = session.disconnect();
                return Err(EngineError::LogonTimeout(self.config.logon_timeout));
            }
            Ok(None) => {
                let _ = session.disconnect();
                return Err(EngineError::Closed);
            }
            Ok(Some(Err(err))) => {
                let _ = session.disconnect();
                return Err(err.into());
            }
            Ok(Some(Ok(frame))) => frame,
        };

        // Typestate: Connecting -> LogonReceived.
        let session = session.on_logon_received();

        // (gap start, high-water) of a gap detected in the inbound Logon.
        let mut pending_resend: Option<(u64, u64)> = None;
        // The admission claim is taken once identity is validated and moved into
        // the reactor task on success; on any handshake failure after the claim
        // this local drops and frees the slot. Assigned on the fall-through path
        // out of the block below; every path before the claim returns first.
        let admission;
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
                let _ = send_handshake_admin(
                    self.application.as_ref(),
                    &session_id,
                    &mut framed,
                    &mut factory,
                    &runtime.sequences,
                    None,
                    DEFAULT_WRITE_TIMEOUT,
                    logout,
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
                let _ = send_handshake_admin(
                    self.application.as_ref(),
                    &session_id,
                    &mut framed,
                    &mut factory,
                    &runtime.sequences,
                    None,
                    DEFAULT_WRITE_TIMEOUT,
                    logout,
                )
                .await;
                let _ = session.reject_logon();
                return Err(EngineError::LogonRejected { reason: detail });
            }

            // MsgSeqNum (34) must sit in the standard header: a body-only 34 is
            // not the session sequence number, exactly as the identity check
            // requires 49/56 in the header.
            let logon_seq = match wire::header_seq_num(&raw) {
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
                let _ = send_handshake_admin(
                    self.application.as_ref(),
                    &session_id,
                    &mut framed,
                    &mut factory,
                    &runtime.sequences,
                    None,
                    DEFAULT_WRITE_TIMEOUT,
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
                    None,
                    DEFAULT_WRITE_TIMEOUT,
                    logout,
                )
                .await;
                let _ = session.reject_logon();
                return Err(EngineError::IdentityMismatch { detail });
            }

            // Identity is proven: claim the single admission slot. A second
            // concurrent Logon for this same counterparty is refused here rather
            // than allowed to fork the session into two independent sequence
            // streams both starting at 1. Policy: the live session is preserved
            // and the newcomer is logged out.
            admission = match self.try_admit() {
                Some(guard) => guard,
                None => {
                    let detail = format!("session already active for {session_id}");
                    tracing::warn!(session = %session_id, "refusing duplicate concurrent Logon");
                    let logout = factory.logout(Some(&detail));
                    let _ = send_handshake_admin(
                        self.application.as_ref(),
                        &session_id,
                        &mut framed,
                        &mut factory,
                        &runtime.sequences,
                        None,
                        DEFAULT_WRITE_TIMEOUT,
                        logout,
                    )
                    .await;
                    let _ = session.reject_logon();
                    return Err(EngineError::LogonRejected { reason: detail });
                }
            };

            // The clock is checked next, before the heartbeat is set: an
            // initiator whose SendingTime is wildly skewed cannot be trusted to
            // sequence a session, and the handshake is the cheapest place to
            // refuse it.
            if let Err(problem) = sending_time.validate(&raw) {
                let detail = problem.to_string();
                let reason = problem.reject_reason();
                let reject = factory.session_reject(logon_seq, MsgType::Logon.as_str(), &reason);
                let _ = send_handshake_admin(
                    self.application.as_ref(),
                    &session_id,
                    &mut framed,
                    &mut factory,
                    &runtime.sequences,
                    None,
                    DEFAULT_WRITE_TIMEOUT,
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
                    None,
                    DEFAULT_WRITE_TIMEOUT,
                    logout,
                )
                .await;
                let _ = session.reject_logon();
                return Err(EngineError::SendingTime { detail });
            }

            // Authentication hook: the application inspects the Logon (Username
            // 553 / Password 554 and the like) and may refuse it.
            if let Err(reason) = self.application.from_admin(&raw, &session_id).await {
                let logout = factory.logout(Some(&reason.text));
                let _ = send_handshake_admin(
                    self.application.as_ref(),
                    &session_id,
                    &mut framed,
                    &mut factory,
                    &runtime.sequences,
                    None,
                    DEFAULT_WRITE_TIMEOUT,
                    logout,
                )
                .await;
                let _ = session.reject_logon();
                return Err(EngineError::LogonRejected {
                    reason: reason.text,
                });
            }

            // Honor the heartbeat interval the initiator requested (HeartBtInt,
            // 108): the acceptor adopts it and echoes it back on the reply. The
            // value is counterparty-controlled and drives a Duration on the
            // heartbeat clock, so it is bounded here — a missing, non-numeric,
            // or over-range 108 fails the handshake rather than being defaulted
            // or, at u64::MAX, overflowing the clock and aborting the process.
            let requested_heartbeat_secs = match wire::parse_heartbeat_interval(&raw) {
                Ok(secs) => secs,
                Err(problem) => {
                    let detail = problem.to_string();
                    tracing::warn!(session = %session_id, detail = %detail, "rejecting Logon HeartBtInt");
                    let logout = factory.logout(Some(&detail));
                    let _ = send_handshake_admin(
                        self.application.as_ref(),
                        &session_id,
                        &mut framed,
                        &mut factory,
                        &runtime.sequences,
                        None,
                        DEFAULT_WRITE_TIMEOUT,
                        logout,
                    )
                    .await;
                    let _ = session.reject_logon();
                    return Err(EngineError::LogonRejected { reason: detail });
                }
            };
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

            // ResetSeqNumFlag (141): the acceptor resets when the peer asks
            // (141=Y) *or* when it is locally configured to (`reset_on_logon`).
            // Whichever drives the reset, the ack must signal it with 141=Y so
            // the peer resets in lockstep — a local reset that seeded fresh
            // counters but acked without 141 would silently desync the peer.
            // The reset is applied before MsgSeqNum is validated, otherwise the
            // Logon's 34=1 reads as fatally too low against continuity-seeded
            // counters.
            let inbound_reset = raw.get_field_str(141) == Some("Y");
            let reset = inbound_reset || self.config.reset_on_logon;
            if inbound_reset && logon_seq != 1 {
                // FIX requires MsgSeqNum = 1 on a Logon that itself carries
                // ResetSeqNumFlag = Y: the reset and the number carrying it have
                // to describe the same stream. This binds only when the *peer*
                // declared the reset; a purely local reset places no such
                // requirement on the number the peer chose.
                let _ = session.reject_logon();
                return Err(EngineError::Sequence(format!(
                    "Logon set ResetSeqNumFlag=Y but carried MsgSeqNum {logon_seq}, not 1"
                )));
            }
            if reset {
                tracing::info!(
                    session = %session_id,
                    inbound_reset,
                    "resetting sequence numbers on Logon"
                );
                runtime.sequences.reset();
            }

            match runtime.sequences.validate_incoming(logon_seq) {
                SequenceResult::Ok => {
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
                    let _ = send_handshake_admin(
                        self.application.as_ref(),
                        &session_id,
                        &mut framed,
                        &mut factory,
                        &runtime.sequences,
                        None,
                        DEFAULT_WRITE_TIMEOUT,
                        logout,
                    )
                    .await;
                    let _ = session.reject_logon();
                    return Err(EngineError::Sequence(detail));
                }
                SequenceResult::Gap { expected, received } => {
                    pending_resend = Some((expected, received));
                }
            }

            // Reply with the Logon acknowledgement, mirroring ResetSeqNumFlag.
            // The peek-then-spend `send_handshake_admin` frames it under the next
            // sender sequence number (1 after a reset) and spends that number
            // only once the frame is built.
            let logon_ack = factory.logon(reply_heartbeat_secs, reset);
            if let Err(err) = send_handshake_admin(
                self.application.as_ref(),
                &session_id,
                &mut framed,
                &mut factory,
                &runtime.sequences,
                None,
                DEFAULT_WRITE_TIMEOUT,
                logon_ack,
            )
            .await
            {
                let _ = session.reject_logon();
                return Err(err);
            }
            lock_heartbeat(&runtime).on_message_sent();
        }

        // Typestate: LogonReceived -> Active.
        let session = session.accept_logon();
        self.application.on_logon(&session_id).await;
        tracing::info!(session = %session_id, "FIX session established (acceptor)");

        // A gap in the inbound Logon means we missed messages: request a resend
        // now that the session is Active.
        if let Some((expected, _high_water)) = pending_resend {
            let request = factory.resend_request(expected, 0);
            send_handshake_admin(
                self.application.as_ref(),
                &session_id,
                &mut framed,
                &mut factory,
                &runtime.sequences,
                None,
                DEFAULT_WRITE_TIMEOUT,
                request,
            )
            .await?;
            lock_heartbeat(&runtime).on_message_sent();
        }

        let resend = pending_resend
            .map(|(expected, high_water)| ResendState::first(expected, high_water, &self.config));
        // Hand the framed socket to the shared reactor, the same one the
        // initiator uses. The admission guard rides the reactor task and frees
        // the slot when the session closes. The acceptor attaches no store, so
        // resends are gap-filled.
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
            store: None,
            resend,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            outbound_capacity: self.outbound_capacity,
            app_queue_capacity: DEFAULT_APP_QUEUE_CAPACITY,
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
