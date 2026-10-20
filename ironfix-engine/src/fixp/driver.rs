/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! The FIXP driver: one task per transport that composes SOFH framing with
//! the sans-IO FIXP session core (ADR-0002, ADR-0003).
//!
//! The loop takes three inputs: SOFH frames from the transport, commands
//! from [`FixpConnection`] handles, and the core's next deadline. Each input
//! goes to the core with the current [`Instant`], and the core's outputs are
//! carried out in order: session messages encoded and framed, application
//! messages framed and (on a Recoverable flow) kept for retransmission,
//! events handed to the application, a transport close.
//!
//! Routing (FIXP v1.1 section 3.1, SOFH v1.0): a frame whose encoding type
//! is SBE 1.0 little-endian and whose SBE header names the FIXP schema
//! (id 2748) is a session message; every other frame is an application
//! message, numbered implicitly by the core (section 3.5.1).
//!
//! The task always ends: on the transport's end of stream, on a read, write
//! or framing error, or when the core asks for the transport to be closed;
//! the core's own timers bound every handshake step, the counterparty's
//! silence and the termination wait. On its way out it tells the core the
//! transport is closed, hands the remaining events to the application,
//! signals the `watch` channel the handles wait on, and resolves a pending
//! handshake.

use crate::fixp::application::{
    EstablishRequest, EstablishmentDecision, FixpApplication, FixpInbound, NegotiateRequest,
    NegotiationDecision,
};
use crate::fixp::connection::{Command, FixpConnection};
use crate::fixp::error::FixpEngineError;
use crate::stream::SessionStream;
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use ironfix_core::SeqNum;
use ironfix_fixp::{
    Credentials, Delivery, Event, FixpClient, FixpError, FixpServer, FlowType,
    NegotiationRejectCode, Output, RetransmitRejectCode, SessionId, SessionMessage, SessionStatus,
    TerminationCode, is_session_message,
};
use ironfix_sofh::{EncodingType, SofhCodec, SofhFrame, SofhHeader};
use std::collections::{BTreeMap, HashSet};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_util::codec::{Encoder, FramedRead};

/// Capacity of the command channel between handles and the driver.
const COMMAND_CAPACITY: usize = 1024;

/// Callbacks queued but not yet run above which the driver stops reading
/// the transport (backpressure). Commands and timers are still served, so a
/// callback awaiting its connection never waits on a stalled driver.
const MAX_QUEUED_CALLBACKS: usize = 1024;

/// Outbound bytes buffered above which the driver stops taking commands
/// (the counterparty is reading slowly). It keeps reading and writing.
const OUTBOUND_SOFT_LIMIT: usize = 1024 * 1024;

/// Outbound bytes buffered above which the transport is closed: the
/// session's own traffic (heartbeats, retransmissions) cannot grow without
/// bound against a counterparty that never reads.
const OUTBOUND_HARD_LIMIT: usize = 16 * 1024 * 1024;

/// A handshake decision the application is computing, in its own task so
/// the driver keeps reading (a disconnect), running the core's handshake
/// deadline and writing while it waits.
enum PendingDecision {
    Negotiation(JoinHandle<NegotiationDecision>),
    Establishment(JoinHandle<EstablishmentDecision>),
}

/// A decision that arrived.
enum Decided {
    Negotiation(NegotiationDecision),
    Establishment(EstablishmentDecision),
    /// The decision task panicked or was cancelled.
    Lost,
}

/// Waits for the pending decision; for ever without one.
async fn decided(pending: &mut Option<PendingDecision>) -> Decided {
    match pending {
        Some(PendingDecision::Negotiation(task)) => match task.await {
            Ok(decision) => Decided::Negotiation(decision),
            Err(_) => Decided::Lost,
        },
        Some(PendingDecision::Establishment(task)) => match task.await {
            Ok(decision) => Decided::Establishment(decision),
            Err(_) => Decided::Lost,
        },
        None => std::future::pending().await,
    }
}

/// Moves buffered bytes to the transport: writes what it can, then flushes
/// once the buffer is empty. Cancel-safe: `write_buf` advances the buffer
/// only by what was written.
async fn drive_write(
    writer: &mut WriteHalf<SessionStream>,
    buffer: &mut BytesMut,
) -> std::io::Result<Written> {
    if buffer.is_empty() {
        writer.flush().await.map(|()| Written::Flushed)
    } else {
        match writer.write_buf(buffer).await? {
            0 => Err(std::io::ErrorKind::WriteZero.into()),
            _ => Ok(Written::Wrote),
        }
    }
}

/// What one [`drive_write`] did.
enum Written {
    Wrote,
    Flushed,
}

/// A callback the driver hands to the session's callback task.
///
/// The driver never awaits a callback that receives or may hold this
/// session's [`FixpConnection`]: `on_established`, `on_message`, `on_event`
/// and `on_closed` run, in order, in a separate task, so they may await
/// `send`, `terminate` or `wait_closed` on it. The handshake decisions
/// (`on_negotiate`, `on_establish`) are not callbacks of this queue: each
/// runs in a task of its own ([`PendingDecision`]), under the core's
/// handshake deadline, and is aborted when the transport closes.
enum Callback {
    Established(FixpConnection),
    Message(SessionId, FixpInbound),
    Event(Option<SessionId>, Event),
    Closed(Option<SessionId>),
}

/// The callback task: runs queued callbacks in order until the driver drops
/// its sender, which it does when it ends.
async fn run_callbacks<A: FixpApplication>(
    app: Arc<A>,
    mut queue: mpsc::UnboundedReceiver<Callback>,
    queued: Arc<AtomicUsize>,
    drained: Arc<Notify>,
) {
    while let Some(callback) = queue.recv().await {
        match callback {
            Callback::Established(connection) => app.on_established(connection).await,
            Callback::Message(session_id, message) => app.on_message(session_id, message).await,
            Callback::Event(session_id, event) => app.on_event(session_id, &event).await,
            Callback::Closed(session_id) => app.on_closed(session_id).await,
        }
        queued.fetch_sub(1, Ordering::AcqRel);
        drained.notify_one();
    }
}

/// The current monotonic time, from tokio's clock so that a paused test
/// clock drives the session timers too.
fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// The session ids an acceptor knows: live on one of its transports, and
/// finalized (FIXP v1.1 section 4.7.2). The core tracks finalization in
/// memory per role instance; a new transport gets a new [`FixpServer`], so
/// the acceptor remembers it across transports.
#[derive(Debug, Default)]
pub(crate) struct SessionRegistry {
    inner: Mutex<RegistryInner>,
}

#[derive(Debug, Default)]
struct RegistryInner {
    live: HashSet<SessionId>,
    finalized: HashSet<SessionId>,
}

/// Why the registry refused a Negotiate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    Finalized,
    Live,
}

impl SessionRegistry {
    /// Claims `id` for a new negotiation, unless it is finalized or live.
    fn claim(&self, id: SessionId) -> Result<(), Refusal> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if inner.finalized.contains(&id) {
            return Err(Refusal::Finalized);
        }
        if !inner.live.insert(id) {
            return Err(Refusal::Live);
        }
        Ok(())
    }

    /// Releases a claimed id, recording it as finalized when it was.
    fn release(&self, id: SessionId, finalized: bool) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.live.remove(&id);
        if finalized {
            inner.finalized.insert(id);
        }
    }

    pub(crate) fn is_finalized(&self, id: SessionId) -> bool {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.finalized.contains(&id)
    }
}

/// The settings of one driver.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DriverSettings {
    /// Largest SOFH `Message_Length` accepted and sent.
    pub(crate) max_message_size: u32,
    /// How many sent application messages are kept for retransmission.
    pub(crate) retransmit_capacity: usize,
    /// Bound on one write and flush.
    pub(crate) write_timeout: Duration,
}

/// The session core of either role.
enum Role {
    Client(Box<FixpClient>),
    Server {
        server: Box<FixpServer>,
        registry: Arc<SessionRegistry>,
    },
}

impl Role {
    fn poll_output(&mut self) -> Option<Output> {
        match self {
            Self::Client(c) => c.poll_output(),
            Self::Server { server, .. } => server.poll_output(),
        }
    }
    fn handle_message(&mut self, message: &SessionMessage, now: Instant) {
        match self {
            Self::Client(c) => c.handle_message(message, now),
            Self::Server { server, .. } => server.handle_message(message, now),
        }
    }
    fn on_application_message(&mut self, now: Instant) -> Delivery {
        match self {
            Self::Client(c) => c.on_application_message(now),
            Self::Server { server, .. } => server.on_application_message(now),
        }
    }
    fn send_application(&mut self, now: Instant) -> Result<Option<SeqNum>, FixpError> {
        match self {
            Self::Client(c) => c.send_application(now),
            Self::Server { server, .. } => server.send_application(now),
        }
    }
    fn terminate(
        &mut self,
        code: TerminationCode,
        reason: String,
        now: Instant,
    ) -> Result<(), FixpError> {
        match self {
            Self::Client(c) => c.terminate(code, reason, now),
            Self::Server { server, .. } => server.terminate(code, reason, now),
        }
    }
    fn retransmit(
        &mut self,
        count: NonZeroU32,
        now: Instant,
    ) -> Result<ironfix_fixp::RetransmitBatch, FixpError> {
        match self {
            Self::Client(c) => c.retransmit(count, now),
            Self::Server { server, .. } => server.retransmit(count, now),
        }
    }
    fn reject_retransmit_request(&mut self, reason: &str) -> Result<(), FixpError> {
        match self {
            Self::Client(c) => {
                c.reject_retransmit_request(RetransmitRejectCode::OutOfRange, reason)
            }
            Self::Server { server, .. } => {
                server.reject_retransmit_request(RetransmitRejectCode::OutOfRange, reason)
            }
        }
    }
    fn handle_timeout(&mut self, now: Instant) {
        match self {
            Self::Client(c) => c.handle_timeout(now),
            Self::Server { server, .. } => server.handle_timeout(now),
        }
    }
    fn poll_timeout(&self) -> Option<Instant> {
        match self {
            Self::Client(c) => c.poll_timeout(),
            Self::Server { server, .. } => server.poll_timeout(),
        }
    }
    fn on_transport_closed(&mut self) {
        match self {
            Self::Client(c) => c.on_transport_closed(),
            Self::Server { server, .. } => server.on_transport_closed(),
        }
    }
    fn status(&self) -> SessionStatus {
        match self {
            Self::Client(c) => c.status(),
            Self::Server { server, .. } => server.status(),
        }
    }
    fn session_id(&self) -> Option<SessionId> {
        match self {
            Self::Client(c) => Some(c.session_id()),
            Self::Server { server, .. } => server.session_id(),
        }
    }
    /// The flow of the messages this side sends, once negotiated.
    fn local_flow(&self) -> Option<FlowType> {
        match self {
            Self::Client(c) => Some(c.client_flow()),
            Self::Server { server, .. } => server.server_flow(),
        }
    }
}

/// The application messages this side sent on a Recoverable flow, by
/// sequence number, bounded by `capacity` (oldest dropped first).
#[derive(Debug)]
struct SentMessages {
    frames: BTreeMap<u64, SofhFrame>,
    capacity: usize,
}

impl SentMessages {
    fn insert(&mut self, seq: SeqNum, frame: SofhFrame) {
        if self.capacity == 0 {
            return;
        }
        self.frames.insert(seq.value(), frame);
        while self.frames.len() > self.capacity {
            self.frames.pop_first();
        }
    }

    /// The frames `from .. from + count`, or `None` when any is missing.
    fn range(&self, from: SeqNum, count: u32) -> Option<Vec<SofhFrame>> {
        let first = from.value();
        let Some(end) = first.checked_add(u64::from(count)) else {
            debug_assert!(false, "a validated retransmit range overflows u64");
            return None;
        };
        let frames: Vec<SofhFrame> = self
            .frames
            .range(first..end)
            .map(|(_, f)| f.clone())
            .collect();
        (frames.len() == usize::try_from(count).ok()?).then_some(frames)
    }
}

/// The result an entry point waits for.
pub(crate) type Handshake = oneshot::Receiver<Result<FixpConnection, FixpEngineError>>;

/// One FIXP session on one transport.
pub(crate) struct Driver<A: FixpApplication> {
    role: Role,
    reader: FramedRead<ReadHalf<SessionStream>, SofhCodec>,
    writer: WriteHalf<SessionStream>,
    /// Encodes outbound frames into `outbound`.
    encoder: SofhCodec,
    /// Bytes framed and not yet written. Writing is polled alongside
    /// reading, so a counterparty that writes while not reading cannot
    /// stall this side's reads (the bilateral deadlock of #126).
    outbound: BytesMut,
    /// Written bytes not yet flushed.
    needs_flush: bool,
    /// Since when the outbound buffer has made no progress.
    write_stalled_since: Option<Instant>,
    /// The application's handshake decision being computed.
    pending_decision: Option<PendingDecision>,
    app: Arc<A>,
    settings: DriverSettings,
    commands: mpsc::Receiver<Command>,
    /// The queue of the callback task.
    callbacks: mpsc::UnboundedSender<Callback>,
    /// Callbacks queued and not yet run.
    queued: Arc<AtomicUsize>,
    /// Signalled by the callback task after each callback.
    drained: Arc<Notify>,
    connection: FixpConnection,
    closed: watch::Sender<bool>,
    handshake: Option<oneshot::Sender<Result<FixpConnection, FixpEngineError>>>,
    sent: SentMessages,
    /// The credentials of the last Negotiate or Establish received (server).
    pending_credentials: Option<Credentials>,
    /// A retransmission range to replay once the outputs are drained.
    pending_replay: Option<Vec<SofhFrame>>,
    /// The core asked for the transport to be closed.
    close_requested: bool,
    /// Close once the queued outputs are written.
    close_after_drain: bool,
    /// The error that ended the transport, if any.
    failure: Option<FixpEngineError>,
    /// The session id this server claimed in the registry.
    claimed: Option<SessionId>,
    /// The core reported the session finalized.
    finalized: bool,
}

impl<A: FixpApplication> Driver<A> {
    /// Spawns the driver task of a client; it negotiates and establishes at
    /// once.
    pub(crate) fn spawn_client(
        client: FixpClient,
        stream: SessionStream,
        app: Arc<A>,
        settings: DriverSettings,
    ) -> Handshake {
        let session_id = client.session_id();
        Self::spawn(
            Role::Client(Box::new(client)),
            session_id,
            stream,
            app,
            settings,
        )
    }

    /// Spawns the driver task of a server waiting for a Negotiate.
    pub(crate) fn spawn_server(
        server: FixpServer,
        registry: Arc<SessionRegistry>,
        stream: SessionStream,
        app: Arc<A>,
        settings: DriverSettings,
    ) -> Handshake {
        // The handle's id is set when the Negotiate names it; until then the
        // nil id is a placeholder no handle is ever built with.
        Self::spawn(
            Role::Server {
                server: Box::new(server),
                registry,
            },
            SessionId::from_bytes([0; 16]),
            stream,
            app,
            settings,
        )
    }

    fn spawn(
        role: Role,
        session_id: SessionId,
        stream: SessionStream,
        app: Arc<A>,
        settings: DriverSettings,
    ) -> Handshake {
        let (tx, commands) = mpsc::channel(COMMAND_CAPACITY);
        let (closed, closed_rx) = watch::channel(false);
        let (handshake, result) = oneshot::channel();
        let codec = SofhCodec::new().with_max_message_size(settings.max_message_size);
        let (read_half, write_half) = tokio::io::split(stream);
        let (callbacks, queue) = mpsc::unbounded_channel();
        let queued = Arc::new(AtomicUsize::new(0));
        let drained = Arc::new(Notify::new());
        // Ends once the driver drops `callbacks` and the queue is run.
        tokio::spawn(run_callbacks(
            Arc::clone(&app),
            queue,
            Arc::clone(&queued),
            Arc::clone(&drained),
        ));
        let driver = Self {
            role,
            reader: FramedRead::new(read_half, codec),
            writer: write_half,
            encoder: SofhCodec::new().with_max_message_size(settings.max_message_size),
            outbound: BytesMut::new(),
            needs_flush: false,
            write_stalled_since: None,
            pending_decision: None,
            app,
            settings,
            commands,
            callbacks,
            queued,
            drained,
            connection: FixpConnection::new(session_id, tx, closed_rx),
            closed,
            handshake: Some(handshake),
            sent: SentMessages {
                frames: BTreeMap::new(),
                capacity: settings.retransmit_capacity,
            },
            pending_credentials: None,
            pending_replay: None,
            close_requested: false,
            close_after_drain: false,
            failure: None,
            claimed: None,
            finalized: false,
        };
        // The task's shutdown path is `run`'s epilogue, reached from every
        // exit of its loop.
        tokio::spawn(driver.run());
        result
    }

    async fn run(mut self) {
        if let Role::Client(client) = &mut self.role
            && let Err(error) = client.negotiate(now())
        {
            self.failure = Some(error.into());
            self.close_requested = true;
        }
        self.process_outputs().await;

        while !self.close_requested {
            let deadline = self.role.poll_timeout();
            let reading = self.queued.load(Ordering::Acquire) < MAX_QUEUED_CALLBACKS;
            let writing = !self.outbound.is_empty() || self.needs_flush;
            let accepting = self.outbound.len() < OUTBOUND_SOFT_LIMIT;
            let stall_deadline = self
                .write_stalled_since
                .and_then(|since| since.checked_add(self.settings.write_timeout));
            tokio::select! {
                () = self.drained.notified(), if !reading => {}
                written = drive_write(&mut self.writer, &mut self.outbound), if writing => {
                    self.on_written(written);
                }
                () = sleep_until(stall_deadline), if stall_deadline.is_some() => {
                    let timeout = self.settings.write_timeout;
                    tracing::warn!(?timeout, "fixp write made no progress; closing");
                    self.fail(FixpEngineError::WriteTimeout(timeout));
                }
                decision = decided(&mut self.pending_decision), if self.pending_decision.is_some() => {
                    self.pending_decision = None;
                    self.on_decided(decision).await;
                }
                frame = self.reader.next(), if reading => match frame {
                    Some(Ok(frame)) => self.on_frame(frame).await,
                    Some(Err(error)) => {
                        tracing::warn!(%error, "fixp transport framing error; closing");
                        self.fail(error.into());
                    }
                    None => {
                        tracing::debug!("fixp transport closed by the counterparty");
                        break;
                    }
                },
                command = self.commands.recv(), if accepting => match command {
                    Some(command) => self.on_command(command).await,
                    // The driver holds a sender in `connection`, so the
                    // channel never closes while it runs.
                    None => break,
                },
                () = sleep_until(deadline) => {
                    self.role.handle_timeout(now());
                    self.process_outputs().await;
                }
            }
        }
        self.shutdown().await;
    }

    /// Accounts for a write or flush of the outbound buffer.
    fn on_written(&mut self, written: std::io::Result<Written>) {
        match written {
            Ok(Written::Flushed) => {
                self.needs_flush = false;
                self.write_stalled_since = None;
            }
            Ok(Written::Wrote) => {
                // Progress: the stall clock restarts while bytes remain.
                self.needs_flush = true;
                self.write_stalled_since = Some(now());
            }
            Err(error) => {
                tracing::warn!(%error, "fixp write failed; closing");
                self.fail(error.into());
            }
        }
    }

    /// Queues a callback for the callback task; never waits for it.
    fn notify(&self, callback: Callback) {
        self.queued.fetch_add(1, Ordering::AcqRel);
        if self.callbacks.send(callback).is_err() {
            // The callback task is gone (the application panicked).
            self.queued.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Records the error that ends the transport.
    fn fail(&mut self, error: FixpEngineError) {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        self.close_requested = true;
    }

    async fn on_frame(&mut self, frame: SofhFrame) {
        let now = now();
        let (header, payload) = frame.into_parts();
        let encoding_type = header.encoding_type();
        if encoding_type == EncodingType::SbeV1LittleEndian && is_session_message(&payload) {
            match SessionMessage::decode(&payload) {
                Ok((message, _)) => {
                    match &message {
                        SessionMessage::Negotiate(m) => {
                            self.pending_credentials.clone_from(&m.credentials);
                        }
                        SessionMessage::Establish(m) => {
                            self.pending_credentials.clone_from(&m.credentials);
                        }
                        _ => {}
                    }
                    tracing::trace!(message = message.name(), "fixp session message in");
                    self.role.handle_message(&message, now);
                }
                Err(error) => {
                    // An untrusted, malformed session message: a protocol
                    // violation (FIXP v1.1 section 6.3). Terminate when
                    // established; otherwise close.
                    tracing::warn!(%error, "malformed fixp session message; unbinding");
                    if self
                        .role
                        .terminate(
                            TerminationCode::UnspecifiedError,
                            "malformed session message".to_owned(),
                            now,
                        )
                        .is_err()
                    {
                        self.fail(error.into());
                    } else if self.failure.is_none() {
                        self.failure = Some(error.into());
                    }
                }
            }
            self.process_outputs().await;
        } else {
            let delivery = self.role.on_application_message(now);
            self.process_outputs().await;
            if let Delivery::Accept { seq, retransmitted } = delivery
                && let Some(session_id) = self.role.session_id()
            {
                let message = FixpInbound {
                    seq,
                    retransmitted,
                    encoding_type,
                    payload,
                };
                self.notify(Callback::Message(session_id, message));
            }
        }
    }

    async fn on_command(&mut self, command: Command) {
        match command {
            Command::Send {
                encoding_type,
                payload,
                reply,
            } => {
                let result = self.send_application(encoding_type, payload).await;
                let _ = reply.send(result);
            }
            Command::Terminate { reason, reply } => {
                let result = self
                    .role
                    .terminate(TerminationCode::Finished, reason, now())
                    .map_err(FixpEngineError::from);
                self.process_outputs().await;
                let _ = reply.send(result);
            }
        }
    }

    async fn send_application(
        &mut self,
        encoding_type: EncodingType,
        payload: Bytes,
    ) -> Result<Option<SeqNum>, FixpEngineError> {
        if encoding_type == EncodingType::SbeV1LittleEndian && is_session_message(&payload) {
            return Err(FixpEngineError::ReservedSchema);
        }
        let max = self.settings.max_message_size;
        let fits = payload
            .len()
            .checked_add(SofhHeader::LEN)
            .is_some_and(|len| u32::try_from(len).is_ok_and(|len| len <= max));
        if !fits {
            return Err(FixpEngineError::PayloadTooLarge {
                len: payload.len(),
                max,
            });
        }
        let frame = SofhFrame::new(encoding_type, payload)?;
        let seq = self.role.send_application(now())?;
        // A Sequence may have to precede the message (FIXP v1.1 sections
        // 3.5.1, 3.5.4).
        self.process_outputs().await;
        if self.close_requested {
            return Err(self.failure_or_closed());
        }
        if let Some(seq) = seq
            && self.role.local_flow() == Some(FlowType::Recoverable)
        {
            self.sent.insert(seq, frame.clone());
        }
        self.write(frame).await;
        if self.close_requested {
            return Err(self.failure_or_closed());
        }
        Ok(seq)
    }

    fn failure_or_closed(&self) -> FixpEngineError {
        match &self.failure {
            Some(FixpEngineError::WriteTimeout(timeout)) => FixpEngineError::WriteTimeout(*timeout),
            Some(_) | None => FixpEngineError::Closed,
        }
    }

    /// Carries out every queued output, in order, then any retransmission
    /// the outputs asked for.
    async fn process_outputs(&mut self) {
        loop {
            while let Some(output) = self.role.poll_output() {
                self.on_output(output).await;
            }
            // FIXP v1.1 section 4.6.2: the stored messages follow the
            // Retransmission header immediately.
            match self.pending_replay.take() {
                Some(frames) => {
                    for frame in frames {
                        self.write(frame).await;
                    }
                }
                None => break,
            }
        }
        if self.close_after_drain {
            self.close_requested = true;
        }
    }

    async fn on_output(&mut self, output: Output) {
        match output {
            Output::Send(message) => self.write_session(&message, None).await,
            Output::SendApplication { seq, message } => {
                self.write_session(&message, seq).await;
            }
            Output::CloseTransport => {
                tracing::debug!("fixp session asked for the transport to be closed");
                self.close_requested = true;
            }
            Output::Event(event) => self.on_event(event).await,
            _ => {
                tracing::debug!("fixp output not handled by this driver");
            }
        }
    }

    async fn write_session(&mut self, message: &SessionMessage, seq: Option<SeqNum>) {
        if self.close_requested {
            return;
        }
        let mut bytes = Vec::new();
        if let Err(error) = message.encode(&mut bytes) {
            tracing::warn!(%error, message = message.name(), "cannot encode fixp session message");
            self.fail(error.into());
            return;
        }
        let frame = match SofhFrame::new(EncodingType::SbeV1LittleEndian, bytes) {
            Ok(frame) => frame,
            Err(error) => {
                self.fail(error.into());
                return;
            }
        };
        // A NotApplied numbered on a Recoverable flow is an application
        // message of that flow (section 4.8.1) and may be asked for again.
        if let Some(seq) = seq
            && self.role.local_flow() == Some(FlowType::Recoverable)
        {
            self.sent.insert(seq, frame.clone());
        }
        tracing::trace!(message = message.name(), "fixp session message out");
        self.write(frame).await;
    }

    /// Writes and flushes one frame, bounded by the write timeout.
    /// Frames one message into the outbound buffer. The run loop writes it
    /// out, polled alongside reads; [`DriverSettings::write_timeout`] bounds
    /// how long the buffer may go without progress.
    async fn write(&mut self, frame: SofhFrame) {
        if self.close_requested {
            return;
        }
        if let Err(error) = self.encoder.encode(frame, &mut self.outbound) {
            self.fail(error.into());
            return;
        }
        if self.write_stalled_since.is_none() {
            self.write_stalled_since = Some(now());
        }
        if self.outbound.len() > OUTBOUND_HARD_LIMIT {
            tracing::warn!(
                len = self.outbound.len(),
                "fixp outbound backlog too large; closing"
            );
            self.fail(FixpEngineError::OutboundBacklog {
                len: self.outbound.len(),
            });
        }
    }

    async fn on_event(&mut self, event: Event) {
        let now = now();
        match &event {
            Event::NegotiateReceived {
                session_id,
                client_flow,
            } => {
                self.notify(Callback::Event(Some(*session_id), event.clone()));
                self.decide_negotiation(*session_id, *client_flow);
                return;
            }
            Event::EstablishReceived {
                session_id,
                keepalive_interval,
                next_seq_no,
            } => {
                self.notify(Callback::Event(Some(*session_id), event.clone()));
                let request = EstablishRequest {
                    session_id: *session_id,
                    keepalive_interval: *keepalive_interval,
                    next_seq_no: *next_seq_no,
                    credentials: self.pending_credentials.take(),
                };
                let app = Arc::clone(&self.app);
                self.pending_decision =
                    Some(PendingDecision::Establishment(tokio::spawn(async move {
                        app.on_establish(&request).await
                    })));
                return;
            }
            Event::Negotiated { .. } => {
                if let Role::Client(client) = &mut self.role
                    && let Err(error) = client.establish(now)
                {
                    self.fail(error.into());
                }
            }
            Event::Established { .. } => {
                if let Some(handshake) = self.handshake.take() {
                    if let Some(session_id) = self.role.session_id() {
                        self.connection = self.connection.with_session_id(session_id);
                    }
                    let _ = handshake.send(Ok(self.connection.clone()));
                    self.notify(Callback::Established(self.connection.clone()));
                }
            }
            Event::NegotiationRejected { code, reason } => {
                self.failure
                    .get_or_insert(FixpEngineError::NegotiationRejected {
                        code: *code,
                        reason: reason.clone(),
                    });
            }
            Event::EstablishmentRejected { code, reason } => {
                self.failure
                    .get_or_insert(FixpEngineError::EstablishmentRejected {
                        code: *code,
                        reason: reason.clone(),
                    });
                // This driver does not retry an establishment on the same
                // transport; the client may on a new one (section 4.3.3).
                self.close_after_drain = true;
            }
            Event::HandshakeTimedOut { stage } => {
                self.failure
                    .get_or_insert(FixpEngineError::HandshakeTimedOut { stage: *stage });
            }
            Event::RetransmitRequested { from, count } => {
                self.serve_retransmission(*from, *count, now);
            }
            Event::SessionFinalized { session_id } => {
                tracing::info!(%session_id, "fixp session finalized");
                self.finalized = true;
            }
            _ => {}
        }
        self.notify(Callback::Event(self.role.session_id(), event));
    }

    /// Claims the identifier in the acceptor's registry, then asks the
    /// application, in a task of its own: while it decides, the driver keeps
    /// reading (a disconnect ends the session and releases the claim) and
    /// the core's handshake deadline keeps running (a lapse closes the
    /// transport, also releasing it).
    fn decide_negotiation(&mut self, session_id: SessionId, client_flow: FlowType) {
        let credentials = self.pending_credentials.take();
        let Role::Server { server, registry } = &mut self.role else {
            return;
        };
        // FIXP v1.1 section 6.3: a finalized identifier is never used again,
        // and section 3.4.1: identifiers are unique. The core only knows
        // its own transport, so the acceptor's registry answers.
        let refusal = match registry.claim(session_id) {
            Ok(()) => {
                self.claimed = Some(session_id);
                None
            }
            Err(Refusal::Finalized) => Some("the session is finalized"),
            Err(Refusal::Live) => Some("the session is already negotiated"),
        };
        if let Some(reason) = refusal {
            tracing::info!(%session_id, reason, "fixp negotiate refused by the acceptor");
            if let Err(error) =
                server.reject_negotiation(NegotiationRejectCode::DuplicateId, reason)
            {
                self.fail(error.into());
            }
            return;
        }
        let request = NegotiateRequest {
            session_id,
            client_flow,
            credentials,
        };
        let app = Arc::clone(&self.app);
        self.pending_decision = Some(PendingDecision::Negotiation(tokio::spawn(async move {
            app.on_negotiate(&request).await
        })));
    }

    /// Applies the application's handshake decision to the core.
    async fn on_decided(&mut self, decided: Decided) {
        let now = now();
        let Role::Server { server, .. } = &mut self.role else {
            return;
        };
        let result = match decided {
            Decided::Negotiation(NegotiationDecision::Accept {
                server_flow,
                credentials,
            }) => server.accept_negotiation(server_flow, credentials, now),
            Decided::Negotiation(NegotiationDecision::Reject { code, reason }) => {
                server.reject_negotiation(code, reason)
            }
            Decided::Establishment(EstablishmentDecision::Accept) => {
                server.accept_establishment(now)
            }
            Decided::Establishment(EstablishmentDecision::Reject { code, reason }) => {
                self.failure
                    .get_or_insert(FixpEngineError::EstablishmentRejected {
                        code,
                        reason: reason.clone(),
                    });
                // One binding per transport: a refused client tries again on
                // a new one (section 4.3.3).
                self.close_after_drain = true;
                server.reject_establishment(code, reason, now)
            }
            Decided::Lost => {
                self.fail(FixpEngineError::HandshakeFailed {
                    detail: "the application's handshake decision failed".to_owned(),
                });
                return;
            }
        };
        if let Err(error) = result {
            tracing::warn!(%error, "fixp handshake decision refused by the core");
            self.fail(error.into());
        }
        self.process_outputs().await;
    }

    /// Answers a RetransmitRequest from the stored messages, in one batch,
    /// or refuses it with `OutOfRange` when they are no longer all kept
    /// (FIXP v1.1 section 4.6.2.3).
    fn serve_retransmission(&mut self, from: SeqNum, count: u32, now: Instant) {
        let frames = self.sent.range(from, count);
        let result = match (frames, NonZeroU32::new(count)) {
            (Some(frames), Some(count)) => match self.role.retransmit(count, now) {
                Ok(_) => {
                    self.pending_replay = Some(frames);
                    Ok(())
                }
                Err(error) => Err(error),
            },
            (None, _) | (_, None) => {
                tracing::info!(
                    from = from.value(),
                    count,
                    "fixp retransmission refused: not stored"
                );
                self.role
                    .reject_retransmit_request("messages no longer stored")
            }
        };
        if let Err(error) = result {
            tracing::warn!(%error, "fixp retransmission failed");
            self.fail(error.into());
        }
    }

    async fn shutdown(&mut self) {
        if let Some(decision) = self.pending_decision.take() {
            // The decision no longer matters; a callback that never returns
            // does not keep its task (FIXP v1.1 section 4.2: the handshake
            // is bounded).
            match decision {
                PendingDecision::Negotiation(task) => task.abort(),
                PendingDecision::Establishment(task) => task.abort(),
            }
        }
        // What is buffered (a Terminate, a reject) goes out, bounded.
        let writer = &mut self.writer;
        let outbound = &mut self.outbound;
        let _ = tokio::time::timeout(self.settings.write_timeout, async {
            writer.write_all_buf(outbound).await?;
            writer.shutdown().await
        })
        .await;
        self.role.on_transport_closed();
        // Only events can follow; a message has no transport to go to.
        while let Some(output) = self.role.poll_output() {
            if let Output::Event(event) = output {
                if let Event::SessionFinalized { .. } = event {
                    self.finalized = true;
                }
                self.notify(Callback::Event(self.role.session_id(), event));
            }
        }
        if let Role::Server { registry, .. } = &self.role
            && let Some(id) = self.claimed
        {
            registry.release(id, self.finalized);
        }
        let status = self.role.status();
        tracing::debug!(?status, "fixp driver ending");
        if let Some(handshake) = self.handshake.take() {
            let error = self
                .failure
                .take()
                .unwrap_or_else(|| FixpEngineError::HandshakeFailed {
                    detail: format!("transport closed before establishment (status {status:?})"),
                });
            let _ = handshake.send(Err(error));
        }
        // The transport is closed: handles see it now, even while the
        // callback task still runs the last callbacks, so a callback may
        // await `wait_closed` without a cycle.
        let _ = self.closed.send(true);
        self.notify(Callback::Closed(self.role.session_id()));
    }
}

/// Sleeps until `deadline`, or for ever without one.
async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => {
            tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
        }
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(n: u8) -> SofhFrame {
        match SofhFrame::new(EncodingType::SbeV1LittleEndian, vec![n]) {
            Ok(frame) => frame,
            Err(error) => panic!("frame: {error}"),
        }
    }

    const fn seq(n: u64) -> SeqNum {
        SeqNum::new(n)
    }

    #[test]
    fn test_sent_messages_keep_the_newest_up_to_capacity() {
        let mut sent = SentMessages {
            frames: BTreeMap::new(),
            capacity: 2,
        };
        for n in 1..=3 {
            sent.insert(seq(u64::from(n)), frame(n));
        }
        assert!(sent.range(seq(1), 1).is_none(), "the oldest was dropped");
        assert_eq!(sent.range(seq(2), 2).map(|f| f.len()), Some(2));
        assert!(sent.range(seq(3), 2).is_none(), "4 was never sent");
    }

    #[test]
    fn test_sent_messages_with_no_capacity_keep_nothing() {
        let mut sent = SentMessages {
            frames: BTreeMap::new(),
            capacity: 0,
        };
        sent.insert(seq(1), frame(1));
        assert!(sent.range(seq(1), 1).is_none());
    }

    #[test]
    fn test_registry_refuses_live_and_finalized_ids() {
        let registry = SessionRegistry::default();
        let id = SessionId::from_bytes([7; 16]);
        assert_eq!(registry.claim(id), Ok(()));
        assert_eq!(registry.claim(id), Err(Refusal::Live));
        registry.release(id, false);
        assert!(!registry.is_finalized(id));
        assert_eq!(registry.claim(id), Ok(()));
        registry.release(id, true);
        assert!(registry.is_finalized(id));
        assert_eq!(registry.claim(id), Err(Refusal::Finalized));
    }
}
