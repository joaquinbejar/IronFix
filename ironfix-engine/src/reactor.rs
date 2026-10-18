/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 22/7/26
******************************************************************************/

//! The live-session reactor: the inbound/outbound event loop shared by the
//! [`Initiator`](crate::Initiator) and the [`Acceptor`](crate::Acceptor).
//!
//! Both engines establish a session with a role-specific Logon handshake and
//! then hand the framed socket to exactly this reactor via [`spawn_session`], so
//! everything that keeps a session legal once it is Active — sequence
//! validation, gap recovery (`ResendRequest` (2), `SequenceReset`/GapFill (4),
//! `PossDupFlag` (43)), counterparty identity and `SendingTime` (52) checks,
//! heartbeat and `TestRequest` (1) timing, resend-from-store replay, the Logout
//! handshake, and the `Application` callback dispatch — lives here so the two
//! roles cannot drift apart.
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
//! # Bounded recovery
//!
//! A gap is answered with a `ResendRequest` (2), and a request that goes
//! unanswered does not wait forever: it is retried every
//! [`SessionConfig::resend_timeout`] up to
//! [`SessionConfig::resend_attempt_limit`] attempts, after which the session is
//! logged out.
//!
//! # Garbled inbound frames
//!
//! Both engines frame the socket with
//! [`FixCodec::with_garbled_recovery`] enabled, so a garbled frame (a wrong
//! `CheckSum` (10), a `BodyLength` (9) that does not match the frame, bytes
//! before `8=`) never reaches this loop as an error: the codec skips it and
//! counts it, and the reactor reads the count before each inbound frame and on
//! every tick. A frame whose header does not decode (`MsgType` (35) not third,
//! `BodyLength` invalid) is garbled too and is handled the same way. A
//! malformed body behind a sound header (an invalid tag, a bad data length) is
//! not garbled: it is dropped with a warning and not counted. A garbled frame
//! is ignored, as FIX requires. It consumes no `MsgSeqNum` (34),
//! so the next valid frame with a higher number is a gap and gets the usual
//! `ResendRequest`. It does not refresh the heartbeat clock, because garbled
//! bytes are not proof of life. It is logged as a count and a static cause,
//! never as bytes, since it may carry `Password` (554). With
//! [`SessionConfig::garbled_frame_limit`] set, reaching the limit inside the
//! window logs the session out. The common path costs one integer read: the
//! clock is read only when there is something to record. Only fatal codec
//! errors (a frame above `max_message_size`, an I/O error) still close the
//! session directly, an oversized frame after a Logout saying so.
//!
//! The Logon handshakes skip garbled frames as well ([`read_handshake_frame`]),
//! against the same logon timeout; those skips are reported but never counted
//! toward the limit.
//!
//! # Resend and the message store
//!
//! When a [`MessageStore`] is attached, every sequenced outbound frame is filed
//! under its `MsgSeqNum` before it goes on the wire, and an inbound
//! `ResendRequest` replays the stored application messages with `PossDupFlag`
//! (43) = Y and their original `SendingTime` in `OrigSendingTime` (122).
//! Administrative messages in the range, and any sequence number the store
//! cannot produce, are covered by `SequenceReset`-GapFill. **Without a store
//! nothing can be replayed** and the whole requested range is answered with one
//! gap fill.
//!
//! The writes follow the order set out in the [`persistence`](crate::persistence)
//! module: the frame is filed and the next sender number persisted before the
//! number is spent and the bytes are written; the next target number is
//! persisted before an inbound message is acted on and before the in-memory
//! expectation moves; any other counter change is persisted before the next
//! event; and a counter is written only when it changed. What a failed write
//! means is the session's [`StoreFailurePolicy`].
//!
//! # What blocks the reactor, and what does not
//!
//! The reactor is a single task owning the socket. A stalled peer cannot park it
//! forever: every write is bounded by the caller's write timeout, and its expiry
//! closes the session. A slow `from_app` cannot delay it either: inbound
//! application messages are handed to a separate dispatcher task over a bounded
//! queue, so an application handler never delays a socket read, a heartbeat, or
//! timeout detection.
//!
//! The attached [`MessageStore`] **does** run on the reactor: every store call
//! is awaited inline, because its result decides whether a frame may be written
//! or a message acted on. A slow store therefore delays this session's reads,
//! heartbeats and timeout detection for as long as the call takes. Each call is
//! bounded by the store timeout, and an overrun is a failed write under the
//! [`StoreFailurePolicy`]. `to_admin`, `to_app` and `from_admin` also run
//! inline.
//!
//! All sequence arithmetic goes through the checked
//! [`SequenceManager::try_allocate_sender_seq`] /
//! [`SequenceManager::try_increment_target_seq`]; an exhausted counter tears the
//! session down rather than wrapping.

use crate::application::{Application, RejectReason, SessionId};
use crate::connection::{Command, SessionRuntime};
use crate::error::EngineError;
use crate::garbled::{GarbledFrameWindow, GarbledVerdict};
use crate::outbound;
use crate::persistence::{
    HandshakeStore, OwedReset, PersistedCounters, SessionStore, StoreFailurePolicy, file_and_spend,
    timed,
};
use crate::wire::{
    self, MessageFactory, PeerIdentity, PendingMessage, SendingTimeGuard, SendingTimeProblem,
};
use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use ironfix_core::error::{DecodeError, EncodeError, StoreError};
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::version::FixVersion;
use ironfix_session::heartbeat::generate_test_req_id;
use ironfix_session::sequence::{SequenceCounter, SequenceExhausted, SequenceResult};
use ironfix_session::{
    Active, HeartbeatManager, LogoutPending, SequenceManager, Session, SessionConfig,
    TestRequestOutcome,
};
use ironfix_store::MessageStore;
use ironfix_transport::{CodecError, FixCodec};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval, timeout};
use tokio_util::codec::Framed;

/// Framed TCP stream carrying FIX messages.
pub(crate) type FixFramed = Framed<TcpStream, FixCodec>;

/// Builds the codec both engines frame their socket with.
///
/// Garbled-frame recovery is always on: FIX ignores a garbled message instead
/// of ending the session over it, and `Framed` cannot resume after a decoder
/// error, so the skip has to happen inside the codec. Resync anchors are
/// restricted to the session's own wire BeginString (`FIXT.1.1` for a 5.0
/// session): every real frame carries it, and an embedded frame of another
/// version can then never be resynchronised onto. The message-size ceiling and
/// checksum validation come from the session configuration.
#[must_use]
pub(crate) fn session_codec(config: &SessionConfig, version: FixVersion) -> FixCodec {
    FixCodec::new()
        .with_max_message_size(config.max_message_size)
        .with_checksum_validation(config.validate_checksum)
        .with_garbled_recovery(true)
        .with_begin_string(version.begin_string())
}

/// Log cause for frames the codec skipped as garbled at the framing level.
const GARBLED_FRAMING: &str = "framing: BeginString, BodyLength or CheckSum";

/// The driver's monotonic time, for the decision logic that takes `now`.
///
/// Read from Tokio's clock and converted at this boundary, per ADR-0002, so a
/// paused-clock test drives the decisions deterministically.
fn driver_now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// Default capacity of the outbound command queue.
pub(crate) const DEFAULT_OUTBOUND_CAPACITY: usize = 1024;

/// Default capacity of the inbound application queue, in messages.
///
/// The queue is bounded by message **count**, not bytes, and each entry retains
/// its whole frame (a reference-counted [`Bytes`] up to
/// [`SessionConfig::max_message_size`]). The worst-case retained memory is
/// therefore `capacity * max_message_size`: with the defaults, 1024 * 1 MiB =
/// 1 GiB, and up to 1024 * 64 MiB = 64 GiB if `max_message_size` is raised to
/// its ceiling.
pub(crate) const DEFAULT_APP_QUEUE_CAPACITY: usize = 1024;

/// Default bound on a single socket write.
pub(crate) const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the reactor waits for the application dispatcher to finish the
/// messages already queued before it reports the session closed.
///
/// The dispatcher always terminates — its queue is closed when the reactor
/// drops the sender — so this only bounds how long `on_logout` waits to follow
/// the last `from_app` rather than run beside it.
const APP_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Reactor tick granularity for heartbeat/timeout checks.
pub(crate) const TICK_INTERVAL: Duration = Duration::from_millis(100);

/// Number of stored messages a resend reads from the store per page.
///
/// A `ResendRequest` with `EndSeqNo` (16) = 0 asks for the whole session, so the
/// replay reads in bounded batches and yields between them rather than
/// allocating and locking over the entire history at once.
const RESEND_PAGE_LIMIT: usize = 256;

/// Runs `to_admin`, checks the body, and writes one administrative frame
/// during the handshake, before the reactor exists.
///
/// Every administrative message goes through the callback, including the ones
/// on the failure paths: now that a mutation is effective, a counterparty that
/// requires a stamped field requires it on the Reject and the Logout too. When
/// a store is attached the frame is filed and the sender counter persisted
/// before the write, the same as [`send_handshake`] does.
///
/// # Errors
/// The same as [`send_handshake`], plus [`EngineError::ReservedTag`] /
/// [`EngineError::InvalidField`] when the callback left a body the engine will
/// not frame.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_handshake_admin<A: Application>(
    application: &A,
    session_id: &SessionId,
    framed: &mut FixFramed,
    factory: &mut MessageFactory,
    sequences: &SequenceManager,
    store: Option<&mut HandshakeStore<'_>>,
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
/// The sequence number is peeked and the frame built; then [`file_and_spend`]
/// files it and persists the next sender number (when a store is attached)
/// and spends the number, the same step the reactor takes; only then does the
/// frame go on the wire. A body with no legal wire form therefore costs
/// nothing, instead of leaving a hole the counterparty would have to resend
/// over, and a store reused across a reconnect can replay the frame and never
/// reports a number the peer has already seen. Under
/// [`StoreFailurePolicy::CloseSession`] a failed write stops here: nothing is
/// spent and nothing is written.
///
/// # Errors
/// [`EngineError::Encode`] when the body has no legal wire form,
/// [`EngineError::SequenceExhausted`] when the sender counter has reached
/// `u64::MAX`, [`EngineError::Store`] when a store write fails under the
/// fail-closed policy, [`EngineError::WriteTimeout`] when the peer is not
/// reading, and the transport's own error otherwise.
async fn send_handshake(
    session_id: &SessionId,
    framed: &mut FixFramed,
    factory: &mut MessageFactory,
    sequences: &SequenceManager,
    store: Option<&mut HandshakeStore<'_>>,
    write_timeout: Duration,
    pending: &PendingMessage,
) -> Result<(), EngineError> {
    let seq = sequences.next_sender_seq().value();
    let frame = factory.encode(seq, pending)?;
    let store = store.map(|store| (store.store, &mut store.persisted));
    file_and_spend(store, sequences, session_id, seq, pending.msg_type(), frame).await?;
    match timeout(write_timeout, framed.send(frame)).await {
        Err(_) => Err(EngineError::WriteTimeout(write_timeout)),
        Ok(Err(err)) => Err(err.into()),
        Ok(Ok(())) => Ok(()),
    }
}

/// Sends the messages that refuse a Logon handshake (a Reject, then a Logout),
/// in order and best effort.
///
/// The handshake is failing already, so a transport or encoding error on one
/// of them is logged and the next one is still tried. A store failure under
/// [`StoreFailurePolicy::CloseSession`] is different: once the store has
/// refused a frame nothing more is written, so the remaining messages (the
/// Logout, typically) are not sent. `refusal` says why the Logon was being
/// refused; it is logged with the store error, because the caller then
/// reports the store error instead.
///
/// # Errors
/// The [`StoreError`] that stopped the refusal, if one did.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn refuse_handshake<A: Application, const N: usize>(
    application: &A,
    session_id: &SessionId,
    framed: &mut FixFramed,
    factory: &mut MessageFactory,
    sequences: &SequenceManager,
    mut store: Option<&mut HandshakeStore<'_>>,
    write_timeout: Duration,
    refusal: &str,
    messages: [PendingMessage; N],
) -> Result<(), StoreError> {
    for pending in messages {
        let msg_type = pending.msg_type().clone();
        match send_handshake_admin(
            application,
            session_id,
            framed,
            factory,
            sequences,
            store.as_deref_mut(),
            write_timeout,
            pending,
        )
        .await
        {
            Ok(()) => {}
            Err(EngineError::Store(err)) => {
                tracing::error!(
                    session = %session_id,
                    refusal,
                    msg_type = msg_type.as_str(),
                    error = %err,
                    "cannot file a message refusing the Logon: refusing without it"
                );
                return Err(err);
            }
            Err(err) => tracing::warn!(
                session = %session_id,
                msg_type = msg_type.as_str(),
                error = %err,
                "cannot send a message refusing the Logon"
            ),
        }
    }
    Ok(())
}

/// What waiting for one handshake frame came to.
#[derive(Debug)]
pub(crate) enum HandshakeRead {
    /// A frame that frames and decodes.
    Frame(BytesMut),
    /// The deadline passed before one arrived.
    TimedOut,
    /// The counterparty closed the transport.
    Closed,
    /// A fatal codec error: a frame above `max_message_size`, or I/O.
    Codec(CodecError),
}

/// Reads the next handshake frame that decodes, ignoring garbled ones, within
/// `logon_timeout`.
///
/// FIX ignores a garbled message during the Logon exchange as it does later,
/// so neither role fails its handshake over one. The codec already skips the
/// frames it cannot frame; a frame whose header does not decode (MsgType (35)
/// not third, BodyLength invalid) is skipped here. A frame whose header
/// decodes but whose body does not (an invalid tag, a bad data length) is not
/// garbled, but it cannot be read as a Logon either, so it is skipped under
/// the same rule rather than failing the handshake. One timeout covers the
/// whole wait, so a stream of either cannot extend the logon timeout, and a
/// Logon that never arrives intact ends in [`HandshakeRead::TimedOut`].
///
/// The skips are reported once, when the read ends: as a warning that the
/// handshake failed after them (so a timeout after garbage is diagnosable), or
/// that it succeeded despite them. The line carries counts and the session
/// only, never frame bytes. The codec's count is drained here, so nothing
/// skipped during the handshake counts toward
/// [`SessionConfig::garbled_frame_limit`], which governs the Active session.
///
/// `session_id` labels the report: the session's identifier, or, before an
/// [`AcceptorRegistry`](crate::AcceptorRegistry) has routed the Logon to a
/// session, a fixed label that names no counterparty.
pub(crate) async fn read_handshake_frame<S>(
    framed: &mut FixFramed,
    logon_timeout: Duration,
    session_id: &S,
) -> HandshakeRead
where
    S: std::fmt::Display + Sync + ?Sized,
{
    let mut skips = HandshakeSkips::default();
    let outcome = timeout(logon_timeout, next_decodable_frame(framed, &mut skips))
        .await
        .unwrap_or(HandshakeRead::TimedOut);
    report_handshake_skips(framed, &skips, &outcome, session_id);
    outcome
}

/// [`read_handshake_frame`] bounded by a `deadline` instead of a duration, so
/// a caller can bound the read and the work that follows it with one budget:
/// the [`AcceptorRegistry`](crate::AcceptorRegistry) reads a Logon and then
/// resolves its session within one logon timeout.
pub(crate) async fn read_handshake_frame_until<S>(
    framed: &mut FixFramed,
    deadline: tokio::time::Instant,
    session_id: &S,
) -> HandshakeRead
where
    S: std::fmt::Display + Sync + ?Sized,
{
    let mut skips = HandshakeSkips::default();
    let outcome = tokio::time::timeout_at(deadline, next_decodable_frame(framed, &mut skips))
        .await
        .unwrap_or(HandshakeRead::TimedOut);
    report_handshake_skips(framed, &skips, &outcome, session_id);
    outcome
}

/// Reports the frames a handshake read skipped, once, when it ends: as a
/// warning that the handshake failed after them, or that it succeeded despite
/// them. Counts and the session label only, never frame bytes. Drains the
/// codec's garbled count, so nothing skipped during the handshake counts
/// toward [`SessionConfig::garbled_frame_limit`].
fn report_handshake_skips<S>(
    framed: &mut FixFramed,
    skips: &HandshakeSkips,
    outcome: &HandshakeRead,
    session_id: &S,
) where
    S: std::fmt::Display + ?Sized,
{
    let framing = framed.codec_mut().take_garbled_count();
    if framing > 0 || skips.garbled > 0 || skips.malformed > 0 {
        let succeeded = matches!(outcome, HandshakeRead::Frame(_));
        tracing::warn!(
            session = %session_id,
            framing,
            garbled = skips.garbled,
            malformed = skips.malformed,
            succeeded,
            "ignored undecodable inbound frame(s) during the Logon handshake"
        );
    }
}

/// Frames that framed but did not decode during one handshake read, for the
/// report only: no decision reads these numbers.
#[derive(Debug, Default)]
struct HandshakeSkips {
    /// Header defects: garbled in the FIX Session Layer's sense.
    garbled: u64,
    /// Malformed bodies behind a header that decoded.
    malformed: u64,
}

impl HandshakeSkips {
    /// Counts one skipped `frame` of the kind `error` describes. At
    /// `u64::MAX` a count stops moving rather than wrapping; the timeout
    /// bounds the loop regardless.
    fn record(&mut self, error: &DecodeError, frame: &[u8]) {
        let count = if wire::decode_is_garbled(error, frame) {
            &mut self.garbled
        } else {
            &mut self.malformed
        };
        if let Some(next) = count.checked_add(1) {
            *count = next;
        }
    }
}

/// The loop inside [`read_handshake_frame`], without its timeout: returns the
/// first frame that decodes, or why the stream ended, and counts the frames
/// that framed but did not decode.
async fn next_decodable_frame(framed: &mut FixFramed, skips: &mut HandshakeSkips) -> HandshakeRead {
    loop {
        match framed.next().await {
            None => return HandshakeRead::Closed,
            Some(Err(err)) => return HandshakeRead::Codec(err),
            Some(Ok(frame)) => {
                // Owned error, so the borrow of `frame` ends before it moves.
                match wire::decode_frame(&frame).err() {
                    None => return HandshakeRead::Frame(frame),
                    Some(err) => skips.record(&err, &frame),
                }
            }
        }
    }
}

/// Locks the shared heartbeat manager.
///
/// A poisoned lock means a previous holder panicked. The heartbeat state is
/// plain timestamps with no invariant a panic could leave half-applied, so
/// the guard is recovered rather than propagated: the release profile is
/// `panic = "abort"`, and taking the consumer's process down over a
/// heartbeat timestamp is never the right trade.
pub(crate) fn lock_heartbeat(
    runtime: &SessionRuntime,
) -> std::sync::MutexGuard<'_, HeartbeatManager> {
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
///
/// After each message it stores that message's `MsgSeqNum` in `completed`, so
/// that if the task has to be aborted the reactor can name the messages it
/// handed over and `from_app` never finished.
async fn run_app_dispatcher<A: Application>(
    application: Arc<A>,
    session_id: SessionId,
    mut frames: mpsc::Receiver<AppFrame>,
    rejections: mpsc::Sender<AppRejection>,
    completed: Arc<AtomicU64>,
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
            completed.store(seq, Ordering::Release);
            continue;
        };
        let delivered = application.from_app(&raw, &session_id).await;
        completed.store(seq, Ordering::Release);
        if let Err(reason) = delivered {
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
    /// Commands from [`Connection`](crate::Connection) handles.
    commands: mpsc::Receiver<Command>,
    /// Rejections coming back from the application dispatcher.
    app_rejects: mpsc::Receiver<AppRejection>,
    /// Closed-flag channel observed by [`Connection::wait_closed`](crate::Connection::wait_closed).
    closed: watch::Sender<bool>,
    /// The application dispatcher, joined on close so `on_logout` follows the
    /// last `from_app` rather than racing it.
    dispatcher: JoinHandle<()>,
    /// The `MsgSeqNum` of the last message the dispatcher finished with, or 0.
    app_completed: Arc<AtomicU64>,
}

/// The `MsgSeqNum` range of the application messages handed to the dispatcher
/// that it did not finish, given the `(first, last)` numbers handed over and
/// the last number it finished with (0 for none).
///
/// Messages reach the dispatcher in ascending `MsgSeqNum` order and it
/// finishes them in that order, so what it did not finish is one range: from
/// just past the last finished number (or from the first handed over, if it
/// finished none of them) to the last handed over. The range can include the
/// numbers of administrative messages processed in between; it names the
/// span, not each lost message.
#[must_use]
fn undelivered_range(handed: Option<(u64, u64)>, completed: u64) -> Option<(u64, u64)> {
    let (first, last) = handed?;
    let start = if completed >= first {
        completed.checked_add(1)?
    } else {
        first
    };
    (start <= last).then_some((start, last))
}

/// Bookkeeping for an outstanding `ResendRequest` (2).
///
/// A resend that is never satisfied must not keep the session open forever:
/// gapped frames refresh the heartbeat clock, so the heartbeat timeout never
/// fires while the inbound expectation sits pinned. This tracks the gap so the
/// reactor can retry the request and, once the attempts are spent, log the
/// session out instead of waiting on a peer that is not answering.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ResendState {
    /// The next sequence number the recovery is waiting to receive. It advances
    /// with in-order inbound progress so a retry re-requests from the current
    /// gap start, never a number already consumed.
    expected: u64,
    /// The top of the outstanding range: the highest sequence number seen while
    /// the gap has been open. The request is open-ended (`EndSeqNo` = 0), so
    /// this is the water mark the expectation must cross for the gap to be
    /// considered closed — clearing recovery on the first in-order message
    /// instead would forget that later numbers in the range are still missing.
    high_water: u64,
    /// When the most recent request for this gap was sent.
    requested_at: Instant,
    /// How many requests have been sent for this gap, counting the first.
    attempts: u32,
    /// Attempt ceiling, resolved once from the configuration.
    limit: u32,
    /// How long a request may make no progress before it is retried.
    timeout: Duration,
}

impl ResendState {
    /// Opens recovery for a gap at `expected`, with `high_water` the highest
    /// sequence number outstanding, counting the first request.
    #[must_use]
    pub(crate) fn first(expected: u64, high_water: u64, config: &SessionConfig) -> Self {
        Self {
            expected,
            high_water,
            requested_at: Instant::now(),
            attempts: 1,
            limit: config.resend_attempt_limit(),
            timeout: config.resend_timeout,
        }
    }

    /// Whether this gap has waited longer than its retry timeout.
    #[must_use]
    fn is_stalled(&self) -> bool {
        self.requested_at.elapsed() >= self.timeout
    }

    /// Whether another request may still be sent for this gap.
    #[must_use]
    const fn can_retry(&self) -> bool {
        self.attempts < self.limit
    }

    /// Records that another request for this same gap has gone out.
    fn record_retry(&mut self) {
        self.requested_at = Instant::now();
        self.attempts = self.attempts.saturating_add(1);
    }

    /// Records genuine in-order progress within the outstanding range.
    ///
    /// The gap start has advanced to `expected`, so the stall clock and the
    /// retry budget both reset: a peer that is actively feeding the gap has
    /// proved itself responsive and must not be logged out for being slow. A
    /// duplicate or an out-of-order frame makes no such progress and so does not
    /// reach here.
    fn record_progress(&mut self, expected: u64) {
        self.expected = expected;
        self.requested_at = Instant::now();
        self.attempts = 1;
    }
}

/// Reactor state shared across event handlers.
struct Reactor<A: Application> {
    /// Outbound frame factory, holding the encoder reused for every message.
    factory: MessageFactory,
    /// Identity every inbound message must carry.
    identity: PeerIdentity,
    /// Clock-skew check applied to every inbound `SendingTime` (52).
    sending_time: SendingTimeGuard,
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
    /// What a failed write to `store` means.
    store_policy: StoreFailurePolicy,
    /// Bound on each call to `store`.
    store_timeout: Duration,
    /// The counter values last written to `store`.
    persisted: PersistedCounters,
    /// Set when the close-time store reset fails, for the engine that owns
    /// the store to perform on its next session.
    reset_owed: Arc<OwedReset>,
    /// The first and last `MsgSeqNum` handed to the application dispatcher.
    app_handed: Option<(u64, u64)>,
    /// The outstanding ResendRequest, if a gap is being recovered.
    ///
    /// The logout deadline is *not* tracked here: `Session<LogoutPending>`
    /// carries the instant the Logout went out, so the phase itself is the
    /// deadline.
    resend: Option<ResendState>,
    /// Bound on a single socket write.
    write_timeout: Duration,
    /// Hand-off queue to the application dispatcher.
    app_tx: mpsc::Sender<AppFrame>,
    /// Garbled-frame count against [`SessionConfig::garbled_frame_limit`], or
    /// `None` when no limit is configured.
    garbled: Option<GarbledFrameWindow>,
}

/// The session reactor: owns the socket, multiplexes inbound frames,
/// outbound commands, application rejections, and heartbeat timers until the
/// session closes.
///
/// `opening_gap` is a gap the Logon exchange found, as (first missing number,
/// highest number seen); its `ResendRequest` is the reactor's first act.
async fn run_reactor<A: Application + 'static>(
    mut framed: FixFramed,
    channels: ReactorChannels,
    mut ctx: Reactor<A>,
    session: Session<Active>,
    opening_gap: Option<(u64, u64)>,
) {
    let ReactorChannels {
        mut commands,
        mut app_rejects,
        closed: closed_tx,
        mut dispatcher,
        app_completed,
    } = channels;
    // The gap is requested here rather than by the handshake: `on_logon` has
    // already run, so a failure to send the request (a store refusal under the
    // fail-closed policy, a peer that stopped reading) has to close the
    // session through the path below, which runs `on_logout`, the close-time
    // reset and the last counter writes. A failure leaves no phase, and the
    // first pass of the loop ends the session with it.
    let (mut phase, mut opening_failure) = match opening_gap {
        Some((expected, high_water)) => {
            let opened = ctx
                .request_resend(&mut framed, Phase::Active(session), expected, high_water)
                .await;
            match opened {
                Ok(phase) => (Some(phase), None),
                Err(outcome) => (None, Some(outcome)),
            }
        }
        None => (Some(Phase::Active(session)), None),
    };
    let mut commands_open = true;
    let mut rejects_open = true;
    let mut tick = interval(TICK_INTERVAL);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    // Garbled frames skipped while the Logon handshake was reading are
    // reported, not counted against the limit: the handshake is bounded by
    // the logon timeout, and the limit governs the Active session.
    // `read_handshake_frame` normally drains and reports them already; this
    // catches anything a handshake read outside it.
    let during_handshake = framed.codec_mut().take_garbled_count();
    if during_handshake > 0 {
        tracing::warn!(
            session = %ctx.session_id,
            skipped = during_handshake,
            "ignored garbled inbound frame(s) during the Logon handshake"
        );
    }

    // The handshake persisted the counters it moved and handed over the record
    // of what it wrote, so the first pass below writes only what it did not.
    let outcome = loop {
        // The phase is put back by every handler that does not close the
        // session, so it is always present here once the opening request
        // succeeded. Treating its absence otherwise as a close keeps the
        // reactor panic-free rather than relying on that.
        let Some(current) = phase.take() else {
            break opening_failure
                .take()
                .unwrap_or_else(|| closed("internal error: session phase lost", false));
        };
        // Every counter change of the previous event (or of the handshake, on
        // the first pass) is persisted before the next event is handled; under
        // the fail-closed policy a failed write ends the session here.
        let current = match ctx.persist_counters().await {
            Ok(()) => current,
            Err(err) => break ctx.close_on_store_failure(current, &err),
        };
        let result = tokio::select! {
            inbound = framed.next() => match inbound {
                // The garbled frames the codec skipped on the way to this one
                // are accounted for first, so a limit reached by them closes
                // the session before the frame behind them is acted on. The
                // common case is one integer read and nothing else: no clock,
                // no allocation.
                Some(Ok(frame)) => match framed.codec_mut().take_garbled_count() {
                    0 => ctx.on_frame(&mut framed, current, frame).await,
                    skipped => match ctx.on_garbled(&mut framed, current, skipped, GARBLED_FRAMING).await {
                        Ok(current) => ctx.on_frame(&mut framed, current, frame).await,
                        Err(outcome) => Err(outcome),
                    },
                },
                // With recovery on, only a fatal error reaches here: an I/O
                // failure or a frame above `max_message_size`. `Framed` ends
                // the stream after any decoder error, so there is nothing to
                // resume either way.
                Some(Err(err)) => Err(ctx.close_on_fatal_codec_error(&mut framed, current, err).await),
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
            // A garbled frame with nothing valid behind it is only seen here:
            // the codec counted it while `Framed` went on waiting for bytes.
            _ = tick.tick() => match framed.codec_mut().take_garbled_count() {
                0 => ctx.on_tick(&mut framed, current).await,
                skipped => match ctx.on_garbled(&mut framed, current, skipped, GARBLED_FRAMING).await {
                    Ok(current) => ctx.on_tick(&mut framed, current).await,
                    Err(outcome) => Err(outcome),
                },
            },
        };
        match result {
            Ok(next) => phase = Some(next),
            Err(outcome) => break outcome,
        }
    };

    let mut write_counters = true;
    if ctx.config.reset_on_disconnect || (outcome.graceful && ctx.config.reset_on_logout) {
        ctx.runtime.sequences.reset();
        // The stored messages go with the counters. Leaving them behind would
        // file the next session's messages on top of this one's, and a resend
        // request in that session could answer with traffic from this one.
        if let Some(store) = ctx.store.as_deref() {
            // Owed from before the call and paid only once it has
            // succeeded: a reactor dropped while the reset is pending (a
            // runtime shutting down) runs no error branch, and the next
            // session must still make the reset.
            let ticket = ctx.reset_owed.owe();
            match timed(ctx.store_timeout, store.reset()).await {
                Ok(()) => ctx.reset_owed.pay(ticket),
                Err(err) => {
                    // The reset counters written over a store that still
                    // holds this session's stream would describe neither, so
                    // none are written. The reset stays owed, and the next
                    // session fails closed on it, whatever the policy. A reset
                    // that timed out may still land later; a store that
                    // applies its mutations in call order lands it before the
                    // next session's reset.
                    write_counters = false;
                    tracing::error!(
                        session = %ctx.session_id,
                        error = %err,
                        "cannot reset the store after a session-closing sequence reset: its \
                         counters are left untouched and the next session must reset it before \
                         it starts"
                    );
                }
            }
        }
    }
    // The session is over, so a failure here has nothing left to close: it is
    // logged, whatever the policy.
    if write_counters && let Err(err) = ctx.persist_counters().await {
        tracing::warn!(
            session = %ctx.session_id,
            error = %err,
            "cannot persist the sequence numbers as the session closes"
        );
    }

    // Closing the queue is what stops the dispatcher; joining it is what keeps
    // `on_logout` from running beside a `from_app` still in flight. A wedged
    // handler bounds the wait rather than the shutdown — and is then aborted, so
    // it cannot outlive `on_logout`/`wait_closed`. Awaiting `&mut dispatcher`
    // keeps ownership of the handle across the timeout: dropping it would only
    // detach the task, leaving the stuck handler running.
    //
    // Aborting loses the messages still queued, and the one in `from_app`:
    // their numbers are consumed, so the counterparty will not send them again.
    // The range is logged, since nothing else will report it (issue #105).
    drop(ctx.app_tx);
    if timeout(APP_DRAIN_TIMEOUT, &mut dispatcher).await.is_err() {
        dispatcher.abort();
        let completed = app_completed.load(Ordering::Acquire);
        match undelivered_range(ctx.app_handed, completed) {
            Some((first, last)) => tracing::error!(
                session = %ctx.session_id,
                first,
                last,
                "application dispatcher did not drain before the session closed and was \
                 aborted: application messages in MsgSeqNum range first..=last were accepted \
                 but from_app did not finish with them"
            ),
            None => tracing::warn!(
                session = %ctx.session_id,
                "application dispatcher did not drain before the session closed; aborting it"
            ),
        }
    }

    ctx.application.on_logout(&ctx.session_id).await;
    let _ = closed_tx.send(true);
    if outcome.graceful {
        tracing::info!(session = %ctx.session_id, reason = %outcome.reason, "FIX session closed");
    } else {
        tracing::warn!(session = %ctx.session_id, reason = %outcome.reason, "FIX session closed");
    }
}

/// Binds an attached store to the session's policy, timeout and owed-reset
/// record.
///
/// A free function over the fields, not a `Reactor` method: a method would
/// borrow the whole reactor, and the callers need the counter record mutably
/// beside it.
#[must_use]
fn bind_store<'s>(
    store: Option<&'s Arc<dyn MessageStore>>,
    policy: StoreFailurePolicy,
    timeout: Duration,
    owed: &'s OwedReset,
) -> Option<SessionStore<'s>> {
    store.map(|store| SessionStore::new(store.as_ref(), policy, timeout, owed))
}

/// Persists `next` as the next target sequence number, if it changed since the
/// last write, under the binding's policy.
///
/// A free function over the store fields rather than a `Reactor` method, so the
/// application path can call it while it holds a reservation on the
/// application queue.
///
/// # Errors
/// A store error under [`StoreFailurePolicy::CloseSession`].
async fn persist_target_with(
    store: Option<SessionStore<'_>>,
    persisted: &mut PersistedCounters,
    session_id: &SessionId,
    next: u64,
) -> Result<(), StoreError> {
    let Some(store) = store else {
        return Ok(());
    };
    if persisted.target_to_write(next).is_none() {
        return Ok(());
    }
    persisted.record_target(next);
    store.persist_target(session_id, next).await
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
    /// Persists whichever sequence counter changed since it was last written.
    ///
    /// The counters are the store's other job: they are what lets a later
    /// session pick up where this one stopped. This runs between every two
    /// events (the 100 ms tick included), so a counter is written only when its
    /// value moved; the common case is two integer comparisons and no store
    /// call. The hot paths write their own counter earlier, at the point the
    /// ordering requires: the sender counter before a frame is written, the
    /// target counter before an inbound message is acted on.
    ///
    /// # Errors
    /// A store error under [`StoreFailurePolicy::CloseSession`].
    async fn persist_counters(&mut self) -> Result<(), StoreError> {
        let Some(store) = self.store.as_deref() else {
            return Ok(());
        };
        let store = SessionStore::new(
            store,
            self.store_policy,
            self.store_timeout,
            &self.reset_owed,
        );
        let sender = self.runtime.sequences.next_sender_seq().value();
        if let Some(next) = self.persisted.sender_to_write(sender) {
            self.persisted.record_sender(next);
            store.persist_sender(&self.session_id, next).await?;
        }
        let target = self.runtime.sequences.next_target_seq().value();
        if let Some(next) = self.persisted.target_to_write(target) {
            self.persisted.record_target(next);
            store.persist_target(&self.session_id, next).await?;
        }
        Ok(())
    }

    /// Persists `next` as the next target sequence number now, ahead of acting
    /// on the inbound message that advanced it.
    ///
    /// # Errors
    /// A store error under [`StoreFailurePolicy::CloseSession`]: the message
    /// must then not be acted on.
    async fn persist_target(&mut self, next: u64) -> Result<(), StoreError> {
        let store = bind_store(
            self.store.as_ref(),
            self.store_policy,
            self.store_timeout,
            &self.reset_owed,
        );
        persist_target_with(store, &mut self.persisted, &self.session_id, next).await
    }

    /// Ends the session because a store write failed under
    /// [`StoreFailurePolicy::CloseSession`].
    ///
    /// No Logout is sent: it would have to be filed through the store that just
    /// failed, and the fail-closed policy writes nothing it could not file. The
    /// log line carries the store's error, which never contains frame bytes.
    fn close_on_store_failure(&self, phase: Phase, err: &StoreError) -> SessionClosed {
        teardown(phase);
        closed(
            format!("store failure under the fail-closed policy: {err}"),
            false,
        )
    }

    /// Frames `pending` under `seq` and writes it, bounded by the write
    /// timeout.
    ///
    /// With `spend` set, `seq` must be the next sender number and this is the
    /// frame that spends it, in this order: encode; then [`file_and_spend`],
    /// which files the frame under `seq` and persists `seq + 1` as the next
    /// sender number when a store is attached, and spends `seq` in memory (the
    /// step the Logon handshakes share); then write. The store and the
    /// in-memory counter therefore agree before any byte reaches the socket,
    /// and a write that fails afterwards cannot lead to `seq` being reused.
    ///
    /// A gap fill passes `false`: it re-occupies a range it does not own, so
    /// filing it would overwrite a message under `seq` that is still
    /// resendable, and it spends no number.
    ///
    /// # Errors
    /// [`WriteFailure::Encode`] leaves the session untouched — nothing was
    /// written and nothing was spent. [`WriteFailure::Fatal`] does not: a
    /// stalled or broken transport, an exhausted sender counter, or a store
    /// write that failed under [`StoreFailurePolicy::CloseSession`] (in which
    /// case nothing was written and nothing spent) ends the session.
    async fn write_at(
        &mut self,
        framed: &mut FixFramed,
        seq: u64,
        pending: &PendingMessage,
        spend: bool,
    ) -> Result<(), WriteFailure> {
        let write_timeout = self.write_timeout;
        let frame = match self.factory.encode(seq, pending) {
            Ok(frame) => frame,
            Err(err) => return Err(WriteFailure::Encode(err)),
        };
        if spend {
            // Only the reactor allocates sender numbers and only this method
            // spends them, so nothing can take the peeked number in between;
            // the mismatch check inside exists so a wrong `MsgSeqNum` can never
            // reach the wire, not because it is reachable.
            let store = bind_store(
                self.store.as_ref(),
                self.store_policy,
                self.store_timeout,
                &self.reset_owed,
            )
            .map(|store| (store, &mut self.persisted));
            file_and_spend(
                store,
                &self.runtime.sequences,
                &self.session_id,
                seq,
                pending.msg_type(),
                frame,
            )
            .await
            .map_err(WriteFailure::Fatal)?;
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
    /// the frame exists and has been filed (see [`Reactor::write_at`]). A body
    /// with no legal wire form is therefore dropped with a warning and
    /// [`Sent::Dropped`] is returned: the session is intact and there is no
    /// hole for the counterparty to resend over. A caller that arms follow-on
    /// state (the logout deadline, a pending TestRequest, a pending resend)
    /// must act only on [`Sent::Yes`], or it advances the session on a frame
    /// the peer never saw.
    ///
    /// # Errors
    /// Every [`EngineError`] returned here is terminal for the session: an
    /// exhausted sender counter, a write timeout, a transport failure, or
    /// [`EngineError::Store`] under the fail-closed store policy (nothing was
    /// written for this message).
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

    /// Handles a command from a [`Connection`](crate::Connection) handle.
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
                Phase::Active(session) => self.begin_logout(framed, session, None).await,
            },
        }
    }

    /// Sends a Logout (35=5) and moves the session to LogoutPending, where it
    /// waits for the acknowledgement until `logout_timeout` expires.
    ///
    /// `text` is the `Text` (58) explaining an engine-initiated logout; a
    /// consumer-initiated one carries none.
    async fn begin_logout(
        &mut self,
        framed: &mut FixFramed,
        session: Session<Active>,
        text: Option<&str>,
    ) -> Result<Phase, SessionClosed> {
        let logout = self.factory.logout(text);
        match self.send(framed, logout).await {
            Err(err) => {
                let _ = session.disconnect();
                Err(closed(format!("send failed: {err}"), false))
            }
            // The Logout never reached the wire — a `to_admin` callback left it
            // unframeable. Staying Active is the honest verdict: arming the
            // logout deadline for a frame the peer never saw would tear the
            // session down over a Logout it was never told about.
            Ok(Sent::Dropped) => Ok(Phase::Active(session)),
            Ok(Sent::Yes) => {
                // Recovery is over: a session on its way out will not process a
                // replay, and leaving the gap armed would keep asking for one.
                self.resend = None;
                // Typestate: Active -> LogoutPending. The new state records when
                // the Logout went out, which is what `on_tick` times through
                // `Session::sent_at`.
                Ok(Phase::LogoutPending(session.initiate_logout()))
            }
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

        // A gap that is making no progress is chased on its own clock,
        // independent of the heartbeat: gapped frames keep the heartbeat alive,
        // so this is the only thing that bounds an unsatisfied resend.
        if let Some(resend) = self.resend
            && resend.is_stalled()
        {
            return self.on_resend_stalled(framed, phase, resend).await;
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

    /// Requests retransmission from `expected` onwards, unless the same range
    /// is already outstanding. `high_water` is the highest sequence number seen
    /// for this gap — the top of the range the request must eventually fill.
    ///
    /// The first request for a gap opens a [`ResendState`], whose timer bounds
    /// how long the gap may sit unfilled (see [`Reactor::on_resend_stalled`]).
    /// A frame that reaches beyond an already-open gap only raises the recorded
    /// water mark; it does not emit a second overlapping request.
    async fn request_resend(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        expected: u64,
        high_water: u64,
    ) -> Result<Phase, SessionClosed> {
        if let Some(state) = self.resend.as_mut() {
            if high_water > state.high_water {
                state.high_water = high_water;
            }
            // The request from this gap start is already on the wire.
            if state.expected == expected {
                return Ok(phase);
            }
        }
        let request = self.factory.resend_request(expected, 0);
        match self.send(framed, request).await {
            Err(EngineError::Store(err)) => {
                return Err(self.close_on_store_failure(phase, &err));
            }
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
        // A re-request at a new gap start keeps the highest water mark seen so
        // far, so the range is never narrowed by a later, lower frame.
        let high_water = self
            .resend
            .map_or(high_water, |state| state.high_water.max(high_water));
        self.resend = Some(ResendState::first(expected, high_water, &self.config));
        Ok(phase)
    }

    /// Reconciles the outstanding resend, if any, with in-order inbound
    /// progress.
    ///
    /// Called after the target expectation advances by one in order. Recovery
    /// is cleared only once the expectation has moved past the whole outstanding
    /// range (above the water mark); until then the state is kept and its gap
    /// start advanced, so a single in-order message can no longer wipe all
    /// knowledge of a still-open gap. Leaving the marker armed also keeps the
    /// stall timer honest against a peer that fills the gap start and then
    /// stalls while spamming timely duplicates.
    fn note_inbound_progress(&mut self) {
        let Some(high_water) = self.resend.as_ref().map(|state| state.high_water) else {
            return;
        };
        let next_target = self.runtime.sequences.next_target_seq().value();
        if next_target > high_water {
            self.resend = None;
        } else if let Some(state) = self.resend.as_mut() {
            state.record_progress(next_target);
        }
    }

    /// Handles an outstanding ResendRequest that has gone unanswered past its
    /// timeout: retry it while attempts remain, otherwise log the session out.
    ///
    /// A peer that keeps a gap open indefinitely — answering neither the gap
    /// nor a fresh request, while its other traffic keeps the heartbeat clock
    /// alive — is one this session cannot make progress with. Retrying a bounded
    /// number of times absorbs a lost request or a slow store; exhausting the
    /// retries turns a silent stall into an observable, graceful close.
    async fn on_resend_stalled(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        resend: ResendState,
    ) -> Result<Phase, SessionClosed> {
        if !resend.can_retry() {
            let reason = format!(
                "resend of MsgSeqNum {} unanswered after {} request(s)",
                resend.expected, resend.attempts
            );
            tracing::warn!(session = %self.session_id, reason = %reason, "abandoning stalled resend");
            return match phase {
                // A logout already in flight cannot be reissued; let its own
                // deadline close the session.
                Phase::LogoutPending(_) => Ok(phase),
                Phase::Active(session) => self.begin_logout(framed, session, Some(&reason)).await,
            };
        }

        let expected = resend.expected;
        let request = self.factory.resend_request(expected, 0);
        match self.send(framed, request).await {
            Err(err) => {
                teardown(phase);
                return Err(closed(format!("send failed: {err}"), false));
            }
            // The retry never went out; leave the state untouched so the next
            // stall tick tries again rather than counting a request the peer
            // never received.
            Ok(Sent::Dropped) => return Ok(phase),
            Ok(Sent::Yes) => {}
        }
        if let Some(state) = self.resend.as_mut() {
            state.record_retry();
        }
        tracing::debug!(
            session = %self.session_id,
            expected,
            "retrying unanswered ResendRequest"
        );
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

    /// Accounts for `skipped` garbled inbound frames: the ones the codec
    /// skipped since the last check, or one frame that framed but did not
    /// decode. `cause` names which, for the log.
    ///
    /// FIX ignores a garbled message, and so does this: no sequence number is
    /// consumed, the heartbeat clock is not touched (garbled bytes are not
    /// proof of life), and nothing reaches the application. The gap a skipped
    /// frame leaves is found by the next valid frame and recovered by the
    /// usual `ResendRequest`.
    ///
    /// With a [`SessionConfig::garbled_frame_limit`], the count is fed to the
    /// sliding window, and reaching the limit closes the session through
    /// [`Reactor::close_on_garbled_limit`]. Callers only get here with a
    /// non-zero count, so the common path never reads the clock.
    async fn on_garbled(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        skipped: u64,
        cause: &'static str,
    ) -> Result<Phase, SessionClosed> {
        match self.note_garbled(skipped, cause) {
            None => Ok(phase),
            Some(reason) => Err(self.close_on_garbled_limit(framed, phase, reason).await),
        }
    }

    /// The synchronous half of [`Reactor::on_garbled`]: logs the skip and, when
    /// a limit is configured, reads the driver's clock and records it.
    ///
    /// Returns the close reason when the limit is reached. The log line carries
    /// the count and a static cause only, never the frame bytes: a garbled
    /// Logon can still hold `Password` (554).
    #[cold]
    #[inline(never)]
    fn note_garbled(&mut self, skipped: u64, cause: &'static str) -> Option<String> {
        tracing::warn!(
            session = %self.session_id,
            skipped,
            cause,
            "ignored garbled inbound frame(s): no MsgSeqNum consumed, heartbeat clock not refreshed"
        );
        let window = self.garbled.as_mut()?;
        match window.record(driver_now(), skipped) {
            GarbledVerdict::Tolerated => None,
            GarbledVerdict::LimitReached => {
                // Whole milliseconds rather than `Duration`'s Debug form, which
                // can print `µs`: this text goes out in Logout `Text` (58).
                let limit = window.limit();
                Some(format!(
                    "garbled frame limit reached: {} garbled inbound frames within {} ms",
                    limit.max(),
                    limit.window().as_millis()
                ))
            }
        }
    }

    /// Ends the session on a fatal codec error.
    ///
    /// With recovery on, the codec only reports what the stream cannot continue
    /// past: a frame above `max_message_size`, or an I/O failure. For an
    /// oversized frame the read side is unusable but the write side still
    /// works, so an Active session first sends a Logout with `Text` (58)
    /// "message too large", letting the counterparty learn why it was cut off.
    /// An I/O failure gets no Logout: the socket is what failed. The close
    /// reason recorded here is a string for the log only; a typed close reason
    /// on the [`Connection`](crate::Connection) is issue #69's job.
    ///
    /// Known limit: the oversized frame's bytes are still arriving when the
    /// socket is dropped after the Logout, so the close can send RST and the
    /// peer may lose the Logout. A graceful drain does not exist yet.
    async fn close_on_fatal_codec_error(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        error: CodecError,
    ) -> SessionClosed {
        if matches!(error, CodecError::MessageTooLarge { .. }) && matches!(phase, Phase::Active(_))
        {
            let logout = self.factory.logout(Some("message too large"));
            let _ = self.send(framed, logout).await;
        }
        teardown(phase);
        closed(format!("codec error: {error}"), false)
    }

    /// Ends a session whose inbound link has garbled
    /// [`SessionConfig::garbled_frame_limit`] frames within its window.
    ///
    /// An Active session sends a Logout carrying the reason in `Text` (58)
    /// first, so the counterparty learns why, and is then torn down without
    /// waiting for the acknowledgement: the very link that keeps garbling
    /// frames is the one the acknowledgement would have to cross. A session
    /// already waiting on its own Logout is simply torn down.
    ///
    /// Known limit: the socket is dropped right after the Logout is written,
    /// while the peer's input may still be arriving. Closing a socket with
    /// unread input can make the kernel send RST, and the peer may then lose
    /// the Logout. A graceful drain before the drop does not exist yet.
    async fn close_on_garbled_limit(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        reason: String,
    ) -> SessionClosed {
        tracing::warn!(session = %self.session_id, reason = %reason, "closing the session");
        if matches!(phase, Phase::Active(_)) {
            let logout = self.factory.logout(Some(&reason));
            let _ = self.send(framed, logout).await;
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
        let reject = self.factory.session_reject(ref_seq, ref_msg_type, &reason);
        let _ = self.send(framed, reject).await;
        let logout = self.factory.logout(Some(&detail));
        let _ = self.send(framed, logout).await;
        teardown(phase);
        closed(detail, false)
    }

    /// Rejects an inbound message whose `SendingTime` (52) is missing,
    /// unparseable, or outside the configured tolerance, then logs out and
    /// tears the session down.
    ///
    /// A wrong clock is a systemic problem, not a per-message one: the peer's
    /// next frame will be just as skewed, so accepting this one and moving on
    /// would only defer the same failure while advancing sequence state on
    /// timestamps that cannot be trusted. The Reject carries
    /// `SessionRejectReason` 10 for a skew, 1 for an absent field and 6 for a
    /// malformed one (`doc/fix_operations.md`, "Session Reject Reasons"), then
    /// the session is closed as it is for an identity mismatch.
    async fn close_on_sending_time(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        ref_seq: u64,
        ref_msg_type: &str,
        problem: SendingTimeProblem,
    ) -> SessionClosed {
        let detail = problem.to_string();
        tracing::warn!(session = %self.session_id, detail = %detail, "inbound SendingTime problem");

        let reason = problem.reject_reason();
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
    ///
    /// Returns whether the target expectation actually advanced, so the caller
    /// can keep an outstanding resend in step with the consumed number.
    fn consume_if_in_sequence(&self, gap_fill: bool, seq: u64) -> Result<bool, SequenceExhausted> {
        if !gap_fill || !self.runtime.sequences.validate_incoming(seq).is_ok() {
            return Ok(false);
        }
        self.runtime
            .sequences
            .try_increment_target_seq()
            .map(|_| true)
    }

    /// Consumes a rejected in-sequence GapFill's MsgSeqNum and keeps recovery in
    /// step with the advance.
    ///
    /// The reject paths in [`Reactor::on_sequence_reset`] discard the fill's
    /// payload but must not discard the fact that its number is now consumed: an
    /// outstanding resend whose gap start is left pointing at that number would
    /// re-request an already-processed sequence and eventually log the session
    /// out despite real progress. Only a fill that genuinely advanced the target
    /// reconciles; a duplicate or a gapped one makes no progress and so does not
    /// disturb the stall clock.
    fn consume_rejected_fill(&mut self, gap_fill: bool, seq: u64) -> Result<(), SequenceExhausted> {
        if self.consume_if_in_sequence(gap_fill, seq)? {
            self.note_inbound_progress();
        }
        Ok(())
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
    ///
    /// With a store attached, an in-sequence Gap Fill persists `MsgSeqNum + 1`
    /// as the next target number before `from_admin` runs, and either mode
    /// persists an accepted `NewSeqNo` (36) before the expectation moves to it.
    /// A Reset reaches `from_admin` before any write: it has no place in the
    /// sequence to persist first.
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
                SequenceResult::Gap { expected, received } => {
                    // The fill is itself gapped: it cannot be trusted to
                    // describe the missing range, so NewSeqNo is not applied
                    // and the range is requested instead.
                    return self.request_resend(framed, phase, expected, received).await;
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
                SequenceResult::Ok => {
                    // The fill occupies `seq` whatever happens next (accepted,
                    // rejected, or carrying an unusable NewSeqNo), so `seq + 1`
                    // is persisted before `from_admin` sees it, as for every
                    // other in-sequence message.
                    let Some(next) = seq.checked_add(1) else {
                        return Err(exhausted(
                            phase,
                            SequenceExhausted {
                                counter: SequenceCounter::Target,
                            },
                        ));
                    };
                    if let Err(err) = self.persist_target(next).await {
                        return Err(self.close_on_store_failure(phase, &err));
                    }
                }
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
            if let Err(err) = self.consume_rejected_fill(gap_fill, seq) {
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
            if let Err(err) = self.consume_rejected_fill(gap_fill, seq) {
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
                // The consumed number is real progress: keep an outstanding
                // resend from re-requesting it.
                self.note_inbound_progress();
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
        // The new expectation is persisted before it takes effect. A Reset
        // has no place in the sequence, so it reached `from_admin` before any
        // write; this is its first.
        if let Err(err) = self.persist_target(new_seq).await {
            return Err(self.close_on_store_failure(phase, &err));
        }
        self.runtime.sequences.set_target_seq(new_seq);
        // Only a reset that actually advances the expectation touches an
        // outstanding ResendRequest. A reset landing on the number we already
        // expect changes nothing, and reconciling for it would let a peer replay
        // it to make the engine emit a fresh ResendRequest every round --
        // sequence amplification with no progress. A reset that advances but
        // stays inside the outstanding range keeps recovery armed against the
        // rest of it; one that jumps past the water mark clears it.
        if new_seq > expected_before {
            self.note_inbound_progress();
        }
        Ok(phase)
    }

    /// Answers an inbound ResendRequest (35=2).
    ///
    /// With a store attached (see [`Initiator::with_store`](crate::Initiator::with_store)) the reply is the
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
    /// Returns [`EngineError`] if writing to the socket fails, or
    /// [`EngineError::Store`] if the store reports itself corrupted
    /// ([`StoreError::Corrupted`]); the session is then closed by the caller.
    /// Every other failure (a store that cannot be read, a read that overruns
    /// the store timeout, a frame that does not rebuild) degrades to a gap
    /// fill.
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
            // Bounded like every store call; a read that overruns degrades to
            // a gap fill like any other failed read.
            let read = store.get_page(read_from, end_seq, RESEND_PAGE_LIMIT);
            let page = match timed(self.store_timeout, read).await {
                Ok(page) => page,
                // A store that finds its own records damaged cannot say which
                // of the messages it holds are intact. Gap-filling the rest of
                // the range would tell the counterparty that application
                // messages it may never have received do not exist, so the
                // session is closed instead and the request is left for the
                // next session to make again.
                Err(err @ StoreError::Corrupted { .. }) => {
                    tracing::error!(
                        session = %self.session_id,
                        read_from,
                        end_seq,
                        error = %err,
                        "the store holding the resend range is corrupted: closing the session \
                         rather than gap-filling messages it may still hold"
                    );
                    return Err(EngineError::Store(err));
                }
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
            // A frame whose header does not decode (MsgType (35) not third,
            // BodyLength invalid, a malformed field among the first three) is
            // garbled: it is ignored exactly like one the codec skipped, and
            // counts toward the same limit. The log names the defect, never
            // the error's text, which can quote input.
            Err(err) if wire::decode_is_garbled(&err, &frame) => {
                return self
                    .on_garbled(framed, phase, 1, wire::decode_defect(&err))
                    .await;
            }
            // A malformed body behind a sound header (an invalid tag, a bad
            // data length) is not garbled. It keeps the behaviour it always
            // had: dropped with a warning, no MsgSeqNum consumed, not counted
            // toward the limit. No Reject can be sent without a decoded
            // MsgSeqNum to reference.
            Err(err) => {
                tracing::warn!(
                    session = %self.session_id,
                    defect = wire::decode_defect(&err),
                    "dropping a message whose body does not decode: no MsgSeqNum consumed"
                );
                return Ok(phase);
            }
        };
        let msg_type = raw.msg_type().clone();

        // Positional read: MsgSeqNum (34) must be in the standard header, the
        // same contract the CompID/SendingTime paths enforce. A 34 that appears
        // only after the body is treated as missing rather than smuggled in as
        // the session sequence number. Both Initiator and Acceptor share this
        // reactor, so this closes the gap for in-session traffic on both.
        let Some(seq) = wire::header_seq_num(&raw) else {
            tracing::warn!(
                session = %self.session_id,
                msg_type = %msg_type,
                "dropping message without a valid header MsgSeqNum (34)"
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

        // Clock accuracy is checked next, and likewise before the heartbeat is
        // refreshed: a peer whose SendingTime is outside the tolerance is one
        // whose sequencing cannot be trusted, so it must not keep the session
        // alive either.
        if let Err(problem) = self.sending_time.validate(&raw) {
            return Err(self
                .close_on_sending_time(framed, phase, seq, msg_type.as_str(), problem)
                .await);
        }

        // The frame is well-formed, sequenced, from the configured
        // counterparty, and timely: it proves the peer is alive. A sequence gap
        // is a recoverable condition, not evidence of a dead peer, so gapped
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
                    // The receive cursor includes this message before it is
                    // acted on, so a restart never asks for it again; and the
                    // in-memory expectation moves only once that write has
                    // been accepted, as for an application message.
                    let Some(next) = seq.checked_add(1) else {
                        return Err(exhausted(
                            phase,
                            SequenceExhausted {
                                counter: SequenceCounter::Target,
                            },
                        ));
                    };
                    if let Err(err) = self.persist_target(next).await {
                        return Err(self.close_on_store_failure(phase, &err));
                    }
                    // Consume the number before the admin handler runs: any
                    // reply it sends is numbered against the advanced
                    // expectation, and admin messages never queue.
                    if let Err(err) = self.runtime.sequences.try_increment_target_seq() {
                        return Err(exhausted(phase, err));
                    }
                    // An in-order message advances recovery but does not
                    // necessarily end it: clear the marker only once the whole
                    // outstanding range is filled, never on the first message
                    // back.
                    self.note_inbound_progress();
                    self.dispatch_admin(framed, phase, &raw, seq).await
                } else {
                    let phase = self.deliver_app(phase, seq, &frame).await?;
                    if let Err(err) = self.runtime.sequences.try_increment_target_seq() {
                        return Err(exhausted(phase, err));
                    }
                    // In-order progress, as above: reconcile recovery rather
                    // than clearing it on the first message back.
                    self.note_inbound_progress();
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
            SequenceResult::Gap { expected, received } => {
                let phase = self
                    .request_resend(framed, phase, expected, received)
                    .await?;
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

    /// Hands one validated, in-sequence inbound application frame to the
    /// dispatcher task, persisting the target counter first.
    ///
    /// The order is: reserve a slot in the application queue; persist `seq + 1`
    /// as the next target number; hand the frame over. The caller advances the
    /// in-memory expectation afterwards.
    ///
    /// - A full queue closes the session before anything is persisted, with the
    ///   sequence number unspent: the counterparty stays free to resend, rather
    ///   than the message being silently lost past a number already consumed.
    /// - A target write that fails under
    ///   [`StoreFailurePolicy::CloseSession`] closes the session and the frame
    ///   never reaches `from_app`. Under [`StoreFailurePolicy::Continue`] the
    ///   failure is logged and the frame is handed over anyway.
    /// - Once handed over, the message's number is consumed (and durable, if
    ///   the write succeeded). A crash, or a dispatcher aborted at close,
    ///   before `from_app` has finished with it loses it to the application:
    ///   inbound delivery is at most once (see the `persistence` module). The
    ///   handed-over range is recorded so an abort can log what it lost.
    async fn deliver_app(
        &mut self,
        phase: Phase,
        seq: u64,
        frame: &Bytes,
    ) -> Result<Phase, SessionClosed> {
        let permit = match self.app_tx.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(())) => {
                teardown(phase);
                return Err(closed(
                    "application queue full: the application is not consuming inbound \
                     messages fast enough",
                    false,
                ));
            }
            Err(mpsc::error::TrySendError::Closed(())) => {
                teardown(phase);
                return Err(closed("application dispatcher stopped", false));
            }
        };
        let Some(next) = seq.checked_add(1) else {
            return Err(exhausted(
                phase,
                SequenceExhausted {
                    counter: SequenceCounter::Target,
                },
            ));
        };
        let store = bind_store(
            self.store.as_ref(),
            self.store_policy,
            self.store_timeout,
            &self.reset_owed,
        );
        if let Err(err) =
            persist_target_with(store, &mut self.persisted, &self.session_id, next).await
        {
            return Err(self.close_on_store_failure(phase, &err));
        }
        permit.send(AppFrame {
            frame: frame.clone(),
            seq,
        });
        self.app_handed = Some(match self.app_handed {
            Some((first, _)) => (first, seq),
            None => (seq, seq),
        });
        Ok(phase)
    }

    /// Runs `from_admin` and the admin reply for an administrative message whose
    /// sequence number has already been validated (and, on the in-sequence
    /// path, consumed).
    ///
    /// Application messages never reach here: they are handed to the dispatcher
    /// task by [`Reactor::deliver_app`], so a slow `from_app` cannot delay the
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
                    // A reply the store refused under the fail-closed policy was
                    // never written: the exchange is incomplete, so the close is
                    // not graceful and does not trigger `reset_on_logout`. Any
                    // other failure to reply keeps the close graceful, as the
                    // counterparty has already logged out.
                    if let Err(EngineError::Store(err)) = self.send(framed, logout).await {
                        return Err(self.close_on_store_failure(Phase::Active(session), &err));
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

/// Everything [`spawn_session`] needs to build and launch a live-session
/// reactor once a handshake has taken the session Active.
///
/// Both engines assemble this after their role-specific Logon exchange: the
/// initiator with a [`MessageStore`] and the write timeout it was configured
/// with, the acceptor with no store and the default write timeout. Sharing the
/// struct is what keeps the two roles running byte-for-byte the same reactor.
pub(crate) struct SessionParams<A: Application> {
    /// The framed socket, already past the Logon handshake.
    pub(crate) framed: FixFramed,
    /// The Active session typestate.
    pub(crate) session: Session<Active>,
    /// Shared session runtime (sequences + heartbeat).
    pub(crate) runtime: Arc<SessionRuntime>,
    /// Outbound frame factory.
    pub(crate) factory: MessageFactory,
    /// Identity every inbound message must carry.
    pub(crate) identity: PeerIdentity,
    /// Clock-skew check applied to every inbound `SendingTime` (52).
    pub(crate) sending_time: SendingTimeGuard,
    /// Session configuration.
    pub(crate) config: SessionConfig,
    /// Application callbacks.
    pub(crate) application: Arc<A>,
    /// Session identifier.
    pub(crate) session_id: SessionId,
    /// Optional message store for outbound frames and resend replay.
    pub(crate) store: Option<Arc<dyn MessageStore>>,
    /// What a failed write to `store` means.
    pub(crate) store_policy: StoreFailurePolicy,
    /// Bound on each call to `store`.
    pub(crate) store_timeout: Duration,
    /// The counter values the handshake wrote to `store`, so the reactor's
    /// first pass does not write them again.
    pub(crate) persisted: PersistedCounters,
    /// Set by the reactor when its close-time store reset fails; the engine
    /// that owns the store performs the reset on its next session.
    pub(crate) reset_owed: Arc<OwedReset>,
    /// A gap detected in the Logon exchange, as (first missing number, highest
    /// number seen). The reactor's first act is to request it, so a failure to
    /// send that request closes the session through the normal close path.
    pub(crate) opening_gap: Option<(u64, u64)>,
    /// Bound on a single socket write.
    pub(crate) write_timeout: Duration,
    /// Capacity of the outbound command queue.
    pub(crate) outbound_capacity: usize,
    /// Capacity of the inbound application queue.
    pub(crate) app_queue_capacity: usize,
}

/// Wires the channels, spawns the application dispatcher and the reactor task,
/// and returns the handles a [`Connection`](crate::Connection) is built from.
///
/// `guard` rides the reactor task for the whole life of the session and is
/// dropped when the task ends, on every close path. The initiator passes `()`;
/// the acceptor passes the admission slot it claimed, so the slot is freed once
/// the session is over and the counterparty may reconnect.
///
/// This is the single place the reactor is launched, so both engines get the
/// same dispatcher hand-off, the same store persistence order and policy, and
/// the same shutdown path: a spawned task that always reaches a close, fires
/// `on_logout`, and signals the `watch` channel. Any counter value the
/// handshake did not already write is persisted first inside the task, before
/// the first inbound message is acted on.
pub(crate) fn spawn_session<A, G>(
    params: SessionParams<A>,
    guard: G,
) -> (mpsc::Sender<Command>, watch::Receiver<bool>)
where
    A: Application + 'static,
    G: Send + 'static,
{
    let SessionParams {
        framed,
        session,
        runtime,
        factory,
        identity,
        sending_time,
        config,
        application,
        session_id,
        store,
        store_policy,
        store_timeout,
        persisted,
        reset_owed,
        opening_gap,
        write_timeout,
        outbound_capacity,
        app_queue_capacity,
    } = params;

    let (command_tx, command_rx) = mpsc::channel(outbound_capacity);
    let (closed_tx, closed_rx) = watch::channel(false);
    let (app_tx, app_rx) = mpsc::channel(app_queue_capacity);
    let (reject_tx, reject_rx) = mpsc::channel(app_queue_capacity);
    let garbled = config.garbled_frame_limit.map(GarbledFrameWindow::new);

    // The dispatcher stops when the reactor drops `app_tx`, which `run_reactor`
    // does on every exit path.
    let app_completed = Arc::new(AtomicU64::new(0));
    let dispatcher = tokio::spawn(run_app_dispatcher(
        Arc::clone(&application),
        session_id.clone(),
        app_rx,
        reject_tx,
        Arc::clone(&app_completed),
    ));

    let reactor = Reactor {
        factory,
        identity,
        sending_time,
        runtime,
        config,
        application,
        session_id,
        store,
        store_policy,
        store_timeout,
        persisted,
        reset_owed,
        app_handed: None,
        resend: None,
        write_timeout,
        app_tx,
        garbled,
    };

    let channels = ReactorChannels {
        commands: command_rx,
        app_rejects: reject_rx,
        closed: closed_tx,
        dispatcher,
        app_completed,
    };
    tokio::spawn(async move {
        let _guard = guard;
        run_reactor(framed, channels, reactor, session, opening_gap).await;
    });

    (command_tx, closed_rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_undelivered_range_nothing_handed_over() {
        assert_eq!(undelivered_range(None, 0), None);
        assert_eq!(undelivered_range(None, 7), None);
    }

    #[test]
    fn test_undelivered_range_none_finished_is_everything_handed_over() {
        // The dispatcher finished nothing in this session: the range starts at
        // the first number handed over, not at 1.
        assert_eq!(undelivered_range(Some((5, 9)), 0), Some((5, 9)));
    }

    #[test]
    fn test_undelivered_range_starts_past_the_last_finished() {
        assert_eq!(undelivered_range(Some((5, 9)), 6), Some((7, 9)));
        // Admin numbers between application messages fall inside the span.
        assert_eq!(undelivered_range(Some((5, 12)), 8), Some((9, 12)));
    }

    #[test]
    fn test_undelivered_range_all_finished_is_none() {
        assert_eq!(undelivered_range(Some((5, 9)), 9), None);
        assert_eq!(undelivered_range(Some((5, 5)), 5), None);
    }

    #[test]
    fn test_undelivered_range_is_checked_at_the_top_of_the_space() {
        // A finished number at u64::MAX leaves nothing past it; the
        // arithmetic must not wrap to a range starting at 0.
        assert_eq!(
            undelivered_range(Some((u64::MAX, u64::MAX)), u64::MAX),
            None
        );
    }
}
