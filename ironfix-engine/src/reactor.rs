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
//! An application message that is next in sequence takes one more check on a
//! FIX 5.0 session (framed as FIXT.1.1) before it reaches `from_app`: an
//! `ApplVerID` (1128) naming a version the session does not accept is
//! answered with a session Reject (`SessionRejectReason` 18, `RefTagID` 1128),
//! and its number is consumed as for any rejected message. A message without
//! 1128 is in the counterparty's default version, checked at the handshake.
//!
//! # Bounded recovery
//!
//! A gap is answered with a `ResendRequest` (2), and a request that goes
//! unanswered does not wait forever: it is retried every
//! [`SessionConfig::resend_timeout`] up to
//! [`SessionConfig::resend_attempt_limit`] attempts, after which the session is
//! logged out.
//!
//! The one exception is a gapped Logon or acknowledgement when both sides
//! declared `NextExpectedMsgSeqNum` (789): the counterparty resends that gap
//! on its own, so the reactor sends nothing, holds the Logon and consumes its
//! number once the gap below it is filled. The gap is still bounded: if it
//! makes no progress for one resend timeout, a real `ResendRequest` goes out,
//! and the usual retries follow.
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
//! The reactor is a single task owning the socket, and it never waits inside
//! a write. Every frame it sends, resends or answers with is appended to the
//! session's write buffer; the buffer is written out by one branch of the
//! loop that polls the flush and the next inbound read together, on the same
//! socket, so a flush the counterparty is not taking never stops the reading.
//! Two sides writing to each other at once (two resends larger than the
//! socket buffers, or live traffic both ways) therefore keep draining each
//! other. A side that waited inside one write would wait for a reader that
//! may be waiting the same way, until the write timeout closed both.
//!
//! A live frame (an application message, a Heartbeat reply, a Reject) is
//! written through as soon as it is fed: the flush is polled once without
//! waiting, and polled again before the next command is taken. Frames
//! therefore wait in the buffer only while the stream is not taking bytes,
//! never while the next message's callback and store call run. Past 16 KiB
//! of waiting output no more live messages are taken from the command queue,
//! which is what holds [`Connection::send`](crate::Connection::send) back
//! while the counterparty reads slowly, and bounds what a fresh message
//! (a Heartbeat echoing a `TestReqID`) queues behind. A resend feeds up to
//! 64 KiB, at most 64 frames a step, so one write carries many resent
//! frames. Reading pauses only while the replies to inbound frames have piled
//! up 64 KiB past the frame that took the buffer over 64 KiB, so a
//! counterparty that sends faster than it reads cannot grow the buffer; a
//! completed flush gives a capacity grown past 128 KiB back.
//!
//! The write timeout is how long waiting output may go with the stream
//! accepting **none** of it, checked on the 100 ms tick, which polls the
//! flush once before it looks: time the reactor spends inside an inline
//! await (a store call, a callback) with nobody polling the flush is not
//! taken for a stall if the stream takes the bytes once polled. A stall is
//! detected about two ticks after the timeout, later if the reactor is
//! inside an inline await when it runs out. Progress means bytes the local
//! stream accepted (for TCP, copied into the kernel's send buffer), not
//! bytes the counterparty received, and a stream that buffers on its own
//! (TLS, for instance) hides a counterparty that stopped reading until its
//! own buffer is full.
//!
//! A Logout of this session's own is sent once it has been written whole.
//! Until then the session behaves as one logging out but its logout timeout
//! has not started (the write timeout bounds the wait); a close whose own
//! Logout was never written whole is not graceful, so `reset_on_logout` does
//! not reset a stream the counterparty still expects to continue. The same
//! holds for the two probes that wait on an answer: a TestRequest's reply
//! deadline and a ResendRequest's retry clock start once the frame is written
//! whole, so output buffered ahead of it under backpressure does not use them
//! up (issue #142).
//!
//! A slow `from_app` cannot delay the reactor either: inbound application
//! messages are handed to a separate dispatcher task over a bounded queue, so
//! an application handler never delays a socket read, a heartbeat, or
//! timeout detection.
//!
//! A resend (the answer to a `ResendRequest`, or the resend a counterparty's
//! `NextExpectedMsgSeqNum` (789) asks for) is queued and fed to the write
//! buffer in steps. Steps and inbound reads alternate in a bounded ratio: a
//! frame the counterparty has already sent is handled before the next step,
//! and at most 16 in a row, so a counterparty that sends without pause cannot
//! hold a resend back, and a resend cannot hold reading back. The owed
//! Logout's deadline is checked before every step as well as on the tick.
//! Nothing that takes a new number is written in the middle of a resend:
//! live outbound application messages (and a Logout the consumer asks for)
//! wait in the command queue, Heartbeat replies, session Rejects and this
//! session's own `ResendRequest` are held back and written right after it,
//! and no idle Heartbeat or TestRequest is sent meanwhile. Once 1024 messages
//! are held, the reactor stops reading until the resend is done rather than
//! write one of them early. A Logout from the counterparty is answered once
//! the resend it is owed is done, within the logout timeout. Only messages
//! that end the session are written at once. Whatever a closing session left
//! in the write buffer (its last Logout, typically) is written out before the
//! socket is dropped, for as long as the stream keeps taking bytes within the
//! write timeout.
//!
//! The attached [`MessageStore`] **does** run on the reactor: every store call
//! is awaited inline, because its result decides whether a frame may be written
//! or a message acted on. A slow store therefore delays this session's reads,
//! heartbeats and timeout detection for as long as the call takes. Each call is
//! bounded by the store timeout, and an overrun is a failed write under the
//! [`StoreFailurePolicy`]. `to_admin`, `to_app_checked` (and through it
//! `to_app`) and `from_admin` also run inline.
//!
//! # The outbound gate and send outcomes
//!
//! Every **new** outbound application message goes through
//! [`Application::to_app_checked`] when it is about to be framed, before a
//! sequence number is peeked and before the store is touched, so a veto
//! spends nothing and files nothing. A replay is not gated: the answer to a
//! `ResendRequest` and the `NextExpectedMsgSeqNum` (789) resend write the
//! filed frame as it was filed, without the callback, where QuickFIX calls
//! `toApp` on each resent application message and gap-fills one that throws
//! `DoNotSend`. Administrative messages go through `to_admin`, which cannot
//! refuse them.
//!
//! A message handed in with
//! [`Connection::send_tracked`](crate::Connection::send_tracked) carries a
//! receipt. Once its frame is fed to the write buffer, the receipt waits in a
//! queue of pending receipts, with the frame's `MsgSeqNum`, the `SendingTime`
//! captured right after it was encoded and whether the store filed it, and is
//! resolved exactly once:
//!
//! - `Sent` by [`Reactor::resolve_sent`], from [`Reactor::on_flushed`], for
//!   every pending receipt: a completed flush wrote everything fed before
//!   it;
//! - `Unknown` with `Transport` or `WriteTimeout` when the write fails or the
//!   write timeout runs out ([`Reactor::close_on_write_failure`]), or when
//!   the closing session's last flush does not drain the buffer: the number
//!   was spent when the frame was buffered;
//! - `NotSent` where the path stops before that (a veto, an unframeable
//!   body, a store refusal), and `Discarded`, `DiscardedBehindResend` or
//!   `LogoutPending` for whatever is still queued when the loop ends
//!   ([`Reactor::discard_unsent`]).
//!
//! # The outbound throttle
//!
//! With a [`ThrottleConfig`] attached, every new outbound application message
//! taken from the command queue goes through [`Reactor::admit_through_throttle`]
//! before anything else happens to it: the classifier names its budget and
//! [`Throttle::admit`], a synchronous decision over the driver's `now`, either
//! reserves a token (the message goes on to the outbound gate at once, and
//! the token is taken when its frame is fed, [`Throttle::charge_at`]), holds it
//! in its budget's queue, or refuses it (`NotSent` with `Throttled`, nothing
//! peeked, spent or filed). A held message is released by a branch of the
//! loop, one per pass, on a single timer moved to the instant the next token
//! is earned ([`Throttle::next_release`]), under the same conditions a command
//! is taken: no resend under way and room under the live mark, and only while
//! the session is Active. A message whose token is already there is released
//! without the timer, whose deadlines Tokio rounds up to the millisecond, so
//! a burst, or a budget faster than one message per millisecond, keeps its
//! rate. It then goes through `to_app_checked` and the write
//! path as a command would ([`Reactor::send_application`]); one the gate
//! vetoes gives its token back. Commands go on being taken while messages are
//! held, so a message of another budget, and every administrative message,
//! never waits behind them. Once this session's own Logout is framed, or the
//! session closes, what the throttle holds resolves `NotSent` with
//! `DiscardedByThrottle` ([`Reactor::discard_throttled`]). Administrative
//! frames, replays and gap fills never go through the throttle.
//!
//! All sequence arithmetic goes through the checked
//! [`SequenceManager::try_allocate_sender_seq`] /
//! [`SequenceManager::try_increment_target_seq`]; an exhausted counter tears the
//! session down rather than wrapping.

use crate::application::{Application, RejectReason, SessionId};
use crate::close::{CloseReason, LogoutCause, bounded_peer_text};
use crate::connection::{Command, SessionRuntime};
use crate::error::EngineError;
use crate::garbled::{GarbledFrameWindow, GarbledVerdict};
use crate::outbound;
use crate::outcome::{self, NotSentReason, Receipt, SendOutcome, UnknownReason};
use crate::persistence::{
    HandshakeStore, OwedReset, PersistedCounters, SessionStore, StoreFailurePolicy, file_and_spend,
    timed,
};
use crate::stream::SessionStream;
use crate::throttle::{Admission, BudgetId, Throttle, ThrottleConfig};
use crate::wire::{
    self, ApplVersionGuard, ApplVersionProblem, MessageFactory, PeerIdentity, PendingMessage,
    SendingTimeGuard, SendingTimeProblem,
};
use bytes::{Bytes, BytesMut};
use futures_util::{FutureExt, Sink, SinkExt, StreamExt};
use ironfix_core::error::{DecodeError, EncodeError, StoreError};
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::Timestamp;
use ironfix_core::version::FixVersion;
use ironfix_session::heartbeat::generate_test_req_id;
use ironfix_session::sequence::{SequenceCounter, SequenceExhausted, SequenceResult};
use ironfix_session::{
    Active, HeartbeatManager, LogoutPending, SequenceManager, Session, SessionConfig,
    TestRequestOutcome,
};
use ironfix_store::{MessageStore, StoredMessage};
use ironfix_transport::{CodecError, FixCodec};
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval, timeout};
use tokio_util::codec::{Encoder, Framed};

/// The session's byte stream, a TCP socket or any stream a caller provided
/// (see [`crate::stream`]), framed as FIX messages.
pub(crate) type FixFramed = Framed<SessionStream, FixCodec>;

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

/// Default write timeout: how long a handshake write may take, and how long
/// an established session's output may wait while the stream accepts none of
/// it.
pub(crate) const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Output, in bytes, a resend lets wait in the write buffer before it stops
/// feeding more.
///
/// The bound is checked before a frame is added, so the buffer can exceed it
/// by one frame. It is what lets one flush carry many resent frames. It is
/// also the base of the read ceiling ([`Writer::reads_paused`]), and the
/// capacity the write buffer is given when the reactor starts and shrunk back
/// to after a flush ([`Writer::flushed`]).
const WRITE_BUFFER_HIGH_WATER: usize = 64 * 1024;

/// Output, in bytes, above which the reactor stops taking live messages from
/// the command queue.
///
/// Lower than [`WRITE_BUFFER_HIGH_WATER`] on purpose. A live frame is written
/// through as soon as it is fed (the flush is polled once, without waiting),
/// so frames wait in the buffer only while the stream is not taking bytes;
/// this mark bounds how much a counterparty that reads slowly can make wait
/// in front of the next message. A Heartbeat echoing a `TestReqID` (112), or
/// any message whose `SendingTime` (52) should be fresh, then queues behind at
/// most this much, and [`Connection::send`](crate::Connection::send) is held
/// back sooner. The cost is fewer frames per write under backpressure than a
/// resend gets.
const LIVE_HIGH_WATER: usize = 16 * 1024;

/// Output, in bytes, that the replies to inbound frames may add past the
/// frame that took the buffer over [`WRITE_BUFFER_HIGH_WATER`] before the
/// reactor stops reading ([`Writer::reads_paused`]).
const REPLY_ALLOWANCE: usize = 64 * 1024;

/// Most frames one resend step feeds, whatever their size, so a step of small
/// frames (gap fills, short reports) does not run for long without the
/// reactor reading or yielding.
const MAX_FRAMES_PER_RESEND_STEP: usize = 64;

/// Most inbound frames the reactor handles in a row while a resend has room
/// to write, before it gives the resend a step.
///
/// Before each resend step the reactor handles a frame the counterparty has
/// already sent, if there is one, so a resend never holds reading back (a
/// Logout that arrived is seen before the resend runs on). This bound is the
/// other half of the ratio: a counterparty that sends without pause (market
/// data, or a TestRequest storm) cannot hold a resend back, and nothing that
/// waits behind the resend is held with it.
const MAX_READS_PER_RESEND_STEP: u32 = 16;

/// Most inbound frames dropped per poll while a closing session writes out
/// its last output, so a counterparty that keeps sending cannot keep that
/// poll from returning.
const CLOSE_DRAIN_FRAMES_PER_POLL: usize = 64;

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
/// replay reads in bounded batches rather than allocating and locking over the
/// entire history at once. Each page read is a step of its own in the reactor
/// loop and spends cooperative budget, so a long run of administrative or
/// unrebuildable entries (skipped, not written) cannot keep the reactor from
/// yielding.
const RESEND_PAGE_LIMIT: usize = 256;

/// Most resends a session queues for its counterparty, the one under way
/// included.
///
/// Resends are answered by steps of the reactor loop, between inbound reads,
/// so requests that keep arriving faster than they are answered would
/// otherwise grow the queue without bound. Past this many, a new request is
/// merged into the last queued one, which is not under way yet: its range
/// widens to cover both, so every number either request asked for is still
/// answered (a number asked for by neither reaches the counterparty as a
/// possible duplicate, which it drops).
const MAX_QUEUED_RESENDS: usize = 64;

// The merge widens the last queued resend, which must not be the one under way.
const _: () = assert!(MAX_QUEUED_RESENDS >= 2);

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
    /// A locally initiated Logout is in the write buffer and has not all been
    /// written yet. The session already behaves as one logging out (no new
    /// application message, an inbound Logout completes the exchange), but
    /// the logout timeout has not started: the Logout has not been sent. Once
    /// its last byte is written, the session moves to
    /// [`Phase::LogoutPending`] ([`Reactor::advance_logout`]), whose
    /// typestate records that moment; if it is never written, the write
    /// timeout closes the session.
    LogoutQueued(Session<Active>),
    /// A locally initiated Logout has been sent and is awaiting
    /// acknowledgement, within the logout timeout from `Session::sent_at`.
    LogoutPending(Session<LogoutPending>),
}

/// Terminal outcome of the reactor loop.
///
/// Whether the close is graceful (it ended through a Logout exchange) is the
/// reason's own [`CloseReason::is_graceful`], so the flag that decides
/// `reset_on_logout` and the reason reported to the application cannot
/// disagree.
struct SessionClosed {
    /// Why the session ended: logged, and reported to the application and
    /// the connection.
    reason: CloseReason,
}

/// Builds a [`SessionClosed`] outcome.
const fn closed(reason: CloseReason) -> SessionClosed {
    SessionClosed { reason }
}

/// The close reason for a fatal error out of a send: a store failure under
/// the fail-closed policy, an exhausted counter, a frame the codec would not
/// take, or a failed write.
fn send_failure_reason(err: &EngineError) -> CloseReason {
    match err {
        EngineError::Store(_) => CloseReason::StoreFailure {},
        EngineError::SequenceExhausted(exhausted) => CloseReason::SequenceExhausted {
            counter: exhausted.counter,
        },
        EngineError::WriteTimeout(timeout) => CloseReason::WriteTimeout { timeout: *timeout },
        EngineError::Io(io) => CloseReason::TransportError {
            kind: Some(io.kind()),
        },
        EngineError::Codec(codec) => codec_failure_reason(codec),
        _ => CloseReason::Internal {},
    }
}

/// The close reason for a fatal codec error, read or write.
fn codec_failure_reason(err: &CodecError) -> CloseReason {
    match err {
        CodecError::MessageTooLarge { size, max_size } => CloseReason::MessageTooLarge {
            size: *size,
            max_size: *max_size,
        },
        CodecError::Io(_) => CloseReason::TransportError { kind: None },
        _ => CloseReason::FramingError {},
    }
}

/// Consumes a phase on an abnormal close, driving the typestate to
/// Disconnected.
fn teardown(phase: Phase) {
    match phase {
        Phase::Active(session) | Phase::LogoutQueued(session) => {
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
    closed(CloseReason::SequenceExhausted {
        counter: err.counter,
    })
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

    /// Opens recovery for a gap that `NextExpectedMsgSeqNum` (789) already
    /// asked the counterparty to fill, with **no** `ResendRequest` sent:
    /// `attempts` is 0.
    ///
    /// The state is armed so a gapped frame arriving meanwhile does not send a
    /// request that would cross the counterparty's 789 resend, and so a gap
    /// that stops filling is still chased: once it has made no progress for
    /// the retry timeout (no resend at all, or one that stalls partway),
    /// [`Reactor::on_resend_stalled`] sends a real `ResendRequest`, which a
    /// limit of one request still allows.
    #[must_use]
    pub(crate) fn implied(expected: u64, high_water: u64, config: &SessionConfig) -> Self {
        Self {
            attempts: 0,
            ..Self::first(expected, high_water, config)
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

    /// Restarts the stall clock: a request that is not charged against the
    /// retry budget has just gone out (or been held back behind a resend).
    fn restart_clock(&mut self) {
        self.requested_at = Instant::now();
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
        // An implied gap (no request sent yet) stays implied, so a stall
        // after partial progress still gets its one real request.
        self.attempts = self.attempts.min(1);
    }
}

/// One resend this session owes the counterparty: what is left of
/// `begin_seq..new_seq`, written a few frames per step of the reactor loop.
#[derive(Debug)]
struct ResendJob {
    /// The first number not covered by the reply (exclusive end).
    new_seq: u64,
    /// The last number the reply may replay: `new_seq - 1`.
    end_seq: u64,
    /// The next number the reply still owes the counterparty.
    reply_cursor: u64,
    /// The next store key to read a page from.
    read_from: u64,
    /// Stored messages read and not yet written or skipped, in order.
    page: std::vec::IntoIter<StoredMessage>,
    /// Whether the store has nothing more to give for this range (or there
    /// is no store, or a read failed): what is left is gap-filled.
    store_done: bool,
    /// A rebuilt replay frame, with its number, written on the call after
    /// the gap fill that precedes it.
    pending: Option<(u64, BytesMut)>,
}

impl ResendJob {
    /// The resend of `begin_seq..new_seq`, or `None` for an empty range. With
    /// `no_store` the store is done from the start: the whole range is one
    /// gap fill.
    #[must_use]
    fn new(begin_seq: u64, new_seq: u64, no_store: bool) -> Option<Self> {
        if begin_seq == 0 || begin_seq >= new_seq {
            return None;
        }
        let end_seq = new_seq.checked_sub(1)?;
        Some(Self {
            new_seq,
            end_seq,
            reply_cursor: begin_seq,
            read_from: begin_seq,
            page: Vec::new().into_iter(),
            store_done: no_store,
            pending: None,
        })
    }

    /// Widens a resend that has written nothing yet to also cover `other`'s
    /// range: from the lower start to the higher end.
    fn widen(&mut self, other: &Self) {
        let begin_seq = self.reply_cursor.min(other.reply_cursor);
        self.reply_cursor = begin_seq;
        self.read_from = begin_seq;
        self.new_seq = self.new_seq.max(other.new_seq);
        self.end_seq = self.end_seq.max(other.end_seq);
    }
}

/// Queues `job` behind `queue`, or, once [`MAX_QUEUED_RESENDS`] are queued,
/// merges it into the last one, which is not under way yet (the head is), so
/// the queue stays bounded and every number `job` asks for is still answered.
fn push_resend(queue: &mut VecDeque<ResendJob>, job: ResendJob) {
    if queue.len() >= MAX_QUEUED_RESENDS
        && let Some(last) = queue.back_mut()
    {
        last.widen(&job);
        return;
    }
    queue.push_back(job);
}

/// What one call of [`Reactor::advance_resend`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResendProgress {
    /// It added one frame to the write buffer (or dropped a gap fill the
    /// callback left unsendable); there may be more.
    Wrote,
    /// It read one page from the store; there may be more. A page read ends
    /// the step, so the loop reads inbound and yields between pages.
    ReadPage,
    /// The resend is complete.
    Done,
}

/// The reactor's side of the session's write buffer (the one inside
/// [`FixFramed`]), and the clock of the write timeout.
///
/// Every frame the reactor sends, resends or answers with is appended to the
/// write buffer here ([`Writer::feed`]) and nothing else happens: no socket
/// call is made. The buffer is written to the stream by the flush half of
/// [`poll_socket`], which the reactor loop polls together with the next
/// inbound read, so a stream that is not taking bytes never stops the reactor
/// from reading; a live frame is also written through at once when the stream
/// takes it ([`Reactor::write_through`]). Two sides writing to each other at
/// once therefore keep draining each other, whatever the socket buffers hold;
/// a side that waited inside one write would wait for a reader that may be
/// waiting the same way.
///
/// The order on the wire is the order frames are fed, because the buffer is
/// written front to back.
///
/// "Written", and "progress" for the write timeout, mean bytes the local
/// stream accepted: for TCP, bytes copied into the kernel's send buffer, not
/// bytes the counterparty received. A stream that buffers on its own (TLS,
/// for instance) accepts bytes it has not sent yet, and so hides a
/// counterparty that stopped reading until its own buffer is full.
#[derive(Debug)]
struct Writer {
    /// Frames outbound bytes into the write buffer under the session's
    /// `max_message_size`, the check the framed socket's codec makes, so a
    /// frame the counterparty would refuse is never sent. Only its encoder
    /// half is used; the framed socket's own codec reads.
    codec: FixCodec,
    /// Whether output is waiting: set when a frame is fed, cleared when a
    /// flush completes (the buffer written and the stream flushed).
    pending: bool,
    /// Whether the stream accepted bytes since the last tick.
    progressed: bool,
    /// Since when the waiting output has made no progress, as the ticks see
    /// it: started by the first tick that finds output waiting and the stream
    /// taking none of it, restarted by every tick that finds progress, and
    /// cleared by a completed flush.
    stalled_since: Option<Instant>,
    /// Set when a write failed or the write timeout ran out: the closing
    /// session does not try to flush again.
    failed: bool,
    /// The first and last new `MsgSeqNum` fed since the last completed flush:
    /// what the next completed flush covers ([`Reactor::on_flushed`]).
    /// Resent frames and gap fills re-occupy old numbers and are not counted.
    fed_new: Option<(u64, u64)>,
    /// The last Logout fed, watched until it is written whole; taken by
    /// [`Reactor::advance_logout`].
    logout: WriteMark,
    /// The last TestRequest fed, watched until it is written whole: its
    /// reply deadline starts only then ([`Reactor::advance_probes`]).
    test_request: WriteMark,
    /// The last ResendRequest fed, watched until it is written whole: its
    /// retry clock starts only then ([`Reactor::advance_probes`]).
    resend_request: WriteMark,
    /// The buffer's length right after the frame that took it to
    /// [`WRITE_BUFFER_HIGH_WATER`] or past: the base of the read ceiling
    /// while the buffer stays there ([`Writer::reads_paused`]).
    crossed_at: Option<usize>,
}

/// Watches one frame fed to the write buffer until the stream has accepted
/// its last byte: only then has it been sent. A frame still buffered behind
/// earlier output has not reached the counterparty, so nothing that waits on
/// the counterparty's answer to it (the logout timeout, a TestRequest's reply
/// deadline, a ResendRequest's retry clock) may start before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WriteMark {
    /// Bytes the stream must still accept before the frame is written whole,
    /// while it is in the buffer.
    ahead: Option<usize>,
    /// Set once the frame has been written whole; taken by its consumer.
    written: bool,
}

impl WriteMark {
    /// A mark watching nothing.
    #[must_use]
    const fn new() -> Self {
        Self {
            ahead: None,
            written: false,
        }
    }

    /// Watches the frame just fed, the last one in the buffer of `framed`.
    fn mark(&mut self, framed: &FixFramed) {
        self.ahead = Some(framed.write_buffer().len());
        self.written = false;
    }

    /// Whether the frame watched has not been written whole.
    #[must_use]
    const fn unwritten(&self) -> bool {
        self.ahead.is_some()
    }

    /// Records that the stream accepted `moved` bytes from the front of the
    /// buffer.
    const fn wrote(&mut self, moved: usize) {
        if let Some(ahead) = self.ahead {
            match ahead.checked_sub(moved) {
                Some(left) if left > 0 => self.ahead = Some(left),
                _ => {
                    self.ahead = None;
                    self.written = true;
                }
            }
        }
    }

    /// Records a completed flush: the frame watched, if any, is written.
    const fn flushed(&mut self) {
        if self.ahead.take().is_some() {
            self.written = true;
        }
    }

    /// Whether the frame watched has been written whole since the last call.
    const fn take_written(&mut self) -> bool {
        std::mem::replace(&mut self.written, false)
    }
}

/// What a tick found on the write side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteCheck {
    /// No output is waiting, or it has waited less than the write timeout.
    Fine,
    /// The stream accepted bytes since the last tick.
    Progressed,
    /// Output has waited the whole write timeout without the stream
    /// accepting any of it.
    Stalled,
}

/// Capacity of the write buffer above which a completed flush replaces it
/// with one of [`WRITE_BUFFER_HIGH_WATER`]: a burst of replies, or one large
/// frame, does not leave its peak allocated for the rest of the session.
const SHRINK_ABOVE: usize = 2 * WRITE_BUFFER_HIGH_WATER;

impl Writer {
    /// A writer framing outbound bytes under `max_message_size`, with no
    /// output waiting.
    #[must_use]
    fn new(max_message_size: usize) -> Self {
        Self {
            codec: FixCodec::new().with_max_message_size(max_message_size),
            pending: false,
            progressed: false,
            stalled_since: None,
            failed: false,
            fed_new: None,
            logout: WriteMark::new(),
            test_request: WriteMark::new(),
            resend_request: WriteMark::new(),
            crossed_at: None,
        }
    }

    /// Appends `frame` to the write buffer of `framed`. No byte reaches the
    /// stream here, and nothing here can wait.
    ///
    /// The buffer keeps its capacity across flushes, so a frame costs a copy
    /// and, in steady state, no allocation.
    ///
    /// # Errors
    /// [`CodecError::MessageTooLarge`] when `frame` exceeds the session's
    /// `max_message_size`; nothing is appended.
    fn feed(&mut self, framed: &mut FixFramed, frame: &[u8]) -> Result<(), CodecError> {
        let before = framed.write_buffer().len();
        self.codec.encode(frame, framed.write_buffer_mut())?;
        let after = framed.write_buffer().len();
        if before < WRITE_BUFFER_HIGH_WATER && after >= WRITE_BUFFER_HIGH_WATER {
            self.crossed_at = Some(after);
        }
        self.pending = true;
        Ok(())
    }

    /// Records that the frame just fed carries the new `MsgSeqNum` `seq`.
    const fn fed_new(&mut self, seq: u64) {
        self.fed_new = Some(match self.fed_new {
            Some((first, _)) => (first, seq),
            None => (seq, seq),
        });
    }

    /// Watches the frame just fed, a Logout, until it is written whole.
    fn mark_logout(&mut self, framed: &FixFramed) {
        self.logout.mark(framed);
    }

    /// Whether a Logout fed has not been written whole.
    #[must_use]
    const fn logout_unwritten(&self) -> bool {
        self.logout.unwritten()
    }

    /// Records that the stream accepted `moved` bytes from the front of the
    /// buffer.
    const fn wrote(&mut self, moved: usize) {
        self.progressed = true;
        self.logout.wrote(moved);
        self.test_request.wrote(moved);
        self.resend_request.wrote(moved);
    }

    /// Records a completed flush: nothing is waiting any more. Returns the
    /// new `MsgSeqNum`s it covered, first and last.
    ///
    /// The buffer is empty, so a capacity above [`SHRINK_ABOVE`] is given
    /// back here: one allocation per shrink, never one per message.
    fn flushed(&mut self, framed: &mut FixFramed) -> Option<(u64, u64)> {
        self.pending = false;
        self.progressed = false;
        self.stalled_since = None;
        self.crossed_at = None;
        self.logout.flushed();
        self.test_request.flushed();
        self.resend_request.flushed();
        if framed.write_buffer().is_empty() && framed.write_buffer().capacity() > SHRINK_ABOVE {
            *framed.write_buffer_mut() = BytesMut::with_capacity(WRITE_BUFFER_HIGH_WATER);
        }
        self.fed_new.take()
    }

    /// Whether `waiting` bytes of output have piled up past the read ceiling,
    /// so the reactor stops reading until the stream takes some of them.
    ///
    /// The ceiling is the frame that took the buffer to
    /// [`WRITE_BUFFER_HIGH_WATER`] or past, plus [`REPLY_ALLOWANCE`]. Resends
    /// and live sends stop at their marks and add at most one frame past
    /// them, so only the replies to inbound frames (Heartbeats, Rejects) can
    /// get here, and only from a counterparty that sends faster than it
    /// reads; reading is then held back rather than the buffer growing. The
    /// arithmetic is a subtraction, so it cannot overflow.
    #[must_use]
    fn reads_paused(&self, waiting: usize) -> bool {
        if waiting < WRITE_BUFFER_HIGH_WATER {
            return false;
        }
        let base = self.crossed_at.map_or(WRITE_BUFFER_HIGH_WATER, |at| {
            at.max(WRITE_BUFFER_HIGH_WATER)
        });
        waiting
            .checked_sub(base)
            .is_some_and(|beyond| beyond > REPLY_ALLOWANCE)
    }

    /// Moves the write timeout's clock on a tick at `now`. The tick polls the
    /// flush once just before, so time the reactor spent inside an inline
    /// await (a store call, a callback) is not counted as a stall when the
    /// stream takes the bytes once polled.
    ///
    /// The timeout measures how long waiting output has made **no
    /// progress** (the stream accepting none of it), not how long one write
    /// takes. Measured on the 100 ms tick, a stall is detected about two
    /// ticks after the timeout, later if the reactor is inside an inline
    /// await when the timeout runs out.
    fn on_tick(&mut self, now: Instant, write_timeout: Duration) -> WriteCheck {
        if !self.pending {
            self.stalled_since = None;
            return WriteCheck::Fine;
        }
        if std::mem::take(&mut self.progressed) {
            self.stalled_since = Some(now);
            return WriteCheck::Progressed;
        }
        match self.stalled_since {
            Some(since)
                if now
                    .checked_duration_since(since)
                    .is_some_and(|waited| waited >= write_timeout) =>
            {
                WriteCheck::Stalled
            }
            Some(_) => WriteCheck::Fine,
            None => {
                self.stalled_since = Some(now);
                WriteCheck::Fine
            }
        }
    }

    /// How long a closing session at `now` may still spend writing its last
    /// output: what is left of one write timeout since the output last made
    /// progress, so the close never extends the wait the timeout allows.
    #[must_use]
    fn close_budget(&self, now: Instant, write_timeout: Duration) -> Duration {
        let waited = self
            .stalled_since
            .and_then(|since| now.checked_duration_since(since))
            .unwrap_or_default();
        write_timeout.checked_sub(waited).unwrap_or_default()
    }
}

/// What one poll of the socket came to.
#[derive(Debug)]
enum SocketEvent {
    /// The waiting output is written and the stream flushed, or the write
    /// failed.
    Flushed(Result<(), CodecError>),
    /// What one read produced: a frame, a fatal codec error, or the end of
    /// the stream.
    Inbound(Option<Result<BytesMut, CodecError>>),
}

/// Polls the flush of the waiting output once, recording what the stream
/// accepted.
fn poll_flush_half(
    framed: &mut FixFramed,
    writer: &mut Writer,
    cx: &mut Context<'_>,
) -> Poll<Result<(), CodecError>> {
    let waiting = framed.write_buffer().len();
    let flush = <FixFramed as Sink<BytesMut>>::poll_flush(Pin::new(&mut *framed), cx);
    if let Some(moved) = waiting
        .checked_sub(framed.write_buffer().len())
        .filter(|moved| *moved > 0)
    {
        writer.wrote(moved);
    }
    flush
}

/// Polls the socket in both directions at once, on the same `framed`.
///
/// The flush of the waiting output is polled first, so a steady inbound
/// stream can never keep the output waiting; then, with `read` set, the next
/// inbound frame, so a flush the stream is not taking never keeps the reactor
/// from reading. A flush that moved bytes is recorded for the write timeout
/// even when it has not completed.
fn poll_socket(
    framed: &mut FixFramed,
    writer: &mut Writer,
    read: bool,
    cx: &mut Context<'_>,
) -> Poll<SocketEvent> {
    if writer.pending
        && let Poll::Ready(result) = poll_flush_half(framed, writer, cx)
    {
        return Poll::Ready(SocketEvent::Flushed(result));
    }
    if read && let Poll::Ready(inbound) = framed.poll_next_unpin(cx) {
        return Poll::Ready(SocketEvent::Inbound(inbound));
    }
    Poll::Pending
}

/// [`poll_socket`] once, without waiting: what the socket has ready now, or
/// `None`. A direction that is not ready is polled again, with the reactor's
/// waker, by the socket branch of the next pass.
fn poll_socket_now(framed: &mut FixFramed, writer: &mut Writer, read: bool) -> Option<SocketEvent> {
    std::future::poll_fn(|cx| poll_socket(framed, writer, read, cx)).now_or_never()
}

/// The flush of the waiting output polled once, without waiting: `None` when
/// nothing is waiting, or when the stream takes no more for now (the socket
/// branch of the next pass polls it again, with the reactor's waker).
fn poll_flush_now(framed: &mut FixFramed, writer: &mut Writer) -> Option<Result<(), CodecError>> {
    if !writer.pending {
        return None;
    }
    std::future::poll_fn(|cx| poll_flush_half(framed, writer, cx)).now_or_never()
}

/// How dropping inbound frames during a close went for one poll.
enum Drain {
    /// Nothing more to read for now; the read waker is registered.
    Waiting,
    /// The stream ended or failed: nothing more will be read.
    Ended,
    /// [`CLOSE_DRAIN_FRAMES_PER_POLL`] frames were dropped and there may be
    /// more; the task is woken to poll again.
    Busy,
}

/// Reads and drops up to [`CLOSE_DRAIN_FRAMES_PER_POLL`] inbound frames.
fn drain_inbound(framed: &mut FixFramed, cx: &mut Context<'_>) -> Drain {
    for _ in 0..CLOSE_DRAIN_FRAMES_PER_POLL {
        match framed.poll_next_unpin(cx) {
            Poll::Pending => return Drain::Waiting,
            Poll::Ready(Some(Ok(_dropped))) => {}
            Poll::Ready(Some(Err(_)) | None) => return Drain::Ended,
        }
    }
    cx.waker().wake_by_ref();
    Drain::Busy
}

/// What one wait of [`flush_on_close`] came to.
enum CloseFlush {
    /// The buffer is written and the stream flushed, or the write failed.
    Done(Result<(), CodecError>),
    /// The stream accepted bytes: the wait starts over.
    Progressed,
}

/// Writes out what a closing session left in the write buffer (its last
/// Logout, typically) before the socket is dropped. Returns whether the
/// buffer drained: `Ok`, or why not, as the reason a tracked frame still in
/// it reports ([`UnknownReason::Transport`] when the write failed,
/// [`UnknownReason::WriteTimeout`] when the stream stopped taking bytes).
///
/// The same rule bounds it as the open session: it gives up once the stream
/// has accepted no byte for the write timeout, `budget` being what is left of
/// it when the session closed. A counterparty that reads slowly but steadily
/// therefore still gets the session's last Logout; one that stopped reading
/// is given no more time than the write timeout allows.
///
/// Inbound frames that arrive meanwhile are read and dropped: the session is
/// over, and a counterparty flushing its own last output must not be left
/// waiting on a reader that stopped. Nothing here is logged but the outcome,
/// never a frame.
async fn flush_on_close(
    framed: &mut FixFramed,
    writer: &mut Writer,
    budget: Duration,
    write_timeout: Duration,
    session_id: &SessionId,
) -> Result<(), UnknownReason> {
    let mut reading = true;
    let mut budget = budget;
    loop {
        let wait = std::future::poll_fn(|cx| {
            if let Poll::Ready(result) = poll_flush_half(framed, writer, cx) {
                return Poll::Ready(CloseFlush::Done(result));
            }
            if std::mem::take(&mut writer.progressed) {
                return Poll::Ready(CloseFlush::Progressed);
            }
            if reading && matches!(drain_inbound(framed, cx), Drain::Ended) {
                reading = false;
            }
            Poll::Pending
        });
        match timeout(budget, wait).await {
            Ok(CloseFlush::Progressed) => budget = write_timeout,
            Ok(CloseFlush::Done(Ok(()))) => return Ok(()),
            Ok(CloseFlush::Done(Err(err))) => {
                tracing::warn!(
                    session = %session_id,
                    error = %err,
                    "cannot write the closing session's last output"
                );
                return Err(UnknownReason::Transport);
            }
            Err(_) => {
                tracing::warn!(
                    session = %session_id,
                    "the closing session's last output made no progress for the write timeout"
                );
                return Err(UnknownReason::WriteTimeout);
            }
        }
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
    /// Application-version check applied to every application message
    /// released to the application on a FIXT.1.1 session (`ApplVerID` 1128).
    appl_version: ApplVersionGuard,
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
    /// The `TestReqID` (112) of a TestRequest fed but not yet written whole:
    /// its reply deadline starts once it is ([`Reactor::advance_probes`]).
    /// While it is set no other TestRequest is sent.
    unwritten_test_request: Option<String>,
    /// The `MsgSeqNum` of a gapped Logon or acknowledgement held until the
    /// `NextExpectedMsgSeqNum` (789) resend fills the gap below it, then
    /// consumed ([`Reactor::release_held_logon`]).
    held_logon: Option<u64>,
    /// Resends this session owes the counterparty, answered in order, by
    /// steps of the reactor loop ([`Reactor::resend_step`]).
    resends: VecDeque<ResendJob>,
    /// Inbound frames handled since the last resend step, counted only while
    /// a resend has room to write; at [`MAX_READS_PER_RESEND_STEP`] the next
    /// pass gives the resend its step before reading again.
    reads_since_resend_step: u32,
    /// Messages that take a new number, held back while a resend is under
    /// way and written in order once it is done ([`Reactor::finish_resends`]).
    deferred: VecDeque<DeferredSend>,
    /// A Logout the counterparty sent while a resend was owed: replied to
    /// once the resend is done, or when the logout timeout runs out.
    logout_owed: Option<OwedLogout>,
    /// The expected number a spanning possible-duplicate gap fill last made
    /// this session re-request, so it re-requests at most once per number
    /// ([`Reactor::rerequest_spanned_gap`]).
    spanning_rerequested: Option<u64>,
    /// Whether this session's own Logout has been fed: messages still queued
    /// behind it when the session closes report `LogoutPending`.
    logout_sent: bool,
    /// Why this session sent its own Logout, once it has: reported in the
    /// close reason when the exchange completes or times out.
    logout_cause: Option<LogoutCause>,
    /// Tracked frames fed to the write buffer and not yet flushed, in the
    /// order they were fed; resolved by the flush that covers them or by the
    /// failure that ends the session ([`PendingReceipt`]).
    receipts: VecDeque<PendingReceipt>,
    /// How long waiting output may make no progress before the session is
    /// closed ([`Writer::on_tick`]).
    write_timeout: Duration,
    /// The write buffer's state and the write timeout's clock.
    writer: Writer,
    /// Hand-off queue to the application dispatcher.
    app_tx: mpsc::Sender<AppFrame>,
    /// Garbled-frame count against [`SessionConfig::garbled_frame_limit`], or
    /// `None` when no limit is configured.
    garbled: Option<GarbledFrameWindow>,
    /// The outbound throttle, when one is attached: the budgets new
    /// application messages are held to, and the messages they hold.
    throttle: Option<OutboundThrottle>,
}

/// A new outbound application message held by the outbound throttle until
/// its budget earns a token, with its receipt.
#[derive(Debug)]
struct HeldSend {
    /// The message, not yet through `to_app_checked`.
    message: outbound::OutboundMessage,
    /// Where its outcome goes, for a tracked send.
    receipt: Option<Receipt>,
}

/// The session's outbound throttle: its configuration, which classifies each
/// message, and the run-time budgets.
#[derive(Debug)]
struct OutboundThrottle {
    /// The budgets and the classifier.
    config: ThrottleConfig,
    /// The tokens, and the messages held for them.
    state: Throttle<HeldSend>,
    /// Whether the classifier has named a budget the configuration does not
    /// define: logged once per session, the message going to the default
    /// budget.
    unknown_budget_logged: bool,
    /// Untracked sends refused so far, per budget: a plain send has no
    /// receipt, so its refusal is a warning, logged at the 1st, 2nd, 4th,
    /// 8th... refusal of each budget so a flood of sends cannot flood the log.
    untracked_refused: Vec<u64>,
}

/// When the outbound throttle may release the next message it holds
/// ([`Reactor::next_throttle_release`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ThrottleRelease {
    /// Nothing to release: no throttle, nothing held, or a session that may
    /// not release now.
    Idle,
    /// A held message has its token already.
    Now,
    /// The next held message's token is earned at this instant.
    At(Instant),
}

/// What the Logon exchange left for the reactor to do before anything else.
#[derive(Debug, Clone, Copy, Default)]
struct Opening {
    /// A gap the Logon exchange found, as (first missing number, highest
    /// number seen); its `ResendRequest` is the reactor's first act.
    gap: Option<(u64, u64)>,
    /// Messages the counterparty's `NextExpectedMsgSeqNum` (789) said it
    /// missed, as (first number, first number not resent); resent right after
    /// the gap is requested.
    replay: Option<(u64, u64)>,
    /// A gapped Logon or acknowledgement held instead of requested, as (first
    /// missing number, the held Logon's `MsgSeqNum`): both sides declared 789,
    /// so the counterparty resends the gap below its Logon on its own, and the
    /// Logon's number is consumed once that gap is filled.
    held_logon: Option<(u64, u64)>,
}

/// The session reactor: owns the socket, multiplexes inbound frames,
/// outbound commands, application rejections, and heartbeat timers until the
/// session closes.
///
/// `opening` is what the Logon exchange left to do first: request a gap it
/// found, then resend what the counterparty's `NextExpectedMsgSeqNum` (789)
/// said it missed.
async fn run_reactor<A: Application + 'static>(
    mut framed: FixFramed,
    channels: ReactorChannels,
    mut ctx: Reactor<A>,
    session: Session<Active>,
    opening: Opening,
) {
    let ReactorChannels {
        mut commands,
        mut app_rejects,
        closed: closed_tx,
        mut dispatcher,
        app_completed,
    } = channels;
    // The write buffer is sized for a resend step once, here, so the steps
    // and the live sends after it do not grow it frame by frame. A completed
    // flush shrinks it back to this size after a peak (`Writer::flushed`).
    framed.write_buffer_mut().reserve(WRITE_BUFFER_HIGH_WATER);
    // The gap is requested, and the 789 replay sent, here rather than by the
    // handshake: `on_logon` has already run, so a failure to send either (a
    // store refusal under the fail-closed policy, a store that reports itself
    // corrupted, a peer that stopped reading) has to close the session through
    // the path below, which runs `on_logout`, the close-time reset and the
    // last counter writes. A failure leaves no phase, and the first pass of
    // the loop ends the session with it.
    let (mut phase, mut opening_failure) =
        match ctx.open(&mut framed, Phase::Active(session), opening).await {
            Ok(phase) => (Some(phase), None),
            Err(outcome) => (None, Some(outcome)),
        };
    let mut commands_open = true;
    let mut rejects_open = true;
    // Whether the latest pass of the loop started with a resend under way,
    // read once the loop ends to say why queued messages were not sent.
    let mut resending = false;
    let mut tick = interval(TICK_INTERVAL);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // When the outbound throttle earns the token its next held message waits
    // for. One timer for the whole session, moved to each new instant, so a
    // throttled send costs no timer allocation; its branch is enabled only
    // while a held message waits for a token still to come. A message whose
    // token is already there does not go through the timer, which rounds
    // every deadline up to the next millisecond: it is released by an
    // always-ready branch, so a budget faster than one message per
    // millisecond, or a burst, is not slowed down to the timer's resolution.
    let mut release_timer = std::pin::pin!(tokio::time::sleep_until(tokio::time::Instant::now()));

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
            break opening_failure.take().unwrap_or_else(|| {
                tracing::error!(session = %ctx.session_id, "internal error: session phase lost");
                closed(CloseReason::Internal {})
            });
        };
        // Every counter change of the previous event (or of the handshake, on
        // the first pass) is persisted before the next event is handled; under
        // the fail-closed policy a failed write ends the session here.
        let current = match ctx.persist_counters().await {
            Ok(()) => current,
            Err(err) => break ctx.close_on_store_failure(current, &err),
        };
        // A Logout of ours written whole since the last pass has now been
        // sent: its logout timeout starts.
        let current = ctx.advance_logout(current);
        ctx.advance_probes();
        // Nothing below waits on the socket: every handler only appends to
        // the write buffer (a live frame is also written through at once when
        // the stream takes it), and the socket branch writes the rest out
        // while it goes on reading. A resend in progress (the answer to a
        // ResendRequest, or the 789 resend) is fed a few frames per step, up
        // to the high water; until it is done, live outbound application
        // messages wait in the command queue, so they never overtake it. Live
        // messages stop at the lower live mark, which is what holds a sender
        // back while the counterparty reads slowly.
        resending = ctx.resend_in_progress();
        let waiting = framed.write_buffer().len();
        let resend_ready = resending && waiting < WRITE_BUFFER_HIGH_WATER;
        let live_room = waiting < LIVE_HIGH_WATER;
        // While a resend is under way and the messages held behind it fill
        // the hold, nothing more is read: a reply to the next inbound frame
        // could only be held past the bound or written in the middle of the
        // resend, under a new number. The write timeout bounds a counterparty
        // that neither reads nor stops sending.
        let hold_full = resending && ctx.deferred.len() >= MAX_DEFERRED_SENDS;
        // Reading also pauses for one pass once a resend that has room has
        // waited through MAX_READS_PER_RESEND_STEP inbound frames, and while
        // the replies to inbound frames have piled up past the read ceiling.
        let read = !hold_full
            && !ctx.writer.reads_paused(waiting)
            && !(resend_ready && ctx.reads_since_resend_step >= MAX_READS_PER_RESEND_STEP);
        let flushing = ctx.writer.pending;
        // A message the outbound throttle holds is released under the same
        // conditions a new command is taken (no resend under way, room under
        // the live mark), and only while the session is Active: once this
        // session's Logout is framed, nothing held is written after it.
        let release = if !resending && live_room && matches!(current, Phase::Active(_)) {
            ctx.next_throttle_release()
        } else {
            ThrottleRelease::Idle
        };
        let release_now = matches!(release, ThrottleRelease::Now);
        let release_later = match release {
            ThrottleRelease::At(at) => {
                let at = tokio::time::Instant::from_std(at);
                if release_timer.deadline() != at {
                    release_timer.as_mut().reset(at);
                }
                true
            }
            ThrottleRelease::Idle | ThrottleRelease::Now => false,
        };
        let result = tokio::select! {
            // Both directions in one poll on the same socket: the flush of
            // the waiting output, then the next inbound frame. A flush the
            // counterparty is not taking never stops the reading, so two sides
            // writing to each other at once keep draining each other.
            event = std::future::poll_fn(|cx| poll_socket(&mut framed, &mut ctx.writer, read, cx)), if read || flushing => {
                ctx.on_socket_event(&mut framed, current, event, resend_ready).await
            }
            // Always ready while a resend has room to write. The socket is
            // polled once first, without waiting: a frame the counterparty
            // has already sent is handled before the next step, up to
            // MAX_READS_PER_RESEND_STEP in a row, so neither the resend nor
            // the reading can hold the other back.
            () = std::future::ready(()), if resend_ready => match poll_socket_now(&mut framed, &mut ctx.writer, read) {
                Some(event) => ctx.on_socket_event(&mut framed, current, event, resend_ready).await,
                None => ctx.resend_step(&mut framed, current).await,
            },
            // A message the outbound throttle holds has its token: released
            // like a command is taken, one per pass, among the other ready
            // branches.
            () = std::future::ready(()), if release_now => {
                ctx.on_throttle_release(&mut framed, current).await
            }
            // The outbound throttle earned the token its oldest held message
            // was waiting for.
            () = &mut release_timer, if release_later => {
                ctx.on_throttle_release(&mut framed, current).await
            }
            command = commands.recv(), if commands_open && !resending && live_room => match command {
                Some(command) => ctx.on_command(&mut framed, current, command).await,
                None => {
                    // All handles dropped: log out gracefully.
                    commands_open = false;
                    ctx.on_command(
                        &mut framed,
                        current,
                        Command::Logout(LogoutCause::HandlesDropped),
                    )
                    .await
                }
            },
            // Not held back by the marks: a Reject answers an inbound
            // message, like a Heartbeat answers a TestRequest, and the read
            // ceiling bounds those. Holding it would stall the dispatcher and
            // fill the application queue while inbound is still read. Behind
            // a full hold it waits, as reading does.
            rejection = app_rejects.recv(), if rejects_open && !hold_full => match rejection {
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

    // Nothing more is framed: every send still queued, or held behind a
    // resend, resolves now, before the close-time store work and before
    // `wait_closed` fires.
    let behind_resend = resending || ctx.resend_in_progress();
    ctx.discard_unsent(&mut commands, behind_resend);

    // What the session queued last (its Logout, the reply to the
    // counterparty's, the Reject before an identity Logout) may still be in
    // the write buffer: it is written out before anything else closes, within
    // what is left of the write timeout, unless writing is what failed. The
    // tracked frames in it are sent if that flush drains the buffer, and
    // unknown otherwise: their numbers were spent when they were buffered.
    let mut outcome = outcome;
    if ctx.writer.pending && !ctx.writer.failed {
        let budget = ctx.writer.close_budget(driver_now(), ctx.write_timeout);
        let write_timeout = ctx.write_timeout;
        match flush_on_close(
            &mut framed,
            &mut ctx.writer,
            budget,
            write_timeout,
            &ctx.session_id,
        )
        .await
        {
            Ok(()) => ctx.on_flushed(&mut framed),
            Err(reason) => ctx.fail_receipts(reason),
        }
    }
    // Anything still waiting was buffered behind a write that failed.
    ctx.fail_receipts(UnknownReason::Transport);
    // A Logout exchange is complete only once this session's own Logout has
    // been written. One still in the buffer never reached the counterparty:
    // the close is not graceful, so `reset_on_logout` does not reset a stream
    // the counterparty still expects to continue.
    if outcome.reason.is_graceful() && ctx.writer.logout_unwritten() {
        tracing::warn!(
            session = %ctx.session_id,
            reason = %outcome.reason,
            "the session's Logout was not written before the close: not a graceful close"
        );
        outcome.reason = outcome.reason.unwritten();
    }
    let graceful = outcome.reason.is_graceful();

    let mut write_counters = true;
    if ctx.config.reset_on_disconnect || (graceful && ctx.config.reset_on_logout) {
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

    // Recorded before the callback, so a `Connection` the callback reads sees
    // it, and before the closed flag, so `close_reason` is set once
    // `wait_closed` returns.
    let _ = ctx.runtime.close_reason.set(outcome.reason.clone());
    ctx.application
        .on_session_closed(&ctx.session_id, &outcome.reason)
        .await;
    let _ = closed_tx.send(true);
    if graceful {
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
    /// The frame is in the write buffer, behind everything sent before it,
    /// and a sequence number was spent. The reactor loop writes it out; if
    /// that fails, the session closes.
    Yes,
    /// The message was dropped before the wire: `to_app_checked` vetoed it,
    /// or the callback (`to_admin` / `to_app_checked`) left it unframeable or
    /// dropped a required field. No sequence number was spent and the session
    /// is intact.
    Dropped,
    /// A resend is under way: the message waits behind it and is written, in
    /// order, once the resend is done ([`Reactor::finish_resends`]). No
    /// sequence number has been spent on it yet.
    Deferred,
}

/// Why [`Reactor::prepare`] refused a message before it was framed. Nothing
/// was spent and nothing filed.
#[derive(Debug)]
enum Refusal {
    /// `to_app_checked` vetoed the application message.
    Vetoed(RejectReason),
    /// The callback left a body the engine will not frame.
    Invalid(EngineError),
}

impl Refusal {
    /// The reason a tracked send reports for this refusal.
    #[must_use]
    fn into_reason(self) -> NotSentReason {
        match self {
            Self::Vetoed(reason) => NotSentReason::Vetoed { reason },
            Self::Invalid(err) => NotSentReason::invalid(&err),
        }
    }
}

/// A tracked frame fed to the write buffer, waiting for the flush that
/// writes it: everything its `Sent` outcome reports, captured when it was
/// framed and filed.
#[derive(Debug)]
struct PendingReceipt {
    /// The `MsgSeqNum` (34) spent on the frame.
    seq: u64,
    /// The `SendingTime` (52) it carries, as written on the wire.
    sending_time: Timestamp,
    /// Whether the store filed it.
    filed: bool,
    /// The caller's receipt, marked as written.
    receipt: Receipt,
}

/// A message that takes a new sequence number, held back while a resend is
/// under way and written once it is done.
#[derive(Debug)]
enum DeferredSend {
    /// A message built when it was asked for: a Heartbeat answering a
    /// TestRequest, a session Reject. A tracked application message would
    /// carry its receipt here, but none is ever held: application messages
    /// wait in the command queue while a resend is under way.
    Message(PendingMessage, Option<Receipt>),
    /// The `ResendRequest` for the gap recovery tracks. It is built when it is
    /// written, from the gap as it stands then, and skipped if the gap has
    /// closed meanwhile.
    ResendRequest,
}

/// Most messages held back behind a resend before the reactor stops reading.
///
/// Once the hold has this many (a counterparty sending TestRequests faster
/// than the resend drains), nothing more is read, and no application Reject
/// is taken, until the resend is done: a new message is never written in the
/// middle of the resend. The hold grows past the bound by at most what one
/// inbound frame produces (a Heartbeat reply and the `ResendRequest` marker).
/// A counterparty that neither reads nor stops sending is closed by the
/// write timeout.
const MAX_DEFERRED_SENDS: usize = 1_024;

/// A Logout the counterparty sent while this session still owed it a resend:
/// the reply waits for the resend, within the logout timeout.
#[derive(Debug, Clone)]
struct OwedLogout {
    /// When the counterparty's Logout arrived.
    since: Instant,
    /// Its `Text` (58), bounded, for the close reason.
    text: Option<String>,
}

impl<A: Application> Reactor<A> {
    /// Why this session sent its own Logout. Every path to
    /// [`Phase::LogoutQueued`] records it; a missing one reads as a plain
    /// request rather than failing the close.
    fn take_logout_cause(&mut self) -> LogoutCause {
        self.logout_cause
            .take()
            .unwrap_or(LogoutCause::Requested { text: None })
    }

    /// The close of a Logout exchange this session started, completed by
    /// the counterparty's Logout `raw`, whose `Text` (58) is kept bounded.
    fn local_logout_complete(&mut self, raw: &RawMessage<'_>) -> SessionClosed {
        let cause = self.take_logout_cause();
        closed(CloseReason::LocalLogout {
            cause,
            peer_text: bounded_peer_text(raw.get_field_str(58)),
        })
    }

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
        tracing::warn!(
            session = %self.session_id,
            error = %err,
            "store failure under the fail-closed policy"
        );
        teardown(phase);
        closed(CloseReason::StoreFailure {})
    }

    /// Handles what one poll of the socket came to: a completed or failed
    /// flush, or an inbound read. `resend_ready` says whether a resend had
    /// room to write when the socket was polled; an inbound frame handled
    /// then counts against [`MAX_READS_PER_RESEND_STEP`].
    async fn on_socket_event(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        event: SocketEvent,
        resend_ready: bool,
    ) -> Result<Phase, SessionClosed> {
        match event {
            SocketEvent::Flushed(Ok(())) => {
                self.on_flushed(framed);
                Ok(phase)
            }
            SocketEvent::Flushed(Err(err)) => Err(self.close_on_write_failure(
                phase,
                codec_failure_reason(&err),
                UnknownReason::Transport,
            )),
            SocketEvent::Inbound(inbound) => {
                if resend_ready && let Some(reads) = self.reads_since_resend_step.checked_add(1) {
                    self.reads_since_resend_step = reads;
                }
                // The same poll can write a probe whole, leave the flush
                // pending and return the counterparty's answer to it: arm
                // the probe first, so the answer clears it instead of a
                // deadline being armed afterwards for a probe already
                // answered.
                self.advance_probes();
                self.on_inbound_event(framed, phase, inbound).await
            }
        }
    }

    /// The one place a completed flush is observed: everything fed so far has
    /// been accepted by the stream, in order, wherever the flush completed
    /// (the socket branch, a live frame written through, the tick's poll, or
    /// the close). Called once per flush, not once per frame.
    ///
    /// The flush covered the new `MsgSeqNum`s `first..=last` fed since the
    /// previous one (resent frames and gap fills re-occupy old numbers and
    /// are not among them): what "sent" means for those messages, and where
    /// a per-message send outcome is resolved. Accepted by the stream is what
    /// the heartbeat clock counts as sending.
    fn on_flushed(&mut self, framed: &mut FixFramed) {
        let covered = self.writer.flushed(framed);
        lock_heartbeat(&self.runtime).on_message_sent();
        if let Some((first, last)) = covered {
            tracing::trace!(session = %self.session_id, first, last, "flushed");
        }
        self.resolve_sent();
    }

    /// Resolves every pending receipt as [`SendOutcome::Sent`]: a completed
    /// flush wrote everything fed before it, so every tracked frame waiting
    /// in the buffer was in it. No sequence number is compared, so nothing
    /// here depends on numbers only going up.
    ///
    /// Called only from [`Reactor::on_flushed`]: a frame is reported sent
    /// once it has been flushed, never when it is buffered.
    fn resolve_sent(&mut self) {
        debug_assert!(
            self.receipts
                .iter()
                .zip(self.receipts.iter().skip(1))
                .all(|(earlier, later)| earlier.seq < later.seq),
            "pending receipts are fed in MsgSeqNum order"
        );
        for pending in self.receipts.drain(..) {
            pending.receipt.resolve(SendOutcome::Sent {
                seq: pending.seq,
                sending_time: pending.sending_time,
                filed: pending.filed,
            });
        }
    }

    /// Resolves every pending receipt as [`SendOutcome::Unknown`] with
    /// `reason`: their frames were numbered and buffered, and the write that
    /// would have carried them failed or will not happen. Each keeps the
    /// number spent on it.
    fn fail_receipts(&mut self, reason: UnknownReason) {
        for pending in self.receipts.drain(..) {
            pending.receipt.resolve(SendOutcome::Unknown {
                seq: pending.seq,
                reason,
            });
        }
    }

    /// Writes the waiting output at once if the stream takes it now, without
    /// waiting: called after every new frame is fed, so a live message, a
    /// Heartbeat reply or a Reject leaves as soon as it exists rather than
    /// waiting for the next pass of the loop (and the next message's callback
    /// and store call). Output waits in the buffer only while the stream is
    /// not taking bytes; the socket branch then goes on with the flush.
    ///
    /// # Errors
    /// The write failed: the session cannot continue, and the closing
    /// session does not try to flush again.
    fn write_through(&mut self, framed: &mut FixFramed) -> Result<(), CodecError> {
        match poll_flush_now(framed, &mut self.writer) {
            None => Ok(()),
            Some(Ok(())) => {
                self.on_flushed(framed);
                Ok(())
            }
            Some(Err(err)) => {
                self.writer.failed = true;
                self.fail_receipts(UnknownReason::Transport);
                Err(err)
            }
        }
    }

    /// Moves a session whose Logout has now been written whole from
    /// [`Phase::LogoutQueued`] to [`Phase::LogoutPending`]: the typestate
    /// records the moment, and the logout timeout runs from it. Any other
    /// phase is handed back as it is.
    fn advance_logout(&mut self, phase: Phase) -> Phase {
        match phase {
            Phase::LogoutQueued(session) if self.writer.logout.take_written() => {
                // Typestate: Active -> LogoutPending, as the Logout is sent.
                Phase::LogoutPending(session.initiate_logout())
            }
            phase => phase,
        }
    }

    /// Starts the deadlines of the probes written whole since the last pass:
    /// a TestRequest's reply deadline and a ResendRequest's retry clock run
    /// from when the frame reached the stream, not from when it was fed, so
    /// output buffered ahead of it under backpressure does not use them up.
    fn advance_probes(&mut self) {
        if self.writer.test_request.take_written()
            && let Some(test_req_id) = self.unwritten_test_request.take()
        {
            lock_heartbeat(&self.runtime).on_test_request_sent(test_req_id);
        }
        if self.writer.resend_request.take_written()
            && let Some(state) = self.resend.as_mut()
        {
            state.restart_clock();
        }
    }

    /// Ends the session because writing to the counterparty failed, or made
    /// no progress for the write timeout. Nothing more is written: the
    /// closing session does not try to flush what is left, and every tracked
    /// frame still buffered resolves [`SendOutcome::Unknown`] with `reason`.
    fn close_on_write_failure(
        &mut self,
        phase: Phase,
        close: CloseReason,
        reason: UnknownReason,
    ) -> SessionClosed {
        tracing::warn!(session = %self.session_id, reason = %close, "write failed");
        self.writer.failed = true;
        self.fail_receipts(reason);
        teardown(phase);
        closed(close)
    }

    /// Frames `pending` under `seq` and feeds it to the write buffer, behind
    /// everything fed before it.
    ///
    /// With `spend` set, `seq` must be the next sender number and this is the
    /// frame that spends it, in this order: encode; then [`file_and_spend`],
    /// which files the frame under `seq` and persists `seq + 1` as the next
    /// sender number when a store is attached, and spends `seq` in memory (the
    /// step the Logon handshakes share); then feed it to the write buffer,
    /// from which the reactor loop writes it. The store and the in-memory
    /// counter therefore agree before any byte reaches the socket, and a
    /// write that fails afterwards cannot lead to `seq` being reused.
    ///
    /// A gap fill passes `false`: it re-occupies a range it does not own, so
    /// filing it would overwrite a message under `seq` that is still
    /// resendable, and it spends no number.
    ///
    /// A tracked send passes its `receipt`, and this resolves it on every
    /// path but one: not sent when the frame cannot be built, numbered or
    /// filed, unknown when the codec refuses the frame after it was filed.
    /// It is marked as filing before the store is touched (a filing that is
    /// interrupted may still have reached the store), and once the frame is
    /// fed it waits with the frame's number, its `SendingTime` as written on
    /// the wire (captured right after the encode) and whether the store filed
    /// it, in the queue the flush resolves ([`Reactor::resolve_sent`]).
    ///
    /// # Errors
    /// [`WriteFailure::Encode`] leaves the session untouched — nothing was
    /// written and nothing was spent. [`WriteFailure::Fatal`] does not: a
    /// frame above `max_message_size`, an exhausted sender counter, or a
    /// store write that failed under [`StoreFailurePolicy::CloseSession`] (in
    /// which case nothing was written and nothing spent) ends the session.
    async fn write_at(
        &mut self,
        framed: &mut FixFramed,
        seq: u64,
        pending: &PendingMessage,
        spend: bool,
        mut receipt: Option<Receipt>,
    ) -> Result<(), WriteFailure> {
        let precision = self.factory.sending_time_precision();
        let (frame, stamped) = match self.factory.encode_stamped(seq, pending) {
            Ok(encoded) => encoded,
            Err(err) => {
                outcome::resolve(receipt, || {
                    SendOutcome::not_sent(NotSentReason::unencodable(&err))
                });
                return Err(WriteFailure::Encode(err));
            }
        };
        let mut filed = false;
        if spend {
            // Marked before the store is touched: a filing that is
            // interrupted may still have reached the store.
            if let Some(receipt) = receipt.as_mut() {
                receipt.filing(seq);
            }
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
            filed = match file_and_spend(
                store,
                &self.runtime.sequences,
                &self.session_id,
                seq,
                pending.msg_type(),
                frame,
            )
            .await
            {
                Ok(filed) => filed,
                Err(err) => {
                    if let Some(receipt) = receipt {
                        receipt.fail(&err);
                    }
                    return Err(WriteFailure::Fatal(err));
                }
            };
        }
        // Appended, not written: the reactor loop writes it out while it
        // goes on reading, and the write timeout watches that.
        if let Err(err) = self.writer.feed(framed, frame) {
            let err = EngineError::from(err);
            if let Some(receipt) = receipt {
                receipt.fail(&err);
            }
            return Err(WriteFailure::Fatal(err));
        }
        if spend {
            self.writer.fed_new(seq);
            if let Some(mut receipt) = receipt.take() {
                receipt.writing(seq);
                self.receipts.push_back(PendingReceipt {
                    seq,
                    sending_time: precision.truncate(stamped),
                    filed,
                    receipt,
                });
            }
        }
        Ok(())
    }

    /// Runs the outbound application callback, checks the body, files the
    /// frame, frames the message under the next sender sequence number and
    /// writes it.
    ///
    /// `to_admin` or `to_app_checked` is chosen by the MsgType, and each runs
    /// on the message **before** it is framed, so what the callback hands back
    /// is what goes on the wire; `to_app_checked` can also veto it.
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
    /// While a resend is under way the message is not written but held back
    /// ([`Sent::Deferred`]) and written once the resend is done: a new number
    /// reaching the counterparty in the middle of a resend is outside the
    /// range being answered, and a counterparty that does not queue gapped
    /// messages (IronFix itself, until #71) would be left waiting for it. The
    /// hold has no overflow path: once it holds [`MAX_DEFERRED_SENDS`], the
    /// reactor stops reading (and taking application Rejects) until the
    /// resend is done, so it grows past the bound by at most what one inbound
    /// frame produces. Messages that end the session (its Logouts, and the
    /// Rejects that precede them) go through [`Reactor::send_now`] instead.
    ///
    /// # Errors
    /// Every [`EngineError`] returned here is terminal for the session: an
    /// exhausted sender counter, a failed write, or [`EngineError::Store`]
    /// under the fail-closed store policy (nothing was written for this
    /// message).
    async fn send(
        &mut self,
        framed: &mut FixFramed,
        pending: PendingMessage,
    ) -> Result<Sent, EngineError> {
        self.send_tracked(framed, pending, None).await
    }

    /// [`Reactor::send`] for a message that may carry a [`Receipt`]: the
    /// receipt travels with it, through a hold behind a resend included, and
    /// is resolved with the message's outcome.
    ///
    /// # Errors
    /// As for [`Reactor::send`].
    async fn send_tracked(
        &mut self,
        framed: &mut FixFramed,
        pending: PendingMessage,
        receipt: Option<Receipt>,
    ) -> Result<Sent, EngineError> {
        if self.resend_in_progress() {
            self.deferred
                .push_back(DeferredSend::Message(pending, receipt));
            return Ok(Sent::Deferred);
        }
        self.send_now_tracked(framed, pending, receipt).await
    }

    /// Feeds `pending` to the write buffer at once, under the next sender
    /// sequence number, as [`Reactor::send`] does when no resend is under
    /// way, then writes it through if the stream takes it now
    /// ([`Reactor::write_through`]). A Logout is watched until it is written
    /// whole: only then has it been sent ([`Reactor::advance_logout`]).
    ///
    /// # Errors
    /// As for [`Reactor::send`].
    async fn send_now(
        &mut self,
        framed: &mut FixFramed,
        pending: PendingMessage,
    ) -> Result<Sent, EngineError> {
        self.send_now_tracked(framed, pending, None).await
    }

    /// [`Reactor::send_now`] for a message that may carry a [`Receipt`]. A
    /// refusal by the callback resolves it here; [`Reactor::write_at`]
    /// resolves it when the frame cannot be built, numbered or filed, and
    /// queues it for the flush once the frame is fed.
    ///
    /// # Errors
    /// As for [`Reactor::send`].
    async fn send_now_tracked(
        &mut self,
        framed: &mut FixFramed,
        mut pending: PendingMessage,
        receipt: Option<Receipt>,
    ) -> Result<Sent, EngineError> {
        if let Err(refusal) = self.prepare(&mut pending).await {
            outcome::resolve(receipt, || SendOutcome::not_sent(refusal.into_reason()));
            return Ok(Sent::Dropped);
        }
        let seq = self.runtime.sequences.next_sender_seq().value();
        match self.write_at(framed, seq, &pending, true, receipt).await {
            Ok(()) => {
                match pending.msg_type() {
                    MsgType::Logout => self.writer.mark_logout(framed),
                    MsgType::TestRequest => self.writer.test_request.mark(framed),
                    MsgType::ResendRequest => self.writer.resend_request.mark(framed),
                    _ => {}
                }
                self.write_through(framed)?;
                Ok(Sent::Yes)
            }
            Err(WriteFailure::Encode(err)) => {
                tracing::warn!(
                    session = %self.session_id,
                    error = %err,
                    "dropping outbound message with no legal wire form; no sequence number spent"
                );
                Ok(Sent::Dropped)
            }
            Err(WriteFailure::Fatal(err)) => Err(err),
        }
    }

    /// Runs `to_admin`, or `to_app_checked` for an application message, on
    /// `pending` and rechecks its body.
    ///
    /// Returns why the message must not be sent when `to_app_checked` vetoes
    /// it, or when the callback left a body the engine will not frame: a
    /// tag the standard header already carries, or a value with no wire
    /// form. The message is then dropped before a sequence number is peeked
    /// and before the store is touched. The warning for an unframeable body
    /// names the tag and never the value, because an outbound Logon body
    /// carries `Password` (554); a veto is logged at debug level with the
    /// reason's code only, since it is the application's own decision.
    ///
    /// Administrative messages go through `to_admin`, which cannot refuse
    /// them: they are what keeps the session legal.
    async fn prepare(&mut self, pending: &mut PendingMessage) -> Result<(), Refusal> {
        if pending.msg_type().is_admin() {
            self.application
                .to_admin(pending.message_mut(), &self.session_id)
                .await;
        } else if let Err(reason) = self
            .application
            .to_app_checked(pending.message_mut(), &self.session_id)
            .await
        {
            tracing::debug!(
                session = %self.session_id,
                msg_type = %pending.msg_type(),
                code = reason.code,
                "outbound application message vetoed by to_app_checked; no sequence number spent"
            );
            return Err(Refusal::Vetoed(reason));
        }
        if let Err(err) = outbound::check_body(pending.message()) {
            tracing::warn!(
                session = %self.session_id,
                msg_type = %pending.msg_type(),
                error = %err,
                "dropping outbound message rejected after the application callback"
            );
            return Err(Refusal::Invalid(err));
        }
        Ok(())
    }

    /// Feeds an already-built replay frame to the write buffer.
    ///
    /// A replayed message keeps the sequence number and body it was first sent
    /// with, so no number is spent and nothing is re-filed. It already
    /// carries `PossDupFlag` (43) = Y and its original `OrigSendingTime` (122),
    /// both stamped by [`wire::resend_frame`], so it is written verbatim rather
    /// than run back through the callback path.
    ///
    /// # Errors
    /// [`EngineError::Codec`] when the rebuilt frame exceeds
    /// `max_message_size`, which is terminal for the session.
    fn send_replay(&mut self, framed: &mut FixFramed, frame: &[u8]) -> Result<(), EngineError> {
        self.writer.feed(framed, frame).map_err(EngineError::from)
    }

    /// Feeds a SequenceReset-GapFill covering `at_seq..new_seq`, numbered with
    /// `at_seq`, to the write buffer, without spending a sender sequence
    /// number.
    ///
    /// A gap fill re-occupies the range it replaces, so it is written at
    /// `at_seq` rather than through [`Reactor::send`], and is **not** filed:
    /// filing it would overwrite a message under `at_seq` that is still
    /// resendable.
    ///
    /// # Errors
    /// Only a fatal failure (a frame above `max_message_size`) is returned.
    /// A body the callback left unframeable is a hole the peer will
    /// re-request and is dropped rather than closing the session.
    async fn send_gap_fill(
        &mut self,
        framed: &mut FixFramed,
        at_seq: u64,
        new_seq: u64,
    ) -> Result<(), EngineError> {
        let mut gap_fill = self.factory.sequence_reset_gap_fill(new_seq);
        if self.prepare(&mut gap_fill).await.is_err() {
            return Ok(());
        }
        match self.write_at(framed, at_seq, &gap_fill, false, None).await {
            Ok(()) => Ok(()),
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
        // A frame still waiting goes first if the stream takes it now: the
        // next message's callback and store call (an fsync, under some sync
        // policies) must not run while an earlier frame waits for nothing but
        // a poll. A write-through can come back empty although the stream has
        // room, when the task's cooperative budget ran out; by the time the
        // next command is taken the task has yielded and the budget is fresh.
        // Frames then wait only while the stream is not taking bytes.
        if let Err(err) = self.write_through(framed) {
            return Err(self.close_on_write_failure(
                phase,
                codec_failure_reason(&err),
                UnknownReason::Transport,
            ));
        }
        match command {
            Command::Send { message, receipt } => {
                if matches!(phase, Phase::LogoutQueued(_) | Phase::LogoutPending(_)) {
                    tracing::warn!(
                        session = %self.session_id,
                        msg_type = %message.msg_type(),
                        "dropping outbound message: logout pending"
                    );
                    outcome::resolve(receipt, || {
                        SendOutcome::not_sent(NotSentReason::LogoutPending)
                    });
                    return Ok(phase);
                }
                let Some((budget, message, receipt)) =
                    self.admit_through_throttle(message, receipt)
                else {
                    return Ok(phase);
                };
                self.send_application(framed, phase, budget, message, receipt)
                    .await
            }
            Command::Logout(cause) => match phase {
                Phase::LogoutQueued(_) | Phase::LogoutPending(_) => Ok(phase),
                Phase::Active(session) => self.begin_logout(framed, session, cause).await,
            },
        }
    }

    /// Puts a new outbound application message through the outbound throttle,
    /// when one is attached.
    ///
    /// Returns the message to frame now, with the budget whose token it took
    /// (`None` without a throttle), or `None` when the throttle holds it until
    /// its budget earns a token, or refused it. A refusal is resolved here,
    /// as [`NotSentReason::Throttled`], before `to_app_checked` runs and
    /// before a sequence number is peeked or the store touched; a refused
    /// plain send is logged at debug level with its budget and MsgType only.
    /// The decision is [`Throttle::admit`], which reads no clock: the time is
    /// the driver's, read here.
    fn admit_through_throttle(
        &mut self,
        message: outbound::OutboundMessage,
        receipt: Option<Receipt>,
    ) -> Option<(Option<BudgetId>, outbound::OutboundMessage, Option<Receipt>)> {
        let Some(throttle) = self.throttle.as_mut() else {
            return Some((None, message, receipt));
        };
        let budget = match throttle.config.classify_checked(&message) {
            Ok(budget) => budget,
            Err(named) => {
                if !throttle.unknown_budget_logged {
                    throttle.unknown_budget_logged = true;
                    tracing::warn!(
                        session = %self.session_id,
                        budget = %named,
                        "the throttle classifier named a budget the configuration does not \
                         define: holding the message to the default budget (logged once)"
                    );
                }
                BudgetId::DEFAULT
            }
        };
        match throttle
            .state
            .admit(budget, HeldSend { message, receipt }, driver_now())
        {
            Admission::Now(HeldSend { message, receipt }) => Some((Some(budget), message, receipt)),
            Admission::Held => {
                tracing::trace!(
                    session = %self.session_id,
                    budget = %budget,
                    held = throttle.state.held(),
                    "outbound application message held by the throttle"
                );
                None
            }
            Admission::Refused(HeldSend { message, receipt }) => {
                match receipt {
                    Some(receipt) => {
                        tracing::debug!(
                            session = %self.session_id,
                            budget = %budget,
                            msg_type = %message.msg_type(),
                            "tracked outbound application message refused by the throttle; no \
                             sequence number spent"
                        );
                        receipt.resolve(SendOutcome::not_sent(NotSentReason::Throttled { budget }));
                    }
                    None => {
                        let slot = usize::from(budget.index());
                        if let Some(count) = throttle.untracked_refused.get_mut(slot)
                            && let Some(next) = count.checked_add(1)
                        {
                            *count = next;
                            if next.is_power_of_two() {
                                tracing::warn!(
                                    session = %self.session_id,
                                    budget = %budget,
                                    msg_type = %message.msg_type(),
                                    refused = next,
                                    "outbound application message sent with Connection::send \
                                     refused by the throttle and dropped; no sequence number \
                                     spent (use send_tracked to learn each outcome; logged at \
                                     powers of two)"
                                );
                            }
                        }
                    }
                }
                None
            }
        }
    }

    /// Frames and feeds a new outbound application message that may go now:
    /// the outbound gate, the store step and the write, through
    /// [`Reactor::send_tracked`]. A message the gate vetoed, or whose body
    /// could not be framed, gives back the token it took from `budget`: it
    /// never reached the wire.
    ///
    /// # Errors
    /// A send failure is terminal for the session, as for any frame.
    async fn send_application(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        budget: Option<BudgetId>,
        message: outbound::OutboundMessage,
        receipt: Option<Receipt>,
    ) -> Result<Phase, SessionClosed> {
        match self
            .send_tracked(framed, PendingMessage::application(message), receipt)
            .await
        {
            Ok(Sent::Dropped) => {
                if let (Some(budget), Some(throttle)) = (budget, self.throttle.as_mut()) {
                    throttle.state.refund(budget);
                }
                Ok(phase)
            }
            Ok(Sent::Yes | Sent::Deferred) => {
                // The token was only reserved before the gate and the store
                // were awaited; it is taken now, at the instant the frame was
                // fed, as if the message had been admitted now.
                if let (Some(budget), Some(throttle)) = (budget, self.throttle.as_mut()) {
                    throttle.state.charge_at(budget, driver_now());
                }
                Ok(phase)
            }
            Err(err) => {
                teardown(phase);
                Err(closed(send_failure_reason(&err)))
            }
        }
    }

    /// When the outbound throttle may release the next message it holds, on
    /// the driver's clock: [`ThrottleRelease::Idle`] without a throttle or
    /// with nothing held. The clock is read only while a message is held.
    fn next_throttle_release(&mut self) -> ThrottleRelease {
        let Some(throttle) = self.throttle.as_mut() else {
            return ThrottleRelease::Idle;
        };
        if throttle.state.held() == 0 {
            return ThrottleRelease::Idle;
        }
        let now = driver_now();
        match throttle.state.next_release(now) {
            None => ThrottleRelease::Idle,
            Some(at) if at <= now => ThrottleRelease::Now,
            Some(at) => ThrottleRelease::At(at),
        }
    }

    /// Releases the message the outbound throttle has earned a token for,
    /// and frames it as a new command would be: a frame still waiting goes
    /// first if the stream takes it now, then the message goes through the
    /// outbound gate, the store step and the write. The loop enables this
    /// only while the session is Active, no resend is under way and the
    /// waiting output is under the live mark; a session whose Logout has
    /// been framed releases nothing, whatever the loop decided, and discards
    /// what is held.
    async fn on_throttle_release(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
    ) -> Result<Phase, SessionClosed> {
        if !matches!(phase, Phase::Active(_)) {
            self.discard_throttled();
            return Ok(phase);
        }
        if let Err(err) = self.write_through(framed) {
            return Err(self.close_on_write_failure(
                phase,
                codec_failure_reason(&err),
                UnknownReason::Transport,
            ));
        }
        let now = driver_now();
        let Some((budget, HeldSend { message, receipt })) = self
            .throttle
            .as_mut()
            .and_then(|throttle| throttle.state.release(now))
        else {
            return Ok(phase);
        };
        self.send_application(framed, phase, Some(budget), message, receipt)
            .await
    }

    /// Resolves every message the outbound throttle still holds as
    /// [`NotSentReason::DiscardedByThrottle`]: none was framed and no number
    /// was spent on it. Called once this session's own Logout is framed, so
    /// that no held message is written after it, and as the session closes.
    /// The count, tracked or not, is logged.
    fn discard_throttled(&mut self) {
        let Some(throttle) = self.throttle.as_mut() else {
            return;
        };
        if throttle.state.held() == 0 {
            return;
        }
        let discarded = throttle
            .state
            .drain()
            .map(|(budget, held)| {
                outcome::resolve(held.receipt, || {
                    SendOutcome::not_sent(NotSentReason::DiscardedByThrottle { budget })
                });
            })
            .count();
        tracing::warn!(
            session = %self.session_id,
            discarded,
            "outbound application message(s) held by the throttle were discarded: none was \
             framed and no sequence number was spent on them"
        );
    }

    /// Sends a Logout (35=5): feeds it, and moves the session to
    /// [`Phase::LogoutQueued`] until it is written whole, then to
    /// LogoutPending ([`Reactor::advance_logout`]), where it waits for the
    /// acknowledgement until `logout_timeout` expires. The timeout runs from
    /// when the Logout was written, not from when it was queued behind
    /// output the counterparty had not taken yet.
    ///
    /// `text` is the `Text` (58) explaining an engine-initiated logout; a
    /// consumer-initiated one carries none.
    async fn begin_logout(
        &mut self,
        framed: &mut FixFramed,
        session: Session<Active>,
        cause: LogoutCause,
    ) -> Result<Phase, SessionClosed> {
        let text = match &cause {
            LogoutCause::Requested { text } => text.clone(),
            LogoutCause::ResendStalled { .. } => Some(cause.to_string()),
            _ => None,
        };
        let logout = self.factory.logout(text.as_deref());
        match self.send_now(framed, logout).await {
            Err(err) => {
                let _ = session.disconnect();
                Err(closed(send_failure_reason(&err)))
            }
            // The Logout never reached the wire — a `to_admin` callback left it
            // unframeable. Staying Active is the honest verdict: arming the
            // logout deadline for a frame the peer never saw would tear the
            // session down over a Logout it was never told about.
            Ok(Sent::Dropped | Sent::Deferred) => Ok(Phase::Active(session)),
            Ok(Sent::Yes) => {
                // Recovery is over: a session on its way out will not process a
                // replay, and leaving the gap armed would keep asking for one.
                // A resend this session owes is never cut short here: neither
                // a Logout the consumer asks for nor the stalled-resend Logout
                // can start while one is under way (both wait behind it), and
                // a resend the counterparty asks for after this Logout is
                // still answered, as FIX allows.
                self.resend = None;
                self.held_logon = None;
                self.logout_sent = true;
                self.logout_cause = Some(cause);
                // Nothing that takes a new number follows this session's own
                // Logout: what the throttle holds is discarded now, not left
                // to wait for a token it can no longer use.
                self.discard_throttled();
                // Typestate: Active -> LogoutPending once the Logout is
                // written (at once if it was written through). The new state
                // records that moment, which is what `on_tick` times through
                // `Session::sent_at`.
                Ok(self.advance_logout(Phase::LogoutQueued(session)))
            }
        }
    }

    /// Periodic write-timeout, heartbeat, TestRequest, and timeout checks.
    async fn on_tick(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
    ) -> Result<Phase, SessionClosed> {
        // The write timeout: output the stream has accepted none of for the
        // whole timeout means a counterparty that stopped reading. The flush
        // is polled once first, without waiting, so time the reactor spent
        // inside an inline await (a store call, a callback), with nobody
        // polling the flush, is not taken for a stall: if the stream takes
        // the bytes now, that is progress. Progress since the last tick
        // counts as sending for the heartbeat clock, as a completed flush
        // does.
        match poll_flush_now(framed, &mut self.writer) {
            None => {}
            Some(Ok(())) => self.on_flushed(framed),
            Some(Err(err)) => {
                return Err(self.close_on_write_failure(
                    phase,
                    codec_failure_reason(&err),
                    UnknownReason::Transport,
                ));
            }
        }
        let phase = self.advance_logout(phase);
        self.advance_probes();
        match self.writer.on_tick(driver_now(), self.write_timeout) {
            WriteCheck::Fine => {}
            WriteCheck::Progressed => lock_heartbeat(&self.runtime).on_message_sent(),
            WriteCheck::Stalled => {
                let close = CloseReason::WriteTimeout {
                    timeout: self.write_timeout,
                };
                return Err(self.close_on_write_failure(phase, close, UnknownReason::WriteTimeout));
            }
        }

        // The logout deadline lives in the typestate: LogoutPending is defined
        // by the instant its Logout was sent (written whole), so there is no
        // second copy of it to drift. A Logout still queued has no deadline
        // yet; the write timeout bounds how long it may wait.
        if let Phase::LogoutPending(session) = &phase
            && session.sent_at().elapsed() >= self.config.logout_timeout
        {
            teardown(phase);
            let cause = self.take_logout_cause();
            return Err(closed(CloseReason::LogoutTimeout { cause }));
        }

        // While a resend is under way only the deadlines are checked. Resend
        // frames are traffic, so no Heartbeat or TestRequest is due; and a
        // stalled gap of our own is not chased, since its request could not go
        // out before the resend ends anyway (it is checked on the first tick
        // after). A Logout the counterparty sent meanwhile is answered once
        // the resend is done, or now if the logout timeout has run out.
        if self.resend_in_progress() {
            let phase = self.cut_resend_for_owed_logout(framed, phase).await?;
            if lock_heartbeat(&self.runtime).is_timed_out() {
                teardown(phase);
                return Err(closed(CloseReason::HeartbeatTimeout {}));
            }
            return Ok(phase);
        }

        // A gap that is making no progress is chased on its own clock,
        // independent of the heartbeat: gapped frames keep the heartbeat alive,
        // so this is the only thing that bounds an unsatisfied resend.
        // A request still buffered has not reached the counterparty: its
        // clock starts once it is written whole ([`Reactor::advance_probes`]),
        // and the write timeout bounds how long it may wait.
        if let Some(resend) = self.resend
            && resend.is_stalled()
            && !self.writer.resend_request.unwritten()
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
            return Err(closed(CloseReason::HeartbeatTimeout {}));
        }
        if send_test_request && self.unwritten_test_request.is_none() {
            let test_req_id = generate_test_req_id();
            let request = self.factory.test_request(&test_req_id);
            match self.send(framed, request).await {
                Err(err) => {
                    teardown(phase);
                    return Err(closed(send_failure_reason(&err)));
                }
                // Only a TestRequest that actually went out starts the timeout
                // countdown, and only once it is written whole
                // ([`Reactor::advance_probes`]): fed behind earlier output
                // under backpressure, it has not reached the counterparty.
                // Arming it for a dropped probe would time the session out
                // waiting for an answer to a frame never sent.
                Ok(Sent::Yes) => {
                    self.unwritten_test_request = Some(test_req_id);
                    self.advance_probes();
                }
                Ok(Sent::Dropped | Sent::Deferred) => {}
            }
        } else if send_heartbeat && !self.writer.pending {
            // Output still waiting to be written is traffic the counterparty
            // is about to receive, so an idle Heartbeat is due only once
            // nothing is waiting.
            let heartbeat = self.factory.heartbeat(None);
            if let Err(err) = self.send(framed, heartbeat).await {
                teardown(phase);
                return Err(closed(send_failure_reason(&err)));
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
        self.send_reject(framed, phase, reject).await
    }

    /// Sends a Reject the caller has built and keeps the session running.
    async fn send_reject(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        reject: PendingMessage,
    ) -> Result<Phase, SessionClosed> {
        if let Err(err) = self.send(framed, reject).await {
            teardown(phase);
            return Err(closed(send_failure_reason(&err)));
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
        // Behind a resend of ours the request waits too, as a marker built
        // when it is written; recovery is armed now, so the gapped frames
        // that follow do not ask again.
        if self.resend_in_progress() {
            let high_water = self
                .resend
                .map_or(high_water, |state| state.high_water.max(high_water));
            self.resend = Some(ResendState::first(expected, high_water, &self.config));
            self.defer_resend_request();
            return Ok(phase);
        }
        let request = self.factory.resend_request(expected, 0);
        match self.send(framed, request).await {
            Err(EngineError::Store(err)) => {
                return Err(self.close_on_store_failure(phase, &err));
            }
            Err(err) => {
                teardown(phase);
                return Err(closed(send_failure_reason(&err)));
            }
            // The ResendRequest never went out; leaving the range unmarked lets
            // the next frame on the same gap try again, instead of suppressing
            // it as already-requested against a request the peer never received.
            Ok(Sent::Dropped) => return Ok(phase),
            Ok(Sent::Yes | Sent::Deferred) => {}
        }
        // A re-request at a new gap start keeps the highest water mark seen so
        // far, so the range is never narrowed by a later, lower frame.
        let high_water = self
            .resend
            .map_or(high_water, |state| state.high_water.max(high_water));
        self.resend = Some(ResendState::first(expected, high_water, &self.config));
        self.drop_held_logon_for_a_request();
        Ok(phase)
    }

    /// Re-requests from `expected` after a possible-duplicate gap fill numbered
    /// below it whose `NewSeqNo` (`new_seq`) reaches past it.
    ///
    /// The fill is ignored, as FIX requires of a too-low possible duplicate,
    /// but it says the counterparty has sent numbers this session still
    /// lacks: typically a resend of the counterparty's own (its 789 resend,
    /// or an earlier answer) that stopped below its Logon, followed by an
    /// answer whose gap fill starts lower and runs through the Logon. The
    /// request asks from `expected`, so its answer starts there and arrives in
    /// sequence.
    ///
    /// The request is not charged against
    /// [`SessionConfig::max_resend_requests`]: recovery already armed keeps its
    /// attempt count and restarts its clock, and one armed here starts implied.
    /// It is made at most once per expected number, so a counterparty that
    /// keeps answering with a fill that starts too low cannot make it loop;
    /// the usual retries and Logout then bound the gap.
    async fn rerequest_spanned_gap(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        expected: u64,
        new_seq: u64,
    ) -> Result<Phase, SessionClosed> {
        self.spanning_rerequested = Some(expected);
        // `new_seq > expected >= 1`, so this cannot underflow.
        let high_water = new_seq.checked_sub(1).unwrap_or(expected).max(expected);
        tracing::info!(
            session = %self.session_id,
            expected,
            new_seq,
            "a possible-duplicate gap fill below the expectation spans numbers still missing: \
             re-requesting them"
        );
        if self.resend_in_progress() {
            self.arm_uncharged(expected, high_water);
            self.defer_resend_request();
            return Ok(phase);
        }
        let request = self.factory.resend_request(expected, 0);
        match self.send(framed, request).await {
            Err(EngineError::Store(err)) => return Err(self.close_on_store_failure(phase, &err)),
            Err(err) => {
                teardown(phase);
                return Err(closed(send_failure_reason(&err)));
            }
            Ok(Sent::Dropped) => return Ok(phase),
            Ok(Sent::Yes | Sent::Deferred) => {}
        }
        self.arm_uncharged(expected, high_water);
        self.drop_held_logon_for_a_request();
        Ok(phase)
    }

    /// Arms recovery from `expected` for a request not charged against the
    /// retry budget: recovery already armed keeps its attempts and restarts
    /// its clock; otherwise it starts implied.
    fn arm_uncharged(&mut self, expected: u64, high_water: u64) {
        match self.resend.as_mut() {
            Some(state) => {
                state.expected = expected;
                state.high_water = state.high_water.max(high_water);
                state.restart_clock();
            }
            None => {
                self.resend = Some(ResendState::implied(expected, high_water, &self.config));
            }
        }
    }

    /// Drops a held Logon because a real `ResendRequest` has just gone out.
    ///
    /// The open-ended request covers the held Logon's own number, which its
    /// answer fills (an administrative Logon is gap-filled), so that number
    /// must arrive in sequence rather than be consumed locally: consumed, the
    /// answer's gap fill starting at it would land below the expectation and
    /// be dropped as a possible duplicate, leaving whatever else it covered
    /// missing. Duplicates of the counterparty's own 789 resend that arrive
    /// meanwhile are dropped as possible duplicates as usual.
    fn drop_held_logon_for_a_request(&mut self) {
        if let Some(logon_seq) = self.held_logon.take() {
            tracing::debug!(
                session = %self.session_id,
                held_logon = logon_seq,
                "a ResendRequest went out: the held Logon is left to its answer"
            );
        }
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
            let cause = LogoutCause::ResendStalled {
                expected: resend.expected,
                attempts: resend.attempts,
            };
            tracing::warn!(session = %self.session_id, reason = %cause, "abandoning stalled resend");
            return match phase {
                // A logout already in flight cannot be reissued; let its own
                // deadline (or, while it is still queued, the write timeout)
                // close the session.
                Phase::LogoutQueued(_) | Phase::LogoutPending(_) => Ok(phase),
                Phase::Active(session) => self.begin_logout(framed, session, cause).await,
            };
        }

        let expected = resend.expected;
        let request = self.factory.resend_request(expected, 0);
        match self.send(framed, request).await {
            Err(err) => {
                teardown(phase);
                return Err(closed(send_failure_reason(&err)));
            }
            // The retry never went out; leave the state untouched so the next
            // stall tick tries again rather than counting a request the peer
            // never received.
            Ok(Sent::Dropped) => return Ok(phase),
            Ok(Sent::Yes | Sent::Deferred) => {}
        }
        if let Some(state) = self.resend.as_mut() {
            state.record_retry();
        }
        self.drop_held_logon_for_a_request();
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
        let reason = CloseReason::SequenceTooLow { expected, received };
        let text = reason.to_string();
        let logout = self.factory.logout(Some(&text));
        let _ = self.send_now(framed, logout).await;
        teardown(phase);
        closed(reason)
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
    fn note_garbled(&mut self, skipped: u64, cause: &'static str) -> Option<CloseReason> {
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
                Some(CloseReason::GarbledFrameLimit {
                    max: limit.max().get(),
                    window: limit.window(),
                })
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
    /// reason is [`CloseReason::MessageTooLarge`] or
    /// [`CloseReason::TransportError`].
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
            let _ = self.send_now(framed, logout).await;
        }
        tracing::warn!(session = %self.session_id, error = %error, "fatal codec error");
        teardown(phase);
        closed(codec_failure_reason(&error))
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
        reason: CloseReason,
    ) -> SessionClosed {
        tracing::warn!(session = %self.session_id, reason = %reason, "closing the session");
        if matches!(phase, Phase::Active(_)) {
            let text = reason.to_string();
            let logout = self.factory.logout(Some(&text));
            let _ = self.send_now(framed, logout).await;
        }
        teardown(phase);
        closed(reason)
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

        let tag = mismatch.tag;
        let reason = RejectReason::new(9, detail.clone()).with_ref_tag(tag);
        let reject = self.factory.session_reject(ref_seq, ref_msg_type, &reason);
        let _ = self.send_now(framed, reject).await;
        let logout = self.factory.logout(Some(&detail));
        let _ = self.send_now(framed, logout).await;
        teardown(phase);
        closed(CloseReason::IdentityMismatch { tag })
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
        let _ = self.send_now(framed, reject).await;
        let logout = self.factory.logout(Some(&detail));
        let _ = self.send_now(framed, logout).await;
        teardown(phase);
        closed(CloseReason::SendingTime {})
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
                        // Duplicate delivery of an already-applied fill: it is
                        // ignored, as FIX requires, even when its NewSeqNo
                        // reaches past the expectation. Such a fill spans
                        // numbers this session still lacks, so they are
                        // re-requested from the expectation, once per expected
                        // number.
                        let spans = raw
                            .get_field_str(36)
                            .and_then(|value| value.parse::<u64>().ok())
                            .filter(|new_seq| *new_seq > expected);
                        if let Some(new_seq) = spans
                            && self.spanning_rerequested != Some(expected)
                        {
                            return self
                                .rerequest_spanned_gap(framed, phase, expected, new_seq)
                                .await;
                        }
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
    ///
    /// A valid request is queued ([`Reactor::queue_resend`]) and answered by
    /// resend steps of the reactor loop, which feed the write buffer while
    /// inbound is still read, so two sides answering large requests at once
    /// keep draining each other.
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

        self.queue_resend(begin_seq, new_seq);
        Ok(phase)
    }

    /// Whether a resend is queued or under way: until it is done, live
    /// outbound application messages wait.
    #[must_use]
    fn resend_in_progress(&self) -> bool {
        !self.resends.is_empty()
    }

    /// Queues the resend of `begin_seq..new_seq` (`new_seq` exclusive): the
    /// stored application messages are replayed and everything else is
    /// gap-filled, so the counterparty's expectation lands exactly on
    /// `new_seq`.
    ///
    /// The answer to an inbound `ResendRequest` (2), and the resend a
    /// counterparty's `NextExpectedMsgSeqNum` (789) on the Logon exchange asks
    /// for. Resends are answered in the order they were queued, each fed to
    /// the write buffer by [`Reactor::resend_step`] a few frames at a time. An
    /// empty range queues nothing, and past [`MAX_QUEUED_RESENDS`] a request
    /// is merged into the last queued one.
    fn queue_resend(&mut self, begin_seq: u64, new_seq: u64) {
        if let Some(job) = ResendJob::new(begin_seq, new_seq, self.store.is_none()) {
            push_resend(&mut self.resends, job);
        }
    }

    /// Feeds the next frames of the resend at the head of the queue
    /// (replayed messages and gap fills) to the write buffer, until the
    /// buffer reaches [`WRITE_BUFFER_HIGH_WATER`], a store page has to be
    /// read, or the resend is complete; a complete resend is dropped.
    ///
    /// Nothing here waits for the socket: the frames are appended, and the
    /// reactor loop writes them out while it goes on reading, so a step costs
    /// the same whether the counterparty is reading or not. A page read ends
    /// the step, so the loop reads inbound and yields between pages.
    ///
    /// # Errors
    /// The session is closed when a frame cannot be fed (one above
    /// `max_message_size`), or when the store reports itself corrupted
    /// ([`StoreError::Corrupted`]): a store that finds its own records damaged
    /// cannot say which messages it still holds intact, so the rest of the
    /// range is not gap-filled. Every other read failure (a store that cannot
    /// be read, a read that overruns the store timeout, a frame that does not
    /// rebuild) degrades to a gap fill.
    async fn resend_step(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
    ) -> Result<Phase, SessionClosed> {
        self.reads_since_resend_step = 0;
        // The owed Logout's deadline is checked before every step, not only
        // on the tick: a step can feed the rest of a resend at once, and must
        // not do so past the deadline.
        let phase = self.cut_resend_for_owed_logout(framed, phase).await?;
        let Some(mut job) = self.resends.pop_front() else {
            return Ok(phase);
        };
        for _ in 0..MAX_FRAMES_PER_RESEND_STEP {
            match self.advance_resend(framed, &mut job).await {
                Ok(ResendProgress::Wrote)
                    if framed.write_buffer().len() < WRITE_BUFFER_HIGH_WATER => {}
                Ok(ResendProgress::Wrote | ResendProgress::ReadPage) => {
                    self.resends.push_front(job);
                    return Ok(phase);
                }
                Ok(ResendProgress::Done) if self.resends.is_empty() => {
                    return self.finish_resends(framed, phase).await;
                }
                Ok(ResendProgress::Done) => return Ok(phase),
                Err(err) => {
                    teardown(phase);
                    return Err(closed(send_failure_reason(&err)));
                }
            }
        }
        // MAX_FRAMES_PER_RESEND_STEP frames fed: the step ends here, below
        // the byte cap, and the resend goes on at the next one.
        self.resends.push_front(job);
        Ok(phase)
    }

    /// Runs once the last owed resend is done: writes, in order, the messages
    /// held back behind it, then replies to a Logout the counterparty sent
    /// meanwhile.
    ///
    /// A held-back `ResendRequest` is built now, from the gap as it stands, and
    /// skipped if the gap has closed meanwhile.
    ///
    /// # Errors
    /// The session is closed when a write fails, or ends with the Logout
    /// exchange.
    async fn finish_resends(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
    ) -> Result<Phase, SessionClosed> {
        while let Some(next) = self.deferred.pop_front() {
            let request = matches!(next, DeferredSend::ResendRequest);
            let (pending, receipt) = match next {
                DeferredSend::Message(pending, receipt) => (pending, receipt),
                DeferredSend::ResendRequest => match self.resend {
                    Some(state) => (self.factory.resend_request(state.expected, 0), None),
                    None => continue,
                },
            };
            match self.send_now_tracked(framed, pending, receipt).await {
                Err(EngineError::Store(err)) => {
                    return Err(self.close_on_store_failure(phase, &err));
                }
                Err(err) => {
                    teardown(phase);
                    return Err(closed(send_failure_reason(&err)));
                }
                Ok(Sent::Yes) if request => {
                    // The stall clock runs from when the request went out.
                    if let Some(state) = self.resend.as_mut() {
                        state.restart_clock();
                    }
                    self.drop_held_logon_for_a_request();
                }
                Ok(_) => {}
            }
        }
        if self.logout_owed.is_some() {
            return self.reply_owed_logout(framed, phase, false).await;
        }
        Ok(phase)
    }

    /// Replies at once to a Logout the counterparty sent while a resend was
    /// owed, dropping what is left of the resend, when the logout timeout has
    /// run out since it arrived; otherwise hands the phase back untouched.
    ///
    /// # Errors
    /// The session closes with the Logout exchange when the reply was due.
    async fn cut_resend_for_owed_logout(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
    ) -> Result<Phase, SessionClosed> {
        let due = self
            .logout_owed
            .as_ref()
            .is_some_and(|owed| owed.since.elapsed() >= self.config.logout_timeout);
        if !due {
            return Ok(phase);
        }
        tracing::warn!(
            session = %self.session_id,
            "the resend owed to a counterparty that logged out did not finish within the \
             logout timeout: replying to its Logout without the rest"
        );
        self.reply_owed_logout(framed, phase, true).await
    }

    /// Replies to the counterparty's Logout and closes the session.
    ///
    /// `abandoned` is set when the logout timeout ran out before the resend
    /// owed to it was done: what is left of it, and the messages held back
    /// behind it, are dropped first.
    ///
    /// A reply the store refused under the fail-closed policy was never
    /// written: the exchange is incomplete, so the close is not graceful and
    /// does not trigger `reset_on_logout`. Any other failure to reply keeps
    /// the close graceful, as the counterparty has already logged out.
    async fn reply_owed_logout(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        abandoned: bool,
    ) -> Result<Phase, SessionClosed> {
        if abandoned {
            self.resends.clear();
            let reason = self.reason_behind_resend();
            self.discard_deferred(&reason);
        }
        let text = self.logout_owed.take().and_then(|owed| owed.text);
        let logout = self.factory.logout(None);
        if let Err(EngineError::Store(err)) = self.send_now(framed, logout).await {
            return Err(self.close_on_store_failure(phase, &err));
        }
        teardown(phase);
        Err(closed(CloseReason::PeerLogout { text }))
    }

    /// Holds a `ResendRequest` back behind the resend under way, unless one is
    /// already held: it is built when it is written, from the gap as it
    /// stands then.
    fn defer_resend_request(&mut self) {
        if !self
            .deferred
            .iter()
            .any(|held| matches!(held, DeferredSend::ResendRequest))
        {
            self.deferred.push_back(DeferredSend::ResendRequest);
        }
    }

    /// The reason a message held behind a resend reports when the session
    /// ends: [`NotSentReason::LogoutPending`] once this session's own Logout
    /// has been fed (the message is behind it as well), otherwise
    /// [`NotSentReason::DiscardedBehindResend`].
    #[must_use]
    const fn reason_behind_resend(&self) -> NotSentReason {
        if self.logout_sent {
            NotSentReason::LogoutPending
        } else {
            NotSentReason::DiscardedBehindResend {}
        }
    }

    /// Drops the messages held back behind a resend, resolving any tracked
    /// one with `reason`.
    fn discard_deferred(&mut self, reason: &NotSentReason) {
        for held in self.deferred.drain(..) {
            if let DeferredSend::Message(_, receipt) = held {
                outcome::resolve(receipt, || SendOutcome::not_sent(reason.clone()));
            }
        }
    }

    /// Resolves every send the closing session will never frame, once the
    /// reactor loop has ended: the messages held back behind a resend, and
    /// the commands still in the outbound queue, which is closed first so
    /// nothing more joins it (a handle that tries gets
    /// [`EngineError::Closed`], or [`NotSentReason::SessionClosed`] from
    /// `send_tracked`).
    ///
    /// `behind_resend` says the queued messages were waiting behind a resend:
    /// the pass that closed the session started with a resend under way
    /// (while one is, the outbound queue is not read at all), or a resend was
    /// queued during that pass. Tracked ones then resolve
    /// [`NotSentReason::DiscardedBehindResend`], or
    /// [`NotSentReason::LogoutPending`] if this session's own Logout had been
    /// fed, which they were behind as well; otherwise they resolve
    /// [`NotSentReason::Discarded`]. Untracked ones are counted in the same
    /// warning, since nothing else reports them. Frames already fed to the
    /// write buffer are not here: they are resolved by the close's last flush.
    fn discard_unsent(&mut self, commands: &mut mpsc::Receiver<Command>, behind_resend: bool) {
        // Taken from the queue before anything still in it, so resolved
        // first.
        self.discard_throttled();
        let held = self.reason_behind_resend();
        self.discard_deferred(&held);
        let reason = if behind_resend {
            held
        } else {
            NotSentReason::Discarded {}
        };
        commands.close();
        let discarded = std::iter::from_fn(|| commands.try_recv().ok())
            .filter_map(|command| match command {
                Command::Send { receipt, .. } => Some(receipt),
                Command::Logout(_) => None,
            })
            .map(|receipt| outcome::resolve(receipt, || SendOutcome::not_sent(reason.clone())))
            .count();
        if discarded > 0 {
            tracing::warn!(
                session = %self.session_id,
                discarded,
                behind_resend,
                "outbound application message(s) still queued when the session closed were \
                 discarded: none was framed and no sequence number was spent on them"
            );
        }
    }

    /// Feeds at most one frame of `job` to the write buffer, or reads one
    /// page of it from the store.
    ///
    /// `reply_cursor` is the next number the reply still owes the peer; it
    /// advances only past what has been fed, so holes, administrative
    /// messages and unrebuildable frames are covered by the gap fill fed
    /// before the next replayed message, or by the trailing one.
    async fn advance_resend(
        &mut self,
        framed: &mut FixFramed,
        job: &mut ResendJob,
    ) -> Result<ResendProgress, EngineError> {
        loop {
            // A replayed message whose gap fill was fed on the previous call.
            if let Some((seq, frame)) = job.pending.take() {
                self.send_replay(framed, &frame)?;
                job.reply_cursor = seq.checked_add(1).unwrap_or(job.new_seq);
                return Ok(ResendProgress::Wrote);
            }
            if let Some(message) = job.page.next() {
                let seq = message.seq_num();
                // A store handing back something outside the asked-for range
                // must not be allowed to move the reply.
                if seq < job.reply_cursor || seq > job.end_seq {
                    continue;
                }
                // Administrative messages are gap-filled, not replayed
                // (`doc/fix_operations.md`, "Resend Request", item 3):
                // resending a stale Heartbeat or Logon says nothing true about
                // the session now.
                if message.msg_type().is_admin() {
                    continue;
                }
                // Replayed in the precision the session stamps everything
                // else in: whole seconds on FIX 4.0 and FIX 4.1.
                let precision = self.factory.sending_time_precision();
                let frame = match wire::resend_frame(message.payload(), precision) {
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
                // Everything between the cursor and this message (holes,
                // admin messages, frames that would not rebuild) is one fill,
                // fed first; the message follows on the next call.
                if seq > job.reply_cursor {
                    self.send_gap_fill(framed, job.reply_cursor, seq).await?;
                    job.reply_cursor = seq;
                    job.pending = Some((seq, frame));
                    return Ok(ResendProgress::Wrote);
                }
                self.send_replay(framed, &frame)?;
                // `seq <= end_seq < new_seq <= u64::MAX`, so this cannot
                // overflow; it is checked rather than assumed because a
                // wrapped sequence number would corrupt the session it is
                // meant to repair.
                job.reply_cursor = seq.checked_add(1).unwrap_or(job.new_seq);
                return Ok(ResendProgress::Wrote);
            }
            // A page read is a step of its own: the loop reads inbound and
            // yields between pages, whatever the page held.
            if !job.store_done {
                self.read_resend_page(job).await?;
                return Ok(ResendProgress::ReadPage);
            }
            // Whatever the replay did not cover (a trailing run of admin
            // messages, holes, or the entire range when there is no store) is
            // gap-filled, so the counterparty's expectation always lands
            // exactly on `new_seq`.
            if job.reply_cursor < job.new_seq {
                self.send_gap_fill(framed, job.reply_cursor, job.new_seq)
                    .await?;
                job.reply_cursor = job.new_seq;
            }
            return Ok(ResendProgress::Done);
        }
    }

    /// Reads the next page of `job`'s range from the store into its page
    /// buffer, or marks the store done for it.
    ///
    /// The store is read in bounded pages of [`RESEND_PAGE_LIMIT`] rather than
    /// all at once: a `ResendRequest` with `EndSeqNo` (16) = 0 asks for the
    /// whole session, and materialising an arbitrarily long history in one
    /// read would allocate it all up front. A short page means the range is
    /// exhausted; a full one means there may be more, read from past its
    /// furthest key on a later call.
    ///
    /// # Errors
    /// [`EngineError::Store`] when the store reports itself corrupted. Every
    /// other failure marks the store done, so the rest of the range is
    /// gap-filled.
    async fn read_resend_page(&self, job: &mut ResendJob) -> Result<(), EngineError> {
        let Some(store) = self.store.as_deref() else {
            job.store_done = true;
            return Ok(());
        };
        if job.read_from > job.end_seq {
            job.store_done = true;
            return Ok(());
        }
        // One unit of cooperative budget per page: a store that answers at
        // once (MemoryStore) never makes the reactor yield by itself.
        tokio::task::consume_budget().await;
        // Bounded like every store call; a read that overruns degrades to a
        // gap fill like any other failed read.
        let read = store.get_page(job.read_from, job.end_seq, RESEND_PAGE_LIMIT);
        let page = match timed(self.store_timeout, read).await {
            Ok(page) => page,
            Err(err @ StoreError::Corrupted { .. }) => {
                tracing::error!(
                    session = %self.session_id,
                    read_from = job.read_from,
                    end_seq = job.end_seq,
                    error = %err,
                    "the store holding the resend range is corrupted: closing the session \
                     rather than gap-filling messages it may still hold"
                );
                return Err(EngineError::Store(err));
            }
            Err(err) => {
                tracing::warn!(
                    session = %self.session_id,
                    read_from = job.read_from,
                    end_seq = job.end_seq,
                    error = %err,
                    "cannot read the resend range from the store: gap-filling the rest"
                );
                job.store_done = true;
                return Ok(());
            }
        };
        // Ascending and bounded to `end_seq`: the last key is the furthest
        // this page reached, so the next page reads from just past it.
        match page.last().map(StoredMessage::seq_num) {
            None => job.store_done = true,
            Some(_) if page.len() < RESEND_PAGE_LIMIT => job.store_done = true,
            Some(furthest) => match furthest.checked_add(1) {
                Some(next) if next <= job.end_seq => job.read_from = next,
                _ => job.store_done = true,
            },
        }
        job.page = page.into_iter();
        Ok(())
    }

    /// Handles what one read of the socket produced: a frame, a fatal codec
    /// error, or the end of the stream.
    ///
    /// The garbled frames the codec skipped on the way to a frame are
    /// accounted for first, so a limit reached by them closes the session
    /// before the frame behind them is acted on. The common case is one
    /// integer read and nothing else: no clock, no allocation. With recovery
    /// on, the only error that reaches here is fatal (an I/O failure or a
    /// frame above `max_message_size`), and `Framed` ends the stream after
    /// any decoder error, so there is nothing to resume either way.
    async fn on_inbound_event(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        inbound: Option<Result<BytesMut, CodecError>>,
    ) -> Result<Phase, SessionClosed> {
        match inbound {
            Some(Ok(frame)) => match framed.codec_mut().take_garbled_count() {
                0 => self.on_inbound(framed, phase, frame).await,
                skipped => {
                    let phase = self
                        .on_garbled(framed, phase, skipped, GARBLED_FRAMING)
                        .await?;
                    self.on_inbound(framed, phase, frame).await
                }
            },
            Some(Err(err)) => Err(self.close_on_fatal_codec_error(framed, phase, err).await),
            None => {
                teardown(phase);
                Err(closed(CloseReason::TransportClosed {}))
            }
        }
    }

    /// Handles one inbound frame ([`Reactor::on_frame`]), then consumes a held
    /// Logon whose turn it now is ([`Reactor::release_held_logon`]).
    async fn on_inbound(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        frame: BytesMut,
    ) -> Result<Phase, SessionClosed> {
        let phase = self.on_frame(framed, phase, frame).await?;
        self.release_held_logon(phase).await
    }

    /// Consumes a Logon or acknowledgement held by [`Reactor::open`] once the
    /// inbound expectation reaches its number, as a receiver that queued it
    /// would: the Logon was processed at the handshake, so only its number is
    /// left to take.
    ///
    /// - Expectation below the held number: the gap is still being filled;
    ///   nothing happens.
    /// - Expectation above it: a gap fill jumped past the Logon (a
    ///   counterparty that fills through its own Logon does); the hold is
    ///   dropped.
    /// - Expectation equal to it: `MsgSeqNum + 1` is persisted as the next
    ///   target number and only then is the expectation moved, the order every
    ///   inbound message takes (ADR-0005), and recovery progress is noted.
    ///
    /// A hold lasts only while nothing has been requested: once a real
    /// `ResendRequest` goes out (the fallback, or a retry), the hold is
    /// dropped and the request's answer fills the Logon's number
    /// ([`Reactor::drop_held_logon_for_a_request`]).
    ///
    /// Nothing is requested here, even when frames from beyond the held Logon
    /// arrived while it was held: a counterparty such as QuickFIX/C++ resends
    /// through its own Logon and the live frames it sent after it, so a
    /// request now would cross that resend. Recovery stays armed, implied, at
    /// the next number with a fresh clock, so a counterparty that does not
    /// cover those frames still gets one `ResendRequest` once the gap has made
    /// no progress for the retry timeout.
    ///
    /// # Errors
    /// The session is closed on an exhausted target counter, or a store write
    /// that fails under the fail-closed policy.
    async fn release_held_logon(&mut self, phase: Phase) -> Result<Phase, SessionClosed> {
        let Some(logon_seq) = self.held_logon else {
            return Ok(phase);
        };
        let next_target = self.runtime.sequences.next_target_seq().value();
        if next_target < logon_seq {
            return Ok(phase);
        }
        self.held_logon = None;
        if next_target > logon_seq {
            tracing::debug!(
                session = %self.session_id,
                held_logon = logon_seq,
                next_target,
                "the gap below the held Logon was filled past it"
            );
            return Ok(phase);
        }
        let Some(next) = logon_seq.checked_add(1) else {
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
        if let Err(err) = self.runtime.sequences.try_increment_target_seq() {
            return Err(exhausted(phase, err));
        }
        self.note_inbound_progress();
        tracing::debug!(
            session = %self.session_id,
            held_logon = logon_seq,
            "consumed the held Logon: the gap below it is filled"
        );
        Ok(phase)
    }

    /// The reactor's first acts, left by the Logon exchange: request a gap it
    /// found in the counterparty's Logon or acknowledgement, or, when both
    /// sides declared `NextExpectedMsgSeqNum` (789), hold that Logon instead;
    /// then resend the messages the counterparty's 789 said it missed.
    ///
    /// A held Logon sends nothing. The gap below it is one the counterparty
    /// resends on its own, because this session's 789 named it: requesting it
    /// as well would cross that resend, which 789 exists to avoid. The gap is
    /// armed as an implied recovery ([`ResendState::implied`]), so a gapped
    /// frame arriving meanwhile sends no request either, and a gap that makes
    /// no progress for [`SessionConfig::resend_timeout`] (no resend, or one
    /// that stalls partway) gets one real `ResendRequest`. The Logon's number
    /// is consumed by [`Reactor::release_held_logon`].
    ///
    /// The resend is the one a `ResendRequest` for exactly that range would
    /// get, queued here ([`Reactor::queue_resend`]) and written by resend
    /// steps of the reactor loop, alternating with inbound reads, ahead of any
    /// live application message. Its range was decided by the handshake against
    /// the counters of the Logon exchange and lies below this session's own
    /// Logon or acknowledgement, so it is within what this session has sent;
    /// it is checked again here, and a range that is empty or reaches past
    /// the next sender number is not sent.
    ///
    /// # Errors
    /// Whatever closes the session while requesting the gap or resending.
    async fn open(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        opening: Opening,
    ) -> Result<Phase, SessionClosed> {
        let mut phase = phase;
        if let Some((expected, high_water)) = opening.gap {
            phase = self
                .request_resend(framed, phase, expected, high_water)
                .await?;
        }
        if let Some((expected, logon_seq)) = opening.held_logon {
            tracing::info!(
                session = %self.session_id,
                expected,
                held_logon = logon_seq,
                "holding the gapped Logon: the counterparty resends the gap below it on its own \
                 (NextExpectedMsgSeqNum)"
            );
            self.resend = Some(ResendState::implied(expected, logon_seq, &self.config));
            self.held_logon = Some(logon_seq);
        }
        if let Some((begin_seq, new_seq)) = opening.replay {
            let next_sender = self.runtime.sequences.next_sender_seq().value();
            if begin_seq == 0 || begin_seq >= new_seq || new_seq > next_sender {
                tracing::warn!(
                    session = %self.session_id,
                    begin_seq,
                    new_seq,
                    next_sender,
                    "not resending a NextExpectedMsgSeqNum range outside what was sent"
                );
                return Ok(phase);
            }
            tracing::info!(
                session = %self.session_id,
                begin_seq,
                up_to_before = new_seq,
                "resending what the counterparty's NextExpectedMsgSeqNum (789) says it missed"
            );
            self.queue_resend(begin_seq, new_seq);
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
                    self.on_app_in_sequence(framed, phase, &raw, seq, &frame)
                        .await
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

    /// Acts on an application message that is next in sequence: checks its
    /// application version, then hands it to the dispatcher or rejects it.
    ///
    /// This is the one path an application message takes to `from_app`, so
    /// every check that decides whether the application may see it lives
    /// here. A path that releases application messages later (a queue of
    /// messages held across a gap, #71) must release each through this
    /// method, in order, rather than calling [`Reactor::deliver_app`]
    /// directly.
    ///
    /// On a FIXT.1.1 session, an `ApplVerID` (1128) that names a version the
    /// session does not accept ([`ApplVersionGuard::check_application`], a
    /// synchronous decision over the message alone) is answered with a
    /// session-level Reject, `SessionRejectReason` 18 and `RefTagID` 1128 (13
    /// for a 1128 repeated in the header, 14 for one outside it); see
    /// [`Reactor::reject_appl_version`]. A message
    /// without 1128 is in the counterparty's default application version,
    /// which the handshake checked, and passes.
    async fn on_app_in_sequence(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        raw: &RawMessage<'_>,
        seq: u64,
        frame: &Bytes,
    ) -> Result<Phase, SessionClosed> {
        if let Err(problem) = self.appl_version.check_application(raw) {
            return self
                .reject_appl_version(framed, phase, raw.msg_type().as_str(), seq, &problem)
                .await;
        }
        let phase = self.deliver_app(phase, seq, frame).await?;
        if let Err(err) = self.runtime.sequences.try_increment_target_seq() {
            return Err(exhausted(phase, err));
        }
        // In-order progress: reconcile recovery rather than clearing it on
        // the first message back.
        self.note_inbound_progress();
        Ok(phase)
    }

    /// Rejects an in-sequence application message whose application version
    /// the session does not accept.
    ///
    /// The message's number is consumed, as for any message answered with a
    /// session-level Reject: `MsgSeqNum + 1` is persisted as the next target
    /// number before the expectation moves, exactly as when the message is
    /// delivered, so the counterparty does not resend it and the stream goes
    /// on. The message never reaches `from_app`. The Reject is sent like any
    /// other session frame, and the session stays up: the version is a
    /// property of this message, not of the session, whose default the
    /// handshake already checked. When the rejected 1128 names a version
    /// (`2` to `9`), the Reject echoes it in `RefApplVerID` (1130).
    async fn reject_appl_version(
        &mut self,
        framed: &mut FixFramed,
        phase: Phase,
        ref_msg_type: &str,
        seq: u64,
        problem: &ApplVersionProblem,
    ) -> Result<Phase, SessionClosed> {
        tracing::warn!(
            session = %self.session_id,
            seq,
            msg_type = ref_msg_type,
            tag = problem.tag(),
            detail = %problem,
            "rejecting an application message: its application version is not accepted"
        );
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
        if let Err(err) = self.runtime.sequences.try_increment_target_seq() {
            return Err(exhausted(phase, err));
        }
        self.note_inbound_progress();
        // A 1128 that names a version the session refuses is echoed in
        // RefApplVerID (1130), so the counterparty sees which version the
        // Reject is about.
        let reason = problem.reject_reason();
        let reject = self.factory.session_reject_with_appl_ver(
            seq,
            ref_msg_type,
            &reason,
            problem.ref_appl_ver_id(),
        );
        self.send_reject(framed, phase, reject).await
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
                return Err(closed(CloseReason::ApplicationQueueFull {}));
            }
            Err(mpsc::error::TrySendError::Closed(())) => {
                teardown(phase);
                return Err(closed(CloseReason::DispatcherStopped {}));
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
        // The reactor is the only writer of this count, which is why the
        // record is a plain load and store rather than an atomic add.
        self.runtime.record_inbound_app_message();
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
                    return Err(closed(send_failure_reason(&err)));
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
                    Err(self.local_logout_complete(raw))
                }
                // The counterparty's Logout arrived while ours was still
                // being written (its last bytes accepted in this same poll,
                // or the two Logouts crossing): the exchange is complete. What
                // is left of ours is written out as the session closes, and a
                // close whose Logout never got out is not graceful.
                Phase::LogoutQueued(session) => {
                    // Typestate: Active -> LogoutPending -> Disconnected.
                    let _ = session.initiate_logout().on_logout_ack();
                    Err(self.local_logout_complete(raw))
                }
                Phase::Active(session) => {
                    let text = bounded_peer_text(raw.get_field_str(58));
                    self.logout_owed = Some(OwedLogout {
                        since: Instant::now(),
                        text,
                    });
                    // A resend this session owes is finished first: FIX gives
                    // the remote end the chance to fill any gap before it
                    // replies to a Logout. The reply waits, bounded by the
                    // logout timeout, and the session keeps resending and
                    // reading meanwhile.
                    if self.resend_in_progress() {
                        tracing::debug!(
                            session = %self.session_id,
                            "the counterparty logged out while a resend is owed: replying once it \
                             is done"
                        );
                        return Ok(Phase::Active(session));
                    }
                    self.reply_owed_logout(framed, Phase::Active(session), false)
                        .await
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
    /// Application-version check (`ApplVerID` 1128) for a FIXT.1.1 session;
    /// the same guard the handshake checked `DefaultApplVerID` (1137) with.
    pub(crate) appl_version: ApplVersionGuard,
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
    /// Messages the counterparty's `NextExpectedMsgSeqNum` (789) said it
    /// missed, as (first number, first number not resent). The reactor resends
    /// them once Active, right after requesting any `opening_gap`, through the
    /// same replay a `ResendRequest` (2) gets.
    pub(crate) opening_replay: Option<(u64, u64)>,
    /// A gapped Logon or acknowledgement held instead of requested, as (first
    /// missing number, the held Logon's `MsgSeqNum`). Set only when both
    /// sides declared `NextExpectedMsgSeqNum` (789); mutually exclusive with
    /// `opening_gap`.
    pub(crate) held_logon: Option<(u64, u64)>,
    /// The write timeout: bound on a handshake write, and on how long an
    /// established session's output may make no progress.
    pub(crate) write_timeout: Duration,
    /// Capacity of the outbound command queue.
    pub(crate) outbound_capacity: usize,
    /// Capacity of the inbound application queue.
    pub(crate) app_queue_capacity: usize,
    /// The outbound throttle, when the engine has one: the session gets its
    /// own budgets, full, from it.
    pub(crate) throttle: Option<ThrottleConfig>,
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
        appl_version,
        config,
        application,
        session_id,
        store,
        store_policy,
        store_timeout,
        persisted,
        reset_owed,
        opening_gap,
        opening_replay,
        held_logon,
        write_timeout,
        outbound_capacity,
        app_queue_capacity,
        throttle,
    } = params;

    let (command_tx, command_rx) = mpsc::channel(outbound_capacity);
    let (closed_tx, closed_rx) = watch::channel(false);
    let (app_tx, app_rx) = mpsc::channel(app_queue_capacity);
    let (reject_tx, reject_rx) = mpsc::channel(app_queue_capacity);
    let garbled = config.garbled_frame_limit.map(GarbledFrameWindow::new);
    let writer = Writer::new(config.max_message_size);
    // A budget whose tokens come faster than the release timer's resolution
    // keeps its rate only with a burst of a millisecond's worth of tokens.
    if let Some(config) = &throttle {
        for (budget, settings, needed) in config.timer_limited() {
            tracing::warn!(
                session = %session_id,
                budget = %budget,
                rate = settings.rate(),
                per_ms = u64::try_from(settings.per().as_millis()).unwrap_or(u64::MAX),
                burst = settings.burst(),
                needed,
                "throttle budget earns tokens faster than the 1 ms release timer: with this burst, \
                 at most `burst` held messages leave per millisecond, below its rate"
            );
        }
    }
    // The budgets start full as the session becomes Active.
    let throttle = throttle.map(|config| OutboundThrottle {
        state: Throttle::new(&config, driver_now()),
        untracked_refused: vec![0; config.budgets().len()],
        config,
        unknown_budget_logged: false,
    });

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
        appl_version,
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
        unwritten_test_request: None,
        held_logon: None,
        resends: VecDeque::new(),
        reads_since_resend_step: 0,
        deferred: VecDeque::new(),
        logout_owed: None,
        spanning_rerequested: None,
        logout_sent: false,
        logout_cause: None,
        receipts: VecDeque::new(),
        write_timeout,
        writer,
        app_tx,
        garbled,
        throttle,
    };

    let channels = ReactorChannels {
        commands: command_rx,
        app_rejects: reject_rx,
        closed: closed_tx,
        dispatcher,
        app_completed,
    };
    let opening = Opening {
        gap: opening_gap,
        replay: opening_replay,
        held_logon,
    };
    tokio::spawn(async move {
        let _guard = guard;
        run_reactor(framed, channels, reactor, session, opening).await;
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

    /// A session configuration allowing `limit` ResendRequests per gap.
    fn config_with_limit(limit: u32) -> SessionConfig {
        let (Ok(sender), Ok(target)) = (
            ironfix_core::types::CompId::new("CLIENT"),
            ironfix_core::types::CompId::new("VENUE"),
        ) else {
            unreachable!("CLIENT and VENUE are valid CompIDs")
        };
        SessionConfig::new(sender, target, "FIX.4.4").with_max_resend_requests(limit)
    }

    #[test]
    fn test_resend_state_implied_has_sent_nothing_yet() {
        let config = config_with_limit(1);
        let implied = ResendState::implied(3, 6, &config);
        assert_eq!(implied.attempts, 0, "nothing sent yet");
        assert_eq!(implied.expected, 3);
        assert_eq!(implied.high_water, 6);
        // Even a limit of one request leaves room for the real one.
        assert!(implied.can_retry());

        let first = ResendState::first(3, 6, &config);
        assert_eq!(first.attempts, 1);
        assert!(!first.can_retry());
    }

    #[test]
    fn test_resend_state_implied_allows_exactly_one_real_request_at_limit_one() {
        let config = config_with_limit(1);
        let mut state = ResendState::implied(3, 6, &config);
        state.record_retry();
        assert_eq!(state.attempts, 1);
        assert!(!state.can_retry(), "the one real request is spent");
    }

    #[test]
    fn test_resend_job_refuses_an_empty_range() {
        assert!(ResendJob::new(5, 5, false).is_none());
        assert!(ResendJob::new(6, 5, false).is_none());
        assert!(ResendJob::new(0, 5, false).is_none());
        let Some(job) = ResendJob::new(3, 6, true) else {
            panic!("3..6 is a range")
        };
        assert_eq!((job.reply_cursor, job.read_from), (3, 3));
        assert_eq!((job.end_seq, job.new_seq), (5, 6));
        assert!(job.store_done, "without a store the range is one gap fill");
    }

    #[test]
    fn test_push_resend_merges_past_the_cap_into_the_last_unstarted_job() {
        let mut queue = VecDeque::new();
        let cap = u64::try_from(MAX_QUEUED_RESENDS).unwrap_or(u64::MAX);
        // One single-number request per number, 2 onwards, past the cap.
        for seq in 2..2 + cap + 6 {
            let Some(job) = ResendJob::new(seq, seq + 1, false) else {
                panic!("a one-number range")
            };
            push_resend(&mut queue, job);
        }
        assert_eq!(queue.len(), MAX_QUEUED_RESENDS, "the queue stays bounded");
        let Some(head) = queue.front() else {
            panic!("the queue is not empty")
        };
        assert_eq!(
            (head.reply_cursor, head.new_seq),
            (2, 3),
            "the head is untouched"
        );
        let Some(last) = queue.back() else {
            panic!("the queue is not empty")
        };
        // The last queued request (cap + 1) absorbed the six that followed it.
        assert_eq!(last.reply_cursor, cap + 1);
        assert_eq!(
            last.new_seq,
            cap + 8,
            "every merged number is still answered"
        );
    }

    #[test]
    fn test_resend_job_widen_covers_both_ranges() {
        let (Some(mut job), Some(other)) =
            (ResendJob::new(10, 20, false), ResendJob::new(4, 30, false))
        else {
            panic!("both are ranges")
        };
        job.widen(&other);
        assert_eq!((job.reply_cursor, job.read_from), (4, 4));
        assert_eq!((job.end_seq, job.new_seq), (29, 30));
        let Some(inner) = ResendJob::new(12, 15, false) else {
            panic!("12..15 is a range")
        };
        job.widen(&inner);
        assert_eq!(
            (job.reply_cursor, job.new_seq),
            (4, 30),
            "a covered range changes nothing"
        );
    }

    /// A framed pipe as the reactor holds one, and the peer's raw end.
    fn framed_pipe(capacity: usize) -> (FixFramed, tokio::io::DuplexStream) {
        let (near, far) = tokio::io::duplex(capacity);
        (
            Framed::new(crate::stream::SessionStream::erased(near), FixCodec::new()),
            far,
        )
    }

    /// A well-formed FIX.4.4 Heartbeat frame.
    fn heartbeat_frame() -> Vec<u8> {
        let body = "35=0\x0149=VENUE\x0156=CLIENT\x0134=2\x0152=20261018-12:00:00.000\x01";
        let head = format!("8=FIX.4.4\x019={}\x01{body}", body.len());
        let checksum = ironfix_tagvalue::checksum::calculate_checksum(head.as_bytes());
        format!("{head}10={checksum:03}\x01").into_bytes()
    }

    #[test]
    fn test_writer_tick_with_nothing_waiting_is_fine() {
        let mut writer = Writer::new(1024);
        let now = Instant::now();
        assert_eq!(writer.on_tick(now, Duration::ZERO), WriteCheck::Fine);
        assert!(writer.stalled_since.is_none(), "no clock runs while idle");
    }

    #[test]
    fn test_writer_tick_stalls_only_after_the_timeout_without_progress() {
        let timeout = Duration::from_millis(300);
        let mut writer = Writer::new(1024);
        writer.pending = true;
        let start = Instant::now();
        assert_eq!(
            writer.on_tick(start, timeout),
            WriteCheck::Fine,
            "clock starts"
        );
        let Some(early) = start.checked_add(Duration::from_millis(200)) else {
            panic!("the clock has room")
        };
        assert_eq!(writer.on_tick(early, timeout), WriteCheck::Fine);
        let Some(late) = start.checked_add(timeout) else {
            panic!("the clock has room")
        };
        assert_eq!(writer.on_tick(late, timeout), WriteCheck::Stalled);
    }

    #[test]
    fn test_writer_progress_restarts_the_write_timeout() {
        let timeout = Duration::from_millis(300);
        let mut writer = Writer::new(1024);
        writer.pending = true;
        let start = Instant::now();
        assert_eq!(writer.on_tick(start, timeout), WriteCheck::Fine);
        let Some(later) = start.checked_add(Duration::from_millis(250)) else {
            panic!("the clock has room")
        };
        writer.progressed = true;
        assert_eq!(writer.on_tick(later, timeout), WriteCheck::Progressed);
        assert!(!writer.progressed, "progress is taken by the tick");
        let Some(past_first) = start.checked_add(timeout) else {
            panic!("the clock has room")
        };
        assert_eq!(
            writer.on_tick(past_first, timeout),
            WriteCheck::Fine,
            "the timeout runs from the last progress, not from the first wait"
        );
    }

    #[tokio::test]
    async fn test_writer_flushed_clears_the_wait_and_reports_the_new_numbers() {
        let (mut framed, _far) = framed_pipe(64);
        let mut writer = Writer::new(1024);
        assert!(writer.feed(&mut framed, b"frame-7").is_ok());
        writer.fed_new(7);
        // A resent frame re-occupies an old number: not among the new ones.
        assert!(writer.feed(&mut framed, b"resend-3").is_ok());
        assert!(writer.feed(&mut framed, b"frame-8").is_ok());
        writer.fed_new(8);
        writer.stalled_since = Some(Instant::now());
        framed.write_buffer_mut().clear();
        assert_eq!(writer.flushed(&mut framed), Some((7, 8)));
        assert!(!writer.pending && writer.stalled_since.is_none());
        assert_eq!(writer.flushed(&mut framed), None, "nothing new since");
    }

    /// Y1: a peak of output does not stay allocated. The buffer is sized for
    /// one resend step when the reactor starts; a completed flush gives back
    /// a capacity above twice that, and keeps one at or below it.
    #[tokio::test]
    async fn test_writer_flushed_shrinks_a_grown_buffer_once_drained() {
        let (mut framed, _far) = framed_pipe(64);
        framed.write_buffer_mut().reserve(WRITE_BUFFER_HIGH_WATER);
        let mut writer = Writer::new(4 * 1024 * 1024);
        let burst = vec![b'x'; 3 * WRITE_BUFFER_HIGH_WATER];
        assert!(writer.feed(&mut framed, &burst).is_ok());
        assert!(
            framed.write_buffer().capacity() > SHRINK_ABOVE,
            "the buffer grew"
        );
        framed.write_buffer_mut().clear();
        let _ = writer.flushed(&mut framed);
        let capacity = framed.write_buffer().capacity();
        assert!(
            (WRITE_BUFFER_HIGH_WATER..=SHRINK_ABOVE).contains(&capacity),
            "shrunk back to the high water: {capacity}"
        );
        // At the working size nothing is replaced.
        assert!(writer.feed(&mut framed, b"small").is_ok());
        framed.write_buffer_mut().clear();
        let _ = writer.flushed(&mut framed);
        assert_eq!(framed.write_buffer().capacity(), capacity);
    }

    /// ORANGE-02: the read ceiling is the frame that crossed the high water
    /// plus a fixed allowance, not the largest message the session allows.
    #[tokio::test]
    async fn test_writer_read_ceiling_follows_the_frame_that_crossed_the_high_water() {
        let (mut framed, _far) = framed_pipe(64);
        let mut writer = Writer::new(64 * 1024 * 1024);
        assert!(!writer.reads_paused(WRITE_BUFFER_HIGH_WATER - 1));
        let below = vec![b'x'; WRITE_BUFFER_HIGH_WATER - 100];
        assert!(writer.feed(&mut framed, &below).is_ok());
        let crossing = vec![b'y'; 1_000];
        assert!(writer.feed(&mut framed, &crossing).is_ok());
        let crossed = framed.write_buffer().len();
        assert_eq!(writer.crossed_at, Some(crossed));
        assert!(!writer.reads_paused(crossed + REPLY_ALLOWANCE));
        assert!(
            writer.reads_paused(crossed + REPLY_ALLOWANCE + 1),
            "replies past the allowance pause reading"
        );
        // A session allowing 64 MiB messages still pauses near 128 KiB, not
        // near 64 MiB.
        assert!(writer.reads_paused(WRITE_BUFFER_HIGH_WATER + 2 * REPLY_ALLOWANCE));
        framed.write_buffer_mut().clear();
        let _ = writer.flushed(&mut framed);
        assert_eq!(writer.crossed_at, None, "a drained buffer starts over");
    }

    /// P2-01: a Logout counts as written only once the stream has accepted
    /// every byte up to its end.
    #[tokio::test]
    async fn test_writer_marks_a_logout_written_only_when_its_last_byte_is() {
        let (mut framed, _far) = framed_pipe(64);
        let mut writer = Writer::new(1024);
        assert!(writer.feed(&mut framed, &[b'a'; 100]).is_ok());
        assert!(writer.feed(&mut framed, &[b'l'; 50]).is_ok());
        writer.mark_logout(&framed);
        assert!(writer.feed(&mut framed, &[b'z'; 30]).is_ok());
        assert!(writer.logout_unwritten());
        writer.wrote(100);
        assert!(writer.logout_unwritten(), "only what is ahead of it");
        writer.wrote(49);
        assert!(writer.logout_unwritten(), "one byte of it is left");
        writer.wrote(31);
        assert!(!writer.logout_unwritten());
        assert!(writer.logout.take_written());
    }

    #[test]
    fn test_writer_close_budget_is_what_is_left_of_the_timeout() {
        let timeout = Duration::from_millis(300);
        let mut writer = Writer::new(1024);
        let start = Instant::now();
        assert_eq!(
            writer.close_budget(start, timeout),
            timeout,
            "nothing waited yet"
        );
        writer.stalled_since = Some(start);
        let Some(later) = start.checked_add(Duration::from_millis(100)) else {
            panic!("the clock has room")
        };
        assert_eq!(
            writer.close_budget(later, timeout),
            Duration::from_millis(200)
        );
        let Some(past) = start.checked_add(Duration::from_secs(1)) else {
            panic!("the clock has room")
        };
        assert_eq!(writer.close_budget(past, timeout), Duration::ZERO);
    }

    #[tokio::test]
    async fn test_writer_feed_refuses_a_frame_above_max_message_size() {
        let (mut framed, _far) = framed_pipe(64);
        let mut writer = Writer::new(8);
        let refused = writer.feed(&mut framed, b"0123456789");
        assert!(
            matches!(refused, Err(CodecError::MessageTooLarge { .. })),
            "{refused:?}"
        );
        assert!(framed.write_buffer().is_empty(), "nothing appended");
        assert!(!writer.pending);
        assert!(writer.feed(&mut framed, b"01234567").is_ok());
        assert_eq!(framed.write_buffer().len(), 8, "appended, not written");
        assert!(writer.pending);
    }

    /// The flush waits on a pipe the peer is not reading, and the inbound
    /// frame the peer sent is read all the same: a write never stops the
    /// reading.
    #[tokio::test]
    async fn test_poll_socket_reads_while_the_flush_waits() {
        use tokio::io::AsyncWriteExt;
        let (mut framed, mut far) = framed_pipe(32);
        let mut writer = Writer::new(1024);
        let outbound = vec![b'x'; 256];
        assert!(writer.feed(&mut framed, &outbound).is_ok());
        let inbound = heartbeat_frame();
        // The peer writes a frame larger than the pipe and never reads.
        let peer = {
            let inbound = inbound.clone();
            tokio::spawn(async move {
                let written = far.write_all(&inbound).await;
                (written.is_ok(), far)
            })
        };
        let event = timeout(
            Duration::from_secs(5),
            std::future::poll_fn(|cx| poll_socket(&mut framed, &mut writer, true, cx)),
        )
        .await;
        let Ok(SocketEvent::Inbound(Some(Ok(frame)))) = event else {
            panic!("the inbound frame is read while the flush waits: {event:?}")
        };
        assert_eq!(frame.as_ref(), inbound.as_slice());
        assert!(writer.pending, "the flush is still waiting");
        assert!(writer.progressed, "the pipe took what it holds");
        assert_eq!(
            framed.write_buffer().len(),
            outbound.len() - 32,
            "the rest waits in the write buffer"
        );
        let Ok((written, _far)) = peer.await else {
            panic!("the peer task joins")
        };
        assert!(written, "the peer's whole frame was taken");
    }

    #[test]
    fn test_resend_state_progress_keeps_an_implied_gap_implied() {
        let config = config_with_limit(1);
        let mut implied = ResendState::implied(3, 6, &config);
        implied.record_progress(4);
        assert_eq!(implied.expected, 4);
        assert_eq!(
            implied.attempts, 0,
            "a stall after partial progress still gets its one real request"
        );

        let mut real = ResendState::first(3, 6, &config);
        real.record_retry();
        real.record_progress(4);
        assert_eq!(real.attempts, 1, "progress resets a real request's budget");
    }
}
