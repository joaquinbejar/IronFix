/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Counts the heap allocations and the heap retained by the reactor's write
//! path in steady state (issue #126).
//!
//! `dhat` is installed as this binary's global allocator and counts every
//! heap block, on every thread. A real `Initiator` runs over a
//! `tokio::io::duplex` pipe of [`PIPE_BYTES`] per direction, less than what a
//! window writes, against a scripted acceptor that, once the Logon is
//! acknowledged, counts the frames it receives without allocating (and only
//! while its gate is open), and writes the frames it is given. The
//! initiator's stream counts its writes, and the writes the stream refused
//! for want of room, so each window can show that it went through the write
//! buffer and its flush waiting on the stream, not past them. Each window
//! follows a warm-up that grows the buffers and queues to their working size:
//!
//! - **Live sends**, with no store: [`MESSAGES`] application messages, built
//!   before the window, through `Connection::send`, the command queue,
//!   `to_app`, the frame factory and the write buffer. One block per message:
//!   the boxed future of the `async_trait` `to_app` call, which the
//!   `Application` trait shape costs every message.
//! - **Live sends with a `MemoryStore`**: the same, each frame filed before
//!   it is fed. [`STORED_LIVE_BLOCKS`] blocks per message (see there), plus
//!   the store's B-tree nodes.
//! - **Throttled live sends** (issue #82): the same as the live sends, with
//!   an outbound throttle of [`THROTTLE_RATE`] messages per second and a
//!   burst of [`THROTTLE_BURST`]. The orders are queued at once, so they wait
//!   in the throttle's queue and leave one per token, released by its timer.
//!   One block per message, as without the throttle: the queue keeps the
//!   capacity the warm-up gave it and the release timer is reset, not
//!   rebuilt. The window also checks it was throttled: it cannot take less
//!   than the time the throttle needs to earn the window's tokens, a lower
//!   bound the throttle guarantees whatever the machine.
//! - **Observed live sends** (issue #70): the same as the live sends, with a
//!   frame observer attached that only counts what it sees. One block per
//!   message, as without it: the observer gets borrowed slices, and the
//!   queue of frames awaiting their write result keeps the capacity it was
//!   given.
//! - **Pooled live sends** (issue #76): the same as the live sends, but each
//!   order is built inside the window, on a message taken from
//!   `Connection::acquire` and filled with the copying push methods; the
//!   session hands it back to the pool once it is framed. One block per
//!   message, the `to_app` future, exactly as for orders built before the
//!   window: the message itself allocates nothing. For the record, the same
//!   orders built inside the window with `OutboundMessage::new` cost
//!   [`UNPOOLED_BLOCKS`] blocks each (that window is measured too).
//! - **Pooled live sends through a ready gate**: the same, for an
//!   application whose `to_app_checked` decides at once with
//!   `SendVerdict::ready` and calls no `to_app`. No block per message from
//!   the message, the gate or the frame; what is left is the command queue:
//!   `tokio::sync::mpsc` grows its slot list by one block about every
//!   [`QUEUE_SENDS_PER_BLOCK`] sends, so the send path is not yet zero
//!   allocation. The window asserts that rate, with a fixed allowance of
//!   [`GATED_FIXED`] blocks, not the general [`SLACK`] that would hide it.
//! - **Pooled throttled and observed live sends**: the pooled live sends
//!   with the throttle, then with the frame observer, of the windows above.
//!   One block per message each. The throttle holds the whole window at
//!   once, so that session's outbound queue, which sizes its pool, has room
//!   for it: a pool smaller than the messages in flight builds the missing
//!   ones fresh.
//!
//! Each pooled window first fills the pool by holding twice a window's
//! orders at once and dropping them unsent, then warms up with a window's
//! worth of sends.
//! - **Replies**: the acceptor sends [`MESSAGES`] TestRequests and the
//!   initiator answers each with a Heartbeat echoing its `TestReqID` (112).
//!   [`REPLY_BLOCKS`] blocks per reply: the `from_admin` and `to_admin`
//!   futures, and the Heartbeat's body and echoed value.
//! - **Resent frames**, from a `MemoryStore`: the acceptor asks for
//!   [`MESSAGES`] stored messages. [`REBUILD_BLOCKS`] blocks per frame: the
//!   store's first clone of the payload, the decoded view of it, and the
//!   rebuilt frame's encoder buffer and field list. The resend goes out in
//!   batches of up to 64 frames a step: the window asserts many frames per
//!   write.
//! - **A pile-up**: the acceptor stops reading and sends TestRequests
//!   faster than the initiator's answers can leave. The initiator stops
//!   reading once the answers waiting in its write buffer pass the read
//!   ceiling (the frame that crossed the 64 KiB high water plus a 64 KiB
//!   allowance), so the heap it holds stays near that, whatever
//!   `max_message_size` allows; once the acceptor reads again and the buffer
//!   drains, the flush gives the grown capacity back.
//!
//! # The allocation matrix (issue #81, deferred from #76)
//!
//! The full profile is one session with every ingredient together: a
//! `FileStore`, a frame observer, TLS, and session-level Rejects (35=3)
//! between accepted messages. In its window the initiator sends [`MESSAGES`]
//! orders while the acceptor sends [`MESSAGES`] ExecutionReports, of which
//! the application refuses the even-numbered half in `from_app`, each refusal
//! answered by a Reject. Control windows, each adding one ingredient, name
//! where every block comes from, and the report gives each component and the
//! profile in blocks per message and per frame (orders, Rejects and messages
//! received together). Measured with this test on macOS, debug and release
//! alike within a few blocks:
//!
//! | Component | Blocks |
//! |---|---|
//! | `to_app` future (`async_trait`), per order | 1 |
//! | `FileStore` filing, per order | 1 |
//! | inbound delivery: the `from_app` future (`async_trait`); the dispatcher's `mpsc` amortised | 1 |
//! | `FileStore`, per message received (the receive cursor) | 1 |
//! | Reject reply: the refusal's text, the `RefMsgType` copy, the Reject body's field list and four values, the `to_admin` future; the rejection `mpsc` amortised | 8 |
//! | `FileStore` filing, per Reject | 1 |
//! | `RawMessage` spill (11 fields, 32 held inline) | 0 |
//! | frame observer | 0 |
//! | rustls, both endpoints, per order | about 1.6 to 1.9 |
//! | rustls, both endpoints, per refused message and its Reject | about 2.1 |
//!
//! The profile without TLS (1024 sent, 1024 received, 512 rejected) costs
//! about 8750 blocks, 3.41 per frame, and the components predict it within
//! a few blocks; the test asserts that they agree within 4 x [`SLACK`]. With
//! TLS it costs about 11850, 4.6 per frame: the rustls share is about 3100
//! blocks, 1.2 per frame.
//!
//! What cannot be measured in a meaningful way: the engine's own half of
//! the rustls share. dhat counts every thread of the process, and the
//! counterparty's TLS endpoint runs in the same process, so every rustls
//! figure here is both endpoints together. A per-frame split would need the
//! counterparty out of process, where dhat cannot see it either. The test
//! therefore asserts only that the share is positive and no larger than the
//! TLS controls charge for the same traffic. The `FileStore` journals are
//! opened under `SyncPolicy::Never`: a flush is a system call that allocates
//! nothing here, and `EveryWrite` would only make the windows slower. The TLS
//! session is established through `Initiator::establish_with_peer`, the path
//! `Initiator::connect_tls` hands its stream to once it has dialled; the TLS
//! windows and the check of the full profile run only with the `tls` feature
//! (`make test` runs it).
//!
//! Each window may also allocate up to [`SLACK`] blocks that do not recur per
//! frame (a page `Vec` per 256 stored messages, a queue block, a request's
//! own callbacks). A write path that allocated once per frame would exceed it
//! many times over.
//!
//! Measured with this test (debug build, macOS) against the reactor of
//! 5f0c013, the base of #126, which wrote each frame with a blocking `send`:
//! the windows allocated 1032 (live), 5299 (live with a store), 4096
//! (replies) and 4131 (resend) blocks, against 1033, 5299 to 5306, 4096 and
//! 4131 here, so feeding the write buffer adds no allocation per frame. The
//! resend took 1061 writes there and 40 here. The pile-up held 427 bytes
//! there, where the blocked write stopped the reading; the first version of
//! #126 (a5517d2, whose read ceiling was 64 KiB plus `max_message_size`)
//! held 508 KB and kept it after the drain; here it holds about 192 KiB and
//! keeps none.
//!
//! It runs without the libtest harness (`harness = false` in `Cargo.toml`), so
//! no other test and no harness thread allocates while it measures. It
//! asserts counts and sizes, and no timing but the throttled window's lower
//! bound, and holds in debug and release builds.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::throttle::{ThrottleBudget, ThrottleConfig, ThrottlePolicy};
use ironfix_engine::{
    Application, Connection, FrameObserver, Initiator, NoOpApplication, Observation,
    OutboundMessage, OutboundResult, RejectReason, SendVerdict, SessionId,
};
use ironfix_session::SessionConfig;
use ironfix_store::{FileStore, FileStoreConfig, MemoryStore, MessageStore, SyncPolicy};
use ironfix_tagvalue::Encoder;
use ironfix_transport::FixCodec;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, WriteHalf,
};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::codec::Framed;

#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;

/// Messages in each measured window.
const MESSAGES: u64 = 1_024;

/// Messages sent, or resent, before each window.
const WARM_UP: u64 = 512;

/// TestRequests the acceptor sends in the pile-up.
const PILE_UP: u64 = 4_096;

/// Blocks a live send costs with a `MemoryStore` attached: the `to_app`
/// future, the `file_outbound` future and the `store` and
/// `set_next_sender_seq` futures it awaits (the trait's default), and the
/// store's copy of the frame.
const STORED_LIVE_BLOCKS: u64 = 5;

/// Most heap the pile-up may add while the answers wait, in bytes: the write
/// buffer's capacity, sized for 64 KiB when the reactor starts, doubles at
/// most twice on the way to its read ceiling (about 128 KiB of output).
const PILE_UP_HELD: i128 = 256 * 1024;

/// Most heap that may stay allocated once the pile-up has drained, in bytes:
/// the flush gives the grown capacity back.
const RETAINED_AFTER_DRAIN: i128 = 16 * 1024;

/// Blocks a live send costs when the order is built inside the window with
/// `OutboundMessage::new`: the field list, the four values and the `to_app`
/// future.
const UNPOOLED_BLOCKS: u64 = 6;

/// Sends per block the command queue (`tokio::sync::mpsc`) allocates as it
/// grows its slot list: measured, about one block every 128 sends.
const QUEUE_SENDS_PER_BLOCK: u64 = 128;

/// Non-recurring blocks the ready-gate window may allocate beyond the command
/// queue's rate.
const GATED_FIXED: u64 = 4;

/// Blocks answering a TestRequest costs.
const REPLY_BLOCKS: u64 = 4;

/// Blocks rebuilding one stored frame as a resend costs.
const REBUILD_BLOCKS: u64 = 4;

/// Blocks the reactor's answer to one `from_app` refusal costs: the
/// refusal's text (the application's `RejectReason`), the copy of
/// `RefMsgType` (372) the reactor takes, the Reject body's field list and
/// its four values (45, 372, 373, 58), and the `to_admin` future.
const REJECT_REPLY_BLOCKS: i128 = 8;

/// Blocks a window may allocate beyond its per-frame cost: allocations that
/// do not recur per frame.
const SLACK: u64 = MESSAGES / 16;

/// Bytes each direction of the pipe holds: far less than a window's output,
/// so the flush waits on the stream and output waits in the write buffer.
const PIPE_BYTES: usize = 4 * 1024;

/// Messages per second the throttled window's budget earns: fast enough to
/// keep the window short, slow enough that the orders, queued at once, wait
/// in the throttle's queue.
const THROTTLE_RATE: u32 = 4_096;

/// The throttled window's burst, in messages.
const THROTTLE_BURST: u32 = 8;

/// The throttled window's queue depth: room for every order of the window
/// and its warm-up, so none is refused.
const THROTTLE_DEPTH: usize = 4_096;

/// Fails the test with context instead of `.unwrap()` / `.expect()`.
#[track_caller]
fn ok<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{what}: {err:?}"),
    }
}

/// Fails the test with context instead of `.unwrap()` / `.expect()`.
#[track_caller]
fn some<T>(value: Option<T>, what: &str) -> T {
    match value {
        Some(value) => value,
        None => panic!("{what}"),
    }
}

/// Heap blocks allocated so far, on every thread.
fn blocks() -> u64 {
    dhat::HeapStats::get().total_blocks
}

/// Heap bytes live now, on every thread.
fn live_bytes() -> usize {
    dhat::HeapStats::get().curr_bytes
}

/// How many heap bytes are live now beyond `before`: negative when the heap
/// shrank.
fn grown_since(before: usize) -> i128 {
    let now = i128::try_from(live_bytes()).unwrap_or(i128::MAX);
    let before = i128::try_from(before).unwrap_or(i128::MAX);
    now - before
}

/// What the initiator's stream saw: writes, the bytes they carried, the
/// largest, and the writes it refused for want of room.
#[derive(Debug, Default)]
struct IoCounts {
    writes: AtomicU64,
    refused: AtomicU64,
    largest: AtomicUsize,
}

impl IoCounts {
    fn snapshot(&self) -> (u64, u64) {
        (
            self.writes.load(Ordering::Relaxed),
            self.refused.load(Ordering::Relaxed),
        )
    }
}

/// The initiator's end of the pipe, counting what the reactor writes.
struct CountingStream {
    inner: DuplexStream,
    counts: Arc<IoCounts>,
}

impl AsyncRead for CountingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for CountingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        match &polled {
            Poll::Ready(Ok(written)) => {
                self.counts.writes.fetch_add(1, Ordering::Relaxed);
                self.counts.largest.fetch_max(*written, Ordering::Relaxed);
            }
            Poll::Pending => {
                self.counts.refused.fetch_add(1, Ordering::Relaxed);
            }
            Poll::Ready(Err(_)) => {}
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A frame from `sender` to `target`: MsgType, the CompIDs, `MsgSeqNum`,
/// `SendingTime`, then `body`.
fn frame(sender: &str, target: &str, msg_type: &str, seq: u64, body: &[(u32, &str)]) -> BytesMut {
    let mut encoder = Encoder::new("FIX.4.4");
    encoder.put_str(35, msg_type);
    encoder.put_str(49, sender);
    encoder.put_str(56, target);
    encoder.put_uint(34, seq);
    encoder.put_str(52, Timestamp::now().format_millis().as_str());
    for (tag, value) in body {
        encoder.put_str(*tag, value);
    }
    let mut frame = BytesMut::new();
    ok(encoder.finish_into(&mut frame), "frame must encode");
    frame
}

/// Counts the frames on a byte stream without allocating, reading only while
/// `gate` is open: one per `<SOH>10=`, the start of every frame's CheckSum
/// (10), matched across reads.
async fn count_frames<R: AsyncRead + Unpin>(
    mut io: R,
    frames: Arc<AtomicU64>,
    mut gate: watch::Receiver<bool>,
) {
    const TRAILER: [u8; 4] = [0x01, b'1', b'0', b'='];
    let mut buf = [0_u8; 4 * 1024];
    let mut matched = 0_usize;
    loop {
        if gate.wait_for(|open| *open).await.is_err() {
            return;
        }
        let read = tokio::select! {
            read = io.read(&mut buf) => match read {
                Ok(0) | Err(_) => return,
                Ok(read) => read,
            },
            changed = gate.changed() => {
                if changed.is_err() {
                    return;
                }
                continue;
            }
        };
        for byte in buf.iter().take(read) {
            matched = if TRAILER.get(matched) == Some(byte) {
                matched + 1
            } else if *byte == 0x01 {
                1
            } else {
                0
            };
            if matched == TRAILER.len() {
                frames.fetch_add(1, Ordering::Relaxed);
                matched = 0;
            }
        }
    }
}

/// Yields until `frames` has counted `target` frames.
async fn wait_for_frames(frames: &AtomicU64, target: u64) {
    let waited = tokio::time::timeout(Duration::from_secs(60), async {
        while frames.load(Ordering::Relaxed) < target {
            tokio::task::yield_now().await;
        }
    })
    .await;
    ok(waited, "the acceptor receives every frame within 60s");
}

/// An application message the initiator sends, built before a window.
fn order(index: u64) -> OutboundMessage {
    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order
        .push_str(11, &format!("ORDER-{index:06}"))
        .push_str(55, "EUR/USD")
        .push_char(54, '1')
        .push_str(38, "100");
    order
}

/// Fills `message` as the order numbered `index`, with the copying push
/// methods only: on a warm pooled message this allocates nothing.
fn fill_order(mut message: OutboundMessage, index: u64) -> OutboundMessage {
    message
        .push_uint(11, index)
        .push_str(55, "EUR/USD")
        .push_char(54, '1')
        .push_str(38, "100");
    message
}

/// An application whose outbound gate decides at once and calls no
/// `to_app`: it boxes no future per message.
#[derive(Debug, Default)]
struct ReadyGate;

#[async_trait]
impl Application for ReadyGate {
    async fn on_create(&self, _: &SessionId) {}
    async fn on_logon(&self, _: &SessionId) {}
    async fn on_logout(&self, _: &SessionId) {}
    async fn to_admin(&self, _: &mut OutboundMessage, _: &SessionId) {}
    async fn from_admin(&self, _: &RawMessage<'_>, _: &SessionId) -> Result<(), RejectReason> {
        Ok(())
    }
    async fn to_app(&self, _: &mut OutboundMessage, _: &SessionId) {}
    async fn from_app(&self, _: &RawMessage<'_>, _: &SessionId) -> Result<(), RejectReason> {
        Ok(())
    }
    fn to_app_checked<'a>(
        &'a self,
        _message: &'a mut OutboundMessage,
        _session_id: &'a SessionId,
    ) -> SendVerdict<'a> {
        SendVerdict::ready(Ok(()))
    }
}

/// A `ResendRequest` from the acceptor, numbered `seq`, for `begin..=end`.
fn resend_request(seq: u64, begin: u64, end: u64) -> BytesMut {
    let (begin, end) = (begin.to_string(), end.to_string());
    frame(
        "VENUE",
        "CLIENT",
        "2",
        seq,
        &[(7, begin.as_str()), (16, end.as_str())],
    )
}

/// `count` TestRequests from the acceptor, numbered from `first`, in one
/// buffer.
fn test_requests(first: u64, count: u64) -> BytesMut {
    let mut wire = BytesMut::new();
    for seq in first..first + count {
        let id = format!("PING-{seq:06}");
        wire.extend_from_slice(&frame("VENUE", "CLIENT", "1", seq, &[(112, id.as_str())]));
    }
    wire
}

/// An initiator from CLIENT to VENUE in FIX.4.4, with `store` attached if
/// any.
fn initiator(store: Option<Arc<MemoryStore>>) -> Initiator<NoOpApplication> {
    initiator_with(store, NoOpApplication)
}

/// An initiator from CLIENT to VENUE in FIX.4.4 driving `application`, with
/// `store` attached if any.
fn initiator_with<A: Application + 'static>(
    store: Option<Arc<MemoryStore>>,
    application: A,
) -> Initiator<A> {
    let comp = |value: &str| ok(CompId::new(value), "CompId");
    let config = SessionConfig::new(comp("CLIENT"), comp("VENUE"), "FIX.4.4")
        .with_heartbeat_interval(Duration::from_secs(30));
    let initiator = Initiator::new(config, Arc::new(application));
    match store {
        Some(store) => initiator.with_store(store as Arc<dyn MessageStore>),
        None => initiator,
    }
}

/// A session logged on over a pipe, seen from the scripted acceptor.
struct Session<V = DuplexStream> {
    connection: Connection,
    /// Where the acceptor writes its frames.
    requests: WriteHalf<V>,
    /// Frames the acceptor has received since the acknowledgement.
    frames: Arc<AtomicU64>,
    /// Opens and closes the acceptor's reading.
    gate: watch::Sender<bool>,
    /// What the initiator's stream saw.
    counts: Arc<IoCounts>,
    counter: JoinHandle<()>,
}

/// Logs `initiator` on to a scripted acceptor that acknowledges with
/// `MsgSeqNum` 1 and then only counts frames.
async fn log_on<A: Application + 'static>(initiator: Initiator<A>) -> Session {
    let (client_io, venue_io) = tokio::io::duplex(PIPE_BYTES);
    let counts = Arc::new(IoCounts::default());
    let client_io = CountingStream {
        inner: client_io,
        counts: Arc::clone(&counts),
    };
    let venue = tokio::spawn(async move {
        let mut framed = Framed::new(venue_io, FixCodec::new());
        let logon = some(framed.next().await, "the Logon arrives");
        ok(logon, "the Logon decodes");
        let ack = frame("VENUE", "CLIENT", "A", 1, &[(98, "0"), (108, "30")]);
        ok(framed.send(ack).await, "the venue acknowledges");
        framed.into_inner()
    });
    let connection = ok(
        initiator.establish(client_io).await,
        "the initiator logs on",
    );
    let venue_io = ok(venue.await, "the venue task joins");
    let (read_half, requests) = tokio::io::split(venue_io);
    let frames = Arc::new(AtomicU64::new(0));
    let (gate, gate_rx) = watch::channel(true);
    let counter = tokio::spawn(count_frames(read_half, Arc::clone(&frames), gate_rx));
    Session {
        connection,
        requests,
        frames,
        gate,
        counts,
        counter,
    }
}

/// A frame observer that counts what it is given and allocates nothing.
#[derive(Debug, Default)]
struct CountingObserver {
    inbound: AtomicU64,
    outbound: AtomicU64,
    written: AtomicU64,
}

impl FrameObserver for CountingObserver {
    fn on_inbound(&self, _frame: &[u8], _observation: &Observation<'_>) {
        self.inbound.fetch_add(1, Ordering::Relaxed);
    }

    fn on_outbound(&self, _frame: &[u8], _observation: &Observation<'_>) {
        self.outbound.fetch_add(1, Ordering::Relaxed);
    }

    fn on_outbound_result(&self, result: &OutboundResult, _observation: &Observation<'_>) {
        if matches!(result, OutboundResult::Written) {
            self.written.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// What one window measured.
#[derive(Debug)]
struct Window {
    /// Heap blocks allocated.
    blocks: u64,
    /// Writes the stream took.
    writes: u64,
    /// Writes the stream refused for want of room.
    refused: u64,
}

/// The throttle of the throttled window: one budget of [`THROTTLE_RATE`]
/// messages per second, with a burst of [`THROTTLE_BURST`].
fn throttle() -> ThrottleConfig {
    let budget = ThrottleBudget::new(THROTTLE_RATE, Duration::from_secs(1))
        .with_burst(THROTTLE_BURST)
        .with_policy(ThrottlePolicy::Queue {
            max_depth: THROTTLE_DEPTH,
        });
    ok(
        ThrottleConfig::builder(budget).build(),
        "the throttle builds",
    )
}

/// Sends `MESSAGES` live orders on `session` after `WARM_UP` and measures
/// the window, and how long it took.
async fn measure_live<V>(
    session: &Session<V>,
    orders: &mut impl Iterator<Item = OutboundMessage>,
) -> (Window, std::time::Duration) {
    for message in orders.by_ref().take(usize::try_from(WARM_UP).unwrap_or(0)) {
        ok(session.connection.send(message).await, "a warm-up order");
    }
    wait_for_frames(&session.frames, WARM_UP).await;
    let (writes, refused) = session.counts.snapshot();
    let started = std::time::Instant::now();
    let before = blocks();
    for message in orders.by_ref().take(usize::try_from(MESSAGES).unwrap_or(0)) {
        ok(session.connection.send(message).await, "an order");
    }
    wait_for_frames(&session.frames, WARM_UP + MESSAGES).await;
    let blocks = blocks() - before;
    let elapsed = started.elapsed();
    let (writes_after, refused_after) = session.counts.snapshot();
    let window = Window {
        blocks,
        writes: writes_after - writes,
        refused: refused_after - refused,
    };
    (window, elapsed)
}

/// Sends `MESSAGES` orders on `session`, each built inside the window by
/// `build` from the connection and its index, after as many warm-up orders,
/// and measures the window and how long it took.
async fn measure_built(
    session: &Session,
    build: impl Fn(&Connection, u64) -> OutboundMessage,
) -> (Window, std::time::Duration) {
    // Fill the pool first: as many orders held at once as the window can
    // have in flight (all of it, when the throttle holds them), dropped
    // unsent. Then a warm-up as long as the window.
    let held: Vec<OutboundMessage> = (0..2 * MESSAGES)
        .map(|index| build(&session.connection, index))
        .collect();
    drop(held);
    for index in 0..MESSAGES {
        let message = build(&session.connection, index);
        ok(session.connection.send(message).await, "a warm-up order");
    }
    wait_for_frames(&session.frames, MESSAGES).await;
    let (writes, refused) = session.counts.snapshot();
    let started = std::time::Instant::now();
    let before = blocks();
    for index in MESSAGES..2 * MESSAGES {
        let message = build(&session.connection, index);
        ok(session.connection.send(message).await, "an order");
    }
    wait_for_frames(&session.frames, 2 * MESSAGES).await;
    let blocks = blocks() - before;
    let elapsed = started.elapsed();
    let (writes_after, refused_after) = session.counts.snapshot();
    let window = Window {
        blocks,
        writes: writes_after - writes,
        refused: refused_after - refused,
    };
    (window, elapsed)
}

/// An order on a message from the session's pool.
fn pooled(connection: &Connection, index: u64) -> OutboundMessage {
    fill_order(connection.acquire(MsgType::NewOrderSingle), index)
}

/// An order on a message built with `OutboundMessage::new`.
fn unpooled(_connection: &Connection, index: u64) -> OutboundMessage {
    fill_order(OutboundMessage::new(MsgType::NewOrderSingle), index)
}

/// The least time a throttled window takes, in nanoseconds: at most
/// `THROTTLE_BURST` tokens were waiting when it began, and every other order
/// waited for one, earned every 1 s / `THROTTLE_RATE`.
fn throttled_floor_nanos() -> u128 {
    let spacing = Duration::from_secs(1)
        .as_nanos()
        .div_ceil(u128::from(THROTTLE_RATE));
    spacing * u128::from(MESSAGES - u64::from(THROTTLE_BURST))
}

/// Reports each window's block count per message on stderr, for the record:
/// the binary runs without the libtest harness, so this is the measurement's
/// only output.
fn eprint_counts(windows: &[(&str, &Window)]) {
    use std::io::Write as _;
    let mut stderr = io::stderr().lock();
    for (name, window) in windows {
        let _ = writeln!(
            stderr,
            "allocations: {name}: {} blocks for {MESSAGES} messages",
            window.blocks
        );
    }
}

/// Which inbound application messages the [`Inbound`] application refuses
/// in `from_app`; the reactor answers each refusal with a session-level
/// Reject (35=3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refuse {
    /// None: every message is accepted, and nothing goes back.
    None,
    /// Every one.
    All,
    /// Those with an even `MsgSeqNum` (34): Rejects between accepted
    /// messages.
    EvenSeq,
}

/// An application that counts the inbound application messages it is given
/// and refuses those `refuse` names, allocating nothing of its own but the
/// refusal's text.
#[derive(Debug)]
struct Inbound {
    refuse: Refuse,
    seen: Arc<AtomicU64>,
}

impl Inbound {
    fn new(refuse: Refuse) -> (Self, Arc<AtomicU64>) {
        let seen = Arc::new(AtomicU64::new(0));
        (
            Self {
                refuse,
                seen: Arc::clone(&seen),
            },
            seen,
        )
    }
}

#[async_trait]
impl Application for Inbound {
    async fn on_create(&self, _: &SessionId) {}
    async fn on_logon(&self, _: &SessionId) {}
    async fn on_logout(&self, _: &SessionId) {}
    async fn to_admin(&self, _: &mut OutboundMessage, _: &SessionId) {}
    async fn from_admin(&self, _: &RawMessage<'_>, _: &SessionId) -> Result<(), RejectReason> {
        Ok(())
    }
    async fn to_app(&self, _: &mut OutboundMessage, _: &SessionId) {}
    async fn from_app(&self, message: &RawMessage<'_>, _: &SessionId) -> Result<(), RejectReason> {
        let refused = match self.refuse {
            Refuse::None => false,
            Refuse::All => true,
            Refuse::EvenSeq => message
                .get_field_str(34)
                .and_then(|seq| seq.parse::<u64>().ok())
                .is_some_and(|seq| seq % 2 == 0),
        };
        self.seen.fetch_add(1, Ordering::Relaxed);
        if refused {
            Err(RejectReason::new(99, "refused"))
        } else {
            Ok(())
        }
    }
}

/// `count` ExecutionReports from the acceptor, numbered from `first`, in one
/// buffer: 11 fields each, well under the 32 a `RawMessage` holds inline.
fn executions(first: u64, count: u64) -> BytesMut {
    let mut wire = BytesMut::new();
    for seq in first..first + count {
        let id = format!("EXEC-{seq:06}");
        wire.extend_from_slice(&frame(
            "VENUE",
            "CLIENT",
            "8",
            seq,
            &[(37, id.as_str()), (17, id.as_str()), (39, "0")],
        ));
    }
    wire
}

/// How many of the `count` messages numbered from `first` have an even
/// `MsgSeqNum`, and so are refused under [`Refuse::EvenSeq`].
fn even_in(first: u64, count: u64) -> u64 {
    u64::try_from((first..first + count).filter(|seq| seq % 2 == 0).count()).unwrap_or(u64::MAX)
}

/// A `FileStore` journal named `name` in `directory`, created empty.
///
/// Opened under `SyncPolicy::Never`: a flush is a system call and allocates
/// nothing in this process, so the policy changes how long a window takes,
/// not what it allocates, while `EveryWrite` would make each window last as
/// many flushes as it has messages.
async fn file_store(directory: &std::path::Path, name: &str) -> Arc<dyn MessageStore> {
    let config = ok(FileStoreConfig::try_new(directory, name), "store config")
        .with_create_if_missing(true)
        .with_sync_policy(SyncPolicy::Never);
    Arc::new(ok(FileStore::open(config).await, "the file store opens"))
}

/// Yields until `counter` reaches `target`.
async fn wait_for_count(counter: &AtomicU64, target: u64) {
    let waited = tokio::time::timeout(Duration::from_secs(60), async {
        while counter.load(Ordering::Relaxed) < target {
            tokio::task::yield_now().await;
        }
    })
    .await;
    ok(waited, "the application sees every message within 60s");
}

/// What a window of mixed traffic moved, beside its blocks.
#[derive(Debug, Clone, Copy)]
struct Traffic {
    /// Orders this session sent.
    sent: u64,
    /// Application messages it received.
    received: u64,
    /// Of those, the ones `from_app` refused, each answered by a Reject.
    rejected: u64,
}

impl Traffic {
    /// Every frame of the window, both ways: orders, Rejects, and the
    /// messages received.
    const fn frames(&self) -> u64 {
        self.sent + self.rejected + self.received
    }
}

/// Measures one window of mixed traffic on `session`, after a warm-up of the
/// same shape: `orders` live orders out while the acceptor sends the
/// executions of `inbound`, which the [`Inbound`] application counts in
/// `seen` and refuses per its policy. Waits until the acceptor has counted
/// every order and Reject and the application every execution.
async fn measure_traffic<V: AsyncWrite>(
    session: &mut Session<V>,
    seen: &AtomicU64,
    orders: &mut impl Iterator<Item = OutboundMessage>,
    warm_up: (&BytesMut, Traffic),
    window: (&BytesMut, Traffic),
) -> Window {
    let mut step = |wire: &BytesMut, traffic: Traffic| {
        let batch: Vec<OutboundMessage> = orders
            .by_ref()
            .take(usize::try_from(traffic.sent).unwrap_or(0))
            .collect();
        let wire = wire.clone();
        (batch, wire, traffic)
    };
    let warm = step(warm_up.0, warm_up.1);
    let measured = step(window.0, window.1);
    let mut out_total = 0_u64;
    let mut in_total = 0_u64;
    let mut result = None;
    for (index, (batch, wire, traffic)) in [warm, measured].into_iter().enumerate() {
        out_total += traffic.sent + traffic.rejected;
        in_total += traffic.received;
        let (writes, refused) = session.counts.snapshot();
        let before = blocks();
        let connection = &session.connection;
        let requests = &mut session.requests;
        let send = async {
            for message in batch {
                ok(connection.send(message).await, "an order");
            }
        };
        let inbound = async {
            if !wire.is_empty() {
                ok(requests.write_all(&wire).await, "executions");
                // A TLS writer keeps ciphertext the pipe has no room for
                // until flushed.
                ok(requests.flush().await, "flush");
            }
        };
        tokio::join!(send, inbound);
        wait_for_frames(&session.frames, out_total).await;
        wait_for_count(seen, in_total).await;
        if index == 1 {
            let (writes_after, refused_after) = session.counts.snapshot();
            result = Some(Window {
                blocks: blocks() - before,
                writes: writes_after - writes,
                refused: refused_after - refused,
            });
        }
    }
    some(result, "the window was measured")
}

/// TLS for the full-profile windows: a self-signed certificate generated at
/// run time, on the `ring` provider (a dev-dependency). No key is committed.
#[cfg(feature = "tls")]
mod tls_profile {
    use super::{CountingStream, IoCounts, Session, count_frames, frame, ok, some};
    use futures_util::{SinkExt, StreamExt};
    use ironfix_engine::tls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use ironfix_engine::tls::rustls::{self, ClientConfig, RootCertStore, ServerConfig};
    use ironfix_engine::{Application, Initiator, PeerInfo};
    use ironfix_transport::FixCodec;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use tokio::io::DuplexStream;
    use tokio::sync::watch;
    use tokio_rustls::server::TlsStream;
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    use tokio_util::codec::Framed;

    /// The venue's end of a TLS session.
    pub(super) type VenueStream = TlsStream<DuplexStream>;

    /// A client and a server configuration for one self-signed venue
    /// certificate.
    pub(super) fn configs() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
        let certified = ok(
            rcgen::generate_simple_self_signed(vec!["venue.test".to_string()]),
            "certificate",
        );
        let cert = certified.cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        ));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        ok(roots.add(cert.clone()), "root");
        let client = ok(
            ClientConfig::builder_with_provider(Arc::clone(&provider))
                .with_safe_default_protocol_versions(),
            "client versions",
        )
        .with_root_certificates(roots)
        .with_no_client_auth();
        let server = ok(
            ok(
                ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions(),
                "server versions",
            )
            .with_no_client_auth()
            .with_single_cert(vec![cert], key),
            "server certificate",
        );
        (Arc::new(client), Arc::new(server))
    }

    /// Logs `initiator` on over TLS on a pipe of `pipe_bytes` per direction,
    /// through `establish_with_peer` (the path `connect_tls` hands its TLS
    /// stream to once it has dialled), to a scripted acceptor that
    /// acknowledges and then only counts frames. The initiator's TLS runs
    /// over a counting stream, so the window still sees its writes.
    pub(super) async fn log_on<A: Application + 'static>(
        initiator: Initiator<A>,
        pipe_bytes: usize,
        client: Arc<ClientConfig>,
        server: Arc<ServerConfig>,
    ) -> Session<VenueStream> {
        let counts = Arc::new(IoCounts::default());
        let (client_io, venue_io) = tokio::io::duplex(pipe_bytes);
        let client_io = CountingStream {
            inner: client_io,
            counts: Arc::clone(&counts),
        };
        let venue = tokio::spawn(async move {
            let tls = ok(
                TlsAcceptor::from(server).accept(venue_io).await,
                "the venue's TLS handshake",
            );
            let mut framed = Framed::new(tls, FixCodec::new());
            let logon = some(framed.next().await, "the Logon arrives");
            ok(logon, "the Logon decodes");
            let ack = frame("VENUE", "CLIENT", "A", 1, &[(98, "0"), (108, "30")]);
            ok(framed.send(ack).await, "the venue acknowledges");
            framed.into_inner()
        });
        let name = ok(ServerName::try_from("venue.test"), "server name");
        let tls = ok(
            TlsConnector::from(client).connect(name, client_io).await,
            "the client's TLS handshake",
        );
        let peer = PeerInfo::new(
            tls.get_ref()
                .1
                .peer_certificates()
                .unwrap_or_default()
                .iter()
                .map(|cert| bytes::Bytes::copy_from_slice(cert.as_ref())),
        );
        let connection = ok(
            initiator.establish_with_peer(tls, peer).await,
            "the initiator logs on over TLS",
        );
        let venue_io = ok(venue.await, "the venue task joins");
        let (read_half, requests) = tokio::io::split(venue_io);
        let frames = Arc::new(AtomicU64::new(0));
        let (gate, gate_rx) = watch::channel(true);
        let counter = tokio::spawn(count_frames(read_half, Arc::clone(&frames), gate_rx));
        Session {
            connection,
            requests,
            frames,
            gate,
            counts,
            counter,
        }
    }
}

/// Every window of the allocation matrix (issue #81).
struct Matrix<'a> {
    /// Live sends, no store: the `to_app` future per order.
    live: &'a Window,
    /// Live sends with a `FileStore`.
    file_live: &'a Window,
    /// Inbound application messages, all accepted, no store.
    accepted: &'a Window,
    /// Inbound application messages, all refused, no store.
    rejected: &'a Window,
    /// The same two with a `FileStore`.
    file_accepted: &'a Window,
    file_rejected: &'a Window,
    /// The full profile without TLS: `FileStore`, frame observer, orders out
    /// and executions in, the even-numbered ones refused.
    plain: &'a Window,
    /// The traffic of the two profile windows.
    mixed: Traffic,
    /// With the `tls` feature: live sends over TLS, refused inbound over TLS
    /// (no store either), and the full profile over TLS.
    tls: Option<&'a (Window, Window, Window)>,
}

/// `blocks / count` with two decimals, in integer arithmetic.
fn per(blocks: i128, count: u64) -> String {
    let count = i128::from(count.max(1));
    let hundredths = blocks * 100 / count;
    let sign = if hundredths < 0 { "-" } else { "" };
    let hundredths = hundredths.abs();
    format!("{sign}{}.{:02}", hundredths / 100, hundredths % 100)
}

fn total(window: &Window) -> i128 {
    i128::from(window.blocks)
}

/// Names each allocation component from the differences between the control
/// windows, reports them and the full profile in blocks per message and per
/// frame, and checks that the components add up to the profile.
fn check_matrix(matrix: &Matrix<'_>) {
    use std::io::Write as _;
    let m = MESSAGES;
    let mixed = matrix.mixed;
    let to_app = total(matrix.live);
    let store_order = total(matrix.file_live) - to_app;
    let inbound = total(matrix.accepted);
    let store_inbound = total(matrix.file_accepted) - inbound;
    let reject = total(matrix.rejected) - inbound;
    let store_reject = total(matrix.file_rejected) - total(matrix.file_accepted) - reject;
    let rejected = i128::from(mixed.rejected);
    let full_m = i128::from(m);
    // What the plain profile should cost if the components add up: every
    // order filed, every message received filed, and every refused one
    // answered with a filed Reject. The frame observer adds nothing.
    let predicted = total(matrix.file_live)
        + total(matrix.file_accepted)
        + rejected * (total(matrix.file_rejected) - total(matrix.file_accepted)) / full_m;
    let plain = total(matrix.plain);

    let mut lines = vec![
        format!("allocation matrix, {m} messages per control window:"),
        format!(
            "  async_trait to_app future, per order:          {}",
            per(to_app, m)
        ),
        format!(
            "  FileStore filing, per order:                    {}",
            per(store_order, m)
        ),
        format!(
            "  inbound delivery (the async_trait from_app future; the dispatcher's mpsc \
             amortised), per message: {}",
            per(inbound, m)
        ),
        format!(
            "  FileStore, per message received:                {}",
            per(store_inbound, m)
        ),
        format!(
            "  Reject reply (the refusal's text, the RefMsgType copy, the Reject body's field \
             list and 4 values, the async_trait to_admin future; the rejection mpsc amortised), \
             per Reject: {}",
            per(reject, m)
        ),
        format!(
            "  FileStore filing, per Reject:                   {}",
            per(store_reject, m)
        ),
        "  RawMessage spill: none (11 fields, 32 inline)".to_string(),
        format!(
            "  plain profile (FileStore + observer + Rejects): sent {}, received {}, \
             rejected {}: {plain} blocks, predicted {predicted}, {} per frame",
            mixed.sent,
            mixed.received,
            mixed.rejected,
            per(plain, mixed.frames())
        ),
    ];
    if let Some((tls_live, tls_rejected, full)) = matrix.tls {
        let tls_order = total(tls_live) - to_app;
        let tls_reject = total(tls_rejected) - total(matrix.rejected);
        let full_total = total(full);
        let rustls = full_total - plain;
        lines.push(format!(
            "  rustls, both endpoints, per order (control):    {}",
            per(tls_order, m)
        ));
        lines.push(format!(
            "  rustls, both endpoints, per refused message and its Reject (control): {}",
            per(tls_reject, m)
        ));
        lines.push(format!(
            "  FULL PROFILE (TLS + FileStore + observer + Rejects): sent {}, received {}, \
             rejected {}: {full_total} blocks, {} per frame; rustls share (both endpoints) \
             {rustls} blocks, {} per frame",
            mixed.sent,
            mixed.received,
            mixed.rejected,
            per(full_total, mixed.frames()),
            per(rustls, mixed.frames())
        ));
        // Over TLS the profile pays what it pays without TLS, plus rustls:
        // more than nothing, and no more than the TLS controls charge for
        // the same traffic (every order, every message received, every
        // Reject).
        let slack = i128::from(SLACK);
        assert!(
            rustls > 0 && rustls <= tls_order + tls_reject + 2 * slack,
            "the full profile's rustls share ({rustls} blocks) is outside (0, {}]",
            tls_order + tls_reject + 2 * slack
        );
    }
    // Each component, at its documented rate. The store's are about one
    // block a call either way: a few B-tree-free pages and queue blocks per
    // window move them by less than the slack.
    let slack = i128::from(SLACK);
    for (name, measured, expected) in [
        ("the to_app future", to_app, 1),
        ("FileStore filing per order", store_order, 1),
        ("inbound delivery", inbound, 1),
        ("FileStore per message received", store_inbound, 1),
        ("the Reject reply", reject, REJECT_REPLY_BLOCKS),
        ("FileStore filing per Reject", store_reject, 1),
    ] {
        let expected = expected * full_m;
        assert!(
            (measured - expected).abs() <= slack,
            "{name}: {measured} blocks for {m} messages, expected {expected} within {slack}"
        );
    }
    let mut stderr = io::stderr().lock();
    for line in &lines {
        let _ = writeln!(stderr, "{line}");
    }
    drop(stderr);
    let tolerance = i128::from(4 * SLACK);
    assert!(
        (plain - predicted).abs() <= tolerance,
        "the plain profile allocated {plain} blocks, the components predict {predicted}: \
         they must agree within {tolerance}"
    );
}

fn main() {
    let runtime = ok(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build(),
        "runtime",
    );
    // The resending initiator's previous stream: its Logon (1) and the
    // orders the acceptor asks for again (2 onwards).
    let stored = WARM_UP + MESSAGES;
    let store = Arc::new(MemoryStore::new());
    runtime.block_on(async {
        let logon = frame("CLIENT", "VENUE", "A", 1, &[(98, "0"), (108, "30")]);
        ok(store.store(1, &MsgType::Logon, &logon).await, "seed Logon");
        for seq in 2..stored + 2 {
            let id = format!("STORED-{seq:06}");
            let body = [(11, id.as_str()), (55, "EUR/USD"), (54, "1"), (38, "100")];
            let message = frame("CLIENT", "VENUE", "D", seq, &body);
            ok(
                store.store(seq, &MsgType::NewOrderSingle, &message).await,
                "seed an order",
            );
        }
        ok(
            store.set_next_sender_seq(stored + 2).await,
            "sender counter",
        );
        ok(store.set_next_target_seq(1).await, "target counter");
    });
    let window_orders = || {
        (0..WARM_UP + MESSAGES)
            .map(order)
            .collect::<Vec<_>>()
            .into_iter()
    };
    let mut live = window_orders();
    let mut stored_live = window_orders();
    let mut throttled_live = window_orders();
    let warm_up_pings = test_requests(2, WARM_UP);
    let pings = test_requests(2 + WARM_UP, MESSAGES);
    let pile_up = test_requests(2 + WARM_UP + MESSAGES, PILE_UP);
    let sending = initiator(None);
    let storing = initiator(Some(Arc::new(MemoryStore::new())));
    let throttling = initiator(None).with_throttle(throttle());
    let mut observed_live = window_orders();
    let observer = Arc::new(CountingObserver::default());
    let observing =
        initiator(None).with_frame_observer(Arc::clone(&observer) as Arc<dyn FrameObserver>);
    let resending = initiator(Some(store));
    let pooling = initiator(None);
    let unpooling = initiator(None);
    let gating = initiator_with(None, ReadyGate);
    // The pool keeps as many idle messages as the outbound queue holds: room
    // for the whole window, which the throttle holds at once.
    let pooled_throttling = initiator(None)
        .with_throttle(throttle())
        .with_outbound_capacity(usize::try_from(2 * MESSAGES).unwrap_or(usize::MAX));
    let pooled_observer = Arc::new(CountingObserver::default());
    let pooled_observing =
        initiator(None).with_frame_observer(Arc::clone(&pooled_observer) as Arc<dyn FrameObserver>);

    // The allocation matrix (issue #81, deferred from #76): controls, then
    // the full profile. One FileStore journal per session, in a directory
    // of this process's own, removed at the end.
    let store_dir =
        std::env::temp_dir().join(format!("ironfix-allocations-{}", std::process::id()));
    let stores = runtime.block_on(async {
        let mut stores = Vec::new();
        for name in ["live", "accepted", "rejected", "plain", "full"] {
            stores.push(file_store(&store_dir, name).await);
        }
        stores
    });
    let [
        live_store,
        accepted_store,
        rejected_store,
        plain_store,
        full_store,
    ]: [Arc<dyn MessageStore>; 5] = match stores.try_into() {
        Ok(stores) => stores,
        Err(_) => panic!("five stores"),
    };
    let none = Traffic {
        sent: 0,
        received: 0,
        rejected: 0,
    };
    let orders_only = |sent| Traffic { sent, ..none };
    let inbound_only = |received, rejected| Traffic {
        received,
        rejected,
        ..none
    };
    let warm_up_executions = executions(2, WARM_UP);
    let window_executions = executions(2 + WARM_UP, MESSAGES);
    let empty = BytesMut::new();
    let mixed_warm_up = Traffic {
        sent: WARM_UP,
        received: WARM_UP,
        rejected: even_in(2, WARM_UP),
    };
    let mixed = Traffic {
        sent: MESSAGES,
        received: MESSAGES,
        rejected: even_in(2 + WARM_UP, MESSAGES),
    };
    // Each session of the matrix, with what it counts.
    let file_live = initiator(None).with_store(live_store);
    let (app, accepted_seen) = Inbound::new(Refuse::None);
    let accepting = initiator_with(None, app);
    let (app, rejected_seen) = Inbound::new(Refuse::All);
    let rejecting = initiator_with(None, app);
    let (app, file_accepted_seen) = Inbound::new(Refuse::None);
    let file_accepting = initiator_with(None, app).with_store(accepted_store);
    let (app, file_rejected_seen) = Inbound::new(Refuse::All);
    let file_rejecting = initiator_with(None, app).with_store(rejected_store);
    let plain_observer = Arc::new(CountingObserver::default());
    let (app, plain_seen) = Inbound::new(Refuse::EvenSeq);
    let plain = initiator_with(None, app)
        .with_store(plain_store)
        .with_frame_observer(Arc::clone(&plain_observer) as Arc<dyn FrameObserver>);
    let full_observer = Arc::new(CountingObserver::default());
    let (app, full_seen) = Inbound::new(Refuse::EvenSeq);
    let full = initiator_with(None, app)
        .with_store(full_store)
        .with_frame_observer(Arc::clone(&full_observer) as Arc<dyn FrameObserver>);
    #[cfg(feature = "tls")]
    let (tls_client, tls_server) = tls_profile::configs();
    #[cfg(feature = "tls")]
    let tls_live = initiator(None);
    #[cfg(feature = "tls")]
    let (app, tls_rejected_seen) = Inbound::new(Refuse::All);
    #[cfg(feature = "tls")]
    let tls_rejecting = initiator_with(None, app);
    #[cfg(not(feature = "tls"))]
    drop((full, Arc::clone(&full_seen)));
    let matrix_orders = || {
        (0..2 * (WARM_UP + MESSAGES))
            .map(order)
            .collect::<Vec<_>>()
            .into_iter()
    };
    let mut file_live_orders = matrix_orders();
    let mut plain_orders = matrix_orders();
    #[cfg(feature = "tls")]
    let mut tls_live_orders = matrix_orders();
    #[cfg(feature = "tls")]
    let mut full_orders = matrix_orders();
    let mut no_orders = std::iter::empty::<OutboundMessage>();

    let _profiler = dhat::Profiler::builder().testing().build();
    let measured = runtime.block_on(async move {
        // Live sends, with no store; then replies and the pile-up on the
        // same session.
        let mut session = log_on(sending).await;
        let (live_window, _) = measure_live(&session, &mut live).await;

        let base = session.frames.load(Ordering::Relaxed);
        ok(
            session.requests.write_all(&warm_up_pings).await,
            "warm-up pings",
        );
        wait_for_frames(&session.frames, base + WARM_UP).await;
        let (writes, refused) = session.counts.snapshot();
        let before = blocks();
        ok(session.requests.write_all(&pings).await, "pings");
        wait_for_frames(&session.frames, base + WARM_UP + MESSAGES).await;
        let reply_window = Window {
            blocks: blocks() - before,
            writes: session.counts.snapshot().0 - writes,
            refused: session.counts.snapshot().1 - refused,
        };

        // The pile-up: the acceptor stops reading and sends TestRequests
        // from another task, so the answers pile up in the initiator's write
        // buffer until it stops reading.
        let base = session.frames.load(Ordering::Relaxed);
        let resting = live_bytes();
        let _ = session.gate.send(false);
        let mut requests = session.requests;
        let flood = tokio::spawn(async move {
            let written = requests.write_all(&pile_up).await.is_ok();
            (written, requests)
        });
        tokio::time::sleep(Duration::from_millis(500)).await;
        let piled_up = grown_since(resting);
        let _ = session.gate.send(true);
        wait_for_frames(&session.frames, base + PILE_UP).await;
        let (written, requests) = ok(flood.await, "the flood joins");
        assert!(written, "every TestRequest of the pile-up was written");
        session.requests = requests;
        tokio::task::yield_now().await;
        let retained = grown_since(resting);
        session.counter.abort();
        drop(session);

        // Live sends with a store attached.
        let session = log_on(storing).await;
        let (stored_live_window, _) = measure_live(&session, &mut stored_live).await;
        session.counter.abort();
        drop(session);

        // Live sends held back by the outbound throttle.
        let session = log_on(throttling).await;
        let throttled_window = measure_live(&session, &mut throttled_live).await;
        session.counter.abort();
        drop(session);

        // Live sends with a frame observer attached.
        let session = log_on(observing).await;
        let (observed_window, _) = measure_live(&session, &mut observed_live).await;
        session.counter.abort();
        drop(session);

        // Orders built inside the window: on pooled messages, on fresh
        // ones, through a ready gate, through the throttle and observed.
        let session = log_on(pooling).await;
        let (pooled_window, _) = measure_built(&session, pooled).await;
        session.counter.abort();
        drop(session);
        let session = log_on(unpooling).await;
        let (unpooled_window, _) = measure_built(&session, unpooled).await;
        session.counter.abort();
        drop(session);
        let session = log_on(gating).await;
        let (gated_window, _) = measure_built(&session, pooled).await;
        session.counter.abort();
        drop(session);
        let session = log_on(pooled_throttling).await;
        let pooled_throttled = measure_built(&session, pooled).await;
        session.counter.abort();
        drop(session);
        let session = log_on(pooled_observing).await;
        let (pooled_observed, _) = measure_built(&session, pooled).await;
        session.counter.abort();
        drop(session);

        // Resent frames: the warm-up asks for the first WARM_UP stored
        // orders, the window for the next MESSAGES.
        let mut session = log_on(resending).await;
        let warm_up_request = resend_request(2, 2, WARM_UP + 1);
        let request = resend_request(3, WARM_UP + 2, WARM_UP + 1 + MESSAGES);
        ok(
            session.requests.write_all(&warm_up_request).await,
            "a warm-up request",
        );
        wait_for_frames(&session.frames, WARM_UP).await;
        let (writes, refused) = session.counts.snapshot();
        session.counts.largest.store(0, Ordering::Relaxed);
        let before = blocks();
        ok(session.requests.write_all(&request).await, "the request");
        wait_for_frames(&session.frames, WARM_UP + MESSAGES).await;
        let resend_window = Window {
            blocks: blocks() - before,
            writes: session.counts.snapshot().0 - writes,
            refused: session.counts.snapshot().1 - refused,
        };
        let largest = session.counts.largest.load(Ordering::Relaxed);
        session.counter.abort();
        drop(session);
        (
            live_window,
            reply_window,
            stored_live_window,
            throttled_window,
            observed_window,
            (
                pooled_window,
                unpooled_window,
                gated_window,
                pooled_throttled,
                pooled_observed,
            ),
            resend_window,
            largest,
            piled_up,
            retained,
        )
    });
    let (
        live,
        reply,
        stored_live,
        (throttled, throttled_for),
        observed,
        (pooled, unpooled, gated, (pooled_throttled, pooled_throttled_for), pooled_observed),
        resend,
        largest,
        piled_up,
        retained,
    ) = measured;

    // The allocation matrix (issue #81): the controls, then the full
    // profile with every ingredient together.
    let matrix = runtime.block_on(async move {
        let mut session = log_on(file_live).await;
        let file_live = measure_traffic(
            &mut session,
            &AtomicU64::new(0),
            &mut file_live_orders,
            (&empty, orders_only(WARM_UP)),
            (&empty, orders_only(MESSAGES)),
        )
        .await;
        session.counter.abort();
        drop(session);

        let mut inbound_windows = Vec::new();
        for (initiator, seen, rejects) in [
            (accepting, accepted_seen, false),
            (rejecting, rejected_seen, true),
            (file_accepting, file_accepted_seen, false),
            (file_rejecting, file_rejected_seen, true),
        ] {
            let warm = inbound_only(WARM_UP, if rejects { WARM_UP } else { 0 });
            let window = inbound_only(MESSAGES, if rejects { MESSAGES } else { 0 });
            let mut session = log_on(initiator).await;
            inbound_windows.push(
                measure_traffic(
                    &mut session,
                    &seen,
                    &mut no_orders,
                    (&warm_up_executions, warm),
                    (&window_executions, window),
                )
                .await,
            );
            session.counter.abort();
            drop(session);
        }

        let mut session = log_on(plain).await;
        let plain = measure_traffic(
            &mut session,
            &plain_seen,
            &mut plain_orders,
            (&warm_up_executions, mixed_warm_up),
            (&window_executions, mixed),
        )
        .await;
        session.counter.abort();
        drop(session);

        #[cfg(feature = "tls")]
        let tls = {
            let mut session = tls_profile::log_on(
                tls_live,
                PIPE_BYTES,
                Arc::clone(&tls_client),
                Arc::clone(&tls_server),
            )
            .await;
            let tls_live = measure_traffic(
                &mut session,
                &AtomicU64::new(0),
                &mut tls_live_orders,
                (&empty, orders_only(WARM_UP)),
                (&empty, orders_only(MESSAGES)),
            )
            .await;
            session.counter.abort();
            drop(session);

            let mut session = tls_profile::log_on(
                tls_rejecting,
                PIPE_BYTES,
                Arc::clone(&tls_client),
                Arc::clone(&tls_server),
            )
            .await;
            let tls_rejected = measure_traffic(
                &mut session,
                &tls_rejected_seen,
                &mut no_orders,
                (&warm_up_executions, inbound_only(WARM_UP, WARM_UP)),
                (&window_executions, inbound_only(MESSAGES, MESSAGES)),
            )
            .await;
            session.counter.abort();
            drop(session);

            let mut session = tls_profile::log_on(full, PIPE_BYTES, tls_client, tls_server).await;
            let full = measure_traffic(
                &mut session,
                &full_seen,
                &mut full_orders,
                (&warm_up_executions, mixed_warm_up),
                (&window_executions, mixed),
            )
            .await;
            session.counter.abort();
            drop(session);
            Some((tls_live, tls_rejected, full))
        };
        #[cfg(not(feature = "tls"))]
        let tls: Option<(Window, Window, Window)> = None;
        (file_live, inbound_windows, plain, tls)
    });
    let _ = std::fs::remove_dir_all(&store_dir);
    let (file_live, inbound_windows, plain, tls) = matrix;
    let [accepted, rejected, file_accepted, file_rejected]: [Window; 4] =
        match inbound_windows.try_into() {
            Ok(windows) => windows,
            Err(_) => panic!("four inbound windows"),
        };
    check_matrix(&Matrix {
        live: &live,
        file_live: &file_live,
        accepted: &accepted,
        rejected: &rejected,
        file_accepted: &file_accepted,
        file_rejected: &file_rejected,
        plain: &plain,
        mixed,
        tls: tls.as_ref(),
    });
    assert!(
        plain_observer.outbound.load(Ordering::Relaxed) > mixed.sent + mixed.rejected,
        "the observer of the plain profile saw every order and Reject"
    );
    #[cfg(feature = "tls")]
    assert!(
        full_observer.outbound.load(Ordering::Relaxed) > mixed.sent + mixed.rejected
            && full_observer.inbound.load(Ordering::Relaxed) > mixed.received,
        "the observer of the full profile saw every frame"
    );
    #[cfg(not(feature = "tls"))]
    let _ = &full_observer;

    // Each window went through the write buffer with the flush waiting on
    // the stream: the stream refused writes for want of room.
    for (name, window) in [
        ("live", &live),
        ("live with a store", &stored_live),
        ("replies", &reply),
        ("resend", &resend),
    ] {
        assert!(
            window.refused > 0,
            "the {name} window never waited on the stream: {window:?}"
        );
    }
    assert!(
        live.writes < MESSAGES && stored_live.writes < MESSAGES,
        "frames waited in the buffer and left together: {live:?} {stored_live:?}"
    );
    assert!(
        resend.writes <= MESSAGES / 8 && largest == PIPE_BYTES,
        "the resend went out in batches, at least one filling the pipe: {resend:?}, \
         largest write {largest}"
    );

    assert!(
        (MESSAGES..=MESSAGES + SLACK).contains(&live.blocks),
        "{MESSAGES} live sends allocated {} blocks; each must allocate one (the async_trait \
         future of to_app) and the window at most {SLACK} more",
        live.blocks
    );
    // The store's B-tree adds a node every few sequential inserts.
    let stored = STORED_LIVE_BLOCKS * MESSAGES;
    assert!(
        (stored..=stored + MESSAGES / 4 + SLACK).contains(&stored_live.blocks),
        "{MESSAGES} live sends with a store allocated {} blocks; each must allocate \
         {STORED_LIVE_BLOCKS}, plus the store's B-tree nodes",
        stored_live.blocks
    );
    assert!(
        (MESSAGES..=MESSAGES + SLACK).contains(&throttled.blocks),
        "{MESSAGES} throttled live sends allocated {} blocks; each must allocate one (the \
         async_trait future of to_app), as without the throttle, and the window at most {SLACK} \
         more",
        throttled.blocks
    );
    assert!(
        (MESSAGES..=MESSAGES + SLACK).contains(&observed.blocks),
        "{MESSAGES} observed live sends allocated {} blocks; each must allocate one (the \
         async_trait future of to_app), as without the observer, and the window at most {SLACK} \
         more",
        observed.blocks
    );
    eprint_counts(&[
        ("live", &live),
        ("pooled live", &pooled),
        ("unpooled built in the window", &unpooled),
        ("pooled through a ready gate", &gated),
        ("pooled throttled", &pooled_throttled),
        ("pooled observed", &pooled_observed),
    ]);
    for (name, window) in [
        ("pooled live sends", &pooled),
        ("pooled throttled live sends", &pooled_throttled),
        ("pooled observed live sends", &pooled_observed),
    ] {
        assert!(
            (MESSAGES..=MESSAGES + SLACK).contains(&window.blocks),
            "{MESSAGES} {name} allocated {} blocks; each must allocate one (the async_trait \
             future of to_app), the pooled message none, and the window at most {SLACK} more",
            window.blocks
        );
    }
    let gated_ceiling = MESSAGES / QUEUE_SENDS_PER_BLOCK + GATED_FIXED;
    assert!(
        gated.blocks <= gated_ceiling,
        "{MESSAGES} pooled live sends through a ready gate allocated {} blocks; only the \
         command queue may allocate, one block per {QUEUE_SENDS_PER_BLOCK} sends, plus at most \
         {GATED_FIXED}: at most {gated_ceiling}",
        gated.blocks
    );
    let unpooled_floor = UNPOOLED_BLOCKS * MESSAGES;
    assert!(
        (unpooled_floor..=unpooled_floor + SLACK).contains(&unpooled.blocks),
        "{MESSAGES} live sends built with OutboundMessage::new allocated {} blocks; each must \
         allocate {UNPOOLED_BLOCKS}",
        unpooled.blocks
    );
    assert!(
        pooled_throttled_for.as_nanos() >= throttled_floor_nanos(),
        "the pooled throttled window took {pooled_throttled_for:?}: the orders were not throttled"
    );
    assert!(
        pooled_observer.outbound.load(Ordering::Relaxed) > 2 * MESSAGES,
        "the observer saw every pooled order"
    );
    let outbound = observer.outbound.load(Ordering::Relaxed);
    assert!(
        outbound > WARM_UP + MESSAGES,
        "the observer saw the Logon and every order: {outbound}"
    );
    assert!(
        observer.inbound.load(Ordering::Relaxed) >= 1,
        "the observer saw the acknowledgement"
    );
    assert!(
        observer.written.load(Ordering::Relaxed) > WARM_UP + MESSAGES,
        "every order was reported written"
    );
    // At most THROTTLE_BURST tokens were waiting when the window began; every
    // other order waited for one, earned every 1 s / THROTTLE_RATE.
    let throttled_floor = throttled_floor_nanos();
    assert!(
        throttled_for.as_nanos() >= throttled_floor,
        "the throttled window took {throttled_for:?}, less than the {throttled_floor} ns its \
         tokens take: the orders were not throttled"
    );
    let replies = REPLY_BLOCKS * MESSAGES;
    assert!(
        (replies..=replies + SLACK).contains(&reply.blocks),
        "{MESSAGES} replies allocated {} blocks; each must allocate {REPLY_BLOCKS}",
        reply.blocks
    );
    let rebuilt = REBUILD_BLOCKS * MESSAGES;
    assert!(
        (rebuilt..=rebuilt + SLACK).contains(&resend.blocks),
        "a resend of {MESSAGES} frames allocated {} blocks; each frame must allocate the \
         {REBUILD_BLOCKS} blocks of its rebuild",
        resend.blocks
    );

    // The pile-up: the write buffer grows to its read ceiling at most (its
    // capacity doubling once past twice the high water), and gives the
    // growth back once drained.
    assert!(
        piled_up <= PILE_UP_HELD,
        "the answers piled up to {piled_up} bytes of heap; the read ceiling holds them under \
         {PILE_UP_HELD}"
    );
    assert!(
        retained <= RETAINED_AFTER_DRAIN,
        "{retained} bytes of heap stayed allocated after the write buffer drained"
    );
}
