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

use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::message::MsgType;
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::throttle::{ThrottleBudget, ThrottleConfig, ThrottlePolicy};
use ironfix_engine::{
    Connection, FrameObserver, Initiator, NoOpApplication, Observation, OutboundMessage,
    OutboundResult,
};
use ironfix_session::SessionConfig;
use ironfix_store::{MemoryStore, MessageStore};
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

/// Blocks answering a TestRequest costs.
const REPLY_BLOCKS: u64 = 4;

/// Blocks rebuilding one stored frame as a resend costs.
const REBUILD_BLOCKS: u64 = 4;

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
    let comp = |value: &str| ok(CompId::new(value), "CompId");
    let config = SessionConfig::new(comp("CLIENT"), comp("VENUE"), "FIX.4.4")
        .with_heartbeat_interval(Duration::from_secs(30));
    let initiator = Initiator::new(config, Arc::new(NoOpApplication));
    match store {
        Some(store) => initiator.with_store(store as Arc<dyn MessageStore>),
        None => initiator,
    }
}

/// A session logged on over a pipe, seen from the scripted acceptor.
struct Session {
    connection: Connection,
    /// Where the acceptor writes its frames.
    requests: WriteHalf<DuplexStream>,
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
async fn log_on(initiator: Initiator<NoOpApplication>) -> Session {
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
async fn measure_live(
    session: &Session,
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
        resend,
        largest,
        piled_up,
        retained,
    ) = measured;

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
    let spacing = Duration::from_secs(1)
        .as_nanos()
        .div_ceil(u128::from(THROTTLE_RATE));
    let throttled_floor = spacing * u128::from(MESSAGES - u64::from(THROTTLE_BURST));
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
