/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Counts the heap allocations of the reactor's write path in steady state
//! (issue #126).
//!
//! `dhat` is installed as this binary's global allocator and counts every
//! heap block, on every thread. A real `Initiator` runs over a
//! `tokio::io::duplex` pipe smaller than what it writes, against a scripted
//! acceptor that, once the Logon is acknowledged, counts the frames it
//! receives without allocating and writes the `ResendRequest`s it is given.
//! Two windows are measured, each after a warm-up that grows the write buffer
//! and the queues to their working size, and each over frames that pass
//! through the write buffer and its flush:
//!
//! - **Live sends**, on a session with no store. [`MESSAGES`] application
//!   messages, built before the window, go through `Connection::send`, the
//!   command queue, `to_app`, the frame factory and the write buffer to the
//!   socket. One block per message is the boxed future of the `async_trait`
//!   `to_app` call, which the `Application` trait shape costs every message;
//!   nothing else is allocated per message.
//! - **Resent frames**, on a session with a `MemoryStore`. The acceptor asks
//!   for [`MESSAGES`] stored messages with a `ResendRequest`. Rebuilding a
//!   stored frame with `PossDupFlag` (43) and `OrigSendingTime` (122) costs
//!   [`REBUILD_BLOCKS_PER_FRAME`] blocks: the store's first clone of the
//!   payload, the decoded view of it, the rebuilt frame's encoder buffer and
//!   its field list. Nothing else is allocated per frame.
//!
//! Each window may also allocate up to [`SLACK`] blocks that do not recur per
//! frame (a page `Vec` per 256 stored messages, the request's own callbacks,
//! a queue block). A write path that allocated once per frame would exceed
//! it many times over. Measured with this test before and after #126 (the
//! reactor that wrote each frame with a blocking `send`, and the one that
//! feeds the write buffer), the counts are the same within a few blocks, the
//! new path's no higher.
//!
//! It runs without the libtest harness (`harness = false` in `Cargo.toml`), so
//! no other test and no harness thread allocates while it measures. It
//! asserts counts, never timings, and holds in debug and release builds.

use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::message::MsgType;
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::{Connection, Initiator, NoOpApplication, OutboundMessage};
use ironfix_session::SessionConfig;
use ironfix_store::{MemoryStore, MessageStore};
use ironfix_tagvalue::Encoder;
use ironfix_transport::FixCodec;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream, WriteHalf};
use tokio::task::JoinHandle;
use tokio_util::codec::Framed;

#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;

/// Messages in each measured window.
const MESSAGES: u64 = 1_024;

/// Messages sent, or resent, before each window.
const WARM_UP: u64 = 512;

/// Blocks rebuilding one stored frame as a resend costs: the store's first
/// clone of its payload, the decoded view of it, and the rebuilt frame's
/// encoder buffer and field list.
const REBUILD_BLOCKS_PER_FRAME: u64 = 4;

/// Blocks a window may allocate beyond its per-frame cost: allocations that
/// do not recur per frame.
const SLACK: u64 = MESSAGES / 16;

/// Bytes each direction of the pipe holds: far less than a window's output,
/// so the flush keeps waiting on the counter and the write buffer fills.
const PIPE_BYTES: usize = 16 * 1024;

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

/// Counts the frames on a byte stream without allocating: one per
/// `<SOH>10=`, the start of every frame's CheckSum (10), matched across reads.
async fn count_frames<R: AsyncRead + Unpin>(mut io: R, frames: Arc<AtomicU64>) {
    const TRAILER: [u8; 4] = [0x01, b'1', b'0', b'='];
    let mut buf = [0_u8; 4 * 1024];
    let mut matched = 0_usize;
    loop {
        let read = match io.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
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
    /// Where the acceptor writes its requests.
    requests: WriteHalf<DuplexStream>,
    /// Frames the acceptor has received since the acknowledgement.
    frames: Arc<AtomicU64>,
    counter: JoinHandle<()>,
}

/// Logs `initiator` on to a scripted acceptor that acknowledges with
/// `MsgSeqNum` 1 and then only counts frames.
async fn log_on(initiator: Initiator<NoOpApplication>) -> Session {
    let (client_io, venue_io) = tokio::io::duplex(PIPE_BYTES);
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
    let counter = tokio::spawn(count_frames(read_half, Arc::clone(&frames)));
    Session {
        connection,
        requests,
        frames,
        counter,
    }
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
    let warm_up = usize::try_from(WARM_UP).unwrap_or(0);
    let mut live = (0..WARM_UP + MESSAGES)
        .map(order)
        .collect::<Vec<_>>()
        .into_iter();
    let sending = initiator(None);
    let resending = initiator(Some(store));

    let _profiler = dhat::Profiler::builder().testing().build();
    let (live_blocks, resend_blocks) = runtime.block_on(async {
        // Live sends, with no store.
        let session = log_on(sending).await;
        for message in live.by_ref().take(warm_up) {
            ok(session.connection.send(message).await, "a warm-up order");
        }
        wait_for_frames(&session.frames, WARM_UP).await;
        let before = blocks();
        for message in live.by_ref() {
            ok(session.connection.send(message).await, "an order");
        }
        wait_for_frames(&session.frames, WARM_UP + MESSAGES).await;
        let live_blocks = blocks() - before;
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
        let before = blocks();
        ok(session.requests.write_all(&request).await, "the request");
        wait_for_frames(&session.frames, WARM_UP + MESSAGES).await;
        let resend_blocks = blocks() - before;
        session.counter.abort();
        drop(session);
        (live_blocks, resend_blocks)
    });

    let most = MESSAGES + SLACK;
    assert!(
        live_blocks >= MESSAGES && live_blocks <= most,
        "{MESSAGES} live sends allocated {live_blocks} blocks; each must allocate one (the \
         async_trait future of to_app) and the window at most {SLACK} more"
    );
    let rebuilt = REBUILD_BLOCKS_PER_FRAME * MESSAGES;
    let most = rebuilt + SLACK;
    assert!(
        resend_blocks >= rebuilt && resend_blocks <= most,
        "a resend of {MESSAGES} frames allocated {resend_blocks} blocks; each frame must allocate \
         the {REBUILD_BLOCKS_PER_FRAME} blocks of its rebuild and the window at most {SLACK} more"
    );
}
