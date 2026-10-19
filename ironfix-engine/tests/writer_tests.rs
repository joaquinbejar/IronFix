/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Integration tests for issue #126: the reactor never blocks on a write.
//!
//! Every frame the reactor writes is fed into the session's write buffer, and
//! the buffer is flushed by a branch of its own that keeps reading while the
//! flush waits for the socket. So two sides that write to each other at once
//! (a resend each, or live traffic each) keep draining each other, even over
//! a pipe that holds less than one frame, where a side that blocked inside one
//! write would wait for a reader that is itself blocked. These tests run a
//! real `Initiator` against a real `Acceptor` over a `tokio::io::duplex` pipe
//! of 256 bytes per direction, which makes that crossing deterministic, and
//! over loopback TCP with small socket buffers:
//!
//! - both sides resend a backlog of frames larger than the pipe at once,
//!   driven by `NextExpectedMsgSeqNum` (789) and by `ResendRequest` (2);
//! - both sides' applications send frames larger than the pipe at once;
//! - a resend of many steps completes while the counterparty keeps the
//!   inbound side busy with a continuous stream of Heartbeats, and reads and
//!   steps alternate on the way;
//! - live frames are written through, one write each, when the stream takes
//!   them;
//! - the write timeout closes a session whose peer stops reading, for that
//!   reason and in bounded time, never one whose peer reads while the
//!   reactor is busy in a slow store call, and never a slow but steady
//!   reader;
//! - a Logout is sent only once it is written whole: the logout timeout
//!   starts then, the final Logout gets out under backpressure, and a close
//!   whose Logout never got out is not graceful (no `reset_on_logout`);
//! - no new `MsgSeqNum` is written in the middle of a resend when the
//!   messages held behind it fill the hold: reading stops instead;
//! - the owed Logout's deadline is checked before every resend step.
//! - a TestRequest's reply deadline and a ResendRequest's retry clock start
//!   when the frame is written whole, not when it is queued behind a large
//!   report (issue #142).

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::error::StoreError;
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::application::{Application, RejectReason, SessionId};
use ironfix_engine::{Acceptor, Connection, Initiator, OutboundMessage};
use ironfix_session::SessionConfig;
use ironfix_store::{MemoryStore, MessageStore, StoredMessage};
use ironfix_tagvalue::{Decoder, Encoder};
use ironfix_transport::FixCodec;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::codec::{Framed, FramedRead, FramedWrite};

/// Bytes a `duplex` pipe holds per direction: far less than one backlog
/// frame, so a frame is only ever written while the other side reads.
const PIPE_BYTES: usize = 256;

/// Messages in each side's backlog.
const BACKLOG_MESSAGES: u64 = 200;

/// Bytes of `Text` (58) padding in each backlog message: every frame is
/// several times the pipe.
const BACKLOG_PADDING: usize = 1_500;

/// Bound on each engine's socket writes. A side blocked inside one write
/// would be closed by it, well inside [`RECOVERY_BOUND`].
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// How long both backlogs may take to cross.
const RECOVERY_BOUND: Duration = Duration::from_secs(20);

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

/// Builds a CompID for the test fixtures.
#[track_caller]
fn comp_id(value: &str) -> CompId {
    ok(CompId::new(value), "test CompId must be valid")
}

/// Acceptor-side configuration: sender VENUE, target CLIENT, FIX.4.4.
fn venue_config() -> SessionConfig {
    SessionConfig::new(comp_id("VENUE"), comp_id("CLIENT"), "FIX.4.4")
        .with_heartbeat_interval(Duration::from_secs(30))
}

/// Initiator-side configuration: sender CLIENT, target VENUE, FIX.4.4.
fn client_config() -> SessionConfig {
    SessionConfig::new(comp_id("CLIENT"), comp_id("VENUE"), "FIX.4.4")
        .with_heartbeat_interval(Duration::from_secs(30))
}

/// An application message as `from_app` saw it: `(MsgSeqNum, PossDupFlag)`.
type AppMessage = (u64, Option<String>);

/// Forwards every application message, and counts the `ResendRequest`s (2)
/// and Heartbeats (0) that reached `from_admin`.
#[derive(Debug)]
struct RecordingApp {
    app_tx: mpsc::UnboundedSender<AppMessage>,
    resend_requests: AtomicU64,
    /// Shared with a [`WriteLogStream`], which reads it at every write.
    heartbeats: Arc<AtomicU64>,
}

impl RecordingApp {
    fn new() -> (Arc<Self>, mpsc::UnboundedReceiver<AppMessage>) {
        let (app_tx, app_rx) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                app_tx,
                resend_requests: AtomicU64::new(0),
                heartbeats: Arc::new(AtomicU64::new(0)),
            }),
            app_rx,
        )
    }

    fn resend_requests(&self) -> u64 {
        self.resend_requests.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl Application for RecordingApp {
    async fn on_create(&self, _session_id: &SessionId) {}

    async fn on_logon(&self, _session_id: &SessionId) {}

    async fn on_logout(&self, _session_id: &SessionId) {}

    async fn to_admin(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_admin(
        &self,
        message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        if message.msg_type() == &MsgType::ResendRequest {
            self.resend_requests.fetch_add(1, Ordering::Relaxed);
        }
        if message.msg_type() == &MsgType::Heartbeat {
            self.heartbeats.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    async fn to_app(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_app(
        &self,
        message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        let seq = message
            .get_field_str(34)
            .and_then(|seq| seq.parse().ok())
            .unwrap_or(0);
        let _ = self
            .app_tx
            .send((seq, message.get_field_str(43).map(str::to_string)));
        Ok(())
    }
}

/// A scripted counterparty's FIX.4.4 frame: MsgType, the CompIDs, `MsgSeqNum`,
/// `SendingTime`, then `body`.
#[track_caller]
fn peer_frame(
    sender: &str,
    target: &str,
    msg_type: &str,
    seq: u64,
    body: &[(u32, &str)],
) -> BytesMut {
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
    ok(encoder.finish_into(&mut frame), "test frame must encode");
    frame
}

/// Extracts a field from a framed message.
fn field(frame: &[u8], tag: u32) -> Option<String> {
    let mut decoder = Decoder::new(frame);
    match decoder.decode() {
        Ok(raw) => raw.get_field_str(tag).map(str::to_string),
        Err(_) => None,
    }
}

/// A store holding one side's previous stream: its Logon (1) and
/// [`BACKLOG_MESSAGES`] application messages (2 onwards) that the other side
/// never received; the other side's Logon (1) was received, so 2 is expected
/// next.
async fn backlog_store(client: bool) -> Arc<MemoryStore> {
    let padding = "x".repeat(BACKLOG_PADDING);
    let store = Arc::new(MemoryStore::new());
    let (sender, target, msg_type, wire_type) = if client {
        ("CLIENT", "VENUE", MsgType::NewOrderSingle, "D")
    } else {
        ("VENUE", "CLIENT", MsgType::ExecutionReport, "8")
    };
    let logon = peer_frame(sender, target, "A", 1, &[(98, "0"), (108, "30")]);
    ok(
        store.store(1, &MsgType::Logon, &logon).await,
        "seed the Logon",
    );
    for seq in 2..BACKLOG_MESSAGES + 2 {
        let id = seq.to_string();
        let frame = peer_frame(
            sender,
            target,
            wire_type,
            seq,
            &[(11, id.as_str()), (58, padding.as_str())],
        );
        ok(
            store.store(seq, &msg_type, &frame).await,
            "seed the backlog",
        );
    }
    ok(
        store.set_next_sender_seq(BACKLOG_MESSAGES + 2).await,
        "seed the sender counter",
    );
    ok(
        store.set_next_target_seq(2).await,
        "seed the target counter",
    );
    store
}

/// Receives the other side's whole backlog, in sequence and flagged as
/// resends.
async fn receive_backlog(rx: &mut mpsc::UnboundedReceiver<AppMessage>) {
    for seq in 2..BACKLOG_MESSAGES + 2 {
        let (received, poss_dup) = some(rx.recv().await, "the application channel stays open");
        assert_eq!(received, seq, "in sequence");
        assert_eq!(poss_dup.as_deref(), Some("Y"), "a resend");
    }
}

/// A real `Initiator` and a real `Acceptor`, each with a backlog the other
/// missed, logged on to each other over `client_io` / `venue_io`.
struct Bilateral {
    client: Connection,
    venue: Connection,
    client_app: Arc<RecordingApp>,
    venue_app: Arc<RecordingApp>,
    client_rx: mpsc::UnboundedReceiver<AppMessage>,
    venue_rx: mpsc::UnboundedReceiver<AppMessage>,
}

/// Logs a real `Initiator` on to a real `Acceptor` over the two ends of a
/// stream pair, each side holding a backlog the other missed. With `with_789`
/// both declare `NextExpectedMsgSeqNum` (789) and each resends what the
/// other's 789 names; without it each requests the gap at the other's Logon
/// and answers the other's `ResendRequest`. Either way both start resending at
/// once.
async fn log_on_with_backlogs<C, V>(client_io: C, venue_io: V, with_789: bool) -> Bilateral
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    V: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let configure = |config: SessionConfig| {
        config
            .with_send_next_expected_msg_seq_num(with_789)
            .with_resend_timeout(Duration::from_secs(30))
    };
    let capacity = 2 * usize::try_from(BACKLOG_MESSAGES).unwrap_or(usize::MAX / 4);
    let (venue_app, venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(configure(venue_config()), Arc::clone(&venue_app))
        .with_store(backlog_store(false).await as Arc<dyn MessageStore>)
        .with_write_timeout(WRITE_TIMEOUT)
        .with_app_queue_capacity(capacity);
    let served = tokio::spawn(async move { acceptor.serve_stream(venue_io).await });
    let (client_app, client_rx) = RecordingApp::new();
    let client = ok(
        Initiator::new(configure(client_config()), Arc::clone(&client_app))
            .with_store(backlog_store(true).await as Arc<dyn MessageStore>)
            .with_write_timeout(WRITE_TIMEOUT)
            .with_app_queue_capacity(capacity)
            .establish(client_io)
            .await,
        "the initiator logs on",
    );
    let venue = ok(
        ok(
            ok(
                timeout(Duration::from_secs(5), served).await,
                "handshake within 5s",
            ),
            "venue task joins",
        ),
        "the acceptor establishes the session",
    );
    Bilateral {
        client,
        venue,
        client_app,
        venue_app,
        client_rx,
        venue_rx,
    }
}

/// Runs the bilateral recovery over the two ends of a stream pair and checks
/// that each side receives the other's whole backlog as resends, that neither
/// session closed on the way, and that live messages then flow both ways.
async fn bilateral_recovery<C, V>(client_io: C, venue_io: V, with_789: bool)
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    V: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Bilateral {
        client,
        venue,
        client_app,
        venue_app,
        mut client_rx,
        mut venue_rx,
    } = log_on_with_backlogs(client_io, venue_io, with_789).await;

    // A side blocked inside one write is closed by its write timeout; that
    // close is reported as such rather than left to the recovery bound.
    let crossed = timeout(RECOVERY_BOUND, async {
        tokio::select! {
            ((), ()) = async {
                tokio::join!(
                    receive_backlog(&mut client_rx),
                    receive_backlog(&mut venue_rx)
                )
            } => Ok(()),
            () = client.wait_closed() => Err("the initiator's session closed"),
            () = venue.wait_closed() => Err("the acceptor's session closed"),
        }
    })
    .await;
    ok(
        ok(
            crossed,
            "both backlogs cross, each larger than the pipe, within the recovery bound",
        ),
        "both backlogs cross before either session closes (a side blocked in a write is \
         closed by its write timeout)",
    );

    let mut report = OutboundMessage::new(MsgType::ExecutionReport);
    report
        .push_str(37, "EX-LIVE")
        .push_str(17, "E-LIVE")
        .push_char(150, '0')
        .push_char(39, '0');
    ok(venue.send(report).await, "a live report");
    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order.push_str(11, "ORDER-LIVE");
    ok(client.send(order).await, "a live order");
    let live_report = some(
        ok(
            timeout(Duration::from_secs(5), client_rx.recv()).await,
            "the live report arrives",
        ),
        "the application channel stays open",
    );
    let live_order = some(
        ok(
            timeout(Duration::from_secs(5), venue_rx.recv()).await,
            "the live order arrives",
        ),
        "the application channel stays open",
    );
    assert_eq!(live_report.1, None, "an original send");
    assert_eq!(live_order.1, None, "an original send");
    // Logon, (the ResendRequest,) then the live message.
    let live_seq = BACKLOG_MESSAGES + if with_789 { 3 } else { 4 };
    assert_eq!(live_report.0, live_seq, "the resend spent no number");
    assert_eq!(live_order.0, live_seq, "the resend spent no number");
    if with_789 {
        assert_eq!(client_app.resend_requests(), 0, "789 needs no request");
        assert_eq!(venue_app.resend_requests(), 0, "789 needs no request");
    }

    ok(client.logout().await, "the client logs out");
    ok(
        timeout(Duration::from_secs(5), client.wait_closed()).await,
        "the client session closes within 5s",
    );
    ok(
        timeout(Duration::from_secs(5), venue.wait_closed()).await,
        "the venue session closes within 5s",
    );
}

/// A loopback TCP pair whose send and receive buffers are asked to be 4 KiB:
/// (dialled, accepted). The kernel may round the sizes up; either way every
/// backlog frame is a sizeable share of what a direction holds in flight.
async fn small_buffer_tcp_pair() -> (TcpStream, TcpStream) {
    const SOCKET_BUFFER: u32 = 4 * 1024;
    let listen = ok(TcpSocket::new_v4(), "listening socket");
    ok(
        listen.set_send_buffer_size(SOCKET_BUFFER),
        "listener SO_SNDBUF",
    );
    ok(
        listen.set_recv_buffer_size(SOCKET_BUFFER),
        "listener SO_RCVBUF",
    );
    ok(
        listen.bind(ok("127.0.0.1:0".parse(), "loopback address")),
        "bind loopback",
    );
    let listener: TcpListener = ok(listen.listen(8), "listen");
    let addr = ok(listener.local_addr(), "listener address");
    let dial = ok(TcpSocket::new_v4(), "dialling socket");
    ok(
        dial.set_send_buffer_size(SOCKET_BUFFER),
        "dialler SO_SNDBUF",
    );
    ok(
        dial.set_recv_buffer_size(SOCKET_BUFFER),
        "dialler SO_RCVBUF",
    );
    let (dialled, accepted) = tokio::join!(dial.connect(addr), listener.accept());
    let dialled = ok(dialled, "dial loopback");
    let (accepted, _) = ok(accepted, "accept loopback");
    // Frames go out whole and at once, as every engine session sends them.
    ok(dialled.set_nodelay(true), "TCP_NODELAY");
    ok(accepted.set_nodelay(true), "TCP_NODELAY");
    (dialled, accepted)
}

// ---------------------------------------------------------------------------
// Two sides resending to each other at once
// ---------------------------------------------------------------------------

/// Both sides declared 789 and each missed the other's backlog: each resends
/// it over a pipe that holds less than one of its frames. A side that blocked
/// writing one frame would wait for a reader blocked the same way, and the
/// write timeout would close both sessions.
#[tokio::test]
async fn test_bilateral_789_resend_over_a_pipe_smaller_than_one_frame() {
    let (client_io, venue_io) = tokio::io::duplex(PIPE_BYTES);
    bilateral_recovery(client_io, venue_io, true).await;
}

/// The same backlogs without 789: each side requests the gap at the other's
/// Logon and answers the other's `ResendRequest` over the same small pipe.
#[tokio::test]
async fn test_bilateral_resend_requests_over_a_pipe_smaller_than_one_frame() {
    let (client_io, venue_io) = tokio::io::duplex(PIPE_BYTES);
    bilateral_recovery(client_io, venue_io, false).await;
}

/// The 789 recovery over loopback TCP with small socket buffers, on a
/// multi-threaded runtime: the two reactors run on different threads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_bilateral_789_resend_over_small_tcp_buffers() {
    let (dialled, accepted) = small_buffer_tcp_pair().await;
    bilateral_recovery(dialled, accepted, true).await;
}

/// The `ResendRequest` recovery over loopback TCP with small socket buffers,
/// on a multi-threaded runtime.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_bilateral_resend_requests_over_small_tcp_buffers() {
    let (dialled, accepted) = small_buffer_tcp_pair().await;
    bilateral_recovery(dialled, accepted, false).await;
}

// ---------------------------------------------------------------------------
// Two sides sending live traffic to each other at once
// ---------------------------------------------------------------------------

/// Live messages each application sends.
const LIVE_MESSAGES: u64 = 200;

/// Receives `count` original (not resent) application messages numbered from
/// 2, in sequence.
async fn receive_live(rx: &mut mpsc::UnboundedReceiver<AppMessage>, count: u64) {
    for seq in 2..count + 2 {
        let (received, poss_dup) = some(rx.recv().await, "the application channel stays open");
        assert_eq!(received, seq, "in sequence");
        assert_eq!(poss_dup, None, "an original send");
    }
}

/// Both applications send frames larger than the pipe at once, with nothing
/// to recover: live sends go through the same writer as a resend, so neither
/// reactor blocks inside a write while the other is blocked the same way.
#[tokio::test]
async fn test_bilateral_live_traffic_over_a_pipe_smaller_than_one_frame() {
    let (client_io, venue_io) = tokio::io::duplex(PIPE_BYTES);
    let capacity = 2 * usize::try_from(LIVE_MESSAGES).unwrap_or(usize::MAX / 4);
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(venue_config(), Arc::clone(&venue_app))
        .with_write_timeout(WRITE_TIMEOUT)
        .with_app_queue_capacity(capacity)
        .with_outbound_capacity(capacity);
    let served = tokio::spawn(async move { acceptor.serve_stream(venue_io).await });
    let (client_app, mut client_rx) = RecordingApp::new();
    let client = ok(
        Initiator::new(client_config(), Arc::clone(&client_app))
            .with_write_timeout(WRITE_TIMEOUT)
            .with_app_queue_capacity(capacity)
            .with_outbound_capacity(capacity)
            .establish(client_io)
            .await,
        "the initiator logs on",
    );
    let venue = ok(
        ok(
            ok(
                timeout(Duration::from_secs(5), served).await,
                "handshake within 5s",
            ),
            "venue task joins",
        ),
        "the acceptor establishes the session",
    );

    let padding = "x".repeat(BACKLOG_PADDING);
    for index in 0..LIVE_MESSAGES {
        let id = index.to_string();
        let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
        order.push_str(11, &id).push_str(58, &padding);
        ok(client.send(order).await, "a live order");
        let mut report = OutboundMessage::new(MsgType::ExecutionReport);
        report
            .push_str(37, &id)
            .push_str(17, &id)
            .push_char(150, '0')
            .push_char(39, '0')
            .push_str(58, &padding);
        ok(venue.send(report).await, "a live report");
    }

    let crossed = timeout(RECOVERY_BOUND, async {
        tokio::select! {
            ((), ()) = async {
                tokio::join!(
                    receive_live(&mut client_rx, LIVE_MESSAGES),
                    receive_live(&mut venue_rx, LIVE_MESSAGES)
                )
            } => Ok(()),
            () = client.wait_closed() => Err("the initiator's session closed"),
            () = venue.wait_closed() => Err("the acceptor's session closed"),
        }
    })
    .await;
    ok(
        ok(
            crossed,
            "both sides' live traffic crosses within the recovery bound",
        ),
        "both sides' live traffic crosses before either session closes",
    );
    ok(client.logout().await, "the client logs out");
    ok(
        timeout(Duration::from_secs(5), venue.wait_closed()).await,
        "the venue session closes within 5s",
    );
}

// ---------------------------------------------------------------------------
// A resend under a continuous inbound stream
// ---------------------------------------------------------------------------

/// Heartbeats the scripted counterparty puts on the wire right behind its
/// Logon, all at once.
const FLOOD_HEARTBEATS: u64 = 20_000;

/// Reports the acceptor owes the counterparty: 2 to 301.
const OWED_REPORTS: u64 = 300;

/// Inbound frames the reactor handles in a row before a resend step (the
/// engine's `MAX_READS_PER_RESEND_STEP`).
const READS_PER_RESEND_STEP: u64 = 16;

/// The acceptor's previous stream: its Logon ack (1) and `reports` reports
/// (2 onwards), each with `padding` bytes of `Text` (58); next sender one
/// past the last report, next target 3.
async fn venue_backlog(reports: u64, padding: usize) -> Arc<MemoryStore> {
    let store = Arc::new(MemoryStore::new());
    let ack = peer_frame("VENUE", "CLIENT", "A", 1, &[(98, "0"), (108, "30")]);
    ok(store.store(1, &MsgType::Logon, &ack).await, "seed the ack");
    let text = "x".repeat(padding);
    for seq in 2..=reports + 1 {
        let mut body = vec![(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")];
        if padding > 0 {
            body.push((58, text.as_str()));
        }
        let report = peer_frame("VENUE", "CLIENT", "8", seq, &body);
        ok(
            store.store(seq, &MsgType::ExecutionReport, &report).await,
            "seed a report",
        );
    }
    ok(
        store.set_next_sender_seq(reports + 2).await,
        "seed the sender counter",
    );
    ok(
        store.set_next_target_seq(3).await,
        "seed the target counter",
    );
    store
}

/// Reads the next frame from a scripted peer's end of a pipe, within 10 s.
async fn next_frame<S: AsyncRead + AsyncWrite + Unpin>(
    framed: &mut Framed<S, FixCodec>,
) -> BytesMut {
    let polled = ok(
        timeout(Duration::from_secs(10), framed.next()).await,
        "a frame arrives within 10s",
    );
    ok(some(polled, "the stream stays open"), "the frame decodes")
}

/// A Logon from the scripted initiator, numbered `seq`, declaring
/// `NextExpectedMsgSeqNum` (789) = 2.
fn client_logon_789(seq: u64) -> BytesMut {
    peer_frame(
        "CLIENT",
        "VENUE",
        "A",
        seq,
        &[(98, "0"), (108, "30"), (789, "2")],
    )
}

/// Serves `acceptor` on `venue_io` while a scripted initiator on `framed`
/// logs on with `logon`; returns the acknowledgement and the connection.
async fn serve_scripted<A, S, V>(
    acceptor: Acceptor<A>,
    venue_io: V,
    framed: &mut Framed<S, FixCodec>,
    logon: BytesMut,
) -> (BytesMut, Connection)
where
    A: Application + 'static,
    S: AsyncRead + AsyncWrite + Unpin,
    V: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let served = tokio::spawn(async move { acceptor.serve_stream(venue_io).await });
    ok(framed.send(logon).await, "the client logs on");
    let ack = next_frame(framed).await;
    assert_eq!(
        field(&ack, 35).as_deref(),
        Some("A"),
        "the Logon is acknowledged"
    );
    let connection = ok(
        ok(
            ok(
                timeout(Duration::from_secs(5), served).await,
                "handshake within 5s",
            ),
            "venue task joins",
        ),
        "the acceptor establishes the session",
    );
    (ack, connection)
}

/// The engine's end of a pipe, logging after every write how many bytes it
/// has written in all and how many Heartbeats its `from_admin` had seen by
/// then: the order of the reactor's own writes and reads, whatever the
/// scheduler did with the test's task meanwhile. It also counts the writes.
struct WriteLogStream {
    inner: DuplexStream,
    heartbeats: Arc<AtomicU64>,
    written: usize,
    writes: Arc<AtomicU64>,
    log: Arc<Mutex<Vec<(usize, u64)>>>,
}

impl WriteLogStream {
    fn new(inner: DuplexStream, heartbeats: Arc<AtomicU64>) -> Self {
        Self {
            inner,
            heartbeats,
            written: 0,
            writes: Arc::new(AtomicU64::new(0)),
            log: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl AsyncRead for WriteLogStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for WriteLogStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = polled {
            self.written += written;
            self.writes.fetch_add(1, Ordering::Relaxed);
            let entry = (self.written, self.heartbeats.load(Ordering::Relaxed));
            match self.log.lock() {
                Ok(mut log) => log.push(entry),
                Err(_) => panic!("write log poisoned"),
            }
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

/// A scripted initiator logs on with `NextExpectedMsgSeqNum` (789) = 2, so
/// the acceptor owes it 300 reports, and puts 20 000 in-sequence Heartbeats on
/// the wire right behind its Logon: the acceptor's inbound side is never idle
/// until it has read them all. The reports are padded (about 200 KB in all),
/// so the resend takes many steps. The resend still goes out, in order,
/// before the acceptor has read a tenth of the Heartbeats, and the acceptor
/// read at least a step's worth of them on the way: reads and resend steps
/// alternate in a bounded ratio, so neither waits for the other to run dry.
/// (Before #126 the resend was written only once inbound was idle, so here
/// only after all 20 000.)
#[tokio::test]
async fn test_resend_progresses_under_a_continuous_inbound_stream() {
    // Large enough for the Logon and every Heartbeat, so the whole stream is
    // on the wire before the acceptor reads its first byte.
    let (client_io, venue_io) = tokio::io::duplex(8 * 1024 * 1024);
    let (venue_app, _venue_rx) = RecordingApp::new();
    let venue_io = WriteLogStream::new(venue_io, Arc::clone(&venue_app.heartbeats));
    let log = Arc::clone(&venue_io.log);
    let acceptor = Acceptor::new(
        venue_config().with_send_next_expected_msg_seq_num(true),
        Arc::clone(&venue_app),
    )
    .with_store(venue_backlog(OWED_REPORTS, 500).await as Arc<dyn MessageStore>);

    let mut wire = BytesMut::new();
    wire.extend_from_slice(&client_logon_789(3));
    let first_heartbeat = 4;
    let past_the_flood = first_heartbeat + FLOOD_HEARTBEATS;
    for seq in first_heartbeat..past_the_flood {
        wire.extend_from_slice(&peer_frame("CLIENT", "VENUE", "0", seq, &[]));
    }
    let mut framed = Framed::new(client_io, FixCodec::new());
    ok(
        framed.get_mut().write_all(&wire).await,
        "the Logon and the whole Heartbeat stream are on the wire",
    );
    let served = tokio::spawn(async move { acceptor.serve_stream(venue_io).await });
    let venue = ok(
        ok(
            ok(
                timeout(Duration::from_secs(5), served).await,
                "handshake within 5s",
            ),
            "venue task joins",
        ),
        "the acceptor establishes the session",
    );

    let ack = next_frame(&mut framed).await;
    assert_eq!(
        field(&ack, 35).as_deref(),
        Some("A"),
        "the Logon is acknowledged"
    );
    assert_eq!(
        field(&ack, 34),
        Some((OWED_REPORTS + 2).to_string()),
        "the acknowledgement takes the next number"
    );
    let mut resend_end = ack.len();
    for seq in 2..=OWED_REPORTS + 1 {
        let frame = next_frame(&mut framed).await;
        assert_eq!(field(&frame, 34), Some(seq.to_string()), "resent in order");
        assert_eq!(field(&frame, 43).as_deref(), Some("Y"), "a resend");
        resend_end += frame.len();
    }
    // The first write that took the acceptor's output past the last resent
    // frame, and how many Heartbeats it had read by then.
    let read_when_done = match log.lock() {
        Ok(log) => log
            .iter()
            .find(|(written, _)| *written >= resend_end)
            .map(|(_, heartbeats)| *heartbeats),
        Err(_) => panic!("write log poisoned"),
    };
    let read_when_done = some(read_when_done, "the whole resend was written");
    assert!(
        read_when_done < FLOOD_HEARTBEATS / 10,
        "the resend was written while the inbound stream was still being read: \
         {read_when_done} of {FLOOD_HEARTBEATS} Heartbeats read by then"
    );
    assert!(
        read_when_done >= READS_PER_RESEND_STEP,
        "inbound was read between the resend's steps: {read_when_done} Heartbeats read"
    );

    // Nothing was dropped: the rest of the stream is read in sequence.
    ok(
        timeout(Duration::from_secs(30), async {
            while venue.next_target_seq() < past_the_flood {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await,
        "the whole Heartbeat stream is read",
    );
    assert!(!venue.is_closed(), "the session is still up");
}

// ---------------------------------------------------------------------------
// The write timeout
// ---------------------------------------------------------------------------

/// Records the `reason` of every "FIX session closed" event emitted on the
/// thread it is the default subscriber of: the reactor's close reason, which
/// nothing else exposes.
#[derive(Debug, Clone, Default)]
struct CloseReasons(Arc<Mutex<Vec<String>>>);

impl CloseReasons {
    #[track_caller]
    fn reasons(&self) -> Vec<String> {
        match self.0.lock() {
            Ok(reasons) => reasons.clone(),
            Err(_) => panic!("close reasons poisoned"),
        }
    }
}

/// Collects an event's `message` and `reason` fields.
#[derive(Default)]
struct CloseFields {
    message: String,
    reason: Option<String>,
}

impl tracing::field::Visit for CloseFields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "message" => self.message = format!("{value:?}"),
            "reason" => self.reason = Some(format!("{value:?}")),
            _ => {}
        }
    }
}

impl tracing::Subscriber for CloseReasons {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = CloseFields::default();
        event.record(&mut fields);
        if fields.message == "FIX session closed"
            && let Some(reason) = fields.reason
            && let Ok(mut reasons) = self.0.lock()
        {
            reasons.push(reason);
        }
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

/// A scripted initiator logs on with 789 = 2 and then never reads again, over
/// a pipe smaller than the resend it is owed: the stream accepts none of the
/// acceptor's output, and the write timeout closes the session for that
/// reason, between the timeout and two ticks (plus scheduling slack) after
/// the client stopped reading.
#[tokio::test]
async fn test_a_resend_the_peer_never_reads_is_closed_by_the_write_timeout() {
    let reasons = CloseReasons::default();
    let _subscriber = tracing::subscriber::set_default(reasons.clone());
    // Tests in this binary run in parallel and tracing caches callsite
    // interest globally; rebuild it so no callsite skips this subscriber.
    tracing::callsite::rebuild_interest_cache();
    let write_timeout = Duration::from_millis(300);
    let (client_io, venue_io) = tokio::io::duplex(PIPE_BYTES);
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config().with_send_next_expected_msg_seq_num(true),
        Arc::clone(&venue_app),
    )
    .with_store(venue_backlog(OWED_REPORTS, 0).await as Arc<dyn MessageStore>)
    .with_write_timeout(write_timeout);
    let mut framed = Framed::new(client_io, FixCodec::new());
    let (_ack, venue) = serve_scripted(acceptor, venue_io, &mut framed, client_logon_789(3)).await;
    // The client holds its end open and reads nothing more.
    let stopped = tokio::time::Instant::now();
    ok(
        timeout(Duration::from_secs(5), venue.wait_closed()).await,
        "the write timeout closes the session",
    );
    let took = stopped.elapsed();
    assert!(
        took >= write_timeout,
        "closed only once the timeout ran out: {took:?}"
    );
    assert!(
        took <= write_timeout + Duration::from_millis(700),
        "closed within two ticks of the timeout, with slack: {took:?}"
    );
    assert_eq!(
        reasons.reasons(),
        vec!["write failed: write timed out after 300ms".to_string()],
        "closed by the write timeout"
    );
    drop(framed);
}

/// A store whose filing of application messages takes [`SLOW_FILING`],
/// standing in for an fsync, a remote store, or a store call that overruns.
#[derive(Debug, Default)]
struct SlowFilingStore(MemoryStore);

/// How long [`SlowFilingStore`] takes to file an application message: longer
/// than the write timeout of [`test_a_busy_reactor_does_not_time_out_a_peer_that_reads`].
const SLOW_FILING: Duration = Duration::from_millis(500);

#[async_trait]
impl MessageStore for SlowFilingStore {
    async fn store(&self, seq: u64, msg_type: &MsgType, message: &[u8]) -> Result<(), StoreError> {
        if msg_type.is_app() {
            tokio::time::sleep(SLOW_FILING).await;
        }
        self.0.store(seq, msg_type, message).await
    }

    async fn get_range(&self, begin: u64, end: u64) -> Result<Vec<StoredMessage>, StoreError> {
        self.0.get_range(begin, end).await
    }

    fn next_sender_seq(&self) -> u64 {
        self.0.next_sender_seq()
    }

    fn next_target_seq(&self) -> u64 {
        self.0.next_target_seq()
    }

    async fn set_next_sender_seq(&self, seq: u64) -> Result<(), StoreError> {
        self.0.set_next_sender_seq(seq).await
    }

    async fn set_next_target_seq(&self, seq: u64) -> Result<(), StoreError> {
        self.0.set_next_target_seq(seq).await
    }

    async fn reset(&self) -> Result<(), StoreError> {
        self.0.reset().await
    }

    fn creation_time(&self) -> std::time::SystemTime {
        self.0.creation_time()
    }
}

/// A scripted acceptor that, once the Logon is acknowledged, reads the
/// initiator's frames only while `gate` is open, and counts the
/// NewOrderSingles among them in `orders`.
fn gated_reader(
    mut framed: Framed<DuplexStream, FixCodec>,
    mut gate: tokio::sync::watch::Receiver<bool>,
    orders: Arc<AtomicU64>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if gate.wait_for(|open| *open).await.is_err() {
                return;
            }
            tokio::select! {
                frame = framed.next() => match frame {
                    Some(Ok(frame)) => {
                        if field(&frame, 35).as_deref() == Some("D") {
                            orders.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    _ => return,
                },
                changed = gate.changed() => if changed.is_err() {
                    return;
                },
            }
        }
    })
}

/// P1-01: an order the counterparty has not read yet waits while the next
/// order's filing (a slow store, longer than the write timeout) keeps the
/// reactor inside an inline await; the counterparty reads again meanwhile,
/// but nobody polls the flush. The write timeout counts only time the stream
/// was asked for bytes and took none, so the session is never closed: each
/// tick polls the flush first, and the bytes the counterparty made room for
/// are progress. Five rounds, each arming the stall clock with the reader
/// paused and then keeping the reactor busy past the timeout with the reader
/// running. (Before the fix a tick that won the race against the socket
/// branch after the busy period closed the session, about one round in two.)
#[tokio::test]
async fn test_a_busy_reactor_does_not_time_out_a_peer_that_reads() {
    const ROUNDS: u64 = 5;
    let write_timeout = Duration::from_millis(300);
    let (client_io, venue_io) = tokio::io::duplex(PIPE_BYTES);
    let (client_app, _client_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(), Arc::clone(&client_app))
        .with_store(Arc::new(SlowFilingStore(MemoryStore::new())) as Arc<dyn MessageStore>)
        .with_write_timeout(write_timeout)
        .with_store_timeout(Duration::from_secs(5));
    let established = tokio::spawn(async move { initiator.establish(client_io).await });
    let mut venue = Framed::new(venue_io, FixCodec::new());
    let logon = next_frame(&mut venue).await;
    assert_eq!(field(&logon, 35).as_deref(), Some("A"));
    ok(
        venue
            .send(peer_frame(
                "VENUE",
                "CLIENT",
                "A",
                1,
                &[(98, "0"), (108, "30")],
            ))
            .await,
        "the venue acknowledges",
    );
    let client = ok(
        ok(
            ok(
                timeout(Duration::from_secs(5), established).await,
                "handshake within 5s",
            ),
            "initiator task joins",
        ),
        "the initiator establishes the session",
    );
    let (gate, gate_rx) = tokio::sync::watch::channel(true);
    let orders = Arc::new(AtomicU64::new(0));
    let reader = gated_reader(venue, gate_rx, Arc::clone(&orders));
    let padding = "x".repeat(1_000);
    let order = |index: u64| {
        let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
        order
            .push_str(11, &index.to_string())
            .push_str(58, &padding);
        order
    };

    ok(client.send(order(0)).await, "the first order");
    for round in 1..=ROUNDS {
        // The previous order is about to be filed and fed: the reader pauses,
        // so it waits in the buffer and the stall clock starts.
        tokio::time::sleep(SLOW_FILING - Duration::from_millis(100)).await;
        let _ = gate.send(false);
        tokio::time::sleep(Duration::from_millis(300)).await;
        // The next order keeps the reactor filing past the write timeout
        // while the reader drains what it can.
        ok(client.send(order(round)).await, "the next order");
        let _ = gate.send(true);
        assert!(!client.is_closed(), "round {round}: still logged on");
    }
    ok(
        timeout(Duration::from_secs(10), async {
            while orders.load(Ordering::Relaxed) < ROUNDS + 1 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await,
        "every order reaches the counterparty",
    );
    assert!(
        !client.is_closed(),
        "a counterparty that reads is never closed by the write timeout"
    );
    reader.abort();
}

/// A slow but steady reader is not cut off: the acceptor resends 100 frames
/// of about 1.6 KB over a 2 KiB pipe to a scripted initiator that reads one
/// frame every 10 ms, a second in all, more than three times the 300 ms write
/// timeout. Every frame arrives and the session stays up: the timeout bounds
/// how long the stream takes no bytes, not how long the output takes.
#[tokio::test]
async fn test_a_slow_steady_reader_is_not_cut_off() {
    const FRAMES: u64 = 100;
    let (client_io, venue_io) = tokio::io::duplex(2 * 1024);
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config().with_send_next_expected_msg_seq_num(true),
        Arc::clone(&venue_app),
    )
    .with_store(venue_backlog(FRAMES, BACKLOG_PADDING).await as Arc<dyn MessageStore>)
    .with_write_timeout(Duration::from_millis(300));
    let mut framed = Framed::new(client_io, FixCodec::new());
    let (_ack, venue) = serve_scripted(acceptor, venue_io, &mut framed, client_logon_789(3)).await;
    for seq in 2..=FRAMES + 1 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let frame = next_frame(&mut framed).await;
        assert_eq!(field(&frame, 34), Some(seq.to_string()), "resent in order");
    }
    assert!(!venue.is_closed(), "the slow reader was not cut off");
}

/// The final Logout gets out under backpressure: the scripted initiator asks
/// for a 789 resend of 200 frames of about 1.6 KB and logs out right behind
/// it, then reads slowly over a 256-byte pipe (one frame every 5 ms). The
/// acceptor answers the Logout after the resend, closes, and writes out what
/// it left in its buffer while the reader goes on: the Logout arrives last,
/// after every resent frame, and the close is graceful (`reset_on_logout`
/// resets the sequence numbers), although writing the rest took longer than
/// the 300 ms write timeout.
#[tokio::test]
async fn test_the_final_logout_gets_out_under_backpressure() {
    let (client_io, venue_io) = tokio::io::duplex(PIPE_BYTES);
    let (venue_app, _venue_rx) = RecordingApp::new();
    let mut config = venue_config().with_send_next_expected_msg_seq_num(true);
    config.reset_on_logout = true;
    let acceptor = Acceptor::new(config, Arc::clone(&venue_app))
        .with_store(backlog_store(false).await as Arc<dyn MessageStore>)
        .with_write_timeout(Duration::from_millis(300));
    let mut framed = Framed::new(client_io, FixCodec::new());
    let mut wire = BytesMut::new();
    wire.extend_from_slice(&peer_frame(
        "CLIENT",
        "VENUE",
        "A",
        2,
        &[(98, "0"), (108, "30"), (789, "2")],
    ));
    wire.extend_from_slice(&peer_frame("CLIENT", "VENUE", "5", 3, &[]));
    let served = tokio::spawn(async move { acceptor.serve_stream(venue_io).await });
    ok(
        framed.get_mut().write_all(&wire).await,
        "the Logon and the Logout",
    );
    let mut resent = 0;
    let mut last = None;
    while let Ok(Some(Ok(frame))) = timeout(Duration::from_secs(2), framed.next()).await {
        tokio::time::sleep(Duration::from_millis(5)).await;
        if field(&frame, 43).as_deref() == Some("Y") {
            resent += 1;
        }
        last = field(&frame, 35);
        if last.as_deref() == Some("5") {
            break;
        }
    }
    assert_eq!(resent, BACKLOG_MESSAGES, "every resent frame arrived first");
    assert_eq!(last.as_deref(), Some("5"), "the Logout reply came last");
    let venue = ok(
        ok(
            ok(timeout(Duration::from_secs(5), served).await, "handshake"),
            "venue task joins",
        ),
        "the acceptor established the session",
    );
    ok(
        timeout(Duration::from_secs(5), venue.wait_closed()).await,
        "the session closes",
    );
    assert_eq!(
        venue.next_sender_seq(),
        1,
        "a graceful close: reset_on_logout reset the sequence numbers"
    );
}

/// P2-01: a Logout that never left the buffer was not sent. The acceptor's
/// application sends a report larger than the 256-byte pipe to a scripted
/// initiator that has stopped reading, then logs out; the Logout waits
/// behind the report. Its logout timeout (100 ms) never starts, since the
/// Logout was never written: the write timeout (600 ms) closes the session,
/// and the close is not graceful, so `reset_on_logout` leaves the sequence
/// numbers alone (a reset here would make the next Logon go out at
/// `MsgSeqNum` 1 without `ResetSeqNumFlag` (141), which the counterparty
/// would refuse as too low).
#[tokio::test]
async fn test_a_logout_that_never_left_is_not_a_graceful_close() {
    let reasons = CloseReasons::default();
    let _subscriber = tracing::subscriber::set_default(reasons.clone());
    // Tests in this binary run in parallel and tracing caches callsite
    // interest globally; rebuild it so no callsite skips this subscriber.
    tracing::callsite::rebuild_interest_cache();
    let write_timeout = Duration::from_millis(600);
    let (client_io, venue_io) = tokio::io::duplex(PIPE_BYTES);
    let (venue_app, _venue_rx) = RecordingApp::new();
    let mut config = venue_config().with_logout_timeout(Duration::from_millis(100));
    config.reset_on_logout = true;
    let acceptor = Acceptor::new(config, Arc::clone(&venue_app)).with_write_timeout(write_timeout);
    let mut framed = Framed::new(client_io, FixCodec::new());
    let logon = peer_frame("CLIENT", "VENUE", "A", 1, &[(98, "0"), (108, "30")]);
    let (_ack, venue) = serve_scripted(acceptor, venue_io, &mut framed, logon).await;
    let padding = "x".repeat(BACKLOG_PADDING);
    let mut report = OutboundMessage::new(MsgType::ExecutionReport);
    report
        .push_str(37, "E")
        .push_str(17, "E")
        .push_char(150, '0')
        .push_char(39, '0')
        .push_str(58, &padding);
    ok(venue.send(report).await, "a report the pipe cannot hold");
    ok(venue.logout().await, "the venue logs out");
    let started = tokio::time::Instant::now();
    ok(
        timeout(Duration::from_secs(5), venue.wait_closed()).await,
        "the session closes",
    );
    assert!(
        started.elapsed() >= write_timeout - Duration::from_millis(150),
        "closed by the write timeout, not the logout timeout: {:?}",
        started.elapsed()
    );
    assert_eq!(
        venue.next_sender_seq(),
        4,
        "not a graceful close: the ack (1), the report (2) and the Logout (3) keep their numbers"
    );
    assert_eq!(
        reasons.reasons(),
        vec!["write failed: write timed out after 600ms".to_string()]
    );
    drop(framed);
}

/// P2-01, the reply: the scripted initiator logs out and stops reading while
/// a report larger than the pipe is still in the acceptor's buffer. The reply
/// to its Logout queues behind the report and never gets out, so the close
/// is not graceful and `reset_on_logout` does not reset.
#[tokio::test]
async fn test_a_logout_reply_that_never_left_is_not_a_graceful_close() {
    let (client_io, venue_io) = tokio::io::duplex(PIPE_BYTES);
    let (venue_app, _venue_rx) = RecordingApp::new();
    let mut config = venue_config();
    config.reset_on_logout = true;
    let acceptor = Acceptor::new(config, Arc::clone(&venue_app))
        .with_write_timeout(Duration::from_millis(300));
    let mut framed = Framed::new(client_io, FixCodec::new());
    let logon = peer_frame("CLIENT", "VENUE", "A", 1, &[(98, "0"), (108, "30")]);
    let (_ack, venue) = serve_scripted(acceptor, venue_io, &mut framed, logon).await;
    let padding = "x".repeat(BACKLOG_PADDING);
    let mut report = OutboundMessage::new(MsgType::ExecutionReport);
    report
        .push_str(37, "E")
        .push_str(17, "E")
        .push_char(150, '0')
        .push_char(39, '0')
        .push_str(58, &padding);
    ok(venue.send(report).await, "a report the pipe cannot hold");
    tokio::time::sleep(Duration::from_millis(50)).await;
    ok(
        framed
            .send(peer_frame("CLIENT", "VENUE", "5", 2, &[]))
            .await,
        "the client logs out and reads no more",
    );
    ok(
        timeout(Duration::from_secs(5), venue.wait_closed()).await,
        "the session closes",
    );
    assert_eq!(
        venue.next_sender_seq(),
        4,
        "not a graceful close: the reply (3) never left, so nothing is reset"
    );
    drop(framed);
}

/// P2-02: while a resend is under way and the messages held behind it fill
/// the hold, the acceptor stops reading instead of writing a new number in
/// the middle of the resend. The scripted initiator asks for a 789 resend of
/// 200 frames larger than the 256-byte pipe, reads nothing, and sends 1 100
/// TestRequests from another task; it starts reading a second later. All 200
/// resent frames arrive before any new number, then the 1 100 Heartbeats,
/// numbered in order and echoing the TestReqIDs in order: the TestRequests
/// past the hold were read only once the resend was done.
#[tokio::test]
async fn test_no_new_number_inside_a_resend_when_the_hold_fills() {
    const TEST_REQUESTS: u64 = 1_100;
    let (client_io, venue_io) = tokio::io::duplex(PIPE_BYTES);
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config().with_send_next_expected_msg_seq_num(true),
        Arc::clone(&venue_app),
    )
    .with_store(backlog_store(false).await as Arc<dyn MessageStore>);
    let (read_half, write_half) = tokio::io::split(client_io);
    let mut reader = FramedRead::new(read_half, FixCodec::new());
    let mut writer = FramedWrite::new(write_half, FixCodec::new());
    let served = tokio::spawn(async move { acceptor.serve_stream(venue_io).await });
    ok(
        writer
            .send(peer_frame(
                "CLIENT",
                "VENUE",
                "A",
                2,
                &[(98, "0"), (108, "30"), (789, "2")],
            ))
            .await,
        "the client logs on",
    );
    let ack = ok(
        some(
            ok(
                timeout(Duration::from_secs(5), reader.next()).await,
                "the ack arrives",
            ),
            "the stream stays open",
        ),
        "the ack decodes",
    );
    assert_eq!(field(&ack, 35).as_deref(), Some("A"));
    let venue = ok(
        ok(
            ok(timeout(Duration::from_secs(5), served).await, "handshake"),
            "venue task joins",
        ),
        "the acceptor established the session",
    );
    let flood = tokio::spawn(async move {
        for seq in 3..3 + TEST_REQUESTS {
            let id = format!("T{seq}");
            if writer
                .send(peer_frame(
                    "CLIENT",
                    "VENUE",
                    "1",
                    seq,
                    &[(112, id.as_str())],
                ))
                .await
                .is_err()
            {
                return false;
            }
        }
        true
    });
    tokio::time::sleep(Duration::from_secs(1)).await;

    let mut resent = 0;
    while resent < BACKLOG_MESSAGES {
        let frame = ok(
            some(
                ok(
                    timeout(Duration::from_secs(10), reader.next()).await,
                    "a frame arrives",
                ),
                "the stream stays open",
            ),
            "the frame decodes",
        );
        assert_eq!(
            field(&frame, 43).as_deref(),
            Some("Y"),
            "after {resent} resent frames, a new number inside the resend: 35={:?} 34={:?}",
            field(&frame, 35),
            field(&frame, 34)
        );
        resent += 1;
    }
    let first_number = BACKLOG_MESSAGES + 3;
    for index in 0..TEST_REQUESTS {
        let frame = ok(
            some(
                ok(
                    timeout(Duration::from_secs(10), reader.next()).await,
                    "a Heartbeat arrives",
                ),
                "the stream stays open",
            ),
            "the frame decodes",
        );
        assert_eq!(field(&frame, 35).as_deref(), Some("0"), "a Heartbeat");
        assert_eq!(field(&frame, 34), Some((first_number + index).to_string()));
        assert_eq!(field(&frame, 112), Some(format!("T{}", 3 + index)));
    }
    assert!(
        ok(
            ok(timeout(Duration::from_secs(5), flood).await, "flood ends"),
            "flood joins"
        ),
        "every TestRequest was written"
    );
    assert!(!venue.is_closed(), "the session is still up");
}

/// A store whose page reads take [`SLOW_PAGE`]: a resend whose first step
/// starts after the owed Logout's deadline.
#[derive(Debug)]
struct SlowPageStore(Arc<MemoryStore>);

/// How long [`SlowPageStore`] takes to read a page: longer than the logout
/// timeout of [`test_the_owed_logout_deadline_is_checked_before_each_step`].
const SLOW_PAGE: Duration = Duration::from_millis(500);

#[async_trait]
impl MessageStore for SlowPageStore {
    async fn store(&self, seq: u64, msg_type: &MsgType, message: &[u8]) -> Result<(), StoreError> {
        self.0.store(seq, msg_type, message).await
    }

    async fn get_range(&self, begin: u64, end: u64) -> Result<Vec<StoredMessage>, StoreError> {
        tokio::time::sleep(SLOW_PAGE).await;
        self.0.get_range(begin, end).await
    }

    fn next_sender_seq(&self) -> u64 {
        self.0.next_sender_seq()
    }

    fn next_target_seq(&self) -> u64 {
        self.0.next_target_seq()
    }

    async fn set_next_sender_seq(&self, seq: u64) -> Result<(), StoreError> {
        self.0.set_next_sender_seq(seq).await
    }

    async fn set_next_target_seq(&self, seq: u64) -> Result<(), StoreError> {
        self.0.set_next_target_seq(seq).await
    }

    async fn reset(&self) -> Result<(), StoreError> {
        self.0.reset().await
    }

    fn creation_time(&self) -> std::time::SystemTime {
        self.0.creation_time()
    }
}

/// The owed Logout's deadline is checked before every resend step, not only
/// on the tick: the scripted initiator asks for a 789 resend of 50 reports
/// (one page, one step's worth) and logs out right behind it. The page takes
/// 500 ms to read, longer than the 200 ms logout timeout, so by the step that
/// would feed the whole resend at once the reply is overdue: it goes out
/// without the resend, and no resent frame does.
///
/// After the page read the overdue tick and that step are both ready, and the
/// tick, which also checks the deadline, wins about three times in five; the
/// scenario runs five times so that a step taken without the check would be
/// seen (with probability about 0.92).
#[tokio::test]
async fn test_the_owed_logout_deadline_is_checked_before_each_step() {
    for round in 0..5 {
        owed_logout_past_its_deadline(round).await;
    }
}

/// One run of [`test_the_owed_logout_deadline_is_checked_before_each_step`].
async fn owed_logout_past_its_deadline(round: u32) {
    let (client_io, venue_io) = tokio::io::duplex(64 * 1024);
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config()
            .with_send_next_expected_msg_seq_num(true)
            .with_logout_timeout(Duration::from_millis(200)),
        Arc::clone(&venue_app),
    )
    .with_store(Arc::new(SlowPageStore(venue_backlog(50, 0).await)) as Arc<dyn MessageStore>);
    let mut framed = Framed::new(client_io, FixCodec::new());
    let mut wire = BytesMut::new();
    wire.extend_from_slice(&client_logon_789(3));
    wire.extend_from_slice(&peer_frame("CLIENT", "VENUE", "5", 4, &[]));
    let served = tokio::spawn(async move { acceptor.serve_stream(venue_io).await });
    ok(
        framed.get_mut().write_all(&wire).await,
        "the Logon and the Logout",
    );
    let mut frames = Vec::new();
    while let Ok(Some(Ok(frame))) = timeout(Duration::from_secs(2), framed.next()).await {
        frames.push((field(&frame, 35), field(&frame, 43)));
    }
    let venue = ok(
        ok(
            ok(timeout(Duration::from_secs(5), served).await, "handshake"),
            "venue task joins",
        ),
        "the acceptor established the session",
    );
    assert_eq!(
        frames.last().map(|(msg_type, _)| msg_type.as_deref()),
        Some(Some("5")),
        "round {round}: the Logout reply went out: {frames:?}"
    );
    let resent = frames
        .iter()
        .filter(|(_, poss_dup)| poss_dup.as_deref() == Some("Y"))
        .count();
    assert_eq!(
        resent, 0,
        "round {round}: the overdue reply went out before any resend step"
    );
    ok(
        timeout(Duration::from_secs(5), venue.wait_closed()).await,
        "the session closes",
    );
}

/// PERF ORANGE-01: a live frame is written through as soon as it is fed when
/// the stream takes it, rather than waiting in the buffer while the next
/// message's callback and store call run. 256 orders queued back to back by
/// an initiator with a store attached, over a pipe that always has room, go
/// out in 256 writes: no frame left behind a later frame's store call.
#[tokio::test]
async fn test_live_frames_are_written_through_one_write_each() {
    const ORDERS: u64 = 256;
    let (client_io, venue_io) = tokio::io::duplex(1024 * 1024);
    let client_io = WriteLogStream::new(client_io, Arc::new(AtomicU64::new(0)));
    let writes = Arc::clone(&client_io.writes);
    let (client_app, _client_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(), Arc::clone(&client_app))
        .with_store(Arc::new(MemoryStore::new()) as Arc<dyn MessageStore>)
        .with_outbound_capacity(2 * usize::try_from(ORDERS).unwrap_or(1024));
    let established = tokio::spawn(async move { initiator.establish(client_io).await });
    let mut venue = Framed::new(venue_io, FixCodec::new());
    let logon = next_frame(&mut venue).await;
    assert_eq!(field(&logon, 35).as_deref(), Some("A"));
    ok(
        venue
            .send(peer_frame(
                "VENUE",
                "CLIENT",
                "A",
                1,
                &[(98, "0"), (108, "30")],
            ))
            .await,
        "the venue acknowledges",
    );
    let client = ok(
        ok(
            ok(
                timeout(Duration::from_secs(5), established).await,
                "handshake within 5s",
            ),
            "initiator task joins",
        ),
        "the initiator establishes the session",
    );
    let before = writes.load(Ordering::Relaxed);
    for index in 0..ORDERS {
        let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
        order.push_str(11, &index.to_string());
        ok(client.send(order).await, "an order");
    }
    for _ in 0..ORDERS {
        let frame = next_frame(&mut venue).await;
        assert_eq!(field(&frame, 35).as_deref(), Some("D"));
    }
    assert_eq!(
        writes.load(Ordering::Relaxed) - before,
        ORDERS,
        "each order went out in a write of its own, as soon as it was fed"
    );
}

/// A scripted counterparty that reads its end of a pipe slowly: at most
/// `chunk` bytes per `pause`, so output written to it drains at a known rate.
struct SlowReader {
    io: DuplexStream,
    buf: BytesMut,
    codec: FixCodec,
    chunk: usize,
    pause: Duration,
}

impl SlowReader {
    /// Takes over the venue's end of the pipe once the handshake is done,
    /// keeping whatever the framed reader had already buffered.
    fn new(framed: Framed<DuplexStream, FixCodec>, chunk: usize, pause: Duration) -> Self {
        let parts = framed.into_parts();
        Self {
            io: parts.io,
            buf: parts.read_buf,
            codec: FixCodec::new(),
            chunk,
            pause,
        }
    }

    /// The next frame, read at the slow rate; `None` once the stream ends.
    async fn next(&mut self) -> Option<BytesMut> {
        use tokio::io::AsyncReadExt;
        use tokio_util::codec::Decoder as _;
        loop {
            if let Some(frame) = ok(self.codec.decode(&mut self.buf), "a frame decodes") {
                return Some(frame);
            }
            tokio::time::sleep(self.pause).await;
            let mut chunk = vec![0_u8; self.chunk];
            let read = ok(self.io.read(&mut chunk).await, "the pipe reads");
            if read == 0 {
                return None;
            }
            self.buf
                .extend_from_slice(chunk.get(..read).unwrap_or_default());
        }
    }

    /// Writes `frame` to the initiator at once.
    async fn send(&mut self, frame: BytesMut) {
        ok(self.io.write_all(&frame).await, "the venue writes");
    }
}

/// Logs a client on over a 1 KiB pipe with `config`; the venue acknowledges
/// with `HeartBtInt` (108) `heartbeat_secs`. Returns the connection and the
/// venue's end, read from then on at 1 KiB every 50 ms.
async fn log_on_behind_a_slow_reader(
    config: SessionConfig,
    heartbeat_secs: &str,
) -> (Connection, SlowReader) {
    let (client_io, venue_io) = tokio::io::duplex(1024);
    let (client_app, _client_rx) = RecordingApp::new();
    let initiator =
        Initiator::new(config, Arc::clone(&client_app)).with_write_timeout(Duration::from_secs(10));
    let established = tokio::spawn(async move { initiator.establish(client_io).await });
    let mut venue = Framed::new(venue_io, FixCodec::new());
    let logon = next_frame(&mut venue).await;
    assert_eq!(field(&logon, 35).as_deref(), Some("A"));
    ok(
        venue
            .send(peer_frame(
                "VENUE",
                "CLIENT",
                "A",
                1,
                &[(98, "0"), (108, heartbeat_secs)],
            ))
            .await,
        "the venue acknowledges",
    );
    let client = ok(
        ok(
            ok(
                timeout(Duration::from_secs(5), established).await,
                "handshake within 5s",
            ),
            "initiator task joins",
        ),
        "the initiator establishes the session",
    );
    (
        client,
        SlowReader::new(venue, 1024, Duration::from_millis(50)),
    )
}

/// A report of about `bytes` bytes of `Text` (58).
fn large_report(bytes: usize) -> OutboundMessage {
    let mut report = OutboundMessage::new(MsgType::ExecutionReport);
    report.push_str(58, &"r".repeat(bytes));
    report
}

/// Issue #142: a TestRequest's reply deadline starts when the TestRequest is
/// written whole, not when it is fed. With `HeartBtInt` 1 s the client sends
/// a TestRequest after about 2 s of inbound silence and times out 1 s after
/// it was sent. A 60 KB report sent at once drains at about 20 KB/s, so the
/// TestRequest fed at about 2 s waits behind it for about another second and
/// reaches the venue at about 3 s. The venue answers it at once: the session
/// stays up. (Before the fix the deadline ran from the feed and could expire
/// while the TestRequest was still buffered.)
#[tokio::test]
async fn test_a_buffered_test_request_does_not_time_out_the_session() {
    let config = client_config().with_heartbeat_interval(Duration::from_secs(1));
    let (client, mut venue) = log_on_behind_a_slow_reader(config, "1").await;
    ok(
        client.send(large_report(60_000)).await,
        "the report is queued",
    );
    let started = tokio::time::Instant::now();
    let test_req_id = loop {
        let frame = some(venue.next().await, "the stream stays open");
        if field(&frame, 35).as_deref() == Some("1") {
            break some(field(&frame, 112), "the TestRequest carries a TestReqID");
        }
    };
    assert!(
        started.elapsed() > Duration::from_millis(2_500),
        "the TestRequest waited behind the report past its reply deadline"
    );
    venue
        .send(peer_frame(
            "VENUE",
            "CLIENT",
            "0",
            2,
            &[(112, test_req_id.as_str())],
        ))
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !client.is_closed(),
        "a TestRequest still buffered behind the report did not time the session out"
    );
}

/// Issue #142: a ResendRequest's retry clock starts when the request is
/// written whole. With a single request allowed and a 300 ms retry timeout,
/// the client's ResendRequest is queued behind a 60 KB report that drains in
/// about 3 s. Its clock starts once it reaches the venue, which fills the gap
/// at once: no Logout follows and the session stays up. (Before the fix the
/// clock ran from the feed, so the retries were spent and a Logout queued
/// before the request ever reached the wire.)
#[tokio::test]
async fn test_a_buffered_resend_request_does_not_spend_its_retries() {
    let mut config = client_config();
    config.resend_timeout = Duration::from_millis(300);
    config.max_resend_requests = 1;
    let (client, mut venue) = log_on_behind_a_slow_reader(config, "30").await;
    ok(
        client.send(large_report(60_000)).await,
        "the report is queued",
    );
    // Let the report be fed first, then open a gap: 2 is missing, so the
    // client asks for it behind the report.
    tokio::time::sleep(Duration::from_millis(100)).await;
    venue.send(peer_frame("VENUE", "CLIENT", "0", 3, &[])).await;
    loop {
        let frame = some(venue.next().await, "the stream stays open");
        match field(&frame, 35).as_deref() {
            Some("2") => break,
            Some("5") => panic!("a Logout came before the ResendRequest reached the venue"),
            _ => {}
        }
    }
    let orig = Timestamp::now().format_millis();
    venue
        .send(peer_frame(
            "VENUE",
            "CLIENT",
            "4",
            2,
            &[(43, "Y"), (122, orig.as_str()), (123, "Y"), (36, "4")],
        ))
        .await;
    if let Ok(Some(frame)) = timeout(Duration::from_millis(800), venue.next()).await {
        assert_ne!(
            field(&frame, 35).as_deref(),
            Some("5"),
            "no Logout once the gap is filled"
        );
    }
    assert!(!client.is_closed(), "the session stays up");
}
