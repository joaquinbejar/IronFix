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
//! - a resend completes while the counterparty keeps the inbound side busy
//!   with a continuous stream of Heartbeats;
//! - the write timeout still closes a session whose peer stops reading.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::application::{Application, RejectReason, SessionId};
use ironfix_engine::{Acceptor, Connection, Initiator, OutboundMessage};
use ironfix_session::SessionConfig;
use ironfix_store::{MemoryStore, MessageStore};
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
use tokio_util::codec::Framed;

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

/// The acceptor's previous stream: its Logon ack (1) and [`OWED_REPORTS`]
/// reports (2 to 301); next sender 302, next target 3.
async fn venue_report_backlog() -> Arc<MemoryStore> {
    let store = Arc::new(MemoryStore::new());
    let ack = peer_frame("VENUE", "CLIENT", "A", 1, &[(98, "0"), (108, "30")]);
    ok(store.store(1, &MsgType::Logon, &ack).await, "seed the ack");
    for seq in 2..=OWED_REPORTS + 1 {
        let report = peer_frame(
            "VENUE",
            "CLIENT",
            "8",
            seq,
            &[(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")],
        );
        ok(
            store.store(seq, &MsgType::ExecutionReport, &report).await,
            "seed a report",
        );
    }
    ok(
        store.set_next_sender_seq(OWED_REPORTS + 2).await,
        "seed the sender counter",
    );
    ok(
        store.set_next_target_seq(3).await,
        "seed the target counter",
    );
    store
}

/// Reads the next frame from a scripted peer's end of a pipe, within 10 s.
async fn next_frame(framed: &mut Framed<DuplexStream, FixCodec>) -> BytesMut {
    let polled = ok(
        timeout(Duration::from_secs(10), framed.next()).await,
        "a frame arrives within 10s",
    );
    ok(some(polled, "the stream stays open"), "the frame decodes")
}

/// The engine's end of a pipe, logging after every write how many bytes it
/// has written in all and how many Heartbeats its `from_admin` had seen by
/// then: the order of the reactor's own writes and reads, whatever the
/// scheduler did with the test's task meanwhile.
struct WriteLogStream {
    inner: DuplexStream,
    heartbeats: Arc<AtomicU64>,
    written: usize,
    log: Arc<Mutex<Vec<(usize, u64)>>>,
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
/// until it has read them all. The resend still goes out, in order, before
/// the acceptor has read even a tenth of the Heartbeats: reads and resend
/// writes share the reactor in a bounded ratio, so neither waits for the
/// other to run dry. (Before #126 the resend was written only once inbound
/// was idle, so here only after all 20 000.)
#[tokio::test]
async fn test_resend_progresses_under_a_continuous_inbound_stream() {
    // Large enough for the Logon and every Heartbeat, so the whole stream is
    // on the wire before the acceptor reads its first byte.
    let (client_io, venue_io) = tokio::io::duplex(8 * 1024 * 1024);
    let (venue_app, _venue_rx) = RecordingApp::new();
    let log = Arc::new(Mutex::new(Vec::new()));
    let venue_io = WriteLogStream {
        inner: venue_io,
        heartbeats: Arc::clone(&venue_app.heartbeats),
        written: 0,
        log: Arc::clone(&log),
    };
    let acceptor = Acceptor::new(
        venue_config().with_send_next_expected_msg_seq_num(true),
        Arc::clone(&venue_app),
    )
    .with_store(venue_report_backlog().await as Arc<dyn MessageStore>);

    let mut wire = BytesMut::new();
    wire.extend_from_slice(&peer_frame(
        "CLIENT",
        "VENUE",
        "A",
        3,
        &[(98, "0"), (108, "30"), (789, "2")],
    ));
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

/// A scripted initiator logs on with 789 = 2 and then never reads again, over
/// a pipe smaller than the resend it is owed: the acceptor's writes make no
/// progress, and the write timeout closes the session rather than leaving it
/// open with its output stuck.
#[tokio::test]
async fn test_a_resend_the_peer_never_reads_is_closed_by_the_write_timeout() {
    let write_timeout = Duration::from_millis(300);
    let (client_io, venue_io) = tokio::io::duplex(PIPE_BYTES);
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config().with_send_next_expected_msg_seq_num(true),
        Arc::clone(&venue_app),
    )
    .with_store(venue_report_backlog().await as Arc<dyn MessageStore>)
    .with_write_timeout(write_timeout);
    let served = tokio::spawn(async move { acceptor.serve_stream(venue_io).await });
    let mut framed = Framed::new(client_io, FixCodec::new());
    ok(
        framed
            .send(peer_frame(
                "CLIENT",
                "VENUE",
                "A",
                3,
                &[(98, "0"), (108, "30"), (789, "2")],
            ))
            .await,
        "the client logs on",
    );
    let ack = next_frame(&mut framed).await;
    assert_eq!(field(&ack, 35).as_deref(), Some("A"));
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
    // The client holds its end open and reads nothing more.
    ok(
        timeout(Duration::from_secs(5), venue.wait_closed()).await,
        "the write timeout closes the session",
    );
    drop(framed);
}
