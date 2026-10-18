/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Integration tests for issue #63 (ADR-0007): both engines over a byte
//! stream the caller provides, mostly with no TCP at all.
//!
//! `Initiator::establish`, `Acceptor::serve_stream` and
//! `AcceptorRegistry::serve_stream` take any `AsyncRead + AsyncWrite` stream.
//! These tests run them over `tokio::io::duplex` pipes, and over a stream type
//! the engine has never heard of (`TapStream`, a pipe that keeps a copy of
//! what is written through it, standing in for a TLS stream): a full session
//! in both roles (Logon, application messages each way, Logout), a
//! `ResendRequest` answered from the initiator's store, a session routed by a
//! registry that also routes a TCP connection, and `NextExpectedMsgSeqNum`
//! (789) on the wire. The handshake rules hold unchanged on the new entry
//! points: the logon timeout, the write timeout, CompID authentication, the
//! rule that an unauthenticated peer never touches the acceptor's store, and
//! the checks made before the stream is written to. A stream that closes
//! mid-handshake ends in a typed `EngineError` in every entry point, and every
//! entry point's future is `Send`, so it can be spawned. Over TCP, the
//! acceptor entry points are shown to set `TCP_NODELAY` on the socket itself,
//! read through a second handle on it after a real handshake.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::StreamExt;
use ironfix_core::error::StoreError;
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::CompId;
use ironfix_engine::application::{Application, RejectReason, SessionId};
use ironfix_engine::{
    Acceptor, AcceptorRegistry, Connection, EngineError, Initiator, OutboundMessage,
};
use ironfix_session::SessionConfig;
use ironfix_session::sequence::SequenceCounter;
use ironfix_store::{MemoryStore, MessageStore};
use ironfix_tagvalue::Decoder;
use ironfix_transport::{CodecError, FixCodec};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::codec::{Decoder as _, Framed};

/// Capacity of each direction of a test pipe, in bytes.
const PIPE_CAPACITY: usize = 64 * 1024;

/// How long a test waits for any one step before failing.
const STEP: Duration = Duration::from_secs(5);

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

/// The venue's session for `member`: sender is VENUE, target the member.
fn venue_config(member: &str) -> SessionConfig {
    SessionConfig::new(comp_id("VENUE"), comp_id(member), "FIX.4.4")
        .with_heartbeat_interval(Duration::from_secs(30))
}

/// The member's own session: sender is the member, target VENUE.
fn member_config(member: &str) -> SessionConfig {
    SessionConfig::new(comp_id(member), comp_id("VENUE"), "FIX.4.4")
        .with_heartbeat_interval(Duration::from_secs(30))
}

/// An in-memory pipe: (initiator end, acceptor end).
fn pipe() -> (DuplexStream, DuplexStream) {
    tokio::io::duplex(PIPE_CAPACITY)
}

/// An application message as the receiving application saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Received {
    /// The session it was delivered for.
    session: String,
    /// Its MsgType (35).
    msg_type: String,
    /// Its MsgSeqNum (34).
    seq: Option<u64>,
    /// Whether it carried PossDupFlag (43) = Y.
    poss_dup: bool,
}

/// Records the session callbacks in order and forwards every application
/// message. On demand it refuses every Logon in `from_admin`.
#[derive(Debug)]
struct RecordingApp {
    events: Mutex<Vec<String>>,
    app_tx: mpsc::UnboundedSender<Received>,
    refuse_logons: AtomicBool,
}

impl RecordingApp {
    fn new() -> (Arc<Self>, mpsc::UnboundedReceiver<Received>) {
        let (app_tx, app_rx) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                events: Mutex::new(Vec::new()),
                app_tx,
                refuse_logons: AtomicBool::new(false),
            }),
            app_rx,
        )
    }

    #[track_caller]
    fn record(&self, event: &str) {
        match self.events.lock() {
            Ok(mut events) => events.push(event.to_string()),
            Err(_) => panic!("event lock poisoned"),
        }
    }

    #[track_caller]
    fn events(&self) -> Vec<String> {
        match self.events.lock() {
            Ok(events) => events.clone(),
            Err(_) => panic!("event lock poisoned"),
        }
    }
}

#[async_trait]
impl Application for RecordingApp {
    async fn on_create(&self, _session_id: &SessionId) {
        self.record("create");
    }

    async fn on_logon(&self, _session_id: &SessionId) {
        self.record("logon");
    }

    async fn on_logout(&self, _session_id: &SessionId) {
        self.record("logout");
    }

    async fn to_admin(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_admin(
        &self,
        message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        if message.msg_type() == &MsgType::Logon && self.refuse_logons.load(Ordering::SeqCst) {
            return Err(RejectReason::new(0, "credentials refused"));
        }
        Ok(())
    }

    async fn to_app(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_app(
        &self,
        message: &RawMessage<'_>,
        session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        let _ = self.app_tx.send(Received {
            session: session_id.to_string(),
            msg_type: message.msg_type().as_str().to_string(),
            seq: message.get_field_str(34).and_then(|seq| seq.parse().ok()),
            poss_dup: message.get_field_str(43) == Some("Y"),
        });
        Ok(())
    }
}

/// A stream type the engine knows nothing about: a pipe that keeps a copy of
/// every byte written through it. It stands in for any caller-built stream,
/// a TLS stream for one.
#[derive(Debug)]
struct TapStream {
    inner: DuplexStream,
    written: Arc<Mutex<Vec<u8>>>,
}

impl TapStream {
    fn new(inner: DuplexStream) -> Self {
        Self {
            inner,
            written: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// The bytes written through the stream, shared with it.
    fn written(&self) -> Arc<Mutex<Vec<u8>>> {
        Arc::clone(&self.written)
    }
}

impl AsyncRead for TapStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TapStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        let polled = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(count)) = &polled
            && let Some(bytes) = buf.get(..*count)
        {
            match this.written.lock() {
                Ok(mut written) => written.extend_from_slice(bytes),
                Err(_) => panic!("tap lock poisoned"),
            }
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Splits the bytes a tap recorded into FIX frames.
#[track_caller]
fn frames(tap: &Mutex<Vec<u8>>) -> Vec<BytesMut> {
    let bytes = match tap.lock() {
        Ok(written) => written.clone(),
        Err(_) => panic!("tap lock poisoned"),
    };
    let mut buf = BytesMut::from(&bytes[..]);
    let mut codec = FixCodec::new();
    let mut frames = Vec::new();
    while let Some(frame) = ok(codec.decode(&mut buf), "recorded bytes must frame") {
        frames.push(frame);
    }
    frames
}

/// Extracts a field from a framed message.
fn field(frame: &[u8], tag: u32) -> Option<String> {
    let mut decoder = Decoder::new(frame);
    match decoder.decode() {
        Ok(raw) => raw.get_field_str(tag).map(str::to_string),
        Err(_) => None,
    }
}

/// Awaits a spawned task within [`STEP`].
async fn joined<T>(task: tokio::task::JoinHandle<T>, what: &str) -> T {
    ok(ok(timeout(STEP, task).await, what), what)
}

/// Receives the next application message within [`STEP`].
async fn received(rx: &mut mpsc::UnboundedReceiver<Received>) -> Received {
    some(
        ok(
            timeout(STEP, rx.recv()).await,
            "an application message arrives within 5s",
        ),
        "the application channel must stay open",
    )
}

/// Sends a NewOrderSingle on `connection`.
async fn send_order(connection: &Connection, id: &str) {
    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order
        .push_str(11, id)
        .push_str(55, "EUR/USD")
        .push_char(54, '1')
        .push_uint(38, 100);
    ok(connection.send(order).await, "the member sends an order");
}

/// Sends an ExecutionReport on `connection`.
async fn send_report(connection: &Connection, id: &str) {
    let mut exec = OutboundMessage::new(MsgType::ExecutionReport);
    exec.push_str(37, id)
        .push_str(17, id)
        .push_char(150, '0')
        .push_char(39, '0');
    ok(connection.send(exec).await, "the venue sends a report");
}

/// Logs `initiator` out and waits for both ends of the session to close.
async fn log_out(initiator: &Connection, acceptor: &Connection) {
    ok(initiator.logout().await, "the initiator logs out");
    ok(
        timeout(STEP, initiator.wait_closed()).await,
        "the initiator session closes within 5s",
    );
    ok(
        timeout(STEP, acceptor.wait_closed()).await,
        "the acceptor session closes within 5s",
    );
}

/// Asserts that nothing at all was written to the other end of `peer`
/// before it closed.
async fn assert_nothing_written(mut peer: DuplexStream) {
    let mut bytes = Vec::new();
    let read = ok(
        ok(
            timeout(STEP, peer.read_to_end(&mut bytes)).await,
            "the stream is closed within 5s",
        ),
        "the closed stream reads to its end",
    );
    assert_eq!(read, 0, "nothing was written: {bytes:?}");
}

/// The acceptance test for issue #63: an `Initiator` and an `Acceptor` run a
/// whole session over an in-memory pipe, with no socket anywhere. Logon, an
/// application message each way, and a graceful Logout, with the callbacks in
/// order on both sides.
#[tokio::test]
async fn test_duplex_initiator_and_acceptor_run_a_full_session() {
    let (client_io, venue_io) = pipe();
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let (member_app, mut member_rx) = RecordingApp::new();

    let acceptor = Acceptor::new(venue_config("CLIENT"), Arc::clone(&venue_app));
    let served = tokio::spawn(async move { acceptor.serve_stream(venue_io).await });
    let member = ok(
        Initiator::new(member_config("CLIENT"), Arc::clone(&member_app))
            .establish(client_io)
            .await,
        "the initiator logs on over the pipe",
    );
    let venue = ok(
        joined(served, "the acceptor handshake ends").await,
        "the acceptor logs on over the pipe",
    );
    assert_eq!(venue.session_id().to_string(), "FIX.4.4:VENUE->CLIENT");

    send_order(&member, "ORDER-1").await;
    let order = received(&mut venue_rx).await;
    assert_eq!(order.msg_type, "D");
    assert_eq!(order.seq, Some(2), "the order follows the Logon");
    assert!(!order.poss_dup);

    send_report(&venue, "EX-1").await;
    let report = received(&mut member_rx).await;
    assert_eq!(report.msg_type, "8");
    assert_eq!(
        report.seq,
        Some(2),
        "the report follows the acknowledgement"
    );

    assert_eq!(member.next_sender_seq(), 3);
    assert_eq!(member.next_target_seq(), 3);
    assert_eq!(venue.next_sender_seq(), 3);
    assert_eq!(venue.next_target_seq(), 3);

    log_out(&member, &venue).await;
    assert_eq!(member_app.events(), ["create", "logon", "logout"]);
    assert_eq!(venue_app.events(), ["create", "logon", "logout"]);
}

/// A `ResendRequest` over a pipe is answered from the initiator's store. The
/// first session files the initiator's Logon (1), an order (2) and its Logout
/// (3). The second, against a venue that expects 2 again, opens with the
/// initiator's Logon at 4: the venue requests the gap, the order is replayed
/// as a possible duplicate, the Logout and the Logon are gap-filled, and the
/// next order arrives in sequence.
#[tokio::test]
async fn test_duplex_resend_request_is_replayed_from_the_store() {
    let store = Arc::new(MemoryStore::new());
    let (member_app, _member_rx) = RecordingApp::new();
    let initiator = Initiator::new(member_config("CLIENT"), member_app)
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);

    // First session: Logon (1), the order (2), Logout (3).
    let (client_io, venue_io) = pipe();
    let (first_app, mut first_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(venue_config("CLIENT"), first_app);
    let served = tokio::spawn(async move { acceptor.serve_stream(venue_io).await });
    let member = ok(
        initiator.establish(client_io).await,
        "the first session logs on",
    );
    let venue = ok(
        joined(served, "the first acceptor handshake ends").await,
        "the first acceptor logs on",
    );
    send_order(&member, "ORDER-1").await;
    let first = received(&mut first_rx).await;
    assert_eq!((first.seq, first.poss_dup), (Some(2), false));
    log_out(&member, &venue).await;
    assert_eq!(store.next_sender_seq(), 4, "Logon, order and Logout filed");
    let venue_next_sender = venue.next_sender_seq();

    // Second session: the venue expects the order's number again.
    let (client_io, venue_io) = pipe();
    let (second_app, mut second_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(venue_config("CLIENT"), Arc::clone(&second_app))
        .with_initial_sequences(venue_next_sender, 2);
    let served = tokio::spawn(async move { acceptor.serve_stream(venue_io).await });
    let member = ok(
        initiator.establish(client_io).await,
        "the second session logs on at 4",
    );
    let venue = ok(
        joined(served, "the second acceptor handshake ends").await,
        "the second acceptor logs on",
    );

    let replayed = received(&mut second_rx).await;
    assert_eq!(replayed.msg_type, "D");
    assert_eq!(replayed.seq, Some(2), "the stored order, under its number");
    assert!(replayed.poss_dup, "a replay carries PossDupFlag (43) = Y");

    send_order(&member, "ORDER-2").await;
    let fresh = received(&mut second_rx).await;
    assert_eq!(
        (fresh.seq, fresh.poss_dup),
        (Some(5), false),
        "the gap fill covered the Logout (3) and the Logon (4)"
    );
    assert_eq!(venue.next_target_seq(), 6);

    log_out(&member, &venue).await;
    assert_eq!(second_app.events(), ["create", "logon", "logout"]);
}

/// A registry routes a session that arrives over a pipe, beside one that
/// arrives over TCP: the stream type plays no part in routing.
#[tokio::test]
async fn test_registry_routes_a_duplex_session_beside_a_tcp_one() {
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let registry = Arc::new(AcceptorRegistry::new());
    for member in ["MEMBER_A", "MEMBER_B"] {
        ok(
            registry.register(Acceptor::new(venue_config(member), Arc::clone(&venue_app))),
            "the session registers",
        );
    }

    // MEMBER_A over TCP.
    let listener = ok(TcpListener::bind("127.0.0.1:0").await, "bind loopback");
    let addr = ok(listener.local_addr(), "listener address");
    let tcp_served = {
        let registry = Arc::clone(&registry);
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            registry.serve(stream).await
        })
    };
    let (member_a_app, _member_a_rx) = RecordingApp::new();
    let member_a = ok(
        Initiator::new(member_config("MEMBER_A"), member_a_app)
            .connect(addr)
            .await,
        "MEMBER_A logs on over TCP",
    );
    let venue_a = ok(
        joined(tcp_served, "the TCP handshake ends").await,
        "the TCP session is routed",
    );

    // MEMBER_B over a pipe.
    let (client_io, venue_io) = pipe();
    let duplex_served = {
        let registry = Arc::clone(&registry);
        tokio::spawn(async move { registry.serve_stream(venue_io).await })
    };
    let (member_b_app, mut member_b_rx) = RecordingApp::new();
    let member_b = ok(
        Initiator::new(member_config("MEMBER_B"), member_b_app)
            .establish(client_io)
            .await,
        "MEMBER_B logs on over the pipe",
    );
    let venue_b = ok(
        joined(duplex_served, "the pipe handshake ends").await,
        "the pipe session is routed",
    );

    assert_eq!(venue_a.session_id().to_string(), "FIX.4.4:VENUE->MEMBER_A");
    assert_eq!(venue_b.session_id().to_string(), "FIX.4.4:VENUE->MEMBER_B");

    send_order(&member_b, "ORDER-B").await;
    let order = received(&mut venue_rx).await;
    assert_eq!(order.session, "FIX.4.4:VENUE->MEMBER_B");
    assert_eq!((order.msg_type.as_str(), order.seq), ("D", Some(2)));

    send_report(&venue_b, "EX-B").await;
    let report = received(&mut member_b_rx).await;
    assert_eq!(report.msg_type, "8");

    log_out(&member_b, &venue_b).await;
    log_out(&member_a, &venue_a).await;
}

/// A stream type of the caller's own carries the Logon exchange byte for
/// byte, `NextExpectedMsgSeqNum` (789) included, when both sides use it.
#[tokio::test]
async fn test_custom_stream_carries_next_expected_msg_seq_num() {
    let (client_io, venue_io) = pipe();
    let client_tap = TapStream::new(client_io);
    let venue_tap = TapStream::new(venue_io);
    let client_written = client_tap.written();
    let venue_written = venue_tap.written();

    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config("CLIENT").with_send_next_expected_msg_seq_num(true),
        venue_app,
    );
    let served = tokio::spawn(async move { acceptor.serve_stream(venue_tap).await });
    let (member_app, _member_rx) = RecordingApp::new();
    let member = ok(
        Initiator::new(
            member_config("CLIENT").with_send_next_expected_msg_seq_num(true),
            member_app,
        )
        .establish(client_tap)
        .await,
        "the initiator logs on over its own stream type",
    );
    let venue = ok(
        joined(served, "the acceptor handshake ends").await,
        "the acceptor logs on over its own stream type",
    );

    let logon = some(
        frames(&client_written).into_iter().next(),
        "the initiator wrote its Logon through the tap",
    );
    assert_eq!(field(&logon, 35).as_deref(), Some("A"));
    assert_eq!(field(&logon, 789).as_deref(), Some("1"));
    let ack = some(
        frames(&venue_written).into_iter().next(),
        "the acceptor wrote its acknowledgement through the tap",
    );
    assert_eq!(field(&ack, 35).as_deref(), Some("A"));
    assert_eq!(
        field(&ack, 789).as_deref(),
        Some("2"),
        "the Logon (1) is consumed"
    );

    log_out(&member, &venue).await;
}

/// The initiator's stream closes mid-handshake: after the Logon is read, and
/// before it can even be written. Each ends in a typed error, and `on_logon`
/// never runs.
#[tokio::test]
async fn test_establish_stream_closing_mid_handshake_is_a_typed_error() {
    // The peer reads the Logon and goes away without acknowledging it.
    let (client_io, peer_io) = pipe();
    let (app, _rx) = RecordingApp::new();
    let initiator = Initiator::new(member_config("CLIENT"), Arc::clone(&app));
    let peer = tokio::spawn(async move {
        let mut framed = Framed::new(peer_io, FixCodec::new());
        let logon = ok(
            some(
                ok(timeout(STEP, framed.next()).await, "the Logon arrives"),
                "the stream stays open",
            ),
            "the Logon frames",
        );
        field(&logon, 35)
    });
    let result = timeout(STEP, initiator.establish(client_io)).await;
    assert_eq!(joined(peer, "the peer ends").await.as_deref(), Some("A"));
    assert!(matches!(result, Ok(Err(EngineError::Closed))), "{result:?}");
    assert_eq!(app.events(), ["create"]);

    // The peer is gone before the Logon is written.
    let (client_io, peer_io) = pipe();
    drop(peer_io);
    let (app, _rx) = RecordingApp::new();
    let initiator = Initiator::new(member_config("CLIENT"), Arc::clone(&app));
    let result = timeout(STEP, initiator.establish(client_io)).await;
    assert!(
        matches!(result, Ok(Err(EngineError::Codec(CodecError::Io(_))))),
        "{result:?}"
    );
    assert_eq!(app.events(), ["create"]);
}

/// The acceptor's stream closes mid-handshake: before any byte, and partway
/// through the Logon. Each ends in a typed error, and `on_logon` never runs.
#[tokio::test]
async fn test_serve_stream_closing_mid_handshake_is_a_typed_error() {
    // The peer goes away before sending anything.
    let (peer_io, venue_io) = pipe();
    drop(peer_io);
    let (app, _rx) = RecordingApp::new();
    let acceptor = Acceptor::new(venue_config("CLIENT"), Arc::clone(&app));
    let result = timeout(STEP, acceptor.serve_stream(venue_io)).await;
    assert!(matches!(result, Ok(Err(EngineError::Closed))), "{result:?}");
    assert_eq!(app.events(), ["create"]);

    // The peer goes away partway through its Logon.
    let (mut peer_io, venue_io) = pipe();
    ok(
        peer_io
            .write_all(b"8=FIX.4.4\x019=72\x0135=A\x0134=1\x01")
            .await,
        "the peer writes half a Logon",
    );
    drop(peer_io);
    let result = timeout(STEP, acceptor.serve_stream(venue_io)).await;
    assert!(
        matches!(result, Ok(Err(EngineError::Codec(CodecError::Io(_))))),
        "{result:?}"
    );
    assert_eq!(app.events(), ["create", "create"]);
}

/// The registry's stream closes before the Logon is routed: before any byte,
/// and partway through the Logon. Each ends in a typed error, and no callback
/// runs, since no session was chosen.
#[tokio::test]
async fn test_registry_serve_stream_closing_mid_handshake_is_a_typed_error() {
    let (app, _rx) = RecordingApp::new();
    let registry = AcceptorRegistry::new();
    ok(
        registry.register(Acceptor::new(venue_config("CLIENT"), Arc::clone(&app))),
        "the session registers",
    );

    let (peer_io, venue_io) = pipe();
    drop(peer_io);
    let result = timeout(STEP, registry.serve_stream(venue_io)).await;
    assert!(matches!(result, Ok(Err(EngineError::Closed))), "{result:?}");

    let (mut peer_io, venue_io) = pipe();
    ok(
        peer_io.write_all(b"8=FIX.4.4\x019=72\x0135=A\x01").await,
        "the peer writes half a Logon",
    );
    drop(peer_io);
    let result = timeout(STEP, registry.serve_stream(venue_io)).await;
    assert!(
        matches!(result, Ok(Err(EngineError::Codec(CodecError::Io(_))))),
        "{result:?}"
    );
    assert!(app.events().is_empty(), "{:?}", app.events());
}

/// The write timeout bounds a write into a stream nobody reads, as it bounds
/// one into a TCP socket whose peer stopped reading.
#[tokio::test]
async fn test_establish_write_into_an_unread_stream_times_out() {
    // A pipe too small for the Logon, whose other end is held but never read.
    let (client_io, _unread) = tokio::io::duplex(16);
    let (app, _rx) = RecordingApp::new();
    let write_timeout = Duration::from_millis(200);
    let initiator =
        Initiator::new(member_config("CLIENT"), Arc::clone(&app)).with_write_timeout(write_timeout);
    let result = timeout(STEP, initiator.establish(client_io)).await;
    assert!(
        matches!(result, Ok(Err(EngineError::WriteTimeout(bound))) if bound == write_timeout),
        "{result:?}"
    );
    assert_eq!(app.events(), ["create"]);
}

/// The logon timeout bounds both handshakes on a stream that stays open and
/// silent.
#[tokio::test]
async fn test_stream_handshakes_are_bounded_by_the_logon_timeout() {
    let logon_timeout = Duration::from_millis(300);

    // The initiator's Logon is read and never acknowledged.
    let (client_io, peer_io) = pipe();
    let (app, _rx) = RecordingApp::new();
    let initiator = Initiator::new(
        member_config("CLIENT").with_logon_timeout(logon_timeout),
        Arc::clone(&app),
    );
    let (result, _held) = tokio::join!(timeout(STEP, initiator.establish(client_io)), async {
        let mut framed = Framed::new(peer_io, FixCodec::new());
        let _ = timeout(STEP, framed.next()).await;
        framed
    });
    assert!(
        matches!(result, Ok(Err(EngineError::LogonTimeout(bound))) if bound == logon_timeout),
        "{result:?}"
    );
    assert_eq!(app.events(), ["create"]);

    // No Logon ever reaches the acceptor.
    let (_silent, venue_io) = pipe();
    let (app, _rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config("CLIENT").with_logon_timeout(logon_timeout),
        Arc::clone(&app),
    );
    let result = timeout(STEP, acceptor.serve_stream(venue_io)).await;
    assert!(
        matches!(result, Ok(Err(EngineError::LogonTimeout(bound))) if bound == logon_timeout),
        "{result:?}"
    );
    assert_eq!(app.events(), ["create"]);
}

/// CompID authentication holds on a stream: a Logon from a counterparty the
/// session does not expect is refused, and neither side reaches `on_logon`.
#[tokio::test]
async fn test_serve_stream_refuses_the_wrong_comp_ids() {
    let (client_io, venue_io) = pipe();
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(venue_config("CLIENT"), Arc::clone(&venue_app));
    let (intruder_app, _intruder_rx) = RecordingApp::new();
    let intruder = Initiator::new(member_config("INTRUDER"), Arc::clone(&intruder_app));

    let (served, established) = tokio::join!(
        timeout(STEP, acceptor.serve_stream(venue_io)),
        timeout(STEP, intruder.establish(client_io)),
    );
    assert!(
        matches!(served, Ok(Err(EngineError::IdentityMismatch { .. }))),
        "{served:?}"
    );
    assert!(
        matches!(established, Ok(Err(EngineError::LogonRejected { .. }))),
        "{established:?}"
    );
    assert_eq!(venue_app.events(), ["create"]);
    assert_eq!(intruder_app.events(), ["create"]);
}

/// ADR-0017 holds on a stream: with a store attached, a Logon `from_admin`
/// refuses is closed without a reply and the store is not touched, not even
/// by the `ResetSeqNumFlag` (141) the Logon declares.
#[tokio::test]
async fn test_serve_stream_unauthenticated_logon_never_touches_the_store() {
    let store = Arc::new(MemoryStore::new());
    ok(
        store.set_next_sender_seq(5).await,
        "the store holds an earlier stream",
    );
    let (venue_app, _venue_rx) = RecordingApp::new();
    venue_app.refuse_logons.store(true, Ordering::SeqCst);
    let acceptor = Acceptor::new(venue_config("CLIENT"), Arc::clone(&venue_app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let (member_app, _member_rx) = RecordingApp::new();
    let initiator = Initiator::new(
        member_config("CLIENT").with_reset_on_logon(true),
        member_app,
    );

    let (client_io, venue_io) = pipe();
    let (served, established) = tokio::join!(
        timeout(STEP, acceptor.serve_stream(venue_io)),
        timeout(STEP, initiator.establish(client_io)),
    );
    assert!(
        matches!(served, Ok(Err(EngineError::LogonRejected { .. }))),
        "{served:?}"
    );
    assert!(
        matches!(established, Ok(Err(EngineError::Closed))),
        "closed without a reply: {established:?}"
    );
    assert_eq!(store.next_sender_seq(), 5, "the store was not reset");
    let filed = store.get_range(1, 10).await;
    assert!(
        matches!(filed, Err(StoreError::RangeNotAvailable { .. })),
        "nothing was filed: {filed:?}"
    );
    assert_eq!(venue_app.events(), ["create"]);
}

/// The checks that need no connection are made before the stream is written
/// to: the stream is closed without a byte, and no callback runs.
#[tokio::test]
async fn test_stream_entry_points_refuse_before_writing() {
    // A zero sender seed the initiator would use.
    let (client_io, peer_io) = pipe();
    let (app, _rx) = RecordingApp::new();
    let initiator =
        Initiator::new(member_config("CLIENT"), Arc::clone(&app)).with_initial_sequences(0, 1);
    let result = initiator.establish(client_io).await;
    assert!(
        matches!(
            result,
            Err(EngineError::InvalidInitialSequence {
                counter: SequenceCounter::Sender
            })
        ),
        "{result:?}"
    );
    assert_nothing_written(peer_io).await;
    assert!(app.events().is_empty(), "{:?}", app.events());

    // A version the acceptor cannot frame.
    let (peer_io, venue_io) = pipe();
    let (app, _rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        SessionConfig::new(comp_id("VENUE"), comp_id("CLIENT"), "FIX.9.9"),
        Arc::clone(&app),
    );
    let result = acceptor.serve_stream(venue_io).await;
    assert!(
        matches!(result, Err(EngineError::UnsupportedVersion { .. })),
        "{result:?}"
    );
    assert_nothing_written(peer_io).await;
    assert!(app.events().is_empty(), "{:?}", app.events());
}

/// Accepts one connection on `listener`, with `TCP_NODELAY` cleared, and
/// returns it together with a second handle on the same socket, through
/// which its options can still be read once an engine owns the first.
async fn accept_with_probe(listener: &TcpListener) -> (TcpStream, std::net::TcpStream) {
    let (accepted, _) = ok(listener.accept().await, "accept loopback");
    ok(
        accepted.set_nodelay(false),
        "start with Nagle's algorithm on",
    );
    let accepted = ok(accepted.into_std(), "take the socket out of Tokio");
    let probe = ok(accepted.try_clone(), "a second handle on the socket");
    let stream = ok(
        TcpStream::from_std(accepted),
        "hand the socket back to Tokio",
    );
    (stream, probe)
}

/// The TCP entry points set `TCP_NODELAY` on the socket they are given,
/// checked on the socket itself after a real handshake, through a second
/// handle on it: `Acceptor::serve` and `AcceptorRegistry::serve`. The
/// initiator's dialled socket is never handed to the caller, so
/// `Initiator::connect` is covered by the unit test of the constructor it
/// calls, the only way a TCP session is built.
#[tokio::test]
async fn test_tcp_entry_points_set_nodelay_on_the_socket() {
    let listener = ok(TcpListener::bind("127.0.0.1:0").await, "bind loopback");
    let addr = ok(listener.local_addr(), "listener address");

    // Acceptor::serve.
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(venue_config("CLIENT"), venue_app);
    let (member_app, _member_rx) = RecordingApp::new();
    let initiator = Initiator::new(member_config("CLIENT"), member_app);
    let ((served, probe), member) = tokio::join!(
        async {
            let (stream, probe) = accept_with_probe(&listener).await;
            (timeout(STEP, acceptor.serve(stream)).await, probe)
        },
        timeout(STEP, initiator.connect(addr)),
    );
    let venue = ok(ok(served, "within 5s"), "Acceptor::serve logs on");
    let member = ok(ok(member, "within 5s"), "the initiator logs on");
    assert!(
        ok(probe.nodelay(), "read TCP_NODELAY"),
        "Acceptor::serve sets TCP_NODELAY"
    );
    drop(probe);
    log_out(&member, &venue).await;

    // AcceptorRegistry::serve.
    let (venue_app, _venue_rx) = RecordingApp::new();
    let registry = AcceptorRegistry::new();
    ok(
        registry.register(Acceptor::new(venue_config("MEMBER_A"), venue_app)),
        "the session registers",
    );
    let (member_app, _member_rx) = RecordingApp::new();
    let initiator = Initiator::new(member_config("MEMBER_A"), member_app);
    let ((served, probe), member) = tokio::join!(
        async {
            let (stream, probe) = accept_with_probe(&listener).await;
            (timeout(STEP, registry.serve(stream)).await, probe)
        },
        timeout(STEP, initiator.connect(addr)),
    );
    let venue = ok(ok(served, "within 5s"), "AcceptorRegistry::serve logs on");
    let member = ok(ok(member, "within 5s"), "the initiator logs on");
    assert!(
        ok(probe.nodelay(), "read TCP_NODELAY"),
        "AcceptorRegistry::serve sets TCP_NODELAY"
    );
    drop(probe);
    log_out(&member, &venue).await;
}

/// A `TcpStream` can be handed to the stream entry points like any other
/// stream, in both roles: it is erased like the rest, and the session runs.
#[tokio::test]
async fn test_serve_stream_accepts_a_tcp_stream() {
    let listener = ok(TcpListener::bind("127.0.0.1:0").await, "bind loopback");
    let addr = ok(listener.local_addr(), "listener address");
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(venue_config("CLIENT"), venue_app);
    let served = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        acceptor.serve_stream(stream).await
    });
    let stream = ok(TcpStream::connect(addr).await, "dial loopback");
    let (member_app, _member_rx) = RecordingApp::new();
    let member = ok(
        Initiator::new(member_config("CLIENT"), member_app)
            .establish(stream)
            .await,
        "the initiator logs on over a socket it dialled itself",
    );
    let venue = ok(
        joined(served, "the acceptor handshake ends").await,
        "the acceptor logs on",
    );
    log_out(&member, &venue).await;
}

/// Asserts at compile time that `value` can move to another thread.
fn assert_send<T: Send>(_value: &T) {}

/// The futures of the three stream entry points can be spawned: each is
/// `Send` for a `Send` stream, as the TCP ones are.
#[tokio::test]
async fn test_stream_entry_point_futures_are_send() {
    let (app, _rx) = RecordingApp::new();
    let initiator = Initiator::new(member_config("CLIENT"), Arc::clone(&app));
    let acceptor = Acceptor::new(venue_config("CLIENT"), Arc::clone(&app));
    let registry: AcceptorRegistry<RecordingApp> = AcceptorRegistry::new();

    let (client_io, venue_io) = pipe();
    let establishing = initiator.establish(client_io);
    assert_send(&establishing);
    let serving = acceptor.serve_stream(venue_io);
    assert_send(&serving);
    let (_peer_io, routed_io) = pipe();
    let routing = registry.serve_stream(routed_io);
    assert_send(&routing);
    // Never polled: dropping them drops the streams unused.
    drop((establishing, serving, routing));
    assert!(app.events().is_empty(), "{:?}", app.events());
}
