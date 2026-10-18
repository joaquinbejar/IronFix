/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 14/7/26
******************************************************************************/

//! Integration tests for the `Initiator`: dial, Logon handshake, message
//! exchange, heartbeats, sequence recovery, garbled inbound frames, and
//! teardown against a stub acceptor.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::error::StoreError;
use ironfix_core::message::MsgType;
use ironfix_core::message::RawMessage;
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::application::{Application, RejectReason, SessionId};
use ironfix_engine::{EngineError, Initiator, OutboundMessage, StoreFailurePolicy};
use ironfix_session::sequence::SequenceCounter;
use ironfix_session::{GarbledFrameLimit, SessionConfig, SessionConfigError};
use ironfix_store::{FileStore, FileStoreConfig, MemoryStore, MessageStore, StoredMessage};
use ironfix_tagvalue::{Decoder, Encoder};
use ironfix_transport::FixCodec;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::codec::Framed;

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

/// Stub-acceptor side frame builder (VENUE -> CLIENT).
fn venue_msg(msg_type: &str, seq: u64, extra: &[(u32, &str)]) -> BytesMut {
    venue_msg_from("VENUE", "CLIENT", msg_type, seq, extra)
}

/// Stub-acceptor side frame builder with explicit CompIDs, for identity
/// validation tests.
fn venue_msg_from(
    sender: &str,
    target: &str,
    msg_type: &str,
    seq: u64,
    extra: &[(u32, &str)],
) -> BytesMut {
    let mut encoder = Encoder::new("FIX.4.4");
    encoder.put_str(35, msg_type);
    encoder.put_str(49, sender);
    encoder.put_str(56, target);
    encoder.put_uint(34, seq);
    encoder.put_str(52, Timestamp::now().format_millis().as_str());
    for (tag, value) in extra {
        encoder.put_str(*tag, value);
    }
    frame_of(&mut encoder)
}

/// Stub-acceptor frame with an explicit `SendingTime` (52), for clock-skew
/// validation tests. Unlike [`venue_msg`], the timestamp is not overwritten
/// with the current clock.
fn venue_msg_at(msg_type: &str, seq: u64, sending_time: &str, extra: &[(u32, &str)]) -> BytesMut {
    let mut encoder = Encoder::new("FIX.4.4");
    encoder.put_str(35, msg_type);
    encoder.put_str(49, "VENUE");
    encoder.put_str(56, "CLIENT");
    encoder.put_uint(34, seq);
    encoder.put_str(52, sending_time);
    for (tag, value) in extra {
        encoder.put_str(*tag, value);
    }
    frame_of(&mut encoder)
}

/// Returns the finished frame, failing the test with the encoder's rejection.
#[track_caller]
fn frame_of(encoder: &mut Encoder) -> BytesMut {
    let mut frame = BytesMut::new();
    match encoder.finish_into(&mut frame) {
        Ok(()) => frame,
        Err(err) => panic!("test fixture frame must encode: {err}"),
    }
}

/// Builds a frame around `body` with a correct BodyLength and CheckSum,
/// bypassing the encoder's conformance checks.
///
/// The encoder refuses to stamp a frame whose first body field is not MsgType,
/// which is exactly the malformed input some of these tests must put on the
/// wire.
fn raw_frame(body: &[u8]) -> BytesMut {
    let mut frame = Vec::with_capacity(body.len() + 32);
    frame.extend_from_slice(b"8=FIX.4.4\x01");
    frame.extend_from_slice(format!("9={}\x01", body.len()).as_bytes());
    frame.extend_from_slice(body);
    let sum: u64 = frame.iter().map(|&b| u64::from(b)).sum();
    frame.extend_from_slice(format!("10={:03}\x01", (sum % 256) as u8).as_bytes());
    BytesMut::from(&frame[..])
}

/// Extracts a field from a framed message.
fn field(frame: &[u8], tag: u32) -> Option<String> {
    let mut decoder = Decoder::new(frame);
    match decoder.decode() {
        Ok(raw) => raw.get_field_str(tag).map(str::to_string),
        Err(_) => None,
    }
}

#[track_caller]
fn msg_type_of(frame: &[u8]) -> String {
    some(field(frame, 35), "frame must carry MsgType (35)")
}

fn client_config(heartbeat: Duration) -> SessionConfig {
    SessionConfig::new(comp_id("CLIENT"), comp_id("VENUE"), "FIX.4.4")
        .with_heartbeat_interval(heartbeat)
}

async fn accept_framed(listener: TcpListener) -> Framed<TcpStream, FixCodec> {
    let (socket, _) = ok(listener.accept().await, "acceptor must accept");
    Framed::new(socket, FixCodec::new())
}

async fn next_frame(framed: &mut Framed<TcpStream, FixCodec>) -> BytesMut {
    let polled = ok(
        timeout(Duration::from_secs(5), framed.next()).await,
        "frame must arrive within 5s",
    );
    let frame = some(polled, "stream must stay open");
    ok(frame, "frame must decode")
}

/// Drives the stub acceptor through the Logon handshake and returns the
/// framed socket, positioned just after the ack.
async fn accept_logon(listener: TcpListener) -> Framed<TcpStream, FixCodec> {
    let mut framed = accept_framed(listener).await;
    let logon = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&logon), "A");
    ok(
        framed
            .send(venue_msg("A", 1, &[(98, "0"), (108, "30")]))
            .await,
        "acceptor must send the Logon ack",
    );
    framed
}

/// Binds an ephemeral loopback listener.
async fn bind_listener() -> (TcpListener, std::net::SocketAddr) {
    let listener = ok(
        TcpListener::bind("127.0.0.1:0").await,
        "listener must bind to loopback",
    );
    let addr = ok(listener.local_addr(), "listener must report its address");
    (listener, addr)
}

/// Records session events and received app messages.
#[derive(Debug)]
struct RecordingApp {
    events: Mutex<Vec<String>>,
    app_rx_tx: mpsc::UnboundedSender<String>,
    reject_app: bool,
    reject_admin: bool,
}

impl RecordingApp {
    fn build(reject_app: bool, reject_admin: bool) -> (Arc<Self>, mpsc::UnboundedReceiver<String>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                events: Mutex::new(Vec::new()),
                app_rx_tx: tx,
                reject_app,
                reject_admin,
            }),
            rx,
        )
    }

    fn new() -> (Arc<Self>, mpsc::UnboundedReceiver<String>) {
        Self::build(false, false)
    }

    fn rejecting_app() -> (Arc<Self>, mpsc::UnboundedReceiver<String>) {
        Self::build(true, false)
    }

    /// Rejects every admin message except the Logon, so the handshake still
    /// completes and the reactor path can be exercised.
    fn rejecting_admin() -> (Arc<Self>, mpsc::UnboundedReceiver<String>) {
        Self::build(false, true)
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
        if self.reject_admin && message.msg_type() != &MsgType::Logon {
            return Err(RejectReason::new(99, "admin rejected by test app"));
        }
        Ok(())
    }

    async fn to_app(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_app(
        &self,
        message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        let _ = self.app_rx_tx.send(message.msg_type().as_str().to_string());
        if self.reject_app {
            Err(RejectReason::new(99, "rejected by test app").with_ref_tag(35))
        } else {
            Ok(())
        }
    }
}

/// Full happy path: Logon, app message out (seq continuity asserted by the
/// acceptor), app message in, graceful logout, wait_closed.
#[tokio::test]
async fn test_logon_exchange_and_logout() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;

        let logon = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logon), "A");
        assert_eq!(field(&logon, 49).as_deref(), Some("CLIENT"));
        assert_eq!(field(&logon, 56).as_deref(), Some("VENUE"));
        assert_eq!(field(&logon, 34).as_deref(), Some("1"));
        assert_eq!(field(&logon, 108).as_deref(), Some("30"));
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "30")]))
                .await,
            "send logon ack",
        );

        let order = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&order), "D");
        assert_eq!(field(&order, 34).as_deref(), Some("2"));
        assert_eq!(field(&order, 11).as_deref(), Some("ORDER-1"));
        ok(
            framed
                .send(venue_msg(
                    "8",
                    2,
                    &[
                        (37, "EX-1"),
                        (11, "ORDER-1"),
                        (17, "E-1"),
                        (150, "0"),
                        (39, "0"),
                    ],
                ))
                .await,
            "send execution report",
        );

        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5");
        assert_eq!(field(&logout, 34).as_deref(), Some("3"));
        ok(framed.send(venue_msg("5", 3, &[])).await, "send logout ack");
    });

    let (app, mut app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    assert_eq!(connection.session_id().to_string(), "FIX.4.4:CLIENT->VENUE");
    assert!(app.events().contains(&"logon".to_string()));
    assert!(!connection.is_closed());

    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order
        .push_str(11, "ORDER-1")
        .push_str(55, "EUR/USD")
        .push_char(54, '1')
        .push_uint(38, 100);
    ok(connection.send(order).await, "send order");

    let received = some(
        ok(
            timeout(Duration::from_secs(5), app_rx.recv()).await,
            "app message within 5s",
        ),
        "app channel must stay open",
    );
    assert_eq!(received, "8");

    ok(connection.logout().await, "logout");
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );

    assert!(connection.is_closed());
    assert!(
        connection
            .send(OutboundMessage::new(MsgType::NewOrderSingle))
            .await
            .is_err()
    );
    let events = app.events();
    assert_eq!(events.first().map(String::as_str), Some("create"));
    assert!(events.contains(&"logout".to_string()));

    ok(acceptor.await, "acceptor task");
}

/// A `RawData` (95/96) field carrying an embedded SOH and a non-UTF-8 byte is
/// sent through `OutboundMessage::push_data`, arrives byte-exact, and neither
/// tears the session down nor spends a sequence number on a legal message.
#[tokio::test]
async fn test_send_raw_data_field_round_trips_byte_exact() {
    let (listener, addr) = bind_listener().await;
    // A payload the encoder refuses as an ordinary field: it carries the SOH
    // delimiter, `=`, and a non-UTF-8 byte, none of which survive outside a
    // counted DATA field.
    const PAYLOAD: &[u8] = b"sig\x01\xff=part2\x01end";

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;

        let order = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&order), "D");
        // First app message after the Logon (seq 1) is seq 2: encoding the
        // RawData field spent no number and opened no gap.
        assert_eq!(field(&order, 34).as_deref(), Some("2"));
        assert_eq!(field(&order, 11).as_deref(), Some("ORDER-1"));
        assert_eq!(field(&order, 95), Some(PAYLOAD.len().to_string()));

        let mut decoder = Decoder::new(&order);
        let decoded = ok(decoder.decode(), "order carrying RawData must decode");
        // Byte-exact, including the embedded SOH and the non-UTF-8 byte.
        assert_eq!(decoded.get_field(96).map(|f| f.value), Some(PAYLOAD));
        // 8, 9, 35, 49, 56, 34, 52, 11, 95, 96 — no phantom field split out of
        // the payload's SOH.
        assert_eq!(decoded.field_count(), 10);
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order
        .push_str(11, "ORDER-1")
        .push_data(95, 96, PAYLOAD.to_vec());
    // The send path must not error and must not tear the session down.
    ok(connection.send(order).await, "send order carrying RawData");

    // The acceptor drops the socket after asserting; the session closes on that
    // transport drop, not on an encode teardown.
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );
    assert!(app.events().contains(&"logon".to_string()));

    ok(acceptor.await, "acceptor task");
}

/// An `OutboundMessage` with no legal wire form is refused at the send
/// boundary: it spends no sequence number and does not tear the session down,
/// so a following encodable message still flows with an unbroken sequence.
/// The engine validates eagerly (`Connection::send` returns a typed error)
/// rather than queuing the message and silently dropping it at encode time,
/// and the rejection never quotes the offending value.
#[tokio::test]
async fn test_unencodable_outbound_message_is_refused_without_teardown() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;

        // Only the encodable message reaches the wire, and it carries seq 2:
        // the refused one before it neither reached the wire nor spent a
        // number, so there is no gap for the peer to resend over.
        let good = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&good), "D");
        assert_eq!(field(&good, 34).as_deref(), Some("2"));
        assert_eq!(field(&good, 11).as_deref(), Some("GOOD"));
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    // An ordinary field carrying SOH has no legal wire form; `send` refuses it
    // at the boundary with a typed error, spending no sequence number, rather
    // than queuing it and tearing the session down on a later encode failure.
    let mut bad = OutboundMessage::new(MsgType::NewOrderSingle);
    bad.push_str(11, "BAD").push_str(58, "text\x0149=EVIL");
    match connection.send(bad).await {
        Err(EngineError::InvalidField { tag: 58, reason }) => {
            assert!(
                !reason.contains("EVIL"),
                "the rejection must not quote the value, got {reason}"
            );
        }
        other => panic!("an embedded SOH must be refused, got {other:?}"),
    }

    let mut good = OutboundMessage::new(MsgType::NewOrderSingle);
    good.push_str(11, "GOOD");
    ok(connection.send(good).await, "queue encodable message");

    // The session is closed by the acceptor's transport drop after it reads the
    // good frame, not by a teardown from the refused message.
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );
    assert!(app.events().contains(&"logon".to_string()));

    ok(acceptor.await, "acceptor task");
}

/// Transport drop after logon fires wait_closed and on_logout.
#[tokio::test]
async fn test_transport_drop_fires_wait_closed() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let _framed = accept_logon(listener).await;
        // Drop the connection without a Logout.
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );
    assert!(connection.is_closed());
    assert!(app.events().contains(&"logout".to_string()));

    ok(acceptor.await, "acceptor task");
}

/// Counterparty-initiated logout is acknowledged and closes the session.
#[tokio::test]
async fn test_counterparty_logout() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        ok(
            framed
                .send(venue_msg("5", 2, &[(58, "session ended")]))
                .await,
            "send logout",
        );
        let reply = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reply), "5");
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );
    assert!(app.events().contains(&"logout".to_string()));

    ok(acceptor.await, "acceptor task");
}

/// No Logon ack within the logon timeout -> LogonTimeout.
#[tokio::test]
async fn test_rejected_in_sequence_gap_fill_still_consumes_its_sequence_number() {
    // A Gap Fill occupies the number it carries. If the application rejects it
    // and the engine does not consume that number, the inbound expectation
    // parks on it forever: every later message looks gapped, is deduplicated
    // against the outstanding ResendRequest and dropped, and the session goes
    // on reporting itself healthy while silently discarding traffic.
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;

        // In-sequence Gap Fill (34=2) that the application will reject.
        ok(
            framed
                .send(venue_msg("4", 2, &[(123, "Y"), (36, "3")]))
                .await,
            "send gap fill",
        );

        // The Reject is expected and correct.
        let reject = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reject), "3");
        assert_eq!(field(&reject, 45).as_deref(), Some("2"));

        // Sequence 2 must now be consumed, so a strictly in-order report at 3
        // is accepted rather than treated as a gap.
        ok(
            framed
                .send(venue_msg("8", 3, &[(11, "AFTER-REJECT")]))
                .await,
            "send report",
        );
    });

    let (app, mut app_rx) = RecordingApp::rejecting_admin();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let _connection = ok(initiator.connect(addr).await, "connect");

    // Delivery is the proof: a wedged session would have deduplicated this
    // message against the outstanding ResendRequest and dropped it silently.
    match timeout(Duration::from_secs(5), app_rx.recv()).await {
        Ok(Some(msg_type)) => assert_eq!(msg_type, "8"),
        other => panic!("the report after a rejected fill must be delivered, got {other:?}"),
    }

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

#[tokio::test]
async fn test_exhausted_sender_counter_fails_the_logon() {
    // Seeding the sender counter at u64::MAX makes the very first allocation
    // -- the Logon's own MsgSeqNum -- fail, so the session must refuse to open
    // with a typed error instead of wrapping the counter round to zero.
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        // The client must never get far enough to send anything.
        let _ = timeout(Duration::from_millis(500), framed.next()).await;
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_initial_sequences(u64::MAX, 1);

    match initiator.connect(addr).await {
        Err(EngineError::SequenceExhausted(err)) => {
            assert_eq!(err.counter, SequenceCounter::Sender);
        }
        other => panic!("expected SequenceExhausted, got {other:?}"),
    }

    acceptor.abort();
}

#[tokio::test]
async fn test_logon_timeout() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        // Never reply; hold the socket open until the client gives up.
        let _ = timeout(Duration::from_secs(5), framed.next()).await;
    });

    let (app, _app_rx) = RecordingApp::new();
    let config =
        client_config(Duration::from_secs(30)).with_logon_timeout(Duration::from_millis(300));
    let initiator = Initiator::new(config, Arc::clone(&app));

    match initiator.connect(addr).await {
        Err(EngineError::LogonTimeout(_)) => {}
        other => panic!("expected LogonTimeout, got {other:?}"),
    }

    acceptor.abort();
}

/// Logout instead of Logon ack -> LogonRejected with the counterparty text.
#[tokio::test]
async fn test_logon_rejected() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        ok(
            framed
                .send(venue_msg("5", 1, &[(58, "bad credentials")]))
                .await,
            "send rejection",
        );
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));

    match initiator.connect(addr).await {
        Err(EngineError::LogonRejected { reason }) => assert_eq!(reason, "bad credentials"),
        other => panic!("expected LogonRejected, got {other:?}"),
    }

    ok(acceptor.await, "acceptor task");
}

/// Idle session: the initiator emits heartbeats at the configured interval.
#[tokio::test]
async fn test_heartbeat_emitted_when_idle() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "1")]))
                .await,
            "send logon ack",
        );

        // Keep the client's inbound side alive so it does not TestRequest.
        let heartbeat = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&heartbeat), "0");
        assert_eq!(field(&heartbeat, 34).as_deref(), Some("2"));
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(1)), Arc::clone(&app));
    let _connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// Inbound TestRequest is answered with a Heartbeat echoing TestReqID (112).
#[tokio::test]
async fn test_test_request_answered() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        ok(
            framed.send(venue_msg("1", 2, &[(112, "PING-42")])).await,
            "send test request",
        );

        let reply = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reply), "0");
        assert_eq!(field(&reply, 112).as_deref(), Some("PING-42"));
        assert_eq!(field(&reply, 34).as_deref(), Some("2"));
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let _connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// A silent counterparty triggers TestRequest, then heartbeat timeout: the
/// session closes and the handle observes is_timed_out().
#[tokio::test]
async fn test_heartbeat_timeout_closes_session() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "1")]))
                .await,
            "send logon ack",
        );

        // Read and ignore everything: never answer the TestRequest.
        let mut saw_test_request = false;
        while let Ok(Some(Ok(frame))) = timeout(Duration::from_secs(10), framed.next()).await {
            if msg_type_of(&frame) == "1" {
                saw_test_request = true;
            }
        }
        saw_test_request
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(1)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    // TestRequest due at interval + 1s grace; timeout one interval later.
    ok(
        timeout(Duration::from_secs(8), connection.wait_closed()).await,
        "closed within 8s",
    );
    assert!(connection.is_timed_out());
    assert!(app.events().contains(&"logout".to_string()));

    assert!(
        ok(acceptor.await, "acceptor task"),
        "acceptor should have seen a TestRequest"
    );
}

/// A counterparty that answers a TestRequest with application traffic instead
/// of a Heartbeat keeps the session alive: any accepted inbound frame stops
/// the timeout countdown.
///
/// This is the regression that was reproduced against a live session — six
/// in-sequence ExecutionReports were delivered to the application and the
/// session was then torn down as timed out.
#[tokio::test]
async fn test_test_request_answered_with_app_traffic_keeps_session_alive() {
    let (listener, addr) = bind_listener().await;
    // Keeps the acceptor's socket open until the client-side assertions have
    // run, so `!is_closed()` below cannot race the acceptor dropping its
    // framed socket at end of task.
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "1")]))
                .await,
            "send logon ack",
        );

        // Stay silent until the client probes us.
        loop {
            let frame = next_frame(&mut framed).await;
            if msg_type_of(&frame) == "1" {
                break;
            }
        }

        // Answer with application traffic only: valid, in sequence, and never
        // a Heartbeat echoing the TestReqID. Eight reports at 200ms span
        // 1.6s, comfortably past the 1s interval the old timeout used.
        for seq in 2..10u64 {
            ok(
                framed
                    .send(venue_msg(
                        "8",
                        seq,
                        &[
                            (37, "ORDER-1"),
                            (17, "EXEC-1"),
                            (150, "0"),
                            (39, "0"),
                            (55, "AAPL"),
                        ],
                    ))
                    .await,
                "send execution report",
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        // Hold the socket open until the test has finished asserting on the
        // live session, then let the task end (dropping `framed`).
        let _ = done_rx.await;
    });

    let (app, mut app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(1)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    for _ in 0..8 {
        let received = ok(
            timeout(Duration::from_secs(5), app_rx.recv()).await,
            "execution report must reach the application",
        );
        assert_eq!(some(received, "app channel must stay open"), "8");
    }

    assert!(
        !connection.is_timed_out(),
        "inbound traffic after the TestRequest must clear the pending probe"
    );
    assert!(
        !connection.is_closed(),
        "a demonstrably live session must not be torn down"
    );

    // Release the acceptor now that the live-session assertions have passed.
    let _ = done_tx.send(());
    ok(
        ok(
            timeout(Duration::from_secs(20), acceptor).await,
            "acceptor done within 20s",
        ),
        "acceptor task",
    );
}

/// HeartBtInt = 0 on the Logon ack disables heartbeating: no Heartbeat, no
/// TestRequest, and no self-inflicted timeout.
#[tokio::test]
async fn test_zero_heartbeat_interval_disables_heartbeating() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "0")]))
                .await,
            "send logon ack with HeartBtInt=0",
        );

        // The client requested a 1s interval, so without the fix this window
        // carries two Heartbeats at least — in practice one per 100ms tick.
        match timeout(Duration::from_secs(2), framed.next()).await {
            Err(_) => {}
            Ok(Some(Ok(frame))) => panic!(
                "HeartBtInt=0 must silence the session, got 35={}",
                msg_type_of(&frame)
            ),
            Ok(Some(Err(err))) => panic!("codec error while expecting silence: {err:?}"),
            Ok(None) => panic!("session closed itself with HeartBtInt=0"),
        }
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(1)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );

    assert!(!connection.is_timed_out());
    assert!(!connection.is_closed());
}

/// A counterparty HeartBtInt above the supported ceiling is refused with a
/// Reject (reason 5, RefTagID 108) and a Logout, and fails the handshake
/// rather than disabling dead-peer detection.
#[tokio::test]
async fn test_out_of_range_heartbeat_interval_fails_handshake() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "99999")]))
                .await,
            "send logon ack with an out-of-range HeartBtInt",
        );

        let reject = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reject), "3");
        assert_eq!(field(&reject, 373).as_deref(), Some("5"));
        assert_eq!(field(&reject, 371).as_deref(), Some("108"));

        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5");
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));

    match initiator.connect(addr).await {
        Err(EngineError::HeartbeatInterval { detail }) => {
            assert!(detail.contains("99999"), "got {detail}");
        }
        other => panic!("expected HeartbeatInterval, got {other:?}"),
    }

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// A HeartBtInt (108) of `u64::MAX` parses as a valid u64, so it is not caught
/// as malformed; `Duration::from_secs(u64::MAX)` plus the transmission grace
/// would overflow and — under `panic = "abort"` — kill the process on the first
/// heartbeat tick. The handshake bound refuses it before any `HeartbeatManager`
/// is built, so a single crafted Logon field fails the handshake with a Reject
/// (reason 5, RefTagID 108) and a Logout rather than aborting.
#[tokio::test]
async fn test_max_u64_heartbeat_interval_fails_handshake_without_abort() {
    let (listener, addr) = bind_listener().await;
    let absurd = u64::MAX.to_string();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        ok(
            framed
                .send(venue_msg(
                    "A",
                    1,
                    &[(98, "0"), (108, "18446744073709551615")],
                ))
                .await,
            "send logon ack with a u64::MAX HeartBtInt",
        );

        let reject = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reject), "3");
        assert_eq!(field(&reject, 373).as_deref(), Some("5"));
        assert_eq!(field(&reject, 371).as_deref(), Some("108"));

        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5");
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));

    match initiator.connect(addr).await {
        Err(EngineError::HeartbeatInterval { detail }) => {
            assert!(detail.contains(&absurd), "got {detail}");
        }
        other => panic!("expected HeartbeatInterval, got {other:?}"),
    }

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// HeartBtInt (108) is a required field of the Logon. An ack that omits it is
/// refused with a Reject (reason 1, RefTagID 108) and a Logout, and fails the
/// handshake rather than silently establishing a session on the locally
/// configured interval.
#[tokio::test]
async fn test_missing_heartbeat_interval_fails_handshake() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        ok(
            framed.send(venue_msg("A", 1, &[(98, "0")])).await,
            "send logon ack without HeartBtInt",
        );

        let reject = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reject), "3");
        assert_eq!(field(&reject, 373).as_deref(), Some("1"));
        assert_eq!(field(&reject, 371).as_deref(), Some("108"));

        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5");
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));

    match initiator.connect(addr).await {
        Err(EngineError::HeartbeatInterval { detail }) => {
            assert!(detail.contains("108"), "got {detail}");
        }
        other => panic!("expected HeartbeatInterval, got {other:?}"),
    }

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// A non-numeric HeartBtInt (108) on the Logon ack is refused with a Reject
/// (reason 6, RefTagID 108) and a Logout, and fails the handshake rather than
/// silently establishing a session on the locally configured interval.
#[tokio::test]
async fn test_non_numeric_heartbeat_interval_fails_handshake() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "abc")]))
                .await,
            "send logon ack with a non-numeric HeartBtInt",
        );

        let reject = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reject), "3");
        assert_eq!(field(&reject, 373).as_deref(), Some("6"));
        assert_eq!(field(&reject, 371).as_deref(), Some("108"));

        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5");
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));

    match initiator.connect(addr).await {
        Err(EngineError::HeartbeatInterval { detail }) => {
            assert!(detail.contains("108"), "got {detail}");
        }
        other => panic!("expected HeartbeatInterval, got {other:?}"),
    }

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// A sequence gap triggers a ResendRequest and the gapped app message is not
/// delivered to the application.
#[tokio::test]
async fn test_sequence_gap_triggers_resend_request() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;

        // Jump from seq 2 to seq 5: gap of 2..=4.
        ok(
            framed
                .send(venue_msg(
                    "8",
                    5,
                    &[(37, "EX-9"), (17, "E-9"), (150, "0"), (39, "0")],
                ))
                .await,
            "send gapped report",
        );

        let resend = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&resend), "2");
        assert_eq!(field(&resend, 7).as_deref(), Some("2"));
        assert_eq!(field(&resend, 16).as_deref(), Some("0"));
    });

    let (app, mut app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let _connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );

    // The gapped ExecutionReport must not reach the application.
    assert!(
        timeout(Duration::from_millis(300), app_rx.recv())
            .await
            .is_err(),
        "gapped app message must not be delivered"
    );
}

/// from_app rejection produces a session-level Reject (35=3).
#[tokio::test]
async fn test_from_app_reject_sends_session_reject() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        ok(
            framed
                .send(venue_msg(
                    "8",
                    2,
                    &[(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")],
                ))
                .await,
            "send report",
        );

        let reject = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reject), "3");
        assert_eq!(field(&reject, 45).as_deref(), Some("2"));
        assert_eq!(field(&reject, 372).as_deref(), Some("8"));
        assert_eq!(field(&reject, 373).as_deref(), Some("99"));
        assert_eq!(field(&reject, 58).as_deref(), Some("rejected by test app"));
    });

    let (app, _app_rx) = RecordingApp::rejecting_app();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let _connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// from_admin rejection produces a session-level Reject instead of the
/// normal admin reply.
#[tokio::test]
async fn test_from_admin_reject_sends_session_reject() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        ok(
            framed.send(venue_msg("1", 2, &[(112, "PING-1")])).await,
            "send test request",
        );

        let reject = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reject), "3");
        assert_eq!(field(&reject, 45).as_deref(), Some("2"));
        assert_eq!(field(&reject, 372).as_deref(), Some("1"));
        assert_eq!(field(&reject, 373).as_deref(), Some("99"));
    });

    let (app, _app_rx) = RecordingApp::rejecting_admin();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let _connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// Sequence state survives across messages within a session and is visible
/// on the handle.
#[tokio::test]
async fn test_sequence_state_within_session() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;

        for expected_seq in 2..=4u64 {
            let frame = next_frame(&mut framed).await;
            assert_eq!(msg_type_of(&frame), "D");
            assert_eq!(field(&frame, 34), Some(expected_seq.to_string()));
        }
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    for i in 0..3 {
        let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
        order.push_str(11, &format!("ORDER-{i}"));
        ok(connection.send(order).await, "send order");
    }

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );

    assert_eq!(connection.next_sender_seq(), 5);
    assert_eq!(connection.next_target_seq(), 2);
}

// ---------------------------------------------------------------------------
// Inbound SequenceReset (35=4)
// ---------------------------------------------------------------------------

/// A GapFill whose own MsgSeqNum is in sequence advances the target
/// expectation to NewSeqNo, and the next message at that number is
/// delivered.
#[tokio::test]
async fn test_sequence_reset_gap_fill_in_sequence_advances_target() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        // In-sequence GapFill: 34=2 while expecting 2, filling 2..=4.
        ok(
            framed
                .send(venue_msg("4", 2, &[(123, "Y"), (36, "5")]))
                .await,
            "send gap fill",
        );
        ok(
            framed
                .send(venue_msg(
                    "8",
                    5,
                    &[(37, "EX-5"), (17, "E-5"), (150, "0"), (39, "0")],
                ))
                .await,
            "send report at the filled sequence",
        );
        // No ResendRequest may come back.
        assert!(
            timeout(Duration::from_millis(300), framed.next())
                .await
                .is_err(),
            "an in-sequence GapFill must not trigger a ResendRequest"
        );
    });

    let (app, mut app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    let received = some(
        ok(
            timeout(Duration::from_secs(5), app_rx.recv()).await,
            "app message within 5s",
        ),
        "app channel must stay open",
    );
    assert_eq!(received, "8");
    assert_eq!(connection.next_target_seq(), 6);

    ok(acceptor.await, "acceptor task");
}

/// A GapFill that is itself gapped must not be applied: the missing range is
/// requested and the target expectation stays put. This is the branch that
/// used to silently skip real messages.
#[tokio::test]
async fn test_sequence_reset_gap_fill_with_gap_requests_resend() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        // Expecting 2, but the GapFill claims 34=7 and jumps to 20.
        ok(
            framed
                .send(venue_msg("4", 7, &[(123, "Y"), (36, "20")]))
                .await,
            "send gapped gap fill",
        );

        let resend = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&resend), "2");
        assert_eq!(field(&resend, 7).as_deref(), Some("2"));
        assert_eq!(field(&resend, 16).as_deref(), Some("0"));
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );

    // NewSeqNo must NOT have been applied.
    assert_eq!(connection.next_target_seq(), 2);
}

/// Reset mode (no GapFillFlag) is the only mode allowed to ignore its own
/// MsgSeqNum.
#[tokio::test]
async fn test_sequence_reset_reset_mode_ignores_msg_seq_num() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        // Reset mode with a meaningless MsgSeqNum: 36 is applied anyway.
        ok(
            framed.send(venue_msg("4", 99, &[(36, "10")])).await,
            "send sequence reset",
        );
        ok(
            framed
                .send(venue_msg(
                    "8",
                    10,
                    &[(37, "EX-10"), (17, "E-10"), (150, "0"), (39, "0")],
                ))
                .await,
            "send report at the reset sequence",
        );
    });

    let (app, mut app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    let received = some(
        ok(
            timeout(Duration::from_secs(5), app_rx.recv()).await,
            "app message within 5s",
        ),
        "app channel must stay open",
    );
    assert_eq!(received, "8");
    assert_eq!(connection.next_target_seq(), 11);

    ok(acceptor.await, "acceptor task");
}

/// A NewSeqNo below the expected sequence is a session Reject with
/// SessionRejectReason 5, not a warning.
#[tokio::test]
async fn test_sequence_reset_backward_new_seq_no_is_rejected() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        // Expecting 2; a Reset to 1 would rewind the inbound stream.
        ok(
            framed.send(venue_msg("4", 2, &[(36, "1")])).await,
            "send backward reset",
        );

        let reject = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reject), "3");
        assert_eq!(field(&reject, 45).as_deref(), Some("2"));
        assert_eq!(field(&reject, 372).as_deref(), Some("4"));
        assert_eq!(field(&reject, 373).as_deref(), Some("5"));
        assert_eq!(field(&reject, 371).as_deref(), Some("36"));
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
    assert_eq!(connection.next_target_seq(), 2);
}

/// A GapFill whose NewSeqNo does not advance past its own MsgSeqNum is
/// rejected with reason 5, and the fill message itself is consumed so the
/// session does not deadlock on that number.
#[tokio::test]
async fn test_sequence_reset_gap_fill_without_advance_is_rejected() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        ok(
            framed
                .send(venue_msg("4", 2, &[(123, "Y"), (36, "2")]))
                .await,
            "send non-advancing gap fill",
        );

        let reject = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reject), "3");
        assert_eq!(field(&reject, 373).as_deref(), Some("5"));
        assert_eq!(field(&reject, 371).as_deref(), Some("36"));
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
    assert_eq!(connection.next_target_seq(), 3);
}

/// A SequenceReset without NewSeqNo is rejected with reason 1 (required tag
/// missing) rather than silently ignored.
#[tokio::test]
async fn test_sequence_reset_without_new_seq_no_is_rejected() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        ok(
            framed.send(venue_msg("4", 2, &[(123, "Y")])).await,
            "send gap fill without NewSeqNo",
        );

        let reject = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reject), "3");
        assert_eq!(field(&reject, 373).as_deref(), Some("1"));
        assert_eq!(field(&reject, 371).as_deref(), Some("36"));
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let _connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

// ---------------------------------------------------------------------------
// Inbound ResendRequest (35=2)
// ---------------------------------------------------------------------------

/// A bounded ResendRequest is answered with a GapFill bounded by EndSeqNo+1,
/// carrying PossDupFlag and OrigSendingTime.
#[tokio::test]
async fn test_resend_request_answered_with_bounded_gap_fill() {
    let (listener, addr) = bind_listener().await;
    // Lets the client hold its next order back until the gap fill is on the
    // wire, so the sequence assertion below is not racing the reactor.
    let (fill_seen_tx, fill_seen_rx) = tokio::sync::oneshot::channel::<()>();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;

        // Drain three orders so the client's next sender sequence is 5.
        for expected_seq in 2..=4u64 {
            let frame = next_frame(&mut framed).await;
            assert_eq!(field(&frame, 34), Some(expected_seq.to_string()));
        }

        ok(
            framed.send(venue_msg("2", 2, &[(7, "2"), (16, "3")])).await,
            "send bounded resend request",
        );

        let fill = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&fill), "4");
        assert_eq!(field(&fill, 123).as_deref(), Some("Y"));
        assert_eq!(field(&fill, 34).as_deref(), Some("2"));
        // Bounded by EndSeqNo + 1, not by our next sender sequence (5).
        assert_eq!(field(&fill, 36).as_deref(), Some("4"));
        assert_eq!(field(&fill, 43).as_deref(), Some("Y"));
        assert_eq!(field(&fill, 122), field(&fill, 52));
        assert!(field(&fill, 122).is_some(), "PossDup requires 122");

        let _ = fill_seen_tx.send(());

        // The crux of "the fill occupies the range it replaces": it carries
        // BeginSeqNo as its own MsgSeqNum and allocates nothing, so the next
        // real message still goes out at 5. Had a sender number been consumed
        // for the fill this would be 6, and the counterparty would see a
        // permanent off-by-one.
        let next = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&next), "D");
        assert_eq!(field(&next, 34).as_deref(), Some("5"));
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    for i in 0..3 {
        let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
        order.push_str(11, &format!("ORDER-{i}"));
        ok(connection.send(order).await, "send order");
    }

    ok(
        timeout(Duration::from_secs(5), fill_seen_rx).await,
        "gap fill observed within 5s",
    )
    .ok();
    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order.push_str(11, "ORDER-AFTER-FILL");
    ok(connection.send(order).await, "send order after fill");

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// EndSeqNo = 0 means infinity: the fill runs up to our next sender
/// sequence.
#[tokio::test]
async fn test_resend_request_unbounded_gap_fill_reaches_next_sender_seq() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;

        for expected_seq in 2..=4u64 {
            let frame = next_frame(&mut framed).await;
            assert_eq!(field(&frame, 34), Some(expected_seq.to_string()));
        }

        ok(
            framed.send(venue_msg("2", 2, &[(7, "2"), (16, "0")])).await,
            "send unbounded resend request",
        );

        let fill = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&fill), "4");
        assert_eq!(field(&fill, 34).as_deref(), Some("2"));
        assert_eq!(field(&fill, 36).as_deref(), Some("5"));
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    for i in 0..3 {
        let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
        order.push_str(11, &format!("ORDER-{i}"));
        ok(connection.send(order).await, "send order");
    }

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// A ResendRequest without BeginSeqNo is rejected with reason 1 and
/// RefTagID 7 instead of silently defaulting to 1.
#[tokio::test]
async fn test_resend_request_without_begin_seq_no_is_rejected() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        ok(
            framed.send(venue_msg("2", 2, &[(16, "0")])).await,
            "send resend request without BeginSeqNo",
        );

        let reject = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reject), "3");
        assert_eq!(field(&reject, 45).as_deref(), Some("2"));
        assert_eq!(field(&reject, 372).as_deref(), Some("2"));
        assert_eq!(field(&reject, 373).as_deref(), Some("1"));
        assert_eq!(field(&reject, 371).as_deref(), Some("7"));
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let _connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// A ResendRequest for messages we never sent is rejected with reason 5.
#[tokio::test]
async fn test_resend_request_out_of_range_is_rejected() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        // We have only sent the Logon (seq 1), so 99 is out of range.
        ok(
            framed
                .send(venue_msg("2", 2, &[(7, "99"), (16, "0")]))
                .await,
            "send out-of-range resend request",
        );

        let reject = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reject), "3");
        assert_eq!(field(&reject, 373).as_deref(), Some("5"));
        assert_eq!(field(&reject, 371).as_deref(), Some("7"));
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let _connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

// ---------------------------------------------------------------------------
// Duplicates, teardown, and handshake edge cases
// ---------------------------------------------------------------------------

/// A too-low message flagged PossDup is dropped without disturbing the
/// session.
#[tokio::test]
async fn test_poss_dup_duplicate_is_dropped() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        let report = &[(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")];
        ok(framed.send(venue_msg("8", 2, report)).await, "send report");
        // Redelivery of the same message, correctly flagged.
        ok(
            framed
                .send(venue_msg(
                    "8",
                    2,
                    &[(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0"), (43, "Y")],
                ))
                .await,
            "send duplicate report",
        );
        // The session must still be alive.
        ok(
            framed.send(venue_msg("1", 3, &[(112, "PING-1")])).await,
            "send test request",
        );

        let reply = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reply), "0");
        assert_eq!(field(&reply, 112).as_deref(), Some("PING-1"));
    });

    let (app, mut app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    let first = some(
        ok(
            timeout(Duration::from_secs(5), app_rx.recv()).await,
            "app message within 5s",
        ),
        "app channel must stay open",
    );
    assert_eq!(first, "8");
    assert!(
        timeout(Duration::from_millis(200), app_rx.recv())
            .await
            .is_err(),
        "the PossDup duplicate must not be delivered twice"
    );
    // The duplicate consumed no sequence number: the TestRequest at 3 was
    // in sequence and the acceptor asserts the Heartbeat reply, which is the
    // proof that the session survived the duplicate.
    assert_eq!(connection.next_target_seq(), 4);

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// A too-low message without PossDupFlag is unrecoverable: the engine logs
/// out and closes the session.
#[tokio::test]
async fn test_too_low_without_poss_dup_closes_session() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        let report = &[(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")];
        ok(framed.send(venue_msg("8", 2, report)).await, "send report");
        ok(
            framed.send(venue_msg("8", 2, report)).await,
            "send unflagged duplicate",
        );

        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5");
        assert!(
            some(field(&logout, 58), "logout must carry Text").contains("MsgSeqNum too low"),
            "logout should explain the sequence failure"
        );
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );
    assert!(connection.is_closed());
    assert!(app.events().contains(&"logout".to_string()));

    ok(acceptor.await, "acceptor task");
}

/// A gap in the Logon ack itself produces a ResendRequest before the reactor
/// starts.
#[tokio::test]
async fn test_gapped_logon_ack_sends_resend_request() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        // Expecting 1, acking with 5.
        ok(
            framed
                .send(venue_msg("A", 5, &[(98, "0"), (108, "30")]))
                .await,
            "send gapped logon ack",
        );

        let resend = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&resend), "2");
        assert_eq!(field(&resend, 34).as_deref(), Some("2"));
        assert_eq!(field(&resend, 7).as_deref(), Some("1"));
        assert_eq!(field(&resend, 16).as_deref(), Some("0"));
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");
    assert!(app.events().contains(&"logon".to_string()));
    // The gap is unresolved, so the target expectation is unchanged.
    assert_eq!(connection.next_target_seq(), 1);

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// ResetSeqNumFlag on the Logon ack resets the inbound counter before
/// MsgSeqNum is validated, so a peer-driven reset does not abort a
/// continuity-seeded handshake.
#[tokio::test]
async fn test_logon_ack_reset_seq_num_flag_resets_counters() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let logon = next_frame(&mut framed).await;
        // Seeded for continuity: our Logon goes out at 10.
        assert_eq!(field(&logon, 34).as_deref(), Some("10"));
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "30"), (141, "Y")]))
                .await,
            "send resetting logon ack",
        );

        // The reset outbound stream continues at 2, never re-emitting 1.
        let order = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&order), "D");
        assert_eq!(field(&order, 34).as_deref(), Some("2"));
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_initial_sequences(10, 10);
    let connection = ok(initiator.connect(addr).await, "connect");

    assert_eq!(connection.next_target_seq(), 2);
    assert_eq!(connection.next_sender_seq(), 2);

    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order.push_str(11, "ORDER-1");
    ok(connection.send(order).await, "send order");

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// A Logon ack from the wrong counterparty is rejected with reason 9 and
/// the handshake fails.
#[tokio::test]
async fn test_logon_ack_comp_id_mismatch_fails_handshake() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        ok(
            framed
                .send(venue_msg_from(
                    "OTHER",
                    "CLIENT",
                    "A",
                    1,
                    &[(98, "0"), (108, "30")],
                ))
                .await,
            "send cross-wired logon ack",
        );

        let reject = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reject), "3");
        assert_eq!(field(&reject, 373).as_deref(), Some("9"));
        assert_eq!(field(&reject, 371).as_deref(), Some("49"));

        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5");
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));

    match initiator.connect(addr).await {
        Err(EngineError::IdentityMismatch { detail }) => {
            assert!(detail.contains("tag 49"), "got {detail}");
        }
        other => panic!("expected IdentityMismatch, got {other:?}"),
    }

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// A mid-session CompID mismatch is rejected with reason 9, logged out, and
/// closes the session.
#[tokio::test]
async fn test_comp_id_mismatch_rejects_and_closes_session() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        ok(
            framed
                .send(venue_msg_from(
                    "VENUE",
                    "SOMEONE-ELSE",
                    "8",
                    2,
                    &[(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")],
                ))
                .await,
            "send cross-wired report",
        );

        let reject = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reject), "3");
        assert_eq!(field(&reject, 45).as_deref(), Some("2"));
        assert_eq!(field(&reject, 373).as_deref(), Some("9"));
        assert_eq!(field(&reject, 371).as_deref(), Some("56"));

        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5");
    });

    let (app, mut app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );
    // The foreign message must never reach the application.
    assert!(
        timeout(Duration::from_millis(200), app_rx.recv())
            .await
            .is_err(),
        "a cross-wired message must not be delivered"
    );

    ok(acceptor.await, "acceptor task");
}

/// An undecodable frame is dropped without killing the session.
#[tokio::test]
async fn test_undecodable_frame_is_dropped() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;

        // Framing is valid (8/9/10) but MsgType is absent, so the tag=value
        // decoder rejects it. Hand-rolled: the encoder will not produce it.
        ok(
            framed
                .send(raw_frame(b"49=VENUE\x0156=CLIENT\x0134=2\x01"))
                .await,
            "send undecodable frame",
        );

        ok(
            framed.send(venue_msg("1", 2, &[(112, "PING-1")])).await,
            "send test request",
        );
        let reply = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reply), "0");
        assert_eq!(field(&reply, 112).as_deref(), Some("PING-1"));
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
    assert!(!connection.is_closed());
}

/// A frame without MsgSeqNum is dropped without disturbing sequence state.
#[tokio::test]
async fn test_frame_without_msg_seq_num_is_dropped() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;

        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "0");
        encoder.put_str(49, "VENUE");
        encoder.put_str(56, "CLIENT");
        encoder.put_str(52, Timestamp::now().format_millis().as_str());
        ok(
            framed.send(frame_of(&mut encoder)).await,
            "send frame without MsgSeqNum",
        );

        // The dropped frame consumed no sequence number, so 2 is still next.
        ok(
            framed.send(venue_msg("1", 2, &[(112, "PING-1")])).await,
            "send test request",
        );
        let reply = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reply), "0");
        assert_eq!(field(&reply, 112).as_deref(), Some("PING-1"));
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
    assert_eq!(connection.next_target_seq(), 3);
}

/// A frame whose MsgSeqNum (34) appears only after the body is dropped as a
/// missing header field on the shared in-session reactor path, the same
/// positional contract the CompID and SendingTime checks already enforce.
/// Initiator and Acceptor share this reactor, so this covers both.
#[tokio::test]
async fn test_frame_with_body_only_msg_seq_num_is_dropped() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;

        // 11 (ClOrdID) opens the body, so the 34 that follows it is not the
        // standard-header MsgSeqNum. Built by hand: the encoder refuses a frame
        // whose header field order is not standard, which is exactly the shape
        // under test.
        let ts = Timestamp::now().format_millis();
        let body = format!(
            "35=0\x0149=VENUE\x0156=CLIENT\x0152={}\x0111=ORDER-1\x0134=1\x01",
            ts.as_str()
        );
        ok(
            framed.send(raw_frame(body.as_bytes())).await,
            "send frame with a body-only MsgSeqNum",
        );

        // The dropped frame consumed no sequence number, so 2 is still next: a
        // valid TestRequest at 2 is answered, proving sequence state is intact.
        ok(
            framed.send(venue_msg("1", 2, &[(112, "PING-1")])).await,
            "send test request",
        );
        let reply = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reply), "0");
        assert_eq!(field(&reply, 112).as_deref(), Some("PING-1"));
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
    // The body-only-34 frame was dropped; 2 was consumed by the TestRequest.
    assert_eq!(connection.next_target_seq(), 3);
}

/// A Logout that is never acknowledged closes the session at the logout
/// deadline.
#[tokio::test]
async fn test_logout_ack_timeout_closes_session() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5");
        // Never acknowledge; hold the socket so the deadline, not the
        // transport, is what closes the session.
        let _ = timeout(Duration::from_secs(3), framed.next()).await;
    });

    let (app, _app_rx) = RecordingApp::new();
    let mut config = client_config(Duration::from_secs(30));
    config.logout_timeout = Duration::from_millis(300);
    let initiator = Initiator::new(config, Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(connection.logout().await, "logout");
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );
    assert!(app.events().contains(&"logout".to_string()));

    acceptor.abort();
}

/// Dropping every Connection handle logs the session out gracefully.
#[tokio::test]
async fn test_dropping_all_handles_logs_out() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5");
        assert_eq!(field(&logout, 34).as_deref(), Some("2"));
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");
    drop(connection);

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

// ---------------------------------------------------------------------------
// Bounded resend recovery (issue #29, gap 1)
// ---------------------------------------------------------------------------

/// A peer that never satisfies a resend reaches a bounded outcome: the client
/// retries the ResendRequest up to the configured limit, then logs out. A long
/// heartbeat interval rules the heartbeat timeout out as the cause, so the
/// close is attributable to the resend bound alone.
#[tokio::test]
async fn test_unsatisfied_resend_request_times_out_into_logout() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;

        // Open a gap the acceptor will never fill: jump straight to seq 5.
        ok(
            framed
                .send(venue_msg(
                    "8",
                    5,
                    &[(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")],
                ))
                .await,
            "send gapped report",
        );

        // Read the client's frames until it gives up and logs out, counting
        // the ResendRequests. The gap is never filled, so the only conforming
        // outcomes are more requests and, finally, a Logout.
        let mut resend_requests = 0;
        loop {
            let frame = next_frame(&mut framed).await;
            match msg_type_of(&frame).as_str() {
                "2" => {
                    assert_eq!(field(&frame, 7).as_deref(), Some("2"));
                    resend_requests += 1;
                }
                "5" => {
                    // The Logout explains why, so a supervisor can tell a
                    // stalled resend from an ordinary shutdown.
                    let text = some(field(&frame, 58), "abandon Logout carries Text");
                    assert!(
                        text.contains("resend"),
                        "Logout should name the stalled resend, got {text:?}"
                    );
                    break;
                }
                other => panic!("unexpected frame while stalled: {other}"),
            }
        }
        // Three attempts total: the request the gap opens plus two retries.
        assert_eq!(
            resend_requests, 3,
            "expected the initial request and two retries"
        );
    });

    let (app, mut app_rx) = RecordingApp::new();
    // A 30s heartbeat cannot fire inside this test, so only the resend bound
    // can close the session; a 150ms resend timeout keeps it quick.
    let config = client_config(Duration::from_secs(30))
        .with_resend_timeout(Duration::from_millis(150))
        .with_max_resend_requests(3);
    let initiator = Initiator::new(config, Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "the stalled session must close within 5s",
    );
    assert!(app.events().contains(&"logout".to_string()));
    // Nothing ever satisfied the gap, so nothing was delivered.
    assert!(
        timeout(Duration::from_millis(200), app_rx.recv())
            .await
            .is_err(),
        "a gapped, never-filled message must not be delivered"
    );

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// A peer that fills only the *start* of a gap and then goes quiet — while
/// spamming timely duplicates that keep the heartbeat clock alive — must still
/// be escalated to Logout. The single in-order message that opens the fill used
/// to wipe all knowledge of the still-open gap, after which neither the resend
/// bound nor the heartbeat timeout could fire: a silent stall. Recovery now
/// tracks the whole outstanding range, so the retries continue from the
/// advanced expectation until the bound is spent.
#[tokio::test]
async fn test_partial_resend_then_duplicate_flood_escalates_to_logout() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;

        // Open a gap 2..=4 by jumping straight to seq 5.
        ok(
            framed
                .send(venue_msg(
                    "8",
                    5,
                    &[(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")],
                ))
                .await,
            "send gapped report",
        );

        // The client requests the whole range from 2.
        let first = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&first), "2");
        assert_eq!(
            field(&first, 7).as_deref(),
            Some("2"),
            "the first request covers the gap start"
        );

        // Fill only the START of the gap, in order: seq 2. Sequences 3 and 4
        // (and the 5 that opened the gap) stay missing. Before the fix this
        // single in-order message cleared all resend state.
        ok(
            framed
                .send(venue_msg(
                    "8",
                    2,
                    &[(43, "Y"), (37, "EX-2"), (17, "E-2"), (150, "0"), (39, "0")],
                ))
                .await,
            "fill the gap start only",
        );

        // Now flood timely duplicate-2s (PossDup): they refresh the heartbeat
        // but make no in-order progress. A correct client keeps chasing the
        // still-open gap from the advanced expectation and finally logs out; a
        // buggy one sits here forever, having forgotten the gap.
        let mut resend_requests = 0;
        loop {
            ok(
                framed
                    .send(venue_msg(
                        "8",
                        2,
                        &[(43, "Y"), (37, "EX-2"), (17, "E-2"), (150, "0"), (39, "0")],
                    ))
                    .await,
                "flood a timely duplicate",
            );
            let frame = next_frame(&mut framed).await;
            match msg_type_of(&frame).as_str() {
                "2" => {
                    // The retry targets the advanced gap start (3), never the
                    // already-consumed 2.
                    assert_eq!(
                        field(&frame, 7).as_deref(),
                        Some("3"),
                        "the retry must start from the advanced expectation, not the consumed number"
                    );
                    resend_requests += 1;
                }
                "5" => {
                    let text = some(field(&frame, 58), "abandon Logout carries Text");
                    assert!(
                        text.contains("resend"),
                        "Logout should name the stalled resend, got {text:?}"
                    );
                    break;
                }
                // A 30s heartbeat cannot fire in this window, but tolerate an
                // admin frame rather than racing on it.
                "0" | "1" => {}
                other => panic!("unexpected frame while stalled: {other}"),
            }
        }
        assert_eq!(
            resend_requests, 2,
            "the partial fill must leave the gap armed: two retries then Logout"
        );
    });

    let (app, _app_rx) = RecordingApp::new();
    // A 30s heartbeat cannot fire inside this test, so only the resend bound can
    // close the session; a 150ms resend timeout keeps it quick.
    let config = client_config(Duration::from_secs(30))
        .with_resend_timeout(Duration::from_millis(150))
        .with_max_resend_requests(3);
    let initiator = Initiator::new(config, Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "the partially-filled, then flooded, session must still close within 5s",
    );
    assert!(app.events().contains(&"logout".to_string()));

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// A GapFill that errors mid-recovery still consumes its sequence number, so the
/// resend must advance with it: the next request starts from the new
/// expectation, never re-requesting the number the errored fill already
/// consumed. The reject paths used to advance the target without updating the
/// resend, so a retry re-asked for an already-processed sequence.
#[tokio::test]
async fn test_errored_gap_fill_mid_recovery_advances_the_resend_request() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;

        // Open a gap 2..=4 by jumping straight to seq 5.
        ok(
            framed
                .send(venue_msg(
                    "8",
                    5,
                    &[(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")],
                ))
                .await,
            "send gapped report",
        );

        // The client requests the whole range from 2.
        let first = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&first), "2");
        assert_eq!(field(&first, 7).as_deref(), Some("2"));

        // Answer with an in-sequence GapFill for seq 2 that the app rejects.
        // It still consumes seq 2, advancing the expectation to 3, so any later
        // resend must start from 3 — never the already-consumed 2.
        ok(
            framed
                .send(venue_msg("4", 2, &[(43, "Y"), (123, "Y"), (36, "3")]))
                .await,
            "send an in-sequence gap fill the app rejects",
        );

        loop {
            let frame = next_frame(&mut framed).await;
            match msg_type_of(&frame).as_str() {
                "3" => {
                    // The Reject for the errored fill references seq 2.
                    assert_eq!(field(&frame, 45).as_deref(), Some("2"));
                }
                "2" => {
                    assert_eq!(
                        field(&frame, 7).as_deref(),
                        Some("3"),
                        "the resend after an errored fill must start from the advanced expectation, not the consumed number"
                    );
                    break;
                }
                "5" => panic!("the session must keep recovering, not log out here"),
                "0" | "1" => {}
                other => panic!("unexpected frame after an errored fill: {other}"),
            }
        }
    });

    let (app, _app_rx) = RecordingApp::rejecting_admin();
    let config =
        client_config(Duration::from_secs(30)).with_resend_timeout(Duration::from_millis(150));
    let initiator = Initiator::new(config, Arc::clone(&app));
    let _connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

// ---------------------------------------------------------------------------
// SendingTime accuracy (issue #29, gap 2)
// ---------------------------------------------------------------------------

/// A message whose SendingTime is far outside the tolerance is rejected with
/// reason 10 and the session is logged out, mirroring an identity mismatch.
#[tokio::test]
async fn test_skewed_sending_time_rejects_with_reason_10_and_closes() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;

        // A SendingTime years in the past, well outside any sane tolerance.
        ok(
            framed
                .send(venue_msg_at(
                    "8",
                    2,
                    "20200101-00:00:00.000",
                    &[(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")],
                ))
                .await,
            "send stale report",
        );

        let reject = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reject), "3");
        assert_eq!(field(&reject, 45).as_deref(), Some("2"));
        assert_eq!(field(&reject, 373).as_deref(), Some("10"));
        assert_eq!(field(&reject, 371).as_deref(), Some("52"));

        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5");
    });

    let (app, mut app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "the skewed session must close within 5s",
    );
    assert!(
        timeout(Duration::from_millis(200), app_rx.recv())
            .await
            .is_err(),
        "a message with a bad SendingTime must not be delivered"
    );

    ok(acceptor.await, "acceptor task");
}

/// With the tolerance switched off, the same stale SendingTime is accepted and
/// the message is delivered.
#[tokio::test]
async fn test_zero_tolerance_accepts_any_sending_time() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        ok(
            framed
                .send(venue_msg_at(
                    "8",
                    2,
                    "20200101-00:00:00.000",
                    &[(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")],
                ))
                .await,
            "send stale report",
        );
    });

    let (app, mut app_rx) = RecordingApp::new();
    let config = client_config(Duration::from_secs(30)).with_sending_time_tolerance(Duration::ZERO);
    let initiator = Initiator::new(config, Arc::clone(&app));
    let _connection = ok(initiator.connect(addr).await, "connect");

    let delivered = ok(
        timeout(Duration::from_secs(5), app_rx.recv()).await,
        "the message must be delivered with the check off",
    );
    assert_eq!(delivered.as_deref(), Some("8"));

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

// ---------------------------------------------------------------------------
// Positional CompID enforcement (issue #29, gap 3)
// ---------------------------------------------------------------------------

/// A frame that carries the CompIDs only after the message body, not in the
/// standard header, is rejected with reason 9 and the session is closed. The
/// tags are present and correct; only their placement is wrong.
#[tokio::test]
async fn test_comp_ids_outside_the_header_reject_and_close() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;

        // 11 (ClOrdID) opens the body; the CompIDs sit after it, so they are
        // no longer in the standard header. Hand-rolled, since the encoder
        // stamps a conforming header.
        let now = Timestamp::now().format_millis();
        let body = format!(
            "35=8\x0134=2\x0152={}\x0111=ORDER-1\x0149=VENUE\x0156=CLIENT\x01",
            now.as_str()
        );
        ok(
            framed.send(raw_frame(body.as_bytes())).await,
            "send body-CompID frame",
        );

        let reject = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reject), "3");
        assert_eq!(field(&reject, 45).as_deref(), Some("2"));
        assert_eq!(field(&reject, 373).as_deref(), Some("9"));
        assert_eq!(field(&reject, 371).as_deref(), Some("49"));

        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5");
    });

    let (app, mut app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "the misplaced-CompID session must close within 5s",
    );
    assert!(
        timeout(Duration::from_millis(200), app_rx.recv())
            .await
            .is_err(),
        "a frame missing header CompIDs must not be delivered"
    );

    ok(acceptor.await, "acceptor task");
}

/// with_initial_sequences seeds both counters for session continuity.
#[tokio::test]
async fn test_with_initial_sequences_seeds_counters() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let logon = next_frame(&mut framed).await;
        assert_eq!(field(&logon, 34).as_deref(), Some("7"));
        ok(
            framed
                .send(venue_msg("A", 9, &[(98, "0"), (108, "30")]))
                .await,
            "send logon ack",
        );

        let order = next_frame(&mut framed).await;
        assert_eq!(field(&order, 34).as_deref(), Some("8"));
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_initial_sequences(7, 9);
    let connection = ok(initiator.connect(addr).await, "connect");

    assert_eq!(connection.next_sender_seq(), 8);
    assert_eq!(connection.next_target_seq(), 10);

    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order.push_str(11, "ORDER-1");
    ok(connection.send(order).await, "send order");

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

// ---------------------------------------------------------------------------
// SequenceReset classification runs before the application callback
// ---------------------------------------------------------------------------

/// A GapFill whose own MsgSeqNum is gapped must trigger a ResendRequest even
/// when the application would reject it: sequence classification runs before
/// `from_admin`, so the rejection cannot turn the required ResendRequest into a
/// session Reject.
#[tokio::test]
async fn test_gapped_gap_fill_rejected_by_app_requests_resend_not_reject() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        // Expecting 2, but the GapFill claims 34=7 and jumps to 20.
        ok(
            framed
                .send(venue_msg("4", 7, &[(123, "Y"), (36, "20")]))
                .await,
            "send gapped gap fill",
        );

        // The reply must be a ResendRequest (35=2), never a session Reject.
        let reply = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reply), "2");
        assert_eq!(field(&reply, 7).as_deref(), Some("2"));
        assert_eq!(field(&reply, 16).as_deref(), Some("0"));
    });

    // rejecting_admin makes from_admin reject every non-Logon admin message: if
    // it were reached for the gapped fill the reply would be a 35=3 Reject.
    let (app, _app_rx) = RecordingApp::rejecting_admin();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
    // NewSeqNo must NOT have been applied.
    assert_eq!(connection.next_target_seq(), 2);
}

/// A too-low GapFill flagged PossDup is an already-applied duplicate: it is
/// dropped before `from_admin` runs. With a from_admin that rejects every admin
/// message, the discriminator is that NO session Reject comes back for the
/// duplicate -- the callback was never reached.
#[tokio::test]
async fn test_too_low_duplicate_gap_fill_dropped_without_from_admin() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;

        // Advance the client's target past 2 with an in-order report at 34=2.
        ok(
            framed
                .send(venue_msg(
                    "8",
                    2,
                    &[(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")],
                ))
                .await,
            "send report at 2",
        );
        // Too-low GapFill (34=2) flagged PossDup: an already-applied duplicate.
        ok(
            framed
                .send(venue_msg("4", 2, &[(123, "Y"), (43, "Y"), (36, "3")]))
                .await,
            "send too-low duplicate gap fill",
        );
        // The next in-order report at 34=3 proves the session survived and the
        // duplicate consumed nothing.
        ok(
            framed
                .send(venue_msg(
                    "8",
                    3,
                    &[(37, "EX-2"), (17, "E-2"), (150, "0"), (39, "0")],
                ))
                .await,
            "send report at 3",
        );

        // No session Reject may come back for the dropped duplicate.
        assert!(
            timeout(Duration::from_millis(300), framed.next())
                .await
                .is_err(),
            "a too-low duplicate must be dropped, not rejected via from_admin"
        );
    });

    let (app, mut app_rx) = RecordingApp::rejecting_admin();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    // Both reports (application messages) are delivered; the duplicate GapFill
    // is not.
    for expected in ["8", "8"] {
        let received = some(
            ok(
                timeout(Duration::from_secs(5), app_rx.recv()).await,
                "app message within 5s",
            ),
            "app channel must stay open",
        );
        assert_eq!(received, expected);
    }

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
    // Target advanced 2 -> 3 -> 4; the duplicate at 2 consumed nothing.
    assert_eq!(connection.next_target_seq(), 4);
}

/// A GapFillFlag (123) that is present but neither Y nor N is a data-format
/// error: session Reject with reason 6 and RefTagID 123, not a silent Reset.
#[tokio::test]
async fn test_sequence_reset_malformed_gap_fill_flag_is_rejected() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        ok(
            framed
                .send(venue_msg("4", 2, &[(123, "X"), (36, "10")]))
                .await,
            "send malformed gap fill flag",
        );

        let reject = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reject), "3");
        assert_eq!(field(&reject, 45).as_deref(), Some("2"));
        assert_eq!(field(&reject, 372).as_deref(), Some("4"));
        assert_eq!(field(&reject, 373).as_deref(), Some("6"));
        assert_eq!(field(&reject, 371).as_deref(), Some("123"));
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
    // The malformed reset was rejected without touching sequence state.
    assert_eq!(connection.next_target_seq(), 2);
}

// ---------------------------------------------------------------------------
// Logon ack BeginString validation
// ---------------------------------------------------------------------------

/// A Logon ack whose BeginString differs from the configured session version
/// aborts the handshake: an ack in a different FIX dialect is not this
/// session's acknowledgement, whatever its CompIDs say.
#[tokio::test]
async fn test_logon_ack_wrong_begin_string_fails_handshake() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        // The client is configured FIX.4.4; ack with FIX.4.2.
        let mut encoder = Encoder::new("FIX.4.2");
        encoder.put_str(35, "A");
        encoder.put_str(49, "VENUE");
        encoder.put_str(56, "CLIENT");
        encoder.put_uint(34, 1);
        encoder.put_str(52, Timestamp::now().format_millis().as_str());
        encoder.put_str(98, "0");
        encoder.put_str(108, "30");
        let ack = match encoder.finish() {
            Ok(bytes) => bytes,
            Err(err) => panic!("encode wrong-version logon ack: {err}"),
        };
        ok(framed.send(ack).await, "send wrong-version logon ack");
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));

    match initiator.connect(addr).await {
        Err(EngineError::BeginStringMismatch { expected, received }) => {
            assert_eq!(expected, "FIX.4.4");
            assert_eq!(received, "FIX.4.2");
        }
        other => panic!("expected BeginStringMismatch, got {other:?}"),
    }

    ok(acceptor.await, "acceptor task");
}

/// A Logon ack whose MsgSeqNum (34) sits only after the body, not in the
/// standard header, fails the handshake: the initiator reads 34 positionally,
/// the same contract the Acceptor handshake and the in-session reactor use.
#[tokio::test]
async fn test_logon_ack_body_only_msg_seq_num_fails_handshake() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;

        // 98 (EncryptMethod) is a body field, so the standard-header run ends at
        // it; the 34 placed after it is not the header MsgSeqNum. Built by hand
        // to place 34 after that body field.
        let ts = Timestamp::now().format_millis();
        let body = format!(
            "35=A\x0149=VENUE\x0156=CLIENT\x0152={}\x0198=0\x01108=30\x0134=1\x01",
            ts.as_str()
        );
        ok(
            framed.send(raw_frame(body.as_bytes())).await,
            "send logon ack with a body-only MsgSeqNum",
        );
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));

    match initiator.connect(addr).await {
        Err(EngineError::Sequence(detail)) => {
            assert!(detail.contains("MsgSeqNum"), "got {detail}");
        }
        other => panic!("expected a Sequence error, got {other:?}"),
    }

    ok(acceptor.await, "acceptor task");
}

/// A zero initial sequence seed is refused before the socket is dialled: a
/// seeded MsgSeqNum (34) of 0 would be rejected by every conforming
/// counterparty, since FIX numbers messages from 1.
#[tokio::test]
async fn test_connect_with_zero_initial_sender_seq_is_rejected() {
    let (listener, addr) = bind_listener().await;

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_initial_sequences(0, 9);

    match initiator.connect(addr).await {
        Err(EngineError::InvalidInitialSequence { counter }) => {
            assert_eq!(counter, SequenceCounter::Sender);
        }
        Err(other) => panic!("expected an invalid-sequence error, got {other:?}"),
        Ok(_) => panic!("a zero MsgSeqNum seed must not establish a session"),
    }

    assert!(
        timeout(Duration::from_millis(200), listener.accept())
            .await
            .is_err(),
        "the socket must never be dialled"
    );
}

/// The target side of the zero-seed guard: a zero incoming seed is refused the
/// same way, before the socket is dialled.
#[tokio::test]
async fn test_connect_with_zero_initial_target_seq_is_rejected() {
    let (listener, addr) = bind_listener().await;

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_initial_sequences(7, 0);

    match initiator.connect(addr).await {
        Err(EngineError::InvalidInitialSequence { counter }) => {
            assert_eq!(counter, SequenceCounter::Target);
        }
        Err(other) => panic!("expected an invalid-sequence error, got {other:?}"),
        Ok(_) => panic!("a zero MsgSeqNum seed must not establish a session"),
    }

    assert!(
        timeout(Duration::from_millis(200), listener.accept())
            .await
            .is_err(),
        "the socket must never be dialled"
    );
}

/// A configuration knob that would corrupt the session's own messages is
/// refused before the socket is dialled: an identity string carrying SOH would
/// terminate tag 50 early in every outbound header.
#[tokio::test]
async fn test_connect_refuses_an_invalid_configuration_without_dialling() {
    let (listener, addr) = bind_listener().await;

    let (app, _app_rx) = RecordingApp::new();
    let config = client_config(Duration::from_secs(30)).with_sender_sub_id("DE\x01SK");
    let initiator = Initiator::new(config, Arc::clone(&app));

    match initiator.connect(addr).await {
        Err(EngineError::Config(SessionConfigError::IllegalByte {
            field,
            byte,
            position,
        })) => {
            assert_eq!(field, "sender_sub_id");
            assert_eq!(byte, 0x01);
            assert_eq!(position, 2);
        }
        Err(other) => panic!("expected a configuration error, got {other:?}"),
        Ok(_) => panic!("an unencodable SenderSubID must not establish a session"),
    }

    assert!(
        timeout(Duration::from_millis(200), listener.accept())
            .await
            .is_err(),
        "the socket must never be dialled"
    );
}

/// A fractional heartbeat interval never reaches the wire: HeartBtInt (108) is
/// whole seconds, and truncating 500ms to 108=0 would negotiate no
/// heartbeating at all.
#[tokio::test]
async fn test_connect_refuses_a_fractional_heartbeat_interval() {
    let (listener, addr) = bind_listener().await;

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_millis(500)), Arc::clone(&app));

    match initiator.connect(addr).await {
        Err(EngineError::Config(SessionConfigError::FractionalHeartbeatInterval { interval })) => {
            assert_eq!(interval, Duration::from_millis(500));
        }
        Err(other) => panic!("expected a configuration error, got {other:?}"),
        Ok(_) => panic!("a sub-second HeartBtInt must not establish a session"),
    }

    assert!(
        timeout(Duration::from_millis(200), listener.accept())
            .await
            .is_err(),
        "the socket must never be dialled"
    );
}

// ---------------------------------------------------------------------------
// Resend from a message store
// ---------------------------------------------------------------------------

/// Wraps a [`MemoryStore`] and silently forgets one sequence number, standing
/// in for a store that has evicted a message the counterparty still asks for.
///
/// The engine must gap-fill the forgotten number rather than skip it: a skipped
/// number leaves the counterparty expecting a message that will never arrive.
#[derive(Debug)]
struct ForgetfulStore {
    inner: MemoryStore,
    forget: u64,
}

impl ForgetfulStore {
    fn new(forget: u64) -> Self {
        Self {
            inner: MemoryStore::new(),
            forget,
        }
    }
}

#[async_trait]
impl MessageStore for ForgetfulStore {
    async fn store(
        &self,
        seq_num: u64,
        msg_type: &MsgType,
        message: &[u8],
    ) -> Result<(), StoreError> {
        if seq_num == self.forget {
            return Ok(());
        }
        self.inner.store(seq_num, msg_type, message).await
    }

    async fn get_range(&self, begin: u64, end: u64) -> Result<Vec<StoredMessage>, StoreError> {
        self.inner.get_range(begin, end).await
    }

    fn next_sender_seq(&self) -> u64 {
        self.inner.next_sender_seq()
    }

    fn next_target_seq(&self) -> u64 {
        self.inner.next_target_seq()
    }

    async fn set_next_sender_seq(&self, seq: u64) -> Result<(), StoreError> {
        self.inner.set_next_sender_seq(seq).await
    }

    async fn set_next_target_seq(&self, seq: u64) -> Result<(), StoreError> {
        self.inner.set_next_target_seq(seq).await
    }

    async fn reset(&self) -> Result<(), StoreError> {
        self.inner.reset().await
    }

    fn creation_time(&self) -> std::time::SystemTime {
        self.inner.creation_time()
    }
}

/// One original send, as the stub acceptor observed it.
struct SentOrder {
    /// ClOrdID (11), so the replay can be matched to the original.
    cl_ord_id: String,
    /// SendingTime (52), which must reappear as OrigSendingTime (122).
    sending_time: String,
}

/// Drains `count` orders starting at sequence `first`, recording what the
/// acceptor saw so a later replay can be compared against it.
async fn drain_orders(
    framed: &mut Framed<TcpStream, FixCodec>,
    first: u64,
    count: u64,
) -> Vec<SentOrder> {
    let mut sent = Vec::new();
    for offset in 0..count {
        let frame = next_frame(framed).await;
        assert_eq!(msg_type_of(&frame), "D");
        assert_eq!(field(&frame, 34), Some((first + offset).to_string()));
        assert_eq!(
            field(&frame, 43),
            None,
            "an original send is not a possible duplicate"
        );
        sent.push(SentOrder {
            cl_ord_id: some(field(&frame, 11), "order must carry ClOrdID (11)"),
            sending_time: some(field(&frame, 52), "order must carry SendingTime (52)"),
        });
    }
    sent
}

/// Asserts that `frame` is `original` replayed under sequence number `seq`.
#[track_caller]
fn assert_replay_of(frame: &[u8], seq: u64, original: &SentOrder) {
    assert_eq!(msg_type_of(frame), "D");
    assert_eq!(field(frame, 34), Some(seq.to_string()));
    assert_eq!(
        field(frame, 11).as_deref(),
        Some(original.cl_ord_id.as_str()),
        "the replayed body must be the original body"
    );
    assert_eq!(
        field(frame, 43).as_deref(),
        Some("Y"),
        "a resend must carry PossDupFlag"
    );
    assert_eq!(
        field(frame, 122).as_deref(),
        Some(original.sending_time.as_str()),
        "OrigSendingTime must be the original SendingTime, not a fresh one"
    );
}

/// Asserts that `frame` is a SequenceReset-GapFill occupying `seq` and
/// advancing the counterparty to `new_seq`.
#[track_caller]
fn assert_gap_fill(frame: &[u8], seq: u64, new_seq: u64) {
    assert_eq!(msg_type_of(frame), "4");
    assert_eq!(field(frame, 123).as_deref(), Some("Y"));
    assert_eq!(field(frame, 34), Some(seq.to_string()));
    assert_eq!(field(frame, 36), Some(new_seq.to_string()));
    assert_eq!(field(frame, 43).as_deref(), Some("Y"));
    assert!(field(frame, 122).is_some(), "PossDup requires 122");
}

/// Sends `count` orders on the connection.
async fn send_orders(connection: &ironfix_engine::Connection, count: usize) {
    for index in 0..count {
        let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
        order.push_str(11, &format!("ORDER-{index}"));
        ok(connection.send(order).await, "send order");
    }
}

/// With a store attached, a bounded ResendRequest replays the real application
/// messages — same bodies, same sequence numbers — carrying PossDupFlag (43)
/// and the original SendingTime in OrigSendingTime (122).
#[tokio::test]
async fn test_resend_request_replays_stored_application_messages() {
    let (listener, addr) = bind_listener().await;
    let (replay_seen_tx, replay_seen_rx) = tokio::sync::oneshot::channel::<()>();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        let sent = drain_orders(&mut framed, 2, 3).await;

        ok(
            framed.send(venue_msg("2", 2, &[(7, "2"), (16, "4")])).await,
            "send bounded resend request",
        );

        for (seq, original) in (2..).zip(sent.iter()) {
            let replayed = next_frame(&mut framed).await;
            assert_replay_of(&replayed, seq, original);
        }

        let _ = replay_seen_tx.send(());

        // A replay re-occupies the numbers it replaces and allocates nothing,
        // so the next real message still goes out at 5.
        let next = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&next), "D");
        assert_eq!(field(&next, 34).as_deref(), Some("5"));
        assert_eq!(field(&next, 43), None);
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::new(MemoryStore::new()));
    let connection = ok(initiator.connect(addr).await, "connect");

    send_orders(&connection, 3).await;

    ok(
        timeout(Duration::from_secs(5), replay_seen_rx).await,
        "replay observed within 5s",
    )
    .ok();
    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order.push_str(11, "ORDER-AFTER-REPLAY");
    ok(connection.send(order).await, "send order after replay");

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// Administrative messages inside the requested range are gap-filled rather
/// than replayed: sequence 1 is the Logon, so the reply opens with a gap fill
/// advancing to the first application message.
#[tokio::test]
async fn test_resend_request_gap_fills_admin_messages_before_replaying_orders() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        let sent = drain_orders(&mut framed, 2, 3).await;

        ok(
            framed.send(venue_msg("2", 2, &[(7, "1"), (16, "4")])).await,
            "send resend request covering the Logon",
        );

        // Sequence 1 is our Logon: administrative, so it is filled, not resent.
        let fill = next_frame(&mut framed).await;
        assert_gap_fill(&fill, 1, 2);

        for (seq, original) in (2..).zip(sent.iter()) {
            let replayed = next_frame(&mut framed).await;
            assert_replay_of(&replayed, seq, original);
        }
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::new(MemoryStore::new()));
    let connection = ok(initiator.connect(addr).await, "connect");

    send_orders(&connection, 3).await;

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// A sequence number the store cannot produce is gap-filled in place, between
/// the messages either side of it, so the counterparty is never desynchronised
/// by a hole in the replay.
#[tokio::test]
async fn test_resend_request_gap_fills_a_message_the_store_lost() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        let sent = drain_orders(&mut framed, 2, 3).await;

        ok(
            framed.send(venue_msg("2", 2, &[(7, "2"), (16, "4")])).await,
            "send bounded resend request",
        );

        let first = next_frame(&mut framed).await;
        let [second, _, fourth] = sent.as_slice() else {
            panic!("three orders must have been recorded, got {}", sent.len());
        };
        assert_replay_of(&first, 2, second);

        // 3 was never filed, so it is covered by a fill that stops at 4.
        let fill = next_frame(&mut framed).await;
        assert_gap_fill(&fill, 3, 4);

        let last = next_frame(&mut framed).await;
        assert_replay_of(&last, 4, fourth);
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::new(ForgetfulStore::new(3)));
    let connection = ok(initiator.connect(addr).await, "connect");

    send_orders(&connection, 3).await;

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// A hole at the end of the requested range is covered by a trailing gap fill,
/// so the counterparty's expectation still lands exactly on EndSeqNo + 1.
#[tokio::test]
async fn test_resend_request_trailing_hole_is_gap_filled_to_the_bound() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        let sent = drain_orders(&mut framed, 2, 3).await;

        ok(
            framed.send(venue_msg("2", 2, &[(7, "2"), (16, "4")])).await,
            "send bounded resend request",
        );

        let [second, third, _] = sent.as_slice() else {
            panic!("three orders must have been recorded, got {}", sent.len());
        };
        let first_replay = next_frame(&mut framed).await;
        assert_replay_of(&first_replay, 2, second);
        let second_replay = next_frame(&mut framed).await;
        assert_replay_of(&second_replay, 3, third);

        // 4 was never filed: the trailing fill still advances to EndSeqNo + 1.
        let fill = next_frame(&mut framed).await;
        assert_gap_fill(&fill, 4, 5);
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::new(ForgetfulStore::new(4)));
    let connection = ok(initiator.connect(addr).await, "connect");

    send_orders(&connection, 3).await;

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// EndSeqNo = 0 with a store replays everything from BeginSeqNo up to the
/// last message actually sent.
#[tokio::test]
async fn test_resend_request_unbounded_replays_to_the_last_sent_message() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        let sent = drain_orders(&mut framed, 2, 3).await;

        ok(
            framed.send(venue_msg("2", 2, &[(7, "2"), (16, "0")])).await,
            "send unbounded resend request",
        );

        for (seq, original) in (2..).zip(sent.iter()) {
            let replayed = next_frame(&mut framed).await;
            assert_replay_of(&replayed, seq, original);
        }

        // Everything up to next-sender-1 was replayed, so there is nothing
        // left to fill: the next frame is the client's Logout.
        ok(
            framed.send(venue_msg("5", 3, &[])).await,
            "send logout to end the test deterministically",
        );
        let reply = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reply), "5");
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::new(MemoryStore::new()));
    let connection = ok(initiator.connect(addr).await, "connect");

    send_orders(&connection, 3).await;
    connection.wait_closed().await;

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// A directory for one test, removed when the test ends, pass or fail.
struct TestDir(std::path::PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("ironfix-engine-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The fields of `frame`, in order, without the ones a resend may change:
/// BodyLength (9), CheckSum (10), PossDupFlag (43), SendingTime (52) and
/// OrigSendingTime (122).
fn resend_invariant_fields(frame: &[u8]) -> Vec<(u32, Vec<u8>)> {
    let mut decoder = Decoder::new(frame);
    let raw = ok(decoder.decode(), "frame must decode");
    raw.fields()
        .filter(|field| !matches!(field.tag().value(), 9 | 10 | 43 | 52 | 122))
        .map(|field| (field.tag().value(), field.as_bytes().to_vec()))
        .collect()
}

/// Asserts that `replayed` is `original` resent: every field the same, in the
/// same order, apart from the ones a resend changes, with PossDupFlag (43) = Y
/// and the original SendingTime (52) as OrigSendingTime (122).
#[track_caller]
fn assert_resent(replayed: &[u8], original: &[u8]) {
    assert_eq!(
        resend_invariant_fields(replayed),
        resend_invariant_fields(original),
        "a resend carries the original message under its original number"
    );
    assert_eq!(field(replayed, 43).as_deref(), Some("Y"));
    assert_eq!(field(replayed, 122), field(original, 52));
}

/// A `FileStore` carries a session across a restart: the first engine is
/// dropped and its store closed, the store is reopened in a new `Initiator`,
/// and the new session resumes from the stored counters and answers a
/// `ResendRequest` with the original frames under their original numbers,
/// field for field, with `PossDupFlag` (43) = Y and the original `SendingTime`
/// in `OrigSendingTime` (122). Administrative messages, the previous process's
/// included, are gap-filled.
#[tokio::test]
async fn test_file_store_resends_original_messages_after_a_restart() {
    let dir = TestDir::new("file-store-restart");
    let config = ok(
        FileStoreConfig::try_new(&dir.0, "FIX.4.4-CLIENT-VENUE"),
        "store config",
    );

    // First process: Logon at 1, orders at 2..=4, then the venue logs out and
    // the client's Logout reply goes out at 5.
    let (listener, addr) = bind_listener().await;
    let first_venue = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        let mut orders = Vec::new();
        for seq in 2..=4u64 {
            let order = next_frame(&mut framed).await;
            assert_eq!(msg_type_of(&order), "D");
            assert_eq!(field(&order, 34), Some(seq.to_string()));
            assert_eq!(field(&order, 43), None, "an original send");
            orders.push(order);
        }
        ok(framed.send(venue_msg("5", 2, &[])).await, "venue logout");
        let reply = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reply), "5");
        assert_eq!(field(&reply, 34).as_deref(), Some("5"));
        orders
    });
    let store = Arc::new(ok(
        FileStore::open(config.clone().with_create_if_missing(true)).await,
        "create the store",
    ));
    {
        let (app, _app_rx) = RecordingApp::new();
        let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
        let connection = ok(initiator.connect(addr).await, "first connect");
        send_orders(&connection, 3).await;
        ok(
            timeout(Duration::from_secs(5), connection.wait_closed()).await,
            "first session closes within 5s",
        );
    }
    let orders = ok(
        ok(
            timeout(Duration::from_secs(5), first_venue).await,
            "first venue done within 5s",
        ),
        "first venue task",
    );
    // The reactor lets go of the store as its task ends. Wait for that, then
    // close the store, as the process exiting would.
    ok(
        timeout(Duration::from_secs(5), async {
            while Arc::strong_count(&store) > 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await,
        "the engine releases the store when its session ends",
    );
    drop(store);

    // Second process: the store must already exist, and holds both counters
    // and the frames.
    let store = ok(FileStore::open(config).await, "reopen the store");
    assert_eq!(store.next_sender_seq(), 6);
    assert_eq!(store.next_target_seq(), 3);

    let (listener, addr) = bind_listener().await;
    let second_venue = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let logon = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logon), "A");
        assert_eq!(
            field(&logon, 34).as_deref(),
            Some("6"),
            "the Logon resumes from the stored sender counter"
        );
        assert_eq!(field(&logon, 141), None, "no sequence reset");
        ok(
            framed
                .send(venue_msg("A", 3, &[(98, "0"), (108, "30")]))
                .await,
            "send the Logon ack at the stored target counter",
        );

        // A bounded request for the previous process's orders.
        ok(
            framed.send(venue_msg("2", 4, &[(7, "2"), (16, "4")])).await,
            "ask for 2..=4",
        );
        for original in &orders {
            let replayed = next_frame(&mut framed).await;
            assert_resent(&replayed, original);
        }

        // The whole session: the Logon of the previous process (1), its
        // Logout (5) and this process's Logon (6) are administrative and
        // gap-filled; the orders are replayed between them.
        ok(
            framed.send(venue_msg("2", 5, &[(7, "1"), (16, "0")])).await,
            "ask for 1..=infinity",
        );
        let leading = next_frame(&mut framed).await;
        assert_gap_fill(&leading, 1, 2);
        for original in &orders {
            let replayed = next_frame(&mut framed).await;
            assert_resent(&replayed, original);
        }
        let trailing = next_frame(&mut framed).await;
        assert_gap_fill(&trailing, 5, 7);

        ok(framed.send(venue_msg("5", 6, &[])).await, "venue logout");
        let reply = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reply), "5");
        assert_eq!(
            field(&reply, 34).as_deref(),
            Some("7"),
            "a replay allocates no sender number"
        );
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::new(store));
    let connection = ok(initiator.connect(addr).await, "second connect");
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "second session closes within 5s",
    );
    ok(
        ok(
            timeout(Duration::from_secs(5), second_venue).await,
            "second venue done within 5s",
        ),
        "second venue task",
    );
    drop(initiator);
}

/// A store whose reads report the store corrupted, standing in for a durable
/// store that finds one of its records damaged when a resend reads it.
#[derive(Debug)]
struct CorruptStore {
    inner: MemoryStore,
}

#[async_trait]
impl MessageStore for CorruptStore {
    async fn store(
        &self,
        seq_num: u64,
        msg_type: &MsgType,
        message: &[u8],
    ) -> Result<(), StoreError> {
        self.inner.store(seq_num, msg_type, message).await
    }

    async fn get_range(&self, _begin: u64, _end: u64) -> Result<Vec<StoredMessage>, StoreError> {
        Err(StoreError::Corrupted {
            reason: "a record failed its checksum".to_string(),
        })
    }

    fn next_sender_seq(&self) -> u64 {
        self.inner.next_sender_seq()
    }

    fn next_target_seq(&self) -> u64 {
        self.inner.next_target_seq()
    }

    async fn set_next_sender_seq(&self, seq: u64) -> Result<(), StoreError> {
        self.inner.set_next_sender_seq(seq).await
    }

    async fn set_next_target_seq(&self, seq: u64) -> Result<(), StoreError> {
        self.inner.set_next_target_seq(seq).await
    }

    async fn reset(&self) -> Result<(), StoreError> {
        self.inner.reset().await
    }

    fn creation_time(&self) -> std::time::SystemTime {
        self.inner.creation_time()
    }
}

/// A store that reports itself corrupted while a resend is read cannot say
/// which messages it still holds: the engine closes the session rather than
/// gap-filling application messages the counterparty may never have received.
#[tokio::test]
async fn test_corrupted_store_closes_the_session_instead_of_gap_filling_a_resend() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        let _ = drain_orders(&mut framed, 2, 2).await;
        ok(
            framed.send(venue_msg("2", 2, &[(7, "2"), (16, "3")])).await,
            "ask for the orders",
        );
        // Everything the client sends until it hangs up.
        let mut after = Vec::new();
        while let Ok(Some(Ok(frame))) = timeout(Duration::from_secs(5), framed.next()).await {
            after.push((msg_type_of(&frame), field(&frame, 43)));
        }
        after
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::new(CorruptStore {
            inner: MemoryStore::new(),
        }));
    let connection = ok(initiator.connect(addr).await, "connect");
    send_orders(&connection, 2).await;
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "the session closes within 5s",
    );

    let after = ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
    assert!(
        after
            .iter()
            .all(|(msg_type, poss_dup)| msg_type != "4" && poss_dup.is_none()),
        "neither a gap fill nor a replay answers the request: {after:?}"
    );
}

/// A store write that fails outright, not only one that overruns the store
/// timeout, may have changed the store before failing: under `Continue` the
/// session carries on, and the next connect resets the store and logs on at
/// 1 with `ResetSeqNumFlag` (141).
#[tokio::test]
async fn test_a_failed_store_write_leaves_a_reset_owed_under_continue() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let (socket, _) = ok(listener.accept().await, "accept the first connection");
        let mut framed = Framed::new(socket, FixCodec::new());
        let _logon = next_frame(&mut framed).await;
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "30")]))
                .await,
            "send logon ack",
        );
        // Continue: the order is sent although the store refused it.
        let order = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&order), "D");
        drop(framed);

        let (socket, _) = ok(listener.accept().await, "accept the second connection");
        let mut framed = Framed::new(socket, FixCodec::new());
        let logon = next_frame(&mut framed).await;
        (field(&logon, 34), field(&logon, 141), framed)
    });

    let store = Arc::new(FailingStore::working());
    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let first = ok(initiator.connect(addr).await, "connect");
    store.fail_store.store(true, Ordering::SeqCst);
    send_orders(&first, 1).await;
    ok(
        timeout(Duration::from_secs(5), first.wait_closed()).await,
        "the first session closes within 5s",
    );
    store.fail_store.store(false, Ordering::SeqCst);

    // The reconnect stops at the Logon; the stub reads it and keeps the socket.
    let _ = timeout(Duration::from_secs(2), initiator.connect(addr)).await;
    let (seq, reset, _framed) = ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
    assert_eq!(
        seq.as_deref(),
        Some("1"),
        "the next session starts a new stream"
    );
    assert_eq!(reset.as_deref(), Some("Y"), "and declares it");
}

/// A store carries sequence numbers as well as messages: a session started
/// against a store holding counters resumes from them, and mirrors its own
/// counters back into it.
#[tokio::test]
async fn test_initiator_seeds_and_mirrors_sequence_numbers_through_the_store() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;

        let logon = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logon), "A");
        // Seeded from the store, not from 1.
        assert_eq!(field(&logon, 34).as_deref(), Some("7"));
        ok(
            framed
                .send(venue_msg("A", 4, &[(98, "0"), (108, "30")]))
                .await,
            "send logon ack",
        );

        let order = next_frame(&mut framed).await;
        assert_eq!(field(&order, 34).as_deref(), Some("8"));
    });

    let store = Arc::new(MemoryStore::new());
    ok(
        store.set_next_sender_seq(7).await,
        "seed the sender counter",
    );
    ok(
        store.set_next_target_seq(4).await,
        "seed the target counter",
    );

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let connection = ok(initiator.connect(addr).await, "connect");

    send_orders(&connection, 1).await;

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );

    // The counters advanced in the session are visible in the store: 7 (Logon)
    // and 8 (the order) were sent, and the Logon ack at 4 was consumed.
    assert_eq!(connection.next_sender_seq(), 9);
    assert_eq!(store.next_sender_seq(), 9);
    assert_eq!(store.next_target_seq(), 5);

    // And the frames themselves are filed under the numbers they went out with.
    let stored = ok(store.get_range(7, 8).await, "the store must hold 7..=8");
    assert_eq!(
        stored
            .iter()
            .map(|message| (message.seq_num(), message.msg_type().as_str().to_string()))
            .collect::<Vec<_>>(),
        vec![(7, "A".to_string()), (8, "D".to_string())]
    );
}

/// A session that resets its counters when it closes must clear the store with
/// them: otherwise the next session, numbering from 1 again, would file its
/// messages on top of this one's and could answer a resend with the wrong
/// session's traffic.
#[tokio::test]
async fn test_reset_on_disconnect_clears_the_store() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        let _ = drain_orders(&mut framed, 2, 1).await;
        // Dropping the socket closes the session abnormally.
        drop(framed);
    });

    let store = Arc::new(MemoryStore::new());
    let mut config = client_config(Duration::from_secs(30));
    config.reset_on_disconnect = true;

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(config, Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let connection = ok(initiator.connect(addr).await, "connect");

    send_orders(&connection, 1).await;
    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
    connection.wait_closed().await;

    assert_eq!(store.message_count(), 0);
    assert_eq!(store.next_sender_seq(), 1);
    assert_eq!(store.next_target_seq(), 1);
}

/// A Logon declaring ResetSeqNumFlag starts both counters at 1 and clears the
/// store, so the numbers the new session hands out cannot collide with
/// messages an earlier one filed under them.
#[tokio::test]
async fn test_reset_on_logon_clears_a_populated_store() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;

        let logon = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logon), "A");
        assert_eq!(field(&logon, 141).as_deref(), Some("Y"));
        // Numbered from 1 despite the store reporting 42.
        assert_eq!(field(&logon, 34).as_deref(), Some("1"));
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "30"), (141, "Y")]))
                .await,
            "send logon ack",
        );

        let order = next_frame(&mut framed).await;
        assert_eq!(field(&order, 34).as_deref(), Some("2"));
    });

    let store = Arc::new(MemoryStore::new());
    ok(
        store.store(41, &MsgType::NewOrderSingle, b"stale").await,
        "seed the store with a previous session's message",
    );
    ok(
        store.set_next_sender_seq(42).await,
        "seed the sender counter",
    );
    ok(
        store.set_next_target_seq(17).await,
        "seed the target counter",
    );

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(
        client_config(Duration::from_secs(30)).with_reset_on_logon(true),
        Arc::clone(&app),
    )
    .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let connection = ok(initiator.connect(addr).await, "connect");

    assert!(!store.contains(41), "the stale message must be gone");

    send_orders(&connection, 1).await;

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// A store whose operations fail on demand, standing in for a persistent
/// backend that cannot vouch for its counters when the session starts, or that
/// starts refusing writes in the middle of a session.
///
/// The `refresh` failure is fixed at construction; `reset`, `store` and the
/// two counter setters can be switched on at any point through the `fail_*`
/// flags, so a test can let the handshake succeed and break the store
/// afterwards. `stall_target` makes the target setter never return, for the
/// store timeout. Every counter write that reaches the store is counted.
#[derive(Debug)]
struct FailingStore {
    inner: MemoryStore,
    fail_reset: AtomicBool,
    fail_refresh: bool,
    fail_store: AtomicBool,
    fail_sender: AtomicBool,
    fail_target: AtomicBool,
    stall_target: AtomicBool,
    sender_writes: AtomicU64,
    target_writes: AtomicU64,
    reset_to_calls: AtomicU64,
    hold_reset_to: AtomicBool,
}

impl FailingStore {
    fn working() -> Self {
        Self {
            inner: MemoryStore::new(),
            fail_reset: AtomicBool::new(false),
            fail_refresh: false,
            fail_store: AtomicBool::new(false),
            fail_sender: AtomicBool::new(false),
            fail_target: AtomicBool::new(false),
            stall_target: AtomicBool::new(false),
            sender_writes: AtomicU64::new(0),
            target_writes: AtomicU64::new(0),
            reset_to_calls: AtomicU64::new(0),
            hold_reset_to: AtomicBool::new(false),
        }
    }

    /// Files five orders of a previous stream and moves the counters past
    /// them, as a session before a reset would have left the store.
    async fn with_previous_stream(self, next_target: u64) -> Self {
        for seq in 1..=5u64 {
            let frame = venue_msg_from("CLIENT", "VENUE", "D", seq, &[(11, "OLD-SESSION")]);
            ok(
                self.inner
                    .store(seq, &MsgType::NewOrderSingle, &frame)
                    .await,
                "seed a frame of the previous stream",
            );
        }
        ok(
            self.inner.set_next_sender_seq(6).await,
            "seed the sender counter",
        );
        ok(
            self.inner.set_next_target_seq(next_target).await,
            "seed the target counter",
        );
        self
    }

    fn failing_reset() -> Self {
        let store = Self::working();
        store.fail_reset.store(true, Ordering::SeqCst);
        store
    }

    /// Counter writes so far, as (sender, target).
    fn counter_writes(&self) -> (u64, u64) {
        (
            self.sender_writes.load(Ordering::SeqCst),
            self.target_writes.load(Ordering::SeqCst),
        )
    }

    fn failing_refresh() -> Self {
        Self {
            fail_refresh: true,
            ..Self::working()
        }
    }

    /// The error every on-demand failure returns. It names the operation only,
    /// never frame bytes, as the trait contract requires.
    fn refused(what: &str) -> StoreError {
        StoreError::Io(format!("{what} refused by the test store"))
    }
}

#[async_trait]
impl MessageStore for FailingStore {
    async fn store(
        &self,
        seq_num: u64,
        msg_type: &MsgType,
        message: &[u8],
    ) -> Result<(), StoreError> {
        if self.fail_store.load(Ordering::SeqCst) {
            return Err(Self::refused("store"));
        }
        self.inner.store(seq_num, msg_type, message).await
    }

    async fn get_range(&self, begin: u64, end: u64) -> Result<Vec<StoredMessage>, StoreError> {
        self.inner.get_range(begin, end).await
    }

    fn next_sender_seq(&self) -> u64 {
        self.inner.next_sender_seq()
    }

    fn next_target_seq(&self) -> u64 {
        self.inner.next_target_seq()
    }

    async fn set_next_sender_seq(&self, seq: u64) -> Result<(), StoreError> {
        self.sender_writes.fetch_add(1, Ordering::SeqCst);
        if self.fail_sender.load(Ordering::SeqCst) {
            return Err(Self::refused("set_next_sender_seq"));
        }
        self.inner.set_next_sender_seq(seq).await
    }

    async fn set_next_target_seq(&self, seq: u64) -> Result<(), StoreError> {
        self.target_writes.fetch_add(1, Ordering::SeqCst);
        if self.stall_target.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        if self.fail_target.load(Ordering::SeqCst) {
            return Err(Self::refused("set_next_target_seq"));
        }
        self.inner.set_next_target_seq(seq).await
    }

    async fn reset(&self) -> Result<(), StoreError> {
        if self.fail_reset.load(Ordering::SeqCst) {
            return Err(StoreError::Io("reset failed".to_string()));
        }
        self.inner.reset().await
    }

    /// Counted, then the same three steps as the trait's default.
    async fn reset_to(&self, next_sender: u64, next_target: u64) -> Result<(), StoreError> {
        self.reset_to_calls.fetch_add(1, Ordering::SeqCst);
        if self.hold_reset_to.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        self.reset().await?;
        self.set_next_sender_seq(next_sender).await?;
        self.set_next_target_seq(next_target).await
    }

    fn creation_time(&self) -> std::time::SystemTime {
        self.inner.creation_time()
    }

    async fn refresh(&self) -> Result<(), StoreError> {
        if self.fail_refresh {
            return Err(StoreError::Io("refresh failed".to_string()));
        }
        Ok(())
    }
}

/// A ResetSeqNumFlag Logon whose store cannot be cleared must abort the
/// handshake with a typed error, not start at 1 with the previous stream still
/// filed — which a later ResendRequest could then replay as this session's.
#[tokio::test]
async fn test_reset_on_logon_aborts_when_the_store_cannot_be_reset() {
    // The connection is dialled before the store is seeded, so a listener must
    // be bound; the handshake never gets far enough to send a Logon.
    let (_listener, addr) = bind_listener().await;

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(
        client_config(Duration::from_secs(30)).with_reset_on_logon(true),
        Arc::clone(&app),
    )
    .with_store(Arc::new(FailingStore::failing_reset()) as Arc<dyn MessageStore>);

    match initiator.connect(addr).await {
        Err(EngineError::Store(_)) => {}
        Err(other) => panic!("expected a store error, got {other:?}"),
        Ok(_) => panic!("connect must fail when the store cannot be reset"),
    }
}

/// A session seeding its counters from the store must abort the handshake if the
/// store cannot be refreshed, rather than start against unknown counters and
/// risk reusing a MsgSeqNum the counterparty has already seen.
#[tokio::test]
async fn test_connect_aborts_when_the_store_cannot_be_refreshed() {
    let (_listener, addr) = bind_listener().await;

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::new(FailingStore::failing_refresh()) as Arc<dyn MessageStore>);

    match initiator.connect(addr).await {
        Err(EngineError::Store(_)) => {}
        Err(other) => panic!("expected a store error, got {other:?}"),
        Ok(_) => panic!("connect must fail when the store cannot be refreshed"),
    }
}

/// The store's sender counter must advance to reflect the Logon before the
/// handshake completes: if the ack never arrives, a reconnect reusing the store
/// must still see the Logon's MsgSeqNum spent, never hand out 1 again.
#[tokio::test]
async fn test_handshake_mirrors_the_sender_counter_before_the_logon_is_acked() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let logon = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logon), "A");
        assert_eq!(field(&logon, 34).as_deref(), Some("1"));
        // Drop without acking: the handshake fails after the Logon is on the
        // wire but before any acknowledgement.
        drop(framed);
    });

    let store = Arc::new(MemoryStore::new());
    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);

    assert!(
        initiator.connect(addr).await.is_err(),
        "the handshake must fail when the ack never arrives"
    );

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );

    // The Logon went out under MsgSeqNum 1, so the store must already read 2
    // even though the handshake failed before any ack. Without the handshake
    // mirroring the counter, the store would still report 1 and a reconnect
    // would reuse the number the counterparty has already seen.
    assert_eq!(store.next_sender_seq(), 2);
}

/// A ResendRequest spanning more messages than one store page replays every one
/// of them, in order, across page boundaries — the paged read must not truncate
/// the reply at the first page.
#[tokio::test]
async fn test_resend_request_replays_across_store_pages() {
    // 260 exceeds the 256-message page size, so the replay must page at least
    // twice; every order still comes back exactly once, in sequence order.
    const ORDERS: u64 = 260;

    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        let sent = drain_orders(&mut framed, 2, ORDERS).await;

        ok(
            framed.send(venue_msg("2", 2, &[(7, "2"), (16, "0")])).await,
            "send unbounded resend request",
        );

        for (seq, original) in (2..).zip(sent.iter()) {
            let replayed = next_frame(&mut framed).await;
            assert_replay_of(&replayed, seq, original);
        }
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::new(MemoryStore::new()));
    let connection = ok(initiator.connect(addr).await, "connect");

    send_orders(&connection, ORDERS as usize).await;

    ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
}

// ---------------------------------------------------------------------------
// Outbound path: effective callbacks, a guarded public boundary, and a reactor
// that no callback or peer can park.
// ---------------------------------------------------------------------------

/// Stamps fields onto every outbound message, so the test can look for them in
/// the bytes the acceptor actually receives.
#[derive(Debug)]
struct StampingApp {
    /// Fields appended to every administrative message.
    admin_fields: Vec<(u32, String)>,
    /// Fields appended to every application message.
    app_fields: Vec<(u32, String)>,
}

impl StampingApp {
    fn build(admin_fields: &[(u32, &str)], app_fields: &[(u32, &str)]) -> Arc<Self> {
        let own = |fields: &[(u32, &str)]| {
            fields
                .iter()
                .map(|(tag, value)| (*tag, (*value).to_string()))
                .collect()
        };
        Arc::new(Self {
            admin_fields: own(admin_fields),
            app_fields: own(app_fields),
        })
    }
}

#[async_trait]
impl Application for StampingApp {
    async fn on_create(&self, _session_id: &SessionId) {}

    async fn on_logon(&self, _session_id: &SessionId) {}

    async fn on_logout(&self, _session_id: &SessionId) {}

    async fn to_admin(&self, message: &mut OutboundMessage, _session_id: &SessionId) {
        for (tag, value) in &self.admin_fields {
            message.push_str(*tag, value);
        }
    }

    async fn from_admin(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }

    async fn to_app(&self, message: &mut OutboundMessage, _session_id: &SessionId) {
        for (tag, value) in &self.app_fields {
            message.push_str(*tag, value);
        }
    }

    async fn from_app(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }
}

/// A `to_admin` mutation is what the counterparty receives. Stamping
/// credentials onto the Logon is the documented use of the callback, and the
/// engine used to hand the application a throwaway copy and then transmit the
/// original.
#[tokio::test]
async fn test_to_admin_mutation_reaches_the_wire() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let logon = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logon), "A");
        // The fields the application appended, in the frame that went out.
        assert_eq!(field(&logon, 553).as_deref(), Some("trader"));
        assert_eq!(field(&logon, 554).as_deref(), Some("s3cret"));
        // And the header the engine stamps is intact and unduplicated.
        assert_eq!(field(&logon, 34).as_deref(), Some("1"));
        assert_eq!(field(&logon, 108).as_deref(), Some("30"));
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "30")]))
                .await,
            "send logon ack",
        );
        framed
    });

    let app = StampingApp::build(&[(553, "trader"), (554, "s3cret")], &[]);
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), app);
    let connection = ok(initiator.connect(addr).await, "connect");
    let _framed = ok(acceptor.await, "acceptor task");
    assert!(!connection.is_closed());
}

/// The same for `to_app`: a field added in the callback is encoded into the
/// application message the counterparty receives.
#[tokio::test]
async fn test_to_app_mutation_reaches_the_wire() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        let order = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&order), "D");
        assert_eq!(field(&order, 11).as_deref(), Some("ORDER-1"));
        assert_eq!(field(&order, 1).as_deref(), Some("ACCOUNT-9"));
        assert_eq!(field(&order, 34).as_deref(), Some("2"));
    });

    let app = StampingApp::build(&[], &[(1, "ACCOUNT-9")]);
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), app);
    let connection = ok(initiator.connect(addr).await, "connect");

    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order.push_str(11, "ORDER-1");
    ok(connection.send(order).await, "send order");

    ok(acceptor.await, "acceptor task");
}

/// Administrative traffic belongs to the session layer. A Logon, Logout or
/// SequenceReset sent through the public path would bypass the typestate and
/// the reactor's phase tracking.
#[tokio::test]
async fn test_send_refuses_admin_msg_types() {
    let (listener, addr) = bind_listener().await;
    let acceptor = tokio::spawn(async move { accept_logon(listener).await });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");
    let _framed = ok(acceptor.await, "acceptor task");

    for msg_type in [
        MsgType::Logon,
        MsgType::Logout,
        MsgType::SequenceReset,
        MsgType::Heartbeat,
        MsgType::TestRequest,
        MsgType::ResendRequest,
        MsgType::Reject,
    ] {
        let expected = msg_type.as_str().to_string();
        match connection.send(OutboundMessage::new(msg_type)).await {
            Err(EngineError::ReservedMsgType { msg_type }) => assert_eq!(msg_type, expected),
            other => panic!("35={expected} must be refused, got {other:?}"),
        }
    }

    // Nothing was queued, so the session is untouched.
    assert_eq!(connection.next_sender_seq(), 2);
    assert!(!connection.is_closed());
}

/// A body field repeating a tag the engine stamps would give the frame two
/// occurrences of it, which a conforming counterparty rejects or misparses.
#[tokio::test]
async fn test_send_refuses_reserved_header_tags() {
    let (listener, addr) = bind_listener().await;
    let acceptor = tokio::spawn(async move { accept_logon(listener).await });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");
    let _framed = ok(acceptor.await, "acceptor task");

    for tag in ironfix_engine::outbound::RESERVED_TAGS {
        let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
        order.push_str(11, "ORDER-1").push_str(tag, "1");
        match connection.send(order).await {
            Err(EngineError::ReservedTag { tag: actual }) => assert_eq!(actual, tag),
            other => panic!("tag {tag} must be refused, got {other:?}"),
        }
    }

    assert_eq!(connection.next_sender_seq(), 2);
    assert!(!connection.is_closed());
}

/// A value with no wire form is refused at the boundary rather than becoming
/// an encoder failure after a sequence number has been spent.
#[tokio::test]
async fn test_send_refuses_values_with_no_wire_form() {
    let (listener, addr) = bind_listener().await;
    let acceptor = tokio::spawn(async move { accept_logon(listener).await });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");
    let _framed = ok(acceptor.await, "acceptor task");

    let mut empty = OutboundMessage::new(MsgType::NewOrderSingle);
    empty.push_str(11, "");
    match connection.send(empty).await {
        Err(EngineError::InvalidField { tag: 11, .. }) => {}
        other => panic!("an empty value must be refused, got {other:?}"),
    }

    let mut injected = OutboundMessage::new(MsgType::NewOrderSingle);
    injected.push_str(58, "text\x0149=EVIL");
    match connection.send(injected).await {
        Err(EngineError::InvalidField { tag: 58, reason }) => {
            assert!(
                !reason.contains("EVIL"),
                "the rejection must not quote the value, got {reason}"
            );
        }
        other => panic!("an embedded SOH must be refused, got {other:?}"),
    }

    assert_eq!(connection.next_sender_seq(), 2);
    assert!(!connection.is_closed());
}

/// Corrupts the first outbound application message from inside `to_app`, then
/// leaves every later one alone.
#[derive(Debug, Default)]
struct CorruptFirstApp {
    /// How many application messages have passed through `to_app`.
    seen: AtomicU64,
}

#[async_trait]
impl Application for CorruptFirstApp {
    async fn on_create(&self, _session_id: &SessionId) {}

    async fn on_logon(&self, _session_id: &SessionId) {}

    async fn on_logout(&self, _session_id: &SessionId) {}

    async fn to_admin(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_admin(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }

    async fn to_app(&self, message: &mut OutboundMessage, _session_id: &SessionId) {
        if self.seen.fetch_add(1, Ordering::SeqCst) == 0 {
            // MsgSeqNum is stamped by the engine; a second copy would give the
            // frame two of it.
            message.push_str(34, "999");
        }
    }

    async fn from_app(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }
}

/// A `to_app` callback that makes a message unsendable costs nothing: the
/// message is dropped, the sequence number is not spent, and the next message
/// takes the number the dropped one would have had. Detecting this after the
/// allocation would leave a gap the counterparty has to resend over.
#[tokio::test]
async fn test_a_message_rejected_after_to_app_spends_no_sequence_number() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        // The first order never reaches the wire; the second takes MsgSeqNum 2.
        let order = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&order), "D");
        assert_eq!(field(&order, 34).as_deref(), Some("2"));
        assert_eq!(field(&order, 11).as_deref(), Some("ORDER-2"));
        // Exactly one MsgSeqNum in the frame, not two.
        assert_eq!(
            String::from_utf8_lossy(&order).matches("\x0134=").count(),
            1
        );
    });

    let app = Arc::new(CorruptFirstApp::default());
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    let mut first = OutboundMessage::new(MsgType::NewOrderSingle);
    first.push_str(11, "ORDER-1");
    ok(connection.send(first).await, "queue the first order");

    // Give the reactor time to process and drop it.
    let mut waited = Duration::ZERO;
    while app.seen.load(Ordering::SeqCst) == 0 && waited < Duration::from_secs(2) {
        tokio::time::sleep(Duration::from_millis(20)).await;
        waited += Duration::from_millis(20);
    }
    assert_eq!(
        connection.next_sender_seq(),
        2,
        "a dropped message must not spend a sequence number"
    );
    assert!(!connection.is_closed(), "the session must survive the drop");

    let mut second = OutboundMessage::new(MsgType::NewOrderSingle);
    second.push_str(11, "ORDER-2");
    ok(connection.send(second).await, "queue the second order");

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor must finish",
        ),
        "acceptor task",
    );
}

/// Records how long `from_app` was inside the callback, so a test can hold the
/// application up while asserting the reactor kept working.
#[derive(Debug)]
struct SlowApp {
    /// How long `from_app` blocks.
    delay: Duration,
    /// Fires when `from_app` is entered.
    entered: mpsc::UnboundedSender<u64>,
}

impl SlowApp {
    fn build(delay: Duration) -> (Arc<Self>, mpsc::UnboundedReceiver<u64>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Arc::new(Self { delay, entered: tx }), rx)
    }
}

#[async_trait]
impl Application for SlowApp {
    async fn on_create(&self, _session_id: &SessionId) {}

    async fn on_logon(&self, _session_id: &SessionId) {}

    async fn on_logout(&self, _session_id: &SessionId) {}

    async fn to_admin(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_admin(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
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
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or_default();
        let _ = self.entered.send(seq);
        tokio::time::sleep(self.delay).await;
        Ok(())
    }
}

/// A slow `from_app` no longer stalls the reactor: while the application is
/// blocked inside the callback, the heartbeat the session owes its
/// counterparty still goes out.
#[tokio::test]
async fn test_slow_from_app_does_not_stall_heartbeats() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let logon = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logon), "A");
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "1")]))
                .await,
            "send logon ack",
        );

        // One application message, which the handler will sit on for 3s.
        ok(
            framed
                .send(venue_msg(
                    "8",
                    2,
                    &[
                        (37, "EX-1"),
                        (11, "ORDER-1"),
                        (17, "E-1"),
                        (150, "0"),
                        (39, "0"),
                    ],
                ))
                .await,
            "send execution report",
        );

        // The reactor must keep working while the handler is blocked. Answer
        // any TestRequest so the session stays alive, and stop as soon as a
        // Heartbeat proves the timer arm still runs.
        let deadline = tokio::time::Instant::now() + Duration::from_millis(2500);
        loop {
            let Ok(polled) = tokio::time::timeout_at(deadline, framed.next()).await else {
                return false;
            };
            let Some(Ok(frame)) = polled else {
                return false;
            };
            match msg_type_of(&frame).as_str() {
                "0" => return true,
                "1" => {
                    let id = some(field(&frame, 112), "TestRequest must carry TestReqID");
                    ok(
                        framed.send(venue_msg("0", 3, &[(112, &id)])).await,
                        "answer the TestRequest",
                    );
                }
                _ => {}
            }
        }
    });

    let (app, mut entered) = SlowApp::build(Duration::from_secs(3));
    let initiator = Initiator::new(client_config(Duration::from_secs(1)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    // The handler really did get the message and really is blocked in it.
    let seq = ok(
        timeout(Duration::from_secs(2), entered.recv()).await,
        "from_app must be entered",
    );
    assert_eq!(seq, Some(2));

    let saw_heartbeat = ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor must finish",
        ),
        "acceptor task",
    );
    assert!(
        saw_heartbeat,
        "the reactor must emit a heartbeat while from_app is blocked"
    );
    assert!(!connection.is_closed());
}

/// A counterparty that stops reading closes its TCP receive window, and a
/// write into a closed window never completes. The write timeout turns that
/// into a session close in bounded time instead of a reactor parked forever
/// with its liveness timers.
#[tokio::test]
async fn test_stalled_peer_write_timeout_closes_the_session() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let framed = accept_logon(listener).await;
        // Hold the socket open and never read again.
        tokio::time::sleep(Duration::from_secs(20)).await;
        drop(framed);
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_write_timeout(Duration::from_millis(300));
    let connection = ok(initiator.connect(addr).await, "connect");

    // Push until the socket buffers fill and the reactor's write parks. The
    // command queue is bounded, so this throttles itself rather than
    // allocating without limit.
    let pushed = timeout(Duration::from_secs(15), async {
        loop {
            let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
            order
                .push_str(11, "ORDER-1")
                .push_raw(58, vec![b'x'; 60_000]);
            if connection.send(order).await.is_err() {
                return;
            }
        }
    })
    .await;
    ok(pushed, "the session must close rather than block forever");

    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "wait_closed must fire after the write timeout",
    );
    assert!(connection.is_closed());
    acceptor.abort();
}

/// Removes a configured tag from every administrative message in `to_admin`,
/// standing in for a callback that strips a field the message cannot go out
/// without.
#[derive(Debug)]
struct DropAdminFieldApp {
    /// The tag removed from every admin message.
    tag: u32,
}

#[async_trait]
impl Application for DropAdminFieldApp {
    async fn on_create(&self, _session_id: &SessionId) {}

    async fn on_logon(&self, _session_id: &SessionId) {}

    async fn on_logout(&self, _session_id: &SessionId) {}

    async fn to_admin(&self, message: &mut OutboundMessage, _session_id: &SessionId) {
        message.remove(self.tag);
    }

    async fn from_admin(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }

    async fn to_app(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_app(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }
}

/// A `to_admin` that drops a required field cannot put a malformed
/// administrative frame on the wire: the Logon, stripped of HeartBtInt (108), is
/// refused before it is written and the handshake fails with a typed error
/// rather than the engine emitting a Logon every venue would reject.
#[tokio::test]
async fn test_to_admin_dropping_a_required_admin_field_fails_the_handshake() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        // The Logon is refused before the socket write, so the venue must never
        // receive a frame — it observes either silence or the client closing.
        if let Ok(Some(Ok(frame))) = timeout(Duration::from_millis(500), framed.next()).await {
            panic!("no frame must be sent, got 35={}", msg_type_of(&frame));
        }
    });

    let app = Arc::new(DropAdminFieldApp { tag: 108 });
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), app);

    match initiator.connect(addr).await {
        Err(EngineError::MissingRequiredField { msg_type, tag }) => {
            assert_eq!(msg_type, "A");
            assert_eq!(tag, 108);
        }
        other => panic!("expected MissingRequiredField, got {other:?}"),
    }

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// Corrupts every Logout from inside `to_admin` so it has no legal wire form,
/// leaving every other administrative message untouched.
#[derive(Debug)]
struct CorruptLogoutApp;

#[async_trait]
impl Application for CorruptLogoutApp {
    async fn on_create(&self, _session_id: &SessionId) {}

    async fn on_logon(&self, _session_id: &SessionId) {}

    async fn on_logout(&self, _session_id: &SessionId) {}

    async fn to_admin(&self, message: &mut OutboundMessage, _session_id: &SessionId) {
        if message.msg_type() == &MsgType::Logout {
            // An embedded SOH leaves the value with no legal wire form, so the
            // Logout is dropped after the callback rather than framed.
            message.push_str(58, "bye\x01evil");
        }
    }

    async fn from_admin(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }

    async fn to_app(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_app(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }
}

/// An administrative message a callback made unsendable must not advance the
/// state machine as if it had gone out. A `to_admin` that corrupts the Logout
/// leaves nothing on the wire, so the reactor must stay Active — before the fix
/// it entered LogoutPending anyway and closed the session at the logout
/// deadline, tearing it down over a Logout the peer was never told about.
#[tokio::test]
async fn test_admin_message_rejected_by_callback_does_not_enter_logout_pending() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        // The Logout never reaches the wire; hold the socket open and readable
        // so the client closes on neither a write nor a transport error.
        let _ = timeout(Duration::from_secs(2), framed.next()).await;
    });

    let app = Arc::new(CorruptLogoutApp);
    let mut config = client_config(Duration::from_secs(30));
    config.logout_timeout = Duration::from_millis(300);
    let initiator = Initiator::new(config, app);
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(connection.logout().await, "logout");

    // Wait well past the logout deadline: a session that wrongly entered
    // LogoutPending would have closed by now.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        !connection.is_closed(),
        "a Logout that never went out must not close the session"
    );
    assert_eq!(
        connection.next_sender_seq(),
        2,
        "the dropped Logout must spend no sequence number"
    );

    acceptor.abort();
}

/// A `from_app` that never returns, bumping a counter each time it wakes so a
/// test can tell an aborted dispatcher (counter frozen) from a detached one
/// (counter still climbing).
#[derive(Debug)]
struct WedgedApp {
    /// Bumped on every loop iteration inside `from_app`.
    ticks: Arc<AtomicU64>,
    /// Fires once when `from_app` is entered.
    entered: mpsc::UnboundedSender<()>,
}

#[async_trait]
impl Application for WedgedApp {
    async fn on_create(&self, _session_id: &SessionId) {}

    async fn on_logon(&self, _session_id: &SessionId) {}

    async fn on_logout(&self, _session_id: &SessionId) {}

    async fn to_admin(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_admin(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }

    async fn to_app(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_app(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        let _ = self.entered.send(());
        // Never returns: the dispatcher can only leave this handler by being
        // aborted.
        loop {
            self.ticks.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// A `from_app` still wedged when the session closes is aborted, not detached,
/// so it cannot outlive `on_logout` / `wait_closed`. The handler's tick counter
/// stops climbing after the close; a detached task would keep running.
#[tokio::test]
async fn test_wedged_from_app_is_aborted_when_the_session_closes() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        // One application message to wedge the handler on.
        ok(
            framed
                .send(venue_msg(
                    "8",
                    2,
                    &[(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")],
                ))
                .await,
            "send report",
        );
        // Let the handler enter, then close the session from the venue side.
        tokio::time::sleep(Duration::from_millis(200)).await;
        ok(framed.send(venue_msg("5", 3, &[])).await, "send logout");
        // Keep the socket open and drain the client's reply until the test
        // aborts this task.
        while let Ok(Some(Ok(_))) = timeout(Duration::from_secs(10), framed.next()).await {}
    });

    let ticks = Arc::new(AtomicU64::new(0));
    let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
    let app = Arc::new(WedgedApp {
        ticks: Arc::clone(&ticks),
        entered: entered_tx,
    });
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    // The handler really is inside from_app.
    ok(
        timeout(Duration::from_secs(2), entered_rx.recv()).await,
        "from_app must be entered",
    );

    // The counterparty Logout closes the session; the reactor drains for its
    // bounded window and then aborts the still-wedged dispatcher.
    ok(
        timeout(Duration::from_secs(10), connection.wait_closed()).await,
        "closed within 10s",
    );

    // Let any in-flight cancellation land, then confirm the loop is dead: an
    // aborted task makes no further progress, a detached one keeps ticking.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let first = ticks.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let second = ticks.load(Ordering::SeqCst);
    assert_eq!(
        first, second,
        "an aborted dispatcher must stop; a detached one would keep ticking \
         (first={first}, second={second})"
    );

    acceptor.abort();
}

// ---------------------------------------------------------------------------
// Garbled inbound frames
// ---------------------------------------------------------------------------

/// Returns `frame` with its CheckSum (10) value off by one: it still frames,
/// but fails checksum validation, which FIX classes as garbled.
#[track_caller]
fn with_wrong_checksum(frame: &[u8]) -> BytesMut {
    // The trailer is `10=NNN<SOH>`: the digits are the four bytes before the
    // end, less the final SOH.
    let digits_at = some(frame.len().checked_sub(4), "frame must carry a trailer");
    let (head, trailer) = frame.split_at(digits_at);
    let digits = some(trailer.get(..3), "trailer must carry three digits");
    let text = ok(std::str::from_utf8(digits), "checksum digits are ASCII");
    let declared: u16 = ok(text.parse(), "checksum digits are decimal");
    let mut garbled = BytesMut::from(head);
    garbled.extend_from_slice(format!("{:03}\x01", (declared + 1) % 256).as_bytes());
    garbled
}

/// A garbled-frame bound of `max` frames within `window`.
#[track_caller]
fn garbled_limit(max: u32, window: Duration) -> GarbledFrameLimit {
    let max = some(NonZeroU32::new(max), "test frame count must be non-zero");
    ok(
        GarbledFrameLimit::try_new(max, window),
        "test limit must be valid",
    )
}

/// A frame with a wrong CheckSum between two valid frames is ignored: the
/// session stays Active, the garbled frame consumes no MsgSeqNum, the next
/// valid frame is a gap answered with a ResendRequest for the garbled number,
/// and the usual GapFill recovers the session.
#[tokio::test]
async fn test_garbled_checksum_frame_is_skipped_and_its_gap_resent() {
    let (listener, addr) = bind_listener().await;
    // Stub -> client: the gap has been requested; check the counters now.
    let (gapped_tx, gapped_rx) = tokio::sync::oneshot::channel::<()>();
    // Client -> stub: counters checked; fill the gap.
    let (fill_tx, fill_rx) = tokio::sync::oneshot::channel::<()>();
    // Stub -> client: the session has recovered.
    let (recovered_tx, recovered_rx) = tokio::sync::oneshot::channel::<()>();
    // Client -> stub: assertions done; the socket may close.
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;

        ok(
            framed.send(venue_msg("1", 2, &[(112, "BEFORE")])).await,
            "send in-sequence TestRequest",
        );
        let reply = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reply), "0");
        assert_eq!(field(&reply, 112).as_deref(), Some("BEFORE"));

        // Seq 3 is garbled; seq 4 follows it in the same write, so the codec
        // skips the garbled frame and returns seq 4 in one decode call.
        let mut burst = with_wrong_checksum(&venue_msg("1", 3, &[(112, "GARBLED")]));
        burst.extend_from_slice(&venue_msg("1", 4, &[(112, "AFTER")]));
        ok(framed.send(burst).await, "send garbled + valid frames");

        let resend = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&resend), "2", "the gap must be requested");
        assert_eq!(field(&resend, 7).as_deref(), Some("3"));
        assert_eq!(field(&resend, 16).as_deref(), Some("0"));
        // The gapped TestRequest is still answered; the garbled one never is.
        let reply = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reply), "0");
        assert_eq!(field(&reply, 112).as_deref(), Some("AFTER"));

        let _ = gapped_tx.send(());
        let _ = fill_rx.await;

        // Recover the gap the usual way: a GapFill over 3..=4, then traffic.
        ok(
            framed
                .send(venue_msg("4", 3, &[(123, "Y"), (36, "5")]))
                .await,
            "send gap fill",
        );
        ok(
            framed.send(venue_msg("1", 5, &[(112, "RECOVERED")])).await,
            "send in-sequence TestRequest after the fill",
        );
        let reply = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reply), "0");
        assert_eq!(field(&reply, 112).as_deref(), Some("RECOVERED"));

        let _ = recovered_tx.send(());
        let _ = done_rx.await;
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(5), gapped_rx).await,
            "gap requested within 5s",
        ),
        "stub must reach the gap",
    );
    // Seq 2 was consumed; the garbled seq 3 was not, and the gapped seq 4
    // cannot be, so the expectation still sits on the garbled number.
    assert_eq!(connection.next_target_seq(), 3);
    assert!(
        !connection.is_closed(),
        "a garbled frame must not end the session"
    );
    let _ = fill_tx.send(());

    ok(
        ok(
            timeout(Duration::from_secs(5), recovered_rx).await,
            "recovered within 5s",
        ),
        "stub must recover",
    );
    assert_eq!(connection.next_target_seq(), 6);
    assert!(!connection.is_closed());

    let _ = done_tx.send(());
    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// Bytes before a frame's `8=` are skipped and the frame behind them is
/// processed normally: no gap, no ResendRequest.
#[tokio::test]
async fn test_garbage_before_a_frame_is_skipped_and_the_frame_processed() {
    let (listener, addr) = bind_listener().await;
    let (answered_tx, answered_rx) = tokio::sync::oneshot::channel::<()>();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;

        let mut burst = BytesMut::from(&b"\x00\x7fline noise before the frame\xff"[..]);
        burst.extend_from_slice(&venue_msg("1", 2, &[(112, "PING")]));
        ok(framed.send(burst).await, "send garbage + TestRequest");

        // The first thing back is the answer: no ResendRequest went first.
        let reply = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reply), "0");
        assert_eq!(field(&reply, 112).as_deref(), Some("PING"));

        let _ = answered_tx.send(());
        let _ = done_rx.await;
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(5), answered_rx).await,
            "answered within 5s",
        ),
        "stub must see the answer",
    );
    assert_eq!(
        connection.next_target_seq(),
        3,
        "the frame was consumed in order"
    );
    assert!(!connection.is_closed());

    let _ = done_tx.send(());
    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// A frame declaring more than `max_message_size` is fatal, recovery or not:
/// the client closes the session. The stub keeps its socket open, so the close
/// is the client's verdict and not a transport drop.
#[tokio::test]
async fn test_oversized_frame_still_closes_the_session() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        // 2 MiB declared against the default 1 MiB ceiling.
        ok(
            framed
                .send(BytesMut::from(
                    &b"8=FIX.4.4\x019=2097152\x0135=0\x0149=VENUE\x01"[..],
                ))
                .await,
            "send oversized header",
        );
        // The read side is unusable but the write side is not: the client
        // says why before it hangs up.
        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5");
        assert_eq!(field(&logout, 58).as_deref(), Some("message too large"));
        // Read until the client hangs up.
        while let Ok(Some(Ok(_))) = timeout(Duration::from_secs(5), framed.next()).await {}
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );
    assert!(connection.is_closed());
    assert!(!connection.is_timed_out());
    assert!(app.events().contains(&"logout".to_string()));

    ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
}

/// With a garbled-frame limit of 3 within a minute, two garbled frames are
/// tolerated and the session keeps working; the third logs it out with a
/// Text naming the reason.
#[tokio::test]
async fn test_garbled_frame_limit_closes_the_session() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;

        let mut burst = with_wrong_checksum(&venue_msg("0", 2, &[]));
        burst.extend_from_slice(&with_wrong_checksum(&venue_msg("0", 3, &[])));
        burst.extend_from_slice(&venue_msg("1", 4, &[(112, "STILL-UP")]));
        ok(
            framed.send(burst).await,
            "send two garbled frames + one valid",
        );

        // Two garbled frames are under the limit: the session answers.
        let resend = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&resend), "2");
        assert_eq!(field(&resend, 7).as_deref(), Some("2"));
        let reply = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reply), "0");
        assert_eq!(field(&reply, 112).as_deref(), Some("STILL-UP"));

        // The third reaches it, with nothing valid behind it: the client
        // sees it on its next tick.
        ok(
            framed
                .send(with_wrong_checksum(&venue_msg("0", 5, &[])))
                .await,
            "send the third garbled frame",
        );
        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5");
        assert!(
            some(field(&logout, 58), "logout must carry Text").contains("garbled"),
            "the logout should explain the garbled-frame limit"
        );
        while let Ok(Some(Ok(_))) = timeout(Duration::from_secs(5), framed.next()).await {}
    });

    let (app, _app_rx) = RecordingApp::new();
    let config = client_config(Duration::from_secs(30))
        .with_garbled_frame_limit(Some(garbled_limit(3, Duration::from_secs(60))));
    let initiator = Initiator::new(config, Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );
    assert!(connection.is_closed());
    assert!(!connection.is_timed_out());

    ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
}

/// Garbled bytes are not proof of life: a peer that sends nothing but garbled
/// frames is probed with a TestRequest and timed out exactly as a silent one
/// is. If garbled frames refreshed the heartbeat clock, the stream below would
/// keep the session alive indefinitely.
#[tokio::test]
async fn test_garbled_frames_do_not_refresh_the_heartbeat() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "1")]))
                .await,
            "send logon ack",
        );

        // A garbled frame every 200 ms, never a valid one, never an answer.
        let mut saw_test_request = false;
        let mut seq = 2u64;
        let mut pace = tokio::time::interval(Duration::from_millis(200));
        let deadline = tokio::time::sleep(Duration::from_secs(10));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = pace.tick() => {
                    let garbled = with_wrong_checksum(&venue_msg("0", seq, &[]));
                    seq += 1;
                    if framed.send(garbled).await.is_err() {
                        break;
                    }
                }
                inbound = framed.next() => match inbound {
                    Some(Ok(frame)) => {
                        if msg_type_of(&frame) == "1" {
                            saw_test_request = true;
                        }
                    }
                    _ => break,
                },
                () = &mut deadline => break,
            }
        }
        saw_test_request
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(1)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    // TestRequest due at interval + 1s grace; timeout one interval later.
    ok(
        timeout(Duration::from_secs(8), connection.wait_closed()).await,
        "closed within 8s despite the garbled stream",
    );
    assert!(
        connection.is_timed_out(),
        "the session must time out: garbled frames are not proof of life"
    );
    assert_eq!(
        connection.next_target_seq(),
        2,
        "no garbled frame may consume a MsgSeqNum"
    );

    assert!(
        ok(
            ok(
                timeout(Duration::from_secs(15), acceptor).await,
                "acceptor done within 15s",
            ),
            "acceptor task",
        ),
        "the client should have probed with a TestRequest"
    );
}

/// Returns `frame` with its BodyLength (9) one short of the real body: the
/// trailer is then not where BodyLength points, so the codec resynchronises
/// through the body instead of consuming a corroborated frame.
#[track_caller]
fn with_wrong_body_length(frame: &[u8]) -> BytesMut {
    let tag_at = some(
        frame.windows(3).position(|window| window == b"\x019="),
        "frame must carry BodyLength",
    );
    let start = some(tag_at.checked_add(3), "BodyLength digits follow the tag");
    let digits_len = some(
        frame
            .get(start..)
            .and_then(|rest| rest.iter().position(|&byte| byte == 0x01)),
        "BodyLength must be terminated",
    );
    let end = some(start.checked_add(digits_len), "digits end inside the frame");
    let digits = some(frame.get(start..end), "digits are inside the frame");
    let declared: usize = ok(
        ok(std::str::from_utf8(digits), "BodyLength is ASCII").parse(),
        "BodyLength is decimal",
    );
    let short = some(declared.checked_sub(1), "BodyLength is positive");
    let mut garbled = BytesMut::from(some(frame.get(..start), "head is inside the frame"));
    garbled.extend_from_slice(short.to_string().as_bytes());
    garbled.extend_from_slice(some(frame.get(end..), "tail is inside the frame"));
    garbled
}

/// A Logon ack that frames correctly but whose MsgType (35) is not the third
/// field: garbled at the decode level, as the FIX Session Layer defines it.
fn ack_with_msg_type_out_of_place() -> BytesMut {
    raw_frame(b"49=VENUE\x0135=A\x0156=CLIENT\x0134=1\x0198=0\x01108=30\x01")
}

/// An ack that never arrives intact ends the handshake in LogonTimeout after
/// `logon_timeout`, not in an immediate codec or decode error: a garbled ack
/// is ignored, both the kind the codec cannot frame and the kind that frames
/// but does not decode.
#[tokio::test]
async fn test_garbled_only_logon_ack_ends_in_logon_timeout() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        let mut burst = with_wrong_checksum(&venue_msg("A", 1, &[(98, "0"), (108, "30")]));
        burst.extend_from_slice(&ack_with_msg_type_out_of_place());
        ok(framed.send(burst).await, "send garbled acks only");
        // Hold the socket open until the client gives up.
        let _ = timeout(Duration::from_secs(5), framed.next()).await;
    });

    let (app, _app_rx) = RecordingApp::new();
    let config =
        client_config(Duration::from_secs(30)).with_logon_timeout(Duration::from_millis(300));
    let initiator = Initiator::new(config, Arc::clone(&app));

    match initiator.connect(addr).await {
        Err(EngineError::LogonTimeout(_)) => {}
        other => panic!("expected LogonTimeout, got {other:?}"),
    }
    assert!(!app.events().contains(&"logon".to_string()));

    acceptor.abort();
}

/// Garbled acks before a valid one are skipped and the valid ack takes the
/// session Active, with no sequence number consumed by the garbled ones.
#[tokio::test]
async fn test_garbled_logon_ack_followed_by_a_valid_ack_goes_active() {
    let (listener, addr) = bind_listener().await;
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        let mut burst = with_wrong_checksum(&venue_msg("A", 1, &[(98, "0"), (108, "30")]));
        burst.extend_from_slice(&ack_with_msg_type_out_of_place());
        burst.extend_from_slice(&venue_msg("A", 1, &[(98, "0"), (108, "30")]));
        ok(framed.send(burst).await, "send garbled acks + a valid one");
        let _ = done_rx.await;
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(
        initiator.connect(addr).await,
        "the valid ack must go Active",
    );

    assert!(app.events().contains(&"logon".to_string()));
    assert_eq!(connection.next_target_seq(), 2);
    assert!(!connection.is_closed());

    let _ = done_tx.send(());
    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// A frame whose BodyLength is wrong, rather than its CheckSum, is skipped in
/// session the same way: no MsgSeqNum consumed, a ResendRequest for its number,
/// and the session stays Active.
#[tokio::test]
async fn test_garbled_body_length_frame_is_skipped_and_its_gap_resent() {
    let (listener, addr) = bind_listener().await;
    let (gapped_tx, gapped_rx) = tokio::sync::oneshot::channel::<()>();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;

        let mut burst = with_wrong_body_length(&venue_msg("1", 2, &[(112, "GARBLED")]));
        burst.extend_from_slice(&venue_msg("1", 3, &[(112, "AFTER")]));
        ok(framed.send(burst).await, "send garbled + valid frames");

        let resend = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&resend), "2", "the gap must be requested");
        assert_eq!(field(&resend, 7).as_deref(), Some("2"));
        let reply = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reply), "0");
        assert_eq!(field(&reply, 112).as_deref(), Some("AFTER"));

        let _ = gapped_tx.send(());
        let _ = done_rx.await;
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(5), gapped_rx).await,
            "gap requested within 5s",
        ),
        "stub must reach the gap",
    );
    assert_eq!(connection.next_target_seq(), 2);
    assert!(!connection.is_closed());

    let _ = done_tx.send(());
    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// Garbled frames skipped during the Logon handshake are not counted toward
/// the limit: with a limit of one, the session survives a garbled ack, keeps
/// answering, and only the first garbled frame of the Active session logs it
/// out.
#[tokio::test]
async fn test_garbled_frames_during_the_handshake_do_not_count_toward_the_limit() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        let mut burst = with_wrong_checksum(&venue_msg("A", 1, &[(98, "0"), (108, "30")]));
        burst.extend_from_slice(&ack_with_msg_type_out_of_place());
        burst.extend_from_slice(&venue_msg("A", 1, &[(98, "0"), (108, "30")]));
        ok(framed.send(burst).await, "send garbled acks + a valid one");

        ok(
            framed.send(venue_msg("1", 2, &[(112, "ALIVE")])).await,
            "send TestRequest",
        );
        let reply = next_frame(&mut framed).await;
        assert_eq!(
            msg_type_of(&reply),
            "0",
            "the handshake garbage did not count"
        );
        assert_eq!(field(&reply, 112).as_deref(), Some("ALIVE"));

        ok(
            framed
                .send(with_wrong_checksum(&venue_msg("0", 3, &[])))
                .await,
            "send one garbled frame in session",
        );
        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5");
        assert!(some(field(&logout, 58), "logout must carry Text").contains("garbled"));
        while let Ok(Some(Ok(_))) = timeout(Duration::from_secs(5), framed.next()).await {}
    });

    let (app, _app_rx) = RecordingApp::new();
    let config = client_config(Duration::from_secs(30))
        .with_garbled_frame_limit(Some(garbled_limit(1, Duration::from_secs(60))));
    let initiator = Initiator::new(config, Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );
    ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
}

/// A limit reached while a locally initiated Logout awaits its ack tears the
/// session down without a second Logout, and well before the logout timeout.
#[tokio::test]
async fn test_garbled_limit_reached_while_logout_pending_sends_no_second_logout() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5");

        // Never ack; garble instead.
        ok(
            framed
                .send(with_wrong_checksum(&venue_msg("0", 2, &[])))
                .await,
            "send a garbled frame",
        );
        let mut after = Vec::new();
        while let Ok(Some(Ok(frame))) = timeout(Duration::from_secs(5), framed.next()).await {
            after.push(msg_type_of(&frame));
        }
        after
    });

    let (app, _app_rx) = RecordingApp::new();
    let config = client_config(Duration::from_secs(30))
        .with_garbled_frame_limit(Some(garbled_limit(1, Duration::from_secs(60))));
    let initiator = Initiator::new(config, Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(connection.logout().await, "logout");
    // The logout timeout is 10 s; the limit must close the session first.
    ok(
        timeout(Duration::from_secs(3), connection.wait_closed()).await,
        "closed by the limit within 3s",
    );

    let after = ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
    assert!(
        !after.iter().any(|msg_type| msg_type == "5"),
        "no second Logout may follow the first: {after:?}"
    );
}

/// A frame that frames but does not decode (MsgType (35) not third) counts
/// toward the limit just like one the codec skipped: one of each reaches a
/// limit of two.
#[tokio::test]
async fn test_decode_level_garbled_frame_counts_toward_the_limit() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;

        let mut burst = raw_frame(b"49=VENUE\x0135=0\x0156=CLIENT\x0134=2\x01");
        burst.extend_from_slice(&venue_msg("1", 3, &[(112, "STILL-UP")]));
        ok(
            framed.send(burst).await,
            "send a decode-garbled frame + one valid",
        );
        let resend = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&resend), "2");
        assert_eq!(field(&resend, 7).as_deref(), Some("2"));
        let reply = next_frame(&mut framed).await;
        assert_eq!(field(&reply, 112).as_deref(), Some("STILL-UP"));

        ok(
            framed
                .send(with_wrong_checksum(&venue_msg("0", 4, &[])))
                .await,
            "send a frame-level garbled frame",
        );
        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5");
        assert!(some(field(&logout, 58), "logout must carry Text").contains("garbled"));
        while let Ok(Some(Ok(_))) = timeout(Duration::from_secs(5), framed.next()).await {}
    });

    let (app, _app_rx) = RecordingApp::new();
    let config = client_config(Duration::from_secs(30))
        .with_garbled_frame_limit(Some(garbled_limit(2, Duration::from_secs(60))));
    let initiator = Initiator::new(config, Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );
    ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
}

/// A message whose header is sound but whose body does not decode (here a
/// non-numeric tag) is not garbled: it is dropped as it always was, consumes
/// no MsgSeqNum, and does not count toward the limit, so a limit of one
/// survives it.
#[tokio::test]
async fn test_malformed_body_frame_is_dropped_and_not_counted_toward_the_limit() {
    let (listener, addr) = bind_listener().await;
    let (answered_tx, answered_rx) = tokio::sync::oneshot::channel::<()>();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;

        let mut burst = raw_frame(b"35=0\x0149=VENUE\x0156=CLIENT\x0134=2\x01abc=1\x01");
        burst.extend_from_slice(&venue_msg("1", 3, &[(112, "STILL-UP")]));
        ok(
            framed.send(burst).await,
            "send a malformed-body frame + one valid",
        );

        // The malformed frame consumed nothing: seq 3 is a gap.
        let resend = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&resend), "2");
        assert_eq!(field(&resend, 7).as_deref(), Some("2"));
        let reply = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reply), "0", "the limit of one was not reached");
        assert_eq!(field(&reply, 112).as_deref(), Some("STILL-UP"));

        let _ = answered_tx.send(());
        let _ = done_rx.await;
    });

    let (app, _app_rx) = RecordingApp::new();
    let config = client_config(Duration::from_secs(30))
        .with_garbled_frame_limit(Some(garbled_limit(1, Duration::from_secs(60))));
    let initiator = Initiator::new(config, Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(5), answered_rx).await,
            "answered within 5s",
        ),
        "stub must see the answer",
    );
    assert!(!connection.is_closed());
    assert_eq!(connection.next_target_seq(), 2);

    let _ = done_tx.send(());
    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// A Logon ack whose header is sound but whose body does not decode cannot be
/// read as an ack: it is skipped under the same logon timeout, and the valid
/// ack behind it takes the session Active.
#[tokio::test]
async fn test_malformed_body_logon_ack_is_skipped_under_the_same_deadline() {
    let (listener, addr) = bind_listener().await;
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        let mut burst =
            raw_frame(b"35=A\x0149=VENUE\x0156=CLIENT\x0134=1\x01abc=1\x0198=0\x01108=30\x01");
        burst.extend_from_slice(&venue_msg("A", 1, &[(98, "0"), (108, "30")]));
        ok(
            framed.send(burst).await,
            "send a malformed-body ack + a valid one",
        );
        let _ = done_rx.await;
    });

    let (app, _app_rx) = RecordingApp::new();
    let config = client_config(Duration::from_secs(30)).with_logon_timeout(Duration::from_secs(2));
    let initiator = Initiator::new(config, Arc::clone(&app));
    let connection = ok(
        initiator.connect(addr).await,
        "the valid ack must go Active",
    );
    assert_eq!(connection.next_target_seq(), 2);
    assert!(!connection.is_closed());

    let _ = done_tx.send(());
    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// A frame whose third field is a malformed tag (`abc=0`) is garbled (MsgType
/// is not third), even though the decoder reports an invalid tag. Two of them,
/// with valid traffic in between, reach a limit of two: valid traffic between
/// them does not reset or bypass the count.
#[tokio::test]
async fn test_invalid_third_field_tag_counts_toward_the_limit() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        let bad = || raw_frame(b"abc=0\x0135=0\x0149=VENUE\x0156=CLIENT\x0134=2\x01");

        let mut burst = bad();
        burst.extend_from_slice(&venue_msg("1", 2, &[(112, "BETWEEN")]));
        ok(framed.send(burst).await, "send one bad frame + one valid");
        let reply = next_frame(&mut framed).await;
        assert_eq!(field(&reply, 112).as_deref(), Some("BETWEEN"));

        ok(framed.send(bad()).await, "send the second bad frame");
        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5");
        assert!(some(field(&logout, 58), "logout must carry Text").contains("garbled"));
        while let Ok(Some(Ok(_))) = timeout(Duration::from_secs(5), framed.next()).await {}
    });

    let (app, _app_rx) = RecordingApp::new();
    let config = client_config(Duration::from_secs(30))
        .with_garbled_frame_limit(Some(garbled_limit(2, Duration::from_secs(60))));
    let initiator = Initiator::new(config, Arc::clone(&app));
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );
    ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
}

// ---------------------------------------------------------------------------
// Store write failures and persistence order
// ---------------------------------------------------------------------------

/// Reads every frame the client writes until it hangs up, returning their
/// MsgTypes. The stub never closes first, so the close is the client's.
async fn msg_types_until_closed(framed: &mut Framed<TcpStream, FixCodec>) -> Vec<String> {
    let mut seen = Vec::new();
    while let Ok(Some(Ok(frame))) = timeout(Duration::from_secs(5), framed.next()).await {
        seen.push(msg_type_of(&frame));
    }
    seen
}

/// Under the default `Continue` policy a failing store changes nothing on the
/// wire: the Logon and the order are written anyway (with warnings), and the
/// session keeps running. The store holds neither frame, which is what makes
/// a later resend of them a gap fill.
#[tokio::test]
async fn test_store_failure_continue_writes_the_frame_and_keeps_the_session() {
    let (listener, addr) = bind_listener().await;
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel::<()>();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        let order = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&order), "D");
        assert_eq!(field(&order, 34).as_deref(), Some("2"));
        let _ = seen_tx.send(());
        let _ = done_rx.await;
    });

    // Every write fails from the start, the handshake included.
    let store = Arc::new(FailingStore::working());
    store.fail_store.store(true, Ordering::SeqCst);
    store.fail_sender.store(true, Ordering::SeqCst);
    store.fail_target.store(true, Ordering::SeqCst);

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
        .with_store_failure_policy(StoreFailurePolicy::Continue);
    let connection = ok(
        initiator.connect(addr).await,
        "Continue must not fail the handshake",
    );
    send_orders(&connection, 1).await;

    ok(
        ok(
            timeout(Duration::from_secs(5), seen_rx).await,
            "order within 5s",
        ),
        "the order must reach the peer",
    );
    assert!(!connection.is_closed());
    assert_eq!(store.inner.message_count(), 0, "nothing could be filed");

    let _ = done_tx.send(());
    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// Under `CloseSession`, an order whose filing fails, or whose next sender
/// number cannot be persisted, is never written: the peer reads no bytes for
/// it, and the session closes.
///
/// The default `file_outbound` files first, so when only the counter write
/// fails the frame is filed and still never written: a filed frame the peer
/// never saw is the safe side of the order.
#[tokio::test]
async fn test_store_failure_close_session_writes_nothing_for_the_frame_and_closes() {
    for (what, arm) in [("store", 0usize), ("set_next_sender_seq", 1usize)] {
        let (listener, addr) = bind_listener().await;
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
        let acceptor = tokio::spawn(async move {
            let mut framed = accept_logon(listener).await;
            // A round trip first, so the session has run its first pass and
            // persisted whatever it owed before the store breaks.
            ok(
                framed.send(venue_msg("1", 2, &[(112, "READY")])).await,
                "send TestRequest",
            );
            let reply = next_frame(&mut framed).await;
            assert_eq!(field(&reply, 112).as_deref(), Some("READY"));
            let _ = ready_tx.send(());
            msg_types_until_closed(&mut framed).await
        });

        let store = Arc::new(FailingStore::working());
        let (app, _app_rx) = RecordingApp::new();
        let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
            .with_store_failure_policy(StoreFailurePolicy::CloseSession);
        let connection = ok(initiator.connect(addr).await, "connect");
        ok(
            ok(
                timeout(Duration::from_secs(5), ready_rx).await,
                "ready within 5s",
            ),
            "stub must reach the session",
        );

        // Break the store only now, after the handshake succeeded. The
        // Heartbeat took 2, so the order is 3.
        let flag = if arm == 0 {
            &store.fail_store
        } else {
            &store.fail_sender
        };
        flag.store(true, Ordering::SeqCst);
        send_orders(&connection, 1).await;

        ok(
            timeout(Duration::from_secs(5), connection.wait_closed()).await,
            "closed within 5s",
        );
        let seen = ok(
            ok(
                timeout(Duration::from_secs(10), acceptor).await,
                "acceptor done within 10s",
            ),
            "acceptor task",
        );
        assert!(
            !seen.iter().any(|msg_type| msg_type == "D"),
            "{what}: the order must never reach the peer, saw {seen:?}"
        );
        assert!(
            !seen.iter().any(|msg_type| msg_type == "5"),
            "{what}: no Logout is written through a failed store, saw {seen:?}"
        );
        if arm == 0 {
            assert!(!store.inner.contains(3), "{what}: order must not be filed");
        } else {
            assert!(
                store.inner.contains(3),
                "{what}: the order is filed before its counter write fails"
            );
        }
        assert_eq!(
            store.inner.next_sender_seq(),
            3,
            "{what}: the order's number is not persisted as spent"
        );
        assert!(app.events().contains(&"logout".to_string()));
    }
}

/// Under `CloseSession`, a target counter that cannot be persisted closes the
/// session before the inbound application message that advanced it is handed
/// over: `from_app` never sees it.
#[tokio::test]
async fn test_target_counter_failure_closes_before_from_app() {
    let (listener, addr) = bind_listener().await;
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
    let (armed_tx, armed_rx) = tokio::sync::oneshot::channel::<()>();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        // A round trip first, so the counters are persisted and the session is
        // demonstrably running before the store breaks.
        ok(
            framed.send(venue_msg("1", 2, &[(112, "READY")])).await,
            "send TestRequest",
        );
        let reply = next_frame(&mut framed).await;
        assert_eq!(field(&reply, 112).as_deref(), Some("READY"));
        let _ = ready_tx.send(());
        let _ = armed_rx.await;

        ok(
            framed
                .send(venue_msg(
                    "8",
                    3,
                    &[(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")],
                ))
                .await,
            "send execution report",
        );
        msg_types_until_closed(&mut framed).await
    });

    let store = Arc::new(FailingStore::working());
    let (app, mut app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
        .with_store_failure_policy(StoreFailurePolicy::CloseSession);
    let connection = ok(initiator.connect(addr).await, "connect");

    ok(
        ok(
            timeout(Duration::from_secs(5), ready_rx).await,
            "ready within 5s",
        ),
        "stub must reach the session",
    );
    assert_eq!(
        store.inner.next_target_seq(),
        3,
        "the TestRequest is in the cursor"
    );
    store.fail_target.store(true, Ordering::SeqCst);
    let _ = armed_tx.send(());

    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );
    assert!(
        timeout(Duration::from_millis(300), app_rx.recv())
            .await
            .is_err(),
        "the execution report must never reach from_app"
    );
    assert_eq!(store.inner.next_target_seq(), 3);
    let _ = ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
}

/// Under `CloseSession`, a store failure during the Logon handshake makes
/// `connect` return `EngineError::Store`, and the Logon is never written.
#[tokio::test]
async fn test_store_failure_during_the_handshake_fails_connect() {
    let (listener, addr) = bind_listener().await;
    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        msg_types_until_closed(&mut framed).await
    });

    let store = Arc::new(FailingStore::working());
    store.fail_store.store(true, Ordering::SeqCst);
    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
        .with_store_failure_policy(StoreFailurePolicy::CloseSession);

    match initiator.connect(addr).await {
        Err(EngineError::Store(_)) => {}
        Err(other) => panic!("expected a store error, got {other:?}"),
        Ok(_) => panic!("connect must fail when the Logon cannot be filed"),
    }
    let seen = ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
    assert!(seen.is_empty(), "the Logon must never be written: {seen:?}");
}

/// The frame is filed and the next sender number persisted before the peer
/// can read the bytes: at the moment the stub reads each frame, the store
/// already holds it and its next sender number is past it. A property check; the
/// deterministic proof of the order is
/// `test_outbound_bytes_wait_for_the_sender_counter_write`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_outbound_frame_and_counter_are_persisted_before_the_peer_reads_them() {
    let (listener, addr) = bind_listener().await;
    let store = Arc::new(MemoryStore::new());
    let observer = Arc::clone(&store);

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let logon = next_frame(&mut framed).await;
        assert_eq!(field(&logon, 34).as_deref(), Some("1"));
        assert!(observer.contains(1), "the Logon is filed before it is read");
        assert_eq!(observer.next_sender_seq(), 2);
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "30")]))
                .await,
            "send logon ack",
        );

        for seq in 2..=4u64 {
            let order = next_frame(&mut framed).await;
            assert_eq!(field(&order, 34), Some(seq.to_string()));
            assert!(
                observer.contains(seq),
                "order {seq} is filed before it is read"
            );
            assert!(
                observer.next_sender_seq() > seq,
                "the counter is past order {seq} before it is read"
            );
        }
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let connection = ok(initiator.connect(addr).await, "connect");
    send_orders(&connection, 3).await;

    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// An application that records the store's persisted target counter at the
/// moment each callback sees an inbound message.
#[derive(Debug)]
struct CursorApp {
    store: Arc<MemoryStore>,
    seen: mpsc::UnboundedSender<(String, u64, u64)>,
}

impl CursorApp {
    fn record(&self, message: &RawMessage<'_>) {
        let seq = message
            .get_field_str(34)
            .and_then(|seq| seq.parse::<u64>().ok())
            .unwrap_or_default();
        let _ = self.seen.send((
            message.msg_type().as_str().to_string(),
            seq,
            self.store.next_target_seq(),
        ));
    }
}

#[async_trait]
impl Application for CursorApp {
    async fn on_create(&self, _session_id: &SessionId) {}

    async fn on_logon(&self, _session_id: &SessionId) {}

    async fn on_logout(&self, _session_id: &SessionId) {}

    async fn to_admin(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_admin(
        &self,
        message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        self.record(message);
        Ok(())
    }

    async fn to_app(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_app(
        &self,
        message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        self.record(message);
        Ok(())
    }
}

/// The target counter is persisted before an inbound message is acted on:
/// when `from_admin` sees the Logon ack and the TestRequest, and when
/// `from_app` sees the execution report, the store already expects the number
/// after it.
#[tokio::test]
async fn test_target_counter_is_persisted_before_the_message_is_acted_on() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        ok(
            framed.send(venue_msg("1", 2, &[(112, "PING")])).await,
            "send TestRequest",
        );
        let _reply = next_frame(&mut framed).await;
        ok(
            framed
                .send(venue_msg(
                    "8",
                    3,
                    &[(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")],
                ))
                .await,
            "send execution report",
        );
        // Hold the socket until the client has seen the report.
        let _ = timeout(Duration::from_secs(5), framed.next()).await;
    });

    let store = Arc::new(MemoryStore::new());
    let (seen_tx, mut seen_rx) = mpsc::unbounded_channel();
    let app = Arc::new(CursorApp {
        store: Arc::clone(&store),
        seen: seen_tx,
    });
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let connection = ok(initiator.connect(addr).await, "connect");

    let mut observed = Vec::new();
    while observed.len() < 3 {
        let next = ok(
            timeout(Duration::from_secs(5), seen_rx.recv()).await,
            "callback within 5s",
        );
        observed.push(some(next, "callback channel must stay open"));
    }
    // The Logon ack is checked in the handshake, before its number is
    // consumed, so the cursor there still reads 1; every message after it is
    // acted on with its own number already in the cursor.
    assert_eq!(
        observed,
        vec![
            ("A".to_string(), 1, 1),
            ("1".to_string(), 2, 3),
            ("8".to_string(), 3, 4),
        ]
    );

    ok(connection.logout().await, "logout");
    acceptor.abort();
}

/// A store whose counter writes block at a chosen value until a gate opens,
/// so a test can hold the engine between "persist" and "act" and see which
/// side of that line an effect falls on.
#[derive(Debug)]
struct GatedStore {
    inner: MemoryStore,
    /// Sender-counter writes of this value or above wait for the gate.
    sender_gate_at: u64,
    /// Target-counter writes of this value or above wait for the gate.
    target_gate_at: u64,
    /// Opens the gate when set to `true`.
    open: tokio::sync::watch::Receiver<bool>,
}

impl GatedStore {
    fn new(sender_gate_at: u64, target_gate_at: u64) -> (Self, tokio::sync::watch::Sender<bool>) {
        let (open_tx, open) = tokio::sync::watch::channel(false);
        (
            Self {
                inner: MemoryStore::new(),
                sender_gate_at,
                target_gate_at,
                open,
            },
            open_tx,
        )
    }

    async fn wait_for_gate(&self) {
        let mut open = self.open.clone();
        let _ = open.wait_for(|open| *open).await;
    }
}

#[async_trait]
impl MessageStore for GatedStore {
    async fn store(
        &self,
        seq_num: u64,
        msg_type: &MsgType,
        message: &[u8],
    ) -> Result<(), StoreError> {
        self.inner.store(seq_num, msg_type, message).await
    }

    async fn get_range(&self, begin: u64, end: u64) -> Result<Vec<StoredMessage>, StoreError> {
        self.inner.get_range(begin, end).await
    }

    fn next_sender_seq(&self) -> u64 {
        self.inner.next_sender_seq()
    }

    fn next_target_seq(&self) -> u64 {
        self.inner.next_target_seq()
    }

    async fn set_next_sender_seq(&self, seq: u64) -> Result<(), StoreError> {
        if seq >= self.sender_gate_at {
            self.wait_for_gate().await;
        }
        self.inner.set_next_sender_seq(seq).await
    }

    async fn set_next_target_seq(&self, seq: u64) -> Result<(), StoreError> {
        if seq >= self.target_gate_at {
            self.wait_for_gate().await;
        }
        self.inner.set_next_target_seq(seq).await
    }

    async fn reset(&self) -> Result<(), StoreError> {
        self.inner.reset().await
    }

    fn creation_time(&self) -> std::time::SystemTime {
        self.inner.creation_time()
    }
}

/// Deterministic outbound order: while the write of the next sender number
/// for an order is held open, the peer reads no byte of that order; it
/// arrives only once the write completes.
#[tokio::test]
async fn test_outbound_bytes_wait_for_the_sender_counter_write() {
    let (listener, addr) = bind_listener().await;
    let (held_tx, held_rx) = tokio::sync::oneshot::channel::<()>();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        // Order 2 is sent, but its counter write (to 3) is held.
        assert!(
            timeout(Duration::from_millis(300), framed.next())
                .await
                .is_err(),
            "no byte of the order may arrive before its counter is persisted"
        );
        let _ = held_tx.send(());
        let order = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&order), "D");
        assert_eq!(field(&order, 34).as_deref(), Some("2"));
    });

    let (store, open) = GatedStore::new(3, u64::MAX);
    let store = Arc::new(store);
    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let connection = ok(initiator.connect(addr).await, "connect");
    send_orders(&connection, 1).await;

    ok(
        ok(
            timeout(Duration::from_secs(5), held_rx).await,
            "held within 5s",
        ),
        "the stub must observe the hold",
    );
    assert!(
        store.inner.contains(2),
        "the order is filed before its counter"
    );
    let _ = open.send(true);
    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
    assert_eq!(store.inner.next_sender_seq(), 3);
}

/// Deterministic inbound order: while the write of the next target number
/// for an application message is held open, `from_app` does not see the
/// message; it is handed over only once the write completes.
#[tokio::test]
async fn test_from_app_waits_for_the_target_counter_write() {
    let (listener, addr) = bind_listener().await;
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        ok(
            framed
                .send(venue_msg(
                    "8",
                    2,
                    &[(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")],
                ))
                .await,
            "send execution report",
        );
        let _ = done_rx.await;
    });

    // The Logon ack takes the target to 2 (not held); the report's write of 3
    // is held.
    let (store, open) = GatedStore::new(u64::MAX, 3);
    let store = Arc::new(store);
    let (app, mut app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let _connection = ok(initiator.connect(addr).await, "connect");

    assert!(
        timeout(Duration::from_millis(300), app_rx.recv())
            .await
            .is_err(),
        "from_app must not see the report before its counter is persisted"
    );
    let _ = open.send(true);
    let received = ok(
        timeout(Duration::from_secs(5), app_rx.recv()).await,
        "report within 5s of the write completing",
    );
    assert_eq!(some(received, "app channel must stay open"), "8");
    assert_eq!(store.inner.next_target_seq(), 3);

    let _ = done_tx.send(());
    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// Under `CloseSession`, a Logon whose next sender number cannot be persisted
/// is never written, and `connect` reports the store error.
#[tokio::test]
async fn test_handshake_sender_counter_failure_writes_no_logon() {
    let (listener, addr) = bind_listener().await;
    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        msg_types_until_closed(&mut framed).await
    });

    let store = Arc::new(FailingStore::working());
    store.fail_sender.store(true, Ordering::SeqCst);
    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
        .with_store_failure_policy(StoreFailurePolicy::CloseSession);

    match initiator.connect(addr).await {
        Err(EngineError::Store(_)) => {}
        Err(other) => panic!("expected a store error, got {other:?}"),
        Ok(_) => panic!("connect must fail when the sender counter cannot be persisted"),
    }
    let seen = ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
    assert!(seen.is_empty(), "the Logon must never be written: {seen:?}");
    assert_eq!(store.inner.next_sender_seq(), 1, "no number was spent");
    assert!(!app.events().contains(&"logon".to_string()));
}

/// Under `CloseSession`, a Logon ack whose number cannot be persisted fails
/// `connect` with the store error before the session goes Active: `on_logon`
/// never runs, and nothing more is written (no Reject, no Logout).
#[tokio::test]
async fn test_handshake_target_counter_failure_fails_connect_before_on_logon() {
    let (listener, addr) = bind_listener().await;
    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        msg_types_until_closed(&mut framed).await
    });

    let store = Arc::new(FailingStore::working());
    store.fail_target.store(true, Ordering::SeqCst);
    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
        .with_store_failure_policy(StoreFailurePolicy::CloseSession);

    match initiator.connect(addr).await {
        Err(EngineError::Store(_)) => {}
        Err(other) => panic!("expected a store error, got {other:?}"),
        Ok(_) => panic!("connect must fail when the ack's number cannot be persisted"),
    }
    let seen = ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
    assert!(
        seen.is_empty(),
        "nothing follows the Logon once the ack cannot be persisted: {seen:?}"
    );
    assert_eq!(store.inner.next_target_seq(), 1);
    assert!(
        !app.events().contains(&"logon".to_string()),
        "on_logon must not run for a session that never went Active"
    );
}

/// Under `CloseSession`, a target counter that cannot be persisted for an
/// administrative message closes the session before the message is acted on:
/// a TestRequest gets no Heartbeat, and the expectation does not move.
#[tokio::test]
async fn test_target_counter_failure_on_an_admin_message_closes_before_the_reply() {
    let (listener, addr) = bind_listener().await;
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
    let (armed_tx, armed_rx) = tokio::sync::oneshot::channel::<()>();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        ok(
            framed.send(venue_msg("1", 2, &[(112, "READY")])).await,
            "send TestRequest",
        );
        let reply = next_frame(&mut framed).await;
        assert_eq!(field(&reply, 112).as_deref(), Some("READY"));
        let _ = ready_tx.send(());
        let _ = armed_rx.await;
        ok(
            framed.send(venue_msg("1", 3, &[(112, "PING")])).await,
            "send TestRequest",
        );
        msg_types_until_closed(&mut framed).await
    });

    let store = Arc::new(FailingStore::working());
    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
        .with_store_failure_policy(StoreFailurePolicy::CloseSession);
    let connection = ok(initiator.connect(addr).await, "connect");
    ok(
        ok(
            timeout(Duration::from_secs(5), ready_rx).await,
            "ready within 5s",
        ),
        "stub must reach the session",
    );
    store.fail_target.store(true, Ordering::SeqCst);
    let _ = armed_tx.send(());

    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );
    let seen = ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
    assert!(
        !seen.iter().any(|msg_type| msg_type == "0"),
        "the TestRequest must not be answered: {seen:?}"
    );
    assert_eq!(store.inner.next_target_seq(), 3);
    assert_eq!(
        connection.next_target_seq(),
        3,
        "the expectation moves only once its write is accepted"
    );
}

/// Under the default `Continue` policy, a target counter that cannot be
/// persisted does not stop delivery: the application message still reaches
/// `from_app` and the session stays up.
#[tokio::test]
async fn test_target_counter_failure_under_continue_still_delivers() {
    let (listener, addr) = bind_listener().await;
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
    let (armed_tx, armed_rx) = tokio::sync::oneshot::channel::<()>();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        ok(
            framed.send(venue_msg("1", 2, &[(112, "READY")])).await,
            "send TestRequest",
        );
        let _reply = next_frame(&mut framed).await;
        let _ = ready_tx.send(());
        let _ = armed_rx.await;
        ok(
            framed
                .send(venue_msg(
                    "8",
                    3,
                    &[(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")],
                ))
                .await,
            "send execution report",
        );
        let _ = done_rx.await;
    });

    let store = Arc::new(FailingStore::working());
    let (app, mut app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let connection = ok(initiator.connect(addr).await, "connect");
    ok(
        ok(
            timeout(Duration::from_secs(5), ready_rx).await,
            "ready within 5s",
        ),
        "stub must reach the session",
    );
    store.fail_target.store(true, Ordering::SeqCst);
    let _ = armed_tx.send(());

    let received = ok(
        timeout(Duration::from_secs(5), app_rx.recv()).await,
        "report within 5s",
    );
    assert_eq!(some(received, "app channel must stay open"), "8");
    assert!(!connection.is_closed());
    assert_eq!(
        store.inner.next_target_seq(),
        3,
        "the failed write did not take"
    );
    assert_eq!(connection.next_target_seq(), 4);

    let _ = done_tx.send(());
    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// The handshake hands the reactor the record of what it wrote, and the
/// reactor writes a counter only when it moves: once connected, an idle
/// session makes no counter write, tick after tick.
#[tokio::test]
async fn test_idle_ticks_make_no_counter_writes() {
    let (listener, addr) = bind_listener().await;
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let acceptor = tokio::spawn(async move {
        let _framed = accept_logon(listener).await;
        let _ = done_rx.await;
    });

    let store = Arc::new(FailingStore::working());
    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let connection = ok(initiator.connect(addr).await, "connect");

    // Several 100 ms ticks, and no heartbeat due at a 30 s interval.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        store.counter_writes(),
        (1, 1),
        "one sender write (with the Logon) and one target write (for the ack), \
         none from the reactor's first pass or its ticks"
    );
    assert_eq!(store.inner.next_sender_seq(), 2);
    assert_eq!(store.inner.next_target_seq(), 2);
    assert!(!connection.is_closed());

    let _ = done_tx.send(());
    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// Polls `store` until its next target number is `expected`.
async fn wait_for_target(store: &MemoryStore, expected: u64) {
    let polled = timeout(Duration::from_secs(5), async {
        while store.next_target_seq() != expected {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    ok(polled, "the target counter must reach the expected value");
}

/// An inbound SequenceReset moves the persisted target, in both modes, with no
/// later message needed to carry it. An in-sequence Gap Fill persists its own
/// number before `from_admin` sees it; a Reset reaches `from_admin` first (it
/// has no place in the sequence) and its NewSeqNo is persisted after.
#[tokio::test]
async fn test_sequence_reset_target_is_persisted_in_both_modes() {
    let (listener, addr) = bind_listener().await;
    let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        ok(
            framed
                .send(venue_msg("4", 2, &[(123, "Y"), (36, "5")]))
                .await,
            "send SequenceReset-GapFill",
        );
        let _ = go_rx.await;
        ok(
            framed
                .send(venue_msg("4", 5, &[(123, "N"), (36, "10")]))
                .await,
            "send SequenceReset-Reset",
        );
        let _ = done_rx.await;
    });

    let store = Arc::new(MemoryStore::new());
    let (seen_tx, mut seen_rx) = mpsc::unbounded_channel();
    let app = Arc::new(CursorApp {
        store: Arc::clone(&store),
        seen: seen_tx,
    });
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let connection = ok(initiator.connect(addr).await, "connect");

    let mut next_seen = async || {
        let next = ok(
            timeout(Duration::from_secs(5), seen_rx.recv()).await,
            "callback within 5s",
        );
        some(next, "callback channel must stay open")
    };
    assert_eq!(next_seen().await, ("A".to_string(), 1, 1));

    wait_for_target(&store, 5).await;
    assert_eq!(
        next_seen().await,
        ("4".to_string(), 2, 3),
        "the Gap Fill's own number is persisted before from_admin sees it"
    );

    let _ = go_tx.send(());
    wait_for_target(&store, 10).await;
    assert_eq!(
        next_seen().await,
        ("4".to_string(), 5, 5),
        "a Reset reaches from_admin before its NewSeqNo is persisted"
    );
    assert_eq!(connection.next_target_seq(), 10);

    let _ = done_tx.send(());
    ok(
        ok(
            timeout(Duration::from_secs(5), acceptor).await,
            "acceptor done within 5s",
        ),
        "acceptor task",
    );
}

/// An application whose first `on_logon` never returns, standing in for a
/// consumer that gives up on a connect while the session is being set up.
#[derive(Debug, Default)]
struct StallingLogonApp {
    logons: AtomicU64,
}

#[async_trait]
impl Application for StallingLogonApp {
    async fn on_create(&self, _session_id: &SessionId) {}

    async fn on_logon(&self, _session_id: &SessionId) {
        if self.logons.fetch_add(1, Ordering::SeqCst) == 0 {
            std::future::pending::<()>().await;
        }
    }

    async fn on_logout(&self, _session_id: &SessionId) {}

    async fn to_admin(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_admin(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }

    async fn to_app(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_app(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }
}

/// A Logon ack with `ResetSeqNumFlag` (141) = Y, when our Logon did not ask
/// for a reset, resets the store and persists the reset counters before
/// `on_logon` runs. A connect abandoned inside `on_logon` and then retried
/// therefore starts the new stream at 2, and a `ResendRequest` in it cannot
/// replay a frame of the previous stream.
#[tokio::test]
async fn test_reset_on_the_logon_ack_resets_the_store_before_on_logon() {
    let (listener, addr) = bind_listener().await;

    let acceptor = tokio::spawn(async move {
        // First connection: the venue resets on its ack.
        let (socket, _) = ok(listener.accept().await, "accept the first connection");
        let mut framed = Framed::new(socket, FixCodec::new());
        let logon = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logon), "A");
        assert_eq!(
            field(&logon, 34).as_deref(),
            Some("6"),
            "numbered from the store"
        );
        assert_eq!(
            field(&logon, 141),
            None,
            "our Logon did not ask for a reset"
        );
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "30"), (141, "Y")]))
                .await,
            "send the resetting logon ack",
        );
        // The client abandons this connect while on_logon is stalled.
        let _ = msg_types_until_closed(&mut framed).await;

        // Second connection: the venue's reset stream continues at 2, and it
        // asks for everything the client has sent in it.
        let (socket, _) = ok(listener.accept().await, "accept the second connection");
        let mut framed = Framed::new(socket, FixCodec::new());
        let logon = next_frame(&mut framed).await;
        assert_eq!(
            field(&logon, 34).as_deref(),
            Some("2"),
            "numbered from the reset stream"
        );
        ok(
            framed
                .send(venue_msg("A", 2, &[(98, "0"), (108, "30")]))
                .await,
            "send logon ack",
        );
        ok(
            framed.send(venue_msg("2", 3, &[(7, "1"), (16, "0")])).await,
            "send ResendRequest",
        );
        // The reply ends with the SequenceReset that reaches the next number.
        let mut replies = Vec::new();
        loop {
            let frame = next_frame(&mut framed).await;
            let msg_type = msg_type_of(&frame);
            let done = msg_type == "4";
            replies.push((msg_type, field(&frame, 11)));
            if done {
                break;
            }
        }
        replies
    });

    // The previous stream: five orders filed, the counters past them.
    let store = Arc::new(MemoryStore::new());
    for seq in 1..=5u64 {
        let frame = venue_msg_from("CLIENT", "VENUE", "D", seq, &[(11, "OLD-SESSION")]);
        ok(
            store.store(seq, &MsgType::NewOrderSingle, &frame).await,
            "seed a frame of the previous stream",
        );
    }
    ok(
        store.set_next_sender_seq(6).await,
        "seed the sender counter",
    );
    ok(
        store.set_next_target_seq(4).await,
        "seed the target counter",
    );

    let app = Arc::new(StallingLogonApp::default());
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);

    assert!(
        timeout(Duration::from_millis(500), initiator.connect(addr))
            .await
            .is_err(),
        "the first connect must still be inside on_logon"
    );
    assert_eq!(
        store.message_count(),
        0,
        "the previous stream is gone before on_logon"
    );
    assert_eq!(store.next_sender_seq(), 2);
    assert_eq!(store.next_target_seq(), 2);

    let connection = ok(initiator.connect(addr).await, "reconnect");
    let replies = ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
    assert!(
        replies.iter().all(|(msg_type, _)| msg_type != "D"),
        "no frame of the previous stream may be replayed: {replies:?}"
    );
    assert_eq!(replies, vec![("4".to_string(), None)]);
    drop(connection);
}

/// Under the default `Continue` policy too, a resetting Logon ack whose store
/// cannot be reset fails `connect` before `on_logon`: carrying on would leave
/// the previous stream filed under the numbers the new one uses, and a
/// `ResendRequest` in the new stream would replay its frames. Nothing follows
/// the Logon on the wire, and the reset goes through one `reset_to` call.
#[tokio::test]
async fn test_failed_reset_on_the_logon_ack_fails_closed_under_continue() {
    let (listener, addr) = bind_listener().await;
    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "30"), (141, "Y")]))
                .await,
            "send the resetting logon ack",
        );
        // The venue asks for its whole new stream at once.
        ok(
            framed.send(venue_msg("2", 2, &[(7, "1"), (16, "0")])).await,
            "send ResendRequest",
        );
        msg_types_until_closed(&mut framed).await
    });

    let store = Arc::new(FailingStore::failing_reset().with_previous_stream(4).await);
    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);

    match initiator.connect(addr).await {
        Err(EngineError::Store(_)) => {}
        Err(other) => panic!("expected a store error, got {other:?}"),
        Ok(_) => panic!("connect must fail when the store cannot be reset"),
    }
    let seen = ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
    assert!(
        seen.is_empty(),
        "nothing follows the Logon, least of all a previous-stream order: {seen:?}"
    );
    assert!(!app.events().contains(&"logon".to_string()));
    assert_eq!(store.reset_to_calls.load(Ordering::SeqCst), 1);
}

/// Under `CloseSession`, a resetting Logon ack whose store cannot be reset
/// fails `connect` and leaves the reset owed. Once the store recovers, the
/// same `Initiator` makes the reset before its next Logon, which declares
/// `ResetSeqNumFlag` (141) = Y at `MsgSeqNum` 1, so the counterparty restarts
/// with it; a `ResendRequest` in that session replays nothing of the previous
/// stream. The Logon after that one declares no reset: the debt is paid.
#[tokio::test]
async fn test_failed_reset_on_the_logon_ack_is_owed_to_the_retry() {
    let (listener, addr) = bind_listener().await;
    let acceptor = tokio::spawn(async move {
        // First connection: the venue resets on its ack; the client refuses.
        let (socket, _) = ok(listener.accept().await, "accept the first connection");
        let mut framed = Framed::new(socket, FixCodec::new());
        let logon = next_frame(&mut framed).await;
        assert_eq!(
            field(&logon, 34).as_deref(),
            Some("6"),
            "numbered from the store"
        );
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "30"), (141, "Y")]))
                .await,
            "send the resetting logon ack",
        );
        let refused = msg_types_until_closed(&mut framed).await;

        // Second connection: the retry declares the reset itself.
        let (socket, _) = ok(listener.accept().await, "accept the second connection");
        let mut framed = Framed::new(socket, FixCodec::new());
        let logon = next_frame(&mut framed).await;
        let retry_logon = (field(&logon, 34), field(&logon, 141));
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "30"), (141, "Y")]))
                .await,
            "acknowledge the reset",
        );
        ok(
            framed.send(venue_msg("2", 2, &[(7, "1"), (16, "0")])).await,
            "send ResendRequest",
        );
        let mut replies = Vec::new();
        loop {
            let frame = next_frame(&mut framed).await;
            let msg_type = msg_type_of(&frame);
            let done = msg_type == "4";
            replies.push((msg_type, field(&frame, 11)));
            if done {
                break;
            }
        }
        // The venue drops the connection; the client closes on it.
        drop(framed);

        // Third connection: nothing is owed any more.
        let (socket, _) = ok(listener.accept().await, "accept the third connection");
        let mut framed = Framed::new(socket, FixCodec::new());
        let logon = next_frame(&mut framed).await;
        let third_logon = (field(&logon, 34), field(&logon, 141));
        (refused, retry_logon, replies, third_logon)
    });

    let store = Arc::new(FailingStore::failing_reset().with_previous_stream(2).await);
    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
        .with_store_failure_policy(StoreFailurePolicy::CloseSession);

    match initiator.connect(addr).await {
        Err(EngineError::Store(_)) => {}
        Err(other) => panic!("expected a store error, got {other:?}"),
        Ok(_) => panic!("connect must fail when the store cannot be reset"),
    }
    assert!(!app.events().contains(&"logon".to_string()));
    assert!(store.inner.contains(5), "the failed reset changed nothing");

    // The store recovers, and the same initiator retries.
    store.fail_reset.store(false, Ordering::SeqCst);
    let connection = ok(initiator.connect(addr).await, "retry");
    assert_eq!(
        app.events()
            .iter()
            .filter(|event| *event == "logon")
            .count(),
        1
    );
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s of the venue dropping the connection",
    );

    // A third connect: the Logon after the paid debt declares no reset. The
    // stub reads it and hangs up, which ends this connect.
    let third = timeout(Duration::from_secs(5), initiator.connect(addr)).await;
    let (refused, retry_logon, replies, third_logon) = ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
    drop(third);

    assert!(
        refused.is_empty(),
        "the refusal writes nothing: {refused:?}"
    );
    assert_eq!(
        retry_logon,
        (Some("1".to_string()), Some("Y".to_string())),
        "the retry starts at 1 and declares ResetSeqNumFlag"
    );
    assert!(
        replies.iter().all(|(msg_type, _)| msg_type != "D"),
        "no frame of the previous stream may be replayed: {replies:?}"
    );
    assert_eq!(replies, vec![("4".to_string(), None)]);
    assert_eq!(
        third_logon.1, None,
        "the reset was paid once acknowledged: the next Logon declares none"
    );
    assert_ne!(third_logon.0.as_deref(), Some("1"));
}

/// When the close-time reset of `reset_on_disconnect` fails, no counter is
/// written: the store keeps describing the session that closed. The reset is
/// owed, and the next connect fails closed on it (whatever the policy) until
/// the store can be reset, after which the session starts from 1.
#[tokio::test]
async fn test_close_time_reset_failure_writes_no_counters_and_is_owed_to_the_next_connect() {
    let (listener, addr) = bind_listener().await;
    let acceptor = tokio::spawn(async move {
        // First session: one order, then the venue drops the connection.
        let (socket, _) = ok(listener.accept().await, "accept the first connection");
        let mut framed = Framed::new(socket, FixCodec::new());
        let logon = next_frame(&mut framed).await;
        assert_eq!(field(&logon, 34).as_deref(), Some("1"));
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "30")]))
                .await,
            "send logon ack",
        );
        let order = next_frame(&mut framed).await;
        assert_eq!(field(&order, 34).as_deref(), Some("2"));
        drop(framed);

        // Second connection: refused before a Logon, as the owed reset fails.
        let (socket, _) = ok(listener.accept().await, "accept the second connection");
        let mut framed = Framed::new(socket, FixCodec::new());
        let refused = msg_types_until_closed(&mut framed).await;

        // Third connection: the reset is made, so the Logon starts from 1 and
        // declares the reset for the counterparty to make too.
        let (socket, _) = ok(listener.accept().await, "accept the third connection");
        let mut framed = Framed::new(socket, FixCodec::new());
        let logon = next_frame(&mut framed).await;
        let logon_fields = (field(&logon, 34), field(&logon, 141));
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "30"), (141, "Y")]))
                .await,
            "send logon ack",
        );
        (refused, logon_fields, framed)
    });

    let store = Arc::new(FailingStore::failing_reset());
    let mut config = client_config(Duration::from_secs(30));
    config.reset_on_disconnect = true;
    let (app, _app_rx) = RecordingApp::new();
    // The default policy: an owed reset fails closed regardless.
    let initiator = Initiator::new(config, Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);

    let connection = ok(initiator.connect(addr).await, "connect");
    send_orders(&connection, 1).await;
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );
    assert_eq!(
        store.inner.next_sender_seq(),
        3,
        "no reset counter was written over the stream still filed"
    );
    assert_eq!(store.inner.next_target_seq(), 2);
    assert!(store.inner.contains(2), "the order is still filed");

    match initiator.connect(addr).await {
        Err(EngineError::Store(_)) => {}
        Err(other) => panic!("expected a store error, got {other:?}"),
        Ok(_) => panic!("connect must fail while the owed reset cannot be made"),
    }
    assert!(store.inner.contains(2), "the failed reset changed nothing");

    store.fail_reset.store(false, Ordering::SeqCst);
    let connection = ok(
        initiator.connect(addr).await,
        "connect once the reset can be made",
    );
    let (refused, logon_fields, _framed) = ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
    assert!(
        refused.is_empty(),
        "the refused connect writes nothing: {refused:?}"
    );
    assert_eq!(
        logon_fields,
        (Some("1".to_string()), Some("Y".to_string())),
        "the Logon after an owed reset starts at 1 and declares ResetSeqNumFlag"
    );
    assert!(!store.inner.contains(2), "the previous stream is gone");
    drop(connection);
}

/// A store call that overruns the store timeout is a failed write under the
/// policy: `CloseSession` closes before answering the TestRequest it was
/// persisting the target for, `Continue` answers it after the overrun.
#[tokio::test]
async fn test_store_timeout_is_a_failed_write_under_the_policy() {
    for policy in [
        StoreFailurePolicy::CloseSession,
        StoreFailurePolicy::Continue,
    ] {
        let (listener, addr) = bind_listener().await;
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
        let (armed_tx, armed_rx) = tokio::sync::oneshot::channel::<()>();

        let acceptor = tokio::spawn(async move {
            let mut framed = accept_logon(listener).await;
            ok(
                framed.send(venue_msg("1", 2, &[(112, "READY")])).await,
                "send TestRequest",
            );
            let _reply = next_frame(&mut framed).await;
            let _ = ready_tx.send(());
            let _ = armed_rx.await;
            ok(
                framed.send(venue_msg("1", 3, &[(112, "PING")])).await,
                "send TestRequest",
            );
            match timeout(Duration::from_secs(5), framed.next()).await {
                Ok(Some(Ok(frame))) => Some((msg_type_of(&frame), field(&frame, 112))),
                _ => None,
            }
        });

        let store = Arc::new(FailingStore::working());
        let (app, _app_rx) = RecordingApp::new();
        let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
            .with_store_failure_policy(policy)
            .with_store_timeout(Duration::from_millis(200));
        let connection = ok(initiator.connect(addr).await, "connect");
        ok(
            ok(
                timeout(Duration::from_secs(5), ready_rx).await,
                "ready within 5s",
            ),
            "stub must reach the session",
        );
        store.stall_target.store(true, Ordering::SeqCst);
        let _ = armed_tx.send(());

        let reply = ok(
            ok(
                timeout(Duration::from_secs(10), acceptor).await,
                "acceptor done within 10s",
            ),
            "acceptor task",
        );
        if policy.closes_session() {
            assert_eq!(
                reply, None,
                "{policy:?}: the TestRequest must not be answered"
            );
            ok(
                timeout(Duration::from_secs(5), connection.wait_closed()).await,
                "closed within 5s",
            );
        } else {
            assert_eq!(
                reply,
                Some(("0".to_string(), Some("PING".to_string()))),
                "{policy:?}: the overrun is logged and the TestRequest answered"
            );
        }
        assert_eq!(store.inner.next_target_seq(), 3, "{policy:?}");
    }
}

/// Under `CloseSession`, a seeded sender number below the store's next sender
/// number is refused before anything is written: the store has frames at the
/// numbers in between.
#[tokio::test]
async fn test_initial_sender_below_the_store_is_refused_under_close_session() {
    let (listener, addr) = bind_listener().await;
    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        msg_types_until_closed(&mut framed).await
    });

    let store = Arc::new(MemoryStore::new());
    ok(
        store.set_next_sender_seq(10).await,
        "seed the sender counter",
    );
    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
        .with_store_failure_policy(StoreFailurePolicy::CloseSession)
        .with_initial_sequences(5, 1);

    match initiator.connect(addr).await {
        Err(EngineError::InitialSequenceBelowStore {
            seeded: 5,
            stored: 10,
        }) => {}
        Err(other) => panic!("expected InitialSequenceBelowStore, got {other:?}"),
        Ok(_) => panic!("connect must refuse a sender seed below the store"),
    }
    let seen = ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
    assert!(seen.is_empty(), "nothing is written: {seen:?}");
    assert_eq!(store.next_sender_seq(), 10);
}

/// Under `CloseSession`, a store failure while refusing a Logon ack is what
/// `connect` reports, and the refusal stops at the frame the store refused:
/// neither the Reject nor the Logout is written.
#[tokio::test]
async fn test_refusing_the_logon_ack_surfaces_a_store_failure_and_writes_no_logout() {
    let (listener, addr) = bind_listener().await;
    let store = Arc::new(FailingStore::working());
    let breaker = Arc::clone(&store);

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        // The store breaks between the Logon and its ack, which comes from the
        // wrong CompID and so has to be refused.
        breaker.fail_store.store(true, Ordering::SeqCst);
        ok(
            framed
                .send(venue_msg_from(
                    "IMPOSTOR",
                    "CLIENT",
                    "A",
                    1,
                    &[(98, "0"), (108, "30")],
                ))
                .await,
            "send the foreign logon ack",
        );
        msg_types_until_closed(&mut framed).await
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
        .with_store_failure_policy(StoreFailurePolicy::CloseSession);

    match initiator.connect(addr).await {
        Err(EngineError::Store(_)) => {}
        Err(other) => panic!("expected the store error, got {other:?}"),
        Ok(_) => panic!("connect must fail for a foreign ack"),
    }
    let seen = ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
    assert!(
        seen.is_empty(),
        "no Reject and no Logout through a failed store: {seen:?}"
    );
}

/// Under `CloseSession`, a reply to the counterparty's Logout that the store
/// refuses is never written, and the close is not graceful: `reset_on_logout`
/// does not run, so the session's stream stays filed.
#[tokio::test]
async fn test_peer_logout_reply_refused_by_the_store_is_not_a_graceful_close() {
    let (listener, addr) = bind_listener().await;
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
    let (armed_tx, armed_rx) = tokio::sync::oneshot::channel::<()>();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_logon(listener).await;
        ok(
            framed.send(venue_msg("1", 2, &[(112, "READY")])).await,
            "send TestRequest",
        );
        let _reply = next_frame(&mut framed).await;
        let _ = ready_tx.send(());
        let _ = armed_rx.await;
        ok(framed.send(venue_msg("5", 3, &[])).await, "send Logout");
        msg_types_until_closed(&mut framed).await
    });

    let store = Arc::new(FailingStore::working());
    let mut config = client_config(Duration::from_secs(30));
    config.reset_on_logout = true;
    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(config, Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
        .with_store_failure_policy(StoreFailurePolicy::CloseSession);
    let connection = ok(initiator.connect(addr).await, "connect");
    ok(
        ok(
            timeout(Duration::from_secs(5), ready_rx).await,
            "ready within 5s",
        ),
        "stub must reach the session",
    );
    store.fail_store.store(true, Ordering::SeqCst);
    let _ = armed_tx.send(());

    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );
    let seen = ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
    assert!(
        !seen.iter().any(|msg_type| msg_type == "5"),
        "the Logout reply must not be written: {seen:?}"
    );
    assert!(
        store.inner.contains(2),
        "not graceful, so reset_on_logout did not clear the store"
    );
    assert_eq!(store.inner.next_sender_seq(), 3);
}

/// An application that breaks the test store as `on_logon` runs, so the first
/// store write after the session goes Active fails.
#[derive(Debug)]
struct BreakStoreOnLogon {
    store: Arc<FailingStore>,
    logons: AtomicU64,
    logouts: AtomicU64,
}

#[async_trait]
impl Application for BreakStoreOnLogon {
    async fn on_create(&self, _session_id: &SessionId) {}

    async fn on_logon(&self, _session_id: &SessionId) {
        self.logons.fetch_add(1, Ordering::SeqCst);
        self.store.fail_store.store(true, Ordering::SeqCst);
    }

    async fn on_logout(&self, _session_id: &SessionId) {
        self.logouts.fetch_add(1, Ordering::SeqCst);
    }

    async fn to_admin(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_admin(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }

    async fn to_app(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_app(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }
}

/// The `ResendRequest` for a gap in the Logon ack is sent once the session is
/// Active, after `on_logon`. Under `CloseSession`, a store failure on it closes
/// the session through the reactor's close path: `connect` succeeds, the
/// request is never written, `on_logout` runs, and so does the close-time
/// reset of `reset_on_disconnect`.
#[tokio::test]
async fn test_opening_resend_request_store_failure_closes_through_the_close_path() {
    let (listener, addr) = bind_listener().await;
    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        // The client expects 1; an ack numbered 3 is a gap.
        ok(
            framed
                .send(venue_msg("A", 3, &[(98, "0"), (108, "30")]))
                .await,
            "send the gapped logon ack",
        );
        msg_types_until_closed(&mut framed).await
    });

    let store = Arc::new(FailingStore::working());
    let app = Arc::new(BreakStoreOnLogon {
        store: Arc::clone(&store),
        logons: AtomicU64::new(0),
        logouts: AtomicU64::new(0),
    });
    let mut config = client_config(Duration::from_secs(30));
    config.reset_on_disconnect = true;
    let initiator = Initiator::new(config, Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
        .with_store_failure_policy(StoreFailurePolicy::CloseSession);

    let connection = ok(
        initiator.connect(addr).await,
        "the session went Active; closing it is the reactor's job",
    );
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );
    let seen = ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
    assert!(
        !seen.iter().any(|msg_type| msg_type == "2"),
        "the ResendRequest the store refused must not be written: {seen:?}"
    );
    assert_eq!(app.logons.load(Ordering::SeqCst), 1);
    assert_eq!(
        app.logouts.load(Ordering::SeqCst),
        1,
        "on_logout follows on_logon"
    );
    assert_eq!(
        store.inner.message_count(),
        0,
        "the close-time reset ran and cleared the filed Logon"
    );
    assert_eq!(store.inner.next_sender_seq(), 1);
}

// ---------------------------------------------------------------------------
// Cancellation and timeouts
// ---------------------------------------------------------------------------

/// A connect dropped while the store reset for a resetting Logon ack is still
/// pending leaves the reset owed: the next connect resets the store, logs on
/// at 1 with `ResetSeqNumFlag` (141), and a `ResendRequest` replays nothing of
/// the previous stream.
#[tokio::test]
async fn test_connect_dropped_during_the_ack_reset_leaves_it_owed() {
    let (listener, addr) = bind_listener().await;
    let acceptor = tokio::spawn(async move {
        // First connection: the venue resets on its ack, and the client gives
        // up while its store reset hangs.
        let (socket, _) = ok(listener.accept().await, "accept the first connection");
        let mut framed = Framed::new(socket, FixCodec::new());
        let logon = next_frame(&mut framed).await;
        assert_eq!(
            field(&logon, 34).as_deref(),
            Some("6"),
            "numbered from the store"
        );
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "30"), (141, "Y")]))
                .await,
            "send the resetting logon ack",
        );
        let _ = msg_types_until_closed(&mut framed).await;

        // Second connection: the client owes the reset and declares it.
        let (socket, _) = ok(listener.accept().await, "accept the second connection");
        let mut framed = Framed::new(socket, FixCodec::new());
        let logon = next_frame(&mut framed).await;
        let retry_logon = (field(&logon, 34), field(&logon, 141));
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "30"), (141, "Y")]))
                .await,
            "acknowledge the reset",
        );
        ok(
            framed.send(venue_msg("2", 2, &[(7, "1"), (16, "0")])).await,
            "send ResendRequest",
        );
        let mut replies = Vec::new();
        loop {
            let frame = next_frame(&mut framed).await;
            let msg_type = msg_type_of(&frame);
            let done = msg_type == "4";
            replies.push((msg_type, field(&frame, 11)));
            if done {
                break;
            }
        }
        (retry_logon, replies, framed)
    });

    let store = Arc::new(FailingStore::working().with_previous_stream(4).await);
    store.hold_reset_to.store(true, Ordering::SeqCst);
    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);

    // The caller abandons the connect while the reset is pending: no error
    // branch runs for it.
    assert!(
        timeout(Duration::from_millis(500), initiator.connect(addr))
            .await
            .is_err(),
        "the first connect must still be inside the store reset"
    );
    assert!(store.inner.contains(5), "the held reset changed nothing");
    store.hold_reset_to.store(false, Ordering::SeqCst);

    let connection = ok(initiator.connect(addr).await, "reconnect");
    let (retry_logon, replies, _framed) = ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
    assert_eq!(
        retry_logon,
        (Some("1".to_string()), Some("Y".to_string())),
        "the retry makes the owed reset and declares it"
    );
    assert!(
        replies.iter().all(|(msg_type, _)| msg_type != "D"),
        "no frame of the previous stream may be replayed: {replies:?}"
    );
    assert_eq!(replies, vec![("4".to_string(), None)]);
    drop(connection);
}

/// A store write that overruns the store timeout may still land later, so it
/// leaves a reset owed: under `Continue` the session carries on, and the next
/// connect resets the store and logs on at 1 with `ResetSeqNumFlag` (141).
#[tokio::test]
async fn test_a_timed_out_store_write_leaves_a_reset_owed() {
    let (listener, addr) = bind_listener().await;
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
    let (armed_tx, armed_rx) = tokio::sync::oneshot::channel::<()>();

    let acceptor = tokio::spawn(async move {
        let (socket, _) = ok(listener.accept().await, "accept the first connection");
        let mut framed = Framed::new(socket, FixCodec::new());
        let _logon = next_frame(&mut framed).await;
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "30")]))
                .await,
            "send logon ack",
        );
        ok(
            framed.send(venue_msg("1", 2, &[(112, "READY")])).await,
            "send TestRequest",
        );
        let _reply = next_frame(&mut framed).await;
        let _ = ready_tx.send(());
        let _ = armed_rx.await;
        ok(
            framed.send(venue_msg("1", 3, &[(112, "PING")])).await,
            "send TestRequest",
        );
        // Continue: answered once the overrun has been logged.
        let heartbeat = next_frame(&mut framed).await;
        assert_eq!(field(&heartbeat, 112).as_deref(), Some("PING"));
        drop(framed);

        let (socket, _) = ok(listener.accept().await, "accept the second connection");
        let mut framed = Framed::new(socket, FixCodec::new());
        let logon = next_frame(&mut framed).await;
        (field(&logon, 34), field(&logon, 141), framed)
    });

    let store = Arc::new(FailingStore::working());
    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
        .with_store_timeout(Duration::from_millis(200));
    let first = ok(initiator.connect(addr).await, "connect");
    ok(
        ok(
            timeout(Duration::from_secs(5), ready_rx).await,
            "ready within 5s",
        ),
        "stub must reach the session",
    );
    store.stall_target.store(true, Ordering::SeqCst);
    let _ = armed_tx.send(());
    ok(
        timeout(Duration::from_secs(5), first.wait_closed()).await,
        "the first session closes within 5s",
    );
    store.stall_target.store(false, Ordering::SeqCst);

    // The reconnect stops at the Logon; the stub reads it and hangs up.
    let _ = timeout(Duration::from_secs(2), initiator.connect(addr)).await;
    let (seq, reset, _framed) = ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
    assert_eq!(
        seq.as_deref(),
        Some("1"),
        "the next session starts a new stream"
    );
    assert_eq!(reset.as_deref(), Some("Y"), "and declares it");
}

/// A store whose reset can be submitted as background work that lands only
/// once a gate opens, after the call's future has been dropped: a durable
/// store whose write outlives the engine's timeout.
///
/// With `ordered` set, every mutation takes a turn in one queue, in call order,
/// and the late reset keeps its turn until it lands: the ordering the
/// `MessageStore` contract requires. Without it, mutations do not wait, and the
/// late reset can land after later writes.
#[derive(Debug)]
struct LateResetStore {
    inner: Arc<MemoryStore>,
    ordered: bool,
    queue: Arc<tokio::sync::Mutex<()>>,
    /// Calls waiting for their turn.
    waiting: AtomicU64,
    defer_next_reset: AtomicBool,
    gate: tokio::sync::watch::Sender<bool>,
    landed: Arc<AtomicBool>,
}

impl LateResetStore {
    fn new(ordered: bool) -> Self {
        Self {
            inner: Arc::new(MemoryStore::new()),
            ordered,
            queue: Arc::new(tokio::sync::Mutex::new(())),
            waiting: AtomicU64::new(0),
            defer_next_reset: AtomicBool::new(false),
            gate: tokio::sync::watch::channel(false).0,
            landed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Waits for this call's turn in the queue, when the store is ordered.
    async fn turn(&self) -> Option<tokio::sync::MutexGuard<'_, ()>> {
        if !self.ordered {
            return None;
        }
        self.waiting.fetch_add(1, Ordering::SeqCst);
        let guard = self.queue.lock().await;
        self.waiting.fetch_sub(1, Ordering::SeqCst);
        Some(guard)
    }
}

#[async_trait]
impl MessageStore for LateResetStore {
    async fn store(
        &self,
        seq_num: u64,
        msg_type: &MsgType,
        message: &[u8],
    ) -> Result<(), StoreError> {
        let _turn = self.turn().await;
        self.inner.store(seq_num, msg_type, message).await
    }

    async fn get_range(&self, begin: u64, end: u64) -> Result<Vec<StoredMessage>, StoreError> {
        self.inner.get_range(begin, end).await
    }

    fn next_sender_seq(&self) -> u64 {
        self.inner.next_sender_seq()
    }

    fn next_target_seq(&self) -> u64 {
        self.inner.next_target_seq()
    }

    async fn set_next_sender_seq(&self, seq: u64) -> Result<(), StoreError> {
        let _turn = self.turn().await;
        self.inner.set_next_sender_seq(seq).await
    }

    async fn set_next_target_seq(&self, seq: u64) -> Result<(), StoreError> {
        let _turn = self.turn().await;
        self.inner.set_next_target_seq(seq).await
    }

    async fn reset(&self) -> Result<(), StoreError> {
        if self.defer_next_reset.swap(false, Ordering::SeqCst) {
            // The work is submitted now, in call order, and outlives the call.
            let turn = if self.ordered {
                Some(Arc::clone(&self.queue).lock_owned().await)
            } else {
                None
            };
            let inner = Arc::clone(&self.inner);
            let mut gate = self.gate.subscribe();
            let landed = Arc::clone(&self.landed);
            tokio::spawn(async move {
                let _ = gate.wait_for(|open| *open).await;
                let _ = inner.reset().await;
                landed.store(true, Ordering::SeqCst);
                drop(turn);
            });
            // The call itself never completes: the engine's timeout drops it.
            std::future::pending::<()>().await;
        }
        let _turn = self.turn().await;
        self.inner.reset().await
    }

    fn creation_time(&self) -> std::time::SystemTime {
        self.inner.creation_time()
    }
}

/// Runs a session whose close-time reset times out but lands later, then a
/// second session on the same store, and returns what the store holds once
/// the late reset has landed: whether frames 1 and 2 of the second session are
/// filed, and the next sender number.
async fn late_reset_scenario(ordered: bool) -> (bool, bool, u64) {
    let (listener, addr) = bind_listener().await;
    let (armed_tx, armed_rx) = tokio::sync::oneshot::channel::<()>();
    let acceptor = tokio::spawn(async move {
        // First session: logon and ack, then the venue drops the connection.
        let (socket, _) = ok(listener.accept().await, "accept the first connection");
        let mut framed = Framed::new(socket, FixCodec::new());
        let _logon = next_frame(&mut framed).await;
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "30")]))
                .await,
            "send logon ack",
        );
        let _ = armed_rx.await;
        drop(framed);

        // Second session: the reset is owed, so the Logon declares it.
        let (socket, _) = ok(listener.accept().await, "accept the second connection");
        let mut framed = Framed::new(socket, FixCodec::new());
        let logon = next_frame(&mut framed).await;
        assert_eq!(field(&logon, 34).as_deref(), Some("1"));
        assert_eq!(field(&logon, 141).as_deref(), Some("Y"));
        ok(
            framed
                .send(venue_msg("A", 1, &[(98, "0"), (108, "30"), (141, "Y")]))
                .await,
            "acknowledge the reset",
        );
        let order = next_frame(&mut framed).await;
        assert_eq!(field(&order, 34).as_deref(), Some("2"));
        let _ = timeout(Duration::from_secs(5), framed.next()).await;
    });

    let store = Arc::new(LateResetStore::new(ordered));
    let mut config = client_config(Duration::from_secs(30));
    config.reset_on_disconnect = true;
    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(config, Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
        .with_store_timeout(Duration::from_millis(200));

    let first = ok(initiator.connect(addr).await, "connect");
    store.defer_next_reset.store(true, Ordering::SeqCst);
    let _ = armed_tx.send(());
    ok(
        timeout(Duration::from_secs(5), first.wait_closed()).await,
        "the first session closes within 5s",
    );
    assert!(
        !store.landed.load(Ordering::SeqCst),
        "the close-time reset timed out with its work still outstanding"
    );

    let second = if ordered {
        // The next session's reset queues behind the late one: open the gate
        // once it waits, so the late reset lands first.
        let opener = async {
            while store.waiting.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let _ = store.gate.send(true);
        };
        let (second, ()) = tokio::join!(initiator.connect(addr), opener);
        ok(second, "reconnect")
    } else {
        ok(initiator.connect(addr).await, "reconnect")
    };
    send_orders(&second, 1).await;
    ok(
        timeout(Duration::from_secs(5), async {
            while !store.inner.contains(2) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await,
        "the order is filed within 5s",
    );

    // Let the late reset land, if it has not already.
    let _ = store.gate.send(true);
    ok(
        timeout(Duration::from_secs(5), async {
            while !store.landed.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await,
        "the late reset lands within 5s",
    );
    let held = (
        store.inner.contains(1),
        store.inner.contains(2),
        store.inner.next_sender_seq(),
    );
    drop(second);
    acceptor.abort();
    held
}

/// With a store that applies its mutations in call order, a close-time reset
/// that timed out and lands later lands before the next session's own reset,
/// so the next session's frames and counters survive it.
#[tokio::test]
async fn test_a_late_reset_cannot_erase_the_next_session_on_an_ordered_store() {
    assert_eq!(late_reset_scenario(true).await, (true, true, 3));
}

/// The documented hazard of a store that does not apply its mutations in call
/// order: the late reset lands after the next session's writes and erases
/// them. Pinned so the documentation stays true; such a store must not be
/// reused after a timed-out mutation.
#[tokio::test]
async fn test_a_late_reset_erases_the_next_session_on_an_unordered_store() {
    assert_eq!(late_reset_scenario(false).await, (false, false, 1));
}

/// The reset rule both roles share: when the initiator drives a reset
/// (`reset_on_logon`), the counterparty's acknowledgement is its message 1
/// whatever its `MsgSeqNum`. An ack at 7 that does not echo the reset opens no
/// gap and draws no `ResendRequest`; the next number expected is 2.
#[tokio::test]
async fn test_initiator_driven_reset_takes_the_ack_as_message_one() {
    let (listener, addr) = bind_listener().await;
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let logon = next_frame(&mut framed).await;
        assert_eq!(field(&logon, 34).as_deref(), Some("1"));
        assert_eq!(field(&logon, 141).as_deref(), Some("Y"));
        ok(
            framed
                .send(venue_msg("A", 7, &[(98, "0"), (108, "30")]))
                .await,
            "send an ack that does not echo the reset",
        );
        // Past the ack: nothing, in particular no ResendRequest for 1..7.
        assert!(
            timeout(Duration::from_millis(500), framed.next())
                .await
                .is_err(),
            "no frame follows the Logon"
        );
        let _ = ready_tx.send(());
        let _ = timeout(Duration::from_secs(5), framed.next()).await;
    });

    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(
        client_config(Duration::from_secs(30)).with_reset_on_logon(true),
        Arc::clone(&app),
    );
    let connection = ok(initiator.connect(addr).await, "connect");
    assert_eq!(connection.next_target_seq(), 2);
    assert_eq!(connection.next_sender_seq(), 2);
    ok(
        ok(
            timeout(Duration::from_secs(5), ready_rx).await,
            "stub checked within 5s",
        ),
        "stub must see no ResendRequest",
    );
    drop(connection);
    acceptor.abort();
}

/// An ack numbered 0 names no message. After a reset the initiator declared,
/// it must not slip through the reset rule, which takes a positive number as
/// the acceptor's message 1: it is validated and refused as too low, the
/// session never goes Active, and the store's target counter does not move.
#[tokio::test]
async fn test_initiator_refuses_an_ack_numbered_zero_after_its_reset() {
    let (listener, addr) = bind_listener().await;
    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let logon = next_frame(&mut framed).await;
        assert_eq!(field(&logon, 141).as_deref(), Some("Y"));
        ok(
            framed
                .send(venue_msg("A", 0, &[(98, "0"), (108, "30")]))
                .await,
            "send an ack numbered 0",
        );
        msg_types_until_closed(&mut framed).await
    });

    let store = Arc::new(FailingStore::working());
    let (app, _app_rx) = RecordingApp::new();
    let initiator = Initiator::new(
        client_config(Duration::from_secs(30)).with_reset_on_logon(true),
        Arc::clone(&app),
    )
    .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);

    match initiator.connect(addr).await {
        Err(EngineError::Sequence(detail)) => assert!(detail.contains("too low"), "{detail}"),
        Err(other) => panic!("expected a too-low Sequence error, got {other:?}"),
        Ok(_) => panic!("an ack numbered 0 must not establish the session"),
    }
    let _ = ok(
        ok(
            timeout(Duration::from_secs(10), acceptor).await,
            "acceptor done within 10s",
        ),
        "acceptor task",
    );
    assert!(!app.events().contains(&"logon".to_string()));
    assert_eq!(
        store.inner.next_target_seq(),
        1,
        "the ack's number was never persisted"
    );
}
