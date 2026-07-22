/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 14/7/26
******************************************************************************/

//! Integration tests for the `Initiator`: dial, Logon handshake, message
//! exchange, heartbeats, sequence recovery, and teardown against a stub
//! acceptor.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::error::StoreError;
use ironfix_core::message::MsgType;
use ironfix_core::message::RawMessage;
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::application::{Application, RejectReason, SessionId};
use ironfix_engine::{EngineError, Initiator, OutboundMessage};
use ironfix_session::sequence::SequenceCounter;
use ironfix_session::{SessionConfig, SessionConfigError};
use ironfix_store::{MemoryStore, MessageStore, StoredMessage};
use ironfix_tagvalue::{Decoder, Encoder};
use ironfix_transport::FixCodec;
use std::sync::atomic::{AtomicU64, Ordering};
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

    fn set_next_sender_seq(&self, seq: u64) {
        self.inner.set_next_sender_seq(seq);
    }

    fn set_next_target_seq(&self, seq: u64) {
        self.inner.set_next_target_seq(seq);
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
    store.set_next_sender_seq(7);
    store.set_next_target_seq(4);

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
    store.set_next_sender_seq(42);
    store.set_next_target_seq(17);

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

/// A store whose `reset` and/or `refresh` fail, standing in for a persistent
/// backend that cannot vouch for its counters when the session starts.
#[derive(Debug)]
struct FailingStore {
    inner: MemoryStore,
    fail_reset: bool,
    fail_refresh: bool,
}

impl FailingStore {
    fn failing_reset() -> Self {
        Self {
            inner: MemoryStore::new(),
            fail_reset: true,
            fail_refresh: false,
        }
    }

    fn failing_refresh() -> Self {
        Self {
            inner: MemoryStore::new(),
            fail_reset: false,
            fail_refresh: true,
        }
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

    fn set_next_sender_seq(&self, seq: u64) {
        self.inner.set_next_sender_seq(seq);
    }

    fn set_next_target_seq(&self, seq: u64) {
        self.inner.set_next_target_seq(seq);
    }

    async fn reset(&self) -> Result<(), StoreError> {
        if self.fail_reset {
            return Err(StoreError::Io("reset failed".to_string()));
        }
        self.inner.reset().await
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
