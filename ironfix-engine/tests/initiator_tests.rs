/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 14/7/26
******************************************************************************/

//! Integration tests for the `Initiator`: dial, Logon handshake, message
//! exchange, heartbeats, and close observation against a stub acceptor.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::message::MsgType;
use ironfix_core::message::RawMessage;
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::application::{Application, RejectReason, SessionId};
use ironfix_engine::{EngineError, Initiator, OutboundMessage};
use ironfix_session::SessionConfig;
use ironfix_tagvalue::{Decoder, Encoder};
use ironfix_transport::FixCodec;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::codec::Framed;

/// Stub-acceptor side frame builder (VENUE -> CLIENT).
fn venue_msg(msg_type: &str, seq: u64, extra: &[(u32, &str)]) -> BytesMut {
    let mut encoder = Encoder::new("FIX.4.4");
    encoder.put_str(35, msg_type);
    encoder.put_str(49, "VENUE");
    encoder.put_str(56, "CLIENT");
    encoder.put_uint(34, seq);
    encoder.put_str(52, Timestamp::now().format_millis().as_str());
    for (tag, value) in extra {
        encoder.put_str(*tag, value);
    }
    encoder.finish()
}

/// Extracts a field from a framed message.
fn field(frame: &[u8], tag: u32) -> Option<String> {
    let mut decoder = Decoder::new(frame);
    let raw = decoder.decode().expect("frame decodes");
    raw.get_field_str(tag).map(str::to_string)
}

fn msg_type_of(frame: &[u8]) -> String {
    field(frame, 35).expect("35 present")
}

fn client_config(heartbeat: Duration) -> SessionConfig {
    SessionConfig::new(
        CompId::new("CLIENT").unwrap(),
        CompId::new("VENUE").unwrap(),
        "FIX.4.4",
    )
    .with_heartbeat_interval(heartbeat)
}

async fn accept_framed(listener: TcpListener) -> Framed<TcpStream, FixCodec> {
    let (socket, _) = listener.accept().await.expect("accept");
    Framed::new(socket, FixCodec::new())
}

async fn next_frame(framed: &mut Framed<TcpStream, FixCodec>) -> BytesMut {
    timeout(Duration::from_secs(5), framed.next())
        .await
        .expect("frame within 5s")
        .expect("stream open")
        .expect("frame ok")
}

/// Records session events and received app messages.
#[derive(Debug)]
struct RecordingApp {
    events: Mutex<Vec<String>>,
    app_rx_tx: mpsc::UnboundedSender<String>,
    reject_app: bool,
}

impl RecordingApp {
    fn new(reject_app: bool) -> (Arc<Self>, mpsc::UnboundedReceiver<String>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                events: Mutex::new(Vec::new()),
                app_rx_tx: tx,
                reject_app,
            }),
            rx,
        )
    }

    fn record(&self, event: &str) {
        self.events.lock().unwrap().push(event.to_string());
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
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

    async fn to_admin(
        &self,
        _message: &mut ironfix_core::message::OwnedMessage,
        _session_id: &SessionId,
    ) {
    }

    async fn from_admin(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }

    async fn to_app(
        &self,
        _message: &mut ironfix_core::message::OwnedMessage,
        _session_id: &SessionId,
    ) {
    }

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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;

        let logon = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logon), "A");
        assert_eq!(field(&logon, 49).as_deref(), Some("CLIENT"));
        assert_eq!(field(&logon, 56).as_deref(), Some("VENUE"));
        assert_eq!(field(&logon, 34).as_deref(), Some("1"));
        assert_eq!(field(&logon, 108).as_deref(), Some("30"));
        framed
            .send(venue_msg("A", 1, &[(98, "0"), (108, "30")]))
            .await
            .unwrap();

        let order = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&order), "D");
        assert_eq!(field(&order, 34).as_deref(), Some("2"));
        assert_eq!(field(&order, 11).as_deref(), Some("ORDER-1"));
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
            .await
            .unwrap();

        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5");
        assert_eq!(field(&logout, 34).as_deref(), Some("3"));
        framed.send(venue_msg("5", 3, &[])).await.unwrap();
    });

    let (app, mut app_rx) = RecordingApp::new(false);
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = initiator.connect(addr).await.expect("connect");

    assert_eq!(connection.session_id().to_string(), "FIX.4.4:CLIENT->VENUE");
    assert!(app.events().contains(&"logon".to_string()));
    assert!(!connection.is_closed());

    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order
        .push_str(11, "ORDER-1")
        .push_str(55, "EUR/USD")
        .push_char(54, '1')
        .push_uint(38, 100);
    connection.send(order).await.expect("send");

    let received = timeout(Duration::from_secs(5), app_rx.recv())
        .await
        .expect("app message within 5s")
        .expect("channel open");
    assert_eq!(received, "8");

    connection.logout().await.expect("logout");
    timeout(Duration::from_secs(5), connection.wait_closed())
        .await
        .expect("closed within 5s");

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

    acceptor.await.unwrap();
}

/// Transport drop after logon fires wait_closed and on_logout.
#[tokio::test]
async fn test_transport_drop_fires_wait_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let logon = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logon), "A");
        framed
            .send(venue_msg("A", 1, &[(98, "0"), (108, "30")]))
            .await
            .unwrap();
        // Drop the connection without a Logout.
    });

    let (app, _app_rx) = RecordingApp::new(false);
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = initiator.connect(addr).await.expect("connect");

    timeout(Duration::from_secs(5), connection.wait_closed())
        .await
        .expect("closed within 5s");
    assert!(connection.is_closed());
    assert!(app.events().contains(&"logout".to_string()));

    acceptor.await.unwrap();
}

/// Counterparty-initiated logout is acknowledged and closes the session.
#[tokio::test]
async fn test_counterparty_logout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        framed
            .send(venue_msg("A", 1, &[(98, "0"), (108, "30")]))
            .await
            .unwrap();
        framed
            .send(venue_msg("5", 2, &[(58, "session ended")]))
            .await
            .unwrap();
        // Expect the Logout acknowledgement.
        let reply = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reply), "5");
    });

    let (app, _app_rx) = RecordingApp::new(false);
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = initiator.connect(addr).await.expect("connect");

    timeout(Duration::from_secs(5), connection.wait_closed())
        .await
        .expect("closed within 5s");
    assert!(app.events().contains(&"logout".to_string()));

    acceptor.await.unwrap();
}

/// No Logon ack within the logon timeout -> LogonTimeout.
#[tokio::test]
async fn test_logon_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        // Never reply; hold the socket open until the client gives up.
        let _ = timeout(Duration::from_secs(5), framed.next()).await;
    });

    let (app, _app_rx) = RecordingApp::new(false);
    let config =
        client_config(Duration::from_secs(30)).with_logon_timeout(Duration::from_millis(300));
    let initiator = Initiator::new(config, Arc::clone(&app));

    let err = initiator
        .connect(addr)
        .await
        .expect_err("logon must time out");
    assert!(matches!(err, EngineError::LogonTimeout(_)), "got {err:?}");

    acceptor.abort();
}

/// Logout instead of Logon ack -> LogonRejected with the counterparty text.
#[tokio::test]
async fn test_logon_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        framed
            .send(venue_msg("5", 1, &[(58, "bad credentials")]))
            .await
            .unwrap();
    });

    let (app, _app_rx) = RecordingApp::new(false);
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));

    let err = initiator
        .connect(addr)
        .await
        .expect_err("logon must be rejected");
    match err {
        EngineError::LogonRejected { reason } => assert_eq!(reason, "bad credentials"),
        other => panic!("expected LogonRejected, got {other:?}"),
    }

    acceptor.await.unwrap();
}

/// Idle session: the initiator emits heartbeats at the configured interval.
#[tokio::test]
async fn test_heartbeat_emitted_when_idle() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        framed
            .send(venue_msg("A", 1, &[(98, "0"), (108, "1")]))
            .await
            .unwrap();

        // Keep the client's inbound side alive so it does not TestRequest.
        let heartbeat = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&heartbeat), "0");
        assert_eq!(field(&heartbeat, 34).as_deref(), Some("2"));
    });

    let (app, _app_rx) = RecordingApp::new(false);
    let initiator = Initiator::new(client_config(Duration::from_secs(1)), Arc::clone(&app));
    let _connection = initiator.connect(addr).await.expect("connect");

    timeout(Duration::from_secs(5), acceptor)
        .await
        .expect("acceptor done within 5s")
        .unwrap();
}

/// Inbound TestRequest is answered with a Heartbeat echoing TestReqID (112).
#[tokio::test]
async fn test_test_request_answered() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        framed
            .send(venue_msg("A", 1, &[(98, "0"), (108, "30")]))
            .await
            .unwrap();
        framed
            .send(venue_msg("1", 2, &[(112, "PING-42")]))
            .await
            .unwrap();

        let reply = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reply), "0");
        assert_eq!(field(&reply, 112).as_deref(), Some("PING-42"));
        assert_eq!(field(&reply, 34).as_deref(), Some("2"));
    });

    let (app, _app_rx) = RecordingApp::new(false);
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let _connection = initiator.connect(addr).await.expect("connect");

    timeout(Duration::from_secs(5), acceptor)
        .await
        .expect("acceptor done within 5s")
        .unwrap();
}

/// A silent counterparty triggers TestRequest, then heartbeat timeout: the
/// session closes and the handle observes is_timed_out().
#[tokio::test]
async fn test_heartbeat_timeout_closes_session() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        framed
            .send(venue_msg("A", 1, &[(98, "0"), (108, "1")]))
            .await
            .unwrap();

        // Read and ignore everything: never answer the TestRequest.
        let mut saw_test_request = false;
        while let Ok(Some(Ok(frame))) = timeout(Duration::from_secs(10), framed.next()).await {
            if msg_type_of(&frame) == "1" {
                saw_test_request = true;
            }
        }
        saw_test_request
    });

    let (app, _app_rx) = RecordingApp::new(false);
    let initiator = Initiator::new(client_config(Duration::from_secs(1)), Arc::clone(&app));
    let connection = initiator.connect(addr).await.expect("connect");

    // TestRequest due at interval + 1s grace; timeout one interval later.
    timeout(Duration::from_secs(8), connection.wait_closed())
        .await
        .expect("closed within 8s");
    assert!(connection.is_timed_out());
    assert!(app.events().contains(&"logout".to_string()));

    let saw_test_request = acceptor.await.unwrap();
    assert!(saw_test_request, "acceptor should have seen a TestRequest");
}

/// A sequence gap triggers a ResendRequest and the gapped app message is not
/// delivered to the application.
#[tokio::test]
async fn test_sequence_gap_triggers_resend_request() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        framed
            .send(venue_msg("A", 1, &[(98, "0"), (108, "30")]))
            .await
            .unwrap();

        // Jump from seq 2 to seq 5: gap of 2..=4.
        framed
            .send(venue_msg(
                "8",
                5,
                &[(37, "EX-9"), (17, "E-9"), (150, "0"), (39, "0")],
            ))
            .await
            .unwrap();

        let resend = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&resend), "2");
        assert_eq!(field(&resend, 7).as_deref(), Some("2"));
        assert_eq!(field(&resend, 16).as_deref(), Some("0"));
    });

    let (app, mut app_rx) = RecordingApp::new(false);
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let _connection = initiator.connect(addr).await.expect("connect");

    timeout(Duration::from_secs(5), acceptor)
        .await
        .expect("acceptor done within 5s")
        .unwrap();

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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        framed
            .send(venue_msg("A", 1, &[(98, "0"), (108, "30")]))
            .await
            .unwrap();
        framed
            .send(venue_msg(
                "8",
                2,
                &[(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")],
            ))
            .await
            .unwrap();

        let reject = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reject), "3");
        assert_eq!(field(&reject, 45).as_deref(), Some("2"));
        assert_eq!(field(&reject, 372).as_deref(), Some("8"));
        assert_eq!(field(&reject, 373).as_deref(), Some("99"));
        assert_eq!(field(&reject, 58).as_deref(), Some("rejected by test app"));
    });

    let (app, _app_rx) = RecordingApp::new(true);
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let _connection = initiator.connect(addr).await.expect("connect");

    timeout(Duration::from_secs(5), acceptor)
        .await
        .expect("acceptor done within 5s")
        .unwrap();
}

/// Sequence state survives across messages within a session and is visible
/// on the handle.
#[tokio::test]
async fn test_sequence_state_within_session() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let acceptor = tokio::spawn(async move {
        let mut framed = accept_framed(listener).await;
        let _logon = next_frame(&mut framed).await;
        framed
            .send(venue_msg("A", 1, &[(98, "0"), (108, "30")]))
            .await
            .unwrap();

        for expected_seq in 2..=4u64 {
            let frame = next_frame(&mut framed).await;
            assert_eq!(msg_type_of(&frame), "D");
            assert_eq!(field(&frame, 34), Some(expected_seq.to_string()));
        }
    });

    let (app, _app_rx) = RecordingApp::new(false);
    let initiator = Initiator::new(client_config(Duration::from_secs(30)), Arc::clone(&app));
    let connection = initiator.connect(addr).await.expect("connect");

    for i in 0..3 {
        let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
        order.push_str(11, &format!("ORDER-{i}"));
        connection.send(order).await.expect("send");
    }

    timeout(Duration::from_secs(5), acceptor)
        .await
        .expect("acceptor done within 5s")
        .unwrap();

    assert_eq!(connection.next_sender_seq(), 5);
    assert_eq!(connection.next_target_seq(), 2);
}
