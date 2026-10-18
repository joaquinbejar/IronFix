/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 22/7/26
******************************************************************************/

//! Integration tests for the `Acceptor`, driven by the real `Initiator` over a
//! loopback `TcpListener`.
//!
//! The headline test is the acceptance criterion for issue #21: a live
//! `Initiator` establishes a session against a live `Acceptor`, an application
//! message flows each way, and the session ends with a graceful Logout. Because
//! both engines run the same reactor, this is the proof that the initiator and
//! acceptor typestates agree on the wire. The remaining tests cover the
//! acceptor-only handshake paths: CompID authentication, the logon timeout, a
//! non-Logon first frame, the `ResetSeqNumFlag` reset handshake, and the
//! handshake hardening — a `HeartBtInt` overflow, a wrong `BeginString`, a
//! body-only `MsgSeqNum`, a duplicate concurrent connection, and a locally
//! driven reset that must signal `141=Y`. The last group covers garbled inbound
//! frames on the acceptor's codec: skipped without consuming a `MsgSeqNum` or
//! refreshing the heartbeat, recovered through `ResendRequest`, bounded by the
//! optional garbled-frame limit, and never masking a fatal oversized frame.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::error::StoreError;
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::application::{Application, RejectReason, SessionId};
use ironfix_engine::{
    Acceptor, Connection, EngineBuilder, EngineError, Initiator, OutboundMessage,
    StoreFailurePolicy,
};
use ironfix_session::sequence::SequenceCounter;
use ironfix_session::{GarbledFrameLimit, SessionConfig};
use ironfix_store::{MemoryStore, MessageStore, StoredMessage};
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

/// Binds an ephemeral loopback listener.
async fn bind_listener() -> (TcpListener, std::net::SocketAddr) {
    let listener = ok(
        TcpListener::bind("127.0.0.1:0").await,
        "listener must bind to loopback",
    );
    let addr = ok(listener.local_addr(), "listener must report its address");
    (listener, addr)
}

/// Acceptor-side session config: sender is VENUE, target is the CLIENT it
/// expects.
fn venue_config(heartbeat: Duration) -> SessionConfig {
    SessionConfig::new(comp_id("VENUE"), comp_id("CLIENT"), "FIX.4.4")
        .with_heartbeat_interval(heartbeat)
}

/// Initiator-side session config: sender is CLIENT, target is VENUE.
fn client_config(heartbeat: Duration) -> SessionConfig {
    SessionConfig::new(comp_id("CLIENT"), comp_id("VENUE"), "FIX.4.4")
        .with_heartbeat_interval(heartbeat)
}

/// Records session events and forwards received app messages.
#[derive(Debug)]
struct RecordingApp {
    events: Mutex<Vec<String>>,
    app_rx_tx: mpsc::UnboundedSender<String>,
}

impl RecordingApp {
    fn new() -> (Arc<Self>, mpsc::UnboundedReceiver<String>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                events: Mutex::new(Vec::new()),
                app_rx_tx: tx,
            }),
            rx,
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
        let _ = self.app_rx_tx.send(message.msg_type().as_str().to_string());
        Ok(())
    }
}

/// The acceptance criterion for issue #21: a real Initiator establishes a
/// session against a real Acceptor, an application message flows each way, and
/// the session ends with a graceful Logout. Both engines run the same reactor,
/// so this proves the two typestates agree on the wire.
#[tokio::test]
async fn test_initiator_against_acceptor_full_session_completes() {
    let (listener, addr) = bind_listener().await;

    let (venue_app, mut venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config(Duration::from_secs(30)),
        Arc::clone(&venue_app),
    );

    let venue = tokio::spawn(async move {
        let connection = ok(
            acceptor.accept(&listener).await,
            "acceptor establishes a session",
        );

        // The client's order must reach the venue application.
        let order = some(
            ok(
                timeout(Duration::from_secs(5), venue_rx.recv()).await,
                "the client order arrives within 5s",
            ),
            "venue app channel must stay open",
        );
        assert_eq!(order, "D");

        // Reply with an ExecutionReport.
        let mut exec = OutboundMessage::new(MsgType::ExecutionReport);
        exec.push_str(37, "EX-1")
            .push_str(11, "ORDER-1")
            .push_str(17, "E-1")
            .push_char(150, '0')
            .push_char(39, '0');
        ok(
            connection.send(exec).await,
            "venue sends the execution report",
        );

        // The client's Logout closes the venue session too.
        ok(
            timeout(Duration::from_secs(5), connection.wait_closed()).await,
            "venue session closes within 5s",
        );
        connection
    });

    let (client_app, mut client_rx) = RecordingApp::new();
    let initiator = Initiator::new(
        client_config(Duration::from_secs(30)),
        Arc::clone(&client_app),
    );
    let connection = ok(initiator.connect(addr).await, "client connects and logs on");

    assert_eq!(connection.session_id().to_string(), "FIX.4.4:CLIENT->VENUE");
    assert!(client_app.events().contains(&"logon".to_string()));

    // The client's Logon is seq 1; the first application message is seq 2.
    assert_eq!(connection.next_sender_seq(), 2);

    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order
        .push_str(11, "ORDER-1")
        .push_str(55, "EUR/USD")
        .push_char(54, '1')
        .push_uint(38, 100);
    ok(connection.send(order).await, "client sends the order");

    // The venue's ExecutionReport must reach the client application.
    let exec = some(
        ok(
            timeout(Duration::from_secs(5), client_rx.recv()).await,
            "the execution report arrives within 5s",
        ),
        "client app channel must stay open",
    );
    assert_eq!(exec, "8");

    ok(connection.logout().await, "client initiates the logout");
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "client session closes within 5s",
    );

    let venue_connection = ok(venue.await, "venue task joins");
    assert!(venue_connection.is_closed());

    // Both sides saw the full lifecycle.
    for app in [&client_app, &venue_app] {
        let events = app.events();
        assert_eq!(events.first().map(String::as_str), Some("create"));
        assert!(
            events.contains(&"logon".to_string()),
            "missing logon: {events:?}"
        );
        assert!(
            events.contains(&"logout".to_string()),
            "missing logout: {events:?}"
        );
    }
}

/// A Logon whose CompIDs do not match the acceptor's configured counterparty is
/// rejected: the handshake fails and the acceptor never reaches a session.
#[tokio::test]
async fn test_acceptor_rejects_unknown_comp_id() {
    let (listener, addr) = bind_listener().await;

    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config(Duration::from_secs(30)),
        Arc::clone(&venue_app),
    );

    let venue = tokio::spawn(async move {
        match acceptor.accept(&listener).await {
            Err(EngineError::IdentityMismatch { detail }) => detail,
            other => panic!("expected IdentityMismatch, got {other:?}"),
        }
    });

    // A stranger connects and sends a Logon claiming the wrong SenderCompID.
    let stream = ok(TcpStream::connect(addr).await, "stranger connects");
    let mut framed = Framed::new(stream, FixCodec::new());
    let mut encoder = Encoder::new("FIX.4.4");
    encoder.put_str(35, "A");
    encoder.put_str(49, "STRANGER");
    encoder.put_str(56, "VENUE");
    encoder.put_uint(34, 1);
    encoder.put_str(52, Timestamp::now().format_millis().as_str());
    encoder.put_uint(98, 0);
    encoder.put_uint(108, 30);
    let mut logon = BytesMut::new();
    ok(
        encoder.finish_into(&mut logon),
        "stranger logon must encode",
    );
    ok(framed.send(logon).await, "stranger sends its logon");

    // The acceptor answers with a session-level Reject (reason 9) and a Logout.
    let reject = some(
        ok(
            timeout(Duration::from_secs(5), framed.next()).await,
            "a Reject arrives within 5s",
        ),
        "stream must stay open",
    );
    let reject = ok(reject, "reject frame must decode");
    let mut decoder = Decoder::new(&reject);
    let raw = ok(decoder.decode(), "reject decodes");
    assert_eq!(raw.msg_type(), &MsgType::Reject);
    assert_eq!(raw.get_field_str(373), Some("9"));

    let detail = ok(venue.await, "venue task joins");
    assert!(detail.contains("tag 49"), "got {detail}");
    // The application was created but never logged on.
    let events = venue_app.events();
    assert!(events.contains(&"create".to_string()));
    assert!(!events.contains(&"logon".to_string()));
}

/// No Logon within the logon timeout aborts the handshake with LogonTimeout.
#[tokio::test]
async fn test_acceptor_logon_timeout_without_logon() {
    let (listener, addr) = bind_listener().await;

    let (venue_app, _venue_rx) = RecordingApp::new();
    let config =
        venue_config(Duration::from_secs(30)).with_logon_timeout(Duration::from_millis(300));
    let acceptor = Acceptor::new(config, Arc::clone(&venue_app));

    let venue = tokio::spawn(async move {
        match acceptor.accept(&listener).await {
            Err(EngineError::LogonTimeout(_)) => {}
            other => panic!("expected LogonTimeout, got {other:?}"),
        }
    });

    // Connect but never send a Logon.
    let _stream = ok(TcpStream::connect(addr).await, "client connects");
    ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue task finishes within 5s",
        ),
        "venue task joins",
    );
}

/// A first frame that is not a Logon is rejected with UnexpectedMessage.
#[tokio::test]
async fn test_acceptor_first_frame_not_logon_is_unexpected() {
    let (listener, addr) = bind_listener().await;

    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config(Duration::from_secs(30)),
        Arc::clone(&venue_app),
    );

    let venue = tokio::spawn(async move {
        match acceptor.accept(&listener).await {
            Err(EngineError::UnexpectedMessage { msg_type }) => msg_type,
            other => panic!("expected UnexpectedMessage, got {other:?}"),
        }
    });

    // Send a Heartbeat before any Logon.
    let stream = ok(TcpStream::connect(addr).await, "client connects");
    let mut framed = Framed::new(stream, FixCodec::new());
    let mut encoder = Encoder::new("FIX.4.4");
    encoder.put_str(35, "0");
    encoder.put_str(49, "CLIENT");
    encoder.put_str(56, "VENUE");
    encoder.put_uint(34, 1);
    encoder.put_str(52, Timestamp::now().format_millis().as_str());
    let mut heartbeat = BytesMut::new();
    ok(encoder.finish_into(&mut heartbeat), "heartbeat must encode");
    ok(framed.send(heartbeat).await, "client sends a heartbeat");

    let msg_type = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue task finishes within 5s",
        ),
        "venue task joins",
    );
    assert_eq!(msg_type, "0");
}

/// Sends a well-formed FIX.4.4 client Logon (49=CLIENT, 56=VENUE, 34=1, 98=0,
/// 108=30) on `framed`.
async fn send_client_logon(framed: &mut Framed<TcpStream, FixCodec>) {
    let mut encoder = Encoder::new("FIX.4.4");
    encoder.put_str(35, "A");
    encoder.put_str(49, "CLIENT");
    encoder.put_str(56, "VENUE");
    encoder.put_uint(34, 1);
    encoder.put_str(52, Timestamp::now().format_millis().as_str());
    encoder.put_uint(98, 0);
    encoder.put_uint(108, 30);
    let mut logon = BytesMut::new();
    ok(encoder.finish_into(&mut logon), "client logon must encode");
    ok(framed.send(logon).await, "client sends its logon");
}

/// A Logon carrying `HeartBtInt (108) = u64::MAX` must fail the handshake, not
/// abort the process. Building `Duration::from_secs(u64::MAX)` and feeding it to
/// the heartbeat clock overflows `interval + grace` and panics — a remote abort
/// under `panic = "abort"`. The acceptor bounds the value at the handshake, so
/// this returns a typed error and the test binary keeps running.
#[tokio::test]
async fn test_acceptor_rejects_overflowing_heartbeat_interval() {
    let (listener, addr) = bind_listener().await;

    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config(Duration::from_secs(30)),
        Arc::clone(&venue_app),
    );

    let venue = tokio::spawn(async move {
        match acceptor.accept(&listener).await {
            Err(EngineError::LogonRejected { reason }) => reason,
            other => panic!("expected LogonRejected, got {other:?}"),
        }
    });

    let stream = ok(TcpStream::connect(addr).await, "client connects");
    let mut framed = Framed::new(stream, FixCodec::new());
    let mut encoder = Encoder::new("FIX.4.4");
    encoder.put_str(35, "A");
    encoder.put_str(49, "CLIENT");
    encoder.put_str(56, "VENUE");
    encoder.put_uint(34, 1);
    encoder.put_str(52, Timestamp::now().format_millis().as_str());
    encoder.put_uint(98, 0);
    encoder.put_str(108, &u64::MAX.to_string());
    let mut logon = BytesMut::new();
    ok(encoder.finish_into(&mut logon), "logon must encode");
    ok(framed.send(logon).await, "client sends its logon");

    let reason = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue task finishes within 5s",
        ),
        "venue task joins",
    );
    assert!(reason.contains("HeartBtInt"), "got {reason}");
    // The application never logged on.
    assert!(!venue_app.events().contains(&"logon".to_string()));
}

/// A Logon whose BeginString (8) does not match the acceptor's configured
/// version is rejected before it can reach a session in the wrong version.
#[tokio::test]
async fn test_acceptor_rejects_wrong_begin_string() {
    let (listener, addr) = bind_listener().await;

    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config(Duration::from_secs(30)),
        Arc::clone(&venue_app),
    );

    let venue = tokio::spawn(async move {
        match acceptor.accept(&listener).await {
            Err(EngineError::LogonRejected { reason }) => reason,
            other => panic!("expected LogonRejected, got {other:?}"),
        }
    });

    // A FIX.4.2 Logon against a FIX.4.4 acceptor, otherwise well-formed.
    let stream = ok(TcpStream::connect(addr).await, "client connects");
    let mut framed = Framed::new(stream, FixCodec::new());
    let mut encoder = Encoder::new("FIX.4.2");
    encoder.put_str(35, "A");
    encoder.put_str(49, "CLIENT");
    encoder.put_str(56, "VENUE");
    encoder.put_uint(34, 1);
    encoder.put_str(52, Timestamp::now().format_millis().as_str());
    encoder.put_uint(98, 0);
    encoder.put_uint(108, 30);
    let mut logon = BytesMut::new();
    ok(encoder.finish_into(&mut logon), "logon must encode");
    ok(framed.send(logon).await, "client sends its logon");

    let reason = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue task finishes within 5s",
        ),
        "venue task joins",
    );
    assert!(reason.contains("BeginString"), "got {reason}");
    assert!(!venue_app.events().contains(&"logon".to_string()));
}

/// A Logon whose MsgSeqNum (34) sits only in the body, not the standard header,
/// is treated as missing its sequence number and fails the handshake.
#[tokio::test]
async fn test_acceptor_rejects_body_only_seq_num() {
    let (listener, addr) = bind_listener().await;

    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config(Duration::from_secs(30)),
        Arc::clone(&venue_app),
    );

    let venue = tokio::spawn(async move {
        match acceptor.accept(&listener).await {
            Err(EngineError::Sequence(detail)) => detail,
            other => panic!("expected Sequence error, got {other:?}"),
        }
    });

    // EncryptMethod (98) is a body field, so the standard-header run ends at it;
    // a 34 placed after it is not the header MsgSeqNum.
    let stream = ok(TcpStream::connect(addr).await, "client connects");
    let mut framed = Framed::new(stream, FixCodec::new());
    let mut encoder = Encoder::new("FIX.4.4");
    encoder.put_str(35, "A");
    encoder.put_str(49, "CLIENT");
    encoder.put_str(56, "VENUE");
    encoder.put_str(52, Timestamp::now().format_millis().as_str());
    encoder.put_uint(98, 0);
    encoder.put_uint(108, 30);
    encoder.put_uint(34, 1);
    let mut logon = BytesMut::new();
    ok(encoder.finish_into(&mut logon), "logon must encode");
    ok(framed.send(logon).await, "client sends its logon");

    let detail = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue task finishes within 5s",
        ),
        "venue task joins",
    );
    assert!(detail.contains("MsgSeqNum"), "got {detail}");
    assert!(!venue_app.events().contains(&"logon".to_string()));
}

/// Two concurrent valid Logons for the same configured counterparty: exactly one
/// is admitted and the other is refused as a duplicate. Without the admission
/// slot both would build independent sequence state and reach Active at 1.
#[tokio::test]
async fn test_acceptor_refuses_second_concurrent_logon() {
    let (listener, addr) = bind_listener().await;

    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Arc::new(Acceptor::new(
        venue_config(Duration::from_secs(30)),
        Arc::clone(&venue_app),
    ));

    // Two clients connect and each sends a well-formed Logon.
    let client_a = ok(TcpStream::connect(addr).await, "client A connects");
    let (server_a, _) = ok(listener.accept().await, "acceptor takes A");
    let client_b = ok(TcpStream::connect(addr).await, "client B connects");
    let (server_b, _) = ok(listener.accept().await, "acceptor takes B");

    let mut framed_a = Framed::new(client_a, FixCodec::new());
    let mut framed_b = Framed::new(client_b, FixCodec::new());
    send_client_logon(&mut framed_a).await;
    send_client_logon(&mut framed_b).await;

    // Serve both on the shared acceptor concurrently.
    let acc_a = Arc::clone(&acceptor);
    let acc_b = Arc::clone(&acceptor);
    let serve_a = tokio::spawn(async move { acc_a.serve(server_a).await });
    let serve_b = tokio::spawn(async move { acc_b.serve(server_b).await });

    let res_a = ok(
        ok(
            timeout(Duration::from_secs(5), serve_a).await,
            "serve A in 5s",
        ),
        "serve A joins",
    );
    let res_b = ok(
        ok(
            timeout(Duration::from_secs(5), serve_b).await,
            "serve B in 5s",
        ),
        "serve B joins",
    );

    // The duplicate is closed without a reply, with or without a store: the
    // live session owns the sequence stream.
    let refused_framed = if res_a.is_err() {
        &mut framed_a
    } else {
        &mut framed_b
    };
    assert!(
        timeout(Duration::from_secs(5), refused_framed.next())
            .await
            .ok()
            .flatten()
            .is_none(),
        "the duplicate gets no reply"
    );

    // Exactly one session established; the other was refused as a duplicate.
    let results = [res_a, res_b];
    let admitted = results.iter().filter(|r| r.is_ok()).count();
    let refused = results
        .iter()
        .filter(|r| matches!(r, Err(EngineError::LogonRejected { reason }) if reason.contains("already active")))
        .count();
    assert_eq!(
        admitted, 1,
        "exactly one session must be admitted: {results:?}"
    );
    assert_eq!(
        refused, 1,
        "exactly one duplicate must be refused: {results:?}"
    );

    drop(framed_a);
    drop(framed_b);
}

/// The initiator drives a ResetSeqNumFlag Logon and the acceptor mirrors it:
/// both counters reset to 1, the acceptor's ack carries 141=Y at seq 1, and the
/// session establishes cleanly.
#[tokio::test]
async fn test_acceptor_mirrors_reset_seq_num_flag() {
    let (listener, addr) = bind_listener().await;

    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config(Duration::from_secs(30)),
        Arc::clone(&venue_app),
    );

    let venue = tokio::spawn(async move {
        let connection = ok(
            acceptor.accept(&listener).await,
            "acceptor establishes a reset session",
        );
        // After a reset the acceptor's Logon reply went out at seq 1, so the
        // next sender sequence is 2, and it expects the client's next inbound
        // at 2.
        assert_eq!(connection.next_sender_seq(), 2);
        assert_eq!(connection.next_target_seq(), 2);
        connection
    });

    let (client_app, _client_rx) = RecordingApp::new();
    // Seed the client with stale counters, then force a reset on logon: the
    // acceptor must mirror it and the handshake must still succeed.
    let config = client_config(Duration::from_secs(30)).with_reset_on_logon(true);
    let initiator = Initiator::new(config, Arc::clone(&client_app)).with_initial_sequences(50, 50);
    let connection = ok(
        initiator.connect(addr).await,
        "client connects with a reset",
    );

    assert!(client_app.events().contains(&"logon".to_string()));
    // The client's Logon went out at seq 1 (reset), so its next sender is 2 and
    // it expects the acceptor's next inbound at 2.
    assert_eq!(connection.next_sender_seq(), 2);
    assert_eq!(connection.next_target_seq(), 2);

    ok(connection.logout().await, "client logs out");
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "client session closes within 5s",
    );

    let venue_connection = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue task finishes within 5s",
        ),
        "venue task joins",
    );
    assert!(venue_connection.is_closed());
}

/// An acceptor configured with `reset_on_logon` whose peer omits `141=Y` must
/// SIGNAL the reset it performs: its Logon ack carries `141=Y` at seq 1 rather
/// than silently resetting and acking without the flag, which would desync the
/// peer.
#[tokio::test]
async fn test_acceptor_reset_on_logon_signals_the_reset() {
    let (listener, addr) = bind_listener().await;

    let (venue_app, _venue_rx) = RecordingApp::new();
    let config = venue_config(Duration::from_secs(30)).with_reset_on_logon(true);
    let acceptor = Acceptor::new(config, Arc::clone(&venue_app));

    let venue = tokio::spawn(async move {
        let connection = ok(
            acceptor.accept(&listener).await,
            "acceptor establishes a session",
        );
        // The acceptor reset and its ack went out at seq 1, so the next sender
        // is 2 and it expects the client's next inbound at 2.
        assert_eq!(connection.next_sender_seq(), 2);
        assert_eq!(connection.next_target_seq(), 2);
        connection
    });

    // A plain Logon at seq 1 with NO ResetSeqNumFlag.
    let stream = ok(TcpStream::connect(addr).await, "client connects");
    let mut framed = Framed::new(stream, FixCodec::new());
    send_client_logon(&mut framed).await;

    // The acceptor's ack must be a Logon at seq 1 carrying 141=Y.
    let ack = some(
        ok(
            timeout(Duration::from_secs(5), framed.next()).await,
            "a Logon ack arrives within 5s",
        ),
        "stream must stay open",
    );
    let ack = ok(ack, "ack frame must decode");
    let mut decoder = Decoder::new(&ack);
    let raw = ok(decoder.decode(), "ack decodes");
    assert_eq!(raw.msg_type(), &MsgType::Logon);
    assert_eq!(raw.get_field_str(34), Some("1"));
    assert_eq!(
        raw.get_field_str(141),
        Some("Y"),
        "the acceptor must signal the reset it performed"
    );

    let connection = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue task finishes within 5s",
        ),
        "venue task joins",
    );
    // Drop the client so the session closes out cleanly.
    drop(framed);
    let _ = timeout(Duration::from_secs(5), connection.wait_closed()).await;
}

// ---------------------------------------------------------------------------
// Garbled inbound frames
// ---------------------------------------------------------------------------

/// Stub-initiator frame builder (CLIENT -> VENUE).
#[track_caller]
fn client_msg(msg_type: &str, seq: u64, extra: &[(u32, &str)]) -> BytesMut {
    let mut encoder = Encoder::new("FIX.4.4");
    encoder.put_str(35, msg_type);
    encoder.put_str(49, "CLIENT");
    encoder.put_str(56, "VENUE");
    encoder.put_uint(34, seq);
    encoder.put_str(52, Timestamp::now().format_millis().as_str());
    for (tag, value) in extra {
        encoder.put_str(*tag, value);
    }
    let mut frame = BytesMut::new();
    ok(
        encoder.finish_into(&mut frame),
        "test fixture frame must encode",
    );
    frame
}

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

/// Builds a frame around `body` with a correct BodyLength and CheckSum,
/// bypassing the encoder, which refuses a body whose first field is not
/// MsgType.
fn raw_frame(body: &[u8]) -> BytesMut {
    let mut frame = Vec::with_capacity(body.len() + 32);
    frame.extend_from_slice(b"8=FIX.4.4\x01");
    frame.extend_from_slice(format!("9={}\x01", body.len()).as_bytes());
    frame.extend_from_slice(body);
    let sum: u64 = frame.iter().map(|&b| u64::from(b)).sum();
    frame.extend_from_slice(format!("10={:03}\x01", sum % 256).as_bytes());
    BytesMut::from(&frame[..])
}

/// A client Logon that frames correctly but whose MsgType (35) is not the
/// third field: garbled at the decode level, as the FIX Session Layer defines
/// it.
fn logon_with_msg_type_out_of_place() -> BytesMut {
    raw_frame(b"49=CLIENT\x0135=A\x0156=VENUE\x0134=1\x0198=0\x01108=30\x01")
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

/// A garbled-frame bound of `max` frames within `window`.
#[track_caller]
fn garbled_limit(max: u32, window: Duration) -> GarbledFrameLimit {
    let max = some(NonZeroU32::new(max), "test frame count must be non-zero");
    ok(
        GarbledFrameLimit::try_new(max, window),
        "test limit must be valid",
    )
}

/// Extracts a field from a framed message.
fn field(frame: &[u8], tag: u32) -> Option<String> {
    let mut decoder = Decoder::new(frame);
    match decoder.decode() {
        Ok(raw) => raw.get_field_str(tag).map(str::to_string),
        Err(_) => None,
    }
}

/// Returns the MsgType (35) of a framed message.
#[track_caller]
fn msg_type_of(frame: &[u8]) -> String {
    some(field(frame, 35), "frame must carry MsgType (35)")
}

/// Reads the next frame the acceptor sends, within 5 s.
async fn next_frame(framed: &mut Framed<TcpStream, FixCodec>) -> BytesMut {
    let polled = ok(
        timeout(Duration::from_secs(5), framed.next()).await,
        "frame must arrive within 5s",
    );
    ok(some(polled, "stream must stay open"), "frame must decode")
}

/// Reads until the acceptor hangs up, so a close is the acceptor's verdict
/// and never this side dropping the socket first.
async fn read_until_closed(framed: &mut Framed<TcpStream, FixCodec>) {
    while let Ok(Some(Ok(_))) = timeout(Duration::from_secs(5), framed.next()).await {}
}

/// Runs the Logon handshake from a stub initiator against `acceptor` and
/// returns the stub's socket together with the acceptor's live connection.
///
/// The Logon asks for `HeartBtInt` (108) = `heartbeat_secs`, which the
/// acceptor honours.
async fn establish(
    acceptor: Acceptor<RecordingApp>,
    heartbeat_secs: u64,
) -> (Framed<TcpStream, FixCodec>, Connection) {
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move { acceptor.accept(&listener).await });

    let stream = ok(TcpStream::connect(addr).await, "client connects");
    let mut framed = Framed::new(stream, FixCodec::new());
    let heartbeat = heartbeat_secs.to_string();
    ok(
        framed
            .send(client_msg("A", 1, &[(98, "0"), (108, heartbeat.as_str())]))
            .await,
        "client sends its logon",
    );
    let ack = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&ack), "A");

    let connection = ok(
        ok(
            ok(
                timeout(Duration::from_secs(5), venue).await,
                "handshake within 5s",
            ),
            "venue task joins",
        ),
        "acceptor establishes the session",
    );
    (framed, connection)
}

/// A garbled frame in the acceptor's session between two valid frames is
/// ignored: the session stays Active, the garbled frame consumes no MsgSeqNum,
/// the next valid frame is a gap answered with a ResendRequest for the garbled
/// number, and the usual GapFill recovers the session.
#[tokio::test]
async fn test_acceptor_garbled_checksum_frame_is_skipped_and_its_gap_resent() {
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config(Duration::from_secs(30)),
        Arc::clone(&venue_app),
    );
    let (mut framed, connection) = establish(acceptor, 30).await;

    ok(
        framed.send(client_msg("1", 2, &[(112, "BEFORE")])).await,
        "send in-sequence TestRequest",
    );
    let reply = next_frame(&mut framed).await;
    assert_eq!(field(&reply, 112).as_deref(), Some("BEFORE"));

    // Seq 3 is garbled and seq 4 follows it in the same write.
    let mut burst = with_wrong_checksum(&client_msg("1", 3, &[(112, "GARBLED")]));
    burst.extend_from_slice(&client_msg("1", 4, &[(112, "AFTER")]));
    ok(framed.send(burst).await, "send garbled + valid frames");

    let resend = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&resend), "2", "the gap must be requested");
    assert_eq!(field(&resend, 7).as_deref(), Some("3"));
    assert_eq!(field(&resend, 16).as_deref(), Some("0"));
    let reply = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&reply), "0");
    assert_eq!(field(&reply, 112).as_deref(), Some("AFTER"));

    // The acceptor answered seq 4 after requesting the gap, so it has
    // processed both: the garbled seq 3 consumed nothing.
    assert_eq!(connection.next_target_seq(), 3);
    assert!(
        !connection.is_closed(),
        "a garbled frame must not end the session"
    );

    // Recover the gap the usual way.
    ok(
        framed
            .send(client_msg("4", 3, &[(123, "Y"), (36, "5")]))
            .await,
        "send gap fill",
    );
    ok(
        framed.send(client_msg("1", 5, &[(112, "RECOVERED")])).await,
        "send in-sequence TestRequest after the fill",
    );
    let reply = next_frame(&mut framed).await;
    assert_eq!(field(&reply, 112).as_deref(), Some("RECOVERED"));
    assert_eq!(connection.next_target_seq(), 6);
    assert!(!connection.is_closed());

    drop(framed);
    let _ = timeout(Duration::from_secs(5), connection.wait_closed()).await;
}

/// Bytes before a frame's `8=` are skipped by the acceptor and the frame
/// behind them is processed normally: no gap, no ResendRequest.
#[tokio::test]
async fn test_acceptor_garbage_before_a_frame_is_skipped_and_the_frame_processed() {
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config(Duration::from_secs(30)),
        Arc::clone(&venue_app),
    );
    let (mut framed, connection) = establish(acceptor, 30).await;

    let mut burst = BytesMut::from(&b"\x00\x7fline noise before the frame\xff"[..]);
    burst.extend_from_slice(&client_msg("1", 2, &[(112, "PING")]));
    ok(framed.send(burst).await, "send garbage + TestRequest");

    let reply = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&reply), "0", "no ResendRequest may come first");
    assert_eq!(field(&reply, 112).as_deref(), Some("PING"));
    assert_eq!(connection.next_target_seq(), 3);
    assert!(!connection.is_closed());

    drop(framed);
    let _ = timeout(Duration::from_secs(5), connection.wait_closed()).await;
}

/// A garbled frame before the Logon is skipped too: the acceptor waits for
/// the valid Logon behind it (within the logon timeout) instead of failing
/// the handshake.
#[tokio::test]
async fn test_acceptor_garbled_frame_before_the_logon_is_skipped() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config(Duration::from_secs(30)),
        Arc::clone(&venue_app),
    );
    let venue = tokio::spawn(async move { acceptor.accept(&listener).await });

    let stream = ok(TcpStream::connect(addr).await, "client connects");
    let mut framed = Framed::new(stream, FixCodec::new());
    // One Logon the codec cannot frame, one that frames but does not decode,
    // then the valid one.
    let mut burst = with_wrong_checksum(&client_msg("A", 1, &[(98, "0"), (108, "30")]));
    burst.extend_from_slice(&logon_with_msg_type_out_of_place());
    burst.extend_from_slice(&client_msg("A", 1, &[(98, "0"), (108, "30")]));
    ok(framed.send(burst).await, "send garbled + valid Logon");

    let ack = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&ack), "A");
    let connection = ok(
        ok(
            ok(
                timeout(Duration::from_secs(5), venue).await,
                "handshake within 5s",
            ),
            "venue task joins",
        ),
        "the valid Logon behind the garbled one establishes the session",
    );
    assert_eq!(connection.next_target_seq(), 2);

    drop(framed);
    let _ = timeout(Duration::from_secs(5), connection.wait_closed()).await;
}

/// A frame declaring more than `max_message_size` is fatal, recovery or not:
/// the acceptor closes the session while the client still holds its socket.
#[tokio::test]
async fn test_acceptor_oversized_frame_still_closes_the_session() {
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config(Duration::from_secs(30)),
        Arc::clone(&venue_app),
    );
    let (mut framed, connection) = establish(acceptor, 30).await;

    // 2 MiB declared against the default 1 MiB ceiling.
    ok(
        framed
            .send(BytesMut::from(
                &b"8=FIX.4.4\x019=2097152\x0135=0\x0149=CLIENT\x01"[..],
            ))
            .await,
        "send oversized header",
    );

    // The read side is unusable but the write side is not: the acceptor says
    // why before it hangs up.
    let logout = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&logout), "5");
    assert_eq!(field(&logout, 58).as_deref(), Some("message too large"));

    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );
    assert!(connection.is_closed());
    assert!(!connection.is_timed_out());
    assert!(venue_app.events().contains(&"logout".to_string()));
    read_until_closed(&mut framed).await;
}

/// With a garbled-frame limit of 3 within a minute, two garbled frames are
/// tolerated by the acceptor; the third logs the session out.
#[tokio::test]
async fn test_acceptor_garbled_frame_limit_closes_the_session() {
    let (venue_app, _venue_rx) = RecordingApp::new();
    let limit = garbled_limit(3, Duration::from_secs(60));
    let config = venue_config(Duration::from_secs(30)).with_garbled_frame_limit(Some(limit));
    let acceptor = Acceptor::new(config, Arc::clone(&venue_app));
    let (mut framed, connection) = establish(acceptor, 30).await;

    let mut burst = with_wrong_checksum(&client_msg("0", 2, &[]));
    burst.extend_from_slice(&with_wrong_checksum(&client_msg("0", 3, &[])));
    burst.extend_from_slice(&client_msg("1", 4, &[(112, "STILL-UP")]));
    ok(
        framed.send(burst).await,
        "send two garbled frames + one valid",
    );

    let resend = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&resend), "2");
    assert_eq!(field(&resend, 7).as_deref(), Some("2"));
    let reply = next_frame(&mut framed).await;
    assert_eq!(field(&reply, 112).as_deref(), Some("STILL-UP"));
    assert!(
        !connection.is_closed(),
        "two garbled frames are under the limit"
    );

    ok(
        framed
            .send(with_wrong_checksum(&client_msg("0", 5, &[])))
            .await,
        "send the third garbled frame",
    );
    let logout = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&logout), "5");
    assert!(
        some(field(&logout, 58), "logout must carry Text").contains("garbled"),
        "the logout should explain the garbled-frame limit"
    );

    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );
    assert!(!connection.is_timed_out());
    read_until_closed(&mut framed).await;
}

/// Garbled bytes are not proof of life on the acceptor either: a peer that
/// sends nothing but garbled frames is probed with a TestRequest and timed
/// out.
#[tokio::test]
async fn test_acceptor_garbled_frames_do_not_refresh_the_heartbeat() {
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config(Duration::from_secs(30)),
        Arc::clone(&venue_app),
    );
    // The acceptor honours the 1 s HeartBtInt the Logon asks for.
    let (mut framed, connection) = establish(acceptor, 1).await;

    let client = tokio::spawn(async move {
        let mut saw_test_request = false;
        let mut seq = 2u64;
        let mut pace = tokio::time::interval(Duration::from_millis(200));
        let deadline = tokio::time::sleep(Duration::from_secs(10));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = pace.tick() => {
                    let garbled = with_wrong_checksum(&client_msg("0", seq, &[]));
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
                timeout(Duration::from_secs(15), client).await,
                "client done within 15s",
            ),
            "client task",
        ),
        "the acceptor should have probed with a TestRequest"
    );
}

/// A Logon that never arrives intact ends the acceptor handshake in
/// LogonTimeout after `logon_timeout`, not in an immediate codec or decode
/// error: both kinds of garbled Logon are ignored.
#[tokio::test]
async fn test_acceptor_garbled_only_logon_ends_in_logon_timeout() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let config =
        venue_config(Duration::from_secs(30)).with_logon_timeout(Duration::from_millis(300));
    let acceptor = Acceptor::new(config, Arc::clone(&venue_app));
    let venue = tokio::spawn(async move { acceptor.accept(&listener).await });

    let stream = ok(TcpStream::connect(addr).await, "client connects");
    let mut framed = Framed::new(stream, FixCodec::new());
    let mut burst = with_wrong_checksum(&client_msg("A", 1, &[(98, "0"), (108, "30")]));
    burst.extend_from_slice(&logon_with_msg_type_out_of_place());
    ok(framed.send(burst).await, "send garbled Logons only");

    match ok(
        timeout(Duration::from_secs(5), venue).await,
        "venue task finishes within 5s",
    ) {
        Ok(Err(EngineError::LogonTimeout(_))) => {}
        other => panic!("expected LogonTimeout, got {other:?}"),
    }
    assert!(!venue_app.events().contains(&"logon".to_string()));
    drop(framed);
}

/// A frame whose BodyLength is wrong, rather than its CheckSum, is skipped by
/// the acceptor too: no MsgSeqNum consumed, a ResendRequest for its number,
/// and the session stays Active.
#[tokio::test]
async fn test_acceptor_garbled_body_length_frame_is_skipped_and_its_gap_resent() {
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config(Duration::from_secs(30)),
        Arc::clone(&venue_app),
    );
    let (mut framed, connection) = establish(acceptor, 30).await;

    let mut burst = with_wrong_body_length(&client_msg("1", 2, &[(112, "GARBLED")]));
    burst.extend_from_slice(&client_msg("1", 3, &[(112, "AFTER")]));
    ok(framed.send(burst).await, "send garbled + valid frames");

    let resend = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&resend), "2", "the gap must be requested");
    assert_eq!(field(&resend, 7).as_deref(), Some("2"));
    let reply = next_frame(&mut framed).await;
    assert_eq!(field(&reply, 112).as_deref(), Some("AFTER"));
    assert_eq!(connection.next_target_seq(), 2);
    assert!(!connection.is_closed());

    drop(framed);
    let _ = timeout(Duration::from_secs(5), connection.wait_closed()).await;
}

/// Garbled Logons skipped during the acceptor handshake are not counted
/// toward the limit: with a limit of one the session survives them, keeps
/// answering, and only the first garbled frame of the Active session logs it
/// out.
#[tokio::test]
async fn test_acceptor_garbled_frames_during_the_handshake_do_not_count_toward_the_limit() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let config = venue_config(Duration::from_secs(30))
        .with_garbled_frame_limit(Some(garbled_limit(1, Duration::from_secs(60))));
    let acceptor = Acceptor::new(config, Arc::clone(&venue_app));
    let venue = tokio::spawn(async move { acceptor.accept(&listener).await });

    let stream = ok(TcpStream::connect(addr).await, "client connects");
    let mut framed = Framed::new(stream, FixCodec::new());
    let mut burst = with_wrong_checksum(&client_msg("A", 1, &[(98, "0"), (108, "30")]));
    burst.extend_from_slice(&logon_with_msg_type_out_of_place());
    burst.extend_from_slice(&client_msg("A", 1, &[(98, "0"), (108, "30")]));
    ok(framed.send(burst).await, "send garbled + valid Logon");
    let ack = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&ack), "A");
    let connection = ok(
        ok(
            ok(
                timeout(Duration::from_secs(5), venue).await,
                "handshake within 5s",
            ),
            "venue task joins",
        ),
        "acceptor establishes the session",
    );

    ok(
        framed.send(client_msg("1", 2, &[(112, "ALIVE")])).await,
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
            .send(with_wrong_checksum(&client_msg("0", 3, &[])))
            .await,
        "send one garbled frame in session",
    );
    let logout = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&logout), "5");
    assert!(some(field(&logout, 58), "logout must carry Text").contains("garbled"));
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );
    read_until_closed(&mut framed).await;
}

// ---------------------------------------------------------------------------
// The acceptor's message store
// ---------------------------------------------------------------------------

/// A store that counts every call the engine makes on it and fails on demand.
///
/// `calls` counts every trait call, the counter reads included, so a test can
/// assert that the engine never touched the store at all. A test seeds history
/// through `inner` directly, which is not counted.
#[derive(Debug)]
struct ProbeStore {
    inner: MemoryStore,
    calls: AtomicU64,
    fail_refresh: AtomicBool,
    fail_store: AtomicBool,
    fail_reset: AtomicBool,
    hold_reset: AtomicBool,
    stall_target: AtomicBool,
}

impl ProbeStore {
    fn new() -> Self {
        Self {
            inner: MemoryStore::new(),
            calls: AtomicU64::new(0),
            fail_refresh: AtomicBool::new(false),
            fail_store: AtomicBool::new(false),
            fail_reset: AtomicBool::new(false),
            hold_reset: AtomicBool::new(false),
            stall_target: AtomicBool::new(false),
        }
    }

    fn touched(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }

    fn count(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl MessageStore for ProbeStore {
    async fn store(
        &self,
        seq_num: u64,
        msg_type: &MsgType,
        message: &[u8],
    ) -> Result<(), StoreError> {
        self.count();
        if self.fail_store.load(Ordering::SeqCst) {
            return Err(StoreError::Io(
                "store refused by the test store".to_string(),
            ));
        }
        self.inner.store(seq_num, msg_type, message).await
    }

    async fn get_range(&self, begin: u64, end: u64) -> Result<Vec<StoredMessage>, StoreError> {
        self.count();
        self.inner.get_range(begin, end).await
    }

    fn next_sender_seq(&self) -> u64 {
        self.count();
        self.inner.next_sender_seq()
    }

    fn next_target_seq(&self) -> u64 {
        self.count();
        self.inner.next_target_seq()
    }

    async fn set_next_sender_seq(&self, seq: u64) -> Result<(), StoreError> {
        self.count();
        self.inner.set_next_sender_seq(seq).await
    }

    async fn set_next_target_seq(&self, seq: u64) -> Result<(), StoreError> {
        self.count();
        if self.stall_target.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        self.inner.set_next_target_seq(seq).await
    }

    async fn reset(&self) -> Result<(), StoreError> {
        self.count();
        if self.hold_reset.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        if self.fail_reset.load(Ordering::SeqCst) {
            return Err(StoreError::Io(
                "reset refused by the test store".to_string(),
            ));
        }
        self.inner.reset().await
    }

    fn creation_time(&self) -> std::time::SystemTime {
        self.count();
        self.inner.creation_time()
    }

    async fn refresh(&self) -> Result<(), StoreError> {
        self.count();
        if self.fail_refresh.load(Ordering::SeqCst) {
            return Err(StoreError::Io(
                "refresh refused by the test store".to_string(),
            ));
        }
        Ok(())
    }
}

/// Logs a stub initiator on to a shared `acceptor` with a Logon numbered `seq`
/// that also carries `extra`, and returns the stub's socket, the acceptor's
/// connection and the acknowledgement it received.
async fn establish_shared(
    acceptor: &Arc<Acceptor<RecordingApp>>,
    seq: u64,
    extra: &[(u32, &str)],
) -> (Framed<TcpStream, FixCodec>, Connection, BytesMut) {
    let (listener, addr) = bind_listener().await;
    let shared = Arc::clone(acceptor);
    let venue = tokio::spawn(async move { shared.accept(&listener).await });

    let stream = ok(TcpStream::connect(addr).await, "client connects");
    let mut framed = Framed::new(stream, FixCodec::new());
    let mut fields = vec![(98, "0"), (108, "30")];
    fields.extend_from_slice(extra);
    ok(
        framed.send(client_msg("A", seq, &fields)).await,
        "client sends its logon",
    );
    let ack = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&ack), "A");

    let connection = ok(
        ok(
            ok(
                timeout(Duration::from_secs(5), venue).await,
                "handshake within 5s",
            ),
            "venue task joins",
        ),
        "acceptor establishes the session",
    );
    (framed, connection, ack)
}

/// Sends `count` execution reports from the acceptor, numbered from `first`
/// in their `ExecID` (17).
async fn send_reports(connection: &Connection, first: usize, count: usize) {
    for index in first..first + count {
        let mut exec = OutboundMessage::new(MsgType::ExecutionReport);
        exec.push_str(37, &format!("EX-{index}"))
            .push_str(17, &format!("E-{index}"))
            .push_char(150, '0')
            .push_char(39, '0');
        ok(connection.send(exec).await, "venue sends a report");
    }
}

/// Runs a first session on `acceptor`: Logon 1 and its ack 1, one report at 2,
/// then a Logout from the stub (2) answered by the acceptor (3). The store then
/// holds frames 1 to 3, next sender 4 and next target 3.
async fn run_first_session(acceptor: &Arc<Acceptor<RecordingApp>>) {
    let (mut framed, connection, ack) = establish_shared(acceptor, 1, &[]).await;
    assert_eq!(field(&ack, 34).as_deref(), Some("1"));
    send_reports(&connection, 1, 1).await;
    let report = next_frame(&mut framed).await;
    assert_eq!(field(&report, 34).as_deref(), Some("2"));
    ok(
        framed.send(client_msg("5", 2, &[])).await,
        "client logs out",
    );
    let reply = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&reply), "5");
    assert_eq!(field(&reply, 34).as_deref(), Some("3"));
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "the first session closes within 5s",
    );
}

/// With a store, the acceptor answers a `ResendRequest` for a sub-range by
/// replaying the application messages under their original `MsgSeqNum`, with
/// `PossDupFlag` (43) = Y and `OrigSendingTime` (122) equal to the original
/// `SendingTime` (52), and gap-fills the administrative message in the range.
#[tokio::test]
async fn test_acceptor_with_store_replays_a_resend_sub_range() {
    let store = Arc::new(MemoryStore::new());
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config(Duration::from_secs(30)),
        Arc::clone(&venue_app),
    )
    .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let (mut framed, connection) = establish(acceptor, 30).await;

    // Reports at 2 and 3, a Heartbeat answering a TestRequest at 4, reports at
    // 5 and 6. The stub keeps what it first received, by MsgSeqNum.
    let mut originals = std::collections::HashMap::new();
    send_reports(&connection, 1, 2).await;
    for _ in 0..2 {
        let frame = next_frame(&mut framed).await;
        originals.insert(field(&frame, 34), (field(&frame, 52), field(&frame, 17)));
    }
    ok(
        framed.send(client_msg("1", 2, &[(112, "PING")])).await,
        "send TestRequest",
    );
    let heartbeat = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&heartbeat), "0");
    assert_eq!(field(&heartbeat, 34).as_deref(), Some("4"));
    send_reports(&connection, 3, 2).await;
    for _ in 0..2 {
        let frame = next_frame(&mut framed).await;
        originals.insert(field(&frame, 34), (field(&frame, 52), field(&frame, 17)));
    }

    ok(
        framed
            .send(client_msg("2", 3, &[(7, "3"), (16, "5")]))
            .await,
        "send ResendRequest for 3..=5",
    );

    for seq in ["3", "5"] {
        if seq == "5" {
            let fill = next_frame(&mut framed).await;
            assert_eq!(msg_type_of(&fill), "4", "the Heartbeat at 4 is gap-filled");
            assert_eq!(field(&fill, 34).as_deref(), Some("4"));
            assert_eq!(field(&fill, 123).as_deref(), Some("Y"));
            assert_eq!(field(&fill, 36).as_deref(), Some("5"));
        }
        let replay = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&replay), "8");
        assert_eq!(field(&replay, 34).as_deref(), Some(seq));
        assert_eq!(field(&replay, 43).as_deref(), Some("Y"));
        let (sending_time, exec_id) = some(
            originals.get(&Some(seq.to_string())),
            "the replayed number was sent before",
        );
        assert_eq!(
            &field(&replay, 122),
            sending_time,
            "OrigSendingTime is the original 52"
        );
        assert_eq!(
            &field(&replay, 17),
            exec_id,
            "the replay carries the original body"
        );
    }
    assert!(store.contains(6));
}

/// The same store reused across two accepted connections continues the
/// numbering when neither side sets `ResetSeqNumFlag` (141): the second
/// session's ack follows the first session's last frame.
#[tokio::test]
async fn test_acceptor_store_continues_numbering_across_connections() {
    let store = Arc::new(MemoryStore::new());
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(
            venue_config(Duration::from_secs(30)),
            Arc::clone(&venue_app),
        )
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );
    run_first_session(&acceptor).await;
    assert_eq!(store.next_sender_seq(), 4);
    assert_eq!(store.next_target_seq(), 3);

    // The stub's own stream continues at 3.
    let (_framed, _connection, ack) = establish_shared(&acceptor, 3, &[]).await;
    assert_eq!(
        field(&ack, 34).as_deref(),
        Some("4"),
        "numbered from the store"
    );
    assert_eq!(field(&ack, 141), None);
    assert_eq!(
        store.next_target_seq(),
        4,
        "the Logon at 3 is in the cursor"
    );
    assert!(
        store.contains(2),
        "the first session's frames are still filed"
    );
}

/// A `ResetSeqNumFlag` (141) Logon restarts both counters at 1, and the store
/// is reset before the acknowledgement is filed: afterwards it holds the new
/// ack alone, at 1.
#[tokio::test]
async fn test_acceptor_reset_logon_clears_the_store_before_the_ack_is_filed() {
    let store = Arc::new(MemoryStore::new());
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(
            venue_config(Duration::from_secs(30)),
            Arc::clone(&venue_app),
        )
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );
    run_first_session(&acceptor).await;

    let (_framed, _connection, ack) = establish_shared(&acceptor, 1, &[(141, "Y")]).await;
    assert_eq!(field(&ack, 34).as_deref(), Some("1"));
    assert_eq!(field(&ack, 141).as_deref(), Some("Y"));
    assert_eq!(
        store.message_count(),
        1,
        "the previous stream is gone and the new ack is filed"
    );
    let filed = ok(store.get_range(1, 1).await, "read the filed ack");
    assert_eq!(
        filed.first().map(|message| message.msg_type().clone()),
        Some(MsgType::Logon)
    );
    assert_eq!(store.next_sender_seq(), 2);
    assert_eq!(store.next_target_seq(), 2);
}

/// A store that cannot be refreshed makes `serve` fail with
/// `EngineError::Store` before the session goes Active: `on_logon` never runs
/// and nothing is written to the peer.
#[tokio::test]
async fn test_acceptor_failing_store_refresh_fails_serve() {
    let (listener, addr) = bind_listener().await;
    let store = Arc::new(ProbeStore::new());
    store.fail_refresh.store(true, Ordering::SeqCst);
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config(Duration::from_secs(30)),
        Arc::clone(&venue_app),
    )
    .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let venue = tokio::spawn(async move { acceptor.accept(&listener).await });

    let stream = ok(TcpStream::connect(addr).await, "client connects");
    let mut framed = Framed::new(stream, FixCodec::new());
    send_client_logon(&mut framed).await;

    match ok(
        timeout(Duration::from_secs(5), venue).await,
        "venue task finishes within 5s",
    ) {
        Ok(Err(EngineError::Store(_))) => {}
        other => panic!("expected a store error, got {other:?}"),
    }
    assert!(
        timeout(Duration::from_secs(5), framed.next())
            .await
            .ok()
            .flatten()
            .is_none(),
        "no frame reaches the peer"
    );
    assert!(!venue_app.events().contains(&"logon".to_string()));
}

/// `EngineBuilder::with_store` reaches both roles: the initiator files its
/// Logon and its order, the acceptor its acknowledgement.
#[tokio::test]
async fn test_engine_builder_store_files_frames_in_both_roles() {
    let (listener, addr) = bind_listener().await;
    let venue_store = Arc::new(MemoryStore::new());
    let client_store = Arc::new(MemoryStore::new());

    let acceptor = ok(
        EngineBuilder::new()
            .add_session(venue_config(Duration::from_secs(30)))
            .with_store(Arc::clone(&venue_store) as Arc<dyn MessageStore>)
            .into_acceptor(),
        "build the acceptor",
    );
    let initiator = ok(
        EngineBuilder::new()
            .add_session(client_config(Duration::from_secs(30)))
            .with_store(Arc::clone(&client_store) as Arc<dyn MessageStore>)
            .into_initiator(),
        "build the initiator",
    );

    let venue = tokio::spawn(async move { acceptor.accept(&listener).await });
    let client = ok(initiator.connect(addr).await, "client connects and logs on");
    let venue_connection = ok(
        ok(
            ok(
                timeout(Duration::from_secs(5), venue).await,
                "handshake within 5s",
            ),
            "venue task joins",
        ),
        "acceptor establishes the session",
    );

    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order.push_str(11, "ORDER-1");
    ok(client.send(order).await, "client sends an order");
    let filed = timeout(Duration::from_secs(5), async {
        while !client_store.contains(2) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    ok(filed, "the order is filed within 5s");

    assert!(client_store.contains(1), "the initiator filed its Logon");
    assert!(venue_store.contains(1), "the acceptor filed its ack");
    drop(venue_connection);
}

/// A Logon whose CompIDs are not the configured counterparty's never touches
/// the store, and with a store attached it is refused without a reply.
#[tokio::test]
async fn test_acceptor_identity_refusal_never_touches_the_store() {
    let (listener, addr) = bind_listener().await;
    let store = Arc::new(ProbeStore::new());
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config(Duration::from_secs(30)),
        Arc::clone(&venue_app),
    )
    .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let venue = tokio::spawn(async move { acceptor.accept(&listener).await });

    let stream = ok(TcpStream::connect(addr).await, "stranger connects");
    let mut framed = Framed::new(stream, FixCodec::new());
    let mut encoder = Encoder::new("FIX.4.4");
    encoder.put_str(35, "A");
    encoder.put_str(49, "STRANGER");
    encoder.put_str(56, "VENUE");
    encoder.put_uint(34, 1);
    encoder.put_str(52, Timestamp::now().format_millis().as_str());
    encoder.put_uint(98, 0);
    encoder.put_uint(108, 30);
    encoder.put_str(141, "Y");
    let mut logon = BytesMut::new();
    ok(
        encoder.finish_into(&mut logon),
        "stranger logon must encode",
    );
    ok(framed.send(logon).await, "stranger sends its logon");

    match ok(
        timeout(Duration::from_secs(5), venue).await,
        "venue task finishes within 5s",
    ) {
        Ok(Err(EngineError::IdentityMismatch { .. })) => {}
        other => panic!("expected IdentityMismatch, got {other:?}"),
    }
    assert!(
        timeout(Duration::from_secs(5), framed.next())
            .await
            .ok()
            .flatten()
            .is_none(),
        "no Reject and no Logout with a store attached"
    );
    assert_eq!(store.touched(), 0, "the store was never touched");
}

/// An application that refuses every Logon in `from_admin`.
#[derive(Debug)]
struct RefusingApp;

#[async_trait]
impl Application for RefusingApp {
    async fn on_create(&self, _session_id: &SessionId) {}

    async fn on_logon(&self, _session_id: &SessionId) {}

    async fn on_logout(&self, _session_id: &SessionId) {}

    async fn to_admin(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_admin(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Err(RejectReason::new(99, "bad credentials"))
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

/// Files three frames of a previous stream in `store` and moves its counters
/// past them: next sender 4, next target 3.
async fn seed_history(store: &MemoryStore) {
    for seq in 1..=3u64 {
        let frame = client_msg("8", seq, &[(17, "OLD")]);
        ok(
            store.store(seq, &MsgType::ExecutionReport, &frame).await,
            "seed the journal",
        );
    }
    ok(
        store.set_next_sender_seq(4).await,
        "seed the sender counter",
    );
    ok(
        store.set_next_target_seq(3).await,
        "seed the target counter",
    );
}

/// Sends `logon` to `acceptor` from a stub initiator, and returns what the
/// acceptor's `accept` returned and every frame the stub received before the
/// acceptor hung up, as (MsgType, MsgSeqNum, Text) triples.
async fn refused_logon<A: Application + 'static>(
    acceptor: Arc<Acceptor<A>>,
    logon: BytesMut,
) -> (
    Result<Connection, EngineError>,
    Vec<(String, Option<String>, Option<String>)>,
) {
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move { acceptor.accept(&listener).await });
    let stream = ok(TcpStream::connect(addr).await, "client connects");
    let mut framed = Framed::new(stream, FixCodec::new());
    ok(framed.send(logon).await, "client sends its logon");
    let result = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue task finishes within 5s",
        ),
        "venue task joins",
    );
    let mut frames = Vec::new();
    while let Ok(Some(Ok(frame))) = timeout(Duration::from_secs(2), framed.next()).await {
        frames.push((msg_type_of(&frame), field(&frame, 34), field(&frame, 58)));
    }
    (result, frames)
}

/// A store-backed acceptor with a previous stream filed (next sender 4, next
/// target 3), and the store.
async fn acceptor_with_history<A: Application + 'static>(
    application: Arc<A>,
) -> (Arc<Acceptor<A>>, Arc<ProbeStore>) {
    let store = Arc::new(ProbeStore::new());
    seed_history(&store.inner).await;
    let acceptor = Arc::new(
        Acceptor::new(venue_config(Duration::from_secs(30)), application)
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );
    (acceptor, store)
}

/// The previous stream survived a refused Logon: frames 1 to 3 are still
/// filed.
#[track_caller]
fn assert_history_kept(store: &ProbeStore) {
    for seq in 1..=3u64 {
        assert!(
            store.inner.contains(seq),
            "the refused Logon must not reset the store (frame {seq})"
        );
    }
}

/// Matching CompIDs authenticate nobody. A Logon that `from_admin` refuses, with
/// a store attached, gets no reply and never touches the store: a peer that
/// knows the CompIDs but not the credentials can neither append to the
/// journal, advance the session's counters, nor (with `ResetSeqNumFlag`)
/// clear it.
#[tokio::test]
async fn test_acceptor_from_admin_refusal_has_no_reply_and_no_store_access() {
    let (acceptor, store) = acceptor_with_history(Arc::new(RefusingApp)).await;
    let (result, frames) = refused_logon(
        acceptor,
        client_msg("A", 1, &[(98, "0"), (108, "30"), (141, "Y")]),
    )
    .await;

    match result {
        Err(EngineError::LogonRejected { reason }) => assert_eq!(reason, "bad credentials"),
        other => panic!("expected LogonRejected, got {other:?}"),
    }
    assert!(frames.is_empty(), "no reply: {frames:?}");
    assert_eq!(store.touched(), 0, "the store was never touched");
    assert_history_kept(&store);
    assert_eq!(
        store.inner.next_sender_seq(),
        4,
        "the counters did not move"
    );
}

/// Without a store there is no journal to protect, and a Logon that
/// `from_admin` refuses still gets a Logout with the refusal's text.
#[tokio::test]
async fn test_acceptor_from_admin_refusal_without_a_store_gets_a_logout() {
    let acceptor = Arc::new(Acceptor::new(
        venue_config(Duration::from_secs(30)),
        Arc::new(RefusingApp),
    ));
    let (result, frames) =
        refused_logon(acceptor, client_msg("A", 1, &[(98, "0"), (108, "30")])).await;

    assert!(
        matches!(result, Err(EngineError::LogonRejected { .. })),
        "expected LogonRejected, got {result:?}"
    );
    assert_eq!(
        frames,
        vec![(
            "5".to_string(),
            Some("1".to_string()),
            Some("bad credentials".to_string())
        )]
    );
}

/// A Logon whose `SendingTime` (52) is out of tolerance is refused before the
/// peer is authenticated: with a store attached it gets no reply and the store
/// is not touched.
#[tokio::test]
async fn test_acceptor_sending_time_refusal_has_no_reply_and_no_store_access() {
    let (venue_app, _venue_rx) = RecordingApp::new();
    let (acceptor, store) = acceptor_with_history(venue_app).await;

    let mut encoder = Encoder::new("FIX.4.4");
    encoder.put_str(35, "A");
    encoder.put_str(49, "CLIENT");
    encoder.put_str(56, "VENUE");
    encoder.put_uint(34, 3);
    encoder.put_str(52, "20200101-00:00:00.000");
    encoder.put_uint(98, 0);
    encoder.put_uint(108, 30);
    let mut logon = BytesMut::new();
    ok(encoder.finish_into(&mut logon), "stale logon must encode");

    let (result, frames) = refused_logon(acceptor, logon).await;
    assert!(
        matches!(result, Err(EngineError::SendingTime { .. })),
        "expected a SendingTime error, got {result:?}"
    );
    assert!(frames.is_empty(), "no reply: {frames:?}");
    assert_eq!(store.touched(), 0, "the store was never touched");
    assert_history_kept(&store);
}

/// A `HeartBtInt` (108) that cannot be honoured is refused after
/// authentication with a filed Logout numbered from the store, and a
/// `ResetSeqNumFlag` (141) on that Logon does not reset the store.
#[tokio::test]
async fn test_acceptor_heartbeat_refusal_is_filed_and_never_resets() {
    let (venue_app, _venue_rx) = RecordingApp::new();
    let (acceptor, store) = acceptor_with_history(venue_app).await;
    let (result, frames) = refused_logon(
        acceptor,
        client_msg("A", 1, &[(98, "0"), (108, "abc"), (141, "Y")]),
    )
    .await;

    assert!(
        matches!(result, Err(EngineError::LogonRejected { .. })),
        "expected LogonRejected, got {result:?}"
    );
    assert_eq!(frames.len(), 1, "one Logout: {frames:?}");
    assert_eq!(frames[0].0, "5");
    assert_eq!(frames[0].1.as_deref(), Some("4"));
    assert!(store.inner.contains(4), "the Logout is filed");
    assert_history_kept(&store);
}

/// A Logon numbered below what the store expects is refused with a Logout
/// numbered from the store and filed.
#[tokio::test]
async fn test_acceptor_too_low_logon_refusal_is_filed() {
    let (venue_app, _venue_rx) = RecordingApp::new();
    let (acceptor, store) = acceptor_with_history(venue_app).await;
    let (result, frames) =
        refused_logon(acceptor, client_msg("A", 2, &[(98, "0"), (108, "30")])).await;

    assert!(
        matches!(result, Err(EngineError::Sequence(ref detail)) if detail.contains("too low")),
        "expected a too-low Sequence error, got {result:?}"
    );
    assert_eq!(frames.len(), 1, "one Logout: {frames:?}");
    assert_eq!(frames[0].0, "5");
    assert_eq!(frames[0].1.as_deref(), Some("4"));
    assert!(store.inner.contains(4), "the Logout is filed");
    assert_eq!(store.inner.next_sender_seq(), 5);
    assert_eq!(
        store.inner.next_target_seq(),
        3,
        "the refused Logon is not consumed"
    );
}

/// A `ResetSeqNumFlag` (141) Logon not numbered 1 is refused with a filed
/// Logout that says why, and does not reset the store.
#[tokio::test]
async fn test_acceptor_reset_logon_not_numbered_one_is_refused_and_filed() {
    let (venue_app, _venue_rx) = RecordingApp::new();
    let (acceptor, store) = acceptor_with_history(venue_app).await;
    let (result, frames) = refused_logon(
        acceptor,
        client_msg("A", 5, &[(98, "0"), (108, "30"), (141, "Y")]),
    )
    .await;

    assert!(
        matches!(result, Err(EngineError::Sequence(_))),
        "expected a Sequence error, got {result:?}"
    );
    assert_eq!(frames.len(), 1, "one Logout: {frames:?}");
    assert_eq!(frames[0].0, "5");
    assert_eq!(frames[0].1.as_deref(), Some("4"));
    assert!(
        frames[0]
            .2
            .as_deref()
            .is_some_and(|text| text.contains("ResetSeqNumFlag")),
        "the Logout says why: {frames:?}"
    );
    assert_history_kept(&store);
}

/// A zero sender seed that would be used is refused once the Logon is
/// authenticated, instead of being raised to 1, and nothing is sent.
#[tokio::test]
async fn test_acceptor_refuses_a_zero_initial_seed() {
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(
            venue_config(Duration::from_secs(30)),
            Arc::clone(&venue_app),
        )
        .with_initial_sequences(0, 1),
    );
    let (result, frames) =
        refused_logon(acceptor, client_msg("A", 1, &[(98, "0"), (108, "30")])).await;

    assert!(
        matches!(
            result,
            Err(EngineError::InvalidInitialSequence {
                counter: SequenceCounter::Sender
            })
        ),
        "expected InvalidInitialSequence, got {result:?}"
    );
    assert!(frames.is_empty(), "nothing is sent: {frames:?}");
    assert!(!venue_app.events().contains(&"logon".to_string()));
}

/// The reset rule both roles share: after a reset the acceptor drives
/// (`reset_on_logon`), the peer's Logon is its message 1 whatever its
/// `MsgSeqNum`. A Logon at 5 without `ResetSeqNumFlag` gets an ack at 1 with
/// `141=Y`, no `ResendRequest` follows it for the old stream's numbers, and
/// the peer's next message, at 2, is accepted.
#[tokio::test]
async fn test_acceptor_driven_reset_takes_the_logon_as_message_one() {
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Arc::new(Acceptor::new(
        venue_config(Duration::from_secs(30)).with_reset_on_logon(true),
        Arc::clone(&venue_app),
    ));
    let (mut framed, connection, ack) = establish_shared(&acceptor, 5, &[]).await;
    assert_eq!(field(&ack, 34).as_deref(), Some("1"));
    assert_eq!(field(&ack, 141).as_deref(), Some("Y"));
    assert_eq!(connection.next_target_seq(), 2);

    // Past the ack: nothing, in particular no ResendRequest for 1..5.
    assert!(
        timeout(Duration::from_millis(500), framed.next())
            .await
            .is_err(),
        "no frame follows the ack"
    );

    // The peer, having reset as the ack told it to, continues at 2.
    ok(
        framed
            .send(client_msg("1", 2, &[(112, "AFTER-RESET")]))
            .await,
        "send TestRequest",
    );
    let heartbeat = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&heartbeat), "0");
    assert_eq!(field(&heartbeat, 34).as_deref(), Some("2"));
    assert_eq!(field(&heartbeat, 112).as_deref(), Some("AFTER-RESET"));
    assert!(!connection.is_closed());
    assert_eq!(connection.next_target_seq(), 3);
}

/// A second concurrent Logon for a live session is refused without touching
/// the store the live session is writing to, and the live session is
/// unaffected.
#[tokio::test]
async fn test_acceptor_duplicate_logon_never_touches_the_store() {
    let store = Arc::new(ProbeStore::new());
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(
            venue_config(Duration::from_secs(30)),
            Arc::clone(&venue_app),
        )
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );
    let (_framed, live, _ack) = establish_shared(&acceptor, 1, &[]).await;
    // Let the live session's reactor finish its first pass.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let before = store.touched();

    let (listener, addr) = bind_listener().await;
    let shared = Arc::clone(&acceptor);
    let venue = tokio::spawn(async move { shared.accept(&listener).await });
    let stream = ok(TcpStream::connect(addr).await, "second client connects");
    let mut framed = Framed::new(stream, FixCodec::new());
    send_client_logon(&mut framed).await;

    match ok(
        timeout(Duration::from_secs(5), venue).await,
        "venue task finishes within 5s",
    ) {
        Ok(Err(EngineError::LogonRejected { reason })) => {
            assert!(reason.contains("already active"), "got {reason}");
        }
        other => panic!("expected LogonRejected, got {other:?}"),
    }
    assert!(
        timeout(Duration::from_secs(5), framed.next())
            .await
            .ok()
            .flatten()
            .is_none(),
        "no Logout with a store attached"
    );
    assert_eq!(
        store.touched(),
        before,
        "the refusal did not touch the store"
    );
    assert!(!live.is_closed(), "the live session is unaffected");
}

/// Under `CloseSession`, a frame the acceptor's store refuses is never
/// written and the session closes, without a Logout.
#[tokio::test]
async fn test_acceptor_close_session_closes_on_a_store_failure() {
    let store = Arc::new(ProbeStore::new());
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config(Duration::from_secs(30)),
        Arc::clone(&venue_app),
    )
    .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
    .with_store_failure_policy(StoreFailurePolicy::CloseSession);
    let (mut framed, connection) = establish(acceptor, 30).await;

    store.fail_store.store(true, Ordering::SeqCst);
    send_reports(&connection, 1, 1).await;
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );

    let mut seen = Vec::new();
    while let Ok(Some(Ok(frame))) = timeout(Duration::from_secs(5), framed.next()).await {
        seen.push(msg_type_of(&frame));
    }
    assert!(
        !seen
            .iter()
            .any(|msg_type| msg_type == "8" || msg_type == "5"),
        "neither the report nor a Logout is written: {seen:?}"
    );
    assert!(!store.inner.contains(2));
    assert!(venue_app.events().contains(&"logout".to_string()));
}

/// A store call that overruns the acceptor's store timeout is a failed write:
/// under `CloseSession` the TestRequest whose number could not be persisted
/// gets no Heartbeat, and the session closes.
#[tokio::test]
async fn test_acceptor_store_timeout_is_a_failed_write() {
    let store = Arc::new(ProbeStore::new());
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config(Duration::from_secs(30)),
        Arc::clone(&venue_app),
    )
    .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
    .with_store_failure_policy(StoreFailurePolicy::CloseSession)
    .with_store_timeout(Duration::from_millis(200));
    let (mut framed, connection) = establish(acceptor, 30).await;

    store.stall_target.store(true, Ordering::SeqCst);
    ok(
        framed.send(client_msg("1", 2, &[(112, "PING")])).await,
        "send TestRequest",
    );
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "closed within 5s",
    );
    let mut seen = Vec::new();
    while let Ok(Some(Ok(frame))) = timeout(Duration::from_secs(5), framed.next()).await {
        seen.push(msg_type_of(&frame));
    }
    assert!(
        !seen.iter().any(|msg_type| msg_type == "0"),
        "the TestRequest is not answered: {seen:?}"
    );
}

/// An unusable configuration is refused before a connection is taken off the
/// listener, as the initiator refuses it before dialling: `accept` returns at
/// once, with nobody connected.
#[tokio::test]
async fn test_acceptor_refuses_an_invalid_configuration() {
    let (listener, _addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    // A fractional HeartBtInt has no wire form.
    let acceptor = Acceptor::new(
        venue_config(Duration::from_millis(1500)),
        Arc::clone(&venue_app),
    );

    match ok(
        timeout(Duration::from_secs(1), acceptor.accept(&listener)).await,
        "accept refuses without waiting for a connection",
    ) {
        Err(EngineError::Config(_)) => {}
        other => panic!("expected a configuration error, got {other:?}"),
    }
    assert!(!venue_app.events().contains(&"create".to_string()));
}

/// When the acceptor's close-time reset of `reset_on_disconnect` fails, the
/// reset is owed: the next authenticated Logon fails `serve` while the store
/// still cannot be reset, and once it can, the session restarts at 1 and the
/// acknowledgement declares `ResetSeqNumFlag` (141) = Y, though the peer's
/// Logon did not ask for it.
#[tokio::test]
async fn test_acceptor_failed_close_time_reset_is_owed_to_the_next_logon() {
    let store = Arc::new(ProbeStore::new());
    let (venue_app, _venue_rx) = RecordingApp::new();
    let mut config = venue_config(Duration::from_secs(30));
    config.reset_on_disconnect = true;
    let acceptor = Arc::new(
        Acceptor::new(config, Arc::clone(&venue_app))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );

    // First session: the store breaks, then the peer drops the connection.
    let (framed, connection, _ack) = establish_shared(&acceptor, 1, &[]).await;
    store.fail_reset.store(true, Ordering::SeqCst);
    drop(framed);
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "the first session closes within 5s",
    );
    assert!(
        store.inner.contains(1),
        "the failed reset left the ack filed"
    );

    // Second Logon, while the store still cannot be reset: refused.
    let (listener, addr) = bind_listener().await;
    let shared = Arc::clone(&acceptor);
    let venue = tokio::spawn(async move { shared.accept(&listener).await });
    let stream = ok(TcpStream::connect(addr).await, "client reconnects");
    let mut refused = Framed::new(stream, FixCodec::new());
    ok(
        refused
            .send(client_msg("A", 2, &[(98, "0"), (108, "30")]))
            .await,
        "client sends its logon",
    );
    match ok(
        timeout(Duration::from_secs(5), venue).await,
        "venue task finishes within 5s",
    ) {
        Ok(Err(EngineError::Store(_))) => {}
        other => panic!("expected a store error, got {other:?}"),
    }

    // Third Logon, with a working store: the owed reset is made.
    store.fail_reset.store(false, Ordering::SeqCst);
    let (_framed, _connection, ack) = establish_shared(&acceptor, 2, &[]).await;
    assert_eq!(field(&ack, 34).as_deref(), Some("1"));
    assert_eq!(field(&ack, 141).as_deref(), Some("Y"));
}

/// A `serve` dropped while the reset for a `ResetSeqNumFlag` (141) Logon is
/// still pending leaves the reset owed: the next accepted Logon, which does not
/// ask for one, still gets the store reset and an acknowledgement at 1 that
/// declares it.
#[tokio::test]
async fn test_acceptor_serve_dropped_during_the_reset_leaves_it_owed() {
    let store = Arc::new(ProbeStore::new());
    seed_history(&store.inner).await;
    store.hold_reset.store(true, Ordering::SeqCst);
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(
            venue_config(Duration::from_secs(30)),
            Arc::clone(&venue_app),
        )
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );

    // First Logon asks for a reset; the caller drops `accept` while the store
    // reset hangs.
    let (listener, addr) = bind_listener().await;
    let stream = ok(TcpStream::connect(addr).await, "client connects");
    let mut framed = Framed::new(stream, FixCodec::new());
    ok(
        framed
            .send(client_msg("A", 1, &[(98, "0"), (108, "30"), (141, "Y")]))
            .await,
        "client sends a resetting logon",
    );
    assert!(
        timeout(Duration::from_millis(500), acceptor.accept(&listener))
            .await
            .is_err(),
        "accept must still be inside the store reset"
    );
    drop(framed);
    assert!(store.inner.contains(1), "the held reset changed nothing");
    store.hold_reset.store(false, Ordering::SeqCst);

    // Second Logon continues the peer's old stream without asking for a reset:
    // the reset is still owed, so it is made and declared.
    let (_framed, _connection, ack) = establish_shared(&acceptor, 3, &[]).await;
    assert_eq!(field(&ack, 34).as_deref(), Some("1"));
    assert_eq!(field(&ack, 141).as_deref(), Some("Y"));
    assert!(!store.inner.contains(3), "the previous stream is gone");
}

/// A store write that overruns the acceptor's store timeout may still land
/// later, so it leaves a reset owed: the next accepted Logon gets the store
/// reset and an acknowledgement at 1 that declares it.
#[tokio::test]
async fn test_acceptor_timed_out_store_write_leaves_a_reset_owed() {
    let store = Arc::new(ProbeStore::new());
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(
            venue_config(Duration::from_secs(30)),
            Arc::clone(&venue_app),
        )
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
        .with_store_timeout(Duration::from_millis(200)),
    );

    let (mut framed, connection, _ack) = establish_shared(&acceptor, 1, &[]).await;
    store.stall_target.store(true, Ordering::SeqCst);
    ok(
        framed.send(client_msg("1", 2, &[(112, "PING")])).await,
        "send TestRequest",
    );
    // Continue: answered once the overrun has been logged.
    let heartbeat = next_frame(&mut framed).await;
    assert_eq!(field(&heartbeat, 112).as_deref(), Some("PING"));
    drop(framed);
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "the first session closes within 5s",
    );
    store.stall_target.store(false, Ordering::SeqCst);

    let (_framed, _connection, ack) = establish_shared(&acceptor, 3, &[]).await;
    assert_eq!(field(&ack, 34).as_deref(), Some("1"), "a new stream starts");
    assert_eq!(field(&ack, 141).as_deref(), Some("Y"), "and is declared");
}

/// A Logon numbered 0 names no message. With a reset the acceptor drives
/// (`reset_on_logon`), it must not slip through the reset rule, which takes a
/// positive old-stream number as message 1: it is refused like a missing
/// `MsgSeqNum`, without a reply and before the store is touched.
#[tokio::test]
async fn test_acceptor_refuses_a_logon_numbered_zero_before_any_reset() {
    let store = Arc::new(ProbeStore::new());
    seed_history(&store.inner).await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(
            venue_config(Duration::from_secs(30)).with_reset_on_logon(true),
            Arc::clone(&venue_app),
        )
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );
    let (result, frames) =
        refused_logon(acceptor, client_msg("A", 0, &[(98, "0"), (108, "30")])).await;

    assert!(
        matches!(result, Err(EngineError::Sequence(_))),
        "expected a Sequence error, got {result:?}"
    );
    assert!(frames.is_empty(), "no reply: {frames:?}");
    assert_eq!(store.touched(), 0, "the store was never touched");
    assert_history_kept(&store);
    assert!(!venue_app.events().contains(&"logon".to_string()));
}

/// Three sessions on one store. The first leaves a reset owed (a store write
/// fails under `Continue`). The second pays it (the store is reset and the
/// acknowledgement declares `ResetSeqNumFlag` (141) at 1), but filing that
/// acknowledgement fails. Paying the reset must not settle the later failure,
/// so the third acknowledgement must again start at 1 and declare a reset.
#[tokio::test]
async fn test_acceptor_ack_filing_failure_still_owes_a_reset_after_one_is_paid() {
    let store = Arc::new(ProbeStore::new());
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(
            venue_config(Duration::from_secs(30)),
            Arc::clone(&venue_app),
        )
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );

    let (mut framed, connection, _ack) = establish_shared(&acceptor, 1, &[]).await;
    store.fail_store.store(true, Ordering::SeqCst);
    send_reports(&connection, 1, 1).await;
    let _report = next_frame(&mut framed).await;
    drop(framed);
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "the first session closes within 5s",
    );
    store.fail_store.store(false, Ordering::SeqCst);

    store.fail_store.store(true, Ordering::SeqCst);
    let (framed, connection, ack) = establish_shared(&acceptor, 2, &[]).await;
    // Off before anything else is written: only the ack's filing failed.
    store.fail_store.store(false, Ordering::SeqCst);
    assert_eq!(
        field(&ack, 34).as_deref(),
        Some("1"),
        "the owed reset is paid"
    );
    assert_eq!(field(&ack, 141).as_deref(), Some("Y"));
    drop(framed);
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "the second session closes within 5s",
    );

    let (_framed, _connection, ack) = establish_shared(&acceptor, 2, &[]).await;
    assert_eq!(
        field(&ack, 34).as_deref(),
        Some("1"),
        "the reset paid in the second session does not settle the filing that failed during it"
    );
    assert_eq!(field(&ack, 141).as_deref(), Some("Y"), "and is declared");
}

/// While a session is live, a second Logon refused for its BeginString gets
/// no reply even without a store, where a refused Logon is otherwise answered
/// with a Logout: that Logout would be numbered from the provisional
/// counters, a stream the live session owns. The live session carries on.
#[tokio::test]
async fn test_acceptor_live_session_answers_no_wrong_version_logon() {
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Arc::new(Acceptor::new(
        venue_config(Duration::from_secs(30)),
        Arc::clone(&venue_app),
    ));
    let (mut live, connection, _ack) = establish_shared(&acceptor, 1, &[]).await;

    let (listener, addr) = bind_listener().await;
    let shared = Arc::clone(&acceptor);
    let venue = tokio::spawn(async move { shared.accept(&listener).await });
    let stream = ok(TcpStream::connect(addr).await, "client connects");
    let mut newcomer = Framed::new(stream, FixCodec::new());
    let mut encoder = Encoder::new("FIX.4.2");
    encoder.put_str(35, "A");
    encoder.put_str(49, "CLIENT");
    encoder.put_str(56, "VENUE");
    encoder.put_uint(34, 1);
    encoder.put_str(52, Timestamp::now().format_millis().as_str());
    encoder.put_uint(98, 0);
    encoder.put_uint(108, 30);
    let mut logon = BytesMut::new();
    ok(encoder.finish_into(&mut logon), "logon must encode");
    ok(newcomer.send(logon).await, "the newcomer logs on");

    assert!(
        timeout(Duration::from_secs(5), newcomer.next())
            .await
            .ok()
            .flatten()
            .is_none(),
        "the newcomer gets no reply"
    );
    match ok(
        timeout(Duration::from_secs(5), venue).await,
        "the refusal within 5s",
    ) {
        Ok(Err(EngineError::LogonRejected { reason })) => {
            assert!(reason.contains("BeginString"), "got {reason}");
        }
        other => panic!("expected a version refusal, got {other:?}"),
    }

    ok(
        live.send(client_msg("1", 2, &[(112, "STILL-THERE")])).await,
        "the live peer sends a TestRequest",
    );
    let heartbeat = next_frame(&mut live).await;
    assert_eq!(msg_type_of(&heartbeat), "0");
    assert_eq!(field(&heartbeat, 112).as_deref(), Some("STILL-THERE"));
    assert!(!connection.is_closed());
}
