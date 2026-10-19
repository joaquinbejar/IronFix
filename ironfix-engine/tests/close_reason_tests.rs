/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 19/10/26
******************************************************************************/

//! Integration tests for the typed close reason (issue #69): every close path
//! a test peer can reach reports the matching [`CloseReason`] to the
//! application and to the [`Connection`], in both roles where it applies;
//! the default `on_session_closed` forwards to `on_logout` only for a session
//! that reached Active; and `Connection::logout_with_text` puts its text in
//! `Text` (58), refusing a text it cannot frame.
//!
//! The counterparty is a scripted peer on the far end of a
//! [`tokio::io::duplex`] pipe, framed with [`FixCodec`].

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::error::StoreError;
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::application::{Application, RejectReason, SessionId};
use ironfix_engine::connection::MAX_LOGOUT_TEXT_LEN;
use ironfix_engine::{
    Acceptor, CloseReason, Connection, EngineError, Initiator, LogoutCause, LogoutInitiator,
    NotSentReason, OutboundMessage, SendOutcome, StoreFailurePolicy,
};
use ironfix_session::{GarbledFrameLimit, SessionConfig};
use ironfix_store::{MemoryStore, MessageStore, StoredMessage};
use ironfix_tagvalue::{Decoder, Encoder};
use ironfix_transport::FixCodec;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::DuplexStream;
use tokio::time::timeout;
use tokio_util::codec::Framed;

/// The scripted peer's end of the pipe.
type Peer = Framed<DuplexStream, FixCodec>;

/// Pipe capacity for every test but the write timeout one.
const PIPE_CAPACITY: usize = 64 * 1024;

/// How long any one step may take before the test fails.
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

#[track_caller]
fn comp_id(value: &str) -> CompId {
    ok(CompId::new(value), "test CompId must be valid")
}

/// The initiator's configuration (CLIENT -> VENUE).
fn client_config() -> SessionConfig {
    SessionConfig::new(comp_id("CLIENT"), comp_id("VENUE"), "FIX.4.4")
        .with_heartbeat_interval(Duration::from_secs(30))
}

/// The acceptor's configuration (VENUE -> CLIENT).
fn venue_config() -> SessionConfig {
    SessionConfig::new(comp_id("VENUE"), comp_id("CLIENT"), "FIX.4.4")
        .with_heartbeat_interval(Duration::from_secs(30))
}

/// A frame from `sender` to `target`.
fn frame(sender: &str, target: &str, msg_type: &str, seq: u64, extra: &[(u32, &str)]) -> BytesMut {
    let mut encoder = Encoder::new("FIX.4.4");
    encoder.put_str(35, msg_type);
    encoder.put_str(49, sender);
    encoder.put_str(56, target);
    encoder.put_uint(34, seq);
    encoder.put_str(52, Timestamp::now().format_millis().as_str());
    for (tag, value) in extra {
        encoder.put_str(*tag, value);
    }
    let mut out = BytesMut::new();
    match encoder.finish_into(&mut out) {
        Ok(()) => out,
        Err(err) => panic!("test frame must encode: {err}"),
    }
}

/// A frame from the venue to the client.
fn venue_msg(msg_type: &str, seq: u64, extra: &[(u32, &str)]) -> BytesMut {
    frame("VENUE", "CLIENT", msg_type, seq, extra)
}

/// A frame from the client to the venue.
fn client_msg(msg_type: &str, seq: u64, extra: &[(u32, &str)]) -> BytesMut {
    frame("CLIENT", "VENUE", msg_type, seq, extra)
}

/// `frame` with its CheckSum off by one: garbled.
fn with_wrong_checksum(frame: &[u8]) -> BytesMut {
    let digits_at = some(frame.len().checked_sub(4), "frame must carry a trailer");
    let (head, trailer) = frame.split_at(digits_at);
    let digits = some(trailer.get(..3), "trailer must carry three digits");
    let text = ok(std::str::from_utf8(digits), "checksum digits are ASCII");
    let declared: u16 = ok(text.parse(), "checksum digits are decimal");
    let mut garbled = BytesMut::from(head);
    garbled.extend_from_slice(format!("{:03}\x01", (declared + 1) % 256).as_bytes());
    garbled
}

/// A field of a frame, as text.
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

/// The next frame the peer reads.
async fn next_frame(peer: &mut Peer) -> BytesMut {
    let polled = ok(timeout(STEP, peer.next()).await, "frame within the step");
    ok(some(polled, "stream must stay open"), "frame must decode")
}

/// The next frame of `msg_type`, skipping others (Heartbeats, typically).
async fn next_of(peer: &mut Peer, msg_type: &str) -> BytesMut {
    loop {
        let frame = next_frame(peer).await;
        if msg_type_of(&frame) == msg_type {
            return frame;
        }
    }
}

/// Sends one frame from the peer.
async fn send(peer: &mut Peer, frame: BytesMut) {
    ok(peer.send(frame).await, "the peer must write");
}

/// Reads and drops everything until the engine closes the pipe.
async fn drain(peer: &mut Peer) {
    while let Ok(Some(Ok(_))) = timeout(STEP, peer.next()).await {}
}

/// Records every callback, and the close reasons it is handed.
#[derive(Debug, Default)]
struct RecordingApp {
    events: Mutex<Vec<String>>,
    reasons: Mutex<Vec<CloseReason>>,
}

impl RecordingApp {
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

    /// The one close reason the application was handed.
    #[track_caller]
    fn reason(&self) -> CloseReason {
        match self.reasons.lock() {
            Ok(reasons) => {
                assert_eq!(reasons.len(), 1, "exactly one close reason: {reasons:?}");
                some(reasons.first().cloned(), "one close reason")
            }
            Err(_) => panic!("reason lock poisoned"),
        }
    }
}

#[async_trait]
impl Application for RecordingApp {
    async fn on_create(&self, _: &SessionId) {
        self.record("create");
    }
    async fn on_logon(&self, _: &SessionId) {
        self.record("logon");
    }
    async fn on_logout(&self, _: &SessionId) {
        self.record("logout");
    }
    async fn on_session_closed(&self, _: &SessionId, reason: &CloseReason) {
        self.record("closed");
        match self.reasons.lock() {
            Ok(mut reasons) => reasons.push(reason.clone()),
            Err(_) => panic!("reason lock poisoned"),
        }
    }
    async fn to_admin(&self, _: &mut OutboundMessage, _: &SessionId) {}
    async fn from_admin(&self, _: &RawMessage<'_>, _: &SessionId) -> Result<(), RejectReason> {
        Ok(())
    }
    async fn to_app(&self, _: &mut OutboundMessage, _: &SessionId) {}
    async fn from_app(&self, _: &RawMessage<'_>, _: &SessionId) -> Result<(), RejectReason> {
        Ok(())
    }
}

/// An application written before `on_session_closed` existed: it relies on
/// the default, which forwards to `on_logout`.
#[derive(Debug, Default)]
struct LegacyApp {
    events: Mutex<Vec<String>>,
}

impl LegacyApp {
    #[track_caller]
    fn events(&self) -> Vec<String> {
        match self.events.lock() {
            Ok(events) => events.clone(),
            Err(_) => panic!("event lock poisoned"),
        }
    }

    #[track_caller]
    fn record(&self, event: &str) {
        match self.events.lock() {
            Ok(mut events) => events.push(event.to_string()),
            Err(_) => panic!("event lock poisoned"),
        }
    }
}

#[async_trait]
impl Application for LegacyApp {
    async fn on_create(&self, _: &SessionId) {
        self.record("create");
    }
    async fn on_logon(&self, _: &SessionId) {
        self.record("logon");
    }
    async fn on_logout(&self, _: &SessionId) {
        self.record("logout");
    }
    async fn to_admin(&self, _: &mut OutboundMessage, _: &SessionId) {}
    async fn from_admin(&self, _: &RawMessage<'_>, _: &SessionId) -> Result<(), RejectReason> {
        Ok(())
    }
    async fn to_app(&self, _: &mut OutboundMessage, _: &SessionId) {}
    async fn from_app(&self, _: &RawMessage<'_>, _: &SessionId) -> Result<(), RejectReason> {
        Ok(())
    }
}

/// A store that refuses to file NewOrderSingle (D), and only that.
#[derive(Debug, Default)]
struct RefusingStore {
    inner: MemoryStore,
}

#[async_trait]
impl MessageStore for RefusingStore {
    async fn store(
        &self,
        seq_num: u64,
        msg_type: &MsgType,
        message: &[u8],
    ) -> Result<(), StoreError> {
        if msg_type.as_str() == "D" {
            return Err(StoreError::StoreFailed {
                seq_num,
                reason: "refused by the test store".to_string(),
            });
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

/// A NewOrderSingle body.
fn order(id: &str) -> OutboundMessage {
    let mut message = OutboundMessage::new(MsgType::NewOrderSingle);
    message
        .push_str(11, id)
        .push_str(55, "EUR/USD")
        .push_str(54, "1")
        .push_str(60, Timestamp::now().format_millis().as_str())
        .push_str(38, "1000")
        .push_str(40, "1");
    message
}

/// Runs the initiator handshake against the scripted venue: the venue acks
/// with `HeartBtInt` (108) `heartbeat_secs`.
async fn initiator_session<A: Application + 'static>(
    initiator: Initiator<A>,
    heartbeat_secs: &str,
    pipe_capacity: usize,
) -> (Connection, Peer) {
    let (client_io, venue_io) = tokio::io::duplex(pipe_capacity);
    let mut peer = Framed::new(venue_io, FixCodec::new());
    let established = tokio::spawn(async move { initiator.establish(client_io).await });
    let logon = next_frame(&mut peer).await;
    assert_eq!(msg_type_of(&logon), "A");
    send(
        &mut peer,
        venue_msg("A", 1, &[(98, "0"), (108, heartbeat_secs)]),
    )
    .await;
    let connection = ok(
        ok(
            ok(
                timeout(STEP, established).await,
                "handshake within the step",
            ),
            "handshake task",
        ),
        "handshake",
    );
    (connection, peer)
}

/// Runs the acceptor handshake against the scripted client.
async fn acceptor_session<A: Application + 'static>(acceptor: Acceptor<A>) -> (Connection, Peer) {
    let (venue_io, client_io) = tokio::io::duplex(PIPE_CAPACITY);
    let mut peer = Framed::new(client_io, FixCodec::new());
    let served = tokio::spawn(async move { acceptor.serve_stream(venue_io).await });
    send(&mut peer, client_msg("A", 1, &[(98, "0"), (108, "30")])).await;
    let ack = next_frame(&mut peer).await;
    assert_eq!(msg_type_of(&ack), "A");
    let connection = ok(
        ok(
            ok(timeout(STEP, served).await, "handshake within the step"),
            "handshake task",
        ),
        "handshake",
    );
    (connection, peer)
}

/// Waits for the close and returns the reason the connection reports,
/// checking it agrees with what the application was handed.
async fn closed_with(connection: &Connection, app: &RecordingApp) -> CloseReason {
    ok(
        timeout(Duration::from_secs(10), connection.wait_closed()).await,
        "the session must close",
    );
    let reason = some(connection.close_reason(), "a closed session has a reason");
    assert_eq!(
        reason,
        app.reason(),
        "the application and the connection agree"
    );
    // The test app overrides `on_session_closed` without calling
    // `on_logout`: the override replaces the forwarding.
    assert!(!app.events().contains(&"logout".to_string()));
    reason
}

/// A counterparty Logout with Text: `PeerLogout` carries the text, in both
/// roles, and the close is graceful.
#[tokio::test]
async fn test_peer_logout_text_reaches_the_reason_initiator() {
    let app = Arc::new(RecordingApp::default());
    let initiator = Initiator::new(client_config(), Arc::clone(&app));
    let (connection, mut peer) = initiator_session(initiator, "30", PIPE_CAPACITY).await;
    assert!(connection.close_reason().is_none(), "no reason while open");

    send(
        &mut peer,
        venue_msg("5", 2, &[(58, "venue closing for the day")]),
    )
    .await;
    let reply = next_of(&mut peer, "5").await;
    assert!(field(&reply, 58).is_none(), "the reply carries no text");

    let reason = closed_with(&connection, &app).await;
    match &reason {
        CloseReason::PeerLogout { text, .. } => {
            assert_eq!(text.as_deref(), Some("venue closing for the day"));
        }
        other => panic!("expected PeerLogout, got {other:?}"),
    }
    assert!(reason.is_graceful());
    assert_eq!(app.events(), ["create", "logon", "closed"]);
}

#[tokio::test]
async fn test_peer_logout_text_reaches_the_reason_acceptor() {
    let app = Arc::new(RecordingApp::default());
    let acceptor = Acceptor::new(venue_config(), Arc::clone(&app));
    let (connection, mut peer) = acceptor_session(acceptor).await;

    send(&mut peer, client_msg("5", 2, &[(58, "client done")])).await;
    let _reply = next_of(&mut peer, "5").await;

    match closed_with(&connection, &app).await {
        CloseReason::PeerLogout { text, .. } => assert_eq!(text.as_deref(), Some("client done")),
        other => panic!("expected PeerLogout, got {other:?}"),
    }
}

/// A peer Logout without Text reports no text.
#[tokio::test]
async fn test_peer_logout_without_text() {
    let app = Arc::new(RecordingApp::default());
    let initiator = Initiator::new(client_config(), Arc::clone(&app));
    let (connection, mut peer) = initiator_session(initiator, "30", PIPE_CAPACITY).await;
    send(&mut peer, venue_msg("5", 2, &[])).await;
    let _reply = next_of(&mut peer, "5").await;
    assert!(matches!(
        closed_with(&connection, &app).await,
        CloseReason::PeerLogout { text: None, .. }
    ));
}

/// `logout_with_text` puts the text in tag 58; the acknowledgement's text
/// and the requested text both reach `LocalLogout`.
#[tokio::test]
async fn test_logout_with_text_on_the_wire_and_in_the_reason() {
    let app = Arc::new(RecordingApp::default());
    let initiator = Initiator::new(client_config(), Arc::clone(&app));
    let (connection, mut peer) = initiator_session(initiator, "30", PIPE_CAPACITY).await;

    ok(
        connection.logout_with_text("kill switch engaged").await,
        "logout_with_text",
    );
    let logout = next_of(&mut peer, "5").await;
    assert_eq!(field(&logout, 58).as_deref(), Some("kill switch engaged"));
    send(&mut peer, venue_msg("5", 2, &[(58, "bye")])).await;

    let reason = closed_with(&connection, &app).await;
    match &reason {
        CloseReason::LocalLogout {
            cause: LogoutCause::Requested { text, .. },
            peer_text,
            ..
        } => {
            assert_eq!(text.as_deref(), Some("kill switch engaged"));
            assert_eq!(peer_text.as_deref(), Some("bye"));
        }
        other => panic!("expected LocalLogout, got {other:?}"),
    }
    assert!(reason.is_graceful());
}

/// A plain `logout` acknowledged in the acceptor role.
#[tokio::test]
async fn test_local_logout_acceptor() {
    let app = Arc::new(RecordingApp::default());
    let acceptor = Acceptor::new(venue_config(), Arc::clone(&app));
    let (connection, mut peer) = acceptor_session(acceptor).await;

    ok(connection.logout().await, "logout");
    let logout = next_of(&mut peer, "5").await;
    assert!(field(&logout, 58).is_none());
    send(&mut peer, client_msg("5", 2, &[])).await;

    assert!(matches!(
        closed_with(&connection, &app).await,
        CloseReason::LocalLogout {
            cause: LogoutCause::Requested { text: None, .. },
            peer_text: None,
            ..
        }
    ));
}

/// Text `logout_with_text` cannot frame is refused before anything is
/// queued, and the session goes on.
#[tokio::test]
async fn test_logout_with_text_refuses_invalid_text() {
    let app = Arc::new(RecordingApp::default());
    let initiator = Initiator::new(client_config(), Arc::clone(&app));
    let (connection, mut peer) = initiator_session(initiator, "30", PIPE_CAPACITY).await;

    let too_long = "x".repeat(MAX_LOGOUT_TEXT_LEN + 1);
    for bad in [
        "",
        "a\u{1}10=000\u{1}",
        "tab\there",
        "caf\u{e9}",
        too_long.as_str(),
    ] {
        assert!(
            matches!(
                connection.logout_with_text(bad).await,
                Err(EngineError::InvalidField { tag: 58, .. })
            ),
            "refused text {bad:?}"
        );
    }
    assert!(
        !connection.is_closed(),
        "a refused text leaves the session open"
    );

    // The session still answers.
    send(&mut peer, venue_msg("1", 2, &[(112, "PING")])).await;
    let heartbeat = next_of(&mut peer, "0").await;
    assert_eq!(field(&heartbeat, 112).as_deref(), Some("PING"));
}

/// Dropping every handle logs out with `HandlesDropped`.
#[tokio::test]
async fn test_handles_dropped_cause() {
    let app = Arc::new(RecordingApp::default());
    let initiator = Initiator::new(client_config(), Arc::clone(&app));
    let (connection, mut peer) = initiator_session(initiator, "30", PIPE_CAPACITY).await;
    drop(connection);
    let _logout = next_of(&mut peer, "5").await;
    send(&mut peer, venue_msg("5", 2, &[])).await;
    drain(&mut peer).await;
    assert!(matches!(
        app.reason(),
        CloseReason::LocalLogout {
            cause: LogoutCause::HandlesDropped,
            ..
        }
    ));
}

/// The transport closing without a Logout, in both roles.
#[tokio::test]
async fn test_transport_closed_initiator() {
    let app = Arc::new(RecordingApp::default());
    let initiator = Initiator::new(client_config(), Arc::clone(&app));
    let (connection, peer) = initiator_session(initiator, "30", PIPE_CAPACITY).await;
    drop(peer);
    let reason = closed_with(&connection, &app).await;
    assert!(matches!(reason, CloseReason::TransportClosed { .. }));
    assert!(!reason.is_graceful());
}

#[tokio::test]
async fn test_transport_closed_acceptor() {
    let app = Arc::new(RecordingApp::default());
    let acceptor = Acceptor::new(venue_config(), Arc::clone(&app));
    let (connection, peer) = acceptor_session(acceptor).await;
    drop(peer);
    assert!(matches!(
        closed_with(&connection, &app).await,
        CloseReason::TransportClosed { .. }
    ));
}

/// An unanswered TestRequest is `HeartbeatTimeout`.
#[tokio::test]
async fn test_heartbeat_timeout() {
    let app = Arc::new(RecordingApp::default());
    let config = client_config().with_heartbeat_interval(Duration::from_secs(1));
    let initiator = Initiator::new(config, Arc::clone(&app));
    let (connection, mut peer) = initiator_session(initiator, "1", PIPE_CAPACITY).await;
    let reader = tokio::spawn(async move { drain(&mut peer).await });
    assert!(matches!(
        closed_with(&connection, &app).await,
        CloseReason::HeartbeatTimeout { .. }
    ));
    assert!(connection.is_timed_out());
    ok(reader.await, "reader");
}

/// A MsgSeqNum below the expected one without PossDupFlag, in both roles.
#[tokio::test]
async fn test_sequence_too_low_initiator() {
    let app = Arc::new(RecordingApp::default());
    let initiator = Initiator::new(client_config(), Arc::clone(&app));
    let (connection, mut peer) = initiator_session(initiator, "30", PIPE_CAPACITY).await;
    send(&mut peer, venue_msg("0", 1, &[])).await;
    let logout = next_of(&mut peer, "5").await;
    assert!(some(field(&logout, 58), "the Logout explains").contains("too low"));
    drain(&mut peer).await;
    match closed_with(&connection, &app).await {
        CloseReason::SequenceTooLow {
            expected, received, ..
        } => {
            assert_eq!(expected, 2);
            assert_eq!(received, 1);
        }
        other => panic!("expected SequenceTooLow, got {other:?}"),
    }
}

#[tokio::test]
async fn test_sequence_too_low_acceptor() {
    let app = Arc::new(RecordingApp::default());
    let acceptor = Acceptor::new(venue_config(), Arc::clone(&app));
    let (connection, mut peer) = acceptor_session(acceptor).await;
    send(&mut peer, client_msg("0", 2, &[])).await;
    send(&mut peer, client_msg("0", 2, &[])).await;
    let _logout = next_of(&mut peer, "5").await;
    drain(&mut peer).await;
    assert!(matches!(
        closed_with(&connection, &app).await,
        CloseReason::SequenceTooLow {
            expected: 3,
            received: 2,
            ..
        }
    ));
}

/// A message from the wrong SenderCompID is `IdentityMismatch` on tag 49.
#[tokio::test]
async fn test_identity_mismatch() {
    let app = Arc::new(RecordingApp::default());
    let initiator = Initiator::new(client_config(), Arc::clone(&app));
    let (connection, mut peer) = initiator_session(initiator, "30", PIPE_CAPACITY).await;
    send(&mut peer, frame("INTRUDER", "CLIENT", "0", 2, &[])).await;
    let _reject = next_of(&mut peer, "3").await;
    let _logout = next_of(&mut peer, "5").await;
    drain(&mut peer).await;
    assert!(matches!(
        closed_with(&connection, &app).await,
        CloseReason::IdentityMismatch { tag: 49, .. }
    ));
}

/// A SendingTime far outside the tolerance is `SendingTime`.
#[tokio::test]
async fn test_sending_time_problem() {
    let app = Arc::new(RecordingApp::default());
    let acceptor = Acceptor::new(venue_config(), Arc::clone(&app));
    let (connection, mut peer) = acceptor_session(acceptor).await;
    let mut encoder = Encoder::new("FIX.4.4");
    encoder.put_str(35, "0");
    encoder.put_str(49, "CLIENT");
    encoder.put_str(56, "VENUE");
    encoder.put_uint(34, 2);
    encoder.put_str(52, "20000101-00:00:00.000");
    let mut skewed = BytesMut::new();
    ok(encoder.finish_into(&mut skewed), "skewed frame");
    send(&mut peer, skewed).await;
    let _logout = next_of(&mut peer, "5").await;
    drain(&mut peer).await;
    assert!(matches!(
        closed_with(&connection, &app).await,
        CloseReason::SendingTime { .. }
    ));
}

/// A Logout never acknowledged is `LogoutTimeout`, still graceful.
#[tokio::test]
async fn test_logout_ack_timeout() {
    let app = Arc::new(RecordingApp::default());
    let mut config = client_config();
    config.logout_timeout = Duration::from_millis(300);
    let initiator = Initiator::new(config, Arc::clone(&app));
    let (connection, mut peer) = initiator_session(initiator, "30", PIPE_CAPACITY).await;
    ok(connection.logout().await, "logout");
    let _logout = next_of(&mut peer, "5").await;
    let reason = closed_with(&connection, &app).await;
    assert!(matches!(
        reason,
        CloseReason::LogoutTimeout {
            cause: LogoutCause::Requested { text: None, .. },
            ..
        }
    ));
    assert!(reason.is_graceful());
}

/// A gap the counterparty never fills logs out with `ResendStalled`, which
/// the acknowledgement completes as a `LocalLogout`.
#[tokio::test]
async fn test_resend_stalled_cause() {
    let app = Arc::new(RecordingApp::default());
    let config = client_config()
        .with_resend_timeout(Duration::from_millis(150))
        .with_max_resend_requests(2);
    let initiator = Initiator::new(config, Arc::clone(&app));
    let (connection, mut peer) = initiator_session(initiator, "30", PIPE_CAPACITY).await;
    send(&mut peer, venue_msg("0", 5, &[])).await;
    let logout = next_of(&mut peer, "5").await;
    assert!(some(field(&logout, 58), "the Logout explains").contains("resend"));
    send(&mut peer, venue_msg("5", 6, &[])).await;
    match closed_with(&connection, &app).await {
        CloseReason::LocalLogout {
            cause: LogoutCause::ResendStalled {
                expected, attempts, ..
            },
            ..
        } => {
            assert_eq!(expected, 2);
            assert_eq!(attempts, 2);
        }
        other => panic!("expected a ResendStalled logout, got {other:?}"),
    }
}

/// The garbled-frame limit, in the acceptor role.
#[tokio::test]
async fn test_garbled_frame_limit() {
    let app = Arc::new(RecordingApp::default());
    let limit = ok(
        GarbledFrameLimit::try_new(
            some(NonZeroU32::new(2), "non-zero"),
            Duration::from_secs(60),
        ),
        "limit",
    );
    let config = venue_config().with_garbled_frame_limit(Some(limit));
    let acceptor = Acceptor::new(config, Arc::clone(&app));
    let (connection, mut peer) = acceptor_session(acceptor).await;
    let mut burst = with_wrong_checksum(&client_msg("0", 2, &[]));
    burst.extend_from_slice(&with_wrong_checksum(&client_msg("0", 3, &[])));
    send(&mut peer, burst).await;
    let logout = next_of(&mut peer, "5").await;
    assert!(some(field(&logout, 58), "the Logout explains").contains("garbled"));
    drain(&mut peer).await;
    match closed_with(&connection, &app).await {
        CloseReason::GarbledFrameLimit { max, window, .. } => {
            assert_eq!(max, 2);
            assert_eq!(window, Duration::from_secs(60));
        }
        other => panic!("expected GarbledFrameLimit, got {other:?}"),
    }
}

/// An inbound frame above `max_message_size` is `MessageTooLarge`.
#[tokio::test]
async fn test_message_too_large() {
    let app = Arc::new(RecordingApp::default());
    let mut config = client_config();
    config.max_message_size = 512;
    let initiator = Initiator::new(config, Arc::clone(&app));
    let (connection, mut peer) = initiator_session(initiator, "30", PIPE_CAPACITY).await;
    let padding = "x".repeat(2048);
    send(&mut peer, venue_msg("0", 2, &[(58, padding.as_str())])).await;
    let _logout = next_of(&mut peer, "5").await;
    drain(&mut peer).await;
    match closed_with(&connection, &app).await {
        CloseReason::MessageTooLarge { max_size, size, .. } => {
            assert_eq!(max_size, 512);
            assert!(size > 512);
        }
        other => panic!("expected MessageTooLarge, got {other:?}"),
    }
}

/// A store failure under `CloseSession` is `StoreFailure`, and a send after
/// the close reports `SessionClosed` with the reason.
#[tokio::test]
async fn test_store_failure_and_session_closed_outcome() {
    let app = Arc::new(RecordingApp::default());
    let initiator = Initiator::new(client_config(), Arc::clone(&app))
        .with_store(Arc::new(RefusingStore::default()))
        .with_store_failure_policy(StoreFailurePolicy::CloseSession);
    let (connection, mut peer) = initiator_session(initiator, "30", PIPE_CAPACITY).await;
    let outcome = connection.send_tracked(order("ORD-1")).await;
    assert!(matches!(
        outcome,
        SendOutcome::NotSent {
            reason: NotSentReason::StoreRefused { .. },
            ..
        }
    ));
    drain(&mut peer).await;
    let reason = closed_with(&connection, &app).await;
    assert!(matches!(reason, CloseReason::StoreFailure { .. }));

    match connection.send_tracked(order("ORD-2")).await {
        SendOutcome::NotSent {
            reason:
                NotSentReason::SessionClosed {
                    reason: Some(closed),
                    ..
                },
            ..
        } => assert_eq!(closed, reason),
        other => panic!("expected SessionClosed with the reason, got {other:?}"),
    }
}

/// A counterparty that stops reading is `WriteTimeout`.
#[tokio::test]
async fn test_write_timeout() {
    let app = Arc::new(RecordingApp::default());
    let initiator = Initiator::new(client_config(), Arc::clone(&app))
        .with_write_timeout(Duration::from_millis(300));
    let (connection, _peer) = initiator_session(initiator, "30", 4 * 1024).await;
    // The peer holds its end and reads nothing more.
    let sender = connection.clone();
    let flood = tokio::spawn(async move {
        for index in 0..200 {
            if sender.send(order(&format!("ORD-{index}"))).await.is_err() {
                break;
            }
        }
    });
    match closed_with(&connection, &app).await {
        CloseReason::WriteTimeout { timeout, .. } => {
            assert_eq!(timeout, Duration::from_millis(300));
        }
        other => panic!("expected WriteTimeout, got {other:?}"),
    }
    ok(flood.await, "flood task");
}

/// A Logon handshake that fails after `on_create` reports `LogonFailed` to
/// the application, in both roles; the default forwarding does not call
/// `on_logout` for it.
#[tokio::test]
async fn test_handshake_failure_reports_logon_failed() {
    let app = Arc::new(RecordingApp::default());
    let mut config = client_config();
    config.logon_timeout = Duration::from_millis(200);
    let initiator = Initiator::new(config, Arc::clone(&app));
    let (client_io, _venue_io) = tokio::io::duplex(PIPE_CAPACITY);
    let result = initiator.establish(client_io).await;
    assert!(matches!(result, Err(EngineError::LogonTimeout(_))));
    assert!(matches!(app.reason(), CloseReason::LogonFailed { .. }));
    assert!(!app.reason().was_active());

    let app = Arc::new(RecordingApp::default());
    let acceptor = Acceptor::new(venue_config(), Arc::clone(&app));
    let (venue_io, client_io) = tokio::io::duplex(PIPE_CAPACITY);
    drop(client_io);
    assert!(acceptor.serve_stream(venue_io).await.is_err());
    assert!(matches!(app.reason(), CloseReason::LogonFailed { .. }));

    let legacy = Arc::new(LegacyApp::default());
    let mut config = client_config();
    config.logon_timeout = Duration::from_millis(200);
    let initiator = Initiator::new(config, Arc::clone(&legacy));
    let (client_io, _venue_io) = tokio::io::duplex(PIPE_CAPACITY);
    assert!(initiator.establish(client_io).await.is_err());
    assert_eq!(legacy.events(), ["create"], "no on_logout before Active");
}

/// The default `on_session_closed` forwards to `on_logout` once Active.
#[tokio::test]
async fn test_default_forwards_to_on_logout_after_active() {
    let legacy = Arc::new(LegacyApp::default());
    let initiator = Initiator::new(client_config(), Arc::clone(&legacy));
    let (connection, mut peer) = initiator_session(initiator, "30", PIPE_CAPACITY).await;
    send(&mut peer, venue_msg("5", 2, &[])).await;
    ok(
        timeout(STEP, connection.wait_closed()).await,
        "the session must close",
    );
    assert_eq!(legacy.events(), ["create", "logon", "logout"]);
    assert!(matches!(
        connection.close_reason(),
        Some(CloseReason::PeerLogout { .. })
    ));
}

/// The two Logouts crossing, ours never written whole, is not graceful:
/// `LogoutUnwritten`. Reached here by a peer Logout that arrives while ours
/// sits behind output the peer does not read.
#[tokio::test]
async fn test_unwritten_logout_is_not_graceful() {
    let app = Arc::new(RecordingApp::default());
    let initiator = Initiator::new(client_config(), Arc::clone(&app))
        .with_write_timeout(Duration::from_millis(400));
    let (connection, mut peer) = initiator_session(initiator, "30", 1024).await;
    // Fill the pipe so the Logout queues behind output the peer is not
    // reading.
    for index in 0..20 {
        ok(
            connection.send(order(&format!("ORD-{index}"))).await,
            "send",
        );
    }
    ok(connection.logout().await, "logout");
    tokio::time::sleep(Duration::from_millis(50)).await;
    send(&mut peer, venue_msg("5", 2, &[])).await;
    let reason = closed_with(&connection, &app).await;
    assert!(!reason.is_graceful(), "got {reason:?}");
    match &reason {
        CloseReason::LogoutUnwritten {
            initiator, cause, ..
        } => {
            assert_eq!(*initiator, LogoutInitiator::Local);
            assert!(matches!(
                cause,
                Some(LogoutCause::Requested { text: None, .. })
            ));
        }
        other => panic!("expected LogoutUnwritten, got {other:?}"),
    }
}

/// A dial that fails after `on_create` reports `ConnectFailed` with the I/O
/// error's kind, and the default does not forward it to `on_logout`.
#[tokio::test]
async fn test_connect_failure_reports_connect_failed() {
    // Bind then drop a listener, so nothing listens on the port.
    let listener = ok(tokio::net::TcpListener::bind("127.0.0.1:0").await, "bind");
    let addr = ok(listener.local_addr(), "address");
    drop(listener);

    let app = Arc::new(RecordingApp::default());
    let initiator = Initiator::new(client_config(), Arc::clone(&app));
    assert!(matches!(
        initiator.connect(addr).await,
        Err(EngineError::Io(_))
    ));
    match app.reason() {
        CloseReason::ConnectFailed {
            kind, timed_out, ..
        } => {
            assert!(!timed_out);
            assert_eq!(kind, Some(std::io::ErrorKind::ConnectionRefused));
        }
        other => panic!("expected ConnectFailed, got {other:?}"),
    }
    assert!(!app.reason().was_active());

    let legacy = Arc::new(LegacyApp::default());
    let initiator = Initiator::new(client_config(), Arc::clone(&legacy));
    assert!(initiator.connect(addr).await.is_err());
    assert_eq!(legacy.events(), ["create"], "no on_logout before Active");
}

/// A peer Logout Text with control characters reaches the reason escaped.
#[tokio::test]
async fn test_peer_logout_text_is_escaped() {
    let app = Arc::new(RecordingApp::default());
    let initiator = Initiator::new(client_config(), Arc::clone(&app));
    let (connection, mut peer) = initiator_session(initiator, "30", PIPE_CAPACITY).await;
    send(&mut peer, venue_msg("5", 2, &[(58, "line1\nline2\tend")])).await;
    let _reply = next_of(&mut peer, "5").await;
    match closed_with(&connection, &app).await {
        CloseReason::PeerLogout { text, .. } => {
            assert_eq!(text.as_deref(), Some("line1?line2?end"));
        }
        other => panic!("expected PeerLogout, got {other:?}"),
    }
}

/// Leaves this session's Logout reply unframeable: an empty `Text` (58)
/// has no legal wire form, so the reply is dropped.
#[derive(Debug, Default)]
struct UnframeableReplyApp {
    inner: RecordingApp,
}

#[async_trait]
impl Application for UnframeableReplyApp {
    async fn on_create(&self, id: &SessionId) {
        self.inner.on_create(id).await;
    }
    async fn on_logon(&self, id: &SessionId) {
        self.inner.on_logon(id).await;
    }
    async fn on_logout(&self, id: &SessionId) {
        self.inner.on_logout(id).await;
    }
    async fn on_session_closed(&self, id: &SessionId, reason: &CloseReason) {
        self.inner.on_session_closed(id, reason).await;
    }
    async fn to_admin(&self, message: &mut OutboundMessage, _: &SessionId) {
        if message.msg_type() == &MsgType::Logout {
            message.push_str(58, "");
        }
    }
    async fn from_admin(&self, _: &RawMessage<'_>, _: &SessionId) -> Result<(), RejectReason> {
        Ok(())
    }
    async fn to_app(&self, _: &mut OutboundMessage, _: &SessionId) {}
    async fn from_app(&self, _: &RawMessage<'_>, _: &SessionId) -> Result<(), RejectReason> {
        Ok(())
    }
}

/// A reply to the peer's Logout that is dropped before it is framed never
/// reaches the peer: the close is `LogoutUnwritten`, not graceful, and
/// `reset_on_logout` does not reset the store (codex review of PR #148).
#[tokio::test]
async fn test_dropped_logout_reply_is_not_graceful() {
    let app = Arc::new(UnframeableReplyApp::default());
    let store = Arc::new(MemoryStore::new());
    let mut config = client_config();
    config.reset_on_logout = true;
    let initiator = Initiator::new(config, Arc::clone(&app)).with_store(store.clone());
    let (connection, mut peer) = initiator_session(initiator, "30", PIPE_CAPACITY).await;
    send(&mut peer, venue_msg("5", 2, &[])).await;
    let reason = closed_with(&connection, &app.inner).await;
    let reply = ok(timeout(STEP, peer.next()).await, "the peer sees the close");
    assert!(reply.is_none(), "no Logout reply reached the peer");
    assert!(!reason.is_graceful(), "got {reason:?}");
    assert!(matches!(
        reason,
        CloseReason::LogoutUnwritten {
            initiator: LogoutInitiator::Peer,
            ..
        }
    ));
    assert_eq!(
        store.next_sender_seq(),
        2,
        "no reset: the sender counter is kept"
    );
    assert_eq!(
        store.next_target_seq(),
        3,
        "no reset: the target counter is kept"
    );
}
