/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Integration tests for application-version validation on FIXT.1.1 sessions
//! (issue #67): `DefaultApplVerID` (1137) on the Logon exchange and
//! `ApplVerID` (1128) on inbound application messages.
//!
//! The acceptor requires an accepted 1137 on a FIX 5.0 Logon and refuses a
//! missing, unknown or disallowed one with a filed Logout once `from_admin`
//! has accepted the peer; the initiator refuses an acknowledgement whose
//! 1137, when present, is not accepted. In session, an application message
//! whose 1128 is not accepted is answered with a session Reject
//! (`SessionRejectReason` 18, `RefTagID` 1128), its number is consumed and it
//! never reaches `from_app`; one without 1128 is delivered. FIX 4.2 and 4.4
//! sessions are unaffected, an allowed set on a FIX 4.x session is a
//! configuration error, and a session routed by an `AcceptorRegistry` behaves
//! as one served directly. Scripted peers play the counterparty over real
//! loopback sockets where a real engine cannot send what a test needs.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::{CompId, Timestamp};
use ironfix_core::version::FixVersion;
use ironfix_engine::application::{Application, RejectReason, SessionId};
use ironfix_engine::{
    Acceptor, AcceptorRegistry, Connection, EngineError, Initiator, OutboundMessage,
};
use ironfix_session::{SessionConfig, SessionConfigError};
use ironfix_store::{MemoryStore, MessageStore};
use ironfix_tagvalue::{Decoder, Encoder};
use ironfix_transport::FixCodec;
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

/// Acceptor-side configuration in `version`: sender VENUE, target CLIENT.
fn venue_config(version: &str) -> SessionConfig {
    SessionConfig::new(comp_id("VENUE"), comp_id("CLIENT"), version)
        .with_heartbeat_interval(Duration::from_secs(30))
}

/// Initiator-side configuration in `version`: sender CLIENT, target VENUE.
fn client_config(version: &str) -> SessionConfig {
    SessionConfig::new(comp_id("CLIENT"), comp_id("VENUE"), version)
        .with_heartbeat_interval(Duration::from_secs(30))
}

/// An application message as `from_app` saw it: `(MsgType, MsgSeqNum,
/// ApplVerID)`.
type AppMessage = (String, String, Option<String>);

/// Records session events, and forwards every application message.
#[derive(Debug)]
struct RecordingApp {
    events: Mutex<Vec<String>>,
    app_tx: mpsc::UnboundedSender<AppMessage>,
}

impl RecordingApp {
    fn new() -> (Arc<Self>, mpsc::UnboundedReceiver<AppMessage>) {
        let (app_tx, app_rx) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                events: Mutex::new(Vec::new()),
                app_tx,
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

    #[track_caller]
    fn logged_on(&self) -> bool {
        self.events().iter().any(|event| event == "logon")
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
        let _ = self.app_tx.send((
            message.msg_type().as_str().to_string(),
            message.get_field_str(34).unwrap_or_default().to_string(),
            message.get_field_str(1128).map(str::to_string),
        ));
        Ok(())
    }
}

/// A scripted counterparty's frame under `begin_string`, from `sender` to
/// `target`: MsgType, then `header` (where 1128 belongs), then the CompIDs,
/// `MsgSeqNum` and `SendingTime`, then `body`.
#[track_caller]
fn peer_frame(
    begin_string: &str,
    sender: &str,
    target: &str,
    msg_type: &str,
    seq: u64,
    header: &[(u32, &str)],
    body: &[(u32, &str)],
) -> BytesMut {
    let mut encoder = Encoder::new(begin_string);
    encoder.put_str(35, msg_type);
    for (tag, value) in header {
        encoder.put_str(*tag, value);
    }
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

/// A FIXT.1.1 frame from the scripted initiator (CLIENT -> VENUE).
#[track_caller]
fn client_fixt(msg_type: &str, seq: u64, header: &[(u32, &str)], body: &[(u32, &str)]) -> BytesMut {
    peer_frame("FIXT.1.1", "CLIENT", "VENUE", msg_type, seq, header, body)
}

/// A FIXT.1.1 Logon from the scripted initiator, numbered `seq`, carrying
/// `extra` after `EncryptMethod` (98) = 0 and `HeartBtInt` (108) = 30.
#[track_caller]
fn client_fixt_logon(seq: u64, extra: &[(u32, &str)]) -> BytesMut {
    let mut body = vec![(98, "0"), (108, "30")];
    body.extend_from_slice(extra);
    client_fixt("A", seq, &[], &body)
}

/// An ExecutionReport body.
const REPORT_BODY: [(u32, &str); 4] = [(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")];

/// A NewOrderSingle body.
const ORDER_BODY: [(u32, &str); 4] = [(11, "ORDER-1"), (55, "EUR/USD"), (54, "1"), (38, "100")];

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

/// Reads the next frame the engine sends, within 5 s.
async fn next_frame(framed: &mut Framed<TcpStream, FixCodec>) -> BytesMut {
    let polled = ok(
        timeout(Duration::from_secs(5), framed.next()).await,
        "frame must arrive within 5s",
    );
    ok(some(polled, "stream must stay open"), "frame must decode")
}

/// Asserts nothing arrives on `framed` for 300 ms.
async fn assert_silent(framed: &mut Framed<TcpStream, FixCodec>, what: &str) {
    if let Ok(Some(Ok(frame))) = timeout(Duration::from_millis(300), framed.next()).await {
        panic!("{what}: unexpected MsgType {}", msg_type_of(&frame));
    }
}

/// Asserts the application receives nothing for 300 ms.
async fn assert_no_app_message(rx: &mut mpsc::UnboundedReceiver<AppMessage>, what: &str) {
    if let Ok(Some(message)) = timeout(Duration::from_millis(300), rx.recv()).await {
        panic!("{what}: from_app received {message:?}");
    }
}

/// Receives the next application message, within 5 s.
async fn next_app_message(rx: &mut mpsc::UnboundedReceiver<AppMessage>) -> AppMessage {
    some(
        ok(
            timeout(Duration::from_secs(5), rx.recv()).await,
            "an application message arrives within 5s",
        ),
        "the application channel must stay open",
    )
}

/// Sends `logon` from a scripted initiator to `acceptor`, and returns what
/// `accept` returned and every frame received before the acceptor hung up, as
/// `(MsgType, MsgSeqNum, Text)`.
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

/// Logs a scripted initiator on to `acceptor` with `logon`, and returns its
/// socket, the acceptor's connection and the acknowledgement.
async fn establish<A: Application + 'static>(
    acceptor: Arc<Acceptor<A>>,
    logon: BytesMut,
) -> (Framed<TcpStream, FixCodec>, Connection, BytesMut) {
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move { acceptor.accept(&listener).await });
    let stream = ok(TcpStream::connect(addr).await, "client connects");
    let mut framed = Framed::new(stream, FixCodec::new());
    ok(framed.send(logon).await, "client sends its logon");
    let ack = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&ack), "A", "the Logon is acknowledged");
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

/// Asserts `result` is an `ApplVersion` refusal whose detail mentions every
/// string in `mentions`.
#[track_caller]
fn assert_appl_version_refusal(result: &Result<Connection, EngineError>, mentions: &[&str]) {
    match result {
        Err(EngineError::ApplVersion { detail }) => {
            for mention in mentions {
                assert!(detail.contains(mention), "'{mention}' not in '{detail}'");
            }
        }
        other => panic!("expected EngineError::ApplVersion, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Acceptor: DefaultApplVerID (1137) on the inbound Logon
// ---------------------------------------------------------------------------

/// A FIX.5.0SP2 acceptor refuses a FIXT.1.1 Logon that declares no
/// `DefaultApplVerID` (1137), a required field of the FIXT.1.1 Logon, with a
/// Logout saying why, and never reaches Active.
#[tokio::test]
async fn test_acceptor_fixt_logon_without_default_appl_ver_id_is_refused() {
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Arc::new(Acceptor::new(
        venue_config("FIX.5.0SP2"),
        Arc::clone(&venue_app),
    ));
    let (result, frames) = refused_logon(acceptor, client_fixt_logon(1, &[])).await;

    assert_appl_version_refusal(&result, &["DefaultApplVerID (1137)", "missing"]);
    assert_eq!(frames.len(), 1, "one Logout: {frames:?}");
    assert_eq!(frames[0].0, "5");
    assert_eq!(frames[0].1.as_deref(), Some("1"));
    let text = some(frames[0].2.clone(), "the Logout says why");
    assert!(text.contains("1137"), "{text}");
    assert!(!venue_app.logged_on(), "the session never reached Active");
}

/// `1137=7` (FIX.5.0) is not accepted by a FIX.5.0SP2 acceptor configured
/// with no other version: the Logout names what it accepts.
#[tokio::test]
async fn test_acceptor_fixt_logon_with_disallowed_default_appl_ver_id_is_refused() {
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Arc::new(Acceptor::new(
        venue_config("FIX.5.0SP2"),
        Arc::clone(&venue_app),
    ));
    let (result, frames) = refused_logon(acceptor, client_fixt_logon(1, &[(1137, "7")])).await;

    assert_appl_version_refusal(&result, &["1137", "FIX.5.0"]);
    assert_eq!(frames.len(), 1, "one Logout: {frames:?}");
    assert_eq!(frames[0].0, "5");
    let text = some(frames[0].2.clone(), "the Logout says why");
    assert!(text.contains("9 (FIX.5.0SP2)"), "{text}");
    assert!(!venue_app.logged_on());
}

/// A `DefaultApplVerID` that is no application-version code at all is
/// refused the same way, and the value echoed is bounded.
#[tokio::test]
async fn test_acceptor_fixt_logon_with_non_numeric_default_appl_ver_id_is_refused() {
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Arc::new(Acceptor::new(
        venue_config("FIX.5.0SP2"),
        Arc::clone(&venue_app),
    ));
    let long = "FIX50SP2-NOT-A-CODE-AT-ALL";
    let (result, frames) = refused_logon(acceptor, client_fixt_logon(1, &[(1137, long)])).await;

    assert_appl_version_refusal(&result, &["1137", "not a supported application version"]);
    assert_eq!(frames.len(), 1, "one Logout: {frames:?}");
    let text = some(frames[0].2.clone(), "the Logout says why");
    assert!(text.contains("FIX50SP2-NOT-A-C"), "{text}");
    assert!(!text.contains(long), "the echoed value is bounded: {text}");
    assert!(!venue_app.logged_on());
}

/// The refusal comes after `from_admin` accepted the peer, so with a store
/// attached it is an authenticated refusal (ADR-0017 group 3): the Logout is
/// numbered from the store and filed, and a `ResetSeqNumFlag` (141) on the
/// refused Logon does not reset the store.
#[tokio::test]
async fn test_acceptor_default_appl_ver_id_refusal_is_filed_and_never_resets() {
    let store = Arc::new(MemoryStore::new());
    let previous = client_fixt("8", 1, &[], &REPORT_BODY);
    for seq in 1..=3u64 {
        ok(
            store.store(seq, &MsgType::ExecutionReport, &previous).await,
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

    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(venue_config("FIX.5.0SP2"), Arc::clone(&venue_app))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );
    let (result, frames) =
        refused_logon(acceptor, client_fixt_logon(1, &[(141, "Y"), (1137, "7")])).await;

    assert_appl_version_refusal(&result, &["1137"]);
    assert_eq!(frames.len(), 1, "one Logout: {frames:?}");
    assert_eq!(frames[0].0, "5");
    assert_eq!(frames[0].1.as_deref(), Some("4"), "numbered from the store");
    assert!(store.contains(4), "the Logout is filed");
    for seq in 1..=3u64 {
        assert!(store.contains(seq), "the store was not reset (frame {seq})");
    }
    assert_eq!(store.next_sender_seq(), 5);
    assert_eq!(
        store.next_target_seq(),
        3,
        "the refused Logon is not consumed"
    );
}

/// `1137=9` on a FIX.5.0SP2 acceptor reaches Active, and the acknowledgement
/// declares the acceptor's own `DefaultApplVerID`.
#[tokio::test]
async fn test_acceptor_fixt_logon_with_default_appl_ver_id_9_reaches_active() {
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let acceptor = Arc::new(Acceptor::new(
        venue_config("FIX.5.0SP2"),
        Arc::clone(&venue_app),
    ));
    let (mut framed, connection, ack) =
        establish(acceptor, client_fixt_logon(1, &[(1137, "9")])).await;

    assert_eq!(field(&ack, 8).as_deref(), Some("FIXT.1.1"));
    assert_eq!(field(&ack, 1137).as_deref(), Some("9"));
    assert!(venue_app.logged_on());

    // An application message stamped with the session's own version is
    // delivered.
    ok(
        framed
            .send(client_fixt("D", 2, &[(1128, "9")], &ORDER_BODY))
            .await,
        "client sends an order",
    );
    assert_eq!(
        next_app_message(&mut venue_rx).await,
        ("D".to_string(), "2".to_string(), Some("9".to_string()))
    );
    assert_eq!(connection.next_target_seq(), 3);
}

/// A real FIX.5.0SP2 `Initiator` against a real FIX.5.0SP2 `Acceptor`: both
/// declare 9, both accept it, and application messages flow each way carrying
/// `ApplVerID` 9.
#[tokio::test]
async fn test_initiator_against_acceptor_fixt_session_exchanges_messages() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(venue_config("FIX.5.0SP2"), Arc::clone(&venue_app));
    let venue = tokio::spawn(async move { acceptor.accept(&listener).await });

    let (client_app, mut client_rx) = RecordingApp::new();
    let client = ok(
        Initiator::new(client_config("FIX.5.0SP2"), Arc::clone(&client_app))
            .connect(addr)
            .await,
        "the initiator logs on",
    );
    let venue_connection = ok(
        ok(
            ok(
                timeout(Duration::from_secs(5), venue).await,
                "handshake within 5s",
            ),
            "venue task joins",
        ),
        "the acceptor establishes the session",
    );

    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order
        .push_str(11, "ORDER-1")
        .push_str(55, "EUR/USD")
        .push_char(54, '1')
        .push_uint(38, 100);
    ok(client.send(order).await, "the client sends an order");
    let (msg_type, _, appl_ver_id) = next_app_message(&mut venue_rx).await;
    assert_eq!(msg_type, "D");
    assert_eq!(appl_ver_id.as_deref(), Some("9"));

    let mut report = OutboundMessage::new(MsgType::ExecutionReport);
    report
        .push_str(37, "EX-1")
        .push_str(17, "E-1")
        .push_char(150, '0')
        .push_char(39, '0');
    ok(
        venue_connection.send(report).await,
        "the venue sends a report",
    );
    let (msg_type, _, appl_ver_id) = next_app_message(&mut client_rx).await;
    assert_eq!(msg_type, "8");
    assert_eq!(appl_ver_id.as_deref(), Some("9"));

    ok(client.logout().await, "the client logs out");
    ok(
        timeout(Duration::from_secs(5), client.wait_closed()).await,
        "the client session closes within 5s",
    );
    ok(
        timeout(Duration::from_secs(5), venue_connection.wait_closed()).await,
        "the venue session closes within 5s",
    );
}

/// An acceptor configured with an allowed set accepts a Logon declaring a
/// version in it besides its own, and in session accepts `ApplVerID` values
/// in the set while still rejecting one outside it.
#[tokio::test]
async fn test_acceptor_accepts_an_allowed_default_appl_ver_id_besides_its_own() {
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let config = venue_config("FIX.5.0SP2").with_allowed_appl_versions([FixVersion::Fix50Sp1]);
    let acceptor = Arc::new(Acceptor::new(config, Arc::clone(&venue_app)));
    let (mut framed, connection, ack) =
        establish(acceptor, client_fixt_logon(1, &[(1137, "8")])).await;

    // The acceptor still declares its own version.
    assert_eq!(field(&ack, 1137).as_deref(), Some("9"));

    for (seq, appl_ver_id) in [(2u64, "8"), (3, "9")] {
        ok(
            framed
                .send(client_fixt("D", seq, &[(1128, appl_ver_id)], &ORDER_BODY))
                .await,
            "client sends an order",
        );
        let (_, received_seq, received) = next_app_message(&mut venue_rx).await;
        assert_eq!(received_seq, seq.to_string());
        assert_eq!(received.as_deref(), Some(appl_ver_id));
    }

    ok(
        framed
            .send(client_fixt("D", 4, &[(1128, "7")], &ORDER_BODY))
            .await,
        "client sends an order in FIX.5.0",
    );
    let reject = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&reject), "3");
    assert_eq!(field(&reject, 373).as_deref(), Some("18"));
    assert_eq!(field(&reject, 371).as_deref(), Some("1128"));
    assert_no_app_message(&mut venue_rx, "the FIX.5.0 order is not delivered").await;
    assert_eq!(connection.next_target_seq(), 5);
}

// ---------------------------------------------------------------------------
// Initiator: DefaultApplVerID (1137) on the Logon acknowledgement
// ---------------------------------------------------------------------------

/// Plays a FIXT.1.1 acceptor: reads the initiator's Logon, checks it declares
/// 9, and acknowledges it with `ack_extra` after 98 and 108. Returns the
/// socket positioned after the ack.
async fn fixt_venue_ack(
    listener: TcpListener,
    ack_extra: &[(u32, &str)],
) -> Framed<TcpStream, FixCodec> {
    let (socket, _) = ok(listener.accept().await, "the venue accepts");
    let mut framed = Framed::new(socket, FixCodec::new());
    let logon = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&logon), "A");
    assert_eq!(field(&logon, 8).as_deref(), Some("FIXT.1.1"));
    assert_eq!(field(&logon, 1137).as_deref(), Some("9"));
    let mut body = vec![(98, "0"), (108, "30")];
    body.extend_from_slice(ack_extra);
    ok(
        framed
            .send(peer_frame(
                "FIXT.1.1",
                "VENUE",
                "CLIENT",
                "A",
                1,
                &[],
                &body,
            ))
            .await,
        "the venue acknowledges the Logon",
    );
    framed
}

/// An acknowledgement declaring a `DefaultApplVerID` the initiator does not
/// accept is refused with a Reject (373 = 18, 371 = 1137) and a Logout, and
/// the session never reaches Active.
#[tokio::test]
async fn test_initiator_refuses_an_ack_with_a_disallowed_default_appl_ver_id() {
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let mut framed = fixt_venue_ack(listener, &[(1137, "7")]).await;
        let reject = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reject), "3");
        assert_eq!(field(&reject, 45).as_deref(), Some("1"));
        assert_eq!(field(&reject, 372).as_deref(), Some("A"));
        assert_eq!(field(&reject, 373).as_deref(), Some("18"));
        assert_eq!(field(&reject, 371).as_deref(), Some("1137"));
        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5");
    });

    let (client_app, _rx) = RecordingApp::new();
    let result = Initiator::new(client_config("FIX.5.0SP2"), Arc::clone(&client_app))
        .connect(addr)
        .await;
    assert_appl_version_refusal(&result, &["1137", "FIX.5.0"]);
    assert!(!client_app.logged_on());
    ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );
}

/// An acknowledgement whose `DefaultApplVerID` is no code at all is refused
/// the same way.
#[tokio::test]
async fn test_initiator_refuses_an_ack_with_a_non_numeric_default_appl_ver_id() {
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let mut framed = fixt_venue_ack(listener, &[(1137, "SP2")]).await;
        let reject = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reject), "3");
        assert_eq!(field(&reject, 373).as_deref(), Some("18"));
        assert_eq!(field(&reject, 371).as_deref(), Some("1137"));
    });

    let (client_app, _rx) = RecordingApp::new();
    let result = Initiator::new(client_config("FIX.5.0SP2"), Arc::clone(&client_app))
        .connect(addr)
        .await;
    assert_appl_version_refusal(&result, &["1137", "SP2"]);
    ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );
}

/// An acknowledgement without `DefaultApplVerID` is accepted (the initiator
/// checks it only when present), and so is one declaring the session's own
/// version; either way the session reaches Active.
#[tokio::test]
async fn test_initiator_accepts_an_ack_without_or_with_its_own_default_appl_ver_id() {
    for ack_extra in [&[][..], &[(1137, "9")][..]] {
        let (listener, addr) = bind_listener().await;
        let extra: Vec<(u32, String)> = ack_extra
            .iter()
            .map(|(tag, value)| (*tag, (*value).to_string()))
            .collect();
        let venue = tokio::spawn(async move {
            let borrowed: Vec<(u32, &str)> = extra
                .iter()
                .map(|(tag, value)| (*tag, value.as_str()))
                .collect();
            let mut framed = fixt_venue_ack(listener, &borrowed).await;
            assert_silent(&mut framed, "no Reject or Logout follows the ack").await;
            framed
        });

        let (client_app, _rx) = RecordingApp::new();
        let connection = ok(
            Initiator::new(client_config("FIX.5.0SP2"), Arc::clone(&client_app))
                .connect(addr)
                .await,
            "the initiator accepts the ack",
        );
        assert!(client_app.logged_on());
        assert_eq!(connection.next_target_seq(), 2);
        let _framed = ok(
            ok(
                timeout(Duration::from_secs(5), venue).await,
                "venue done within 5s",
            ),
            "venue task",
        );
    }
}

// ---------------------------------------------------------------------------
// In session: ApplVerID (1128) on inbound application messages
// ---------------------------------------------------------------------------

/// An application message whose `ApplVerID` (1128) is not accepted gets a
/// session Reject (373 = 18, 371 = 1128, 45 = its number), never reaches
/// `from_app`, and has its number consumed: the next message is in sequence,
/// draws no `ResendRequest`, and is delivered. The consumed number is
/// persisted to the attached store as for a delivered message. A message
/// without 1128 is in the session default and is delivered.
#[tokio::test]
async fn test_disallowed_appl_ver_id_is_rejected_and_its_number_consumed() {
    let store = Arc::new(MemoryStore::new());
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(venue_config("FIX.5.0SP2"), Arc::clone(&venue_app))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );
    let (mut framed, connection, _ack) =
        establish(acceptor, client_fixt_logon(1, &[(1137, "9")])).await;

    ok(
        framed
            .send(client_fixt("D", 2, &[(1128, "7")], &ORDER_BODY))
            .await,
        "client sends a FIX.5.0 order",
    );
    let reject = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&reject), "3");
    assert_eq!(field(&reject, 45).as_deref(), Some("2"));
    assert_eq!(field(&reject, 372).as_deref(), Some("D"));
    assert_eq!(field(&reject, 373).as_deref(), Some("18"));
    assert_eq!(field(&reject, 371).as_deref(), Some("1128"));
    assert_eq!(field(&reject, 34).as_deref(), Some("2"));
    let text = some(field(&reject, 58), "the Reject says why");
    assert!(text.contains("ApplVerID (1128) 7 (FIX.5.0)"), "{text}");
    assert_no_app_message(&mut venue_rx, "the rejected order").await;
    assert_eq!(connection.next_target_seq(), 3, "its number is consumed");
    assert_eq!(store.next_target_seq(), 3, "and persisted");

    // The next message, without 1128, is in sequence and delivered.
    ok(
        framed.send(client_fixt("D", 3, &[], &ORDER_BODY)).await,
        "client sends an order in its default version",
    );
    assert_eq!(
        next_app_message(&mut venue_rx).await,
        ("D".to_string(), "3".to_string(), None)
    );
    assert_silent(&mut framed, "no ResendRequest for the rejected number").await;
    assert_eq!(connection.next_target_seq(), 4);
    assert_eq!(store.next_target_seq(), 4);

    // The session is still up.
    ok(
        framed
            .send(client_fixt("1", 4, &[], &[(112, "STILL-THERE")]))
            .await,
        "client sends a TestRequest",
    );
    let heartbeat = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&heartbeat), "0");
    assert_eq!(field(&heartbeat, 112).as_deref(), Some("STILL-THERE"));
}

/// A message whose `ApplVerID` names a FIX 4.x version (FIX 4.4 carried over
/// FIXT.1.1), or is repeated, is rejected too (18 and 13 respectively), each
/// consuming its number.
#[tokio::test]
async fn test_fix4_or_repeated_appl_ver_id_is_rejected() {
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let acceptor = Arc::new(Acceptor::new(
        venue_config("FIX.5.0SP2"),
        Arc::clone(&venue_app),
    ));
    let (mut framed, connection, _ack) =
        establish(acceptor, client_fixt_logon(1, &[(1137, "9")])).await;

    ok(
        framed
            .send(client_fixt("D", 2, &[(1128, "6")], &ORDER_BODY))
            .await,
        "client sends a FIX.4.4-over-FIXT order",
    );
    let reject = next_frame(&mut framed).await;
    assert_eq!(field(&reject, 373).as_deref(), Some("18"));
    assert_eq!(field(&reject, 371).as_deref(), Some("1128"));
    let text = some(field(&reject, 58), "the Reject says why");
    assert!(
        text.contains("ApplVerID (1128) 6 (FIX.4.4) is not an application version"),
        "{text}"
    );

    ok(
        framed
            .send(client_fixt(
                "D",
                3,
                &[(1128, "9"), (1128, "9")],
                &ORDER_BODY,
            ))
            .await,
        "client sends an order with 1128 twice",
    );
    let reject = next_frame(&mut framed).await;
    assert_eq!(field(&reject, 45).as_deref(), Some("3"));
    assert_eq!(field(&reject, 373).as_deref(), Some("13"));
    assert_eq!(field(&reject, 371).as_deref(), Some("1128"));

    assert_no_app_message(&mut venue_rx, "neither order").await;
    assert_eq!(connection.next_target_seq(), 4);
}

/// The initiator runs the same reactor: an inbound report with a disallowed
/// `ApplVerID` is rejected there too and never reaches `from_app`.
#[tokio::test]
async fn test_initiator_rejects_a_disallowed_appl_ver_id_in_session() {
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let mut framed = fixt_venue_ack(listener, &[(1137, "9")]).await;
        ok(
            framed
                .send(peer_frame(
                    "FIXT.1.1",
                    "VENUE",
                    "CLIENT",
                    "8",
                    2,
                    &[(1128, "8")],
                    &REPORT_BODY,
                ))
                .await,
            "the venue sends a FIX.5.0SP1 report",
        );
        let reject = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&reject), "3");
        assert_eq!(field(&reject, 45).as_deref(), Some("2"));
        assert_eq!(field(&reject, 373).as_deref(), Some("18"));
        assert_eq!(field(&reject, 371).as_deref(), Some("1128"));
        framed
    });

    let (client_app, mut client_rx) = RecordingApp::new();
    let connection = ok(
        Initiator::new(client_config("FIX.5.0SP2"), Arc::clone(&client_app))
            .connect(addr)
            .await,
        "the initiator logs on",
    );
    let _framed = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );
    assert_no_app_message(&mut client_rx, "the rejected report").await;
    assert_eq!(connection.next_target_seq(), 3);
}

// ---------------------------------------------------------------------------
// FIX 4.x sessions are unaffected
// ---------------------------------------------------------------------------

/// A FIX.4.2 or FIX.4.4 acceptor takes a Logon without 1137 to Active (a
/// stray 1137 is not inspected), and delivers an application message
/// carrying a 1128 that a FIXT session would reject: neither field belongs
/// to FIX 4.x, so neither is checked.
#[tokio::test]
async fn test_fix4_sessions_are_unaffected() {
    for version in ["FIX.4.2", "FIX.4.4"] {
        for logon_extra in [&[][..], &[(1137, "7")][..]] {
            let (venue_app, mut venue_rx) = RecordingApp::new();
            let acceptor = Arc::new(Acceptor::new(venue_config(version), Arc::clone(&venue_app)));
            let mut body = vec![(98, "0"), (108, "30")];
            body.extend_from_slice(logon_extra);
            let logon = peer_frame(version, "CLIENT", "VENUE", "A", 1, &[], &body);
            let (mut framed, connection, ack) = establish(acceptor, logon).await;
            assert_eq!(field(&ack, 1137), None, "{version} declares no 1137");
            assert!(venue_app.logged_on(), "{version} reaches Active");

            ok(
                framed
                    .send(peer_frame(
                        version,
                        "CLIENT",
                        "VENUE",
                        "D",
                        2,
                        &[],
                        &[
                            (11, "ORDER-1"),
                            (55, "EUR/USD"),
                            (54, "1"),
                            (38, "100"),
                            (1128, "7"),
                        ],
                    ))
                    .await,
                "client sends an order",
            );
            let (msg_type, seq, appl_ver_id) = next_app_message(&mut venue_rx).await;
            assert_eq!((msg_type.as_str(), seq.as_str()), ("D", "2"));
            assert_eq!(appl_ver_id.as_deref(), Some("7"), "{version} delivers it");
            assert_silent(&mut framed, "no Reject on a FIX 4.x session").await;
            assert_eq!(connection.next_target_seq(), 3);
        }
    }
}

/// A FIX.4.4 initiator accepts an acknowledgement carrying a stray 1137.
#[tokio::test]
async fn test_fix44_initiator_ignores_a_stray_default_appl_ver_id() {
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (socket, _) = ok(listener.accept().await, "the venue accepts");
        let mut framed = Framed::new(socket, FixCodec::new());
        let logon = next_frame(&mut framed).await;
        assert_eq!(field(&logon, 1137), None);
        ok(
            framed
                .send(peer_frame(
                    "FIX.4.4",
                    "VENUE",
                    "CLIENT",
                    "A",
                    1,
                    &[],
                    &[(98, "0"), (108, "30"), (1137, "7")],
                ))
                .await,
            "the venue acknowledges",
        );
        assert_silent(&mut framed, "no Reject on a FIX 4.4 session").await;
        framed
    });
    let (client_app, _rx) = RecordingApp::new();
    let _connection = ok(
        Initiator::new(client_config("FIX.4.4"), Arc::clone(&client_app))
            .connect(addr)
            .await,
        "the FIX.4.4 initiator logs on",
    );
    let _framed = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );
}

/// An allowed set on a FIX 4.x session is a configuration error, reported by
/// both engines before any connection is taken or dialled.
#[tokio::test]
async fn test_allowed_appl_versions_on_a_fix4_session_is_a_config_error() {
    let expected = SessionConfigError::UnusableApplVersion {
        version: FixVersion::Fix50Sp2,
        begin_string: "FIX.4.4".to_string(),
    };

    let (listener, _addr) = bind_listener().await;
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config("FIX.4.4").with_allowed_appl_versions([FixVersion::Fix50Sp2]),
        Arc::clone(&venue_app),
    );
    match acceptor.accept(&listener).await {
        Err(EngineError::Config(err)) => assert_eq!(err, expected),
        other => panic!("expected a configuration error, got {other:?}"),
    }

    let (client_app, _rx) = RecordingApp::new();
    let initiator = Initiator::new(
        client_config("FIX.4.4").with_allowed_appl_versions([FixVersion::Fix50Sp2]),
        Arc::clone(&client_app),
    );
    // Port 9 (discard) is never dialled: the configuration is refused first.
    match initiator.connect("127.0.0.1:9").await {
        Err(EngineError::Config(err)) => assert_eq!(err, expected),
        other => panic!("expected a configuration error, got {other:?}"),
    }
    assert!(venue_app.events().is_empty() && client_app.events().is_empty());
}

// ---------------------------------------------------------------------------
// A session routed by an AcceptorRegistry
// ---------------------------------------------------------------------------

/// A FIX.5.0SP2 session routed by an `AcceptorRegistry` checks 1137 and 1128
/// exactly as one served directly: a Logon declaring FIX.5.0 is refused with a
/// Logout; one declaring SP2 reaches Active, where a FIX.5.0 message is
/// rejected and a default-version one delivered.
#[tokio::test]
async fn test_registry_routed_fixt_session_checks_application_versions() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let registry = Arc::new(AcceptorRegistry::new());
    ok(
        registry.register(Acceptor::new(
            venue_config("FIX.5.0SP2"),
            Arc::clone(&venue_app),
        )),
        "the FIXT session registers",
    );
    let serving = Arc::clone(&registry);
    let (results_tx, mut results) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        for _ in 0..2 {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let _ = results_tx.send(serving.serve(stream).await);
        }
    });

    // Refused: 1137=7.
    let stream = ok(TcpStream::connect(addr).await, "peer connects");
    let mut refused = Framed::new(stream, FixCodec::new());
    ok(
        refused.send(client_fixt_logon(1, &[(1137, "7")])).await,
        "peer logs on declaring FIX.5.0",
    );
    let logout = next_frame(&mut refused).await;
    assert_eq!(msg_type_of(&logout), "5");
    assert!(
        some(field(&logout, 58), "the Logout says why").contains("1137"),
        "the Logout names DefaultApplVerID"
    );
    let result = some(
        ok(
            timeout(Duration::from_secs(5), results.recv()).await,
            "the refusal is reported within 5s",
        ),
        "the server stays up",
    );
    assert_appl_version_refusal(&result, &["1137"]);
    assert!(!venue_app.logged_on());

    // Accepted: 1137=9. Without a store nothing of the refused attempt
    // persists, so the new connection starts again from 1.
    let stream = ok(TcpStream::connect(addr).await, "peer reconnects");
    let mut framed = Framed::new(stream, FixCodec::new());
    ok(
        framed.send(client_fixt_logon(1, &[(1137, "9")])).await,
        "peer logs on declaring FIX.5.0SP2",
    );
    let ack = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&ack), "A");
    assert_eq!(field(&ack, 1137).as_deref(), Some("9"));
    let connection = ok(
        some(
            ok(
                timeout(Duration::from_secs(5), results.recv()).await,
                "the session is reported within 5s",
            ),
            "the server stays up",
        ),
        "the routed session is established",
    );
    assert_eq!(
        connection.session_id().to_string(),
        "FIX.5.0SP2:VENUE->CLIENT"
    );

    ok(
        framed
            .send(client_fixt("D", 2, &[(1128, "7")], &ORDER_BODY))
            .await,
        "peer sends a FIX.5.0 order",
    );
    let reject = next_frame(&mut framed).await;
    assert_eq!(field(&reject, 373).as_deref(), Some("18"));
    assert_eq!(field(&reject, 371).as_deref(), Some("1128"));
    ok(
        framed.send(client_fixt("D", 3, &[], &ORDER_BODY)).await,
        "peer sends an order in its default version",
    );
    assert_eq!(
        next_app_message(&mut venue_rx).await,
        ("D".to_string(), "3".to_string(), None)
    );
    assert_eq!(connection.next_target_seq(), 4);
}
