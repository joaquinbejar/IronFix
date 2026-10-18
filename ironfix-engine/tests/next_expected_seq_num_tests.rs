/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Integration tests for `NextExpectedMsgSeqNum` (789) on the Logon exchange
//! (issue #79), in both roles.
//!
//! With `SessionConfig::send_next_expected_msg_seq_num` set, the initiator's
//! Logon and the acceptor's acknowledgement declare the next `MsgSeqNum` each
//! expects (1 on a `ResetSeqNumFlag` (141) Logon, 2 on the acknowledgement of
//! one, the first missing number after a gapped Logon), and each acts on the
//! counterparty's: a 789 below its own Logon or acknowledgement makes it
//! resend exactly the range the counterparty missed once Active (stored
//! application messages with `PossDupFlag` (43) = Y and `OrigSendingTime`
//! (122), everything else gap-filled, and without a store one gap fill),
//! stopping before its own Logon; a 789 above the next number it sends is
//! refused with a Logout and `EngineError::NextExpectedMsgSeqNum`, before
//! `on_logon`; a 789 that is 0, not a number or repeated is refused without a
//! panic. A gap in the Logon's own `MsgSeqNum` still draws a `ResendRequest`.
//! With the flag off nothing changes: no 789 is sent and a counterparty's is
//! ignored. FIX.4.2 with the flag on is a configuration error in both roles.
//! A session routed by an `AcceptorRegistry` behaves like one served directly,
//! and a real `Initiator` reconnecting to a real `Acceptor` over `FileStore`s
//! gets back what it missed. Scripted peers play the counterparty over real
//! loopback sockets where a real engine cannot send what a test needs.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::error::StoreError;
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::{CompId, Timestamp};
use ironfix_core::version::FixVersion;
use ironfix_engine::application::{Application, RejectReason, SessionId};
use ironfix_engine::{
    Acceptor, AcceptorRegistry, Connection, EngineError, Initiator, OutboundMessage,
    StoreFailurePolicy,
};
use ironfix_session::{SessionConfig, SessionConfigError};
use ironfix_store::{FileStore, FileStoreConfig, MemoryStore, MessageStore, StoredMessage};
use ironfix_tagvalue::{Decoder, Encoder};
use ironfix_transport::FixCodec;
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

/// Acceptor-side configuration: sender VENUE, target CLIENT.
fn venue_config(version: &str) -> SessionConfig {
    SessionConfig::new(comp_id("VENUE"), comp_id("CLIENT"), version)
        .with_heartbeat_interval(Duration::from_secs(30))
}

/// Initiator-side configuration: sender CLIENT, target VENUE.
fn client_config(version: &str) -> SessionConfig {
    SessionConfig::new(comp_id("CLIENT"), comp_id("VENUE"), version)
        .with_heartbeat_interval(Duration::from_secs(30))
}

/// An acceptor configuration in FIX.4.4 with 789 on.
fn venue_789() -> SessionConfig {
    venue_config("FIX.4.4").with_send_next_expected_msg_seq_num(true)
}

/// An initiator configuration in FIX.4.4 with 789 on.
fn client_789() -> SessionConfig {
    client_config("FIX.4.4").with_send_next_expected_msg_seq_num(true)
}

/// An application message as `from_app` saw it: `(MsgType, MsgSeqNum,
/// PossDupFlag, OrigSendingTime)`.
type AppMessage = (String, String, Option<String>, Option<String>);

/// Records session events (including the 789 of every inbound Logon) and
/// forwards every application message.
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
    fn record(&self, event: String) {
        match self.events.lock() {
            Ok(mut events) => events.push(event),
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
        self.record("create".to_string());
    }

    async fn on_logon(&self, _session_id: &SessionId) {
        self.record("logon".to_string());
    }

    async fn on_logout(&self, _session_id: &SessionId) {
        self.record("logout".to_string());
    }

    async fn to_admin(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_admin(
        &self,
        message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        if message.msg_type() == &MsgType::Logon {
            self.record(format!(
                "logon 789={}",
                message.get_field_str(789).unwrap_or("-")
            ));
        }
        if message.msg_type() == &MsgType::ResendRequest {
            self.record("resend request".to_string());
        }
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
            message.get_field_str(43).map(str::to_string),
            message.get_field_str(122).map(str::to_string),
        ));
        Ok(())
    }
}

/// A scripted counterparty's frame under `begin_string`: MsgType, the CompIDs,
/// `MsgSeqNum`, `SendingTime`, then `body`.
#[track_caller]
fn peer_frame(
    begin_string: &str,
    sender: &str,
    target: &str,
    msg_type: &str,
    seq: u64,
    body: &[(u32, &str)],
) -> BytesMut {
    let mut encoder = Encoder::new(begin_string);
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

/// A FIX.4.4 frame from the scripted initiator (CLIENT -> VENUE).
#[track_caller]
fn client_msg(msg_type: &str, seq: u64, body: &[(u32, &str)]) -> BytesMut {
    peer_frame("FIX.4.4", "CLIENT", "VENUE", msg_type, seq, body)
}

/// A FIX.4.4 frame from the scripted acceptor (VENUE -> CLIENT).
#[track_caller]
fn venue_msg(msg_type: &str, seq: u64, body: &[(u32, &str)]) -> BytesMut {
    peer_frame("FIX.4.4", "VENUE", "CLIENT", msg_type, seq, body)
}

/// A FIX.4.4 Logon from the scripted initiator, numbered `seq`, carrying
/// `extra` after `EncryptMethod` (98) = 0 and `HeartBtInt` (108) = 30.
#[track_caller]
fn client_logon(seq: u64, extra: &[(u32, &str)]) -> BytesMut {
    let mut body = vec![(98, "0"), (108, "30")];
    body.extend_from_slice(extra);
    client_msg("A", seq, &body)
}

/// A FIX.4.4 Logon acknowledgement from the scripted acceptor, numbered
/// `seq`, carrying `extra` after 98 and 108.
#[track_caller]
fn venue_ack(seq: u64, extra: &[(u32, &str)]) -> BytesMut {
    let mut body = vec![(98, "0"), (108, "30")];
    body.extend_from_slice(extra);
    venue_msg("A", seq, &body)
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
        panic!(
            "{what}: unexpected MsgType {} at {:?}",
            msg_type_of(&frame),
            field(&frame, 34)
        );
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

/// Asserts `frame` is a `SequenceReset`-GapFill numbered `seq` with
/// `NewSeqNo` (36) = `new_seq`, `PossDupFlag` (43) = Y and an
/// `OrigSendingTime` (122).
#[track_caller]
fn assert_gap_fill(frame: &[u8], seq: u64, new_seq: u64) {
    assert_eq!(msg_type_of(frame), "4", "a SequenceReset");
    assert_eq!(field(frame, 123).as_deref(), Some("Y"), "GapFill mode");
    assert_eq!(field(frame, 34), Some(seq.to_string()), "gap fill number");
    assert_eq!(field(frame, 36), Some(new_seq.to_string()), "NewSeqNo");
    assert_eq!(field(frame, 43).as_deref(), Some("Y"));
    assert!(field(frame, 122).is_some(), "PossDup requires 122");
}

/// The fields of `frame`, in order, without the ones a resend may change:
/// BodyLength (9), CheckSum (10), PossDupFlag (43), SendingTime (52) and
/// OrigSendingTime (122).
fn resend_invariant_fields(frame: &[u8]) -> Vec<(u32, Vec<u8>)> {
    let mut decoder = Decoder::new(frame);
    let raw = ok(decoder.decode(), "frame must decode");
    raw.fields()
        .filter(|field| !matches!(field.tag, 9 | 10 | 43 | 52 | 122))
        .map(|field| (field.tag, field.value.to_vec()))
        .collect()
}

/// Asserts that `replayed` is `original` resent: every field the same, in the
/// same order, apart from the ones a resend changes, with `PossDupFlag` (43) =
/// Y and the original `SendingTime` (52) as `OrigSendingTime` (122).
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

/// Asserts `result` is a `NextExpectedMsgSeqNum` refusal whose detail
/// mentions every string in `mentions`.
#[track_caller]
fn assert_next_expected_refusal<T: std::fmt::Debug>(
    result: &Result<T, EngineError>,
    mentions: &[&str],
) {
    match result {
        Err(EngineError::NextExpectedMsgSeqNum { detail }) => {
            for mention in mentions {
                assert!(detail.contains(mention), "'{mention}' not in '{detail}'");
            }
        }
        other => panic!("expected EngineError::NextExpectedMsgSeqNum, got {other:?}"),
    }
}

/// Sends `logon` from a scripted initiator to `acceptor`, and returns what
/// `accept` returned and every frame received before the acceptor hung up.
async fn refused_logon<A: Application + 'static>(
    acceptor: Arc<Acceptor<A>>,
    logon: BytesMut,
) -> (Result<Connection, EngineError>, Vec<BytesMut>) {
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
        frames.push(frame);
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

/// Plays an acceptor: takes the initiator's connection and reads its Logon.
async fn read_client_logon(listener: TcpListener) -> (Framed<TcpStream, FixCodec>, BytesMut) {
    let (socket, _) = ok(listener.accept().await, "the venue accepts");
    let mut framed = Framed::new(socket, FixCodec::new());
    let logon = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&logon), "A");
    (framed, logon)
}

/// The acceptor's previous stream, filed in a store: its Logon ack (1), two
/// ExecutionReports (2 and 4) around a Heartbeat (3); next sender 5, next
/// target 3. Returns the store and the two filed reports.
async fn seeded_venue_store() -> (Arc<MemoryStore>, BytesMut, BytesMut) {
    let store = Arc::new(MemoryStore::new());
    let report_2 = venue_msg("8", 2, &REPORT_BODY);
    let report_4 = venue_msg("8", 4, &REPORT_BODY);
    for (seq, msg_type, frame) in [
        (1u64, MsgType::Logon, venue_ack(1, &[])),
        (2, MsgType::ExecutionReport, report_2.clone()),
        (3, MsgType::Heartbeat, venue_msg("0", 3, &[])),
        (4, MsgType::ExecutionReport, report_4.clone()),
    ] {
        ok(
            store.store(seq, &msg_type, &frame).await,
            "seed the journal",
        );
    }
    ok(
        store.set_next_sender_seq(5).await,
        "seed the sender counter",
    );
    ok(
        store.set_next_target_seq(3).await,
        "seed the target counter",
    );
    (store, report_2, report_4)
}

/// The initiator's previous stream, filed in a store: its Logon (1), orders
/// at 2, 3 and 5 around a Heartbeat (4); next sender 6, next target 3.
/// Returns the store and the three filed orders.
async fn seeded_client_store() -> (Arc<MemoryStore>, [BytesMut; 3]) {
    let store = Arc::new(MemoryStore::new());
    let orders = [
        client_msg("D", 2, &ORDER_BODY),
        client_msg("D", 3, &ORDER_BODY),
        client_msg("D", 5, &ORDER_BODY),
    ];
    for (seq, msg_type, frame) in [
        (1u64, MsgType::Logon, client_logon(1, &[])),
        (2, MsgType::NewOrderSingle, orders[0].clone()),
        (3, MsgType::NewOrderSingle, orders[1].clone()),
        (4, MsgType::Heartbeat, client_msg("0", 4, &[])),
        (5, MsgType::NewOrderSingle, orders[2].clone()),
    ] {
        ok(
            store.store(seq, &msg_type, &frame).await,
            "seed the journal",
        );
    }
    ok(
        store.set_next_sender_seq(6).await,
        "seed the sender counter",
    );
    ok(
        store.set_next_target_seq(3).await,
        "seed the target counter",
    );
    (store, orders)
}

// ---------------------------------------------------------------------------
// Acceptor: the acknowledgement declares 789
// ---------------------------------------------------------------------------

/// With the flag on, the acknowledgement declares the next number expected
/// from the initiator once its Logon is processed (FIX.4.4 and FIXT.1.1);
/// with it off, no 789 is sent.
#[tokio::test]
async fn test_acceptor_ack_declares_next_expected_only_when_enabled() {
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Arc::new(Acceptor::new(venue_789(), Arc::clone(&venue_app)));
    let (_framed, connection, ack) = establish(acceptor, client_logon(1, &[])).await;
    assert_eq!(field(&ack, 34).as_deref(), Some("1"));
    assert_eq!(
        field(&ack, 789).as_deref(),
        Some("2"),
        "the Logon is consumed"
    );
    assert_eq!(field(&ack, 141), None);
    assert!(venue_app.logged_on());
    assert_eq!(connection.next_target_seq(), 2);

    // FIXT.1.1: 789 sits before DefaultApplVerID (1137).
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Arc::new(Acceptor::new(
        venue_config("FIX.5.0SP2").with_send_next_expected_msg_seq_num(true),
        Arc::clone(&venue_app),
    ));
    let fixt_logon = peer_frame(
        "FIXT.1.1",
        "CLIENT",
        "VENUE",
        "A",
        1,
        &[(98, "0"), (108, "30"), (1137, "9")],
    );
    let (_framed, _connection, ack) = establish(acceptor, fixt_logon).await;
    assert_eq!(field(&ack, 789).as_deref(), Some("2"));
    assert_eq!(field(&ack, 1137).as_deref(), Some("9"));

    // Off: no 789.
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Arc::new(Acceptor::new(
        venue_config("FIX.4.4"),
        Arc::clone(&venue_app),
    ));
    let (_framed, _connection, ack) = establish(acceptor, client_logon(1, &[])).await;
    assert_eq!(field(&ack, 789), None, "the flag is off");
}

/// A `ResetSeqNumFlag` (141) Logon declaring 789 = 1 is acknowledged at 1
/// with 141 = Y and 789 = 2: the initiator's Logon is message 1 of the new
/// stream. The store is reset and nothing is replayed.
#[tokio::test]
async fn test_acceptor_reset_logon_declaring_789_1_is_acked_with_789_2() {
    let (store, _, _) = seeded_venue_store().await;
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(venue_789(), Arc::clone(&venue_app))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );
    let (mut framed, connection, ack) =
        establish(acceptor, client_logon(1, &[(141, "Y"), (789, "1")])).await;
    assert_eq!(field(&ack, 34).as_deref(), Some("1"));
    assert_eq!(field(&ack, 141).as_deref(), Some("Y"));
    assert_eq!(field(&ack, 789).as_deref(), Some("2"));
    assert_silent(&mut framed, "nothing is replayed after a reset").await;
    assert_eq!(connection.next_sender_seq(), 2);
    assert!(
        !store.contains(2) && !store.contains(4),
        "the store was reset"
    );
    assert!(venue_app.events().contains(&"logon 789=1".to_string()));
}

// ---------------------------------------------------------------------------
// Acceptor: the initiator's 789 below the next number sent
// ---------------------------------------------------------------------------

/// The initiator's 789 = 1 against an acceptor whose acknowledgement goes out
/// at 5: once Active the acceptor resends exactly 1..=4, its own
/// acknowledgement excluded. The application messages (2 and 4) are replayed
/// from the store with `PossDupFlag` = Y and their original `SendingTime` in
/// `OrigSendingTime`; the stored Logon (1) and Heartbeat (3) are gap-filled.
#[tokio::test]
async fn test_acceptor_replays_exactly_the_missed_range_from_its_store() {
    let (store, report_2, report_4) = seeded_venue_store().await;
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(venue_789(), Arc::clone(&venue_app))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );
    let (mut framed, connection, ack) = establish(acceptor, client_logon(3, &[(789, "1")])).await;
    assert_eq!(field(&ack, 34).as_deref(), Some("5"));
    assert_eq!(field(&ack, 789).as_deref(), Some("4"));
    assert!(venue_app.logged_on());

    assert_gap_fill(&next_frame(&mut framed).await, 1, 2);
    assert_resent(&next_frame(&mut framed).await, &report_2);
    assert_gap_fill(&next_frame(&mut framed).await, 3, 4);
    assert_resent(&next_frame(&mut framed).await, &report_4);
    assert_silent(&mut framed, "nothing at or past the acknowledgement").await;
    assert_eq!(
        connection.next_sender_seq(),
        6,
        "a replay allocates no sender number"
    );
}

/// Without a store there is nothing to replay: the missed range is answered
/// with one gap fill, from the initiator's 789 up to the acknowledgement.
#[tokio::test]
async fn test_acceptor_without_a_store_gap_fills_the_missed_range() {
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor =
        Arc::new(Acceptor::new(venue_789(), Arc::clone(&venue_app)).with_initial_sequences(5, 3));
    let (mut framed, _connection, ack) = establish(acceptor, client_logon(3, &[(789, "2")])).await;
    assert_eq!(field(&ack, 34).as_deref(), Some("5"));
    assert_gap_fill(&next_frame(&mut framed).await, 2, 5);
    assert_silent(&mut framed, "one gap fill covers the range").await;
}

/// A 789 naming the acknowledgement's own number asks for nothing.
#[tokio::test]
async fn test_acceptor_in_step_next_expected_replays_nothing() {
    let (store, _, _) = seeded_venue_store().await;
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(venue_789(), Arc::clone(&venue_app))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );
    let (mut framed, _connection, ack) = establish(acceptor, client_logon(3, &[(789, "5")])).await;
    assert_eq!(field(&ack, 34).as_deref(), Some("5"));
    assert_silent(&mut framed, "the initiator has everything").await;
}

// ---------------------------------------------------------------------------
// Acceptor: refusals
// ---------------------------------------------------------------------------

/// A 789 above the next number the acceptor sends claims messages never
/// sent: a Logout saying so, numbered from the store and filed, no
/// `on_logon`, the typed error, and the Logon not consumed.
#[tokio::test]
async fn test_acceptor_refuses_a_next_expected_ahead_of_what_was_sent() {
    let (store, _, _) = seeded_venue_store().await;
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(venue_789(), Arc::clone(&venue_app))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );
    let (result, frames) = refused_logon(acceptor, client_logon(3, &[(789, "6")])).await;

    assert_next_expected_refusal(&result, &["789", "6", "higher than expected", "5"]);
    assert_eq!(frames.len(), 1, "one Logout");
    assert_eq!(msg_type_of(&frames[0]), "5");
    assert_eq!(field(&frames[0], 34).as_deref(), Some("5"));
    let text = some(field(&frames[0], 58), "the Logout says why");
    assert!(text.contains("NextExpectedMsgSeqNum (789)"), "{text}");
    assert!(!venue_app.logged_on(), "on_logon never runs");
    assert!(store.contains(5), "the Logout is filed");
    assert!(store.contains(2) && store.contains(4), "nothing was reset");
    assert_eq!(store.next_sender_seq(), 6);
    assert_eq!(store.next_target_seq(), 3, "the Logon is not consumed");
}

/// A `ResetSeqNumFlag` Logon must declare 789 = 1, since the acknowledgement
/// of a reset is message 1: anything above is refused before the store is
/// reset, with a Logout numbered from the previous stream.
#[tokio::test]
async fn test_acceptor_refuses_a_reset_logon_whose_next_expected_is_not_1() {
    let (store, _, _) = seeded_venue_store().await;
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(venue_789(), Arc::clone(&venue_app))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );
    let (result, frames) =
        refused_logon(acceptor, client_logon(1, &[(141, "Y"), (789, "3")])).await;

    assert_next_expected_refusal(&result, &["789", "3"]);
    assert_eq!(frames.len(), 1, "one Logout");
    assert_eq!(msg_type_of(&frames[0]), "5");
    assert_eq!(field(&frames[0], 34).as_deref(), Some("5"));
    assert!(!venue_app.logged_on());
    for seq in 1..=5u64 {
        assert!(store.contains(seq), "the store was not reset (frame {seq})");
    }
}

/// A 789 that is 0, not a number, signed or repeated is refused with a
/// Logout and the typed error, without a panic and without `on_logon`.
#[tokio::test]
async fn test_acceptor_refuses_a_malformed_next_expected_without_panic() {
    let cases: [(&[(u32, &str)], &str); 4] = [
        (&[(789, "0")], "is 0"),
        (&[(789, "abc")], "'abc' is not a sequence number"),
        (&[(789, "+2")], "'+2' is not a sequence number"),
        (&[(789, "1"), (789, "1")], "more than once"),
    ];
    for (extra, mention) in cases {
        let (venue_app, _rx) = RecordingApp::new();
        let acceptor = Arc::new(Acceptor::new(venue_789(), Arc::clone(&venue_app)));
        let (result, frames) = refused_logon(acceptor, client_logon(1, extra)).await;
        assert_next_expected_refusal(&result, &["789", mention]);
        assert_eq!(frames.len(), 1, "one Logout for {extra:?}");
        assert_eq!(msg_type_of(&frames[0]), "5");
        assert!(!venue_app.logged_on(), "{extra:?}");
    }
}

// ---------------------------------------------------------------------------
// Acceptor: a gapped Logon, held or requested
// ---------------------------------------------------------------------------

/// Both sides declared 789 and the Logon is gapped (3 expected, 6 received):
/// the acknowledgement declares 789 = 3, and no `ResendRequest` goes out,
/// since the initiator resends 3..=5 on its own because of that 789. The
/// Logon is held and its number consumed once the gap below it is filled:
/// the next number expected is then 7, persisted, and a message at 7 is
/// delivered.
#[tokio::test]
async fn test_acceptor_holds_a_gapped_logon_when_both_sides_declared_789() {
    let store = Arc::new(MemoryStore::new());
    ok(
        store.set_next_target_seq(3).await,
        "seed the target counter",
    );
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(venue_789(), Arc::clone(&venue_app))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );
    let (mut framed, connection, ack) = establish(acceptor, client_logon(6, &[(789, "1")])).await;
    assert_eq!(field(&ack, 34).as_deref(), Some("1"));
    assert_eq!(field(&ack, 789).as_deref(), Some("3"));
    assert_silent(&mut framed, "no ResendRequest crosses the 789 resend").await;
    assert_eq!(connection.next_target_seq(), 3, "the Logon is held");

    // The initiator's 789 resend: 3 and 4 filled, 5 replayed.
    ok(
        framed
            .send(client_msg("4", 3, &[(123, "Y"), (36, "5")]))
            .await,
        "the client fills 3..=4",
    );
    ok(
        framed.send(client_msg("D", 5, &ORDER_BODY)).await,
        "the client resends 5",
    );
    assert_eq!(next_app_message(&mut venue_rx).await.1, "5");
    assert_eq!(
        connection.next_target_seq(),
        7,
        "the held Logon (6) is consumed"
    );
    assert_eq!(store.next_target_seq(), 7, "and its number persisted");

    ok(
        framed.send(client_msg("D", 7, &ORDER_BODY)).await,
        "the client sends a live order",
    );
    assert_eq!(next_app_message(&mut venue_rx).await.1, "7");
    assert_silent(&mut framed, "no ResendRequest at any point").await;
}

/// A counterparty that fills the gap through its own Logon (one gap fill from
/// the expected number to the Logon's plus one) releases the hold: the
/// expectation jumps past the held Logon, which is not consumed a second
/// time.
#[tokio::test]
async fn test_acceptor_gap_fill_past_the_held_logon_clears_the_hold() {
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let acceptor =
        Arc::new(Acceptor::new(venue_789(), Arc::clone(&venue_app)).with_initial_sequences(1, 3));
    let (mut framed, connection, _ack) = establish(acceptor, client_logon(6, &[(789, "1")])).await;
    ok(
        framed
            .send(client_msg("4", 3, &[(123, "Y"), (36, "7")]))
            .await,
        "the client fills 3..=6",
    );
    ok(
        framed.send(client_msg("D", 7, &ORDER_BODY)).await,
        "the client sends a live order",
    );
    assert_eq!(next_app_message(&mut venue_rx).await.1, "7");
    assert_eq!(connection.next_target_seq(), 8);
    assert_silent(&mut framed, "no ResendRequest").await;
}

/// The fallback: the initiator declared 789 but never resends. Nothing goes
/// out before the resend timeout; then exactly one `ResendRequest` (from the
/// first missing number, open-ended) does, even with a limit of one request,
/// and once it too goes unanswered the session is logged out.
#[tokio::test]
async fn test_acceptor_held_logon_falls_back_to_one_resend_request() {
    let resend_timeout = Duration::from_millis(400);
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(
            venue_789()
                .with_resend_timeout(resend_timeout)
                .with_max_resend_requests(1),
            Arc::clone(&venue_app),
        )
        .with_initial_sequences(1, 3),
    );
    let (mut framed, _connection, _ack) = establish(acceptor, client_logon(6, &[(789, "1")])).await;
    let held_at = std::time::Instant::now();
    let request = next_frame(&mut framed).await;
    assert!(
        held_at.elapsed() >= resend_timeout / 2,
        "nothing before the resend timeout"
    );
    assert_eq!(msg_type_of(&request), "2");
    assert_eq!(field(&request, 7).as_deref(), Some("3"));
    assert_eq!(field(&request, 16).as_deref(), Some("0"));
    let logout = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&logout), "5", "one request only, then a Logout");
}

/// A resend from the scripted initiator: `body` with `PossDupFlag` (43) = Y
/// and an `OrigSendingTime` (122).
#[track_caller]
fn client_resend(msg_type: &str, seq: u64, body: &[(u32, &str)]) -> BytesMut {
    let mut fields = vec![(43, "Y"), (122, "20261018-12:00:00.000")];
    fields.extend_from_slice(body);
    client_msg(msg_type, seq, &fields)
}

/// Frames from beyond the held Logon that overtake the resend are not
/// requested when the held Logon is consumed: a counterparty such as
/// QuickFIX/C++ resends them too, and a request then would cross that resend.
/// A counterparty that does not resend them gets one `ResendRequest`, from the
/// first missing number, once the gap has made no progress for the resend
/// timeout.
#[tokio::test]
async fn test_acceptor_does_not_request_frames_past_the_held_logon_on_release() {
    let resend_timeout = Duration::from_millis(600);
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(
            venue_789().with_resend_timeout(resend_timeout),
            Arc::clone(&venue_app),
        )
        .with_initial_sequences(1, 3),
    );
    let (mut framed, connection, _ack) = establish(acceptor, client_logon(6, &[(789, "1")])).await;
    ok(
        framed.send(client_msg("D", 7, &ORDER_BODY)).await,
        "a live order overtakes the resend",
    );
    ok(
        framed
            .send(client_msg("4", 3, &[(123, "Y"), (36, "6")]))
            .await,
        "the client fills 3..=5 and stops there",
    );
    let released_at = std::time::Instant::now();
    assert_silent(&mut framed, "no request when the held Logon is consumed").await;
    assert_eq!(
        connection.next_target_seq(),
        7,
        "the held Logon (6) is consumed"
    );

    let request = next_frame(&mut framed).await;
    assert!(
        released_at.elapsed() >= resend_timeout / 2,
        "the request waits for the resend timeout"
    );
    assert_eq!(msg_type_of(&request), "2");
    assert_eq!(field(&request, 7).as_deref(), Some("7"));
    assert_eq!(field(&request, 16).as_deref(), Some("0"));
    ok(
        framed.send(client_resend("D", 7, &ORDER_BODY)).await,
        "the client resends 7",
    );
    assert_eq!(next_app_message(&mut venue_rx).await.1, "7");
}

/// The QuickFIX/C++ shape: the initiator's application sends live orders
/// (7, 8) from its `onLogon`, before its retransmit, and the retransmit runs
/// through its own Logon and those live orders: 3..=5 replayed, a gap fill for
/// its Logon (6), then 7 and 8 again. The Logon is consumed when 5 arrives,
/// the gap fill for it is dropped as a possible duplicate below the
/// expectation, 7 and 8 are delivered from the retransmit, and no
/// `ResendRequest` goes out at any point.
#[tokio::test]
async fn test_acceptor_absorbs_a_retransmit_through_the_peers_logon_without_a_request() {
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let acceptor =
        Arc::new(Acceptor::new(venue_789(), Arc::clone(&venue_app)).with_initial_sequences(1, 3));
    let (mut framed, connection, _ack) = establish(acceptor, client_logon(6, &[(789, "1")])).await;
    for seq in [7u64, 8] {
        ok(
            framed.send(client_msg("D", seq, &ORDER_BODY)).await,
            "a live order sent from onLogon",
        );
    }
    for seq in [3u64, 4, 5] {
        ok(
            framed.send(client_resend("D", seq, &ORDER_BODY)).await,
            "the retransmit below the Logon",
        );
    }
    ok(
        framed
            .send(client_resend("4", 6, &[(123, "Y"), (36, "7")]))
            .await,
        "the retransmit gap-fills the Logon",
    );
    for seq in [7u64, 8] {
        ok(
            framed.send(client_resend("D", seq, &ORDER_BODY)).await,
            "the retransmit of the live orders",
        );
    }
    let mut delivered = Vec::new();
    for _ in 0..5 {
        delivered.push(next_app_message(&mut venue_rx).await.1);
    }
    assert_eq!(delivered, ["3", "4", "5", "7", "8"]);
    assert_eq!(connection.next_target_seq(), 9);
    assert_silent(&mut framed, "no ResendRequest at any point").await;
}

/// Once the fallback request has gone out, the hold is dropped: the answer to
/// that request covers the Logon itself, so the Logon is not consumed
/// locally. Here an administrative frame past the held Logon (a Heartbeat at
/// 7) arrived live during the hold, the fallback requests 3 onwards, and the
/// answer replays 3..=5 and covers 6..=7 with one gap fill numbered 6. That
/// fill is in sequence, so the recovery is complete at 8, with a limit of one
/// request and no Logout or further request after it.
#[tokio::test]
async fn test_acceptor_fallback_request_drops_the_hold_and_its_answer_completes_recovery() {
    let resend_timeout = Duration::from_millis(400);
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(
            venue_789()
                .with_resend_timeout(resend_timeout)
                .with_max_resend_requests(1),
            Arc::clone(&venue_app),
        )
        .with_initial_sequences(1, 3),
    );
    let (mut framed, connection, _ack) = establish(acceptor, client_logon(6, &[(789, "1")])).await;
    ok(
        framed.send(client_msg("0", 7, &[])).await,
        "a live Heartbeat past the held Logon",
    );
    let request = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&request), "2", "the fallback fires");
    assert_eq!(field(&request, 7).as_deref(), Some("3"));

    // The answer to ResendRequest(3, 0) from a peer whose next number is 8.
    for seq in [3u64, 4, 5] {
        ok(
            framed.send(client_resend("D", seq, &ORDER_BODY)).await,
            "the answer replays an order",
        );
    }
    ok(
        framed
            .send(client_resend("4", 6, &[(123, "Y"), (36, "8")]))
            .await,
        "the answer gap-fills 6..=7",
    );
    for expected in ["3", "4", "5"] {
        assert_eq!(next_app_message(&mut venue_rx).await.1, expected);
    }
    if let Ok(Some(Ok(frame))) = timeout(resend_timeout * 3, framed.next()).await {
        panic!(
            "the recovery is complete: unexpected MsgType {}",
            msg_type_of(&frame)
        );
    }
    assert_eq!(connection.next_target_seq(), 8, "the fill covered 6 and 7");
    assert!(
        !venue_app.events().contains(&"logout".to_string()),
        "no Logout"
    );
}

/// The fallback went out, then the initiator's own 789 resend arrives late
/// (3..=5, stopping before its Logon), followed by the answer to the request.
/// With the hold dropped, 6 is not consumed when 5 arrives; the answer's
/// replays of 3..=5 are dropped as duplicates and its gap fill at 6 is in
/// sequence, so the recovery completes at 8 with no further request.
#[tokio::test]
async fn test_acceptor_late_789_resend_after_the_fallback_completes_recovery() {
    let resend_timeout = Duration::from_millis(400);
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(
            venue_789()
                .with_resend_timeout(resend_timeout)
                .with_max_resend_requests(1),
            Arc::clone(&venue_app),
        )
        .with_initial_sequences(1, 3),
    );
    let (mut framed, connection, _ack) = establish(acceptor, client_logon(6, &[(789, "1")])).await;
    let request = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&request), "2", "the fallback fires");

    // The late 789 resend, then the answer to the request.
    for seq in [3u64, 4, 5] {
        ok(
            framed.send(client_resend("D", seq, &ORDER_BODY)).await,
            "the 789 resend",
        );
    }
    for seq in [3u64, 4, 5] {
        ok(
            framed.send(client_resend("D", seq, &ORDER_BODY)).await,
            "the answer replays an order again",
        );
    }
    ok(
        framed
            .send(client_resend("4", 6, &[(123, "Y"), (36, "8")]))
            .await,
        "the answer gap-fills 6..=7",
    );
    for expected in ["3", "4", "5"] {
        assert_eq!(next_app_message(&mut venue_rx).await.1, expected);
    }
    if let Ok(Some(Ok(frame))) = timeout(resend_timeout * 3, framed.next()).await {
        panic!(
            "the recovery is complete: unexpected MsgType {}",
            msg_type_of(&frame)
        );
    }
    assert_eq!(connection.next_target_seq(), 8);
}

/// Partial progress keeps the recovery implied: the initiator resends 3, then
/// stalls. Exactly one real `ResendRequest` (from 4) goes out once the gap has
/// made no progress for the resend timeout, even with a limit of one request,
/// and the Logout follows when it too goes unanswered.
#[tokio::test]
async fn test_acceptor_partial_resend_then_stall_gets_exactly_one_request() {
    let resend_timeout = Duration::from_millis(400);
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(
            venue_789()
                .with_resend_timeout(resend_timeout)
                .with_max_resend_requests(1),
            Arc::clone(&venue_app),
        )
        .with_initial_sequences(1, 3),
    );
    let (mut framed, _connection, _ack) = establish(acceptor, client_logon(6, &[(789, "1")])).await;
    ok(
        framed.send(client_resend("D", 3, &ORDER_BODY)).await,
        "the client resends 3 and stalls",
    );
    assert_eq!(next_app_message(&mut venue_rx).await.1, "3");
    let request = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&request), "2");
    assert_eq!(field(&request, 7).as_deref(), Some("4"));
    assert_eq!(field(&request, 16).as_deref(), Some("0"));
    let logout = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&logout), "5", "one request only, then a Logout");
}

/// A `SequenceReset` in Reset mode during the hold moves the expectation, and
/// the held Logon (6) follows it: a reset below it (5) keeps the hold, and the
/// Logon is consumed once 5 arrives; a reset to it (6) consumes it at once; a
/// reset above it (8) drops the hold.
#[tokio::test]
async fn test_acceptor_sequence_reset_during_the_hold() {
    for (new_seq, after_reset) in [("5", 5u64), ("6", 7), ("8", 8)] {
        let (venue_app, mut venue_rx) = RecordingApp::new();
        let acceptor = Arc::new(
            Acceptor::new(venue_789(), Arc::clone(&venue_app)).with_initial_sequences(1, 3),
        );
        let (mut framed, connection, _ack) =
            establish(acceptor, client_logon(6, &[(789, "1")])).await;
        ok(
            framed.send(client_msg("4", 7, &[(36, new_seq)])).await,
            "the client resets the sequence",
        );
        assert_silent(&mut framed, "a reset draws no request").await;
        assert_eq!(
            connection.next_target_seq(),
            after_reset,
            "after a reset to {new_seq}"
        );
        if after_reset == 5 {
            ok(
                framed.send(client_msg("D", 5, &ORDER_BODY)).await,
                "the client sends 5",
            );
            assert_eq!(next_app_message(&mut venue_rx).await.1, "5");
            assert_eq!(connection.next_target_seq(), 7, "the held Logon follows 5");
        }
    }
}

/// A `TestRequest` arriving during the hold, past the held Logon, is answered
/// with a Heartbeat echoing its `TestReqID` (112); its number is not consumed
/// and no `ResendRequest` goes out.
#[tokio::test]
async fn test_acceptor_test_request_during_the_hold() {
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor =
        Arc::new(Acceptor::new(venue_789(), Arc::clone(&venue_app)).with_initial_sequences(1, 3));
    let (mut framed, connection, _ack) = establish(acceptor, client_logon(6, &[(789, "1")])).await;
    ok(
        framed.send(client_msg("1", 7, &[(112, "PING-7")])).await,
        "the client sends a TestRequest",
    );
    let heartbeat = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&heartbeat), "0");
    assert_eq!(field(&heartbeat, 112).as_deref(), Some("PING-7"));
    assert_silent(&mut framed, "no ResendRequest").await;
    assert_eq!(
        connection.next_target_seq(),
        3,
        "the TestRequest is not consumed"
    );
}

/// A Logout arriving during the hold is answered with a Logout and ends the
/// session, with no `ResendRequest` before it.
#[tokio::test]
async fn test_acceptor_logout_during_the_hold() {
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor =
        Arc::new(Acceptor::new(venue_789(), Arc::clone(&venue_app)).with_initial_sequences(1, 3));
    let (mut framed, connection, _ack) = establish(acceptor, client_logon(6, &[(789, "1")])).await;
    ok(
        framed.send(client_msg("5", 7, &[])).await,
        "the client logs out",
    );
    let reply = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&reply), "5", "a Logout, and no request first");
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "the session closes within 5s",
    );
    assert!(venue_app.events().contains(&"logout".to_string()));
}

/// A store whose write of one particular next target number fails.
#[derive(Debug)]
struct FailTargetStore {
    inner: MemoryStore,
    fail_target: AtomicU64,
}

#[async_trait]
impl MessageStore for FailTargetStore {
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
        self.inner.set_next_sender_seq(seq).await
    }

    async fn set_next_target_seq(&self, seq: u64) -> Result<(), StoreError> {
        if seq == self.fail_target.load(Ordering::SeqCst) {
            return Err(StoreError::Io(
                "target write refused by the test store".to_string(),
            ));
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

/// Under `StoreFailurePolicy::CloseSession` the held Logon's number is
/// persisted before the expectation moves past it: when that write (7) fails,
/// the session closes, without a Logout, and the expectation is still 6, in
/// memory and in the store.
#[tokio::test]
async fn test_acceptor_held_logon_is_persisted_before_it_is_consumed() {
    let store = Arc::new(FailTargetStore {
        inner: MemoryStore::new(),
        fail_target: AtomicU64::new(7),
    });
    ok(
        store.inner.set_next_target_seq(3).await,
        "seed the target counter",
    );
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(venue_789(), Arc::clone(&venue_app))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
            .with_store_failure_policy(StoreFailurePolicy::CloseSession),
    );
    let (mut framed, connection, _ack) = establish(acceptor, client_logon(6, &[(789, "1")])).await;
    ok(
        framed
            .send(client_msg("4", 3, &[(123, "Y"), (36, "6")]))
            .await,
        "the client fills 3..=5",
    );
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "the session closes within 5s",
    );
    assert_eq!(
        connection.next_target_seq(),
        6,
        "the expectation did not move past the held Logon"
    );
    assert_eq!(store.next_target_seq(), 6);
    let after: Vec<String> = {
        let mut frames = Vec::new();
        while let Ok(Some(Ok(frame))) = timeout(Duration::from_secs(2), framed.next()).await {
            frames.push(msg_type_of(&frame));
        }
        frames
    };
    assert!(
        !after
            .iter()
            .any(|msg_type| msg_type == "5" || msg_type == "2"),
        "closed without a Logout or a request: {after:?}"
    );
}

/// Both sides missed messages and both declared 789: a real `Initiator` and a
/// real `Acceptor`, each over a `MemoryStore` holding the previous stream,
/// each hold the other's gapped Logon, resend what the other missed, consume
/// the held number once the other's resend arrives, and then exchange live
/// messages in sequence, with no `ResendRequest` either way.
#[tokio::test]
async fn test_both_sides_hold_at_once() {
    // Each side sent its Logon (1) and two application messages (2, 3), and
    // received only the other's Logon: next sender 4, next target 2.
    let client_store = Arc::new(MemoryStore::new());
    for (seq, msg_type, frame) in [
        (1u64, MsgType::Logon, client_logon(1, &[])),
        (2, MsgType::NewOrderSingle, client_msg("D", 2, &ORDER_BODY)),
        (3, MsgType::NewOrderSingle, client_msg("D", 3, &ORDER_BODY)),
    ] {
        ok(client_store.store(seq, &msg_type, &frame).await, "seed");
    }
    let venue_store = Arc::new(MemoryStore::new());
    for (seq, msg_type, frame) in [
        (1u64, MsgType::Logon, venue_ack(1, &[])),
        (2, MsgType::ExecutionReport, venue_msg("8", 2, &REPORT_BODY)),
        (3, MsgType::ExecutionReport, venue_msg("8", 3, &REPORT_BODY)),
    ] {
        ok(venue_store.store(seq, &msg_type, &frame).await, "seed");
    }
    for store in [&client_store, &venue_store] {
        ok(
            store.set_next_sender_seq(4).await,
            "seed the sender counter",
        );
        ok(
            store.set_next_target_seq(2).await,
            "seed the target counter",
        );
    }

    let (listener, addr) = bind_listener().await;
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(venue_789(), Arc::clone(&venue_app))
        .with_store(Arc::clone(&venue_store) as Arc<dyn MessageStore>);
    let venue = tokio::spawn(async move { acceptor.accept(&listener).await });
    let (client_app, mut client_rx) = RecordingApp::new();
    let client = ok(
        Initiator::new(client_789(), Arc::clone(&client_app))
            .with_store(Arc::clone(&client_store) as Arc<dyn MessageStore>)
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

    // Each side gets the other's 2 and 3 again, flagged as resends.
    for _ in 0..2 {
        assert_eq!(
            next_app_message(&mut client_rx).await.2.as_deref(),
            Some("Y")
        );
        assert_eq!(
            next_app_message(&mut venue_rx).await.2.as_deref(),
            Some("Y")
        );
    }

    let mut report = OutboundMessage::new(MsgType::ExecutionReport);
    report
        .push_str(37, "EX-LIVE")
        .push_str(17, "E-LIVE")
        .push_char(150, '0')
        .push_char(39, '0');
    ok(venue_connection.send(report).await, "a live report");
    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order.push_str(11, "ORDER-LIVE");
    ok(client.send(order).await, "a live order");
    let live_report = next_app_message(&mut client_rx).await;
    let live_order = next_app_message(&mut venue_rx).await;
    assert_eq!((live_report.1.as_str(), live_report.2), ("5", None));
    assert_eq!((live_order.1.as_str(), live_order.2), ("5", None));
    for (side, events) in [
        ("client", client_app.events()),
        ("venue", venue_app.events()),
    ] {
        assert!(
            !events.iter().any(|event| event == "resend request"),
            "no ResendRequest reached the {side}: {events:?}"
        );
    }
}

/// A gapped Logon that declares no 789 is not held: the counterparty is not
/// known to resend anything on its own, so the gap is requested at once.
#[tokio::test]
async fn test_acceptor_gapped_logon_without_789_still_requests_a_resend() {
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor =
        Arc::new(Acceptor::new(venue_789(), Arc::clone(&venue_app)).with_initial_sequences(1, 3));
    let (mut framed, _connection, ack) = establish(acceptor, client_logon(6, &[])).await;
    assert_eq!(field(&ack, 789).as_deref(), Some("3"));
    let request = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&request), "2");
    assert_eq!(field(&request, 7).as_deref(), Some("3"));
    assert_eq!(field(&request, 16).as_deref(), Some("0"));
}

/// A reset this side drives (`reset_on_logon`) discards the stream the
/// initiator's 789 describes, so its value is ignored: the acknowledgement is
/// message 1 of the new stream, with 141 = Y and 789 = 2.
#[tokio::test]
async fn test_acceptor_local_reset_ignores_the_initiators_next_expected() {
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Arc::new(Acceptor::new(
        venue_789().with_reset_on_logon(true),
        Arc::clone(&venue_app),
    ));
    let (mut framed, _connection, ack) = establish(acceptor, client_logon(5, &[(789, "9")])).await;
    assert_eq!(field(&ack, 34).as_deref(), Some("1"));
    assert_eq!(field(&ack, 141).as_deref(), Some("Y"));
    assert_eq!(field(&ack, 789).as_deref(), Some("2"));
    assert!(venue_app.logged_on());
    assert_silent(&mut framed, "nothing to replay in a new stream").await;
}

/// With the flag off a counterparty's 789 is ignored, as before: even one far
/// above what was sent reaches Active, and the acknowledgement carries none.
#[tokio::test]
async fn test_acceptor_with_the_flag_off_ignores_the_initiators_next_expected() {
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Arc::new(Acceptor::new(
        venue_config("FIX.4.4"),
        Arc::clone(&venue_app),
    ));
    let (mut framed, _connection, ack) = establish(acceptor, client_logon(1, &[(789, "99")])).await;
    assert_eq!(field(&ack, 789), None);
    assert!(venue_app.logged_on());
    assert_silent(&mut framed, "nothing is replayed").await;
}

/// FIX.4.2 does not define 789: the flag on a FIX.4.2 session is a
/// configuration error in both roles, reported before a connection is taken
/// or dialled.
#[tokio::test]
async fn test_next_expected_on_a_fix42_session_is_a_config_error_in_both_roles() {
    let expected = SessionConfigError::NextExpectedMsgSeqNumUnsupported {
        begin_string: "FIX.4.2".to_string(),
    };

    let (listener, _addr) = bind_listener().await;
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config("FIX.4.2").with_send_next_expected_msg_seq_num(true),
        Arc::clone(&venue_app),
    );
    match acceptor.accept(&listener).await {
        Err(EngineError::Config(err)) => assert_eq!(err, expected),
        other => panic!("expected a configuration error, got {other:?}"),
    }

    let (client_app, _rx) = RecordingApp::new();
    let initiator = Initiator::new(
        client_config("FIX.4.2").with_send_next_expected_msg_seq_num(true),
        Arc::clone(&client_app),
    );
    // Port 9 (discard) is never dialled: the configuration is refused first.
    match initiator.connect("127.0.0.1:9").await {
        Err(EngineError::Config(err)) => assert_eq!(err, expected),
        other => panic!("expected a configuration error, got {other:?}"),
    }
    assert!(venue_app.events().is_empty() && client_app.events().is_empty());
}

/// A FIX.4.2 session with the flag off sends no 789, in either role.
#[tokio::test]
async fn test_fix42_sessions_send_no_next_expected() {
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Arc::new(Acceptor::new(
        venue_config("FIX.4.2"),
        Arc::clone(&venue_app),
    ));
    let logon = peer_frame(
        "FIX.4.2",
        "CLIENT",
        "VENUE",
        "A",
        1,
        &[(98, "0"), (108, "30")],
    );
    let (_framed, _connection, ack) = establish(acceptor, logon).await;
    assert_eq!(field(&ack, 789), None);

    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (_framed, logon) = read_client_logon(listener).await;
        field(&logon, 789)
    });
    let (client_app, _rx) = RecordingApp::new();
    let _ = Initiator::new(client_config("FIX.4.2"), Arc::clone(&client_app))
        .connect(addr)
        .await;
    let declared = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );
    assert_eq!(declared, None);
}

// ---------------------------------------------------------------------------
// Acceptor: a session routed by an AcceptorRegistry
// ---------------------------------------------------------------------------

/// A session routed by an `AcceptorRegistry` honours 789 as one served
/// directly: a Logon whose 789 is above what was sent is refused with a
/// Logout, and one below it gets exactly the missed range.
#[tokio::test]
async fn test_registry_routed_session_honours_next_expected() {
    let (store, report_2, report_4) = seeded_venue_store().await;
    let (listener, addr) = bind_listener().await;
    let (venue_app, _rx) = RecordingApp::new();
    let registry = Arc::new(AcceptorRegistry::new());
    ok(
        registry.register(
            Acceptor::new(venue_789(), Arc::clone(&venue_app))
                .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
        ),
        "the session registers",
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

    // Refused: 789 = 6 against a next sender number of 5.
    let stream = ok(TcpStream::connect(addr).await, "peer connects");
    let mut refused = Framed::new(stream, FixCodec::new());
    ok(
        refused.send(client_logon(3, &[(789, "6")])).await,
        "peer logs on expecting 6",
    );
    let logout = next_frame(&mut refused).await;
    assert_eq!(msg_type_of(&logout), "5");
    assert_eq!(field(&logout, 34).as_deref(), Some("5"));
    let result = some(
        ok(
            timeout(Duration::from_secs(5), results.recv()).await,
            "the refusal is reported within 5s",
        ),
        "the server stays up",
    );
    assert_next_expected_refusal(&result, &["789"]);
    assert!(!venue_app.logged_on());

    // Accepted: 789 = 2, after the refusal's Logout took 5.
    let stream = ok(TcpStream::connect(addr).await, "peer reconnects");
    let mut framed = Framed::new(stream, FixCodec::new());
    ok(
        framed.send(client_logon(3, &[(789, "2")])).await,
        "peer logs on expecting 2",
    );
    let ack = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&ack), "A");
    assert_eq!(field(&ack, 34).as_deref(), Some("6"));
    let _connection = ok(
        some(
            ok(
                timeout(Duration::from_secs(5), results.recv()).await,
                "the session is reported within 5s",
            ),
            "the server stays up",
        ),
        "the routed session is established",
    );
    assert_resent(&next_frame(&mut framed).await, &report_2);
    assert_gap_fill(&next_frame(&mut framed).await, 3, 4);
    assert_resent(&next_frame(&mut framed).await, &report_4);
    // The refusal's Logout (5) is administrative: gap-filled up to the ack.
    assert_gap_fill(&next_frame(&mut framed).await, 5, 6);
    assert_silent(&mut framed, "nothing at or past the acknowledgement").await;
}

// ---------------------------------------------------------------------------
// Initiator: the Logon declares 789
// ---------------------------------------------------------------------------

/// With the flag on, the Logon declares the next number expected from the
/// acceptor (the seeded target counter); with it off, none.
#[tokio::test]
async fn test_initiator_logon_declares_next_expected_only_when_enabled() {
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (mut framed, logon) = read_client_logon(listener).await;
        assert_eq!(field(&logon, 34).as_deref(), Some("4"));
        assert_eq!(field(&logon, 789).as_deref(), Some("7"));
        assert_eq!(field(&logon, 141), None);
        ok(
            framed.send(venue_ack(7, &[(789, "5")])).await,
            "the venue acknowledges",
        );
        assert_silent(&mut framed, "in step: nothing replayed").await;
        framed
    });
    let (client_app, _rx) = RecordingApp::new();
    let connection = ok(
        Initiator::new(client_789(), Arc::clone(&client_app))
            .with_initial_sequences(4, 7)
            .connect(addr)
            .await,
        "the initiator logs on",
    );
    assert!(client_app.logged_on());
    assert_eq!(connection.next_target_seq(), 8);
    let _framed = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );

    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (mut framed, logon) = read_client_logon(listener).await;
        ok(
            framed.send(venue_ack(1, &[])).await,
            "the venue acknowledges",
        );
        (framed, field(&logon, 789))
    });
    let (client_app, _rx) = RecordingApp::new();
    let _connection = ok(
        Initiator::new(client_config("FIX.4.4"), Arc::clone(&client_app))
            .connect(addr)
            .await,
        "the initiator logs on",
    );
    let (_framed, declared) = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );
    assert_eq!(declared, None, "the flag is off");
}

/// A Logon declaring `ResetSeqNumFlag` (141) = Y declares 789 = 1: the
/// acknowledgement of a reset is message 1.
#[tokio::test]
async fn test_initiator_reset_logon_declares_next_expected_1() {
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (mut framed, logon) = read_client_logon(listener).await;
        assert_eq!(field(&logon, 34).as_deref(), Some("1"));
        assert_eq!(field(&logon, 141).as_deref(), Some("Y"));
        assert_eq!(field(&logon, 789).as_deref(), Some("1"));
        ok(
            framed.send(venue_ack(1, &[(141, "Y"), (789, "2")])).await,
            "the venue acknowledges the reset",
        );
        assert_silent(&mut framed, "nothing replayed after a reset").await;
        framed
    });
    let (client_app, _rx) = RecordingApp::new();
    let connection = ok(
        Initiator::new(
            client_789().with_reset_on_logon(true),
            Arc::clone(&client_app),
        )
        .with_initial_sequences(9, 9)
        .connect(addr)
        .await,
        "the initiator logs on",
    );
    assert_eq!(connection.next_sender_seq(), 2);
    assert_eq!(connection.next_target_seq(), 2);
    assert!(client_app.events().contains(&"logon 789=2".to_string()));
    let _framed = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );
}

// ---------------------------------------------------------------------------
// Initiator: the acceptor's 789 below the next number sent
// ---------------------------------------------------------------------------

/// The acknowledgement's 789 = 2 against an initiator whose Logon went out at
/// 6: once Active it resends exactly 2..=5, its Logon excluded. The orders (2,
/// 3, 5) are replayed from the store with `PossDupFlag` = Y and their original
/// `SendingTime` in `OrigSendingTime`; the Heartbeat (4) is gap-filled.
#[tokio::test]
async fn test_initiator_replays_exactly_the_missed_range_from_its_store() {
    let (store, orders) = seeded_client_store().await;
    let [order_2, order_3, order_5] = orders;
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (mut framed, logon) = read_client_logon(listener).await;
        assert_eq!(field(&logon, 34).as_deref(), Some("6"));
        assert_eq!(field(&logon, 789).as_deref(), Some("3"));
        ok(
            framed.send(venue_ack(3, &[(789, "2")])).await,
            "the venue acknowledges, expecting 2",
        );
        assert_resent(&next_frame(&mut framed).await, &order_2);
        assert_resent(&next_frame(&mut framed).await, &order_3);
        assert_gap_fill(&next_frame(&mut framed).await, 4, 5);
        assert_resent(&next_frame(&mut framed).await, &order_5);
        assert_silent(&mut framed, "nothing at or past the Logon").await;
        framed
    });
    let (client_app, _rx) = RecordingApp::new();
    let connection = ok(
        Initiator::new(client_789(), Arc::clone(&client_app))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
            .connect(addr)
            .await,
        "the initiator logs on",
    );
    assert!(client_app.logged_on());
    let _framed = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );
    assert_eq!(
        connection.next_sender_seq(),
        7,
        "a replay allocates no sender number"
    );
}

/// Without a store the missed range is answered with one gap fill, from the
/// acknowledgement's 789 up to the Logon.
#[tokio::test]
async fn test_initiator_without_a_store_gap_fills_the_missed_range() {
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (mut framed, logon) = read_client_logon(listener).await;
        assert_eq!(field(&logon, 34).as_deref(), Some("6"));
        ok(
            framed.send(venue_ack(3, &[(789, "2")])).await,
            "the venue acknowledges, expecting 2",
        );
        assert_gap_fill(&next_frame(&mut framed).await, 2, 6);
        assert_silent(&mut framed, "one gap fill covers the range").await;
        framed
    });
    let (client_app, _rx) = RecordingApp::new();
    let _connection = ok(
        Initiator::new(client_789(), Arc::clone(&client_app))
            .with_initial_sequences(6, 3)
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
}

// ---------------------------------------------------------------------------
// Initiator: refusals
// ---------------------------------------------------------------------------

/// An acknowledgement whose 789 is above the next number the initiator sends
/// (its Logon was 6, so 7) is refused with a Logout alone, no `on_logon` and
/// the typed error; 789 = 7 is in step.
#[tokio::test]
async fn test_initiator_refuses_an_ack_whose_next_expected_is_ahead() {
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (mut framed, _logon) = read_client_logon(listener).await;
        ok(
            framed.send(venue_ack(3, &[(789, "8")])).await,
            "the venue acknowledges, expecting 8",
        );
        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5", "a Logout, and no Reject first");
        assert_eq!(field(&logout, 34).as_deref(), Some("7"));
        let text = some(field(&logout, 58), "the Logout says why");
        assert!(text.contains("NextExpectedMsgSeqNum (789) 8"), "{text}");
    });
    let (client_app, _rx) = RecordingApp::new();
    let result = Initiator::new(client_789(), Arc::clone(&client_app))
        .with_initial_sequences(6, 3)
        .connect(addr)
        .await;
    assert_next_expected_refusal(&result, &["789", "8", "higher than expected", "7"]);
    assert!(!client_app.logged_on(), "on_logon never runs");
    ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );

    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (mut framed, _logon) = read_client_logon(listener).await;
        ok(
            framed.send(venue_ack(3, &[(789, "7")])).await,
            "the venue acknowledges, expecting 7",
        );
        assert_silent(&mut framed, "in step").await;
        framed
    });
    let (client_app, _rx) = RecordingApp::new();
    let _connection = ok(
        Initiator::new(client_789(), Arc::clone(&client_app))
            .with_initial_sequences(6, 3)
            .connect(addr)
            .await,
        "789 = 7 is in step",
    );
    assert!(client_app.logged_on());
    let _framed = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );
}

/// An acknowledgement whose 789 is 0, not a number, or repeated is refused
/// like its other malformed fields: a Reject (373 = 5, 6 or 13; 371 = 789;
/// 45 = the ack's number) and a Logout, without a panic.
#[tokio::test]
async fn test_initiator_refuses_a_malformed_next_expected_with_a_reject() {
    let cases: [(&[(u32, &str)], &str); 3] = [
        (&[(789, "0")], "5"),
        (&[(789, "abc")], "6"),
        (&[(789, "2"), (789, "2")], "13"),
    ];
    for (extra, code) in cases {
        let (listener, addr) = bind_listener().await;
        let extra_owned: Vec<(u32, String)> = extra
            .iter()
            .map(|(tag, value)| (*tag, (*value).to_string()))
            .collect();
        let expected_code = code.to_string();
        let venue = tokio::spawn(async move {
            let borrowed: Vec<(u32, &str)> = extra_owned
                .iter()
                .map(|(tag, value)| (*tag, value.as_str()))
                .collect();
            let (mut framed, _logon) = read_client_logon(listener).await;
            ok(
                framed.send(venue_ack(1, &borrowed)).await,
                "the venue acknowledges",
            );
            let reject = next_frame(&mut framed).await;
            assert_eq!(msg_type_of(&reject), "3");
            assert_eq!(field(&reject, 45).as_deref(), Some("1"));
            assert_eq!(field(&reject, 372).as_deref(), Some("A"));
            assert_eq!(field(&reject, 373), Some(expected_code));
            assert_eq!(field(&reject, 371).as_deref(), Some("789"));
            let logout = next_frame(&mut framed).await;
            assert_eq!(msg_type_of(&logout), "5");
        });
        let (client_app, _rx) = RecordingApp::new();
        let result = Initiator::new(client_789(), Arc::clone(&client_app))
            .connect(addr)
            .await;
        assert_next_expected_refusal(&result, &["789"]);
        assert!(!client_app.logged_on(), "{extra:?}");
        ok(
            ok(
                timeout(Duration::from_secs(5), venue).await,
                "venue done within 5s",
            ),
            "venue task",
        );
    }
}

// ---------------------------------------------------------------------------
// Initiator: a gapped acknowledgement, held or requested
// ---------------------------------------------------------------------------

/// Both sides declared 789 and the acknowledgement is gapped (1 expected, 4
/// received): no `ResendRequest` goes out, since the acceptor resends 1..=3 on
/// its own because of the Logon's 789. The ack is held and its number
/// consumed once the gap below it is filled, and a live message at 5 is then
/// delivered in sequence.
#[tokio::test]
async fn test_initiator_holds_a_gapped_ack_when_both_sides_declared_789() {
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (mut framed, logon) = read_client_logon(listener).await;
        assert_eq!(field(&logon, 789).as_deref(), Some("1"));
        ok(
            framed.send(venue_ack(4, &[(789, "2")])).await,
            "the venue acknowledges at 4",
        );
        assert_silent(&mut framed, "no ResendRequest crosses the 789 resend").await;
        ok(
            framed
                .send(venue_msg("4", 1, &[(123, "Y"), (36, "4")]))
                .await,
            "the venue fills 1..=3",
        );
        ok(
            framed.send(venue_msg("8", 5, &REPORT_BODY)).await,
            "the venue sends a live report",
        );
        assert_silent(&mut framed, "no ResendRequest at any point").await;
        framed
    });
    let (client_app, mut client_rx) = RecordingApp::new();
    let connection = ok(
        Initiator::new(client_789(), Arc::clone(&client_app))
            .connect(addr)
            .await,
        "a gapped ack still establishes the session",
    );
    assert_eq!(next_app_message(&mut client_rx).await.1, "5");
    assert_eq!(
        connection.next_target_seq(),
        6,
        "the held ack (4) was consumed"
    );
    let _framed = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );
}

/// On the initiator side too, one gap fill from the expected number past the
/// held acknowledgement clears the hold.
#[tokio::test]
async fn test_initiator_gap_fill_past_the_held_ack_clears_the_hold() {
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (mut framed, _logon) = read_client_logon(listener).await;
        ok(
            framed.send(venue_ack(4, &[(789, "2")])).await,
            "the venue acknowledges at 4",
        );
        ok(
            framed
                .send(venue_msg("4", 1, &[(123, "Y"), (36, "5")]))
                .await,
            "the venue fills 1..=4",
        );
        ok(
            framed.send(venue_msg("8", 5, &REPORT_BODY)).await,
            "the venue sends a live report",
        );
        assert_silent(&mut framed, "no ResendRequest").await;
        framed
    });
    let (client_app, mut client_rx) = RecordingApp::new();
    let connection = ok(
        Initiator::new(client_789(), Arc::clone(&client_app))
            .connect(addr)
            .await,
        "the session is established",
    );
    assert_eq!(next_app_message(&mut client_rx).await.1, "5");
    assert_eq!(connection.next_target_seq(), 6);
    let _framed = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );
}

/// The fallback on the initiator side: the acceptor declared 789 but never
/// resends. Exactly one `ResendRequest` goes out after the resend timeout,
/// even with a limit of one request, and then the session is logged out.
#[tokio::test]
async fn test_initiator_held_ack_falls_back_to_one_resend_request() {
    let resend_timeout = Duration::from_millis(400);
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (mut framed, _logon) = read_client_logon(listener).await;
        ok(
            framed.send(venue_ack(4, &[(789, "2")])).await,
            "the venue acknowledges at 4",
        );
        let held_at = std::time::Instant::now();
        let request = next_frame(&mut framed).await;
        assert!(
            held_at.elapsed() >= resend_timeout / 2,
            "nothing before the resend timeout"
        );
        assert_eq!(msg_type_of(&request), "2");
        assert_eq!(field(&request, 34).as_deref(), Some("2"));
        assert_eq!(field(&request, 7).as_deref(), Some("1"));
        assert_eq!(field(&request, 16).as_deref(), Some("0"));
        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5", "one request only, then a Logout");
    });
    let (client_app, _rx) = RecordingApp::new();
    let _connection = ok(
        Initiator::new(
            client_789()
                .with_resend_timeout(resend_timeout)
                .with_max_resend_requests(1),
            Arc::clone(&client_app),
        )
        .connect(addr)
        .await,
        "the session is established",
    );
    ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );
}

/// A gapped acknowledgement that declares no 789 is not held: the gap is
/// requested as the session's first act.
#[tokio::test]
async fn test_initiator_gapped_ack_without_789_still_requests_a_resend() {
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (mut framed, _logon) = read_client_logon(listener).await;
        ok(
            framed.send(venue_ack(4, &[])).await,
            "the venue acknowledges at 4 without 789",
        );
        let request = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&request), "2");
        assert_eq!(field(&request, 7).as_deref(), Some("1"));
        assert_eq!(field(&request, 16).as_deref(), Some("0"));
        framed
    });
    let (client_app, _rx) = RecordingApp::new();
    let _connection = ok(
        Initiator::new(client_789(), Arc::clone(&client_app))
            .connect(addr)
            .await,
        "a gapped ack still establishes the session",
    );
    let _framed = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );
}

/// A reset the acceptor declares on its acknowledgement makes the initiator's
/// Logon message 1 of the new stream, so the ack's 789 is compared with 1 and
/// 2: 789 = 2 is in step, and 789 = 3 is refused with a Logout numbered from
/// the previous stream, before the reset is made.
#[tokio::test]
async fn test_initiator_compares_next_expected_with_the_acks_reset_counters() {
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (mut framed, logon) = read_client_logon(listener).await;
        assert_eq!(field(&logon, 34).as_deref(), Some("6"));
        assert_eq!(field(&logon, 789).as_deref(), Some("3"));
        ok(
            framed.send(venue_ack(1, &[(141, "Y"), (789, "2")])).await,
            "the venue resets",
        );
        assert_silent(&mut framed, "nothing replayed in a new stream").await;
        framed
    });
    let (client_app, _rx) = RecordingApp::new();
    let connection = ok(
        Initiator::new(client_789(), Arc::clone(&client_app))
            .with_initial_sequences(6, 3)
            .connect(addr)
            .await,
        "the reset ack is accepted",
    );
    assert_eq!(connection.next_sender_seq(), 2);
    assert_eq!(connection.next_target_seq(), 2);
    let _framed = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );

    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (mut framed, _logon) = read_client_logon(listener).await;
        ok(
            framed.send(venue_ack(1, &[(141, "Y"), (789, "3")])).await,
            "the venue resets, expecting 3",
        );
        let logout = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&logout), "5");
        assert_eq!(field(&logout, 34).as_deref(), Some("7"));
    });
    let (client_app, _rx) = RecordingApp::new();
    let result = Initiator::new(client_789(), Arc::clone(&client_app))
        .with_initial_sequences(6, 3)
        .connect(addr)
        .await;
    assert_next_expected_refusal(&result, &["789", "3", "2"]);
    assert!(!client_app.logged_on());
    ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );
}

/// With the flag off an acknowledgement's 789 is ignored, as before.
#[tokio::test]
async fn test_initiator_with_the_flag_off_ignores_the_acks_next_expected() {
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (mut framed, _logon) = read_client_logon(listener).await;
        ok(
            framed.send(venue_ack(1, &[(789, "99")])).await,
            "the venue acknowledges, expecting 99",
        );
        assert_silent(&mut framed, "nothing is replayed or refused").await;
        framed
    });
    let (client_app, _rx) = RecordingApp::new();
    let _connection = ok(
        Initiator::new(client_config("FIX.4.4"), Arc::clone(&client_app))
            .connect(addr)
            .await,
        "the ack is accepted",
    );
    assert!(client_app.logged_on());
    let _framed = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );
}

// ---------------------------------------------------------------------------
// Owed resets, a store behind a refusal, and FIXT.1.1 end to end
// ---------------------------------------------------------------------------

/// A store whose `reset` can be made to fail, to leave a reset owed.
#[derive(Debug)]
struct FlakyResetStore {
    inner: MemoryStore,
    fail_reset: AtomicBool,
}

impl FlakyResetStore {
    fn new() -> Self {
        Self {
            inner: MemoryStore::new(),
            fail_reset: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl MessageStore for FlakyResetStore {
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
        self.inner.set_next_sender_seq(seq).await
    }

    async fn set_next_target_seq(&self, seq: u64) -> Result<(), StoreError> {
        self.inner.set_next_target_seq(seq).await
    }

    async fn reset(&self) -> Result<(), StoreError> {
        if self.fail_reset.load(Ordering::SeqCst) {
            return Err(StoreError::Io(
                "reset refused by the test store".to_string(),
            ));
        }
        self.inner.reset().await
    }

    fn creation_time(&self) -> std::time::SystemTime {
        self.inner.creation_time()
    }
}

/// A reset an earlier session owes (its close-time reset failed) is one this
/// side drives: the next Logon, which did not ask for it, has its 789 ignored,
/// since that 789 describes the stream the reset discards. The acknowledgement
/// is message 1 of the new stream, with 141 = Y and 789 = 2, and nothing is
/// replayed or refused.
#[tokio::test]
async fn test_acceptor_owed_reset_ignores_the_initiators_next_expected() {
    let store = Arc::new(FlakyResetStore::new());
    let (venue_app, _rx) = RecordingApp::new();
    let mut config = venue_789();
    config.reset_on_disconnect = true;
    let acceptor = Arc::new(
        Acceptor::new(config, Arc::clone(&venue_app))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );

    // First session: the close-time reset fails, so the reset is owed.
    let (framed, connection, _ack) =
        establish(Arc::clone(&acceptor), client_logon(1, &[(789, "1")])).await;
    store.fail_reset.store(true, Ordering::SeqCst);
    drop(framed);
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "the first session closes within 5s",
    );
    store.fail_reset.store(false, Ordering::SeqCst);

    // Second session: 789 = 9 would be above anything sent, but the stream it
    // describes is discarded by the owed reset.
    let (mut framed, connection, ack) =
        establish(Arc::clone(&acceptor), client_logon(5, &[(789, "9")])).await;
    assert_eq!(field(&ack, 34).as_deref(), Some("1"));
    assert_eq!(field(&ack, 141).as_deref(), Some("Y"));
    assert_eq!(field(&ack, 789).as_deref(), Some("2"));
    assert_eq!(connection.next_target_seq(), 2);
    assert_silent(&mut framed, "nothing is replayed or refused").await;
}

/// An initiator that owes a reset (its close-time reset failed) declares it on
/// its next Logon, at 1 with 141 = Y, and that Logon declares 789 = 1: the
/// acknowledgement of a reset is message 1.
#[tokio::test]
async fn test_initiator_owed_reset_logon_declares_next_expected_1() {
    let store = Arc::new(FlakyResetStore::new());
    let (client_app, _rx) = RecordingApp::new();
    let mut config = client_789();
    config.reset_on_disconnect = true;
    let initiator = Initiator::new(config, Arc::clone(&client_app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);

    // First session: acknowledged, then the venue hangs up while the store
    // refuses the close-time reset.
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (mut framed, logon) = read_client_logon(listener).await;
        assert_eq!(field(&logon, 789).as_deref(), Some("1"));
        ok(
            framed.send(venue_ack(1, &[(789, "2")])).await,
            "the venue acknowledges",
        );
        framed
    });
    let connection = ok(initiator.connect(addr).await, "first connect");
    let framed = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );
    store.fail_reset.store(true, Ordering::SeqCst);
    drop(framed);
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "the first session closes within 5s",
    );
    store.fail_reset.store(false, Ordering::SeqCst);

    // Second session: the owed reset is declared, with 789 = 1.
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (mut framed, logon) = read_client_logon(listener).await;
        assert_eq!(field(&logon, 34).as_deref(), Some("1"));
        assert_eq!(field(&logon, 141).as_deref(), Some("Y"));
        assert_eq!(field(&logon, 789).as_deref(), Some("1"));
        ok(
            framed.send(venue_ack(1, &[(141, "Y"), (789, "2")])).await,
            "the venue acknowledges the reset",
        );
        assert_silent(&mut framed, "nothing replayed after a reset").await;
        framed
    });
    let connection = ok(initiator.connect(addr).await, "second connect");
    assert_eq!(connection.next_sender_seq(), 2);
    assert_eq!(connection.next_target_seq(), 2);
    let _framed = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );
}

/// A malformed 789 on a `ResetSeqNumFlag` Logon, against an acceptor with a
/// store: refused before the store is reset. The previous stream stays filed,
/// the Logon is not consumed, and the only write is the refusal's own Logout,
/// numbered from the store and filed like every authenticated refusal
/// (ADR-0017).
#[tokio::test]
async fn test_acceptor_malformed_next_expected_with_a_store_never_resets_it() {
    let (store, _, _) = seeded_venue_store().await;
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(venue_789(), Arc::clone(&venue_app))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );
    let (result, frames) =
        refused_logon(acceptor, client_logon(1, &[(141, "Y"), (789, "abc")])).await;

    assert_next_expected_refusal(&result, &["789", "'abc' is not a sequence number"]);
    assert_eq!(frames.len(), 1, "one Logout");
    assert_eq!(msg_type_of(&frames[0]), "5");
    assert_eq!(field(&frames[0], 34).as_deref(), Some("5"));
    assert!(!venue_app.logged_on());
    for seq in 1..=4u64 {
        assert!(store.contains(seq), "the store was not reset (frame {seq})");
    }
    assert!(store.contains(5), "the Logout is filed");
    assert_eq!(store.next_sender_seq(), 6);
    assert_eq!(store.next_target_seq(), 3, "the Logon is not consumed");
}

/// A real FIX.5.0SP2 `Initiator` against a real FIX.5.0SP2 `Acceptor`, both
/// with 789 on, over FIXT.1.1. The initiator's Logon (5) declares 789 = 1
/// besides `DefaultApplVerID` (1137) = 9; the acceptor, whose ack goes out
/// at 3, fills 1..=2; the initiator holds the gapped ack and consumes it once
/// that fill arrives, without a `ResendRequest` either way; then application
/// messages flow in both directions in sequence.
#[tokio::test]
async fn test_fixt_initiator_against_acceptor_with_next_expected() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_config("FIX.5.0SP2").with_send_next_expected_msg_seq_num(true),
        Arc::clone(&venue_app),
    )
    .with_initial_sequences(3, 5);
    let venue = tokio::spawn(async move { acceptor.accept(&listener).await });
    let (client_app, mut client_rx) = RecordingApp::new();
    let client = ok(
        Initiator::new(
            client_config("FIX.5.0SP2").with_send_next_expected_msg_seq_num(true),
            Arc::clone(&client_app),
        )
        .with_initial_sequences(5, 1)
        .connect(addr)
        .await,
        "the FIXT initiator logs on",
    );
    let venue_connection = ok(
        ok(
            ok(
                timeout(Duration::from_secs(5), venue).await,
                "handshake within 5s",
            ),
            "venue task joins",
        ),
        "the FIXT acceptor establishes the session",
    );
    assert!(venue_app.events().contains(&"logon 789=1".to_string()));
    assert!(client_app.events().contains(&"logon 789=6".to_string()));
    assert_eq!(
        client.counterparty_default_appl_version(),
        Some(FixVersion::Fix50Sp2)
    );

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
    let received = next_app_message(&mut client_rx).await;
    assert_eq!(received.1, "4", "in sequence after the held ack (3)");
    assert_eq!(client.next_target_seq(), 5);

    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order.push_str(11, "ORDER-1");
    ok(client.send(order).await, "the client sends an order");
    assert_eq!(next_app_message(&mut venue_rx).await.1, "6");

    for (side, events) in [
        ("client", client_app.events()),
        ("venue", venue_app.events()),
    ] {
        assert!(
            !events.iter().any(|event| event == "resend request"),
            "no ResendRequest reached the {side}: {events:?}"
        );
    }
    ok(client.logout().await, "the client logs out");
    ok(
        timeout(Duration::from_secs(5), client.wait_closed()).await,
        "the client session closes within 5s",
    );
}

// ---------------------------------------------------------------------------
// Initiator: a reset it declared that the ack does not echo
// ---------------------------------------------------------------------------

/// After a reset the initiator declared (`reset_on_logon`), an ack that does
/// not echo `ResetSeqNumFlag` is the acceptor's message 1 whatever its
/// number (the reset rule), and its 789 may describe the stream the reset
/// discards: it is ignored. An ack at 7 with 789 = 9 is accepted, nothing is
/// replayed or refused, and 2 is expected next.
#[tokio::test]
async fn test_initiator_reset_logon_ignores_the_789_of_an_ack_without_141() {
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (mut framed, logon) = read_client_logon(listener).await;
        assert_eq!(field(&logon, 141).as_deref(), Some("Y"));
        assert_eq!(field(&logon, 789).as_deref(), Some("1"));
        ok(
            framed.send(venue_ack(7, &[(789, "9")])).await,
            "the venue acknowledges in its old stream",
        );
        assert_silent(&mut framed, "nothing replayed or refused").await;
        framed
    });
    let (client_app, _rx) = RecordingApp::new();
    let connection = ok(
        Initiator::new(
            client_789().with_reset_on_logon(true),
            Arc::clone(&client_app),
        )
        .connect(addr)
        .await,
        "the ack is accepted as message 1",
    );
    assert!(client_app.logged_on());
    assert_eq!(connection.next_target_seq(), 2);
    assert_eq!(connection.next_sender_seq(), 2);
    let _framed = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );
}

/// The same for a reset an earlier session owes: the Logon declares it, the
/// ack does not echo it, and the ack's 789 (9) is ignored.
#[tokio::test]
async fn test_initiator_owed_reset_ignores_the_789_of_an_ack_without_141() {
    let store = Arc::new(FlakyResetStore::new());
    let (client_app, _rx) = RecordingApp::new();
    let mut config = client_789();
    config.reset_on_disconnect = true;
    let initiator = Initiator::new(config, Arc::clone(&client_app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);

    // First session: its close-time reset fails, so the reset is owed.
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (mut framed, _logon) = read_client_logon(listener).await;
        ok(
            framed.send(venue_ack(1, &[(789, "2")])).await,
            "the venue acknowledges",
        );
        framed
    });
    let connection = ok(initiator.connect(addr).await, "first connect");
    let framed = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );
    store.fail_reset.store(true, Ordering::SeqCst);
    drop(framed);
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "the first session closes within 5s",
    );
    store.fail_reset.store(false, Ordering::SeqCst);

    // Second session: the owed reset is declared; the ack ignores it.
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (mut framed, logon) = read_client_logon(listener).await;
        assert_eq!(field(&logon, 34).as_deref(), Some("1"));
        assert_eq!(field(&logon, 141).as_deref(), Some("Y"));
        ok(
            framed.send(venue_ack(7, &[(789, "9")])).await,
            "the venue acknowledges in its old stream",
        );
        assert_silent(&mut framed, "nothing replayed or refused").await;
        framed
    });
    let connection = ok(initiator.connect(addr).await, "second connect");
    assert_eq!(connection.next_target_seq(), 2);
    assert_eq!(connection.next_sender_seq(), 2);
    let _framed = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "venue done within 5s",
        ),
        "venue task",
    );
}

/// What a declared reset does not relax: an ack that echoes
/// `ResetSeqNumFlag` knew of the reset, so its 789 is still held to the new
/// stream (3 is above the next number sent, 2: refused), and a malformed 789
/// is refused whatever the ack declares.
#[tokio::test]
async fn test_initiator_reset_logon_still_checks_an_echoing_or_malformed_789() {
    for (ack_extra, mention) in [
        (&[(141u32, "Y"), (789, "3")][..], "higher than expected"),
        (&[(789u32, "abc")][..], "not a sequence number"),
    ] {
        let (listener, addr) = bind_listener().await;
        let ack = venue_ack(1, ack_extra);
        let venue = tokio::spawn(async move {
            let (mut framed, _logon) = read_client_logon(listener).await;
            ok(framed.send(ack).await, "the venue acknowledges");
            let mut types = Vec::new();
            while let Ok(Some(Ok(frame))) = timeout(Duration::from_secs(2), framed.next()).await {
                types.push(msg_type_of(&frame));
            }
            types
        });
        let (client_app, _rx) = RecordingApp::new();
        let result = Initiator::new(
            client_789().with_reset_on_logon(true),
            Arc::clone(&client_app),
        )
        .connect(addr)
        .await;
        assert_next_expected_refusal(&result, &["789", mention]);
        assert!(!client_app.logged_on());
        let types = ok(
            ok(
                timeout(Duration::from_secs(5), venue).await,
                "venue done within 5s",
            ),
            "venue task",
        );
        assert_eq!(types.last().map(String::as_str), Some("5"), "a Logout");
    }
}

// ---------------------------------------------------------------------------
// Bilateral recovery with backlogs larger than the socket buffers
// ---------------------------------------------------------------------------

/// Messages in each side's backlog. With [`BACKLOG_PADDING`] that is about
/// 9 MB per side, above what the loopback socket buffers hold in flight
/// (4 MB send plus 4 MB receive at most on macOS; less on Linux): if each side
/// wrote its whole resend before reading, both would block writing.
const BACKLOG_MESSAGES: u64 = 6_000;

/// Bytes of `Text` (58) padding in each backlog message.
const BACKLOG_PADDING: usize = 1_500;

/// A store holding one side's previous stream: its Logon (1) and
/// [`BACKLOG_MESSAGES`] application messages (2 onwards) that the other side
/// never received; the other side's Logon (1) was received, so 2 is expected
/// next.
async fn backlog_store(client: bool) -> Arc<MemoryStore> {
    let padding = "x".repeat(BACKLOG_PADDING);
    let store = Arc::new(MemoryStore::new());
    let (sender, target, logon, msg_type, wire_type) = if client {
        (
            "CLIENT",
            "VENUE",
            client_logon(1, &[]),
            MsgType::NewOrderSingle,
            "D",
        )
    } else {
        (
            "VENUE",
            "CLIENT",
            venue_ack(1, &[]),
            MsgType::ExecutionReport,
            "8",
        )
    };
    ok(
        store.store(1, &MsgType::Logon, &logon).await,
        "seed the Logon",
    );
    for seq in 2..BACKLOG_MESSAGES + 2 {
        let id = seq.to_string();
        let frame = peer_frame(
            "FIX.4.4",
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
        let message = some(rx.recv().await, "the application channel stays open");
        assert_eq!(message.1, seq.to_string(), "in sequence");
        assert_eq!(message.2.as_deref(), Some("Y"), "a resend");
    }
}

/// Runs a real `Initiator` against a real `Acceptor`, each with a backlog the
/// other missed, and checks that each side receives the other's whole backlog
/// as resends and that live messages then flow in both directions.
///
/// `with_789` turns 789 on for both sides: each resends what the other's 789
/// names while holding the other's gapped Logon. Without it, each requests the
/// gap at its Logon and answers the other's `ResendRequest`. Either way both
/// sides resend at once, and each keeps reading while it resends, so neither
/// blocks writing into a full socket.
async fn bilateral_recovery(with_789: bool) {
    let configure = |config: SessionConfig| {
        config
            .with_send_next_expected_msg_seq_num(with_789)
            .with_resend_timeout(Duration::from_secs(30))
    };
    let client_store = backlog_store(true).await;
    let venue_store = backlog_store(false).await;
    let capacity = 2 * usize::try_from(BACKLOG_MESSAGES).unwrap_or(usize::MAX / 4);

    let (listener, addr) = bind_listener().await;
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(configure(venue_config("FIX.4.4")), Arc::clone(&venue_app))
        .with_store(Arc::clone(&venue_store) as Arc<dyn MessageStore>)
        .with_write_timeout(Duration::from_secs(3))
        .with_app_queue_capacity(capacity);
    let venue = tokio::spawn(async move { acceptor.accept(&listener).await });
    let (client_app, mut client_rx) = RecordingApp::new();
    let client = ok(
        Initiator::new(configure(client_config("FIX.4.4")), Arc::clone(&client_app))
            .with_store(Arc::clone(&client_store) as Arc<dyn MessageStore>)
            .with_write_timeout(Duration::from_secs(3))
            .with_app_queue_capacity(capacity)
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

    ok(
        timeout(Duration::from_secs(30), async {
            tokio::join!(
                receive_backlog(&mut client_rx),
                receive_backlog(&mut venue_rx)
            )
        })
        .await,
        "both backlogs are resent within 30s",
    );

    let live_seq = (BACKLOG_MESSAGES + 4).to_string();
    let mut report = OutboundMessage::new(MsgType::ExecutionReport);
    report
        .push_str(37, "EX-LIVE")
        .push_str(17, "E-LIVE")
        .push_char(150, '0')
        .push_char(39, '0');
    ok(venue_connection.send(report).await, "a live report");
    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order.push_str(11, "ORDER-LIVE");
    ok(client.send(order).await, "a live order");
    let live_report = next_app_message(&mut client_rx).await;
    let live_order = next_app_message(&mut venue_rx).await;
    assert_eq!(live_report.2, None, "an original send");
    assert_eq!(live_order.2, None, "an original send");
    if with_789 {
        // Logon, then the live message: nothing was spent on a request.
        assert_eq!(live_report.1, (BACKLOG_MESSAGES + 3).to_string());
        assert_eq!(live_order.1, (BACKLOG_MESSAGES + 3).to_string());
        for (side, events) in [
            ("client", client_app.events()),
            ("venue", venue_app.events()),
        ] {
            assert!(
                !events.iter().any(|event| event == "resend request"),
                "no ResendRequest reached the {side}: {events:?}"
            );
        }
    } else {
        // Logon, the ResendRequest, then the live message.
        assert_eq!(live_report.1, live_seq);
        assert_eq!(live_order.1, live_seq);
    }
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

/// Both sides missed the other's backlog and both declared 789: each resends
/// its backlog to the other at once, reading while it does, so the recovery
/// completes in both directions without a `ResendRequest`.
#[tokio::test]
async fn test_bilateral_789_resend_larger_than_the_socket_buffers() {
    bilateral_recovery(true).await;
}

/// The same backlogs without 789: each side requests the gap at its Logon and
/// answers the other's `ResendRequest` while reading the other's answer.
#[tokio::test]
async fn test_bilateral_resend_requests_larger_than_the_socket_buffers() {
    bilateral_recovery(false).await;
}

/// The resend stays ahead of live application messages: the acceptor owes
/// 300 messages (two store pages) and its application sends a live report as
/// soon as the session is Active. The scripted initiator receives every
/// resent message, in order, before the live report, which carries the next
/// number after the acknowledgement.
#[tokio::test]
async fn test_resend_stays_ahead_of_live_application_messages() {
    let store = Arc::new(MemoryStore::new());
    ok(
        store.store(1, &MsgType::Logon, &venue_ack(1, &[])).await,
        "seed the Logon",
    );
    for seq in 2..=301u64 {
        ok(
            store
                .store(
                    seq,
                    &MsgType::ExecutionReport,
                    &venue_msg("8", seq, &REPORT_BODY),
                )
                .await,
            "seed a report",
        );
    }
    ok(
        store.set_next_sender_seq(302).await,
        "seed the sender counter",
    );
    ok(
        store.set_next_target_seq(3).await,
        "seed the target counter",
    );
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(venue_789(), Arc::clone(&venue_app))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );
    let (mut framed, connection, ack) = establish(acceptor, client_logon(3, &[(789, "2")])).await;
    assert_eq!(field(&ack, 34).as_deref(), Some("302"));

    let mut report = OutboundMessage::new(MsgType::ExecutionReport);
    report
        .push_str(37, "EX-LIVE")
        .push_str(17, "E-LIVE")
        .push_char(150, '0')
        .push_char(39, '0');
    ok(connection.send(report).await, "a live report");

    for seq in 2..=301u64 {
        let frame = next_frame(&mut framed).await;
        assert_eq!(field(&frame, 34), Some(seq.to_string()), "resent in order");
        assert_eq!(field(&frame, 43).as_deref(), Some("Y"), "a resend");
    }
    let live = next_frame(&mut framed).await;
    assert_eq!(field(&live, 37).as_deref(), Some("EX-LIVE"));
    assert_eq!(field(&live, 34).as_deref(), Some("303"));
    assert_eq!(field(&live, 43), None, "an original send");
}

// ---------------------------------------------------------------------------
// A resend under way: what waits behind it, and what does not cut it short
// ---------------------------------------------------------------------------

/// A resend from the scripted acceptor: `body` with `PossDupFlag` (43) = Y
/// and an `OrigSendingTime` (122).
#[track_caller]
fn venue_resend(msg_type: &str, seq: u64, body: &[(u32, &str)]) -> BytesMut {
    let mut fields = vec![(43, "Y"), (122, "20261018-12:00:00.000")];
    fields.extend_from_slice(body);
    venue_msg(msg_type, seq, &fields)
}

/// The acceptor's previous stream: its Logon ack (1) and 300 reports (2 to
/// 301); next sender 302, next target 3.
async fn venue_report_backlog() -> Arc<MemoryStore> {
    let store = Arc::new(MemoryStore::new());
    ok(
        store.store(1, &MsgType::Logon, &venue_ack(1, &[])).await,
        "seed the Logon",
    );
    for seq in 2..=301u64 {
        ok(
            store
                .store(
                    seq,
                    &MsgType::ExecutionReport,
                    &venue_msg("8", seq, &REPORT_BODY),
                )
                .await,
            "seed a report",
        );
    }
    ok(
        store.set_next_sender_seq(302).await,
        "seed the sender counter",
    );
    ok(
        store.set_next_target_seq(3).await,
        "seed the target counter",
    );
    store
}

/// Reads every frame until the engine stops sending for 2 s or hangs up, as
/// `(MsgType, MsgSeqNum, PossDupFlag)`.
async fn drain_frames(
    framed: &mut Framed<TcpStream, FixCodec>,
) -> Vec<(String, u64, Option<String>)> {
    let mut frames = Vec::new();
    while let Ok(Some(Ok(frame))) = timeout(Duration::from_secs(2), framed.next()).await {
        frames.push((
            msg_type_of(&frame),
            field(&frame, 34)
                .and_then(|seq| seq.parse::<u64>().ok())
                .unwrap_or(0),
            field(&frame, 43),
        ));
    }
    frames
}

/// A counterparty that asks for a resend and logs out right behind it gets
/// the whole resend before the Logout reply: FIX gives the remote end the
/// chance to fill the gap first. 300 reports are replayed and the
/// acknowledgement gap-filled, then the Logout goes out and the session ends
/// gracefully.
#[tokio::test]
async fn test_acceptor_finishes_a_resend_before_replying_to_a_logout() {
    let store = venue_report_backlog().await;
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(venue_config("FIX.4.4"), Arc::clone(&venue_app))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );
    let (mut framed, connection, ack) = establish(acceptor, client_logon(3, &[])).await;
    assert_eq!(field(&ack, 34).as_deref(), Some("302"));
    ok(
        framed
            .send(client_msg("2", 4, &[(7, "2"), (16, "0")]))
            .await,
        "the client asks for everything",
    );
    ok(
        framed.send(client_msg("5", 5, &[])).await,
        "and logs out right behind it",
    );
    let frames = drain_frames(&mut framed).await;
    let Some((last_type, last_seq, _)) = frames.last() else {
        panic!("the venue answered nothing")
    };
    assert_eq!(
        (last_type.as_str(), *last_seq),
        ("5", 303),
        "the Logout reply comes last"
    );
    let resent: Vec<u64> = frames
        .iter()
        .filter(|(_, _, poss_dup)| poss_dup.as_deref() == Some("Y"))
        .map(|(_, seq, _)| *seq)
        .collect();
    let expected: Vec<u64> = (2..=302).collect();
    assert_eq!(
        resent, expected,
        "300 replays and the gap fill for the ack, in order"
    );
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "the session closes within 5s",
    );
    assert!(venue_app.events().contains(&"logout".to_string()));
}

/// A store whose page reads are slow, standing in for a resend that takes
/// longer than the logout timeout.
#[derive(Debug)]
struct SlowPageStore {
    inner: Arc<MemoryStore>,
    delay: Duration,
}

#[async_trait]
impl MessageStore for SlowPageStore {
    async fn store(
        &self,
        seq_num: u64,
        msg_type: &MsgType,
        message: &[u8],
    ) -> Result<(), StoreError> {
        self.inner.store(seq_num, msg_type, message).await
    }

    async fn get_range(&self, begin: u64, end: u64) -> Result<Vec<StoredMessage>, StoreError> {
        tokio::time::sleep(self.delay).await;
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

/// The wait for an owed resend is bounded by the logout timeout: when the
/// resend takes longer, the Logout reply goes out without the rest of it.
#[tokio::test]
async fn test_owed_logout_reply_is_bounded_by_the_logout_timeout() {
    let store = Arc::new(SlowPageStore {
        inner: venue_report_backlog().await,
        delay: Duration::from_millis(500),
    });
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(
            venue_config("FIX.4.4").with_logout_timeout(Duration::from_millis(200)),
            Arc::clone(&venue_app),
        )
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );
    let (mut framed, connection, _ack) = establish(acceptor, client_logon(3, &[])).await;
    ok(
        framed
            .send(client_msg("2", 4, &[(7, "2"), (16, "0")]))
            .await,
        "the client asks for everything",
    );
    ok(
        framed.send(client_msg("5", 5, &[])).await,
        "and logs out right behind it",
    );
    let frames = drain_frames(&mut framed).await;
    let Some((last_type, _, _)) = frames.last() else {
        panic!("the venue answered nothing")
    };
    assert_eq!(last_type, "5", "the Logout reply still goes out");
    let resent = frames
        .iter()
        .filter(|(_, _, poss_dup)| poss_dup.as_deref() == Some("Y"))
        .count();
    assert!(resent < 301, "the resend was cut short: {resent} frames");
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "the session closes within 5s",
    );
}

/// A Logout the consumer asks for while a resend is under way waits behind
/// it: the 789 resend of 300 reports goes out whole, then the Logout.
#[tokio::test]
async fn test_consumer_logout_waits_behind_a_resend() {
    let store = venue_report_backlog().await;
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(venue_789(), Arc::clone(&venue_app))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );
    let (mut framed, connection, ack) = establish(acceptor, client_logon(3, &[(789, "2")])).await;
    assert_eq!(field(&ack, 34).as_deref(), Some("302"));
    ok(connection.logout().await, "the venue logs out at once");
    for seq in 2..=301u64 {
        let frame = next_frame(&mut framed).await;
        assert_eq!(field(&frame, 34), Some(seq.to_string()), "resent in order");
        assert_eq!(field(&frame, 43).as_deref(), Some("Y"));
    }
    let logout = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&logout), "5", "the Logout follows the resend");
    assert_eq!(field(&logout, 34).as_deref(), Some("303"));
    ok(
        framed.send(client_msg("5", 4, &[])).await,
        "the client acknowledges",
    );
    ok(
        timeout(Duration::from_secs(5), connection.wait_closed()).await,
        "the session closes within 5s",
    );
}

/// Reads the next frame from a scripted peer's end of a pipe, within 5 s.
async fn next_pipe_frame(framed: &mut Framed<tokio::io::DuplexStream, FixCodec>) -> BytesMut {
    let polled = ok(
        timeout(Duration::from_secs(5), framed.next()).await,
        "frame must arrive within 5s",
    );
    ok(some(polled, "stream must stay open"), "frame must decode")
}

/// Every message that takes a new number waits behind a resend: a TestRequest
/// (4) and a gapped Heartbeat (9) arrive while the 789 resend of 300 reports
/// is being written, and the application sends a live report. The resend
/// goes out whole and in order; then the Heartbeat answering the
/// TestRequest, the ResendRequest for the gap (from 5) and the live report,
/// in that order, under 303, 304 and 305. No number is used twice.
///
/// The reports are padded so the resend (about 200 KB) is larger than what
/// the engine buffers before waiting for the socket plus what the 4 KiB pipe
/// holds, and the scripted initiator reads nothing until it has sent the
/// TestRequest and the Heartbeat: the resend is therefore still being written
/// when they arrive, whatever order the engine picks its work in.
#[tokio::test]
async fn test_new_numbers_wait_behind_a_resend() {
    let store = Arc::new(MemoryStore::new());
    ok(
        store.store(1, &MsgType::Logon, &venue_ack(1, &[])).await,
        "seed the Logon",
    );
    let padding = "x".repeat(500);
    for seq in 2..=301u64 {
        let mut body = REPORT_BODY.to_vec();
        body.push((58, padding.as_str()));
        ok(
            store
                .store(seq, &MsgType::ExecutionReport, &venue_msg("8", seq, &body))
                .await,
            "seed a report",
        );
    }
    ok(
        store.set_next_sender_seq(302).await,
        "seed the sender counter",
    );
    ok(
        store.set_next_target_seq(3).await,
        "seed the target counter",
    );
    let (venue_app, _rx) = RecordingApp::new();
    let acceptor = Acceptor::new(venue_789(), Arc::clone(&venue_app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let (client_io, venue_io) = tokio::io::duplex(4 * 1024);
    let served = tokio::spawn(async move { acceptor.serve_stream(venue_io).await });
    let mut framed = Framed::new(client_io, FixCodec::new());
    ok(
        framed.send(client_logon(3, &[(789, "2")])).await,
        "the client logs on",
    );
    let ack = next_pipe_frame(&mut framed).await;
    assert_eq!(msg_type_of(&ack), "A", "the Logon is acknowledged");
    assert_eq!(field(&ack, 34).as_deref(), Some("302"));
    let connection = ok(
        ok(
            ok(
                timeout(Duration::from_secs(5), served).await,
                "handshake within 5s",
            ),
            "venue task joins",
        ),
        "acceptor establishes the session",
    );
    ok(
        framed.send(client_msg("1", 4, &[(112, "PING")])).await,
        "a TestRequest",
    );
    ok(
        framed.send(client_msg("0", 9, &[])).await,
        "a gapped Heartbeat",
    );
    let mut report = OutboundMessage::new(MsgType::ExecutionReport);
    report
        .push_str(37, "EX-LIVE")
        .push_str(17, "E-LIVE")
        .push_char(150, '0')
        .push_char(39, '0');
    ok(connection.send(report).await, "a live report");

    for seq in 2..=301u64 {
        let frame = next_pipe_frame(&mut framed).await;
        assert_eq!(field(&frame, 34), Some(seq.to_string()), "resent in order");
        assert_eq!(
            field(&frame, 43).as_deref(),
            Some("Y"),
            "nothing new in between"
        );
    }
    let heartbeat = next_pipe_frame(&mut framed).await;
    assert_eq!(msg_type_of(&heartbeat), "0");
    assert_eq!(field(&heartbeat, 34).as_deref(), Some("303"));
    assert_eq!(field(&heartbeat, 112).as_deref(), Some("PING"));
    let request = next_pipe_frame(&mut framed).await;
    assert_eq!(msg_type_of(&request), "2");
    assert_eq!(field(&request, 34).as_deref(), Some("304"));
    assert_eq!(field(&request, 7).as_deref(), Some("5"));
    let live = next_pipe_frame(&mut framed).await;
    assert_eq!(msg_type_of(&live), "8");
    assert_eq!(field(&live, 34).as_deref(), Some("305"));
    assert_eq!(field(&live, 43), None);
}

/// After the fallback request, a late 789 resend from the initiator stops
/// below its Logon (6) with an administrative message (5, gap-filled), so
/// the expectation is 6. The answer to the request then gap-fills 5 and 6
/// with one fill numbered 5: a possible duplicate below the expectation,
/// ignored as FIX requires. Its NewSeqNo (7) spans 6, which is still missing,
/// so 6 is re-requested at once, not charged against the one request
/// allowed; the answer fills 6 in sequence and the recovery completes with
/// no Logout.
#[tokio::test]
async fn test_acceptor_re_requests_what_a_spanning_possible_duplicate_fill_skips() {
    let resend_timeout = Duration::from_millis(400);
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let acceptor = Arc::new(
        Acceptor::new(
            venue_789()
                .with_resend_timeout(resend_timeout)
                .with_max_resend_requests(1),
            Arc::clone(&venue_app),
        )
        .with_initial_sequences(1, 3),
    );
    let (mut framed, connection, _ack) = establish(acceptor, client_logon(6, &[(789, "1")])).await;
    let request = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&request), "2", "the fallback fires");
    assert_eq!(field(&request, 7).as_deref(), Some("3"));
    for seq in [3u64, 4] {
        ok(
            framed.send(client_resend("D", seq, &ORDER_BODY)).await,
            "the late 789 resend",
        );
    }
    ok(
        framed
            .send(client_resend("4", 5, &[(123, "Y"), (36, "6")]))
            .await,
        "the 789 resend fills 5 and stops before the Logon",
    );
    for seq in [3u64, 4] {
        ok(
            framed.send(client_resend("D", seq, &ORDER_BODY)).await,
            "the answer",
        );
    }
    ok(
        framed
            .send(client_resend("4", 5, &[(123, "Y"), (36, "7")]))
            .await,
        "the answer fills 5..=6",
    );
    for expected in ["3", "4"] {
        assert_eq!(next_app_message(&mut venue_rx).await.1, expected);
    }
    let rerequest = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&rerequest), "2", "6 is re-requested at once");
    assert_eq!(field(&rerequest, 7).as_deref(), Some("6"));
    assert_eq!(field(&rerequest, 16).as_deref(), Some("0"));
    ok(
        framed
            .send(client_resend("4", 6, &[(123, "Y"), (36, "7")]))
            .await,
        "the answer fills 6",
    );
    if let Ok(Some(Ok(frame))) = timeout(resend_timeout * 3, framed.next()).await {
        panic!(
            "the recovery is complete: unexpected MsgType {}",
            msg_type_of(&frame)
        );
    }
    assert_eq!(connection.next_target_seq(), 7);
}

/// What a resend with a new number written in the middle does to an IronFix
/// receiver, which does not queue gapped messages (#71), and so why IronFix
/// writes nothing new while it resends. The scripted acceptor answers the
/// initiator's ResendRequest (2 to 4, and a fill for its ack at 5).
///
/// - Written whole, then a Heartbeat at 6: the initiator recovers to 7.
/// - With the Heartbeat at 6 written in the middle: the initiator reads 6 as
///   gapped (processed, not consumed), fills 2..=5, and is left expecting 6,
///   which nothing will send again until it asks; with a limit of one
///   request that ends in a Logout.
#[tokio::test]
async fn test_a_new_number_inside_an_answer_strands_an_ironfix_receiver() {
    async fn run(interleave: bool) -> (u64, Vec<String>) {
        let resend_timeout = Duration::from_millis(400);
        let (listener, addr) = bind_listener().await;
        let venue = tokio::spawn(async move {
            let (mut framed, _logon) = read_client_logon(listener).await;
            ok(framed.send(venue_ack(5, &[])).await, "ack at 5");
            let request = next_frame(&mut framed).await;
            assert_eq!(msg_type_of(&request), "2");
            assert_eq!(field(&request, 7).as_deref(), Some("2"));
            ok(
                framed.send(venue_resend("8", 2, &REPORT_BODY)).await,
                "replay 2",
            );
            if interleave {
                ok(
                    framed.send(venue_msg("0", 6, &[])).await,
                    "a new Heartbeat inside the answer",
                );
            }
            for seq in [3u64, 4] {
                ok(
                    framed.send(venue_resend("8", seq, &REPORT_BODY)).await,
                    "replay 3 and 4",
                );
            }
            ok(
                framed
                    .send(venue_resend("4", 5, &[(123, "Y"), (36, "6")]))
                    .await,
                "fill the ack",
            );
            if !interleave {
                ok(
                    framed.send(venue_msg("0", 6, &[])).await,
                    "a new Heartbeat after the answer",
                );
            }
            let mut after = Vec::new();
            while let Ok(Some(Ok(frame))) = timeout(resend_timeout * 3, framed.next()).await {
                after.push(msg_type_of(&frame));
            }
            after
        });
        let (client_app, mut client_rx) = RecordingApp::new();
        let connection = ok(
            Initiator::new(
                client_config("FIX.4.4")
                    .with_resend_timeout(resend_timeout)
                    .with_max_resend_requests(1),
                Arc::clone(&client_app),
            )
            .with_initial_sequences(1, 2)
            .connect(addr)
            .await,
            "connect",
        );
        for expected in ["2", "3", "4"] {
            assert_eq!(next_app_message(&mut client_rx).await.1, expected);
        }
        let after = ok(
            ok(
                timeout(Duration::from_secs(5), venue).await,
                "venue done within 5s",
            ),
            "venue task",
        );
        (connection.next_target_seq(), after)
    }

    let (target, after) = run(false).await;
    assert_eq!(
        target, 7,
        "written whole, the answer completes the recovery"
    );
    assert!(after.is_empty(), "nothing more was asked: {after:?}");

    let (target, after) = run(true).await;
    assert_eq!(
        target, 6,
        "6 arrived inside the answer and is still missing"
    );
    assert_eq!(
        after.last().map(String::as_str),
        Some("5"),
        "a Logout: {after:?}"
    );
}

// ---------------------------------------------------------------------------
// End to end: a real Initiator reconnecting to a real Acceptor over FileStores
// ---------------------------------------------------------------------------

/// A directory for one test, removed when the test ends, pass or fail.
struct TestDir(std::path::PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("ironfix-engine-789-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Waits until the engine has let go of `store`, as a process exiting would.
async fn released(store: &Arc<FileStore>) {
    ok(
        timeout(Duration::from_secs(5), async {
            while Arc::strong_count(store) > 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await,
        "the engine releases the store when its session ends",
    );
}

/// A real `Initiator` and a real `Acceptor`, each over its own `FileStore`,
/// with 789 on. In the first session the venue sends three reports and the
/// client logs out. The client is then restarted from a journal whose target
/// counter stops at 2, as a crash after reading the reports and before making
/// their numbers durable leaves it. Its next Logon declares 789 = 2, and the
/// venue, restarted from its own journal, resends the three reports
/// (`PossDupFlag` = Y, original `SendingTime` in `OrigSendingTime`) and
/// gap-fills its Logout, all below its acknowledgement. The client holds the
/// gapped acknowledgement and consumes it once the resend fills the gap, so
/// no `ResendRequest` goes either way, and a report the venue sends after the
/// resend is delivered in sequence, well within the resend timeout both sides
/// are configured with: nothing waits on a retry.
#[tokio::test]
async fn test_initiator_against_acceptor_replays_what_the_restarted_side_missed() {
    let dir = TestDir::new("restart");
    let client_store_config = ok(
        FileStoreConfig::try_new(&dir.0, "FIX.4.4-CLIENT-VENUE"),
        "client store config",
    );
    let venue_store_config = ok(
        FileStoreConfig::try_new(&dir.0, "FIX.4.4-VENUE-CLIENT"),
        "venue store config",
    );

    // First session.
    let client_store = Arc::new(ok(
        FileStore::open(client_store_config.clone().with_create_if_missing(true)).await,
        "create the client store",
    ));
    let venue_store = Arc::new(ok(
        FileStore::open(venue_store_config.clone().with_create_if_missing(true)).await,
        "create the venue store",
    ));
    let first_reports = {
        let (listener, addr) = bind_listener().await;
        let (venue_app, _venue_rx) = RecordingApp::new();
        let acceptor = Acceptor::new(venue_789(), Arc::clone(&venue_app))
            .with_store(Arc::clone(&venue_store) as Arc<dyn MessageStore>);
        let venue = tokio::spawn(async move { acceptor.accept(&listener).await });
        let (client_app, mut client_rx) = RecordingApp::new();
        let client = ok(
            Initiator::new(client_789(), Arc::clone(&client_app))
                .with_store(Arc::clone(&client_store) as Arc<dyn MessageStore>)
                .connect(addr)
                .await,
            "first connect",
        );
        let venue_connection = ok(
            ok(
                ok(
                    timeout(Duration::from_secs(5), venue).await,
                    "first handshake within 5s",
                ),
                "venue task joins",
            ),
            "the venue establishes the first session",
        );
        assert!(
            client_app.events().contains(&"logon 789=2".to_string()),
            "the venue's ack declares 2"
        );
        assert!(
            venue_app.events().contains(&"logon 789=1".to_string()),
            "the client's first Logon declares 1"
        );
        for index in 0..3 {
            let mut report = OutboundMessage::new(MsgType::ExecutionReport);
            report
                .push_str(37, &format!("EX-{index}"))
                .push_str(17, &format!("E-{index}"))
                .push_char(150, '0')
                .push_char(39, '0');
            ok(
                venue_connection.send(report).await,
                "the venue sends a report",
            );
        }
        let mut first = Vec::new();
        for _ in 0..3 {
            first.push(next_app_message(&mut client_rx).await);
        }
        ok(client.logout().await, "the client logs out");
        ok(
            timeout(Duration::from_secs(5), client.wait_closed()).await,
            "the client session closes within 5s",
        );
        ok(
            timeout(Duration::from_secs(5), venue_connection.wait_closed()).await,
            "the venue session closes within 5s",
        );
        first
    };
    let numbers: Vec<&str> = first_reports.iter().map(|m| m.1.as_str()).collect();
    assert_eq!(numbers, ["2", "3", "4"]);
    released(&client_store).await;
    released(&venue_store).await;
    drop(client_store);
    drop(venue_store);

    // The restarted client lost the numbers of the reports.
    let client_store = ok(
        FileStore::open(client_store_config).await,
        "reopen the client store",
    );
    assert_eq!(client_store.next_sender_seq(), 3);
    assert_eq!(client_store.next_target_seq(), 6);
    ok(
        client_store.set_next_target_seq(2).await,
        "rewind the client's receive cursor",
    );
    let venue_store = ok(
        FileStore::open(venue_store_config).await,
        "reopen the venue store",
    );
    assert_eq!(venue_store.next_sender_seq(), 6);

    // Second session, with a short resend timeout on both sides: a gap left
    // to a retry would show up as a delay of at least this much.
    let resend_timeout = Duration::from_secs(2);
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let acceptor = Acceptor::new(
        venue_789().with_resend_timeout(resend_timeout),
        Arc::clone(&venue_app),
    )
    .with_store(Arc::new(venue_store) as Arc<dyn MessageStore>);
    let venue = tokio::spawn(async move { acceptor.accept(&listener).await });
    let (client_app, mut client_rx) = RecordingApp::new();
    let client = ok(
        Initiator::new(
            client_789().with_resend_timeout(resend_timeout),
            Arc::clone(&client_app),
        )
        .with_store(Arc::new(client_store) as Arc<dyn MessageStore>)
        .connect(addr)
        .await,
        "second connect",
    );
    let venue_connection = ok(
        ok(
            ok(
                timeout(Duration::from_secs(5), venue).await,
                "second handshake within 5s",
            ),
            "venue task joins",
        ),
        "the venue establishes the second session",
    );
    assert!(
        venue_app.events().contains(&"logon 789=2".to_string()),
        "the reconnecting client declares what it missed: {:?}",
        venue_app.events()
    );

    for (first, number) in first_reports.iter().zip(["2", "3", "4"]) {
        let replayed = next_app_message(&mut client_rx).await;
        assert_eq!(replayed.0, "8");
        assert_eq!(replayed.1, number, "resent under its original number");
        assert_eq!(replayed.2.as_deref(), Some("Y"), "PossDupFlag");
        assert!(replayed.3.is_some(), "OrigSendingTime");
        assert_eq!(first.2, None, "the first delivery was no duplicate");
    }

    // A live report after the resend: the held acknowledgement (6) was
    // consumed once the resend filled 2..=5, so the report (7) is in sequence
    // and arrives well within the resend timeout.
    let mut report = OutboundMessage::new(MsgType::ExecutionReport);
    report
        .push_str(37, "EX-LIVE")
        .push_str(17, "E-LIVE")
        .push_char(150, '0')
        .push_char(39, '0');
    let sent_at = std::time::Instant::now();
    ok(
        venue_connection.send(report).await,
        "the venue sends a live report",
    );
    let live = ok(
        timeout(resend_timeout / 2, client_rx.recv()).await,
        "the live report arrives within half the resend timeout",
    );
    let live = some(live, "the application channel stays open");
    assert!(sent_at.elapsed() < resend_timeout / 2);
    assert_eq!(live.1, "7");
    assert_eq!(live.2, None, "an original send, not a resend");
    assert_eq!(client.next_target_seq(), 8);
    for (side, events) in [
        ("client", client_app.events()),
        ("venue", venue_app.events()),
    ] {
        assert!(
            !events.iter().any(|event| event == "resend request"),
            "no ResendRequest reached the {side}: {events:?}"
        );
    }

    ok(client.logout().await, "the client logs out");
    ok(
        timeout(Duration::from_secs(5), client.wait_closed()).await,
        "the client session closes within 5s",
    );
    ok(
        timeout(Duration::from_secs(5), venue_connection.wait_closed()).await,
        "the venue session closes within 5s",
    );
    for (side, events) in [
        ("client", client_app.events()),
        ("venue", venue_app.events()),
    ] {
        assert!(
            !events.iter().any(|event| event == "resend request"),
            "no ResendRequest reached the {side} up to the Logout: {events:?}"
        );
    }
}
