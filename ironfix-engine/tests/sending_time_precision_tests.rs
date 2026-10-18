/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! End-to-end tests for issue #134: the precision of the `SendingTime` (52)
//! and `OrigSendingTime` (122) the engine writes, by FIX version.
//!
//! FIX 4.0 and FIX 4.1 type both fields as `time`, `YYYYMMDD-HH:MM:SS` in
//! whole seconds; FIX 4.2 replaced it with `UTCTimestamp`, which may also
//! carry milliseconds. Both engines, in both roles, write whole seconds on a
//! FIX 4.0 or FIX 4.1 session (the Logon, an application message, a
//! SequenceReset-GapFill's 52 and 122, and a replayed message's 52 and 122)
//! and keep milliseconds on every later version. Every framable version runs.
//!
//! The scripted peer stamps its Logon in whole seconds and its later messages
//! in milliseconds, so every session also proves that both inbound forms are
//! accepted whatever the version. Last, a real `Initiator` against a real
//! `Acceptor` on FIX 4.0 and on FIX 4.1 log on and exchange application
//! messages in whole seconds both ways.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::{CompId, Timestamp};
use ironfix_core::version::FixVersion;
use ironfix_engine::application::{Application, RejectReason, SessionId};
use ironfix_engine::{Acceptor, Connection, Initiator, OutboundMessage};
use ironfix_session::SessionConfig;
use ironfix_store::{MemoryStore, MessageStore};
use ironfix_tagvalue::{Decoder, Encoder};
use ironfix_transport::FixCodec;
use std::sync::Arc;
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
fn venue_config(version: FixVersion) -> SessionConfig {
    SessionConfig::new(comp_id("VENUE"), comp_id("CLIENT"), version.as_str())
        .with_heartbeat_interval(Duration::from_secs(30))
}

/// Initiator-side configuration in `version`: sender CLIENT, target VENUE.
fn client_config(version: FixVersion) -> SessionConfig {
    SessionConfig::new(comp_id("CLIENT"), comp_id("VENUE"), version.as_str())
        .with_heartbeat_interval(Duration::from_secs(30))
}

/// Every version a session can be configured with: bare FIXT.1.1 names no
/// application version and is refused.
fn framable_versions() -> impl Iterator<Item = FixVersion> {
    FixVersion::ALL
        .into_iter()
        .filter(|version| *version != FixVersion::Fixt11)
}

/// The two shapes a `UTCTimestamp` the engine writes can take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Precision {
    /// `YYYYMMDD-HH:MM:SS`, 17 bytes.
    WholeSeconds,
    /// `YYYYMMDD-HH:MM:SS.sss`, 21 bytes.
    Millis,
}

/// What the FIX specification asks a session in `version` to write: whole
/// seconds before FIX 4.2, milliseconds from it.
fn expected_precision(version: FixVersion) -> Precision {
    match version {
        FixVersion::Fix40 | FixVersion::Fix41 => Precision::WholeSeconds,
        _ => Precision::Millis,
    }
}

/// Asserts that `tag` of `frame` is a `UTCTimestamp` in `precision`.
#[track_caller]
fn assert_precision(frame: &[u8], tag: u32, precision: Precision, what: &str) {
    let value = some(field(frame, tag), &format!("{what}: tag {tag} is missing"));
    let bytes = value.as_bytes();
    // Shared shape: YYYYMMDD-HH:MM:SS.
    let shape_ok = bytes.len() >= 17
        && bytes.get(8) == Some(&b'-')
        && bytes.get(11) == Some(&b':')
        && bytes.get(14) == Some(&b':')
        && [0..8, 9..11, 12..14, 15..17].into_iter().all(|range| {
            bytes
                .get(range)
                .is_some_and(|d| d.iter().all(u8::is_ascii_digit))
        });
    assert!(shape_ok, "{what}: {tag}='{value}' is not a UTCTimestamp");
    match precision {
        Precision::WholeSeconds => assert_eq!(
            bytes.len(),
            17,
            "{what}: {tag}='{value}' must be whole seconds"
        ),
        Precision::Millis => {
            assert_eq!(
                bytes.len(),
                21,
                "{what}: {tag}='{value}' must be milliseconds"
            );
            assert_eq!(bytes.get(17), Some(&b'.'), "{what}: {tag}='{value}'");
            assert!(
                bytes
                    .get(18..21)
                    .is_some_and(|d| d.iter().all(u8::is_ascii_digit)),
                "{what}: {tag}='{value}'"
            );
        }
    }
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

/// Reads the next frame the engine sends, within 5 s.
async fn next_frame(framed: &mut Framed<TcpStream, FixCodec>) -> BytesMut {
    let polled = ok(
        timeout(Duration::from_secs(5), framed.next()).await,
        "frame must arrive within 5s",
    );
    ok(some(polled, "stream must stay open"), "frame must decode")
}

/// A scripted peer's frame in `version`, from `sender` to `target`, stamped
/// with `sending_time`.
#[track_caller]
fn peer_frame(
    version: FixVersion,
    sender: &str,
    target: &str,
    msg_type: &str,
    seq: u64,
    sending_time: &str,
    body: &[(u32, &str)],
) -> BytesMut {
    let mut encoder = Encoder::new(version.begin_string());
    encoder.put_str(35, msg_type);
    encoder.put_str(49, sender);
    encoder.put_str(56, target);
    encoder.put_uint(34, seq);
    encoder.put_str(52, sending_time);
    for (tag, value) in body {
        encoder.put_str(*tag, value);
    }
    let mut frame = BytesMut::new();
    ok(encoder.finish_into(&mut frame), "test frame must encode");
    frame
}

/// A Logon body in `version`: `EncryptMethod` (98) = 0, `HeartBtInt` (108) =
/// 30 and, on a FIXT.1.1 session, the version's `DefaultApplVerID` (1137).
fn logon_body(version: FixVersion) -> Vec<(u32, &'static str)> {
    let mut body = vec![(98, "0"), (108, "30")];
    if let Some(code) = version.appl_ver_id() {
        body.push((1137, code));
    }
    body
}

/// An inbound message as the application saw it: `(MsgType, SendingTime)`.
type Seen = (String, Option<String>);

/// Forwards every inbound message, admin and application alike.
#[derive(Debug)]
struct RecordingApp {
    seen_tx: mpsc::UnboundedSender<Seen>,
}

impl RecordingApp {
    fn new() -> (Arc<Self>, mpsc::UnboundedReceiver<Seen>) {
        let (seen_tx, seen_rx) = mpsc::unbounded_channel();
        (Arc::new(Self { seen_tx }), seen_rx)
    }

    fn forward(&self, message: &RawMessage<'_>) {
        let _ = self.seen_tx.send((
            message.msg_type().as_str().to_string(),
            message.get_field_str(52).map(str::to_string),
        ));
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
        self.forward(message);
        Ok(())
    }

    async fn to_app(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_app(
        &self,
        message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        self.forward(message);
        Ok(())
    }
}

/// Receives the next inbound message of type `msg_type`, within 5 s.
async fn next_seen(rx: &mut mpsc::UnboundedReceiver<Seen>, msg_type: &str) -> Seen {
    loop {
        let seen = some(
            ok(
                timeout(Duration::from_secs(5), rx.recv()).await,
                "an inbound message arrives within 5s",
            ),
            "the application channel must stay open",
        );
        if seen.0 == msg_type {
            return seen;
        }
    }
}

/// An ExecutionReport the venue sends.
fn report() -> OutboundMessage {
    let mut report = OutboundMessage::new(MsgType::ExecutionReport);
    report
        .push_str(37, "EX-1")
        .push_str(17, "E-1")
        .push_char(150, '0')
        .push_char(39, '0');
    report
}

/// A NewOrderSingle the client sends.
fn order() -> OutboundMessage {
    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order
        .push_str(11, "ORDER-1")
        .push_str(55, "EUR/USD")
        .push_char(54, '1')
        .push_uint(38, 100);
    order
}

/// Asks the engine on the other end of `framed` to resend 1 to 2, with a
/// millisecond `SendingTime`, and asserts the reply: a GapFill for the Logon
/// at 1 and the replay of `original` at 2, every 52 and 122 in `precision`,
/// the replay's 122 equal to `original`'s 52.
async fn assert_resend_reply(
    framed: &mut Framed<TcpStream, FixCodec>,
    version: FixVersion,
    (sender, target): (&str, &str),
    original: &[u8],
    precision: Precision,
) {
    let request = peer_frame(
        version,
        sender,
        target,
        "2",
        2,
        Timestamp::now().format_millis().as_str(),
        &[(7, "1"), (16, "2")],
    );
    ok(framed.send(request).await, "the peer asks for a resend");

    // The Logon at 1 is administrative, so it is gap-filled.
    let fill = next_frame(framed).await;
    assert_eq!(msg_type_of(&fill), "4", "{version}: a GapFill comes first");
    assert_eq!(field(&fill, 34).as_deref(), Some("1"), "{version}");
    assert_eq!(field(&fill, 123).as_deref(), Some("Y"), "{version}");
    assert_eq!(field(&fill, 36).as_deref(), Some("2"), "{version}");
    assert_eq!(field(&fill, 43).as_deref(), Some("Y"), "{version}");
    assert_precision(&fill, 52, precision, &format!("{version} GapFill"));
    assert_precision(&fill, 122, precision, &format!("{version} GapFill"));
    assert_eq!(field(&fill, 122), field(&fill, 52), "{version}");

    // The application message at 2 is replayed from the store.
    let replay = next_frame(framed).await;
    assert_eq!(msg_type_of(&replay), msg_type_of(original), "{version}");
    assert_eq!(field(&replay, 34).as_deref(), Some("2"), "{version}");
    assert_eq!(field(&replay, 43).as_deref(), Some("Y"), "{version}");
    assert_precision(&replay, 52, precision, &format!("{version} replay"));
    assert_precision(&replay, 122, precision, &format!("{version} replay"));
    assert_eq!(
        field(&replay, 122),
        field(original, 52),
        "{version}: OrigSendingTime is the original SendingTime"
    );
}

/// An acceptor, in every framable version, writes 52 on its Logon
/// acknowledgement and on an application message, and 52 and 122 on the
/// GapFill and the replay answering a ResendRequest, in whole seconds on
/// FIX 4.0 and FIX 4.1 and in milliseconds on every later version. It
/// accepts the scripted client's whole-second Logon and millisecond
/// ResendRequest alike.
#[tokio::test]
async fn test_acceptor_writes_sending_times_in_the_precision_of_its_version() {
    let mut covered = Vec::new();
    for version in framable_versions() {
        let precision = expected_precision(version);
        let store = Arc::new(MemoryStore::new());
        let (venue_app, _rx) = RecordingApp::new();
        let acceptor = Acceptor::new(venue_config(version), venue_app)
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
        let (listener, addr) = bind_listener().await;
        let venue = tokio::spawn(async move { acceptor.accept(&listener).await });

        let stream = ok(TcpStream::connect(addr).await, "client connects");
        let mut framed = Framed::new(stream, FixCodec::new());
        let logon = peer_frame(
            version,
            "CLIENT",
            "VENUE",
            "A",
            1,
            Timestamp::now().format_seconds().as_str(),
            &logon_body(version),
        );
        ok(framed.send(logon).await, "client sends its logon");
        let ack = next_frame(&mut framed).await;
        assert_eq!(
            msg_type_of(&ack),
            "A",
            "{version}: the Logon is acknowledged"
        );
        assert_precision(&ack, 52, precision, &format!("{version} Logon ack"));
        let connection: Connection = ok(
            ok(
                ok(
                    timeout(Duration::from_secs(5), venue).await,
                    "handshake within 5s",
                ),
                "venue task joins",
            ),
            "acceptor establishes the session",
        );

        ok(connection.send(report()).await, "venue sends a report");
        let sent = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&sent), "8", "{version}");
        assert_eq!(field(&sent, 34).as_deref(), Some("2"), "{version}");
        assert_precision(&sent, 52, precision, &format!("{version} report"));

        assert_resend_reply(&mut framed, version, ("CLIENT", "VENUE"), &sent, precision).await;
        // Both inbound forms were taken in sequence: no Reject, nothing lost.
        assert_eq!(connection.next_target_seq(), 3, "{version}");
        covered.push(version);
    }
    assert_eq!(covered.len(), 8, "every framable version runs: {covered:?}");
}

/// An initiator, in every framable version, writes 52 on its Logon and on an
/// application message, and 52 and 122 on the GapFill and the replay
/// answering a ResendRequest, in whole seconds on FIX 4.0 and FIX 4.1 and in
/// milliseconds on every later version. It accepts the scripted venue's
/// whole-second acknowledgement and millisecond ResendRequest alike.
#[tokio::test]
async fn test_initiator_writes_sending_times_in_the_precision_of_its_version() {
    let mut covered = Vec::new();
    for version in framable_versions() {
        let precision = expected_precision(version);
        let (listener, addr) = bind_listener().await;
        let venue = tokio::spawn(async move {
            let (socket, _) = ok(listener.accept().await, "the venue accepts");
            let mut framed = Framed::new(socket, FixCodec::new());
            let logon = next_frame(&mut framed).await;
            assert_eq!(msg_type_of(&logon), "A", "{version}: a Logon comes first");
            assert_precision(&logon, 52, precision, &format!("{version} Logon"));
            let ack = peer_frame(
                version,
                "VENUE",
                "CLIENT",
                "A",
                1,
                Timestamp::now().format_seconds().as_str(),
                &logon_body(version),
            );
            ok(framed.send(ack).await, "the venue acknowledges");
            framed
        });

        let store = Arc::new(MemoryStore::new());
        let (client_app, _rx) = RecordingApp::new();
        let connection = ok(
            Initiator::new(client_config(version), client_app)
                .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
                .connect(addr)
                .await,
            "the initiator logs on",
        );
        let mut framed = ok(
            ok(
                timeout(Duration::from_secs(5), venue).await,
                "venue done within 5s",
            ),
            "venue task",
        );

        ok(connection.send(order()).await, "client sends an order");
        let sent = next_frame(&mut framed).await;
        assert_eq!(msg_type_of(&sent), "D", "{version}");
        assert_eq!(field(&sent, 34).as_deref(), Some("2"), "{version}");
        assert_precision(&sent, 52, precision, &format!("{version} order"));

        assert_resend_reply(&mut framed, version, ("VENUE", "CLIENT"), &sent, precision).await;
        assert_eq!(connection.next_target_seq(), 3, "{version}");
        covered.push(version);
    }
    assert_eq!(covered.len(), 8, "every framable version runs: {covered:?}");
}

/// A real `Initiator` against a real `Acceptor`, both on FIX 4.0 and then
/// both on FIX 4.1: each validates the other's whole-second Logon, and an
/// application message each way arrives with a whole-second 52.
#[tokio::test]
async fn test_fix40_and_fix41_engines_exchange_whole_second_messages() {
    for version in [FixVersion::Fix40, FixVersion::Fix41] {
        let (listener, addr) = bind_listener().await;
        let (venue_app, mut venue_rx) = RecordingApp::new();
        let acceptor = Acceptor::new(venue_config(version), venue_app);
        let venue = tokio::spawn(async move { acceptor.accept(&listener).await });

        let (client_app, mut client_rx) = RecordingApp::new();
        let client = ok(
            Initiator::new(client_config(version), client_app)
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

        for (rx, side) in [(&mut venue_rx, "venue"), (&mut client_rx, "client")] {
            let (_, sending_time) = next_seen(rx, "A").await;
            let sending_time = some(sending_time, "the Logon carries SendingTime");
            assert_eq!(
                sending_time.len(),
                17,
                "{version}: the {side} saw Logon 52='{sending_time}'"
            );
        }

        ok(client.send(order()).await, "the client sends an order");
        let (_, sending_time) = next_seen(&mut venue_rx, "D").await;
        let sending_time = some(sending_time, "the order carries SendingTime");
        assert_eq!(
            sending_time.len(),
            17,
            "{version}: order 52='{sending_time}'"
        );

        ok(
            venue_connection.send(report()).await,
            "the venue sends a report",
        );
        let (_, sending_time) = next_seen(&mut client_rx, "8").await;
        let sending_time = some(sending_time, "the report carries SendingTime");
        assert_eq!(
            sending_time.len(),
            17,
            "{version}: report 52='{sending_time}'"
        );

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
}
