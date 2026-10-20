/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! Integration tests for inbound dictionary validation on the session path
//! (issue #84, ADR-0031), in both roles, against a scripted counterparty.
//!
//! The engine is given an `InboundValidation` over an embedded
//! `ironfix-dictionary` dictionary (FIX 4.4, or FIXT 1.1 composed with FIX
//! 5.0 SP2) and a policy:
//!
//! - `Reject`: a failing application message gets a Reject carrying the
//!   right `SessionRejectReason` (373) and `RefTagID` (371), its number is
//!   consumed, it never reaches `from_app`, and the next message is delivered;
//! - `Log`: the message is delivered and a warning without field values is
//!   logged;
//! - `Off`, or no validation at all: behaviour is unchanged.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::message::RawMessage;
use ironfix_core::types::{CompId, Timestamp};
use ironfix_dictionary::{Dictionary, SessionDictionary, Validator};
use ironfix_engine::application::{Application, RejectReason, SessionId};
use ironfix_engine::{
    Acceptor, Connection, EngineBuilder, GapPolicy, InboundValidation, Initiator, OutboundMessage,
    ValidationPolicy, ValidationRejectMessage,
};
use ironfix_session::SessionConfig;
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

#[track_caller]
fn comp_id(value: &str) -> CompId {
    ok(CompId::new(value), "test CompId must be valid")
}

/// Which engine the test drives; the scripted counterparty plays the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Initiator,
    Acceptor,
}

/// The session's FIX version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Version {
    /// FIX 4.4, validated against the embedded FIX 4.4 dictionary.
    Fix44,
    /// FIX 5.0 SP2 over FIXT.1.1, validated against FIXT 1.1 + FIX 5.0 SP2.
    Fix50Sp2,
}

impl Version {
    /// The session configuration's `begin_string`.
    const fn config(self) -> &'static str {
        match self {
            Self::Fix44 => "FIX.4.4",
            Self::Fix50Sp2 => "FIX.5.0SP2",
        }
    }

    /// `BeginString` (8) on the wire.
    const fn wire(self) -> &'static str {
        match self {
            Self::Fix44 => "FIX.4.4",
            Self::Fix50Sp2 => "FIXT.1.1",
        }
    }

    /// The Logon body: `EncryptMethod`, `HeartBtInt` and, on FIXT.1.1,
    /// `DefaultApplVerID` (1137) = 9.
    fn logon(self) -> Vec<(u32, &'static str)> {
        let mut body = vec![(98, "0"), (108, "30")];
        if self == Self::Fix50Sp2 {
            body.push((1137, "9"));
        }
        body
    }

    /// A validator for this version over the embedded dictionaries.
    fn validator(self) -> Arc<dyn ironfix_core::InboundValidator> {
        match self {
            Self::Fix44 => Arc::new(Validator::new(ok(Dictionary::fix44(), "FIX 4.4 loads"))),
            Self::Fix50Sp2 => Arc::new(ok(
                SessionDictionary::new(
                    ok(Dictionary::fixt11(), "FIXT 1.1 loads"),
                    ok(Dictionary::fix50sp2(), "FIX 5.0 SP2 loads"),
                ),
                "FIXT 1.1 + FIX 5.0 SP2 compose",
            )),
        }
    }
}

impl Role {
    /// The counterparty's (sender, target) CompIDs.
    const fn peer_ids(self) -> (&'static str, &'static str) {
        match self {
            Self::Initiator => ("VENUE", "CLIENT"),
            Self::Acceptor => ("CLIENT", "VENUE"),
        }
    }

    /// The engine's configuration.
    fn config(self, version: Version, gap_policy: GapPolicy) -> SessionConfig {
        let (sender, target) = match self {
            Self::Initiator => ("CLIENT", "VENUE"),
            Self::Acceptor => ("VENUE", "CLIENT"),
        };
        SessionConfig::new(comp_id(sender), comp_id(target), version.config())
            .with_heartbeat_interval(Duration::from_secs(30))
            .with_gap_policy(gap_policy)
    }
}

/// A counterparty frame: MsgType, CompIDs, MsgSeqNum, SendingTime, `body`.
#[track_caller]
fn peer_msg(
    role: Role,
    version: Version,
    msg_type: &str,
    seq: u64,
    body: &[(u32, &str)],
) -> BytesMut {
    let (sender, target) = role.peer_ids();
    let mut encoder = Encoder::new(version.wire());
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

/// A ClOrdID whose value must never appear in a log line or a Reject.
const SECRET_CLORDID: &str = "SECRET-ORDER-7";

/// A NewOrderSingle body valid against the version's dictionary, with
/// `drop` left out and `extra` appended.
fn order(
    version: Version,
    drop: Option<u32>,
    extra: &[(u32, &'static str)],
) -> Vec<(u32, &'static str)> {
    let mut body: Vec<(u32, &'static str)> = Vec::new();
    if version == Version::Fix50Sp2 {
        body.push((1128, "9"));
    }
    body.extend([
        (11, SECRET_CLORDID),
        (55, "EURUSD"),
        (54, "1"),
        (60, "20261020-10:00:00.000"),
        (40, "1"),
    ]);
    body.retain(|(tag, _)| Some(*tag) != drop);
    body.extend_from_slice(extra);
    body
}

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

type Peer = Framed<TcpStream, FixCodec>;

async fn next_frame(framed: &mut Peer) -> BytesMut {
    let polled = ok(
        timeout(Duration::from_secs(5), framed.next()).await,
        "frame must arrive within 5s",
    );
    ok(some(polled, "stream must stay open"), "frame must decode")
}

async fn send(framed: &mut Peer, frame: BytesMut) {
    ok(framed.send(frame).await, "the counterparty sends");
}

/// Records `(MsgType, MsgSeqNum)` of every application message `from_app`
/// sees.
#[derive(Debug)]
struct RecordingApp {
    app_tx: mpsc::UnboundedSender<(String, String)>,
}

#[async_trait]
impl Application for RecordingApp {
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
        let _ = self.app_tx.send((
            message.msg_type().as_str().to_string(),
            message.get_field_str(34).unwrap_or_default().to_string(),
        ));
        Ok(())
    }
}

/// A live session with the engine in `role`, both sides past their Logon at
/// MsgSeqNum 1, so the counterparty's next number is 2.
struct Live {
    framed: Peer,
    connection: Connection,
    app_rx: mpsc::UnboundedReceiver<(String, String)>,
    role: Role,
    version: Version,
}

impl Live {
    async fn open(role: Role, version: Version, validation: Option<InboundValidation>) -> Self {
        Self::open_with(role, version, validation, GapPolicy::default()).await
    }

    async fn open_with(
        role: Role,
        version: Version,
        validation: Option<InboundValidation>,
        gap_policy: GapPolicy,
    ) -> Self {
        let (app_tx, app_rx) = mpsc::unbounded_channel();
        let listener = ok(TcpListener::bind("127.0.0.1:0").await, "listener binds");
        let addr = ok(listener.local_addr(), "listener address");
        let logon = version.logon();
        let (framed, connection) = match role {
            Role::Initiator => {
                let venue = tokio::spawn(async move {
                    let (socket, _) = ok(listener.accept().await, "the venue accepts");
                    let mut framed = Framed::new(socket, FixCodec::new());
                    let logon_frame = next_frame(&mut framed).await;
                    assert_eq!(msg_type_of(&logon_frame), "A");
                    send(&mut framed, peer_msg(role, version, "A", 1, &logon)).await;
                    framed
                });
                // Through the builder, so its terminal method is covered.
                let builder = EngineBuilder::new()
                    .with_application(RecordingApp { app_tx })
                    .add_session(role.config(version, gap_policy));
                let builder = match validation {
                    Some(validation) => builder.with_inbound_validation(validation),
                    None => builder,
                };
                let initiator: Initiator<RecordingApp> =
                    ok(builder.into_initiator(), "the builder makes an initiator");
                let connection = ok(initiator.connect(addr).await, "the initiator connects");
                let framed = ok(
                    ok(timeout(Duration::from_secs(5), venue).await, "venue in 5s"),
                    "venue task joins",
                );
                (framed, connection)
            }
            Role::Acceptor => {
                let acceptor = Acceptor::new(
                    role.config(version, gap_policy),
                    Arc::new(RecordingApp { app_tx }),
                );
                let acceptor = match validation {
                    Some(validation) => acceptor.with_inbound_validation(validation),
                    None => acceptor,
                };
                let acceptor = Arc::new(acceptor);
                let venue = tokio::spawn(async move { acceptor.accept(&listener).await });
                let stream = ok(TcpStream::connect(addr).await, "the client connects");
                let mut framed = Framed::new(stream, FixCodec::new());
                send(&mut framed, peer_msg(role, version, "A", 1, &logon)).await;
                let ack = next_frame(&mut framed).await;
                assert_eq!(msg_type_of(&ack), "A");
                let connection = ok(
                    ok(
                        ok(timeout(Duration::from_secs(5), venue).await, "venue in 5s"),
                        "venue task joins",
                    ),
                    "the acceptor establishes the session",
                );
                (framed, connection)
            }
        };
        Self {
            framed,
            connection,
            app_rx,
            role,
            version,
        }
    }

    async fn send_app(&mut self, msg_type: &str, seq: u64, body: &[(u32, &str)]) {
        let frame = peer_msg(self.role, self.version, msg_type, seq, body);
        send(&mut self.framed, frame).await;
    }

    /// Reads the next frame, which must be a session-level Reject of `seq`
    /// with `RefTagID` (371) and `SessionRejectReason` (373); returns its
    /// Text (58).
    async fn expect_reject(
        &mut self,
        seq: u64,
        ref_msg_type: &str,
        ref_tag: &str,
        code: &str,
    ) -> String {
        let reject = next_frame(&mut self.framed).await;
        assert_eq!(msg_type_of(&reject), "3", "a session-level Reject");
        let seq = seq.to_string();
        assert_eq!(
            field(&reject, 45).as_deref(),
            Some(seq.as_str()),
            "RefSeqNum"
        );
        assert_eq!(
            field(&reject, 372).as_deref(),
            Some(ref_msg_type),
            "RefMsgType"
        );
        assert_eq!(field(&reject, 371).as_deref(), Some(ref_tag), "RefTagID");
        assert_eq!(
            field(&reject, 373).as_deref(),
            Some(code),
            "SessionRejectReason"
        );
        let text = some(field(&reject, 58), "the Reject carries Text (58)");
        assert!(
            !text.contains(SECRET_CLORDID),
            "Text quotes a value: {text}"
        );
        text
    }

    /// Collects exactly `expected` `(MsgType, MsgSeqNum)` from `from_app`,
    /// then nothing more.
    async fn expect_app(&mut self, expected: &[(&str, &str)]) {
        let mut seen = Vec::new();
        for _ in expected {
            let next = ok(
                timeout(Duration::from_secs(5), self.app_rx.recv()).await,
                "an application message within 5s",
            );
            seen.push(some(next, "the app channel stays open"));
        }
        let expected: Vec<(String, String)> = expected
            .iter()
            .map(|(t, s)| ((*t).to_string(), (*s).to_string()))
            .collect();
        assert_eq!(seen, expected, "from_app");
        self.expect_no_app().await;
    }

    async fn expect_no_app(&mut self) {
        if let Ok(Some(seen)) = timeout(Duration::from_millis(300), self.app_rx.recv()).await {
            panic!("unexpected application message {seen:?}");
        }
    }

    /// Asserts the engine sends nothing for 300 ms.
    async fn expect_silent(&mut self) {
        if let Ok(Some(Ok(frame))) = timeout(Duration::from_millis(300), self.framed.next()).await {
            panic!("unexpected MsgType {}", msg_type_of(&frame));
        }
    }
}

fn validation(version: Version, policy: ValidationPolicy) -> InboundValidation {
    InboundValidation::new(version.validator(), policy)
}

const ROLES: [Role; 2] = [Role::Initiator, Role::Acceptor];

/// One defect case: (MsgType, body, expected `RefTagID`, expected 373).
type DefectCase = (
    &'static str,
    Vec<(u32, &'static str)>,
    &'static str,
    &'static str,
);

// ---------------------------------------------------------------------------
// Reject
// ---------------------------------------------------------------------------

/// A NewOrderSingle without `Side` (54) gets a Reject with `RefTagID` = 54
/// and reason 1, its number is consumed, `from_app` never sees it, and the
/// next message is delivered.
async fn missing_side_is_rejected(role: Role, version: Version) {
    let mut live = Live::open(
        role,
        version,
        Some(validation(version, ValidationPolicy::Reject)),
    )
    .await;
    live.send_app("D", 2, &order(version, Some(54), &[])).await;
    let text = live.expect_reject(2, "D", "54", "1").await;
    assert_eq!(text, "required tag missing: Side(54)");
    live.expect_no_app().await;
    assert_eq!(
        live.connection.next_target_seq(),
        3,
        "the number is consumed"
    );

    live.send_app("D", 3, &order(version, None, &[])).await;
    live.expect_app(&[("D", "3")]).await;
    assert_eq!(live.connection.next_target_seq(), 4);
}

#[tokio::test]
async fn test_reject_missing_side_fix44_both_roles() {
    for role in ROLES {
        missing_side_is_rejected(role, Version::Fix44).await;
    }
}

#[tokio::test]
async fn test_reject_missing_side_fixt_with_fix50sp2_application_dictionary_both_roles() {
    for role in ROLES {
        missing_side_is_rejected(role, Version::Fix50Sp2).await;
    }
}

/// Each defect class is rejected with its reason code and `RefTagID`.
#[tokio::test]
async fn test_reject_maps_each_defect_to_its_reason_both_roles() {
    let v = Version::Fix44;
    // (MsgType, body, RefTagID, 373)
    let cases: Vec<DefectCase> = vec![
        // An undefined tag: 373 = 0.
        ("D", order(v, None, &[(4999, "1")]), "4999", "0"),
        // A defined tag the message type does not allow: 373 = 2.
        ("D", order(v, None, &[(150, "0")]), "150", "2"),
        // A bad enum value: 373 = 5.
        ("D", order(v, Some(54), &[(54, "X")]), "54", "5"),
        // A bad data format (OrderQty not a number): 373 = 6.
        ("D", order(v, None, &[(38, "lots")]), "38", "6"),
        // A group count that does not match its entries: 373 = 16.
        (
            "D",
            order(
                v,
                None,
                &[(453, "2"), (448, "BROKER-A"), (447, "D"), (452, "1")],
            ),
            "453",
            "16",
        ),
        // A group entry not led by its delimiter: 373 = 15.
        (
            "D",
            order(
                v,
                None,
                &[(453, "1"), (447, "D"), (448, "BROKER-A"), (452, "1")],
            ),
            "447",
            "15",
        ),
        // A message type the dictionary does not define: 373 = 11.
        ("ZZ", vec![(11, SECRET_CLORDID)], "35", "11"),
    ];
    for role in ROLES {
        let mut live = Live::open(role, v, Some(validation(v, ValidationPolicy::Reject))).await;
        let mut seq = 2;
        for (msg_type, body, ref_tag, code) in &cases {
            live.send_app(msg_type, seq, body).await;
            live.expect_reject(seq, msg_type, ref_tag, code).await;
            seq += 1;
        }
        live.expect_no_app().await;
        assert_eq!(live.connection.next_target_seq(), seq);
        live.send_app("D", seq, &order(v, None, &[])).await;
        let seq = seq.to_string();
        live.expect_app(&[("D", seq.as_str())]).await;
    }
}

/// With the BusinessMessageReject option, a missing required tag is answered
/// with 35=j, `BusinessRejectReason` (380) = 5; a syntax defect still gets a
/// session-level Reject.
#[tokio::test]
async fn test_reject_with_business_message_reject_both_roles() {
    let v = Version::Fix44;
    for role in ROLES {
        let validation = validation(v, ValidationPolicy::Reject)
            .with_reject_message(ValidationRejectMessage::BusinessMessageReject);
        let mut live = Live::open(role, v, Some(validation)).await;
        live.send_app("D", 2, &order(v, Some(54), &[])).await;
        let reject = next_frame(&mut live.framed).await;
        assert_eq!(msg_type_of(&reject), "j");
        assert_eq!(field(&reject, 45).as_deref(), Some("2"));
        assert_eq!(field(&reject, 372).as_deref(), Some("D"));
        assert_eq!(field(&reject, 380).as_deref(), Some("5"));
        assert_eq!(
            field(&reject, 58).as_deref(),
            Some("required tag missing: Side(54)")
        );

        live.send_app("D", 3, &order(v, None, &[(38, "lots")]))
            .await;
        live.expect_reject(3, "D", "38", "6").await;
        live.expect_no_app().await;
        assert_eq!(live.connection.next_target_seq(), 4);
    }
}

// ---------------------------------------------------------------------------
// Log
// ---------------------------------------------------------------------------

/// A `tracing` writer that keeps everything written to it.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.0.lock() {
            Ok(mut out) => out.extend_from_slice(buf),
            Err(poisoned) => poisoned.into_inner().extend_from_slice(buf),
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn text(&self) -> String {
        match self.0.lock() {
            Ok(out) => String::from_utf8_lossy(&out).into_owned(),
            Err(poisoned) => String::from_utf8_lossy(&poisoned.into_inner()).into_owned(),
        }
    }
}

/// With `Log`, the message reaches `from_app` and a warning names the
/// defect and the tag, never a value.
/// The process-wide capture every event of this test binary is written to.
///
/// Global rather than thread-local: `tracing` caches each callsite's
/// interest process-wide, so a thread-local subscriber can miss an event
/// whose callsite another test thread registered first. Every test here
/// writes to it, so the value check below covers the `Reject` warnings too.
fn captured() -> &'static Captured {
    static CAPTURED: std::sync::OnceLock<Captured> = std::sync::OnceLock::new();
    CAPTURED.get_or_init(|| {
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        ok(
            tracing::subscriber::set_global_default(subscriber),
            "the test subscriber installs once",
        );
        captured
    })
}

#[tokio::test]
async fn test_log_delivers_and_warns_without_values_both_roles() {
    let captured = captured();
    let v = Version::Fix44;
    for role in ROLES {
        let mut live = Live::open(role, v, Some(validation(v, ValidationPolicy::Log))).await;
        live.send_app("D", 2, &order(v, Some(54), &[])).await;
        live.expect_app(&[("D", "2")]).await;
        live.expect_silent().await;
        assert_eq!(live.connection.next_target_seq(), 3);
    }
    let logged = captured.text();
    let log_lines: Vec<&str> = logged
        .lines()
        .filter(|line| line.contains("policy=Log"))
        .collect();
    assert_eq!(log_lines.len(), 2, "one warning per role: {logged}");
    for line in log_lines {
        assert!(
            line.contains("inbound application message failed dictionary validation"),
            "{line}"
        );
        assert!(line.contains("ref_tag=54"), "{line}");
        assert!(line.contains("defect=required tag missing"), "{line}");
    }
    for value in [SECRET_CLORDID, "EURUSD", "20261020-10:00:00.000"] {
        assert!(!logged.contains(value), "the log quotes {value}: {logged}");
    }
}

// ---------------------------------------------------------------------------
// Off
// ---------------------------------------------------------------------------

/// With `Off`, and with no validation at all, an invalid message is
/// delivered and nothing is sent back.
#[tokio::test]
async fn test_off_leaves_behaviour_unchanged_both_roles() {
    let v = Version::Fix44;
    for role in ROLES {
        for validation in [None, Some(validation(v, ValidationPolicy::Off))] {
            let mut live = Live::open(role, v, validation).await;
            live.send_app("D", 2, &order(v, Some(54), &[])).await;
            live.send_app("ZZ", 3, &[(11, SECRET_CLORDID)]).await;
            live.expect_app(&[("D", "2"), ("ZZ", "3")]).await;
            live.expect_silent().await;
            assert_eq!(live.connection.next_target_seq(), 4);
        }
    }
}

/// Administrative messages are never validated: a TestRequest is answered
/// under `Reject` even though the FIX 4.4 dictionary would not object.
#[tokio::test]
async fn test_reject_does_not_touch_admin_messages_both_roles() {
    let v = Version::Fix44;
    for role in ROLES {
        let mut live = Live::open(role, v, Some(validation(v, ValidationPolicy::Reject))).await;
        // 4999 is undefined; on an application message it would be rejected.
        live.send_app("1", 2, &[(112, "PING"), (4999, "1")]).await;
        let heartbeat = next_frame(&mut live.framed).await;
        assert_eq!(msg_type_of(&heartbeat), "0");
        assert_eq!(field(&heartbeat, 112).as_deref(), Some("PING"));
        assert_eq!(live.connection.next_target_seq(), 3);
    }
}

/// Under `GapPolicy::Queue`, an invalid message held above a gap is
/// validated when it is released in order, not when it arrives: the resent
/// message that fills the gap is delivered, then the held one is rejected.
#[tokio::test]
async fn test_reject_validates_a_queued_message_on_release_both_roles() {
    let v = Version::Fix44;
    let queue = GapPolicy::Queue {
        max_messages: 16,
        max_bytes: 1024 * 1024,
    };
    for role in ROLES {
        let validation = validation(v, ValidationPolicy::Reject);
        let mut live = Live::open_with(role, v, Some(validation), queue).await;
        live.send_app("D", 3, &order(v, Some(54), &[])).await;
        let request = next_frame(&mut live.framed).await;
        assert_eq!(msg_type_of(&request), "2", "a ResendRequest, not a Reject");
        assert_eq!(field(&request, 7).as_deref(), Some("2"));
        live.expect_no_app().await;

        let mut resent = vec![(43, "Y"), (122, "20261020-09:59:59.000")];
        resent.extend(order(v, None, &[]));
        live.send_app("D", 2, &resent).await;
        live.expect_reject(3, "D", "54", "1").await;
        live.expect_app(&[("D", "2")]).await;
        assert_eq!(live.connection.next_target_seq(), 4);
    }
}
