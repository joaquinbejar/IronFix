/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! Integration tests for the replay gate (issue #133, ADR-0023 "Replay
//! gate"), in both roles and on both resend paths.
//!
//! Before a filed application message is resent, the engine asks
//! `Application::to_app_resend`. A veto gap-fills the message instead of
//! resending it, and a run of vetoed messages (with the administrative
//! messages and holes next to it) is covered by one SequenceReset-GapFill.
//! A message that is resent still carries `PossDupFlag` (43) = Y and
//! `OrigSendingTime` (122). The default hook allows every replay.
//!
//! Each test seeds the engine's store with its Logon (1) and execution
//! reports at 2..=6, logs on against a scripted counterparty over an
//! in-memory pipe, and triggers the resend either with a `ResendRequest`
//! (2) for everything from 2 or with `NextExpectedMsgSeqNum` (789) = 2 on
//! the counterparty's Logon or acknowledgement.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::application::{Application, RejectReason, SendVerdict, SessionId};
use ironfix_engine::{Acceptor, Connection, Initiator, OutboundMessage};
use ironfix_session::SessionConfig;
use ironfix_store::{MemoryStore, MessageStore};
use ironfix_tagvalue::{Decoder, Encoder};
use ironfix_transport::FixCodec;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::DuplexStream;
use tokio::time::timeout;
use tokio_util::codec::Framed;

/// The last execution report seeded in the store; reports are 2..=LAST.
const LAST: u64 = 6;

/// Fails the test with context instead of `.unwrap()` / `.expect()`.
#[track_caller]
fn ok<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{what}: {err:?}"),
    }
}

/// Builds a CompID for the test fixtures.
#[track_caller]
fn comp_id(value: &str) -> CompId {
    ok(CompId::new(value), "test CompId must be valid")
}

/// The role the engine under test plays; the scripted peer plays the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Acceptor,
    Initiator,
}

/// What asks the engine for the resend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Trigger {
    /// A `ResendRequest` (2) from 2 to infinity, after the logon.
    ResendRequest,
    /// `NextExpectedMsgSeqNum` (789) = 2 on the peer's Logon or ack.
    NextExpected,
}

impl Role {
    /// The engine's (SenderCompID, TargetCompID).
    const fn ids(self) -> (&'static str, &'static str) {
        match self {
            Self::Acceptor => ("VENUE", "CLIENT"),
            Self::Initiator => ("CLIENT", "VENUE"),
        }
    }

    /// The engine's FIX.4.4 configuration.
    fn config(self, trigger: Trigger) -> SessionConfig {
        let (sender, target) = self.ids();
        SessionConfig::new(comp_id(sender), comp_id(target), "FIX.4.4")
            .with_heartbeat_interval(Duration::from_secs(30))
            .with_send_next_expected_msg_seq_num(trigger == Trigger::NextExpected)
    }

    /// A frame the engine itself sent, for seeding its store.
    fn engine_msg(self, msg_type: &str, seq: u64, body: &[(u32, &str)]) -> BytesMut {
        let (sender, target) = self.ids();
        frame(sender, target, msg_type, seq, body)
    }

    /// A frame from the scripted peer.
    fn peer_msg(self, msg_type: &str, seq: u64, body: &[(u32, &str)]) -> BytesMut {
        let (sender, target) = self.ids();
        frame(target, sender, msg_type, seq, body)
    }
}

/// A FIX.4.4 frame: MsgType, the CompIDs, `MsgSeqNum`, `SendingTime`, then
/// `body`.
#[track_caller]
fn frame(sender: &str, target: &str, msg_type: &str, seq: u64, body: &[(u32, &str)]) -> BytesMut {
    let mut encoder = Encoder::new("FIX.4.4");
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

/// A frame's field as a string.
fn field(frame: &[u8], tag: u32) -> Option<String> {
    let mut decoder = Decoder::new(frame);
    let message = decoder.decode().ok()?;
    message.get_field_str(tag).map(str::to_string)
}

/// A frame's numeric field, or 0.
fn num(frame: &[u8], tag: u32) -> u64 {
    field(frame, tag)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

type PeerFramed = Framed<DuplexStream, FixCodec>;

/// Reads the next frame, within 5 s.
async fn next_frame(framed: &mut PeerFramed) -> BytesMut {
    match timeout(Duration::from_secs(5), framed.next()).await {
        Ok(Some(Ok(frame))) => frame,
        Ok(Some(Err(err))) => panic!("frame must decode: {err:?}"),
        Ok(None) => panic!("the engine hung up"),
        Err(_) => panic!("no frame within 5s"),
    }
}

/// One frame of the resend, as the peer sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    /// A resent execution report under this number.
    Replay(u64),
    /// A SequenceReset-GapFill at `.0` with `NewSeqNo` (36) `.1`.
    Fill(u64, u64),
}

/// Classifies a resend frame, checking the tags each kind must carry.
fn classify(frame: &[u8]) -> Seen {
    let seq = num(frame, 34);
    match field(frame, 35).as_deref() {
        Some("8") => {
            assert_eq!(field(frame, 43).as_deref(), Some("Y"), "43=Y on {seq}");
            assert!(field(frame, 122).is_some(), "122 on {seq}");
            assert_eq!(field(frame, 37).as_deref(), Some("EX-1"), "body kept");
            Seen::Replay(seq)
        }
        Some("4") => {
            assert_eq!(field(frame, 123).as_deref(), Some("Y"), "a gap fill");
            Seen::Fill(seq, num(frame, 36))
        }
        other => panic!("unexpected MsgType {other:?} at {seq} inside the resend"),
    }
}

/// The resend of `2..end` the engine must write when the reports in
/// `vetoed` are refused: every allowed report replayed, and each run of
/// vetoed reports, together with the Logon or acknowledgement at the end,
/// covered by one gap fill.
fn expected(vetoed: &BTreeSet<u64>, end: u64) -> Vec<Seen> {
    let mut out = Vec::new();
    let mut cursor = 2;
    for seq in 2..=LAST {
        if vetoed.contains(&seq) {
            continue;
        }
        if seq > cursor {
            out.push(Seen::Fill(cursor, seq));
        }
        out.push(Seen::Replay(seq));
        cursor = seq + 1;
    }
    if cursor < end {
        out.push(Seen::Fill(cursor, end));
    }
    out
}

/// What the gate saw: `(MsgSeqNum, MsgType, PossDupFlag, has
/// OrigSendingTime)`.
type Asked = (u64, String, Option<String>, bool);

/// Records every replay the gate is asked about and vetoes the numbers in
/// `veto`; with `gate` off it keeps the default hook.
#[derive(Debug, Default)]
struct App {
    gate: bool,
    veto: BTreeSet<u64>,
    /// `(MsgSeqNum, MsgType, PossDupFlag, has OrigSendingTime)`.
    asked: Mutex<Vec<Asked>>,
    checked: Mutex<u64>,
}

impl App {
    fn asked(&self) -> Vec<Asked> {
        self.asked
            .lock()
            .map(|asked| asked.clone())
            .unwrap_or_default()
    }
}

#[async_trait]
impl Application for App {
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

    async fn to_app(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {
        if let Ok(mut checked) = self.checked.lock() {
            *checked += 1;
        }
    }

    async fn from_app(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }

    fn to_app_resend<'a>(
        &'a self,
        message: &'a RawMessage<'_>,
        _session_id: &'a SessionId,
    ) -> SendVerdict<'a> {
        if !self.gate {
            return SendVerdict::ready(Ok(()));
        }
        let seq = message
            .get_field_str(34)
            .and_then(|seq| seq.parse().ok())
            .unwrap_or(0);
        if let Ok(mut asked) = self.asked.lock() {
            asked.push((
                seq,
                message.get_field_str(35).unwrap_or_default().to_string(),
                message.get_field_str(43).map(str::to_string),
                message.get_field_str(122).is_some(),
            ));
        }
        if self.veto.contains(&seq) {
            SendVerdict::ready(Err(RejectReason::new(1, "stale order")))
        } else {
            SendVerdict::ready(Ok(()))
        }
    }
}

/// The engine's previous stream: its Logon (1) and reports 2..=LAST; next
/// sender LAST+1, next target 3.
async fn seeded_store(role: Role) -> Arc<MemoryStore> {
    let store = MemoryStore::new();
    ok(
        store
            .store(
                1,
                &MsgType::Logon,
                &role.engine_msg("A", 1, &[(98, "0"), (108, "30")]),
            )
            .await,
        "seed the Logon",
    );
    let body = [(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")];
    for seq in 2..=LAST {
        ok(
            store
                .store(
                    seq,
                    &MsgType::ExecutionReport,
                    &role.engine_msg("8", seq, &body),
                )
                .await,
            "seed a report",
        );
    }
    ok(store.set_next_sender_seq(LAST + 1).await, "sender counter");
    ok(store.set_next_target_seq(3).await, "target counter");
    Arc::new(store)
}

/// Logs on, triggers the resend, and returns the frames of the resend, the
/// peer's end of the pipe and the connection.
async fn run(role: Role, trigger: Trigger, app: Arc<App>) -> (Vec<Seen>, PeerFramed, Connection) {
    let store = seeded_store(role).await as Arc<dyn MessageStore>;
    let (peer_io, engine_io) = tokio::io::duplex(64 * 1024);
    let config = role.config(trigger);
    let engine_app = Arc::clone(&app);
    let engine = match role {
        Role::Acceptor => tokio::spawn(async move {
            Acceptor::new(config, engine_app)
                .with_store(store)
                .serve_stream(engine_io)
                .await
        }),
        Role::Initiator => tokio::spawn(async move {
            Initiator::new(config, engine_app)
                .with_store(store)
                .establish(engine_io)
                .await
        }),
    };
    let mut framed = Framed::new(peer_io, FixCodec::new());
    let mut logon_body = vec![(98, "0"), (108, "30")];
    if trigger == Trigger::NextExpected {
        logon_body.push((789, "2"));
    }
    if role == Role::Initiator {
        let theirs = next_frame(&mut framed).await;
        assert_eq!(
            field(&theirs, 35).as_deref(),
            Some("A"),
            "initiator logs on"
        );
        assert_eq!(num(&theirs, 34), LAST + 1);
    }
    ok(
        framed.send(role.peer_msg("A", 3, &logon_body)).await,
        "the peer's Logon",
    );
    if role == Role::Acceptor {
        let ack = next_frame(&mut framed).await;
        assert_eq!(field(&ack, 35).as_deref(), Some("A"), "Logon acknowledged");
        assert_eq!(num(&ack, 34), LAST + 1);
    }
    let connection = ok(
        ok(
            ok(timeout(Duration::from_secs(5), engine).await, "handshake"),
            "engine task joins",
        ),
        "the engine establishes the session",
    );
    // The ResendRequest covers the engine's own Logon or ack (admin, so
    // gap-filled) as well; 789 stops before it.
    let end = match trigger {
        Trigger::ResendRequest => {
            ok(
                framed
                    .send(role.peer_msg("2", 4, &[(7, "2"), (16, "0")]))
                    .await,
                "the ResendRequest",
            );
            LAST + 2
        }
        Trigger::NextExpected => LAST + 1,
    };
    let mut seen = Vec::new();
    loop {
        let frame = next_frame(&mut framed).await;
        let item = classify(&frame);
        let reached = match item {
            Seen::Replay(seq) => seq + 1,
            Seen::Fill(_, new_seq) => new_seq,
        };
        seen.push(item);
        if reached >= end {
            break;
        }
    }
    (seen, framed, connection)
}

/// Runs one gated resend and checks the frames, what the gate saw, and that
/// the session carries on with new numbers after the resend.
async fn gated(role: Role, trigger: Trigger, veto: &[u64]) {
    let veto: BTreeSet<u64> = veto.iter().copied().collect();
    let app = Arc::new(App {
        gate: true,
        veto: veto.clone(),
        ..App::default()
    });
    let (seen, mut framed, connection) = run(role, trigger, Arc::clone(&app)).await;
    let end = match trigger {
        Trigger::ResendRequest => LAST + 2,
        Trigger::NextExpected => LAST + 1,
    };
    assert_eq!(seen, expected(&veto, end), "{role:?} {trigger:?} {veto:?}");

    // Asked once per stored application message, in order, about the
    // rebuilt frame; never about the stored Logon or acknowledgement.
    let asked = app.asked();
    let seqs: Vec<u64> = asked.iter().map(|entry| entry.0).collect();
    assert_eq!(seqs, (2..=LAST).collect::<Vec<_>>(), "one ask per report");
    for (seq, msg_type, poss_dup, orig) in asked {
        assert_eq!(msg_type, "8", "admin never gated ({seq})");
        assert_eq!(poss_dup.as_deref(), Some("Y"), "gate sees 43=Y ({seq})");
        assert!(orig, "gate sees 122 ({seq})");
    }
    assert_eq!(
        app.checked.lock().map(|checked| *checked).unwrap_or(1),
        0,
        "to_app_checked is not called for a replay"
    );

    // The resend stays ahead of new numbers: a new message after it takes
    // the next sender number, unflagged.
    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order.push_str(11, "ORD-1");
    ok(connection.send(order).await, "a new order");
    let new = next_frame(&mut framed).await;
    assert_eq!(field(&new, 35).as_deref(), Some("D"));
    assert_eq!(num(&new, 34), LAST + 2, "the next new number");
    assert_eq!(field(&new, 43), None, "a new message is not a duplicate");
    assert!(!connection.is_closed());
}

// ---------------------------------------------------------------------------
// ResendRequest, acceptor
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_acceptor_resend_request_veto_in_the_middle() {
    gated(Role::Acceptor, Trigger::ResendRequest, &[4]).await;
}

#[tokio::test]
async fn test_acceptor_resend_request_veto_at_the_start() {
    gated(Role::Acceptor, Trigger::ResendRequest, &[2]).await;
}

#[tokio::test]
async fn test_acceptor_resend_request_veto_at_the_end() {
    gated(Role::Acceptor, Trigger::ResendRequest, &[LAST]).await;
}

#[tokio::test]
async fn test_acceptor_resend_request_run_of_vetoes_is_one_gap_fill() {
    gated(Role::Acceptor, Trigger::ResendRequest, &[3, 4, 5]).await;
}

#[tokio::test]
async fn test_acceptor_resend_request_all_vetoed_is_one_gap_fill() {
    gated(Role::Acceptor, Trigger::ResendRequest, &[2, 3, 4, 5, 6]).await;
}

// ---------------------------------------------------------------------------
// ResendRequest, initiator
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_initiator_resend_request_veto_in_the_middle() {
    gated(Role::Initiator, Trigger::ResendRequest, &[4]).await;
}

#[tokio::test]
async fn test_initiator_resend_request_veto_at_the_start() {
    gated(Role::Initiator, Trigger::ResendRequest, &[2]).await;
}

#[tokio::test]
async fn test_initiator_resend_request_veto_at_the_end() {
    gated(Role::Initiator, Trigger::ResendRequest, &[LAST]).await;
}

#[tokio::test]
async fn test_initiator_resend_request_run_of_vetoes_is_one_gap_fill() {
    gated(Role::Initiator, Trigger::ResendRequest, &[3, 4, 5]).await;
}

// ---------------------------------------------------------------------------
// NextExpectedMsgSeqNum (789), both roles
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_acceptor_next_expected_veto_in_the_middle() {
    gated(Role::Acceptor, Trigger::NextExpected, &[4]).await;
}

#[tokio::test]
async fn test_acceptor_next_expected_veto_at_the_start() {
    gated(Role::Acceptor, Trigger::NextExpected, &[2]).await;
}

#[tokio::test]
async fn test_acceptor_next_expected_veto_at_the_end() {
    gated(Role::Acceptor, Trigger::NextExpected, &[LAST]).await;
}

#[tokio::test]
async fn test_acceptor_next_expected_run_of_vetoes_is_one_gap_fill() {
    gated(Role::Acceptor, Trigger::NextExpected, &[2, 3, 5, 6]).await;
}

#[tokio::test]
async fn test_initiator_next_expected_veto_in_the_middle() {
    gated(Role::Initiator, Trigger::NextExpected, &[4]).await;
}

#[tokio::test]
async fn test_initiator_next_expected_veto_at_the_start() {
    gated(Role::Initiator, Trigger::NextExpected, &[2]).await;
}

#[tokio::test]
async fn test_initiator_next_expected_veto_at_the_end() {
    gated(Role::Initiator, Trigger::NextExpected, &[LAST]).await;
}

#[tokio::test]
async fn test_initiator_next_expected_run_of_vetoes_is_one_gap_fill() {
    gated(Role::Initiator, Trigger::NextExpected, &[3, 4, 5, 6]).await;
}

// ---------------------------------------------------------------------------
// The default hook: unchanged behaviour
// ---------------------------------------------------------------------------

/// With the default `to_app_resend`, every filed report is resent with
/// 43=Y and 122, in both roles and on both paths.
#[tokio::test]
async fn test_default_hook_resends_everything_as_filed() {
    for role in [Role::Acceptor, Role::Initiator] {
        for trigger in [Trigger::ResendRequest, Trigger::NextExpected] {
            let app = Arc::new(App::default());
            let (seen, _framed, connection) = run(role, trigger, Arc::clone(&app)).await;
            let end = match trigger {
                Trigger::ResendRequest => LAST + 2,
                Trigger::NextExpected => LAST + 1,
            };
            assert_eq!(
                seen,
                expected(&BTreeSet::new(), end),
                "{role:?} {trigger:?}"
            );
            assert!(app.asked().is_empty());
            assert!(!connection.is_closed());
        }
    }
}
