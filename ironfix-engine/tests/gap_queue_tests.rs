/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 19/10/26
******************************************************************************/

//! Integration tests for `GapPolicy` (issue #71, ADR-0027): messages that
//! arrive above an open gap are dropped under `Discard` and kept and released
//! in order under `Queue`, in both roles, against a scripted counterparty.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::message::RawMessage;
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::application::{Application, RejectReason, SessionId};
use ironfix_engine::{Acceptor, Connection, GapPolicy, Initiator, OutboundMessage};
use ironfix_session::SessionConfig;
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

impl Role {
    /// The counterparty's (sender, target) CompIDs.
    const fn peer_ids(self) -> (&'static str, &'static str) {
        match self {
            Self::Initiator => ("VENUE", "CLIENT"),
            Self::Acceptor => ("CLIENT", "VENUE"),
        }
    }

    /// The engine's configuration.
    fn config(self, policy: GapPolicy) -> SessionConfig {
        let (sender, target) = match self {
            Self::Initiator => ("CLIENT", "VENUE"),
            Self::Acceptor => ("VENUE", "CLIENT"),
        };
        SessionConfig::new(comp_id(sender), comp_id(target), "FIX.4.4")
            .with_heartbeat_interval(Duration::from_secs(30))
            .with_gap_policy(policy)
    }
}

/// A queue holding up to `max_messages` and 1 MiB.
const fn queue(max_messages: usize) -> GapPolicy {
    GapPolicy::Queue {
        max_messages,
        max_bytes: 1024 * 1024,
    }
}

/// A counterparty frame: MsgType, CompIDs, MsgSeqNum, SendingTime, `body`.
#[track_caller]
fn peer_msg(role: Role, msg_type: &str, seq: u64, body: &[(u32, &str)]) -> BytesMut {
    let (sender, target) = role.peer_ids();
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

/// An application message (an ExecutionReport) from the counterparty.
#[track_caller]
fn app(role: Role, seq: u64) -> BytesMut {
    peer_msg(
        role,
        "8",
        seq,
        &[(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")],
    )
}

/// A resent application message: `PossDupFlag` (43) = Y and an
/// `OrigSendingTime` (122).
#[track_caller]
fn resent(role: Role, seq: u64) -> BytesMut {
    peer_msg(
        role,
        "8",
        seq,
        &[
            (43, "Y"),
            (122, "20261019-12:00:00.000"),
            (37, "EX-1"),
            (17, "E-1"),
            (150, "0"),
            (39, "0"),
        ],
    )
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

/// Records the `MsgSeqNum` of every application message `from_app` sees.
#[derive(Debug)]
struct RecordingApp {
    app_tx: mpsc::UnboundedSender<String>,
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
        let _ = self
            .app_tx
            .send(message.get_field_str(34).unwrap_or_default().to_string());
        Ok(())
    }
}

/// A live session with the engine in `role`, both sides past their Logon at
/// MsgSeqNum 1, so the counterparty's next number is 2.
struct Live {
    framed: Peer,
    connection: Connection,
    app_rx: mpsc::UnboundedReceiver<String>,
    role: Role,
}

impl Live {
    async fn open(role: Role, policy: GapPolicy) -> Self {
        let (app_tx, app_rx) = mpsc::unbounded_channel();
        let application = Arc::new(RecordingApp { app_tx });
        let listener = ok(TcpListener::bind("127.0.0.1:0").await, "listener binds");
        let addr = ok(listener.local_addr(), "listener address");
        let (framed, connection) = match role {
            Role::Initiator => {
                let venue = tokio::spawn(async move {
                    let (socket, _) = ok(listener.accept().await, "the venue accepts");
                    let mut framed = Framed::new(socket, FixCodec::new());
                    let logon = next_frame(&mut framed).await;
                    assert_eq!(msg_type_of(&logon), "A");
                    send(
                        &mut framed,
                        peer_msg(role, "A", 1, &[(98, "0"), (108, "30")]),
                    )
                    .await;
                    framed
                });
                let initiator = Initiator::new(role.config(policy), application);
                let connection = ok(initiator.connect(addr).await, "the initiator connects");
                let framed = ok(
                    ok(timeout(Duration::from_secs(5), venue).await, "venue in 5s"),
                    "venue task joins",
                );
                (framed, connection)
            }
            Role::Acceptor => {
                let acceptor = Arc::new(Acceptor::new(role.config(policy), application));
                let venue = tokio::spawn(async move { acceptor.accept(&listener).await });
                let stream = ok(TcpStream::connect(addr).await, "the client connects");
                let mut framed = Framed::new(stream, FixCodec::new());
                send(
                    &mut framed,
                    peer_msg(role, "A", 1, &[(98, "0"), (108, "30")]),
                )
                .await;
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
        }
    }

    async fn send(&mut self, frame: BytesMut) {
        send(&mut self.framed, frame).await;
    }

    /// Reads the `ResendRequest` the first gapped frame triggers.
    async fn expect_resend_request(&mut self, begin: &str) {
        let request = next_frame(&mut self.framed).await;
        assert_eq!(msg_type_of(&request), "2", "a ResendRequest");
        assert_eq!(field(&request, 7).as_deref(), Some(begin));
        assert_eq!(field(&request, 16).as_deref(), Some("0"));
    }

    /// Collects exactly `expected` from `from_app`, then nothing more.
    async fn expect_app(&mut self, expected: &[&str]) {
        let mut seen = Vec::new();
        for _ in expected {
            let next = ok(
                timeout(Duration::from_secs(5), self.app_rx.recv()).await,
                "an application message within 5s",
            );
            seen.push(some(next, "the app channel stays open"));
        }
        assert_eq!(seen, expected, "from_app order");
        self.expect_no_app().await;
    }

    async fn expect_no_app(&mut self) {
        if let Ok(Some(seq)) = timeout(Duration::from_millis(300), self.app_rx.recv()).await {
            panic!("unexpected application message {seq}");
        }
    }

    /// Proves the session is alive and its expectation is `seq`: a
    /// TestRequest numbered `seq` is answered with the matching Heartbeat,
    /// and nothing (no ResendRequest) comes before it.
    async fn ping(&mut self, seq: u64) {
        let id = format!("PING-{seq}");
        let role = self.role;
        self.send(peer_msg(role, "1", seq, &[(112, id.as_str())]))
            .await;
        let heartbeat = next_frame(&mut self.framed).await;
        assert_eq!(msg_type_of(&heartbeat), "0", "a Heartbeat, not a request");
        assert_eq!(field(&heartbeat, 112).as_deref(), Some(id.as_str()));
        let next = some(seq.checked_add(1), "seq in range");
        assert_eq!(self.connection.next_target_seq(), next);
    }
}

/// Under `Queue`, 3..=5 arrive while 2 is missing, with a TestRequest at 4
/// and a possible-duplicate copy of 3 meanwhile. The TestRequest is answered
/// at once; when 2 is resent, 3 and 5 follow it to `from_app` in order and
/// the TestRequest's number is consumed. The rest of the resend (3 and 5
/// again, a gap fill for 4) is ignored: nothing is delivered twice.
async fn queued_messages_are_released_in_order(role: Role) {
    let mut live = Live::open(role, queue(16)).await;
    live.send(app(role, 3)).await;
    live.expect_resend_request("2").await;
    live.send(resent(role, 3)).await;
    live.send(peer_msg(role, "1", 4, &[(112, "IN-GAP")])).await;
    let heartbeat = next_frame(&mut live.framed).await;
    assert_eq!(msg_type_of(&heartbeat), "0");
    assert_eq!(field(&heartbeat, 112).as_deref(), Some("IN-GAP"));
    live.send(app(role, 5)).await;
    live.expect_no_app().await;
    assert_eq!(live.connection.next_target_seq(), 2, "nothing released yet");

    live.send(resent(role, 2)).await;
    live.expect_app(&["2", "3", "5"]).await;
    assert_eq!(live.connection.next_target_seq(), 6);

    live.send(resent(role, 3)).await;
    live.send(peer_msg(
        role,
        "4",
        4,
        &[
            (43, "Y"),
            (122, "20261019-12:00:00.000"),
            (123, "Y"),
            (36, "5"),
        ],
    ))
    .await;
    live.send(resent(role, 5)).await;
    live.expect_no_app().await;
    live.ping(6).await;
}

#[tokio::test]
async fn test_initiator_queue_releases_in_order_once_the_gap_is_filled() {
    queued_messages_are_released_in_order(Role::Initiator).await;
}

#[tokio::test]
async fn test_acceptor_queue_releases_in_order_once_the_gap_is_filled() {
    queued_messages_are_released_in_order(Role::Acceptor).await;
}

/// The same opening under `policy`: 3 and 4 arrive while 2 is missing, then
/// only 2 is resent. Returns the session for the caller to finish.
async fn gap_then_resend_two(role: Role, policy: GapPolicy) -> Live {
    let mut live = Live::open(role, policy).await;
    live.send(app(role, 3)).await;
    live.expect_resend_request("2").await;
    live.send(app(role, 4)).await;
    live.expect_no_app().await;
    live.send(resent(role, 2)).await;
    live
}

/// Under `Discard` (the default) nothing above the gap is kept: once 2 is
/// resent the expectation is 3, and 3 and 4 reach `from_app` only from the
/// resend, exactly as before the policy existed.
async fn discard_is_unchanged(role: Role) {
    let mut live = gap_then_resend_two(role, GapPolicy::default()).await;
    live.expect_app(&["2"]).await;
    assert_eq!(live.connection.next_target_seq(), 3);
    live.send(resent(role, 3)).await;
    live.send(resent(role, 4)).await;
    live.expect_app(&["3", "4"]).await;
    live.ping(5).await;
}

#[tokio::test]
async fn test_initiator_discard_is_unchanged() {
    discard_is_unchanged(Role::Initiator).await;
}

#[tokio::test]
async fn test_acceptor_discard_is_unchanged() {
    discard_is_unchanged(Role::Acceptor).await;
}

/// The same script under `Queue`: 3 and 4 follow 2 at once, and their resent
/// copies are ignored.
async fn queue_contrast(role: Role) {
    let mut live = gap_then_resend_two(role, queue(16)).await;
    live.expect_app(&["2", "3", "4"]).await;
    assert_eq!(live.connection.next_target_seq(), 5);
    live.send(resent(role, 3)).await;
    live.send(resent(role, 4)).await;
    live.expect_no_app().await;
    live.ping(5).await;
}

#[tokio::test]
async fn test_initiator_queue_delivers_without_waiting_for_the_resend() {
    queue_contrast(Role::Initiator).await;
}

#[tokio::test]
async fn test_acceptor_queue_delivers_without_waiting_for_the_resend() {
    queue_contrast(Role::Acceptor).await;
}

/// A queue that holds two: 3 and 4 are kept, 5 and 6 are discarded and the
/// session stays up. Once 2 arrives, 2..=4 are delivered, and 5 and 6 come
/// from the resend.
async fn overflow_discards_without_closing(role: Role, policy: GapPolicy) {
    let mut live = Live::open(role, policy).await;
    live.send(app(role, 3)).await;
    live.expect_resend_request("2").await;
    for seq in 4..=6 {
        live.send(app(role, seq)).await;
    }
    live.expect_no_app().await;
    assert!(!live.connection.is_closed(), "an overflow never closes");
    live.send(resent(role, 2)).await;
    live.expect_app(&["2", "3", "4"]).await;
    assert_eq!(live.connection.next_target_seq(), 5);
    for seq in 3..=6 {
        live.send(resent(role, seq)).await;
    }
    live.expect_app(&["5", "6"]).await;
    live.ping(7).await;
}

#[tokio::test]
async fn test_initiator_queue_overflow_by_count() {
    overflow_discards_without_closing(Role::Initiator, queue(2)).await;
}

#[tokio::test]
async fn test_acceptor_queue_overflow_by_count() {
    overflow_discards_without_closing(Role::Acceptor, queue(2)).await;
}

/// Room for two and a half frames of this shape.
fn two_frames_of_bytes(role: Role) -> GapPolicy {
    let len = app(role, 3).len();
    GapPolicy::Queue {
        max_messages: 16,
        max_bytes: len * 2 + len / 2,
    }
}

#[tokio::test]
async fn test_initiator_queue_overflow_by_bytes() {
    let role = Role::Initiator;
    overflow_discards_without_closing(role, two_frames_of_bytes(role)).await;
}

#[tokio::test]
async fn test_acceptor_queue_overflow_by_bytes() {
    let role = Role::Acceptor;
    overflow_discards_without_closing(role, two_frames_of_bytes(role)).await;
}

/// A `SequenceReset`-Reset during the gap renumbers the stream: what was
/// queued is dropped, never delivered, and the stream goes on at NewSeqNo.
async fn sequence_reset_clears_the_queue(role: Role) {
    let mut live = Live::open(role, queue(16)).await;
    live.send(app(role, 3)).await;
    live.expect_resend_request("2").await;
    live.send(app(role, 4)).await;
    live.send(peer_msg(role, "4", 5, &[(123, "N"), (36, "10")]))
        .await;
    live.send(app(role, 10)).await;
    live.expect_app(&["10"]).await;
    assert_eq!(live.connection.next_target_seq(), 11);
    live.ping(11).await;
}

#[tokio::test]
async fn test_initiator_sequence_reset_during_a_gap_clears_the_queue() {
    sequence_reset_clears_the_queue(Role::Initiator).await;
}

#[tokio::test]
async fn test_acceptor_sequence_reset_during_a_gap_clears_the_queue() {
    sequence_reset_clears_the_queue(Role::Acceptor).await;
}

/// An in-sequence gap fill that jumps past a queued number drops it (the
/// counterparty says that number carried nothing to deliver) and releases the
/// one it lands on.
async fn gap_fill_past_a_queued_number(role: Role) {
    let mut live = Live::open(role, queue(16)).await;
    live.send(app(role, 3)).await;
    live.expect_resend_request("2").await;
    live.send(app(role, 4)).await;
    live.send(peer_msg(role, "4", 2, &[(123, "Y"), (36, "4")]))
        .await;
    live.expect_app(&["4"]).await;
    live.ping(5).await;
}

#[tokio::test]
async fn test_initiator_gap_fill_past_a_queued_number_drops_it() {
    gap_fill_past_a_queued_number(Role::Initiator).await;
}

#[tokio::test]
async fn test_acceptor_gap_fill_past_a_queued_number_drops_it() {
    gap_fill_past_a_queued_number(Role::Acceptor).await;
}

/// A gapped gap fill is kept and applied in turn: once 2 arrives, the fill at
/// 3 moves the expectation to 5, and the queued 5 follows.
async fn gapped_gap_fill_is_applied_in_turn(role: Role) {
    let mut live = Live::open(role, queue(16)).await;
    live.send(peer_msg(role, "4", 3, &[(123, "Y"), (36, "5")]))
        .await;
    live.expect_resend_request("2").await;
    live.send(app(role, 5)).await;
    live.send(resent(role, 2)).await;
    live.expect_app(&["2", "5"]).await;
    live.ping(6).await;
}

#[tokio::test]
async fn test_initiator_gapped_gap_fill_is_applied_in_turn() {
    gapped_gap_fill_is_applied_in_turn(Role::Initiator).await;
}

#[tokio::test]
async fn test_acceptor_gapped_gap_fill_is_applied_in_turn() {
    gapped_gap_fill_is_applied_in_turn(Role::Acceptor).await;
}

/// A Logout during the gap is answered and ends the session; nothing queued
/// reaches `from_app`.
async fn logout_during_a_gap(role: Role) {
    let mut live = Live::open(role, queue(16)).await;
    live.send(app(role, 3)).await;
    live.expect_resend_request("2").await;
    live.send(app(role, 4)).await;
    live.send(peer_msg(role, "5", 5, &[])).await;
    let reply = next_frame(&mut live.framed).await;
    assert_eq!(msg_type_of(&reply), "5", "the Logout is answered");
    ok(
        timeout(Duration::from_secs(5), live.connection.wait_closed()).await,
        "the session closes",
    );
    live.expect_no_app().await;
}

#[tokio::test]
async fn test_initiator_logout_during_a_gap_drops_the_queue() {
    logout_during_a_gap(Role::Initiator).await;
}

#[tokio::test]
async fn test_acceptor_logout_during_a_gap_drops_the_queue() {
    logout_during_a_gap(Role::Acceptor).await;
}

/// ADR-0021 / #128: with both sides on `NextExpectedMsgSeqNum` (789), a
/// gapped Logon (6) is held while the counterparty resends 3..=5 on its own.
/// A TestRequest (7) and an order (8) that overtake that resend are no longer
/// stranded under `Queue`: the TestRequest is answered at once, and once the
/// fill reaches the held Logon its number, then 7's, are consumed and 8 is
/// delivered, with no `ResendRequest` at any point.
#[tokio::test]
async fn test_acceptor_frames_past_a_held_logon_are_released_under_queue() {
    let role = Role::Acceptor;
    let (app_tx, mut app_rx) = mpsc::unbounded_channel();
    let application = Arc::new(RecordingApp { app_tx });
    let config = role
        .config(queue(16))
        .with_send_next_expected_msg_seq_num(true);
    let acceptor = Arc::new(Acceptor::new(config, application).with_initial_sequences(1, 3));
    let listener = ok(TcpListener::bind("127.0.0.1:0").await, "listener binds");
    let addr = ok(listener.local_addr(), "listener address");
    let venue = tokio::spawn(async move { acceptor.accept(&listener).await });
    let stream = ok(TcpStream::connect(addr).await, "the client connects");
    let mut framed = Framed::new(stream, FixCodec::new());
    send(
        &mut framed,
        peer_msg(role, "A", 6, &[(98, "0"), (108, "30"), (789, "1")]),
    )
    .await;
    let ack = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&ack), "A");
    let connection = ok(
        ok(
            ok(timeout(Duration::from_secs(5), venue).await, "venue in 5s"),
            "venue task joins",
        ),
        "the acceptor establishes the session",
    );
    assert_eq!(connection.next_target_seq(), 3, "the Logon is held");

    send(&mut framed, peer_msg(role, "1", 7, &[(112, "HELD")])).await;
    let heartbeat = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&heartbeat), "0");
    assert_eq!(field(&heartbeat, 112).as_deref(), Some("HELD"));
    send(&mut framed, app(role, 8)).await;
    send(
        &mut framed,
        peer_msg(role, "4", 3, &[(123, "Y"), (36, "6")]),
    )
    .await;

    let delivered = ok(
        timeout(Duration::from_secs(5), app_rx.recv()).await,
        "an application message within 5s",
    );
    assert_eq!(some(delivered, "the app channel stays open"), "8");
    assert_eq!(connection.next_target_seq(), 9);

    send(&mut framed, peer_msg(role, "1", 9, &[(112, "AFTER")])).await;
    let heartbeat = next_frame(&mut framed).await;
    assert_eq!(
        msg_type_of(&heartbeat),
        "0",
        "no ResendRequest at any point"
    );
    assert_eq!(field(&heartbeat, 112).as_deref(), Some("AFTER"));
    assert_eq!(connection.next_target_seq(), 10);
}

/// Asserts the engine writes nothing for 300 ms.
async fn assert_silent(framed: &mut Peer, what: &str) {
    if let Ok(Some(Ok(frame))) = timeout(Duration::from_millis(300), framed.next()).await {
        panic!(
            "{what}: unexpected MsgType {} at {:?}",
            msg_type_of(&frame),
            field(&frame, 34)
        );
    }
}

/// A gapped TestRequest sent twice under the same number is answered once:
/// the second copy finds its number queued and is dropped, not acted on.
async fn repeated_gapped_test_request_is_answered_once(role: Role) {
    let mut live = Live::open(role, queue(16)).await;
    live.send(app(role, 3)).await;
    live.expect_resend_request("2").await;
    live.send(peer_msg(role, "1", 4, &[(112, "TWICE")])).await;
    let heartbeat = next_frame(&mut live.framed).await;
    assert_eq!(msg_type_of(&heartbeat), "0");
    assert_eq!(field(&heartbeat, 112).as_deref(), Some("TWICE"));
    live.send(peer_msg(role, "1", 4, &[(112, "TWICE")])).await;
    assert_silent(&mut live.framed, "the repeated TestRequest is not answered").await;
    live.send(resent(role, 2)).await;
    live.expect_app(&["2", "3"]).await;
    live.ping(5).await;
}

#[tokio::test]
async fn test_initiator_repeated_gapped_test_request_is_answered_once() {
    repeated_gapped_test_request_is_answered_once(Role::Initiator).await;
}

#[tokio::test]
async fn test_acceptor_repeated_gapped_test_request_is_answered_once() {
    repeated_gapped_test_request_is_answered_once(Role::Acceptor).await;
}

/// An administrative frame on a number an application message already
/// claimed in the queue does not run: the TestRequest at 3 is not answered,
/// and the queued application message at 3 is the one released.
async fn admin_frame_on_a_claimed_number_does_not_run(role: Role) {
    let mut live = Live::open(role, queue(16)).await;
    live.send(app(role, 3)).await;
    live.expect_resend_request("2").await;
    live.send(peer_msg(role, "1", 3, &[(112, "CLAIMED")])).await;
    assert_silent(&mut live.framed, "the TestRequest on a claimed number").await;
    live.send(resent(role, 2)).await;
    live.expect_app(&["2", "3"]).await;
    live.ping(4).await;
}

#[tokio::test]
async fn test_initiator_admin_frame_on_a_claimed_number_does_not_run() {
    admin_frame_on_a_claimed_number_does_not_run(Role::Initiator).await;
}

#[tokio::test]
async fn test_acceptor_admin_frame_on_a_claimed_number_does_not_run() {
    admin_frame_on_a_claimed_number_does_not_run(Role::Acceptor).await;
}

/// Ported from the PR #151 protocol probes: a possible-duplicate copy of a
/// gapped number, with the same `TestReqID`, triggers no second admin action.
/// With `app_first` the number was claimed by an application message, which
/// is the one released; otherwise by a TestRequest answered once.
async fn possdup_copy_of_a_held_number_is_not_acted_on(role: Role, app_first: bool) {
    let mut live = Live::open(role, queue(16)).await;
    if app_first {
        live.send(app(role, 3)).await;
        live.expect_resend_request("2").await;
    } else {
        live.send(peer_msg(role, "1", 3, &[(112, "FIRST")])).await;
        live.expect_resend_request("2").await;
        let heartbeat = next_frame(&mut live.framed).await;
        assert_eq!(field(&heartbeat, 112).as_deref(), Some("FIRST"));
    }
    live.send(peer_msg(role, "1", 3, &[(43, "Y"), (112, "FIRST")]))
        .await;
    assert_silent(&mut live.framed, "a copy of a held number").await;
    live.send(resent(role, 2)).await;
    if app_first {
        live.expect_app(&["2", "3"]).await;
    } else {
        live.expect_app(&["2"]).await;
    }
    assert_eq!(live.connection.next_target_seq(), 4);
    live.ping(4).await;
}

#[tokio::test]
async fn test_initiator_possdup_copy_of_a_gapped_test_request_is_dropped() {
    possdup_copy_of_a_held_number_is_not_acted_on(Role::Initiator, false).await;
}

#[tokio::test]
async fn test_acceptor_possdup_copy_of_a_gapped_test_request_is_dropped() {
    possdup_copy_of_a_held_number_is_not_acted_on(Role::Acceptor, false).await;
}

#[tokio::test]
async fn test_initiator_app_first_wins_over_an_admin_copy_of_its_number() {
    possdup_copy_of_a_held_number_is_not_acted_on(Role::Initiator, true).await;
}

#[tokio::test]
async fn test_acceptor_app_first_wins_over_an_admin_copy_of_its_number() {
    possdup_copy_of_a_held_number_is_not_acted_on(Role::Acceptor, true).await;
}
