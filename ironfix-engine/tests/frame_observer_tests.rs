/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 19/10/26
******************************************************************************/

//! Integration tests for issue #70 (ADR-0026): the frame observer, a capture
//! hook for every inbound and outbound frame.
//!
//! Every session runs over a `tokio::io::duplex` pipe. The counterparty is a
//! real engine of the other role, or a scripted `Framed<DuplexStream,
//! FixCodec>` that records every frame it reads and writes, so the capture
//! can be compared with the bytes on the wire.
//!
//! Covered: a session with a Logon, application traffic, a `ResendRequest`
//! answered with a gap fill and replays, a rejected inbound message and a
//! Logout yields a capture equal to the wire, in order, with replays marked;
//! both roles see each other's frames byte for byte; an inbound frame from the
//! wrong CompID is observed although the session closes over it; a vetoed
//! message is never observed as a frame and reports `NotSent`; a Logout or a
//! kill with a full outbound queue reports `NotSent` for every message never
//! written and `Written` for the Logout; a write that starts and does not
//! complete is observed, then reported `Unknown`, never `Written` or
//! `NotSent`.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::application::{Application, RejectReason, SendVerdict, SessionId};
use ironfix_engine::{
    Acceptor, Connection, Direction, FrameKind, FrameObserver, Initiator, NotSentReason,
    Observation, OutboundMessage, OutboundResult, SendOutcome, UnknownReason,
};
use ironfix_session::SessionConfig;
use ironfix_store::{MemoryStore, MessageStore};
use ironfix_tagvalue::{Decoder, Encoder};
use ironfix_transport::FixCodec;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::DuplexStream;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::codec::Framed;

/// Capacity of each direction of a roomy pipe.
const PIPE_CAPACITY: usize = 64 * 1024;
/// A pipe too small for [`large_order`].
const SMALL_PIPE: usize = 1024;
/// Bound on every wait.
const STEP: Duration = Duration::from_secs(5);
/// How long a test lets the reactor settle.
const QUIET: Duration = Duration::from_millis(300);
/// The acknowledgement body of a scripted venue.
const ACK: &[(u32, &str)] = &[(98, "0"), (108, "30")];

type VenueFramed = Framed<DuplexStream, FixCodec>;

#[track_caller]
fn ok<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{what}: {err:?}"),
    }
}

#[track_caller]
fn some<T>(value: Option<T>, what: &str) -> T {
    match value {
        Some(value) => value,
        None => panic!("{what}"),
    }
}

#[track_caller]
fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(_) => panic!("test lock poisoned"),
    }
}

#[track_caller]
fn comp_id(value: &str) -> CompId {
    ok(CompId::new(value), "test CompId must be valid")
}

/// The venue's session: sender VENUE, target CLIENT.
fn venue_config() -> SessionConfig {
    SessionConfig::new(comp_id("VENUE"), comp_id("CLIENT"), "FIX.4.4")
        .with_heartbeat_interval(Duration::from_secs(30))
}

/// The member's session: sender CLIENT, target VENUE.
fn member_config() -> SessionConfig {
    SessionConfig::new(comp_id("CLIENT"), comp_id("VENUE"), "FIX.4.4")
        .with_heartbeat_interval(Duration::from_secs(30))
}

/// One thing the observer was told.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    /// A frame, with its observation.
    Frame {
        direction: Direction,
        kind: FrameKind,
        seq: Option<u64>,
        bytes: Vec<u8>,
    },
    /// A write result.
    Result {
        kind: FrameKind,
        seq: Option<u64>,
        result: OutboundResult,
    },
}

/// A frame observer recording everything it is told, in order.
#[derive(Debug, Default)]
struct Recorder {
    entries: Mutex<Vec<Entry>>,
    session: Mutex<Option<SessionId>>,
}

impl Recorder {
    fn record(&self, entry: Entry, observation: &Observation<'_>) {
        let mut session = locked(&self.session);
        match session.as_ref() {
            Some(seen) => assert_eq!(seen, observation.session_id(), "one session observed"),
            None => *session = Some(observation.session_id().clone()),
        }
        locked(&self.entries).push(entry);
    }

    fn entries(&self) -> Vec<Entry> {
        locked(&self.entries).clone()
    }

    /// The frames observed in `direction`, in order.
    fn frames(&self, direction: Direction) -> Vec<Vec<u8>> {
        self.entries()
            .into_iter()
            .filter_map(|entry| match entry {
                Entry::Frame {
                    direction: seen,
                    bytes,
                    ..
                } if seen == direction => Some(bytes),
                _ => None,
            })
            .collect()
    }

    /// The write results, in order.
    fn results(&self) -> Vec<(FrameKind, Option<u64>, OutboundResult)> {
        self.entries()
            .into_iter()
            .filter_map(|entry| match entry {
                Entry::Result { kind, seq, result } => Some((kind, seq, result)),
                Entry::Frame { .. } => None,
            })
            .collect()
    }

    /// The (kind, seq) of every outbound frame, in order.
    fn outbound_kinds(&self) -> Vec<(FrameKind, Option<u64>)> {
        self.entries()
            .into_iter()
            .filter_map(|entry| match entry {
                Entry::Frame {
                    direction: Direction::Outbound,
                    kind,
                    seq,
                    ..
                } => Some((kind, seq)),
                _ => None,
            })
            .collect()
    }

    /// Asserts that every outbound frame got exactly one write result, with
    /// its kind and number, after it, and that the result is never
    /// `NotSent`.
    #[track_caller]
    fn assert_one_result_per_frame(&self) {
        let entries = self.entries();
        let mut open: Vec<(FrameKind, Option<u64>)> = Vec::new();
        for entry in &entries {
            match entry {
                Entry::Frame {
                    direction: Direction::Outbound,
                    kind,
                    seq,
                    ..
                } => open.push((*kind, *seq)),
                Entry::Result { kind, seq, result } => match result {
                    OutboundResult::NotSent { .. } => {
                        assert_eq!(*seq, None, "a NotSent message was never numbered");
                        assert!(
                            !open.contains(&(*kind, *seq)),
                            "a NotSent message was never observed as a frame"
                        );
                    }
                    _ => {
                        let at = open.iter().position(|frame| frame == &(*kind, *seq));
                        let at = some(at, "a write result follows its frame");
                        open.remove(at);
                    }
                },
                Entry::Frame { .. } => {}
            }
        }
        assert!(open.is_empty(), "frames without a write result: {open:?}");
    }
}

impl FrameObserver for Recorder {
    fn on_inbound(&self, frame: &[u8], observation: &Observation<'_>) {
        assert_eq!(observation.direction(), Direction::Inbound);
        self.record(
            Entry::Frame {
                direction: Direction::Inbound,
                kind: observation.kind(),
                seq: observation.msg_seq_num(),
                bytes: frame.to_vec(),
            },
            observation,
        );
    }

    fn on_outbound(&self, frame: &[u8], observation: &Observation<'_>) {
        assert_eq!(observation.direction(), Direction::Outbound);
        self.record(
            Entry::Frame {
                direction: Direction::Outbound,
                kind: observation.kind(),
                seq: observation.msg_seq_num(),
                bytes: frame.to_vec(),
            },
            observation,
        );
    }

    fn on_outbound_result(&self, result: &OutboundResult, observation: &Observation<'_>) {
        self.record(
            Entry::Result {
                kind: observation.kind(),
                seq: observation.msg_seq_num(),
                result: result.clone(),
            },
            observation,
        );
    }
}

/// The application under test: vetoes ClOrdID (11) `VETO*`, parks
/// `to_app_checked` on ClOrdID `GATE` until released, and rejects every
/// inbound application message whose ClOrdID is `REJECT`.
#[derive(Debug, Default)]
struct GateApp {
    entered: Notify,
    release: Notify,
}

#[async_trait]
impl Application for GateApp {
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

    fn to_app_checked<'a>(
        &'a self,
        message: &'a mut OutboundMessage,
        _session_id: &'a SessionId,
    ) -> SendVerdict<'a> {
        let id = message
            .get(11)
            .map(|id| String::from_utf8_lossy(id).into_owned())
            .unwrap_or_default();
        if id.starts_with("VETO") {
            return SendVerdict::ready(Err(RejectReason::new(7, "vetoed by the test")));
        }
        if id == "GATE" {
            return SendVerdict::new(async move {
                self.entered.notify_one();
                self.release.notified().await;
                Ok(())
            });
        }
        SendVerdict::ready(Ok(()))
    }

    async fn from_app(
        &self,
        message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        if message.get_field_str(11) == Some("REJECT") {
            return Err(RejectReason::new(99, "refused by the test application"));
        }
        Ok(())
    }
}

/// A NewOrderSingle with ClOrdID (11) `id`.
fn order(id: &str) -> OutboundMessage {
    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order
        .push_str(11, id)
        .push_str(55, "EUR/USD")
        .push_char(54, '1')
        .push_uint(38, 100);
    order
}

/// An order whose Text (58) carries `size` bytes, too large for
/// [`SMALL_PIPE`].
fn large_order(id: &str, size: usize) -> OutboundMessage {
    let mut message = order(id);
    message.push_str(58, &"X".repeat(size));
    message
}

/// A frame from `sender` to `target`, numbered `seq`.
fn frame_from(
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
    let mut frame = BytesMut::new();
    ok(encoder.finish_into(&mut frame), "test frame encodes");
    frame
}

/// A frame the scripted venue sends (VENUE -> CLIENT).
fn venue_msg(msg_type: &str, seq: u64, extra: &[(u32, &str)]) -> BytesMut {
    frame_from("VENUE", "CLIENT", msg_type, seq, extra)
}

/// Extracts a field from a framed message.
fn field(frame: &[u8], tag: u32) -> Option<String> {
    let mut decoder = Decoder::new(frame);
    match decoder.decode() {
        Ok(raw) => raw.get_field_str(tag).map(str::to_string),
        Err(_) => None,
    }
}

/// The MsgType (35) and MsgSeqNum (34) of a frame.
#[track_caller]
fn header(frame: &[u8]) -> (String, u64) {
    let msg_type = some(field(frame, 35), "a frame carries MsgType (35)");
    let seq = some(
        field(frame, 34).and_then(|seq| seq.parse().ok()),
        "a frame carries MsgSeqNum (34)",
    );
    (msg_type, seq)
}

/// A scripted venue that records every frame it reads and writes.
struct Venue {
    framed: VenueFramed,
    read: Vec<Vec<u8>>,
    wrote: Vec<Vec<u8>>,
}

impl Venue {
    async fn next(&mut self) -> BytesMut {
        let polled = ok(
            timeout(STEP, self.framed.next()).await,
            "a frame arrives within 5s",
        );
        let frame = ok(some(polled, "the stream stays open"), "the frame frames");
        self.read.push(frame.to_vec());
        frame
    }

    async fn send(&mut self, frame: BytesMut) {
        self.wrote.push(frame.to_vec());
        ok(
            ok(
                timeout(STEP, self.framed.send(frame)).await,
                "the venue writes within 5s",
            ),
            "the venue writes",
        );
    }
}

/// Starts `initiator` over a pipe of `capacity` bytes against a scripted
/// venue that acknowledges its Logon at 1.
async fn scripted<A: Application + 'static>(
    initiator: &Initiator<A>,
    capacity: usize,
) -> (Connection, Venue) {
    let (client_io, venue_io) = tokio::io::duplex(capacity);
    let venue = tokio::spawn(async move {
        let mut venue = Venue {
            framed: Framed::new(venue_io, FixCodec::new()),
            read: Vec::new(),
            wrote: Vec::new(),
        };
        let logon = venue.next().await;
        assert_eq!(field(&logon, 35).as_deref(), Some("A"));
        venue.send(venue_msg("A", 1, ACK)).await;
        venue
    });
    let member = ok(
        initiator.establish(client_io).await,
        "the member logs on over the pipe",
    );
    let venue = joined(venue, "the scripted venue acknowledges the Logon").await;
    (member, venue)
}

/// Awaits a spawned task within [`STEP`].
async fn joined<T>(task: JoinHandle<T>, what: &str) -> T {
    ok(ok(timeout(STEP, task).await, what), what)
}

/// Waits for `connection` to close within [`STEP`].
async fn closed(connection: &Connection, what: &str) {
    ok(timeout(STEP, connection.wait_closed()).await, what);
}

/// Spawns a tracked send of an order with ClOrdID `id`.
fn track(member: &Connection, id: &'static str) -> JoinHandle<SendOutcome> {
    let member = member.clone();
    tokio::spawn(async move { member.send_tracked(order(id)).await })
}

/// A session with a Logon, application traffic, a `ResendRequest` answered
/// with a gap fill and replays, a rejected inbound message and a Logout: the
/// outbound frames observed are the bytes the venue read, the inbound ones
/// the bytes it wrote, both in order; replays and gap fills are marked; every
/// outbound frame is reported written.
#[tokio::test]
async fn test_capture_equals_the_wire_through_a_resend_a_reject_and_a_logout() {
    let recorder = Arc::new(Recorder::default());
    let store = Arc::new(MemoryStore::new());
    let initiator = Initiator::new(member_config(), Arc::new(GateApp::default()))
        .with_store(store as Arc<dyn MessageStore>)
        .with_frame_observer(Arc::clone(&recorder) as Arc<dyn FrameObserver>);
    assert!(initiator.has_frame_observer());
    let (member, mut venue) = scripted(&initiator, PIPE_CAPACITY).await;

    for id in ["O-1", "O-2"] {
        let outcome = member.send_tracked(order(id)).await;
        assert!(outcome.is_sent(), "{outcome:?}");
        assert_eq!(header(&venue.next().await).0, "D");
    }

    // The venue asks for everything: the Logon is gap-filled, the orders
    // replayed.
    venue.send(venue_msg("2", 2, &[(7, "1"), (16, "0")])).await;
    let fill = venue.next().await;
    assert_eq!(header(&fill), ("4".to_string(), 1));
    assert_eq!(field(&fill, 123).as_deref(), Some("Y"));
    for seq in [2, 3] {
        let replay = venue.next().await;
        assert_eq!(header(&replay), ("D".to_string(), seq));
        assert_eq!(field(&replay, 43).as_deref(), Some("Y"));
    }

    // An inbound order the application rejects.
    venue
        .send(venue_msg(
            "D",
            3,
            &[(11, "REJECT"), (55, "EUR/USD"), (54, "1"), (38, "1")],
        ))
        .await;
    assert_eq!(header(&venue.next().await), ("3".to_string(), 4));

    ok(member.logout().await, "the member logs out");
    assert_eq!(header(&venue.next().await), ("5".to_string(), 5));
    venue.send(venue_msg("5", 4, &[])).await;
    closed(&member, "the Logout exchange closes the session").await;

    assert_eq!(
        recorder.frames(Direction::Outbound),
        venue.read,
        "the outbound capture is the bytes the venue read, in order"
    );
    assert_eq!(
        recorder.frames(Direction::Inbound),
        venue.wrote,
        "the inbound capture is the bytes the venue wrote, in order"
    );
    assert_eq!(
        recorder.outbound_kinds(),
        vec![
            (FrameKind::Handshake, Some(1)),
            (FrameKind::Session, Some(2)),
            (FrameKind::Session, Some(3)),
            (FrameKind::GapFill, Some(1)),
            (FrameKind::Replay, Some(2)),
            (FrameKind::Replay, Some(3)),
            (FrameKind::Session, Some(4)),
            (FrameKind::Session, Some(5)),
        ]
    );
    let inbound: Vec<(FrameKind, Option<u64>)> = recorder
        .entries()
        .into_iter()
        .filter_map(|entry| match entry {
            Entry::Frame {
                direction: Direction::Inbound,
                kind,
                seq,
                ..
            } => Some((kind, seq)),
            _ => None,
        })
        .collect();
    assert_eq!(
        inbound,
        vec![
            (FrameKind::Handshake, Some(1)),
            (FrameKind::Session, Some(2)),
            (FrameKind::Session, Some(3)),
            (FrameKind::Session, Some(4)),
        ]
    );
    recorder.assert_one_result_per_frame();
    assert!(
        recorder
            .results()
            .iter()
            .all(|(_, _, result)| *result == OutboundResult::Written),
        "every frame was written: {:?}",
        recorder.results()
    );
}

/// Both roles observe: what one side observes going out is, byte for byte
/// and in order, what the other observes coming in.
#[tokio::test]
async fn test_both_roles_observe_each_others_frames() {
    let member_log = Arc::new(Recorder::default());
    let venue_log = Arc::new(Recorder::default());
    let initiator = Initiator::new(member_config(), Arc::new(GateApp::default()))
        .with_frame_observer(Arc::clone(&member_log) as Arc<dyn FrameObserver>);
    let acceptor = Acceptor::new(venue_config(), Arc::new(GateApp::default()))
        .with_frame_observer(Arc::clone(&venue_log) as Arc<dyn FrameObserver>);
    assert!(acceptor.has_frame_observer());
    let (client_io, venue_io) = tokio::io::duplex(PIPE_CAPACITY);
    let served = tokio::spawn(async move { acceptor.serve_stream(venue_io).await });
    let member = ok(
        initiator.establish(client_io).await,
        "the initiator logs on",
    );
    let venue = ok(
        joined(served, "the acceptor handshake ends").await,
        "the acceptor logs on",
    );

    for id in ["M-1", "M-2"] {
        assert!(member.send_tracked(order(id)).await.is_sent());
    }
    for id in ["V-1", "V-2"] {
        assert!(venue.send_tracked(order(id)).await.is_sent());
    }
    ok(member.logout().await, "the initiator logs out");
    closed(&member, "the initiator closes").await;
    closed(&venue, "the acceptor closes").await;

    let member_out = member_log.frames(Direction::Outbound);
    assert_eq!(member_out, venue_log.frames(Direction::Inbound));
    assert_eq!(
        venue_log.frames(Direction::Outbound),
        member_log.frames(Direction::Inbound)
    );
    // Logon, two orders, Logout.
    assert_eq!(member_out.len(), 4);
    assert_eq!(
        member_log.outbound_kinds().first(),
        Some(&(FrameKind::Handshake, Some(1)))
    );
    assert_eq!(
        venue_log.outbound_kinds().first(),
        Some(&(FrameKind::Handshake, Some(1)))
    );
    member_log.assert_one_result_per_frame();
    venue_log.assert_one_result_per_frame();
}

/// An inbound frame from the wrong CompID closes the session, and it is in
/// the capture: it is observed before the session acts on it.
#[tokio::test]
async fn test_frame_from_the_wrong_comp_id_is_observed() {
    let recorder = Arc::new(Recorder::default());
    let initiator = Initiator::new(member_config(), Arc::new(GateApp::default()))
        .with_frame_observer(Arc::clone(&recorder) as Arc<dyn FrameObserver>);
    let (member, mut venue) = scripted(&initiator, PIPE_CAPACITY).await;

    let intruder = frame_from("INTRUDER", "CLIENT", "0", 2, &[]);
    venue.send(intruder.clone()).await;
    closed(&member, "the wrong CompID closes the session").await;

    let inbound = recorder.frames(Direction::Inbound);
    assert_eq!(
        inbound.last().map(Vec::as_slice),
        Some(&intruder[..]),
        "the intruder's frame is observed"
    );
    assert!(recorder.entries().contains(&Entry::Frame {
        direction: Direction::Inbound,
        kind: FrameKind::Session,
        seq: Some(2),
        bytes: intruder.to_vec(),
    }));
    recorder.assert_one_result_per_frame();
    drop(venue);
}

/// A vetoed message is never observed as a frame: it reports `NotSent`
/// alone, with no number, and the next message takes the number.
#[tokio::test]
async fn test_vetoed_message_is_not_observed_as_outbound() {
    let recorder = Arc::new(Recorder::default());
    let initiator = Initiator::new(member_config(), Arc::new(GateApp::default()))
        .with_frame_observer(Arc::clone(&recorder) as Arc<dyn FrameObserver>);
    let (member, mut venue) = scripted(&initiator, PIPE_CAPACITY).await;

    let vetoed = member.send_tracked(order("VETO-1")).await;
    assert!(matches!(vetoed, SendOutcome::NotSent { .. }), "{vetoed:?}");
    assert!(member.send_tracked(order("O-1")).await.is_sent());
    assert_eq!(header(&venue.next().await), ("D".to_string(), 2));

    let outbound = recorder.frames(Direction::Outbound);
    assert!(
        outbound
            .iter()
            .all(|frame| field(frame, 11).as_deref() != Some("VETO-1")),
        "the vetoed message never reached the observer as a frame"
    );
    assert_eq!(
        recorder.outbound_kinds(),
        vec![
            (FrameKind::Handshake, Some(1)),
            (FrameKind::Session, Some(2))
        ]
    );
    let not_sent: Vec<_> = recorder
        .results()
        .into_iter()
        .filter(|(_, _, result)| matches!(result, OutboundResult::NotSent { .. }))
        .collect();
    assert_eq!(not_sent.len(), 1);
    assert!(matches!(
        &not_sent[0],
        (
            FrameKind::Session,
            None,
            OutboundResult::NotSent {
                reason: NotSentReason::Vetoed { .. },
                ..
            }
        )
    ));
    recorder.assert_one_result_per_frame();
    drop(venue);
    closed(&member, "the session closes once the venue is gone").await;
}

/// This session's Logout with the outbound queue full: the messages behind
/// the Logout report `NotSent` and are never observed as frames; the frames
/// ahead of it, and the Logout itself, report `Written`.
#[tokio::test]
async fn test_logout_with_a_full_queue_reports_not_sent_and_the_logout_written() {
    let recorder = Arc::new(Recorder::default());
    let app = Arc::new(GateApp::default());
    let initiator = Initiator::new(member_config(), Arc::clone(&app))
        .with_outbound_capacity(4)
        .with_frame_observer(Arc::clone(&recorder) as Arc<dyn FrameObserver>);
    let (member, mut venue) = scripted(&initiator, PIPE_CAPACITY).await;

    let gated = track(&member, "GATE");
    ok(
        timeout(STEP, app.entered.notified()).await,
        "the gated message reaches to_app_checked",
    );
    let ahead = track(&member, "AHEAD-1");
    tokio::time::sleep(QUIET).await;
    let logout = {
        let member = member.clone();
        tokio::spawn(async move { member.logout().await })
    };
    tokio::time::sleep(QUIET).await;
    let behind: Vec<_> = ["BEHIND-1", "BEHIND-2"]
        .into_iter()
        .map(|id| track(&member, id))
        .collect();
    tokio::time::sleep(QUIET).await;

    app.release.notify_one();
    assert!(joined(gated, "the gated outcome").await.is_sent());
    assert!(joined(ahead, "the outcome ahead").await.is_sent());
    ok(joined(logout, "the logout is queued").await, "logout");
    for task in behind {
        let outcome = joined(task, "an outcome behind").await;
        assert!(
            matches!(outcome, SendOutcome::NotSent { .. }),
            "{outcome:?}"
        );
    }
    assert_eq!(header(&venue.next().await), ("D".to_string(), 2));
    assert_eq!(header(&venue.next().await), ("D".to_string(), 3));
    assert_eq!(header(&venue.next().await), ("5".to_string(), 4));
    venue.send(venue_msg("5", 2, &[])).await;
    closed(&member, "the Logout exchange closes the session").await;

    assert_eq!(recorder.frames(Direction::Outbound), venue.read);
    let results = recorder.results();
    let not_sent = results
        .iter()
        .filter(|(_, seq, result)| {
            seq.is_none()
                && matches!(
                    result,
                    OutboundResult::NotSent {
                        reason: NotSentReason::LogoutPending,
                        ..
                    }
                )
        })
        .count();
    assert_eq!(not_sent, 2, "both messages behind the Logout: {results:?}");
    for seq in 1..=4 {
        assert!(
            results
                .iter()
                .any(|(_, at, result)| *at == Some(seq) && *result == OutboundResult::Written),
            "frame {seq} written: {results:?}"
        );
    }
    recorder.assert_one_result_per_frame();
}

/// A kill with a full outbound queue: every message either was observed
/// and reports `Unknown`, or was never observed and reports `NotSent`.
/// Nothing reports `Written` after the Logon.
#[tokio::test]
async fn test_kill_with_a_full_queue_reports_every_message() {
    let recorder = Arc::new(Recorder::default());
    let app = Arc::new(GateApp::default());
    let initiator = Initiator::new(member_config(), Arc::clone(&app))
        .with_outbound_capacity(4)
        .with_frame_observer(Arc::clone(&recorder) as Arc<dyn FrameObserver>);
    let (member, venue) = scripted(&initiator, PIPE_CAPACITY).await;

    let in_flight = track(&member, "GATE");
    ok(
        timeout(STEP, app.entered.notified()).await,
        "the gated message reaches to_app_checked",
    );
    let queued: Vec<_> = ["Q-1", "Q-2", "Q-3", "Q-4"]
        .into_iter()
        .map(|id| track(&member, id))
        .collect();
    tokio::time::sleep(QUIET).await;
    drop(venue);
    app.release.notify_one();

    let mut outcomes = vec![joined(in_flight, "the in-flight outcome").await];
    for task in queued {
        outcomes.push(joined(task, "a queued outcome").await);
    }
    closed(&member, "the dead transport closes the session").await;

    let results = recorder.results();
    let session_frames = recorder
        .outbound_kinds()
        .into_iter()
        .filter(|(kind, _)| *kind == FrameKind::Session)
        .count();
    let unknown = results
        .iter()
        .filter(|(kind, _, result)| {
            *kind == FrameKind::Session && matches!(result, OutboundResult::Unknown { .. })
        })
        .count();
    let not_sent = results
        .iter()
        .filter(|(_, _, result)| matches!(result, OutboundResult::NotSent { .. }))
        .count();
    assert!(session_frames >= 1, "the in-flight frame was buffered");
    assert_eq!(unknown, session_frames, "every observed frame is Unknown");
    assert_eq!(
        session_frames + not_sent,
        outcomes.len(),
        "every message is reported once: {results:?}"
    );
    assert!(
        !results
            .iter()
            .any(|(kind, _, result)| *kind == FrameKind::Session
                && *result == OutboundResult::Written),
        "nothing is written over a dead transport"
    );
    recorder.assert_one_result_per_frame();
}

/// A write that starts and does not complete (the counterparty takes part of
/// the frame, then stops reading): the frame is observed whole, then reported
/// `Unknown` under its number, never `Written` or `NotSent`.
#[tokio::test]
async fn test_partial_write_is_observed_then_unknown() {
    let recorder = Arc::new(Recorder::default());
    let initiator = Initiator::new(member_config(), Arc::new(GateApp::default()))
        .with_write_timeout(QUIET)
        .with_frame_observer(Arc::clone(&recorder) as Arc<dyn FrameObserver>);
    let (member, venue) = scripted(&initiator, SMALL_PIPE).await;

    let outcome = member
        .send_tracked(large_order("STALLED-1", 16 * 1024))
        .await;
    assert!(
        matches!(
            outcome,
            SendOutcome::Unknown {
                seq: 2,
                reason: UnknownReason::WriteTimeout,
                ..
            }
        ),
        "{outcome:?}"
    );
    closed(&member, "a stalled write closes the session").await;

    let stalled = some(
        recorder
            .entries()
            .into_iter()
            .find_map(|entry| match entry {
                Entry::Frame {
                    direction: Direction::Outbound,
                    seq: Some(2),
                    bytes,
                    ..
                } => Some(bytes),
                _ => None,
            }),
        "the stalled frame is observed",
    );
    assert_eq!(field(&stalled, 11).as_deref(), Some("STALLED-1"));
    let for_seq: Vec<_> = recorder
        .results()
        .into_iter()
        .filter(|(_, seq, _)| *seq == Some(2))
        .collect();
    assert_eq!(for_seq.len(), 1, "one result for the frame: {for_seq:?}");
    assert!(
        matches!(
            &for_seq[0],
            (
                FrameKind::Session,
                Some(2),
                OutboundResult::Unknown {
                    reason: UnknownReason::WriteTimeout,
                    ..
                }
            )
        ),
        "{for_seq:?}"
    );
    recorder.assert_one_result_per_frame();
    drop(venue);
}
