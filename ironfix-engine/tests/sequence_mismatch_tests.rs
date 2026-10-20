/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! The Logon sequence mismatch report (issue #80, ADR-0015), in both roles.
//!
//! A scripted counterparty plays the other side over an in-memory duplex
//! stream. Each test checks what `Application::on_sequence_mismatch` saw, in
//! which order relative to `on_inbound_lost` and `on_logon`, and that the
//! engine then behaves exactly as without the report: the same result, the
//! same counters.
//!
//! Covered: an inbound gap, an inbound Logon too low, a 789 below our Logon
//! (`PeerMissed`), a 789 above our next outbound (`PeerAhead`), no report
//! when everything matches, no report on a 141=Y exchange, a store combined
//! with explicit seeds (the comparison uses the effective counters), and the
//! order of the start reports.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::message::RawMessage;
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::application::RejectReason;
use ironfix_engine::{
    Acceptor, Application, Connection, EngineError, InboundLoss, InboundMismatch, Initiator,
    OutboundMessage, OutboundMismatch, SequenceMismatch, SessionId,
};
use ironfix_session::SessionConfig;
use ironfix_store::{MemoryStore, MessageStore};
use ironfix_tagvalue::{Decoder, Encoder};
use ironfix_transport::FixCodec;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::DuplexStream;
use tokio::time::timeout;
use tokio_util::codec::Framed;

/// The scripted counterparty's end of the pipe.
type Peer = Framed<DuplexStream, FixCodec>;

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

#[track_caller]
fn comp_id(value: &str) -> CompId {
    ok(CompId::new(value), "test CompId must be valid")
}

/// A frame from `sender` to `target`.
fn frame(
    sender: &str,
    target: &str,
    msg_type: &str,
    seq: u64,
    extra: &[(u32, String)],
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
    let mut out = BytesMut::new();
    ok(encoder.finish_into(&mut out), "test frame must encode");
    out
}

fn field(frame: &[u8], tag: u32) -> Option<String> {
    let mut decoder = Decoder::new(frame);
    match decoder.decode() {
        Ok(raw) => raw.get_field_str(tag).map(str::to_string),
        Err(_) => None,
    }
}

async fn next_frame(peer: &mut Peer) -> BytesMut {
    match timeout(STEP, peer.next()).await {
        Ok(Some(Ok(frame))) => frame,
        other => panic!("a frame must arrive within the step: {other:?}"),
    }
}

/// What the application saw, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Lost(u64, u64),
    Mismatch(SequenceMismatch),
    Logon,
}

#[derive(Debug, Default)]
struct Recorder {
    events: Mutex<Vec<Event>>,
}

impl Recorder {
    #[track_caller]
    fn push(&self, event: Event) {
        match self.events.lock() {
            Ok(mut events) => events.push(event),
            Err(_) => panic!("event lock poisoned"),
        }
    }

    #[track_caller]
    fn events(&self) -> Vec<Event> {
        match self.events.lock() {
            Ok(events) => events.clone(),
            Err(_) => panic!("event lock poisoned"),
        }
    }

    /// The single mismatch report, failing the test unless exactly one was
    /// made.
    #[track_caller]
    fn mismatch(&self) -> SequenceMismatch {
        let reports: Vec<SequenceMismatch> = self
            .events()
            .into_iter()
            .filter_map(|event| match event {
                Event::Mismatch(mismatch) => Some(mismatch),
                _ => None,
            })
            .collect();
        match reports.as_slice() {
            [one] => *one,
            other => panic!("expected exactly one mismatch report, got {other:?}"),
        }
    }

    #[track_caller]
    fn assert_no_mismatch(&self) {
        let events = self.events();
        assert!(
            !events.iter().any(|e| matches!(e, Event::Mismatch(_))),
            "no mismatch report expected: {events:?}"
        );
    }
}

#[async_trait]
impl Application for Recorder {
    async fn on_create(&self, _: &SessionId) {}

    async fn on_logon(&self, _: &SessionId) {
        self.push(Event::Logon);
    }

    async fn on_logout(&self, _: &SessionId) {}

    async fn on_inbound_lost(&self, _: &SessionId, loss: &InboundLoss) {
        self.push(Event::Lost(loss.first(), loss.last()));
    }

    async fn on_sequence_mismatch(&self, _: &SessionId, mismatch: &SequenceMismatch) {
        self.push(Event::Mismatch(*mismatch));
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Initiator,
    Acceptor,
}

/// One Logon exchange to script.
#[derive(Debug, Clone, Default)]
struct Setup {
    /// A `MemoryStore` holding (next sender, next target, app watermark).
    store: Option<(u64, u64, u64)>,
    /// Explicit initial (sender, target).
    seeds: Option<(u64, u64)>,
    /// Whether the engine uses `NextExpectedMsgSeqNum` (789).
    use_789: bool,
    /// The counterparty Logon's `MsgSeqNum`.
    peer_seq: u64,
    /// Extra fields on the counterparty's Logon.
    peer_extra: Vec<(u32, String)>,
}

/// What a scripted exchange produced.
struct Outcome {
    result: Result<Connection, EngineError>,
    app: Arc<Recorder>,
    peer: Peer,
}

async fn memory_store(sender: u64, target: u64, watermark: u64) -> Arc<dyn MessageStore> {
    let store = Arc::new(MemoryStore::new());
    ok(store.set_next_sender_seq(sender).await, "seed store sender");
    ok(store.set_next_target_seq(target).await, "seed store target");
    if watermark > 0 {
        ok(store.set_app_watermark(watermark).await, "seed watermark");
    }
    store
}

async fn run(role: Role, setup: Setup) -> Outcome {
    let app = Arc::new(Recorder::default());
    let store = match setup.store {
        Some((sender, target, watermark)) => Some(memory_store(sender, target, watermark).await),
        None => None,
    };
    let mut extra = vec![(98, "0".to_string()), (108, "30".to_string())];
    extra.extend(setup.peer_extra.iter().cloned());
    let (engine_io, peer_io) = tokio::io::duplex(64 * 1024);
    let mut peer = Framed::new(peer_io, FixCodec::new());
    let result = match role {
        Role::Initiator => {
            let config = SessionConfig::new(comp_id("CLIENT"), comp_id("VENUE"), "FIX.4.4")
                .with_heartbeat_interval(Duration::from_secs(30))
                .with_send_next_expected_msg_seq_num(setup.use_789);
            let mut initiator = Initiator::new(config, Arc::clone(&app));
            if let Some(store) = store {
                initiator = initiator.with_store(store);
            }
            if let Some((sender, target)) = setup.seeds {
                initiator = initiator.with_initial_sequences(sender, target);
            }
            let established = tokio::spawn(async move { initiator.establish(engine_io).await });
            let _logon = next_frame(&mut peer).await;
            ok(
                peer.send(frame("VENUE", "CLIENT", "A", setup.peer_seq, &extra))
                    .await,
                "the counterparty sends its ack",
            );
            ok(
                ok(timeout(STEP, established).await, "handshake in time"),
                "handshake task",
            )
        }
        Role::Acceptor => {
            let config = SessionConfig::new(comp_id("VENUE"), comp_id("CLIENT"), "FIX.4.4")
                .with_heartbeat_interval(Duration::from_secs(30))
                .with_send_next_expected_msg_seq_num(setup.use_789);
            let mut acceptor = Acceptor::new(config, Arc::clone(&app));
            if let Some(store) = store {
                acceptor = acceptor.with_store(store);
            }
            if let Some((sender, target)) = setup.seeds {
                acceptor = acceptor.with_initial_sequences(sender, target);
            }
            let served = tokio::spawn(async move { acceptor.serve_stream(engine_io).await });
            ok(
                peer.send(frame("CLIENT", "VENUE", "A", setup.peer_seq, &extra))
                    .await,
                "the counterparty sends its Logon",
            );
            ok(
                ok(timeout(STEP, served).await, "handshake in time"),
                "handshake task",
            )
        }
    };
    Outcome { result, app, peer }
}

#[track_caller]
fn connection(outcome: &Outcome) -> &Connection {
    match &outcome.result {
        Ok(connection) => connection,
        Err(err) => panic!("the session must be established: {err:?}"),
    }
}

fn next_expected(value: u64) -> Vec<(u32, String)> {
    vec![(789, value.to_string())]
}

fn reset_flag() -> Vec<(u32, String)> {
    vec![(141, "Y".to_string())]
}

/// Reads frames until one of `msg_type` arrives, skipping the ack.
async fn frame_of(peer: &mut Peer, msg_type: &str) -> BytesMut {
    loop {
        let frame = next_frame(peer).await;
        if field(&frame, 35).as_deref() == Some(msg_type) {
            return frame;
        }
    }
}

// ---------------------------------------------------------------------------
// Inbound gap
// ---------------------------------------------------------------------------

async fn inbound_gap(role: Role) {
    let mut outcome = run(
        role,
        Setup {
            store: Some((1, 4, 0)),
            peer_seq: 9,
            ..Setup::default()
        },
    )
    .await;
    let mismatch = outcome.app.mismatch();
    assert_eq!(
        mismatch.inbound(),
        Some(InboundMismatch::Gap { first: 4, last: 8 })
    );
    assert_eq!(mismatch.outbound(), OutboundMismatch::NotDeclared);
    assert_eq!(mismatch.effective_next_sender(), 1);
    assert_eq!(mismatch.effective_next_target(), 4);
    assert_eq!(mismatch.stored_next_sender(), Some(1));
    assert_eq!(mismatch.stored_next_target(), Some(4));
    assert_eq!(mismatch.peer_logon_seq(), 9);
    assert_eq!(mismatch.peer_next_expected(), None);
    assert_eq!(
        outcome.app.events(),
        vec![Event::Mismatch(mismatch), Event::Logon]
    );
    // Unchanged behaviour: the gapped Logon is not consumed and the gap is
    // requested.
    assert_eq!(connection(&outcome).next_target_seq(), 4);
    let request = frame_of(&mut outcome.peer, "2").await;
    assert_eq!(field(&request, 7).as_deref(), Some("4"));
}

#[tokio::test]
async fn test_initiator_reports_an_inbound_gap() {
    inbound_gap(Role::Initiator).await;
}

#[tokio::test]
async fn test_acceptor_reports_an_inbound_gap() {
    inbound_gap(Role::Acceptor).await;
}

// ---------------------------------------------------------------------------
// Inbound too low
// ---------------------------------------------------------------------------

async fn inbound_too_low(role: Role) {
    let outcome = run(
        role,
        Setup {
            store: Some((1, 5, 0)),
            peer_seq: 2,
            ..Setup::default()
        },
    )
    .await;
    let mismatch = outcome.app.mismatch();
    assert_eq!(
        mismatch.inbound(),
        Some(InboundMismatch::TooLow {
            received: 2,
            expected: 5
        })
    );
    // Unchanged behaviour: the session is refused, without on_logon.
    assert!(
        matches!(outcome.result, Err(EngineError::Sequence(_))),
        "a Logon too low is refused: {:?}",
        outcome.result.as_ref().err()
    );
    assert_eq!(outcome.app.events(), vec![Event::Mismatch(mismatch)]);
}

#[tokio::test]
async fn test_initiator_reports_an_inbound_logon_too_low() {
    inbound_too_low(Role::Initiator).await;
}

#[tokio::test]
async fn test_acceptor_reports_an_inbound_logon_too_low() {
    inbound_too_low(Role::Acceptor).await;
}

// ---------------------------------------------------------------------------
// Outbound: the counterparty missed messages
// ---------------------------------------------------------------------------

async fn peer_missed(role: Role) {
    let mut outcome = run(
        role,
        Setup {
            store: Some((5, 1, 0)),
            use_789: true,
            peer_seq: 1,
            peer_extra: next_expected(3),
            ..Setup::default()
        },
    )
    .await;
    let mismatch = outcome.app.mismatch();
    assert_eq!(mismatch.inbound(), None);
    assert_eq!(
        mismatch.outbound(),
        OutboundMismatch::PeerMissed { first: 3, last: 4 }
    );
    assert_eq!(mismatch.peer_next_expected(), Some(3));
    assert_eq!(
        outcome.app.events(),
        vec![Event::Mismatch(mismatch), Event::Logon]
    );
    // Unchanged behaviour: 3..=4 is gap-filled (no stored messages), and the
    // counters are where the exchange left them.
    let fill = frame_of(&mut outcome.peer, "4").await;
    assert_eq!(field(&fill, 34).as_deref(), Some("3"));
    assert_eq!(field(&fill, 36).as_deref(), Some("5"));
    let connection = connection(&outcome);
    assert_eq!(connection.next_sender_seq(), 6);
    assert_eq!(connection.next_target_seq(), 2);
}

#[tokio::test]
async fn test_initiator_reports_a_peer_that_missed_outbound_messages() {
    peer_missed(Role::Initiator).await;
}

#[tokio::test]
async fn test_acceptor_reports_a_peer_that_missed_outbound_messages() {
    peer_missed(Role::Acceptor).await;
}

// ---------------------------------------------------------------------------
// Outbound: the counterparty is ahead of us
// ---------------------------------------------------------------------------

async fn peer_ahead(role: Role, next_outbound: u64) {
    let outcome = run(
        role,
        Setup {
            use_789: true,
            peer_seq: 1,
            peer_extra: next_expected(9),
            ..Setup::default()
        },
    )
    .await;
    let mismatch = outcome.app.mismatch();
    assert_eq!(mismatch.inbound(), None);
    assert_eq!(
        mismatch.outbound(),
        OutboundMismatch::PeerAhead {
            declared: 9,
            next_outbound
        }
    );
    assert_eq!(mismatch.stored_next_sender(), None);
    assert_eq!(mismatch.stored_next_target(), None);
    // Unchanged behaviour: refused under ADR-0021, after the report.
    assert!(
        matches!(
            outcome.result,
            Err(EngineError::NextExpectedMsgSeqNum { .. })
        ),
        "a 789 above the next outbound is refused: {:?}",
        outcome.result.as_ref().err()
    );
    assert_eq!(outcome.app.events(), vec![Event::Mismatch(mismatch)]);
}

#[tokio::test]
async fn test_initiator_reports_a_peer_ahead_of_its_outbound_stream() {
    // Our Logon was 1, so the next outbound is 2.
    peer_ahead(Role::Initiator, 2).await;
}

#[tokio::test]
async fn test_acceptor_reports_a_peer_ahead_of_its_outbound_stream() {
    // Our acknowledgement is the next outbound, 1.
    peer_ahead(Role::Acceptor, 1).await;
}

// ---------------------------------------------------------------------------
// No report
// ---------------------------------------------------------------------------

async fn in_sync(role: Role, use_789: bool, declared: Option<u64>) {
    let outcome = run(
        role,
        Setup {
            store: Some((3, 6, 0)),
            use_789,
            peer_seq: 6,
            peer_extra: declared.map(next_expected).unwrap_or_default(),
            ..Setup::default()
        },
    )
    .await;
    let connection = connection(&outcome);
    outcome.app.assert_no_mismatch();
    assert_eq!(outcome.app.events(), vec![Event::Logon]);
    assert_eq!(connection.next_sender_seq(), 4);
    assert_eq!(connection.next_target_seq(), 7);
}

#[tokio::test]
async fn test_initiator_makes_no_report_when_everything_matches() {
    in_sync(Role::Initiator, false, None).await;
    // 789 = our next outbound after the Logon numbered 3.
    in_sync(Role::Initiator, true, Some(4)).await;
}

#[tokio::test]
async fn test_acceptor_makes_no_report_when_everything_matches() {
    in_sync(Role::Acceptor, false, None).await;
    // 789 = the number our acknowledgement takes.
    in_sync(Role::Acceptor, true, Some(3)).await;
}

async fn reset_exchange(role: Role) {
    // The store says 7 is next, and the counterparty resets: its Logon is 1,
    // which would be too low without the reset.
    let outcome = run(
        role,
        Setup {
            store: Some((4, 7, 0)),
            use_789: true,
            peer_seq: 1,
            peer_extra: reset_flag(),
            ..Setup::default()
        },
    )
    .await;
    let connection = connection(&outcome);
    outcome.app.assert_no_mismatch();
    assert_eq!(outcome.app.events(), vec![Event::Logon]);
    assert_eq!(connection.next_target_seq(), 2);
}

#[tokio::test]
async fn test_initiator_makes_no_report_on_a_reset_exchange() {
    reset_exchange(Role::Initiator).await;
}

#[tokio::test]
async fn test_acceptor_makes_no_report_on_a_reset_exchange() {
    reset_exchange(Role::Acceptor).await;
}

// ---------------------------------------------------------------------------
// Store plus explicit seeds: the effective counters are the baseline
// ---------------------------------------------------------------------------

async fn seeds_over_store(role: Role) {
    // Store 10/20, seeds 15/30, peer Logon 30: in sync, although the store's
    // target is 20.
    let outcome = run(
        role,
        Setup {
            store: Some((10, 20, 0)),
            seeds: Some((15, 30)),
            peer_seq: 30,
            ..Setup::default()
        },
    )
    .await;
    let in_sync = connection(&outcome);
    outcome.app.assert_no_mismatch();
    assert_eq!(in_sync.next_sender_seq(), 16);
    assert_eq!(in_sync.next_target_seq(), 31);

    // Peer Logon 31: a gap of one from the seeds, with the store's values
    // reported beside them.
    let outcome = run(
        role,
        Setup {
            store: Some((10, 20, 0)),
            seeds: Some((15, 30)),
            peer_seq: 31,
            ..Setup::default()
        },
    )
    .await;
    let mismatch = outcome.app.mismatch();
    assert_eq!(
        mismatch.inbound(),
        Some(InboundMismatch::Gap {
            first: 30,
            last: 30
        })
    );
    assert_eq!(mismatch.effective_next_sender(), 15);
    assert_eq!(mismatch.effective_next_target(), 30);
    assert_eq!(mismatch.stored_next_sender(), Some(10));
    assert_eq!(mismatch.stored_next_target(), Some(20));
    assert_eq!(connection(&outcome).next_target_seq(), 30);
}

#[tokio::test]
async fn test_initiator_compares_seeds_over_a_store_as_effective_counters() {
    seeds_over_store(Role::Initiator).await;
}

#[tokio::test]
async fn test_acceptor_compares_seeds_over_a_store_as_effective_counters() {
    seeds_over_store(Role::Acceptor).await;
}

// ---------------------------------------------------------------------------
// Order with the other start reports
// ---------------------------------------------------------------------------

async fn report_order(role: Role) {
    // Watermark 2 below a stored target of 5: 3..=4 may be lost. The peer
    // Logon 8 opens a gap 5..=7.
    let outcome = run(
        role,
        Setup {
            store: Some((1, 5, 2)),
            peer_seq: 8,
            ..Setup::default()
        },
    )
    .await;
    let _ = connection(&outcome);
    let mismatch = outcome.app.mismatch();
    assert_eq!(
        mismatch.inbound(),
        Some(InboundMismatch::Gap { first: 5, last: 7 })
    );
    assert_eq!(
        outcome.app.events(),
        vec![Event::Lost(3, 4), Event::Mismatch(mismatch), Event::Logon]
    );
}

#[tokio::test]
async fn test_initiator_reports_after_inbound_lost_and_before_logon() {
    report_order(Role::Initiator).await;
}

#[tokio::test]
async fn test_acceptor_reports_after_inbound_lost_and_before_logon() {
    report_order(Role::Acceptor).await;
}
