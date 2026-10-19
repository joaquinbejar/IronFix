/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Integration tests for issue #68 (ADR-0023): the outbound veto
//! (`Application::to_app_checked`) and per-message send outcomes
//! (`Connection::send_tracked`).
//!
//! Every session here runs over a `tokio::io::duplex` pipe (issue #63). The
//! counterparty is either a real engine of the other role, or a scripted
//! `Framed<DuplexStream, FixCodec>` when the test must control exactly when
//! the counterparty reads: a small pipe that nobody reads is how a frame is
//! kept from being flushed, and dropping the scripted end is how the transport
//! is killed. The application under test can park the reactor inside
//! `to_app_checked` or inside `from_admin` for an inbound Logout, which is how
//! a test holds messages in the outbound queue at a chosen moment.
//!
//! Covered: a veto spends no `MsgSeqNum` and files nothing, in both roles;
//! `Sent` reports the number, `SendingTime` and `filed` the peer and the
//! store see, and resolves only after the flush; a write that does not
//! complete is `Unknown`, replays from the store, and does not after a
//! close-time reset; every `NotSentReason`, and that `Invalid` never quotes a
//! secret; administrative messages cannot be vetoed; an application that
//! overrides only `to_app` behaves as before; a full queue at a kill, at this
//! session's Logout and at the counterparty's; and tracked sends held behind
//! a resend or a 789 resend, including one a gate closed meanwhile stops.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{FutureExt, SinkExt, StreamExt};
use ironfix_core::error::StoreError;
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::application::{Application, RejectReason, SendVerdict, SessionId};
use ironfix_engine::{
    Acceptor, Connection, Initiator, NotSentReason, OutboundMessage, SendOutcome,
    StoreFailurePolicy, UnknownReason,
};
use ironfix_session::SessionConfig;
use ironfix_store::{MemoryStore, MessageStore, StoredMessage};
use ironfix_tagvalue::{Decoder, Encoder};
use ironfix_transport::FixCodec;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::DuplexStream;
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::codec::Framed;

/// Capacity of each direction of a roomy test pipe, in bytes.
const PIPE_CAPACITY: usize = 64 * 1024;

/// Capacity of a pipe meant to fill up, in bytes: a Logon fits, a large
/// order does not.
const SMALL_PIPE: usize = 1024;

/// How long a test waits for any one step before failing.
const STEP: Duration = Duration::from_secs(5);

/// How long a test waits to show that something has **not** happened.
const QUIET: Duration = Duration::from_millis(300);

/// How many orders of 2 KiB a resend test files: more than the 64 KiB a
/// resend feeds the write buffer before it waits for the counterparty to
/// read, so the resend is still under way while messages wait behind it.
const RESEND_ORDERS: u64 = 100;

/// The Logon acknowledgement body the scripted venue sends by default.
const ACK: &[(u32, &str)] = &[(98, "0"), (108, "30")];

/// A value that must never appear in an outcome or a log line.
const SECRET: &str = "hunter2\u{1}TOP-SECRET";

/// The scripted counterparty's end of a pipe.
type VenueFramed = Framed<DuplexStream, FixCodec>;

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

/// Locks a test mutex, failing the test if it is poisoned.
#[track_caller]
fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(_) => panic!("test lock poisoned"),
    }
}

/// An application message as the receiving application saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Received {
    /// Its MsgType (35).
    msg_type: String,
    /// Its MsgSeqNum (34).
    seq: Option<u64>,
    /// Whether it carried PossDupFlag (43) = Y.
    poss_dup: bool,
    /// Its ClOrdID (11).
    id: Option<String>,
    /// Its SendingTime (52).
    sending_time: Option<String>,
    /// Its Account (1).
    account: Option<String>,
}

impl Received {
    fn from_raw(message: &RawMessage<'_>) -> Self {
        let text = |tag| message.get_field_str(tag).map(str::to_string);
        Self {
            msg_type: message.msg_type().as_str().to_string(),
            seq: message.get_field_str(34).and_then(|seq| seq.parse().ok()),
            poss_dup: message.get_field_str(43) == Some("Y"),
            id: text(11),
            sending_time: text(52),
            account: text(1),
        }
    }
}

/// The application under test: a gate in `to_app_checked`.
///
/// It vetoes every application message whose ClOrdID (11) starts with
/// `VETO` (or every one, once `veto_all` is set), parks the one whose ClOrdID
/// is `GATE` until released, breaks the body of one whose ClOrdID starts
/// with `BREAK` by appending a tag the engine stamps itself, and appends
/// [`SECRET`] as `Password` (554) to one whose ClOrdID starts with `LEAK`.
/// With `park_logout` set, `from_admin` parks on an inbound Logout until
/// released. It records which MsgTypes went through `to_admin` and which
/// through `to_app_checked`, rejects an inbound administrative message whose
/// Text (58) is `REJECT ME`, and forwards every inbound application message.
#[derive(Debug)]
struct GateApp {
    veto_all: AtomicBool,
    park_logout: AtomicBool,
    admin_seen: Mutex<Vec<String>>,
    app_checked_seen: Mutex<Vec<String>>,
    entered: Notify,
    release: Notify,
    logout_entered: Notify,
    logout_release: Notify,
    app_tx: mpsc::UnboundedSender<Received>,
}

impl GateApp {
    fn new() -> (Arc<Self>, mpsc::UnboundedReceiver<Received>) {
        let (app_tx, app_rx) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                veto_all: AtomicBool::new(false),
                park_logout: AtomicBool::new(false),
                admin_seen: Mutex::new(Vec::new()),
                app_checked_seen: Mutex::new(Vec::new()),
                entered: Notify::new(),
                release: Notify::new(),
                logout_entered: Notify::new(),
                logout_release: Notify::new(),
                app_tx,
            }),
            app_rx,
        )
    }

    fn admin_seen(&self) -> Vec<String> {
        locked(&self.admin_seen).clone()
    }

    fn app_checked_seen(&self) -> Vec<String> {
        locked(&self.app_checked_seen).clone()
    }
}

#[async_trait]
impl Application for GateApp {
    async fn on_create(&self, _session_id: &SessionId) {}

    async fn on_logon(&self, _session_id: &SessionId) {}

    async fn on_logout(&self, _session_id: &SessionId) {}

    async fn to_admin(&self, message: &mut OutboundMessage, _session_id: &SessionId) {
        locked(&self.admin_seen).push(message.msg_type().as_str().to_string());
    }

    async fn from_admin(
        &self,
        message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        if message.msg_type() == &MsgType::Logout && self.park_logout.load(Ordering::SeqCst) {
            self.logout_entered.notify_one();
            self.logout_release.notified().await;
        }
        if message.get_field_str(58) == Some("REJECT ME") {
            return Err(RejectReason::new(99, "refused by the test application"));
        }
        Ok(())
    }

    async fn to_app(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {
        panic!("the engine calls to_app_checked, which this application overrides");
    }

    fn to_app_checked<'a>(
        &'a self,
        message: &'a mut OutboundMessage,
        _session_id: &'a SessionId,
    ) -> SendVerdict<'a> {
        locked(&self.app_checked_seen).push(message.msg_type().as_str().to_string());
        let id = message
            .get(11)
            .map(|id| String::from_utf8_lossy(id).into_owned())
            .unwrap_or_default();
        if self.veto_all.load(Ordering::SeqCst) || id.starts_with("VETO") {
            return SendVerdict::ready(Err(RejectReason::new(
                7,
                format!("risk gate refused {id}"),
            )));
        }
        if id.starts_with("BREAK") {
            // MsgSeqNum (34) is the engine's to stamp: a body carrying it is
            // refused after the callback.
            message.push_uint(34, 99);
        }
        if id.starts_with("LEAK") {
            message.push_str(554, SECRET);
        }
        if id == "GATE" {
            // A decision that has to wait: the engine awaits it inline.
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
        let _ = self.app_tx.send(Received::from_raw(message));
        Ok(())
    }
}

/// An application written before `to_app_checked` existed: it overrides
/// `to_app` only, stamping Account (1) on every application message.
#[derive(Debug)]
struct StampingApp;

#[async_trait]
impl Application for StampingApp {
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

    async fn to_app(&self, message: &mut OutboundMessage, _session_id: &SessionId) {
        message.push_str(1, "ACC-1");
    }

    async fn from_app(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }
}

/// A store that refuses to file frames on demand; counters still work.
#[derive(Debug)]
struct RefusingStore {
    inner: MemoryStore,
    refuse: AtomicBool,
}

impl RefusingStore {
    fn new() -> Self {
        Self {
            inner: MemoryStore::new(),
            refuse: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl MessageStore for RefusingStore {
    async fn store(
        &self,
        seq_num: u64,
        msg_type: &MsgType,
        message: &[u8],
    ) -> Result<(), StoreError> {
        if self.refuse.load(Ordering::SeqCst) {
            // Names the operation only, never frame bytes.
            return Err(StoreError::Io(
                "store refused by the test store".to_string(),
            ));
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

/// Returns the finished frame, failing the test with the encoder's rejection.
#[track_caller]
fn frame_of(encoder: &mut Encoder) -> BytesMut {
    let mut frame = BytesMut::new();
    match encoder.finish_into(&mut frame) {
        Ok(()) => frame,
        Err(err) => panic!("test fixture frame must encode: {err}"),
    }
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
    frame_of(&mut encoder)
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

/// Reads the next frame within [`STEP`].
async fn next_frame(framed: &mut VenueFramed) -> BytesMut {
    let polled = ok(
        timeout(STEP, framed.next()).await,
        "a frame arrives within 5s",
    );
    ok(some(polled, "the stream stays open"), "the frame frames")
}

/// Reads frames until one of MsgType `msg_type` arrives, returning it.
async fn frame_of_type(framed: &mut VenueFramed, msg_type: &str) -> BytesMut {
    frame_where(framed, |frame| {
        field(frame, 35).as_deref() == Some(msg_type)
    })
    .await
}

/// Reads frames until one matching `wanted` arrives, returning it.
async fn frame_where(framed: &mut VenueFramed, wanted: impl Fn(&[u8]) -> bool) -> BytesMut {
    loop {
        let frame = next_frame(framed).await;
        if wanted(&frame) {
            return frame;
        }
    }
}

/// Asserts that the venue reads nothing for [`QUIET`].
async fn assert_silent(framed: &mut VenueFramed, what: &str) {
    if let Ok(frame) = timeout(QUIET, framed.next()).await {
        panic!("{what}: read {frame:?}");
    }
}

/// Writes one frame from the scripted venue.
async fn venue_send(framed: &mut VenueFramed, frame: BytesMut) {
    ok(
        ok(
            timeout(STEP, framed.send(frame)).await,
            "the venue writes within 5s",
        ),
        "the venue writes",
    );
}

/// Awaits a spawned task within [`STEP`].
async fn joined<T>(task: JoinHandle<T>, what: &str) -> T {
    ok(ok(timeout(STEP, task).await, what), what)
}

/// Receives the next application message within [`STEP`].
async fn received(rx: &mut mpsc::UnboundedReceiver<Received>) -> Received {
    some(
        ok(
            timeout(STEP, rx.recv()).await,
            "an application message arrives within 5s",
        ),
        "the application channel stays open",
    )
}

/// Spawns a tracked send of an order with ClOrdID `id`.
fn track(member: &Connection, id: &'static str) -> JoinHandle<SendOutcome> {
    let member = member.clone();
    tokio::spawn(async move { member.send_tracked(order(id)).await })
}

/// The `MsgSeqNum`, `SendingTime` and `filed` of a `Sent` outcome.
#[track_caller]
fn sent(outcome: &SendOutcome) -> (u64, Timestamp, bool) {
    match outcome {
        SendOutcome::Sent {
            seq,
            sending_time,
            filed,
            ..
        } => (*seq, *sending_time, *filed),
        other => panic!("expected Sent, got {other:?}"),
    }
}

/// The reason of a `NotSent` outcome.
#[track_caller]
fn not_sent(outcome: &SendOutcome) -> &NotSentReason {
    match outcome {
        SendOutcome::NotSent { reason, .. } => reason,
        other => panic!("expected NotSent, got {other:?}"),
    }
}

/// The `MsgSeqNum` and reason of an `Unknown` outcome.
#[track_caller]
fn unknown(outcome: &SendOutcome) -> (u64, UnknownReason) {
    match outcome {
        SendOutcome::Unknown { seq, reason, .. } => (*seq, *reason),
        other => panic!("expected Unknown, got {other:?}"),
    }
}

/// Asserts that a tracked send resolved `NotSent` with `Discarded`.
#[track_caller]
fn assert_discarded(outcome: &SendOutcome) {
    assert!(
        matches!(not_sent(outcome), NotSentReason::Discarded { .. }),
        "expected Discarded, got {outcome:?}"
    );
}

/// Whether `store` holds a frame under `seq`. An empty range is reported as
/// `RangeNotAvailable`, which means it does not.
async fn holds(store: &dyn MessageStore, seq: u64) -> bool {
    match store.get_range(seq, seq).await {
        Ok(messages) => !messages.is_empty(),
        Err(StoreError::RangeNotAvailable { .. }) => false,
        Err(err) => panic!("the store reads: {err:?}"),
    }
}

/// Waits for `connection` to close within [`STEP`].
async fn closed(connection: &Connection, what: &str) {
    ok(timeout(STEP, connection.wait_closed()).await, what);
}

/// Starts `initiator` over a pipe of `capacity` bytes against a scripted
/// venue that acknowledges its Logon at 1 with the body `ack`. Returns the
/// session and the venue's end, just past the ack, with the member's Logon.
async fn scripted<A: Application + 'static>(
    initiator: &Initiator<A>,
    capacity: usize,
    ack: &[(u32, &str)],
) -> (Connection, VenueFramed, BytesMut) {
    let (client_io, venue_io) = tokio::io::duplex(capacity);
    let ack: Vec<(u32, String)> = ack
        .iter()
        .map(|(tag, value)| (*tag, (*value).to_string()))
        .collect();
    let venue = tokio::spawn(async move {
        let mut framed = Framed::new(venue_io, FixCodec::new());
        let logon = next_frame(&mut framed).await;
        assert_eq!(field(&logon, 35).as_deref(), Some("A"));
        let body: Vec<(u32, &str)> = ack
            .iter()
            .map(|(tag, value)| (*tag, value.as_str()))
            .collect();
        venue_send(&mut framed, venue_msg("A", 1, &body)).await;
        (framed, logon)
    });
    let member = ok(
        initiator.establish(client_io).await,
        "the member logs on over the pipe",
    );
    let (framed, logon) = joined(venue, "the scripted venue acknowledges the Logon").await;
    (member, framed, logon)
}

/// Starts an Initiator and an Acceptor against each other over a roomy pipe.
async fn engines<M, V>(initiator: Initiator<M>, acceptor: Acceptor<V>) -> (Connection, Connection)
where
    M: Application + 'static,
    V: Application + 'static,
{
    let (client_io, venue_io) = tokio::io::duplex(PIPE_CAPACITY);
    let served = tokio::spawn(async move { acceptor.serve_stream(venue_io).await });
    let member = ok(
        initiator.establish(client_io).await,
        "the initiator logs on over the pipe",
    );
    let venue = ok(
        joined(served, "the acceptor handshake ends").await,
        "the acceptor logs on over the pipe",
    );
    (member, venue)
}

/// Logs `initiator` out and waits for both ends to close.
async fn log_out(initiator: &Connection, acceptor: &Connection) {
    ok(initiator.logout().await, "the initiator logs out");
    closed(initiator, "the initiator session closes within 5s").await;
    closed(acceptor, "the acceptor session closes within 5s").await;
}

/// `send_tracked` reports the `MsgSeqNum` and `SendingTime` (52) the peer
/// actually reads, in both roles; without a store nothing is filed.
#[tokio::test]
async fn test_send_tracked_reports_the_seq_and_sending_time_the_peer_reads_in_both_roles() {
    let (member_app, mut member_rx) = GateApp::new();
    let (venue_app, mut venue_rx) = GateApp::new();
    let (member, venue) = engines(
        Initiator::new(member_config(), member_app),
        Acceptor::new(venue_config(), venue_app),
    )
    .await;

    for (expected, id) in [(2, "ORDER-1"), (3, "ORDER-2")] {
        let outcome = member.send_tracked(order(id)).await;
        let (seq, sending_time, filed) = sent(&outcome);
        assert_eq!(outcome.seq(), Some(seq));
        assert!(outcome.is_sent());
        assert!(!filed, "there is no store to file it in");
        let seen = received(&mut venue_rx).await;
        assert_eq!(seen.id.as_deref(), Some(id));
        assert_eq!(seen.seq, Some(seq), "the number the venue read");
        assert_eq!(seq, expected);
        assert_eq!(
            seen.sending_time.as_deref(),
            Some(sending_time.format_millis().as_str()),
            "the SendingTime the venue read"
        );
    }

    let outcome = venue.send_tracked(order("REPORT-1")).await;
    let (seq, sending_time, _) = sent(&outcome);
    let seen = received(&mut member_rx).await;
    assert_eq!(
        (seen.seq, seq),
        (Some(2), 2),
        "the acceptor role reports too"
    );
    assert_eq!(
        seen.sending_time.as_deref(),
        Some(sending_time.format_millis().as_str())
    );

    log_out(&member, &venue).await;
}

/// The veto in one role: `sender` vetoes messages whose ClOrdID starts with
/// VETO. A vetoed message, tracked or not, spends no `MsgSeqNum` and leaves
/// the sender's store untouched; the next message takes the number the
/// vetoed one would have had, so the receiver sees no gap.
async fn assert_veto_spends_nothing(
    sender: &Connection,
    store: &MemoryStore,
    receiver: &Connection,
    receiver_rx: &mut mpsc::UnboundedReceiver<Received>,
) {
    let first = sender.send_tracked(order("OK-1")).await;
    assert_eq!(sent(&first).0, 2);
    assert!(sent(&first).2, "the store filed it");
    assert_eq!(received(receiver_rx).await.seq, Some(2));

    let next_sender = sender.next_sender_seq();
    let filed = store.message_count();
    let stored_next = store.next_sender_seq();
    assert_eq!((next_sender, stored_next), (3, 3));

    let vetoed = sender.send_tracked(order("VETO-1")).await;
    match not_sent(&vetoed) {
        NotSentReason::Vetoed { reason, .. } => {
            assert_eq!(reason.code, 7);
            assert_eq!(reason.text, "risk gate refused VETO-1");
        }
        other => panic!("expected Vetoed, got {other:?}"),
    }
    assert_eq!(vetoed.seq(), None, "a vetoed message spends no number");
    assert_eq!(sender.next_sender_seq(), next_sender, "no number spent");
    assert_eq!(store.message_count(), filed, "nothing filed");
    assert_eq!(store.next_sender_seq(), stored_next, "no counter written");

    // A plain send goes through the same gate: queued, then vetoed.
    ok(sender.send(order("VETO-2")).await, "a plain send is queued");

    let next = sender.send_tracked(order("OK-2")).await;
    assert_eq!(
        sent(&next).0,
        3,
        "the next message takes the number the vetoed ones would have had"
    );
    let seen = received(receiver_rx).await;
    assert_eq!(
        (seen.id.as_deref(), seen.seq),
        (Some("OK-2"), Some(3)),
        "no vetoed message reached the peer"
    );
    assert_eq!(store.message_count(), filed + 1, "only OK-2 was filed");
    assert_eq!(receiver.next_target_seq(), 4, "the peer saw no gap");
    assert!(!sender.is_closed() && !receiver.is_closed());
}

#[tokio::test]
async fn test_veto_spends_no_seq_and_files_nothing_on_the_initiator() {
    let store = Arc::new(MemoryStore::new());
    let (member_app, _member_rx) = GateApp::new();
    let (venue_app, mut venue_rx) = GateApp::new();
    let (member, venue) = engines(
        Initiator::new(member_config(), Arc::clone(&member_app))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
        Acceptor::new(venue_config(), venue_app),
    )
    .await;
    assert_veto_spends_nothing(&member, &store, &venue, &mut venue_rx).await;
    assert_eq!(
        member_app.app_checked_seen(),
        ["D", "D", "D", "D"],
        "every application message went through the gate, plain sends included"
    );
    log_out(&member, &venue).await;
}

#[tokio::test]
async fn test_veto_spends_no_seq_and_files_nothing_on_the_acceptor() {
    let store = Arc::new(MemoryStore::new());
    let (member_app, mut member_rx) = GateApp::new();
    let (venue_app, _venue_rx) = GateApp::new();
    let (member, venue) = engines(
        Initiator::new(member_config(), member_app),
        Acceptor::new(venue_config(), Arc::clone(&venue_app))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    )
    .await;
    assert_veto_spends_nothing(&venue, &store, &member, &mut member_rx).await;
    assert_eq!(venue_app.app_checked_seen(), ["D", "D", "D", "D"]);
    log_out(&member, &venue).await;
}

/// `Sent` means flushed, not queued: while the counterparty does not read, a
/// frame larger than the pipe cannot be flushed and the outcome stays
/// pending; it resolves once the counterparty reads the frame.
#[tokio::test]
async fn test_sent_resolves_only_after_the_frame_is_flushed() {
    let (app, _rx) = GateApp::new();
    let initiator = Initiator::new(member_config(), app);
    let (member, mut venue, _logon) = scripted(&initiator, SMALL_PIPE, ACK).await;

    let tracked = {
        let member = member.clone();
        tokio::spawn(async move { member.send_tracked(large_order("BIG-1", 16 * 1024)).await })
    };
    tokio::time::sleep(QUIET).await;
    assert!(
        !tracked.is_finished(),
        "the frame is not flushed while the venue does not read, so it is not Sent"
    );

    let frame = next_frame(&mut venue).await;
    let outcome = joined(tracked, "the outcome resolves once the venue reads").await;
    let (seq, sending_time, _) = sent(&outcome);
    assert_eq!(header(&frame), ("D".to_string(), seq));
    assert_eq!(seq, 2);
    assert_eq!(
        field(&frame, 52).as_deref(),
        Some(sending_time.format_millis().as_str())
    );
    drop(venue);
    closed(&member, "the session closes once the venue is gone").await;
}

/// A write that starts and does not complete (the counterparty takes part of
/// the frame, then stops reading) is `Unknown` with the spent `MsgSeqNum`,
/// never `NotSent`. The number stays spent and the frame stays filed, so a
/// later session replays it from the store when the counterparty asks.
#[tokio::test]
async fn test_write_that_does_not_complete_is_unknown_and_replays_from_the_store() {
    let store = Arc::new(MemoryStore::new());
    let (app, _rx) = GateApp::new();
    let initiator = Initiator::new(member_config(), app)
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
        .with_write_timeout(QUIET);
    let (member, venue, _logon) = scripted(&initiator, SMALL_PIPE, ACK).await;

    let outcome = member
        .send_tracked(large_order("STALLED-1", 16 * 1024))
        .await;
    assert_eq!(unknown(&outcome), (2, UnknownReason::WriteTimeout));
    assert_eq!(outcome.seq(), Some(2), "the number spent on the frame");
    closed(&member, "a stalled write closes the session").await;
    assert_eq!(member.next_sender_seq(), 3, "the number stays spent");
    assert_eq!(store.next_sender_seq(), 3);
    let filed = ok(store.get_range(2, 2).await, "the store reads");
    assert_eq!(filed.len(), 1, "the frame stays filed under its number");
    drop(venue);

    // A later session: the venue still expects 2, so it asks for it.
    let (venue_app, mut venue_rx) = GateApp::new();
    let (member, venue) = engines(
        initiator,
        Acceptor::new(venue_config(), venue_app).with_initial_sequences(2, 2),
    )
    .await;
    let replayed = received(&mut venue_rx).await;
    assert_eq!(replayed.id.as_deref(), Some("STALLED-1"));
    assert_eq!(
        replayed.seq,
        Some(2),
        "replayed under the number it was given"
    );
    assert!(replayed.poss_dup, "a replay carries PossDupFlag (43) = Y");
    log_out(&member, &venue).await;
}

/// One documented exception to the replay of an `Unknown` frame: with
/// `reset_on_disconnect`, the close resets the store, so it no longer holds
/// the frame and nothing can replay it.
#[tokio::test]
async fn test_unknown_frame_is_not_replayable_after_a_reset_on_disconnect() {
    let store = Arc::new(MemoryStore::new());
    let (app, _rx) = GateApp::new();
    let mut config = member_config();
    config.reset_on_disconnect = true;
    let initiator = Initiator::new(config, app)
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
        .with_write_timeout(QUIET);
    let (member, venue, _logon) = scripted(&initiator, SMALL_PIPE, ACK).await;

    let outcome = member
        .send_tracked(large_order("STALLED-1", 16 * 1024))
        .await;
    assert_eq!(unknown(&outcome), (2, UnknownReason::WriteTimeout));
    closed(&member, "a stalled write closes the session").await;
    assert!(
        !holds(store.as_ref(), 2).await,
        "the close-time reset erased the frame"
    );
    assert_eq!(store.message_count(), 0);
    assert_eq!(
        store.next_sender_seq(),
        1,
        "the next session starts the sequence again"
    );
    drop(venue);
}

/// A message the engine will not frame is `NotSent` with `Invalid`, whether
/// it is refused before it is queued (an administrative MsgType, a reserved
/// tag) or after `to_app_checked` broke its body; the tag is named, no
/// number is spent and the session carries on.
#[tokio::test]
async fn test_unframeable_message_is_not_sent_invalid() {
    let (member_app, _member_rx) = GateApp::new();
    let (venue_app, mut venue_rx) = GateApp::new();
    let (member, venue) = engines(
        Initiator::new(member_config(), member_app),
        Acceptor::new(venue_config(), venue_app),
    )
    .await;

    let admin = member
        .send_tracked(OutboundMessage::new(MsgType::Heartbeat))
        .await;
    assert!(
        matches!(
            not_sent(&admin),
            NotSentReason::Invalid { tag: Some(35), .. }
        ),
        "an administrative MsgType: {admin:?}"
    );

    let mut reserved = order("RESERVED-1");
    reserved.push_uint(34, 5);
    let reserved = member.send_tracked(reserved).await;
    match not_sent(&reserved) {
        NotSentReason::Invalid { detail, tag, .. } => {
            assert_eq!(*tag, Some(34));
            assert!(detail.contains("34"), "{detail}");
        }
        other => panic!("expected Invalid, got {other:?}"),
    }

    let broken = member.send_tracked(order("BREAK-1")).await;
    assert!(
        matches!(
            not_sent(&broken),
            NotSentReason::Invalid { tag: Some(34), .. }
        ),
        "a body the callback broke: {broken:?}"
    );
    assert_eq!(member.next_sender_seq(), 2, "no number spent");

    let next = member.send_tracked(order("OK-1")).await;
    assert_eq!(sent(&next).0, 2);
    assert_eq!(received(&mut venue_rx).await.seq, Some(2));
    log_out(&member, &venue).await;
}

/// `Invalid` names the tag and never quotes the value: a secret carrying SOH
/// in Text (58) or Password (554), handed in or added by the callback, does
/// not appear in the detail.
#[tokio::test]
async fn test_invalid_detail_never_quotes_a_secret_value() {
    let (member_app, _member_rx) = GateApp::new();
    let (venue_app, _venue_rx) = GateApp::new();
    let (member, venue) = engines(
        Initiator::new(member_config(), member_app),
        Acceptor::new(venue_config(), venue_app),
    )
    .await;

    let mut in_text = order("SECRET-58");
    in_text.push_str(58, SECRET);
    let mut in_password = order("SECRET-554");
    in_password.push_str(554, SECRET);
    for (message, expected) in [(in_text, 58), (in_password, 554), (order("LEAK-554"), 554)] {
        let outcome = member.send_tracked(message).await;
        match not_sent(&outcome) {
            NotSentReason::Invalid { detail, tag, .. } => {
                assert_eq!(*tag, Some(expected));
                for piece in ["hunter2", "TOP-SECRET"] {
                    assert!(
                        !detail.contains(piece),
                        "the detail quotes the value: {detail}"
                    );
                }
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
        assert!(
            !format!("{outcome:?}").contains("hunter2"),
            "the whole outcome is free of it"
        );
    }
    assert_eq!(member.next_sender_seq(), 2, "no number spent");
    log_out(&member, &venue).await;
}

/// The store refuses to file a frame under `CloseSession`: the message is
/// `NotSent` with `StoreRefused` (the store's state unknown), nothing is
/// spent or written, and the session closes.
#[tokio::test]
async fn test_store_refusal_under_close_session_is_not_sent() {
    let store = Arc::new(RefusingStore::new());
    let (member_app, _member_rx) = GateApp::new();
    let (venue_app, mut venue_rx) = GateApp::new();
    let (member, venue) = engines(
        Initiator::new(member_config(), member_app)
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
            .with_store_failure_policy(StoreFailurePolicy::CloseSession),
        Acceptor::new(venue_config(), venue_app),
    )
    .await;
    store.refuse.store(true, Ordering::SeqCst);

    let outcome = member.send_tracked(order("FILED-1")).await;
    assert!(
        matches!(
            not_sent(&outcome),
            NotSentReason::StoreRefused {
                state_unknown: true,
                ..
            }
        ),
        "{outcome:?}"
    );
    closed(&member, "a refused filing closes the session").await;
    assert_eq!(member.next_sender_seq(), 2, "nothing spent");
    closed(&venue, "the venue sees the transport close").await;
    assert!(
        venue_rx.try_recv().is_err(),
        "the venue read no application message"
    );
    assert_eq!(venue.next_target_seq(), 2);
}

/// Under `Continue` a refused filing does not stop the frame: it is `Sent`
/// with `filed` false. The store does not hold it, so a `ResendRequest` for
/// it is answered with a gap fill, not a replay.
#[tokio::test]
async fn test_store_refusal_under_continue_is_sent_unfiled_and_gap_filled() {
    let store = Arc::new(RefusingStore::new());
    let (app, _rx) = GateApp::new();
    let initiator = Initiator::new(member_config(), app)
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>)
        .with_store_failure_policy(StoreFailurePolicy::Continue);
    let (member, mut venue, _logon) = scripted(&initiator, PIPE_CAPACITY, ACK).await;
    store.refuse.store(true, Ordering::SeqCst);

    let outcome = member.send_tracked(order("UNFILED-1")).await;
    let (seq, _, filed) = sent(&outcome);
    assert_eq!(seq, 2, "Continue writes the frame anyway");
    assert!(!filed, "but the store did not file it");
    assert_eq!(header(&next_frame(&mut venue).await), ("D".to_string(), 2));
    assert!(
        !holds(store.as_ref(), 2).await,
        "the frame is not in the store"
    );

    venue_send(&mut venue, venue_msg("2", 2, &[(7, "2"), (16, "0")])).await;
    let answer = next_frame(&mut venue).await;
    assert_eq!(header(&answer), ("4".to_string(), 2), "a gap fill at 2");
    assert_eq!(field(&answer, 123).as_deref(), Some("Y"));
    assert_eq!(field(&answer, 36).as_deref(), Some("3"));
    drop(venue);
    closed(&member, "the session closes once the venue is gone").await;
}

/// A sender counter at `u64::MAX` leaves no number for the next frame: it is
/// `NotSent` with `SequenceExhausted`, and the session closes rather than
/// wrap the counter.
#[tokio::test]
async fn test_exhausted_sender_counter_is_not_sent() {
    let (app, _rx) = GateApp::new();
    let initiator = Initiator::new(member_config(), app).with_initial_sequences(u64::MAX - 1, 1);
    let (member, _venue, logon) = scripted(&initiator, PIPE_CAPACITY, ACK).await;
    assert_eq!(
        header(&logon).1,
        u64::MAX - 1,
        "the Logon took the last number but one"
    );

    let outcome = member.send_tracked(order("LAST-1")).await;
    assert_eq!(not_sent(&outcome), &NotSentReason::SequenceExhausted);
    closed(&member, "an exhausted counter closes the session").await;
    assert_eq!(member.next_sender_seq(), u64::MAX, "nothing wrapped");
}

/// A message queued behind the consumer's Logout reports `LogoutPending`; one
/// queued before it is sent first; and once the session is closed a tracked
/// send reports `SessionClosed`, and returns rather than wait.
#[tokio::test]
async fn test_logout_pending_and_session_closed() {
    let (app, _rx) = GateApp::new();
    let initiator = Initiator::new(member_config(), app);
    let (member, mut venue, _logon) = scripted(&initiator, PIPE_CAPACITY, ACK).await;

    let before = member.send_tracked(order("BEFORE-1")).await;
    assert_eq!(sent(&before).0, 2);
    ok(member.logout().await, "the member logs out");
    let after = member.send_tracked(order("AFTER-1")).await;
    assert_eq!(not_sent(&after), &NotSentReason::LogoutPending);

    assert_eq!(header(&next_frame(&mut venue).await), ("D".to_string(), 2));
    assert_eq!(header(&next_frame(&mut venue).await), ("5".to_string(), 3));
    venue_send(&mut venue, venue_msg("5", 2, &[])).await;
    closed(&member, "the Logout exchange closes the session").await;
    assert_eq!(
        member.next_sender_seq(),
        4,
        "the Logout was the last number spent"
    );

    let late = ok(
        timeout(STEP, member.send_tracked(order("LATE-1"))).await,
        "a send on a closed session returns at once",
    );
    assert!(
        matches!(not_sent(&late), NotSentReason::SessionClosed { .. }),
        "{late:?}"
    );
    assert!(
        member.send(order("LATE-2")).await.is_err(),
        "send is unchanged"
    );
}

/// The transport dies with the outbound queue full. The reactor is parked in
/// `to_app_checked` on the first message while four more fill the queue and
/// a fifth waits for room; the transport is killed, then the reactor goes on.
///
/// The session writes through a buffer and spends a number when a frame is
/// buffered, so which messages got a number before the reactor saw the dead
/// stream depends on scheduling (a write-through can find the task's
/// cooperative budget spent). What does not depend on it: the first message
/// was buffered and reports `Unknown` with the first number; every message
/// that got a number reports `Unknown` with `Transport`, the numbers in
/// order and without a hole; every other one reports `NotSent` (`Discarded`,
/// or `SessionClosed` for one that never got into the queue); nothing
/// reports `Sent`, nothing stays pending, and `next_sender_seq` counts
/// exactly the numbers the `Unknown` outcomes report.
#[tokio::test]
async fn test_kill_with_a_full_outbound_queue_resolves_every_message() {
    let (app, _rx) = GateApp::new();
    let initiator = Initiator::new(member_config(), Arc::clone(&app)).with_outbound_capacity(4);
    let (member, venue, _logon) = scripted(&initiator, PIPE_CAPACITY, ACK).await;

    // The first message parks the reactor in to_app_checked.
    let in_flight = track(&member, "GATE");
    ok(
        timeout(STEP, app.entered.notified()).await,
        "the gated message reaches to_app_checked",
    );
    // Four fill the queue; the fifth waits for room.
    let mut queued: Vec<_> = ["Q-1", "Q-2", "Q-3", "Q-4"]
        .into_iter()
        .map(|id| track(&member, id))
        .collect();
    tokio::time::sleep(QUIET).await;
    let waiting = track(&member, "WAITING-1");
    tokio::time::sleep(QUIET).await;
    assert!(!waiting.is_finished(), "the queue is full");
    queued.push(waiting);

    // Kill the transport, then let the reactor go on.
    drop(venue);
    app.release.notify_one();

    let outcome = joined(in_flight, "the in-flight outcome resolves").await;
    assert_eq!(
        unknown(&outcome),
        (2, UnknownReason::Transport),
        "buffered, so its number is spent"
    );
    let mut spent = vec![2];
    for task in queued {
        let outcome = joined(task, "a queued outcome resolves").await;
        match &outcome {
            SendOutcome::Unknown { seq, reason, .. } => {
                assert_eq!(*reason, UnknownReason::Transport);
                spent.push(*seq);
            }
            SendOutcome::NotSent { reason, .. } => assert!(
                matches!(
                    reason,
                    NotSentReason::Discarded { .. } | NotSentReason::SessionClosed { .. }
                ),
                "{outcome:?}"
            ),
            other => panic!("nothing is sent over a dead transport: {other:?}"),
        }
    }
    closed(&member, "the dead transport closes the session").await;
    let expected: Vec<u64> = (2..).take(spent.len()).collect();
    assert_eq!(spent, expected, "numbers spent in order, without a hole");
    assert_eq!(
        member.next_sender_seq(),
        2 + u64::try_from(spent.len()).unwrap_or(u64::MAX),
        "a number is spent exactly for each frame buffered, every one reported Unknown"
    );
}

/// Sends a large tracked order on `member` and polls it for [`QUIET`]: long
/// enough to queue it and have it buffered, not long enough for a small pipe
/// nobody reads to take it. Returns the still pending future.
async fn buffered_order(
    member: &Connection,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = SendOutcome> + Send + '_>> {
    let mut tracked = Box::pin(member.send_tracked(large_order("CLOSING-1", 16 * 1024)));
    tokio::select! {
        outcome = &mut tracked => panic!("not flushed, so not resolved: {outcome:?}"),
        () = tokio::time::sleep(QUIET) => {}
    }
    tracked
}

/// The counterparty logs out while a tracked frame is still in the write
/// buffer. The reply goes in behind it, the session closes, and its last
/// flush drains the buffer as the counterparty reads: the frame reports
/// `Sent`, resolved before `wait_closed` returns.
#[tokio::test]
async fn test_frame_flushed_by_the_closing_flush_is_sent() {
    let (app, _rx) = GateApp::new();
    let initiator = Initiator::new(member_config(), app);
    let (member, mut venue, _logon) = scripted(&initiator, SMALL_PIPE, ACK).await;

    let tracked = buffered_order(&member).await;
    venue_send(&mut venue, venue_msg("5", 2, &[])).await;
    assert_eq!(header(&next_frame(&mut venue).await), ("D".to_string(), 2));
    assert_eq!(header(&next_frame(&mut venue).await), ("5".to_string(), 3));
    closed(&member, "the Logout exchange closes the session").await;

    let outcome = some(
        tracked.now_or_never(),
        "the outcome resolved before wait_closed returned",
    );
    assert_eq!(sent(&outcome).0, 2, "the closing flush wrote it");
}

/// The session closes while a tracked frame is still in the write buffer,
/// and the counterparty never reads it: the frame reports `Unknown` with
/// `WriteTimeout` and the number it spent when it was buffered, resolved
/// before `wait_closed` returns.
#[tokio::test]
async fn test_frame_the_closing_flush_cannot_write_is_unknown() {
    let (app, _rx) = GateApp::new();
    // Long enough that the counterparty's Logout is read before the open
    // session's write timeout runs out: the close, and its last flush, is
    // what gives up on the frame.
    let initiator = Initiator::new(member_config(), app).with_write_timeout(Duration::from_secs(1));
    let (member, mut venue, _logon) = scripted(&initiator, SMALL_PIPE, ACK).await;

    let tracked = buffered_order(&member).await;
    venue_send(&mut venue, venue_msg("5", 2, &[])).await;
    closed(&member, "the session closes").await;

    let outcome = some(
        tracked.now_or_never(),
        "the outcome resolved before wait_closed returned",
    );
    assert_eq!(unknown(&outcome), (2, UnknownReason::WriteTimeout));
    assert_eq!(
        member.next_sender_seq(),
        4,
        "the order and the Logout reply behind it, both spent when buffered"
    );
    drop(venue);
}

/// This session's Logout with the outbound queue full. The messages ahead of
/// the Logout are `Sent`; the ones behind it that the reactor reaches while
/// the Logout is pending are `LogoutPending`; the ones still queued when the
/// acknowledgement closes the session are `Discarded`. Only the frames ahead
/// of the Logout and the Logout itself spend numbers.
#[tokio::test]
async fn test_logout_with_a_full_outbound_queue_resolves_every_message() {
    let (app, _rx) = GateApp::new();
    let initiator = Initiator::new(member_config(), Arc::clone(&app)).with_outbound_capacity(4);
    let (member, mut venue, _logon) = scripted(&initiator, PIPE_CAPACITY, ACK).await;

    // Park the reactor, then fill the queue: two orders, the Logout, one
    // order behind it; one more waits for room.
    let gated = track(&member, "GATE");
    ok(
        timeout(STEP, app.entered.notified()).await,
        "the gated message reaches to_app_checked",
    );
    let ahead: Vec<_> = ["AHEAD-1", "AHEAD-2"]
        .into_iter()
        .map(|id| track(&member, id))
        .collect();
    tokio::time::sleep(QUIET).await;
    let logout = {
        let member = member.clone();
        tokio::spawn(async move { member.logout().await })
    };
    tokio::time::sleep(QUIET).await;
    let behind = vec![track(&member, "BEHIND-1")];
    tokio::time::sleep(QUIET).await;
    let waiting = track(&member, "BEHIND-2");
    tokio::time::sleep(QUIET).await;
    assert!(!waiting.is_finished(), "the queue is full");

    app.release.notify_one();
    assert_eq!(
        sent(&joined(gated, "the gated outcome resolves").await).0,
        2
    );
    for (task, seq) in ahead.into_iter().zip([3, 4]) {
        assert_eq!(
            sent(&joined(task, "an outcome ahead resolves").await).0,
            seq
        );
    }
    ok(joined(logout, "the logout is queued").await, "logout");
    for task in behind.into_iter().chain([waiting]) {
        let outcome = joined(task, "an outcome behind resolves").await;
        assert_eq!(not_sent(&outcome), &NotSentReason::LogoutPending);
    }
    for seq in 2..=4 {
        assert_eq!(
            header(&next_frame(&mut venue).await),
            ("D".to_string(), seq)
        );
    }
    assert_eq!(header(&next_frame(&mut venue).await), ("5".to_string(), 5));

    // The acknowledgement parks the reactor in from_admin while two more
    // messages queue; they are still queued when the session closes.
    app.park_logout.store(true, Ordering::SeqCst);
    venue_send(&mut venue, venue_msg("5", 2, &[])).await;
    ok(
        timeout(STEP, app.logout_entered.notified()).await,
        "the acknowledgement reaches from_admin",
    );
    let late: Vec<_> = ["LATE-1", "LATE-2"]
        .into_iter()
        .map(|id| track(&member, id))
        .collect();
    tokio::time::sleep(QUIET).await;
    app.logout_release.notify_one();
    for task in late {
        assert_discarded(&joined(task, "a late outcome resolves").await);
    }
    closed(&member, "the Logout exchange closes the session").await;
    assert_eq!(
        member.next_sender_seq(),
        6,
        "numbers spent for the three orders and the Logout only: nothing behind \
         the Logout was buffered"
    );
}

/// The counterparty's Logout with the outbound queue full: the reactor
/// replies and closes, so every message still queued is `Discarded` and one
/// waiting for room is `SessionClosed`. Only the frame sent before and the
/// Logout reply spend numbers.
#[tokio::test]
async fn test_counterparty_logout_with_a_full_outbound_queue_resolves_every_message() {
    let (app, _rx) = GateApp::new();
    app.park_logout.store(true, Ordering::SeqCst);
    let initiator = Initiator::new(member_config(), Arc::clone(&app)).with_outbound_capacity(4);
    let (member, mut venue, _logon) = scripted(&initiator, PIPE_CAPACITY, ACK).await;

    let before = member.send_tracked(order("BEFORE-1")).await;
    assert_eq!(sent(&before).0, 2);
    assert_eq!(header(&next_frame(&mut venue).await), ("D".to_string(), 2));

    venue_send(&mut venue, venue_msg("5", 2, &[(58, "end of day")])).await;
    ok(
        timeout(STEP, app.logout_entered.notified()).await,
        "the counterparty's Logout reaches from_admin",
    );
    let queued: Vec<_> = ["Q-1", "Q-2", "Q-3", "Q-4"]
        .into_iter()
        .map(|id| track(&member, id))
        .collect();
    tokio::time::sleep(QUIET).await;
    let waiting = track(&member, "WAITING-1");
    tokio::time::sleep(QUIET).await;
    assert!(!waiting.is_finished(), "the queue is full");

    app.logout_release.notify_one();
    for task in queued {
        assert_discarded(&joined(task, "a queued outcome resolves").await);
    }
    let outcome = joined(waiting, "the waiting outcome resolves").await;
    assert!(
        matches!(not_sent(&outcome), NotSentReason::SessionClosed { .. }),
        "{outcome:?}"
    );
    assert_eq!(header(&next_frame(&mut venue).await), ("5".to_string(), 3));
    closed(&member, "the Logout exchange closes the session").await;
    assert_eq!(
        member.next_sender_seq(),
        4,
        "numbers spent for the order and the Logout reply only: nothing queued \
         was buffered"
    );
}

/// Files `count` orders of `size` bytes each under 2..=count+1, as a previous
/// session would have, and sets the next sender number past them.
async fn previous_orders(store: &MemoryStore, count: u64, size: usize) -> u64 {
    let filler = "F".repeat(size);
    for seq in 2..=count + 1 {
        let id = format!("OLD-{seq}");
        let frame = frame_from("CLIENT", "VENUE", "D", seq, &[(11, &id), (58, &filler)]);
        ok(
            store.store(seq, &MsgType::NewOrderSingle, &frame).await,
            "seed a filed order",
        );
    }
    let next = count + 2;
    ok(
        store.set_next_sender_seq(next).await,
        "seed the sender counter",
    );
    next
}

/// Reads the first replayed frame of a resend that has just started, so the
/// resend is known to be under way; the venue then stops reading and the
/// remaining replayed frames fill the pipe.
async fn first_replay(venue: &mut VenueFramed) {
    let first = next_frame(venue).await;
    assert_eq!(header(&first), ("D".to_string(), 2));
    assert_eq!(field(&first, 43).as_deref(), Some("Y"), "a replay");
}

/// Starts a resend the member owes the scripted venue and blocks it: the
/// venue asks for everything from 2, reads the first replayed frame, then
/// stops reading.
async fn blocked_resend(venue: &mut VenueFramed) {
    venue_send(venue, venue_msg("2", 2, &[(7, "2"), (16, "0")])).await;
    first_replay(venue).await;
}

/// Reads frames until the fresh (not possible-duplicate) order `id`,
/// returning `(MsgType, MsgSeqNum, PossDupFlag)` for every frame read.
async fn frames_until(venue: &mut VenueFramed, id: &str) -> Vec<(String, u64, bool)> {
    let mut seen = Vec::new();
    loop {
        let frame = next_frame(venue).await;
        let (msg_type, seq) = header(&frame);
        let poss_dup = field(&frame, 43).as_deref() == Some("Y");
        seen.push((msg_type.clone(), seq, poss_dup));
        if msg_type == "D" && !poss_dup && field(&frame, 11).as_deref() == Some(id) {
            return seen;
        }
    }
}

/// Tracked sends queued while a resend is under way wait behind it, and
/// report `Sent` with fresh numbers once the resend is written.
#[tokio::test]
async fn test_tracked_sends_held_behind_a_resend_report_after_it() {
    let store = Arc::new(MemoryStore::new());
    let logon_seq = previous_orders(&store, RESEND_ORDERS, 2048).await;
    let (app, _rx) = GateApp::new();
    let initiator = Initiator::new(member_config(), app)
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let (member, mut venue, logon) = scripted(&initiator, SMALL_PIPE, ACK).await;
    assert_eq!(header(&logon).1, logon_seq);

    blocked_resend(&mut venue).await;
    let held: Vec<_> = ["HELD-1", "HELD-2"]
        .into_iter()
        .map(|id| track(&member, id))
        .collect();
    tokio::time::sleep(QUIET).await;
    assert!(
        held.iter().all(|task| !task.is_finished()),
        "nothing that takes a new number is written in the middle of a resend"
    );

    // The venue reads again: the rest of the replay, the gap fill over the
    // Logon, then the held messages with fresh numbers.
    let mut expected: Vec<_> = (3..logon_seq)
        .map(|seq| ("D".to_string(), seq, true))
        .collect();
    expected.push(("4".to_string(), logon_seq, true));
    expected.push(("D".to_string(), logon_seq + 1, false));
    expected.push(("D".to_string(), logon_seq + 2, false));
    assert_eq!(frames_until(&mut venue, "HELD-2").await, expected);

    for (task, seq) in held.into_iter().zip([logon_seq + 1, logon_seq + 2]) {
        let outcome = joined(task, "a held outcome resolves").await;
        assert_eq!(sent(&outcome).0, seq);
        assert!(sent(&outcome).2, "filed");
    }
    drop(venue);
    closed(&member, "the session closes once the venue is gone").await;
}

/// The session ends while tracked sends wait behind a resend: they report
/// `DiscardedBehindResend` and spend nothing.
#[tokio::test]
async fn test_tracked_sends_held_behind_a_resend_are_discarded_when_the_session_ends() {
    let store = Arc::new(MemoryStore::new());
    let logon_seq = previous_orders(&store, RESEND_ORDERS, 2048).await;
    let (app, _rx) = GateApp::new();
    let initiator = Initiator::new(member_config(), app)
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let (member, mut venue, _logon) = scripted(&initiator, SMALL_PIPE, ACK).await;

    blocked_resend(&mut venue).await;
    let held: Vec<_> = ["HELD-1", "HELD-2"]
        .into_iter()
        .map(|id| track(&member, id))
        .collect();
    tokio::time::sleep(QUIET).await;
    assert!(held.iter().all(|task| !task.is_finished()));

    drop(venue);
    for task in held {
        let outcome = joined(task, "a held outcome resolves").await;
        assert!(
            matches!(
                not_sent(&outcome),
                NotSentReason::DiscardedBehindResend { .. }
            ),
            "{outcome:?}"
        );
    }
    closed(&member, "the dead transport closes the session").await;
    assert_eq!(
        member.next_sender_seq(),
        logon_seq + 1,
        "no number spent past the Logon"
    );
}

/// This session's Logout went out, then the counterparty asked for a resend,
/// which is still answered; the session ends while a tracked send waits
/// behind it. The message is behind the Logout as well, and that is what it
/// reports: `LogoutPending`, not `DiscardedBehindResend`.
#[tokio::test]
async fn test_message_behind_our_logout_and_a_resend_reports_logout_pending() {
    let store = Arc::new(MemoryStore::new());
    let logon_seq = previous_orders(&store, RESEND_ORDERS, 2048).await;
    let (app, _rx) = GateApp::new();
    let initiator = Initiator::new(member_config(), app)
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let (member, mut venue, _logon) = scripted(&initiator, SMALL_PIPE, ACK).await;

    ok(member.logout().await, "the member logs out");
    let logout = next_frame(&mut venue).await;
    assert_eq!(header(&logout), ("5".to_string(), logon_seq + 1));

    blocked_resend(&mut venue).await;
    let held = track(&member, "HELD-1");
    tokio::time::sleep(QUIET).await;
    assert!(!held.is_finished(), "held behind the resend");

    drop(venue);
    let outcome = joined(held, "the held outcome resolves").await;
    assert_eq!(not_sent(&outcome), &NotSentReason::LogoutPending);
    closed(&member, "the dead transport closes the session").await;
    assert_eq!(
        member.next_sender_seq(),
        logon_seq + 2,
        "the Logon and the Logout, nothing else"
    );
}

/// The gate runs when a message is written, not when it is queued: a gate
/// closed while a message waits behind a resend still stops it, and it
/// spends nothing.
#[tokio::test]
async fn test_gate_closed_while_a_message_waits_behind_a_resend_still_stops_it() {
    let store = Arc::new(MemoryStore::new());
    let logon_seq = previous_orders(&store, RESEND_ORDERS, 2048).await;
    let (app, _rx) = GateApp::new();
    let initiator = Initiator::new(member_config(), Arc::clone(&app))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let (member, mut venue, _logon) = scripted(&initiator, SMALL_PIPE, ACK).await;

    blocked_resend(&mut venue).await;
    let held = track(&member, "HELD-1");
    tokio::time::sleep(QUIET).await;
    assert!(!held.is_finished(), "held behind the resend");

    // The kill switch flips while the message waits.
    app.veto_all.store(true, Ordering::SeqCst);
    let gap_fill = frame_of_type(&mut venue, "4").await;
    assert_eq!(header(&gap_fill).1, logon_seq, "the resend ends");
    let outcome = joined(held, "the held outcome resolves").await;
    assert!(
        matches!(not_sent(&outcome), NotSentReason::Vetoed { .. }),
        "{outcome:?}"
    );
    assert_silent(&mut venue, "the vetoed order never reaches the wire").await;
    assert_eq!(
        member.next_sender_seq(),
        logon_seq + 1,
        "the veto spent nothing"
    );
    drop(venue);
    closed(&member, "the session closes once the venue is gone").await;
}

/// Tracked sends wait behind the resend a counterparty's
/// `NextExpectedMsgSeqNum` (789) asks for, and report `Sent` once it is
/// written.
#[tokio::test]
async fn test_tracked_sends_held_behind_a_789_resend_report_after_it() {
    let store = Arc::new(MemoryStore::new());
    let logon_seq = previous_orders(&store, RESEND_ORDERS, 2048).await;
    let (app, _rx) = GateApp::new();
    let initiator = Initiator::new(
        member_config().with_send_next_expected_msg_seq_num(true),
        app,
    )
    .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    // The venue says it expects 2: the member resends 2 up to its Logon.
    let (member, mut venue, logon) = scripted(
        &initiator,
        SMALL_PIPE,
        &[(98, "0"), (108, "30"), (789, "2")],
    )
    .await;
    assert_eq!(header(&logon).1, logon_seq);

    first_replay(&mut venue).await;
    let held: Vec<_> = ["HELD-1", "HELD-2"]
        .into_iter()
        .map(|id| track(&member, id))
        .collect();
    tokio::time::sleep(QUIET).await;
    assert!(
        held.iter().all(|task| !task.is_finished()),
        "held behind the 789 resend"
    );

    let mut expected: Vec<_> = (3..logon_seq)
        .map(|seq| ("D".to_string(), seq, true))
        .collect();
    expected.push(("D".to_string(), logon_seq + 1, false));
    expected.push(("D".to_string(), logon_seq + 2, false));
    assert_eq!(
        frames_until(&mut venue, "HELD-2").await,
        expected,
        "the replay stops before the Logon; the held messages follow it"
    );
    for (task, seq) in held.into_iter().zip([logon_seq + 1, logon_seq + 2]) {
        assert_eq!(sent(&joined(task, "a held outcome resolves").await).0, seq);
    }
    drop(venue);
    closed(&member, "the session closes once the venue is gone").await;
}

/// Administrative messages cannot be vetoed. With a gate that vetoes every
/// application message, the session still sends its Logon, a Heartbeat
/// answering a TestRequest, a Reject, a SequenceReset-GapFill answering a
/// ResendRequest, an idle Heartbeat and a TestRequest, its own
/// ResendRequest, and its Logout: all of them through `to_admin`, none
/// through `to_app_checked`.
#[tokio::test]
async fn test_admin_messages_cannot_be_vetoed() {
    let (app, _rx) = GateApp::new();
    app.veto_all.store(true, Ordering::SeqCst);
    let initiator = Initiator::new(
        member_config().with_heartbeat_interval(Duration::from_secs(1)),
        Arc::clone(&app),
    );
    let (member, mut venue, _logon) =
        scripted(&initiator, PIPE_CAPACITY, &[(98, "0"), (108, "1")]).await;

    let vetoed = member.send_tracked(order("ANY-1")).await;
    assert!(matches!(not_sent(&vetoed), NotSentReason::Vetoed { .. }));

    venue_send(&mut venue, venue_msg("1", 2, &[(112, "PING")])).await;
    let _reply = frame_where(&mut venue, |frame| {
        field(frame, 35).as_deref() == Some("0") && field(frame, 112).as_deref() == Some("PING")
    })
    .await;

    venue_send(&mut venue, venue_msg("0", 3, &[(58, "REJECT ME")])).await;
    let reject = frame_of_type(&mut venue, "3").await;
    assert_eq!(field(&reject, 45).as_deref(), Some("3"));

    venue_send(&mut venue, venue_msg("2", 4, &[(7, "1"), (16, "0")])).await;
    let gap_fill = frame_of_type(&mut venue, "4").await;
    assert_eq!(field(&gap_fill, 123).as_deref(), Some("Y"));

    // Silence: an idle Heartbeat, then a TestRequest, which is answered.
    let probe = frame_of_type(&mut venue, "1").await;
    let probe_id = some(field(&probe, 112), "a TestRequest carries TestReqID");
    venue_send(&mut venue, venue_msg("0", 5, &[(112, &probe_id)])).await;

    // A gap makes the member ask for a resend.
    venue_send(&mut venue, venue_msg("D", 10, &[(11, "GAPPED")])).await;
    let request = frame_of_type(&mut venue, "2").await;
    assert_eq!(field(&request, 7).as_deref(), Some("6"));

    ok(member.logout().await, "the member logs out");
    let _logout = frame_of_type(&mut venue, "5").await;
    drop(venue);
    closed(&member, "the session closes").await;

    assert_eq!(
        app.app_checked_seen(),
        ["D"],
        "only the application message reached the gate"
    );
    let admin = app.admin_seen();
    for msg_type in ["A", "0", "1", "2", "3", "4", "5"] {
        assert!(
            admin.iter().any(|seen| seen == msg_type),
            "{msg_type} went through to_admin: {admin:?}"
        );
    }
}

/// An application written before `to_app_checked` existed, overriding only
/// `to_app`, behaves exactly as before: its mutation reaches the wire on both
/// send paths, and numbering is unchanged.
#[tokio::test]
async fn test_application_overriding_only_to_app_behaves_as_before() {
    let (venue_app, mut venue_rx) = GateApp::new();
    let (member, venue) = engines(
        Initiator::new(member_config(), Arc::new(StampingApp)),
        Acceptor::new(venue_config(), venue_app),
    )
    .await;

    ok(member.send(order("PLAIN-1")).await, "a plain send");
    let plain = received(&mut venue_rx).await;
    assert_eq!(
        (plain.seq, plain.account.as_deref()),
        (Some(2), Some("ACC-1"))
    );

    let tracked = member.send_tracked(order("TRACKED-1")).await;
    assert_eq!(sent(&tracked).0, 3);
    let seen = received(&mut venue_rx).await;
    assert_eq!(
        (seen.seq, seen.account.as_deref()),
        (Some(3), Some("ACC-1"))
    );

    log_out(&member, &venue).await;
}
