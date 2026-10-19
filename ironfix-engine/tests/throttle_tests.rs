/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 19/10/26
******************************************************************************/

//! Integration tests for issue #82: the optional per-session outbound
//! throttle (`with_throttle`, `ironfix_engine::throttle`).
//!
//! Every test runs on a **paused** Tokio clock (`start_paused = true`): the
//! reactor reads the throttle's time from Tokio's clock, so a token earned
//! one second later is earned one virtual second later, the runtime jumping
//! there as soon as every task is idle, and the timings asserted here are
//! exact. The session under test runs over a `tokio::io::duplex` pipe against
//! a scripted counterparty (`Framed<DuplexStream, FixCodec>`), in the role
//! the test names: the counterparty is a venue for an `Initiator`, a member
//! for an `Acceptor`.
//!
//! Covered, in both roles unless stated: messages above the rate are held
//! and released in order, one per token, under `Queue`, and refused under
//! `Refuse`; a tracked send reports `Sent` once released, or `NotSent` with
//! `Throttled`; two budgets are independent; administrative messages (the
//! Heartbeat answering a TestRequest, a gap fill, the Logout) and resends are
//! never throttled, and a message held by the throttle waits behind a resend
//! like a new one; a Logout or a kill with the throttle queue and the
//! outbound queue both full resolves every held message `NotSent`, the
//! Logout going out at once with no application frame after it; a partial
//! write of a released message is `Unknown` and the rest of the queue
//! `NotSent` (initiator); a veto gives the token back (initiator); a session
//! an `AcceptorRegistry` routes keeps its `Acceptor`'s throttle; and the
//! inbound application count.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::application::{Application, RejectReason, SendVerdict, SessionId};
use ironfix_engine::throttle::{
    BudgetId, ThrottleBudget, ThrottleConfig, ThrottleConfigBuilder, ThrottlePolicy,
};
use ironfix_engine::{
    Acceptor, AcceptorRegistry, Connection, Initiator, NotSentReason, OutboundMessage, SendOutcome,
    UnknownReason,
};
use ironfix_session::SessionConfig;
use ironfix_store::{MemoryStore, MessageStore};
use ironfix_tagvalue::{Decoder, Encoder};
use ironfix_transport::FixCodec;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};
use tokio_util::codec::Framed;

/// Capacity of each direction of a roomy test pipe, in bytes.
const PIPE_CAPACITY: usize = 64 * 1024;

/// Capacity of a pipe meant to fill up, in bytes: a Logon fits, a resend of
/// many large orders does not.
const SMALL_PIPE: usize = 1024;

/// How long a test waits for any one step before failing (virtual time).
const STEP: Duration = Duration::from_secs(5);

/// How long a test waits to show that something has **not** happened.
const QUIET: Duration = Duration::from_millis(300);

/// One second.
const SECOND: Duration = Duration::from_secs(1);

/// A window long enough that no token is earned during a test.
const HOUR: Duration = Duration::from_secs(3_600);

/// How late after its token a held message may be released: the timer
/// fires on the millisecond, and nothing else waits.
const RELEASE_SLACK: Duration = Duration::from_millis(50);

/// Orders a resend test files, 2 KiB each: far more than [`SMALL_PIPE`], so
/// the resend is still under way while the counterparty does not read.
const RESEND_ORDERS: u64 = 100;

/// The body of a Logon and of its acknowledgement.
const LOGON_BODY: &[(u32, &str)] = &[(98, "0"), (108, "30")];

/// The budget a classifier puts a message whose ClOrdID (11) is `GATE` in.
const GATE_BUDGET: BudgetId = BudgetId::new(1);

/// The scripted counterparty's end of a pipe.
type PeerFramed = Framed<DuplexStream, FixCodec>;

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

/// Builds a throttle configuration, failing the test with the error.
#[track_caller]
fn throttle(builder: ThrottleConfigBuilder) -> ThrottleConfig {
    ok(builder.build(), "the test throttle builds")
}

/// One budget of `rate` messages per `per`, with the default burst (1) and
/// policy (a queue).
fn one_budget(rate: u32, per: Duration) -> ThrottleConfig {
    throttle(ThrottleConfig::builder(ThrottleBudget::new(rate, per)))
}

/// The ClOrdID (11) of an outbound message, or an empty string.
fn cl_ord_id(message: &OutboundMessage) -> String {
    message
        .get(11)
        .map(|id| String::from_utf8_lossy(id).into_owned())
        .unwrap_or_default()
}

/// The application under test: a gate in `to_app_checked`, which vetoes a
/// message whose ClOrdID starts with `VETO` and parks one whose ClOrdID is
/// `GATE` until released; it forwards the ClOrdID of every inbound
/// application message.
#[derive(Debug)]
struct ThrottleApp {
    entered: Notify,
    release: Notify,
    app_tx: mpsc::UnboundedSender<String>,
}

impl ThrottleApp {
    fn new() -> (Arc<Self>, mpsc::UnboundedReceiver<String>) {
        let (app_tx, app_rx) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                entered: Notify::new(),
                release: Notify::new(),
                app_tx,
            }),
            app_rx,
        )
    }
}

#[async_trait]
impl Application for ThrottleApp {
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
        let id = cl_ord_id(message);
        if id.starts_with("VETO") {
            return SendVerdict::ready(Err(RejectReason::new(7, "vetoed by the test gate")));
        }
        if id == "GATE" {
            // A decision that has to wait: the reactor awaits it inline.
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
        let id = message.get_field_str(11).unwrap_or_default().to_string();
        let _ = self.app_tx.send(id);
        Ok(())
    }
}

/// A NewOrderSingle with ClOrdID (11) `id`.
fn order(id: &str) -> OutboundMessage {
    order_of(id, 0)
}

/// A NewOrderSingle with ClOrdID (11) `id` and `size` bytes of Text (58).
fn order_of(id: &str, size: usize) -> OutboundMessage {
    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order
        .push_str(11, id)
        .push_str(55, "EUR/USD")
        .push_char(54, '1')
        .push_uint(38, 100);
    if size > 0 {
        order.push_str(58, &"X".repeat(size));
    }
    order
}

/// An OrderCancelRequest with ClOrdID (11) `id`.
fn cancel(id: &str) -> OutboundMessage {
    let mut cancel = OutboundMessage::new(MsgType::OrderCancelRequest);
    cancel
        .push_str(11, id)
        .push_str(41, "ORDER-1")
        .push_str(55, "EUR/USD")
        .push_char(54, '1');
    cancel
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
    ok(
        encoder.finish_into(&mut frame),
        "test fixture frame must encode",
    );
    frame
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
async fn next_frame(framed: &mut PeerFramed) -> BytesMut {
    let polled = ok(
        timeout(STEP, framed.next()).await,
        "a frame arrives within 5s",
    );
    ok(some(polled, "the stream stays open"), "the frame frames")
}

/// Reads frames until one of MsgType `msg_type` arrives, returning it.
async fn frame_of_type(framed: &mut PeerFramed, msg_type: &str) -> BytesMut {
    loop {
        let frame = next_frame(framed).await;
        if field(&frame, 35).as_deref() == Some(msg_type) {
            return frame;
        }
    }
}

/// Asserts that the counterparty reads nothing for [`QUIET`].
async fn assert_silent(framed: &mut PeerFramed, what: &str) {
    if let Ok(frame) = timeout(QUIET, framed.next()).await {
        panic!("{what}: read {frame:?}");
    }
}

/// Writes one frame from the scripted counterparty.
async fn peer_write(framed: &mut PeerFramed, frame: BytesMut) {
    ok(
        ok(
            timeout(STEP, framed.send(frame)).await,
            "the counterparty writes within 5s",
        ),
        "the counterparty writes",
    );
}

/// Awaits a spawned task within [`STEP`].
async fn joined<T>(task: JoinHandle<T>, what: &str) -> T {
    ok(ok(timeout(STEP, task).await, what), what)
}

/// Waits for `connection` to close within [`STEP`].
async fn closed(connection: &Connection, what: &str) {
    ok(timeout(STEP, connection.wait_closed()).await, what);
}

/// Hands `message` to `send_tracked` on a task of its own and lets that task
/// run until it is queued (or waits for room), so tasks queue in the order
/// they were started. No virtual time passes.
async fn track(connection: &Connection, message: OutboundMessage) -> JoinHandle<SendOutcome> {
    let connection = connection.clone();
    let task = tokio::spawn(async move { connection.send_tracked(message).await });
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    task
}

/// Awaits a tracked send's outcome.
async fn outcome(task: JoinHandle<SendOutcome>) -> SendOutcome {
    joined(task, "a tracked outcome resolves within 5s").await
}

/// The `MsgSeqNum` of a `Sent` outcome.
#[track_caller]
fn sent(outcome: &SendOutcome) -> u64 {
    match outcome {
        SendOutcome::Sent { seq, .. } => *seq,
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

/// Asserts a tracked send was refused by the throttle, by `budget`.
#[track_caller]
fn assert_throttled(outcome: &SendOutcome, budget: BudgetId) {
    match not_sent(outcome) {
        NotSentReason::Throttled {
            budget: refused, ..
        } => assert_eq!(*refused, budget),
        other => panic!("expected Throttled, got {other:?}"),
    }
    assert_eq!(outcome.seq(), None, "a refused message spends no number");
}

/// Asserts a tracked send was discarded from the throttle's queue.
#[track_caller]
fn assert_discarded_by_throttle(outcome: &SendOutcome, budget: BudgetId) {
    match not_sent(outcome) {
        NotSentReason::DiscardedByThrottle { budget: held, .. } => assert_eq!(*held, budget),
        other => panic!("expected DiscardedByThrottle, got {other:?}"),
    }
}

/// The role the engine under test plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// An `Initiator`; the scripted counterparty is a venue.
    Initiator,
    /// An `Acceptor`; the scripted counterparty is a member.
    Acceptor,
}

impl Role {
    /// The CompIDs of the session under test, as (its own, the
    /// counterparty's).
    const fn comp_ids(self) -> (&'static str, &'static str) {
        match self {
            Self::Initiator => ("CLIENT", "VENUE"),
            Self::Acceptor => ("VENUE", "CLIENT"),
        }
    }
}

/// The scripted counterparty.
struct Peer {
    framed: PeerFramed,
    /// Its own CompID.
    me: &'static str,
    /// The session's CompID.
    them: &'static str,
    /// The `MsgSeqNum` of its next frame.
    next_seq: u64,
}

impl Peer {
    /// Sends the next frame of the counterparty's stream.
    async fn send(&mut self, msg_type: &str, extra: &[(u32, &str)]) {
        let frame = frame_from(self.me, self.them, msg_type, self.next_seq, extra);
        self.next_seq += 1;
        peer_write(&mut self.framed, frame).await;
    }
}

/// How the engine under test is set up.
struct Setup {
    throttle: ThrottleConfig,
    store: Option<Arc<MemoryStore>>,
    pipe: usize,
    outbound_capacity: usize,
}

impl Setup {
    fn new(throttle: ThrottleConfig) -> Self {
        Self {
            throttle,
            store: None,
            pipe: PIPE_CAPACITY,
            outbound_capacity: 1024,
        }
    }
}

/// Starts the engine of `role` with `app` as `setup` says, against a scripted
/// counterparty. Returns the session, the counterparty just past the Logon
/// exchange, and the `MsgSeqNum` of the session's own Logon or
/// acknowledgement: its first application message takes the next one.
async fn start(role: Role, app: Arc<ThrottleApp>, setup: Setup) -> (Connection, Peer, u64) {
    let (engine_io, peer_io) = tokio::io::duplex(setup.pipe);
    let (own, counterparty) = role.comp_ids();
    match role {
        Role::Initiator => {
            let mut initiator = Initiator::new(member_config(), app)
                .with_throttle(setup.throttle)
                .with_outbound_capacity(setup.outbound_capacity);
            if let Some(store) = setup.store {
                initiator = initiator.with_store(store as Arc<dyn MessageStore>);
            }
            let venue = tokio::spawn(async move {
                let mut framed = Framed::new(peer_io, FixCodec::new());
                let logon = next_frame(&mut framed).await;
                assert_eq!(field(&logon, 35).as_deref(), Some("A"));
                peer_write(
                    &mut framed,
                    frame_from(counterparty, own, "A", 1, LOGON_BODY),
                )
                .await;
                (framed, header(&logon).1)
            });
            let connection = ok(
                initiator.establish(engine_io).await,
                "the initiator logs on over the pipe",
            );
            let (framed, logon_seq) = joined(venue, "the venue acknowledges the Logon").await;
            let peer = Peer {
                framed,
                me: counterparty,
                them: own,
                next_seq: 2,
            };
            (connection, peer, logon_seq)
        }
        Role::Acceptor => {
            let mut acceptor = Acceptor::new(venue_config(), app)
                .with_throttle(setup.throttle)
                .with_outbound_capacity(setup.outbound_capacity);
            if let Some(store) = setup.store {
                acceptor = acceptor.with_store(store as Arc<dyn MessageStore>);
            }
            let served = tokio::spawn(async move { acceptor.serve_stream(engine_io).await });
            let mut framed = Framed::new(peer_io, FixCodec::new());
            peer_write(
                &mut framed,
                frame_from(counterparty, own, "A", 1, LOGON_BODY),
            )
            .await;
            let ack = next_frame(&mut framed).await;
            assert_eq!(field(&ack, 35).as_deref(), Some("A"));
            let connection = ok(
                joined(served, "the acceptor handshake ends").await,
                "the acceptor logs on over the pipe",
            );
            let peer = Peer {
                framed,
                me: counterparty,
                them: own,
                next_seq: 2,
            };
            (connection, peer, header(&ack).1)
        }
    }
}

/// Logs the session out from its side and completes the exchange.
async fn log_out(connection: &Connection, peer: &mut Peer) {
    ok(connection.logout().await, "the logout is queued");
    let _ = frame_of_type(&mut peer.framed, "5").await;
    peer.send("5", &[]).await;
    closed(connection, "the Logout exchange closes the session").await;
}

/// Under `Queue`, messages above the rate are held and released one per
/// token, in order, each reporting `Sent` once released and not before.
async fn assert_queue_releases_in_order_at_the_rate(role: Role) {
    let (app, _rx) = ThrottleApp::new();
    let (connection, mut peer, handshake) =
        start(role, app, Setup::new(one_budget(1, SECOND))).await;
    let first = handshake + 1;

    let t0 = Instant::now();
    let mut tasks = Vec::new();
    for index in 0..4 {
        tasks.push(track(&connection, order(&format!("ORDER-{index}"))).await);
    }
    for (index, offset) in (0_u32..4).zip(0_u64..) {
        let frame = frame_of_type(&mut peer.framed, "D").await;
        let at = t0.elapsed();
        assert_eq!(
            header(&frame).1,
            first + offset,
            "{role:?}: numbered in order"
        );
        assert_eq!(
            field(&frame, 11),
            Some(format!("ORDER-{index}")),
            "{role:?}: no message overtakes an earlier one"
        );
        let earliest = SECOND * index;
        assert!(
            at >= earliest && at < earliest + RELEASE_SLACK,
            "{role:?}: message {index} left at {at:?}, its token was earned at {earliest:?}"
        );
        if let Some(next) = tasks.get(usize::try_from(index + 1).unwrap_or(usize::MAX)) {
            assert!(
                !next.is_finished(),
                "{role:?}: the next message is still held, so not resolved"
            );
        }
    }
    for (task, offset) in tasks.into_iter().zip(0_u64..) {
        assert_eq!(sent(&outcome(task).await), first + offset);
    }
    log_out(&connection, &mut peer).await;
}

#[tokio::test(start_paused = true)]
async fn test_queue_policy_releases_in_order_at_the_rate_on_the_initiator() {
    assert_queue_releases_in_order_at_the_rate(Role::Initiator).await;
}

#[tokio::test(start_paused = true)]
async fn test_queue_policy_releases_in_order_at_the_rate_on_the_acceptor() {
    assert_queue_releases_in_order_at_the_rate(Role::Acceptor).await;
}

/// How long `count` orders, queued at once, take to reach the counterparty
/// through a budget of `rate` per second with `burst`.
async fn drain_time(rate: u32, burst: u32, count: u64) -> Duration {
    let (app, _rx) = ThrottleApp::new();
    let config = throttle(ThrottleConfig::builder(
        ThrottleBudget::new(rate, SECOND).with_burst(burst),
    ));
    let (connection, mut peer, handshake) = start(Role::Initiator, app, Setup::new(config)).await;
    let first = handshake + 1;
    let t0 = Instant::now();
    for index in 0..count {
        ok(
            connection.send(order(&format!("FAST-{index}"))).await,
            "queued",
        );
    }
    for offset in 0..count {
        let frame = frame_of_type(&mut peer.framed, "D").await;
        assert_eq!(header(&frame).1, first + offset, "in order");
    }
    let took = t0.elapsed();
    log_out(&connection, &mut peer).await;
    took
}

/// A budget faster than one message per millisecond. The release timer has
/// Tokio's one-millisecond resolution, so it reaches its rate with a burst
/// of at least one millisecond's worth of tokens: a held message whose token
/// is already there is released without the timer. 100 messages at 10 000
/// per second with a burst of 10 take 9 ms (90 tokens to earn). With a burst
/// of 1 the bucket holds one token per wake-up, so the same 100 take 99 ms:
/// slower than the rate, never faster.
#[tokio::test(start_paused = true)]
async fn test_rate_above_one_message_per_millisecond_needs_a_burst_to_be_kept() {
    let slack = Duration::from_millis(2);
    let took = drain_time(10_000, 10, 100).await;
    let floor = Duration::from_micros(100) * 90;
    assert!(
        took >= floor && took < floor + slack,
        "100 messages at 10 000 per second with a burst of 10 took {took:?}"
    );

    let took = drain_time(10_000, 1, 100).await;
    let floor = Duration::from_millis(99);
    assert!(
        took >= floor && took < floor + slack,
        "100 messages at 10 000 per second with a burst of 1 took {took:?}: one per wake-up"
    );
}

/// Under `Refuse`, messages above the burst are refused at once, spend no
/// number and never reach the counterparty; once tokens are earned again,
/// the next message takes the next number.
async fn assert_refuse_policy_refuses_above_the_rate(role: Role) {
    let (app, _rx) = ThrottleApp::new();
    let budget = ThrottleBudget::new(2, SECOND)
        .with_burst(2)
        .with_policy(ThrottlePolicy::Refuse);
    let (connection, mut peer, handshake) = start(
        role,
        app,
        Setup::new(throttle(ThrottleConfig::builder(budget))),
    )
    .await;
    let first = handshake + 1;

    let mut tasks = Vec::new();
    for index in 0..5 {
        tasks.push(track(&connection, order(&format!("ORDER-{index}"))).await);
    }
    let mut outcomes = Vec::new();
    for task in tasks {
        outcomes.push(outcome(task).await);
    }
    assert_eq!(sent(&outcomes[0]), first);
    assert_eq!(sent(&outcomes[1]), first + 1);
    for refused in &outcomes[2..] {
        assert_throttled(refused, BudgetId::DEFAULT);
    }
    for offset in 0..2 {
        let frame = frame_of_type(&mut peer.framed, "D").await;
        assert_eq!(header(&frame).1, first + offset);
    }
    assert_silent(&mut peer.framed, "a refused message never reaches the wire").await;
    assert_eq!(
        connection.next_sender_seq(),
        first + 2,
        "{role:?}: nothing spent"
    );

    // A second later the budget is full again.
    tokio::time::sleep(SECOND).await;
    let later = outcome(track(&connection, order("LATER-1")).await).await;
    assert_eq!(
        sent(&later),
        first + 2,
        "{role:?}: no gap after the refusals"
    );
    let frame = frame_of_type(&mut peer.framed, "D").await;
    assert_eq!(header(&frame).1, first + 2);
    log_out(&connection, &mut peer).await;
}

#[tokio::test(start_paused = true)]
async fn test_refuse_policy_refuses_above_the_rate_on_the_initiator() {
    assert_refuse_policy_refuses_above_the_rate(Role::Initiator).await;
}

#[tokio::test(start_paused = true)]
async fn test_refuse_policy_refuses_above_the_rate_on_the_acceptor() {
    assert_refuse_policy_refuses_above_the_rate(Role::Acceptor).await;
}

/// New orders and cancels in separate budgets: an exhausted order budget,
/// with an order held in it, does not delay a cancel.
async fn assert_budgets_are_independent(role: Role) {
    let (app, _rx) = ThrottleApp::new();
    const CANCELS: BudgetId = BudgetId::new(1);
    let config = throttle(
        ThrottleConfig::builder(ThrottleBudget::new(1, HOUR))
            .budget(ThrottleBudget::new(10, SECOND).with_burst(10))
            .classifier(|message| match message.msg_type() {
                MsgType::OrderCancelRequest => CANCELS,
                _ => BudgetId::DEFAULT,
            }),
    );
    let (connection, mut peer, handshake) = start(role, app, Setup::new(config)).await;
    let first = handshake + 1;

    let sent_order = track(&connection, order("ORDER-1")).await;
    let held_order = track(&connection, order("ORDER-2")).await;
    let cancel_1 = track(&connection, cancel("CANCEL-1")).await;
    let cancel_2 = track(&connection, cancel("CANCEL-2")).await;
    assert_eq!(sent(&outcome(sent_order).await), first);
    assert_eq!(
        sent(&outcome(cancel_1).await),
        first + 1,
        "{role:?}: the cancel goes ahead of the order held in the other budget"
    );
    assert_eq!(sent(&outcome(cancel_2).await), first + 2);
    let wire: Vec<_> = [
        next_frame(&mut peer.framed).await,
        next_frame(&mut peer.framed).await,
        next_frame(&mut peer.framed).await,
    ]
    .iter()
    .map(|frame| (header(frame), field(frame, 11)))
    .collect();
    assert_eq!(
        wire,
        [
            (("D".to_string(), first), Some("ORDER-1".to_string())),
            (("F".to_string(), first + 1), Some("CANCEL-1".to_string())),
            (("F".to_string(), first + 2), Some("CANCEL-2".to_string())),
        ]
    );
    assert_silent(&mut peer.framed, "the second order waits for an hour").await;
    assert!(!held_order.is_finished());

    log_out(&connection, &mut peer).await;
    assert_discarded_by_throttle(&outcome(held_order).await, BudgetId::DEFAULT);
}

#[tokio::test(start_paused = true)]
async fn test_budgets_are_independent_on_the_initiator() {
    assert_budgets_are_independent(Role::Initiator).await;
}

#[tokio::test(start_paused = true)]
async fn test_budgets_are_independent_on_the_acceptor() {
    assert_budgets_are_independent(Role::Acceptor).await;
}

/// With the budget exhausted and a message held: a TestRequest is answered
/// at once with a Heartbeat echoing its TestReqID (112), a ResendRequest
/// with a gap fill, and the session's Logout goes out at once; none of them
/// takes a token, and the held message never goes out. Inbound application
/// messages are counted meanwhile.
async fn assert_admin_messages_are_never_throttled(role: Role) {
    let (app, mut app_rx) = ThrottleApp::new();
    let (connection, mut peer, handshake) = start(role, app, Setup::new(one_budget(1, HOUR))).await;
    let first = handshake + 1;

    assert_eq!(
        sent(&outcome(track(&connection, order("ORDER-1")).await).await),
        first
    );
    let held = track(&connection, order("ORDER-2")).await;
    let _ = frame_of_type(&mut peer.framed, "D").await;

    let asked = Instant::now();
    peer.send("1", &[(112, "PING-1")]).await;
    let heartbeat = next_frame(&mut peer.framed).await;
    assert_eq!(header(&heartbeat), ("0".to_string(), first + 1));
    assert_eq!(field(&heartbeat, 112).as_deref(), Some("PING-1"));
    assert!(
        asked.elapsed() < RELEASE_SLACK,
        "{role:?}: the TestRequest is answered at once while sends are throttled"
    );

    let begin = first.to_string();
    peer.send("2", &[(7, begin.as_str()), (16, "0")]).await;
    let fill = next_frame(&mut peer.framed).await;
    assert_eq!(header(&fill), ("4".to_string(), first));
    assert_eq!(field(&fill, 123).as_deref(), Some("Y"), "a gap fill");
    let end = (first + 2).to_string();
    assert_eq!(field(&fill, 36).as_deref(), Some(end.as_str()));

    // Inbound application messages are counted as the session reads them.
    peer.send("8", &[(11, "REPORT-1")]).await;
    peer.send("8", &[(11, "REPORT-2")]).await;
    for expected in ["REPORT-1", "REPORT-2"] {
        let id = some(
            ok(timeout(STEP, app_rx.recv()).await, "from_app runs"),
            "the application channel stays open",
        );
        assert_eq!(id, expected);
    }
    assert_eq!(connection.inbound_app_messages(), 2);

    assert!(!held.is_finished(), "{role:?}: still waiting for its token");
    let logout_at = Instant::now();
    ok(connection.logout().await, "the logout is queued");
    let logout = frame_of_type(&mut peer.framed, "5").await;
    assert_eq!(
        header(&logout).1,
        first + 2,
        "the held message took no number"
    );
    assert!(
        logout_at.elapsed() < RELEASE_SLACK,
        "{role:?}: the Logout goes out at once"
    );
    assert_discarded_by_throttle(&outcome(held).await, BudgetId::DEFAULT);
    assert_silent(&mut peer.framed, "no application frame after the Logout").await;
    peer.send("5", &[]).await;
    closed(&connection, "the Logout exchange closes the session").await;
}

#[tokio::test(start_paused = true)]
async fn test_admin_messages_are_never_throttled_on_the_initiator() {
    assert_admin_messages_are_never_throttled(Role::Initiator).await;
}

#[tokio::test(start_paused = true)]
async fn test_admin_messages_are_never_throttled_on_the_acceptor() {
    assert_admin_messages_are_never_throttled(Role::Acceptor).await;
}

/// Files `count` orders of `size` bytes each under 2..=count+1, from
/// `sender` to `target`, as a previous session would have, and sets the
/// next sender number past them. Returns that number.
async fn previous_orders(
    store: &MemoryStore,
    (sender, target): (&str, &str),
    count: u64,
    size: usize,
) -> u64 {
    let filler = "F".repeat(size);
    for seq in 2..=count + 1 {
        let id = format!("OLD-{seq}");
        let frame = frame_from(sender, target, "D", seq, &[(11, &id), (58, &filler)]);
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

/// A resend is never throttled, and a message the throttle holds waits
/// behind it like any new message: its token is earned while the resend is
/// under way, and it is released, with the next number, only once the
/// resend is written.
async fn assert_resend_is_not_throttled_and_held_messages_wait_behind_it(role: Role) {
    let store = Arc::new(MemoryStore::new());
    let handshake_seq = previous_orders(&store, role.comp_ids(), RESEND_ORDERS, 2048).await;
    let (app, _rx) = ThrottleApp::new();
    let setup = Setup {
        store: Some(Arc::clone(&store)),
        pipe: SMALL_PIPE,
        ..Setup::new(one_budget(1, SECOND))
    };
    let (connection, mut peer, handshake) = start(role, app, setup).await;
    assert_eq!(handshake, handshake_seq);
    let first = handshake + 1;

    assert_eq!(
        sent(&outcome(track(&connection, order("X-1")).await).await),
        first
    );
    let frame = frame_of_type(&mut peer.framed, "D").await;
    assert_eq!(header(&frame).1, first);
    let held = track(&connection, order("Y-1")).await;

    // The counterparty asks for everything from 2, reads the first replayed
    // frame, then stops reading for longer than the held message's token
    // takes.
    peer.send("2", &[(7, "2"), (16, "0")]).await;
    let replay = next_frame(&mut peer.framed).await;
    assert_eq!(header(&replay), ("D".to_string(), 2));
    assert_eq!(field(&replay, 43).as_deref(), Some("Y"));
    tokio::time::sleep(3 * SECOND).await;
    assert!(
        !held.is_finished(),
        "{role:?}: a token earned in the middle of a resend does not release a new number"
    );

    // The rest of the resend goes out without a token per frame, then the
    // held message with the next number.
    let resumed = Instant::now();
    let mut seen = Vec::new();
    loop {
        let frame = next_frame(&mut peer.framed).await;
        let (msg_type, seq) = header(&frame);
        let poss_dup = field(&frame, 43).as_deref() == Some("Y");
        let fresh_y = msg_type == "D" && !poss_dup && field(&frame, 11).as_deref() == Some("Y-1");
        seen.push((msg_type, seq, poss_dup));
        if fresh_y {
            break;
        }
    }
    let mut expected: Vec<_> = (3..handshake)
        .map(|seq| ("D".to_string(), seq, true))
        .collect();
    expected.push(("4".to_string(), handshake, true));
    expected.push(("D".to_string(), first, true));
    expected.push(("D".to_string(), first + 1, false));
    assert_eq!(seen, expected, "{role:?}");
    assert!(
        resumed.elapsed() < RELEASE_SLACK,
        "{role:?}: {} replayed frames took no token",
        RESEND_ORDERS
    );
    assert_eq!(sent(&outcome(held).await), first + 1);
    log_out(&connection, &mut peer).await;
}

#[tokio::test(start_paused = true)]
async fn test_resend_is_not_throttled_and_held_messages_wait_behind_it_on_the_initiator() {
    assert_resend_is_not_throttled_and_held_messages_wait_behind_it(Role::Initiator).await;
}

#[tokio::test(start_paused = true)]
async fn test_resend_is_not_throttled_and_held_messages_wait_behind_it_on_the_acceptor() {
    assert_resend_is_not_throttled_and_held_messages_wait_behind_it(Role::Acceptor).await;
}

/// A message held when this session's Logout goes out is never written,
/// even once its token is earned while the Logout waits for its
/// acknowledgement: it reports `DiscardedByThrottle` as soon as the Logout
/// is framed.
async fn assert_held_message_never_follows_the_logout(role: Role) {
    let (app, _rx) = ThrottleApp::new();
    let (connection, mut peer, handshake) =
        start(role, app, Setup::new(one_budget(1, SECOND))).await;
    let first = handshake + 1;

    assert_eq!(
        sent(&outcome(track(&connection, order("SENT-1")).await).await),
        first
    );
    let _ = frame_of_type(&mut peer.framed, "D").await;
    let held = track(&connection, order("HELD-1")).await;
    ok(connection.logout().await, "the logout is queued");
    let logout = next_frame(&mut peer.framed).await;
    assert_eq!(header(&logout), ("5".to_string(), first + 1));
    assert_discarded_by_throttle(&outcome(held).await, BudgetId::DEFAULT);

    // The held message's token is earned while the acknowledgement is late.
    tokio::time::sleep(2 * SECOND).await;
    assert_silent(&mut peer.framed, "nothing is written after the Logout").await;
    peer.send("5", &[]).await;
    closed(&connection, "the Logout exchange closes the session").await;
    assert_eq!(connection.next_sender_seq(), first + 2);
}

#[tokio::test(start_paused = true)]
async fn test_held_message_never_follows_the_logout_on_the_initiator() {
    assert_held_message_never_follows_the_logout(Role::Initiator).await;
}

#[tokio::test(start_paused = true)]
async fn test_held_message_never_follows_the_logout_on_the_acceptor() {
    assert_held_message_never_follows_the_logout(Role::Acceptor).await;
}

/// The setup of the full-queue tests: orders in a budget of one per hour
/// held up to two deep, and a second budget, for the message whose ClOrdID
/// is `GATE`, that parks the reactor in `to_app_checked`. The outbound queue
/// holds two messages.
fn full_queue_setup() -> Setup {
    let config = throttle(
        ThrottleConfig::builder(
            ThrottleBudget::new(1, HOUR).with_policy(ThrottlePolicy::Queue { max_depth: 2 }),
        )
        .budget(ThrottleBudget::new(10, SECOND).with_burst(10))
        .classifier(|message| {
            if message.get(11) == Some(b"GATE".as_slice()) {
                GATE_BUDGET
            } else {
                BudgetId::DEFAULT
            }
        }),
    );
    Setup {
        outbound_capacity: 2,
        ..Setup::new(config)
    }
}

/// What the full-queue tests leave in flight.
struct FullQueues {
    /// The order sent before anything was held.
    sent: JoinHandle<SendOutcome>,
    /// The two orders the throttle holds: its queue is full.
    held: Vec<JoinHandle<SendOutcome>>,
    /// The gated message, parking the reactor.
    gated: JoinHandle<SendOutcome>,
    /// The two orders filling the outbound queue behind it.
    queued: Vec<JoinHandle<SendOutcome>>,
    /// An order waiting for room in the outbound queue.
    waiting: JoinHandle<SendOutcome>,
}

/// Fills the throttle's queue, parks the reactor in `to_app_checked`, then
/// fills the outbound queue behind it and leaves one more send waiting for
/// room.
async fn fill_both_queues(
    connection: &Connection,
    app: &ThrottleApp,
    peer: &mut Peer,
) -> FullQueues {
    let sent = track(connection, order("SENT-1")).await;
    let _ = frame_of_type(&mut peer.framed, "D").await;
    let held = vec![
        track(connection, order("HELD-1")).await,
        track(connection, order("HELD-2")).await,
    ];
    let gated = track(connection, order("GATE")).await;
    ok(
        timeout(STEP, app.entered.notified()).await,
        "the gated message reaches to_app_checked",
    );
    let queued = vec![
        track(connection, order("QUEUED-1")).await,
        track(connection, order("QUEUED-2")).await,
    ];
    let waiting = track(connection, order("WAITING-1")).await;
    tokio::time::sleep(QUIET).await;
    assert!(!waiting.is_finished(), "the outbound queue is full");
    assert!(held.iter().all(|task| !task.is_finished()));
    FullQueues {
        sent,
        held,
        gated,
        queued,
        waiting,
    }
}

/// A Logout while the throttle's queue and the outbound queue are both full:
/// the Logout goes out at once behind the gated message, every message the
/// throttle held reports `DiscardedByThrottle`, every one it had no room for
/// `Throttled`, and no application frame follows the Logout.
async fn assert_logout_with_both_queues_full_resolves_every_message(role: Role) {
    let (app, _rx) = ThrottleApp::new();
    let (connection, mut peer, handshake) = start(role, Arc::clone(&app), full_queue_setup()).await;
    let first = handshake + 1;
    let full = fill_both_queues(&connection, &app, &mut peer).await;
    let logout = {
        let connection = connection.clone();
        tokio::spawn(async move { connection.logout().await })
    };
    tokio::time::sleep(QUIET).await;
    assert!(!logout.is_finished(), "the Logout waits for room too");

    let released = Instant::now();
    app.release.notify_one();
    let gate = next_frame(&mut peer.framed).await;
    assert_eq!(header(&gate), ("D".to_string(), first + 1));
    assert_eq!(field(&gate, 11).as_deref(), Some("GATE"));
    let logout_frame = next_frame(&mut peer.framed).await;
    assert_eq!(header(&logout_frame), ("5".to_string(), first + 2));
    assert!(
        released.elapsed() < RELEASE_SLACK,
        "{role:?}: the Logout takes no token and goes out at once"
    );
    assert_silent(&mut peer.framed, "no application frame follows the Logout").await;
    ok(joined(logout, "the logout is queued").await, "logout");

    assert_eq!(sent(&outcome(full.sent).await), first);
    assert_eq!(sent(&outcome(full.gated).await), first + 1);
    for task in full.held {
        assert_discarded_by_throttle(&outcome(task).await, BudgetId::DEFAULT);
    }
    for task in full.queued {
        assert_throttled(&outcome(task).await, BudgetId::DEFAULT);
    }
    // Taken from the queue as the Logout's slot freed up, either side of it:
    // refused by the full throttle queue, or reached behind the Logout.
    let waiting = outcome(full.waiting).await;
    assert!(
        matches!(
            not_sent(&waiting),
            NotSentReason::Throttled { .. } | NotSentReason::LogoutPending
        ),
        "{role:?}: {waiting:?}"
    );

    peer.send("5", &[]).await;
    closed(&connection, "the Logout exchange closes the session").await;
    assert_eq!(
        connection.next_sender_seq(),
        first + 3,
        "{role:?}: numbers spent for the two orders sent and the Logout only"
    );
}

#[tokio::test(start_paused = true)]
async fn test_logout_with_both_queues_full_resolves_every_message_on_the_initiator() {
    assert_logout_with_both_queues_full_resolves_every_message(Role::Initiator).await;
}

#[tokio::test(start_paused = true)]
async fn test_logout_with_both_queues_full_resolves_every_message_on_the_acceptor() {
    assert_logout_with_both_queues_full_resolves_every_message(Role::Acceptor).await;
}

/// The transport dies while the throttle's queue and the outbound queue are
/// both full: the gated frame, buffered over a dead stream, is `Unknown`;
/// every message the throttle held reports `DiscardedByThrottle`, and every
/// one still in the outbound queue `Discarded` (or `SessionClosed`, for the
/// one that never got in).
async fn assert_kill_with_both_queues_full_resolves_every_message(role: Role) {
    let (app, _rx) = ThrottleApp::new();
    let (connection, peer, handshake) = start(role, Arc::clone(&app), full_queue_setup()).await;
    let first = handshake + 1;
    let mut peer = peer;
    let full = fill_both_queues(&connection, &app, &mut peer).await;

    drop(peer);
    app.release.notify_one();

    assert_eq!(sent(&outcome(full.sent).await), first);
    assert_eq!(
        unknown(&outcome(full.gated).await),
        (first + 1, UnknownReason::Transport),
        "{role:?}: buffered over a dead stream, so its number is spent"
    );
    for task in full.held {
        assert_discarded_by_throttle(&outcome(task).await, BudgetId::DEFAULT);
    }
    for task in full.queued {
        let queued = outcome(task).await;
        assert!(
            matches!(not_sent(&queued), NotSentReason::Discarded { .. }),
            "{role:?}: {queued:?}"
        );
    }
    let waiting = outcome(full.waiting).await;
    assert!(
        matches!(
            not_sent(&waiting),
            NotSentReason::Discarded { .. } | NotSentReason::SessionClosed { .. }
        ),
        "{role:?}: {waiting:?}"
    );
    closed(&connection, "the dead transport closes the session").await;
    assert_eq!(connection.next_sender_seq(), first + 2);
}

#[tokio::test(start_paused = true)]
async fn test_kill_with_both_queues_full_resolves_every_message_on_the_initiator() {
    assert_kill_with_both_queues_full_resolves_every_message(Role::Initiator).await;
}

#[tokio::test(start_paused = true)]
async fn test_kill_with_both_queues_full_resolves_every_message_on_the_acceptor() {
    assert_kill_with_both_queues_full_resolves_every_message(Role::Acceptor).await;
}

/// The member's end of a pipe, which passes everything through until it is
/// armed with a byte budget: it then accepts that many more bytes, and fails
/// every write after them with `BrokenPipe`.
struct FailingStream {
    inner: DuplexStream,
    /// Bytes still accepted once armed; `None` while it passes through.
    budget: Arc<Mutex<Option<usize>>>,
}

impl AsyncRead for FailingStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FailingStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let budget = Arc::clone(&this.budget);
        let mut budget = locked(&budget);
        match *budget {
            None => Pin::new(&mut this.inner).poll_write(cx, buf),
            Some(0) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Some(left) => {
                let part = buf.get(..left.min(buf.len())).unwrap_or(buf);
                let polled = Pin::new(&mut this.inner).poll_write(cx, part);
                if let Poll::Ready(Ok(written)) = &polled {
                    *budget = Some(some(
                        left.checked_sub(*written),
                        "a write never takes more than it is offered",
                    ));
                }
                polled
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
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

/// A message the throttle released whose write the transport takes only in
/// part before failing is `Unknown`, with its number spent; the messages
/// still held are `NotSent`, with nothing spent on them.
#[tokio::test(start_paused = true)]
async fn test_partial_write_of_a_released_message_is_unknown_and_the_rest_not_sent() {
    let (app, _rx) = ThrottleApp::new();
    let (engine_io, peer_io) = tokio::io::duplex(PIPE_CAPACITY);
    let budget = Arc::new(Mutex::new(None));
    let stream = FailingStream {
        inner: engine_io,
        budget: Arc::clone(&budget),
    };
    let initiator = Initiator::new(member_config(), app).with_throttle(one_budget(1, SECOND));
    let venue = tokio::spawn(async move {
        let mut framed = Framed::new(peer_io, FixCodec::new());
        let logon = next_frame(&mut framed).await;
        assert_eq!(header(&logon), ("A".to_string(), 1));
        peer_write(
            &mut framed,
            frame_from("VENUE", "CLIENT", "A", 1, LOGON_BODY),
        )
        .await;
        framed
    });
    let member = ok(
        initiator.establish(stream).await,
        "the initiator logs on over the failing stream",
    );
    let mut venue = joined(venue, "the venue acknowledges the Logon").await;

    assert_eq!(
        sent(&outcome(track(&member, order("SENT-1")).await).await),
        2
    );
    let _ = frame_of_type(&mut venue, "D").await;
    let released = track(&member, order("PARTIAL-1")).await;
    let held = vec![
        track(&member, order("HELD-1")).await,
        track(&member, order("HELD-2")).await,
    ];
    // The next write takes ten bytes of the released frame, then fails.
    *locked(&budget) = Some(10);

    assert_eq!(
        unknown(&outcome(released).await),
        (3, UnknownReason::Transport),
        "part of the frame reached the stream: never NotSent"
    );
    for task in held {
        assert_discarded_by_throttle(&outcome(task).await, BudgetId::DEFAULT);
    }
    closed(&member, "the failed write closes the session").await;
    assert_eq!(
        member.next_sender_seq(),
        4,
        "a number was spent on the released frame only"
    );
    drop(venue);
}

/// A message the outbound gate vetoes gives back the token it took, so the
/// next message goes at once rather than waiting for the next token.
#[tokio::test(start_paused = true)]
async fn test_vetoed_message_gives_its_token_back() {
    let (app, _rx) = ThrottleApp::new();
    let (connection, mut peer, handshake) =
        start(Role::Initiator, app, Setup::new(one_budget(1, HOUR))).await;
    let first = handshake + 1;

    let vetoed = outcome(track(&connection, order("VETO-1")).await).await;
    assert!(
        matches!(not_sent(&vetoed), NotSentReason::Vetoed { .. }),
        "{vetoed:?}"
    );
    assert_eq!(
        sent(&outcome(track(&connection, order("ORDER-1")).await).await),
        first,
        "the vetoed message's token was given back"
    );
    let frame = frame_of_type(&mut peer.framed, "D").await;
    assert_eq!(field(&frame, 11).as_deref(), Some("ORDER-1"));
    let held = track(&connection, order("ORDER-2")).await;
    assert_silent(&mut peer.framed, "the budget is empty again").await;
    log_out(&connection, &mut peer).await;
    assert_discarded_by_throttle(&outcome(held).await, BudgetId::DEFAULT);
}

/// A plain `send` goes through the same throttle: one refused is dropped,
/// spending nothing, and the next tracked message takes the next number.
#[tokio::test(start_paused = true)]
async fn test_plain_send_is_throttled_too() {
    let (app, _rx) = ThrottleApp::new();
    let budget = ThrottleBudget::new(1, HOUR).with_policy(ThrottlePolicy::Refuse);
    let (connection, mut peer, handshake) = start(
        Role::Initiator,
        app,
        Setup::new(throttle(ThrottleConfig::builder(budget))),
    )
    .await;
    let first = handshake + 1;

    ok(connection.send(order("PLAIN-1")).await, "queued");
    ok(
        connection.send(order("PLAIN-2")).await,
        "queued, then refused",
    );
    let frame = frame_of_type(&mut peer.framed, "D").await;
    assert_eq!(header(&frame).1, first);
    assert_eq!(field(&frame, 11).as_deref(), Some("PLAIN-1"));
    assert_silent(&mut peer.framed, "the refused plain send never goes out").await;
    assert_eq!(connection.next_sender_seq(), first + 1);
    assert_throttled(
        &outcome(track(&connection, order("TRACKED-1")).await).await,
        BudgetId::DEFAULT,
    );
    log_out(&connection, &mut peer).await;
}

/// A session an `AcceptorRegistry` routes runs with the throttle of the
/// `Acceptor` it was routed to.
#[tokio::test(start_paused = true)]
async fn test_registry_routed_session_keeps_its_acceptor_throttle() {
    let (app, _rx) = ThrottleApp::new();
    let budget = ThrottleBudget::new(1, HOUR).with_policy(ThrottlePolicy::Refuse);
    let acceptor =
        Acceptor::new(venue_config(), app).with_throttle(throttle(ThrottleConfig::builder(budget)));
    assert!(acceptor.throttle().is_some());
    let registry = Arc::new(AcceptorRegistry::new());
    ok(registry.register(acceptor), "the session registers");

    let (engine_io, peer_io) = tokio::io::duplex(PIPE_CAPACITY);
    let served = {
        let registry = Arc::clone(&registry);
        tokio::spawn(async move { registry.serve_stream(engine_io).await })
    };
    let mut framed = Framed::new(peer_io, FixCodec::new());
    peer_write(
        &mut framed,
        frame_from("CLIENT", "VENUE", "A", 1, LOGON_BODY),
    )
    .await;
    let ack = next_frame(&mut framed).await;
    assert_eq!(header(&ack), ("A".to_string(), 1));
    let venue = ok(
        joined(served, "the routed handshake ends").await,
        "the registry routes the Logon",
    );

    assert_eq!(
        sent(&outcome(track(&venue, order("REPORT-1")).await).await),
        2
    );
    assert_throttled(
        &outcome(track(&venue, order("REPORT-2")).await).await,
        BudgetId::DEFAULT,
    );
    let mut peer = Peer {
        framed,
        me: "CLIENT",
        them: "VENUE",
        next_seq: 2,
    };
    log_out(&venue, &mut peer).await;
}
