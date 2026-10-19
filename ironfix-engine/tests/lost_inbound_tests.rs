/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 19/10/26
******************************************************************************/

//! The inbound loss report (issue #105, ADR-0030).
//!
//! Inbound application delivery is at most once: the target counter is
//! persisted before `from_app` sees a message. These tests check that what a
//! crash or an aborted dispatcher may have lost is **reported** through
//! `Application::on_inbound_lost`, with the exact span, and that nothing is
//! redelivered.
//!
//! A crash is simulated as in `durable_reset_tests.rs`: a [`CrashStore`]
//! armed at one store call lets the wrapped store go and hangs every later
//! call, as a dead process would; the engine is abandoned and a **new** one
//! is started over the same store (the same `MemoryStore`, or a `FileStore`
//! reopened from disk).
//!
//! Covered, in both roles and for both store types:
//!
//! - a crash after the target counter of an application message is
//!   persisted and before `from_app` sees it: the message is reported;
//! - a crash after `from_app` returned and before its watermark write: the
//!   message is reported too (the residual window ADR-0030 names);
//! - a crash after the watermark write: nothing is reported;
//! - a clean close: nothing is reported, administrative messages included;
//! - a reset at the next start: the span is still reported, and the reset
//!   clears the watermark;
//! - a dispatcher aborted after its drain timeout, and one stopped by a
//!   failed watermark write under the fail-closed policy: the span is
//!   reported at close, and not again at the next start.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::error::StoreError;
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::application::RejectReason;
use ironfix_engine::{
    Acceptor, Application, CloseReason, Connection, InboundLoss, InboundLossCause, Initiator,
    OutboundMessage, SessionId, StoreFailurePolicy,
};
use ironfix_session::SessionConfig;
use ironfix_store::{FileStore, FileStoreConfig, MemoryStore, MessageStore, StoredMessage};
use ironfix_tagvalue::{Decoder, Encoder};
use ironfix_transport::FixCodec;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
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

fn client_config() -> SessionConfig {
    SessionConfig::new(comp_id("CLIENT"), comp_id("VENUE"), "FIX.4.4")
        .with_heartbeat_interval(Duration::from_secs(30))
}

fn venue_config() -> SessionConfig {
    SessionConfig::new(comp_id("VENUE"), comp_id("CLIENT"), "FIX.4.4")
        .with_heartbeat_interval(Duration::from_secs(30))
}

/// A frame from `sender` to `target`.
fn frame(sender: &str, target: &str, msg_type: &str, seq: u64, extra: &[(u32, &str)]) -> BytesMut {
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

async fn send(peer: &mut Peer, frame: BytesMut) {
    ok(peer.send(frame).await, "the counterparty sends");
}

/// Polls `condition` until it holds, failing the test after the step.
async fn until(what: &str, mut condition: impl FnMut() -> bool) {
    let reached = timeout(STEP, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(reached.is_ok(), "{what}: not reached within the step");
}

// ---------------------------------------------------------------------------
// The recording application
// ---------------------------------------------------------------------------

/// What the application saw, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Logon,
    App(u64),
    Lost(u64, u64, InboundLossCause),
    Closed,
}

/// Records every callback; `from_app` can hang forever on one number, or
/// sleep on one.
#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<Event>>,
    hang_on: Option<u64>,
    slow_on: Option<(u64, Duration)>,
}

impl Recorder {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn hanging_on(seq: u64) -> Arc<Self> {
        Arc::new(Self {
            hang_on: Some(seq),
            ..Self::default()
        })
    }

    fn slow_on(seq: u64, delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            slow_on: Some((seq, delay)),
            ..Self::default()
        })
    }

    fn push(&self, event: Event) {
        match self.events.lock() {
            Ok(mut events) => events.push(event),
            Err(_) => panic!("recorder lock poisoned"),
        }
    }

    fn events(&self) -> Vec<Event> {
        match self.events.lock() {
            Ok(events) => events.clone(),
            Err(_) => panic!("recorder lock poisoned"),
        }
    }

    fn delivered(&self) -> Vec<u64> {
        self.events()
            .into_iter()
            .filter_map(|event| match event {
                Event::App(seq) => Some(seq),
                _ => None,
            })
            .collect()
    }

    fn losses(&self) -> Vec<(u64, u64, InboundLossCause)> {
        self.events()
            .into_iter()
            .filter_map(|event| match event {
                Event::Lost(first, last, cause) => Some((first, last, cause)),
                _ => None,
            })
            .collect()
    }
}

#[async_trait]
impl Application for Recorder {
    async fn on_create(&self, _: &SessionId) {}

    async fn on_logon(&self, _: &SessionId) {
        self.push(Event::Logon);
    }

    async fn on_logout(&self, _: &SessionId) {}

    async fn on_session_closed(&self, _: &SessionId, _: &CloseReason) {
        self.push(Event::Closed);
    }

    async fn on_inbound_lost(&self, _: &SessionId, loss: &InboundLoss) {
        self.push(Event::Lost(loss.first(), loss.last(), loss.cause()));
    }

    async fn to_admin(&self, _: &mut OutboundMessage, _: &SessionId) {}

    async fn from_admin(&self, _: &RawMessage<'_>, _: &SessionId) -> Result<(), RejectReason> {
        Ok(())
    }

    async fn to_app(&self, _: &mut OutboundMessage, _: &SessionId) {}

    async fn from_app(&self, message: &RawMessage<'_>, _: &SessionId) -> Result<(), RejectReason> {
        let seq = message
            .get_field_str(34)
            .and_then(|seq| seq.parse::<u64>().ok())
            .unwrap_or_default();
        if self.hang_on == Some(seq) {
            std::future::pending::<()>().await;
        }
        if let Some((slow, delay)) = self.slow_on
            && slow == seq
        {
            tokio::time::sleep(delay).await;
        }
        self.push(Event::App(seq));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The crashing store
// ---------------------------------------------------------------------------

/// Where a store crashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Point {
    /// Once `set_next_target_seq(value)` has taken effect.
    TargetAfter(u64),
    /// When `set_app_watermark(value)` is called, before it takes effect.
    WatermarkBefore(u64),
    /// Once `set_app_watermark(value)` has taken effect.
    WatermarkAfter(u64),
}

/// Wraps a store; once it crashes the wrapped store is let go and every call
/// hangs forever, so nothing after the crash reaches it.
struct CrashStore {
    inner: Mutex<Option<Arc<dyn MessageStore>>>,
    point: Point,
    crashed: AtomicBool,
}

impl CrashStore {
    fn new(inner: Arc<dyn MessageStore>, point: Point) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Some(inner)),
            point,
            crashed: AtomicBool::new(false),
        })
    }

    fn inner(&self) -> Option<Arc<dyn MessageStore>> {
        match self.inner.lock() {
            Ok(inner) => inner.clone(),
            Err(_) => panic!("crash store lock poisoned"),
        }
    }

    fn crash(&self) {
        self.crashed.store(true, Ordering::SeqCst);
        match self.inner.lock() {
            Ok(mut inner) => drop(inner.take()),
            Err(_) => panic!("crash store lock poisoned"),
        }
    }

    fn has_crashed(&self) -> bool {
        self.crashed.load(Ordering::SeqCst)
    }

    async fn alive(&self) -> Arc<dyn MessageStore> {
        match self.inner() {
            Some(inner) => inner,
            None => std::future::pending().await,
        }
    }

    async fn dead(&self) {
        self.crash();
        std::future::pending::<()>().await;
    }
}

#[async_trait]
impl MessageStore for CrashStore {
    async fn store(
        &self,
        seq_num: u64,
        msg_type: &MsgType,
        message: &[u8],
    ) -> Result<(), StoreError> {
        self.alive().await.store(seq_num, msg_type, message).await
    }

    async fn get_range(&self, begin: u64, end: u64) -> Result<Vec<StoredMessage>, StoreError> {
        self.alive().await.get_range(begin, end).await
    }

    async fn file_outbound(
        &self,
        seq_num: u64,
        msg_type: &MsgType,
        message: &[u8],
        next_sender: u64,
    ) -> Result<(), StoreError> {
        self.alive()
            .await
            .file_outbound(seq_num, msg_type, message, next_sender)
            .await
    }

    fn next_sender_seq(&self) -> u64 {
        self.inner().map_or(1, |inner| inner.next_sender_seq())
    }

    fn next_target_seq(&self) -> u64 {
        self.inner().map_or(1, |inner| inner.next_target_seq())
    }

    async fn set_next_sender_seq(&self, seq: u64) -> Result<(), StoreError> {
        self.alive().await.set_next_sender_seq(seq).await
    }

    async fn set_next_target_seq(&self, seq: u64) -> Result<(), StoreError> {
        let result = self.alive().await.set_next_target_seq(seq).await;
        if self.point == Point::TargetAfter(seq) {
            self.dead().await;
        }
        result
    }

    async fn reset(&self) -> Result<(), StoreError> {
        self.alive().await.reset().await
    }

    async fn reset_to(&self, next_sender: u64, next_target: u64) -> Result<(), StoreError> {
        self.alive().await.reset_to(next_sender, next_target).await
    }

    fn reset_owed(&self) -> bool {
        self.inner().is_some_and(|inner| inner.reset_owed())
    }

    async fn set_reset_owed(&self, owed: bool) -> Result<(), StoreError> {
        self.alive().await.set_reset_owed(owed).await
    }

    fn app_watermark(&self) -> u64 {
        self.inner().map_or(0, |inner| inner.app_watermark())
    }

    async fn set_app_watermark(&self, watermark: u64) -> Result<(), StoreError> {
        if self.point == Point::WatermarkBefore(watermark) {
            self.dead().await;
        }
        let result = self.alive().await.set_app_watermark(watermark).await;
        if self.point == Point::WatermarkAfter(watermark) {
            self.dead().await;
        }
        result
    }

    fn creation_time(&self) -> SystemTime {
        self.inner()
            .map_or(SystemTime::UNIX_EPOCH, |inner| inner.creation_time())
    }

    async fn refresh(&self) -> Result<(), StoreError> {
        self.alive().await.refresh().await
    }
}

/// A `MemoryStore` whose watermark writes fail from `fail_from` on.
struct FailingWatermark {
    inner: MemoryStore,
    fail_from: u64,
}

#[async_trait]
impl MessageStore for FailingWatermark {
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
        self.inner.reset().await
    }

    fn app_watermark(&self) -> u64 {
        self.inner.app_watermark()
    }

    async fn set_app_watermark(&self, watermark: u64) -> Result<(), StoreError> {
        if watermark >= self.fail_from {
            return Err(StoreError::Io(
                "watermark write refused by the test".to_string(),
            ));
        }
        self.inner.set_app_watermark(watermark).await
    }

    fn creation_time(&self) -> SystemTime {
        self.inner.creation_time()
    }
}

// ---------------------------------------------------------------------------
// The two store types, across a restart
// ---------------------------------------------------------------------------

/// A directory for one test, removed when it ends.
struct TestDir(std::path::PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ironfix-lost-inbound-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Memory,
    File,
}

/// One store across a restart: a `MemoryStore` that outlives the engine, or
/// a `FileStore` closed and reopened from its directory.
struct Durable {
    store: Arc<dyn MessageStore>,
    file: Option<(FileStoreConfig, TestDir)>,
}

impl Durable {
    async fn new(kind: Kind, name: &str) -> Self {
        match kind {
            Kind::Memory => Self {
                store: Arc::new(MemoryStore::new()),
                file: None,
            },
            Kind::File => {
                let dir = TestDir::new(name);
                let config = ok(FileStoreConfig::try_new(&dir.0, "STORE"), "store config");
                let store = ok(
                    FileStore::open(config.clone().with_create_if_missing(true)).await,
                    "create the file store",
                );
                Self {
                    store: Arc::new(store),
                    file: Some((config, dir)),
                }
            }
        }
    }

    /// The restart: the crashed engine is gone; a `FileStore` is closed, as
    /// the dying process would, and opened again from disk.
    async fn restart(self) -> Self {
        let Self { store, file } = self;
        let Some((config, dir)) = file else {
            return Self { store, file: None };
        };
        let released = timeout(STEP, async {
            while Arc::strong_count(&store) > 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(released.is_ok(), "the crashed engine must let the store go");
        drop(store);
        let reopened = ok(FileStore::open(config.clone()).await, "reopen the store");
        Self {
            store: Arc::new(reopened),
            file: Some((config, dir)),
        }
    }
}

// ---------------------------------------------------------------------------
// Sessions in either role
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Initiator,
    Acceptor,
}

impl Role {
    /// The counterparty's identity for a frame it sends.
    const fn peer(self) -> (&'static str, &'static str) {
        match self {
            Self::Initiator => ("VENUE", "CLIENT"),
            Self::Acceptor => ("CLIENT", "VENUE"),
        }
    }

    /// An application message from the counterparty.
    fn app_frame(self, seq: u64) -> BytesMut {
        let (sender, target) = self.peer();
        match self {
            Self::Initiator => frame(sender, target, "8", seq, &[(17, "EXEC")]),
            Self::Acceptor => frame(sender, target, "D", seq, &[(11, "ORDER")]),
        }
    }

    /// An administrative message from the counterparty.
    fn admin_frame(self, msg_type: &str, seq: u64) -> BytesMut {
        let (sender, target) = self.peer();
        frame(sender, target, msg_type, seq, &[])
    }
}

/// An engine of `role` over `store`, its counterparty, and the
/// application's recorder. The counterparty's Logon or acknowledgement goes
/// out at `logon_seq`, declaring a reset when `reset` is set.
struct Live {
    connection: Connection,
    peer: Peer,
    /// The engine's own Logon or acknowledgement.
    logon: BytesMut,
}

async fn start(
    role: Role,
    store: Arc<dyn MessageStore>,
    app: Arc<Recorder>,
    logon_seq: u64,
    reset: bool,
    policy: StoreFailurePolicy,
) -> Live {
    let mut logon_fields = vec![(98, "0"), (108, "30")];
    if reset {
        logon_fields.push((141, "Y"));
    }
    match role {
        Role::Initiator => {
            let mut config = client_config();
            config.reset_on_logon = reset;
            let initiator = Initiator::new(config, app)
                .with_store(store)
                .with_store_failure_policy(policy);
            let (client_io, venue_io) = tokio::io::duplex(64 * 1024);
            let mut peer = Framed::new(venue_io, FixCodec::new());
            let established = tokio::spawn(async move { initiator.establish(client_io).await });
            let logon = next_frame(&mut peer).await;
            send(
                &mut peer,
                frame("VENUE", "CLIENT", "A", logon_seq, &logon_fields),
            )
            .await;
            let connection = ok(
                ok(
                    ok(timeout(STEP, established).await, "handshake in time"),
                    "handshake task",
                ),
                "the initiator establishes the session",
            );
            Live {
                connection,
                peer,
                logon,
            }
        }
        Role::Acceptor => {
            let acceptor = Acceptor::new(venue_config(), app)
                .with_store(store)
                .with_store_failure_policy(policy);
            let (venue_io, client_io) = tokio::io::duplex(64 * 1024);
            let mut peer = Framed::new(client_io, FixCodec::new());
            let served = tokio::spawn(async move { acceptor.serve_stream(venue_io).await });
            send(
                &mut peer,
                frame("CLIENT", "VENUE", "A", logon_seq, &logon_fields),
            )
            .await;
            let logon = next_frame(&mut peer).await;
            let connection = ok(
                ok(
                    ok(timeout(STEP, served).await, "handshake in time"),
                    "handshake task",
                ),
                "the acceptor establishes the session",
            );
            Live {
                connection,
                peer,
                logon,
            }
        }
    }
}

/// The first session: the counterparty logs on at 1, sends application
/// message 2, waits until it is delivered and its watermark is stored, then
/// sends application message 3, and the store crashes at `point`. Returns
/// what the dead engine's application saw, and the dead session's ends,
/// which the caller keeps until the test ends so nothing runs a close path.
async fn crash_at(role: Role, durable: &Durable, point: Point, case: &str) -> (Vec<Event>, Live) {
    let store = CrashStore::new(Arc::clone(&durable.store), point);
    let app = Recorder::new();
    let mut live = start(
        role,
        Arc::clone(&store) as Arc<dyn MessageStore>,
        Arc::clone(&app),
        1,
        false,
        StoreFailurePolicy::Continue,
    )
    .await;
    send(&mut live.peer, role.app_frame(2)).await;
    let inner = Arc::clone(&durable.store);
    until(
        &format!("{case}: message 2 delivered and its watermark stored"),
        || app.delivered() == [2] && inner.app_watermark() == 2,
    )
    .await;
    send(&mut live.peer, role.app_frame(3)).await;
    until(&format!("{case}: the store crashes"), || {
        store.has_crashed()
    })
    .await;
    // Whatever the dead engine would still do never reaches the store.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (app.events(), live)
}

/// The restarted engine: the counterparty continues at 4 and sends
/// application message 5. Returns what the new application saw.
async fn restart_and_continue(role: Role, store: Arc<dyn MessageStore>, case: &str) -> Vec<Event> {
    let app = Recorder::new();
    let mut live = start(
        role,
        store,
        Arc::clone(&app),
        4,
        false,
        StoreFailurePolicy::Continue,
    )
    .await;
    assert_eq!(
        field(&live.logon, 34).as_deref(),
        Some("2"),
        "{case}: the engine continues its own stream"
    );
    send(&mut live.peer, role.app_frame(5)).await;
    until(&format!("{case}: message 5 delivered"), || {
        app.delivered() == [5]
    })
    .await;
    drop(live);
    app.events()
}

async fn crash_cases(role: Role, kind: Kind) {
    // (crash point, delivered before the crash, span reported at restart)
    let cases = [
        (
            "after the target persist, before from_app",
            Point::TargetAfter(4),
            vec![2],
            Some((3, 3)),
        ),
        (
            "after from_app, before the watermark write",
            Point::WatermarkBefore(3),
            vec![2, 3],
            Some((3, 3)),
        ),
        (
            "after the watermark write",
            Point::WatermarkAfter(3),
            vec![2, 3],
            None,
        ),
    ];
    for (index, (name, point, delivered, reported)) in cases.into_iter().enumerate() {
        let case = format!("{role:?} {kind:?}: crash {name}");
        let durable = Durable::new(kind, &format!("{role:?}-{index}")).await;
        let (before, dead) = crash_at(role, &durable, point, &case).await;
        let seen: Vec<u64> = before
            .iter()
            .filter_map(|event| match event {
                Event::App(seq) => Some(*seq),
                _ => None,
            })
            .collect();
        assert_eq!(seen, delivered, "{case}: from_app before the crash");
        let durable = durable.restart().await;
        assert_eq!(
            durable.store.next_target_seq(),
            4,
            "{case}: the receive cursor survives"
        );
        let after = restart_and_continue(role, Arc::clone(&durable.store), &case).await;
        let expected_losses: Vec<_> = reported
            .map(|(first, last)| (first, last, InboundLossCause::FoundAtStart))
            .into_iter()
            .collect();
        let losses: Vec<_> = after
            .iter()
            .filter_map(|event| match event {
                Event::Lost(first, last, cause) => Some((*first, *last, *cause)),
                _ => None,
            })
            .collect();
        assert_eq!(losses, expected_losses, "{case}: the exact span, once");
        if reported.is_some() {
            assert!(
                matches!(after.first(), Some(Event::Lost(..))),
                "{case}: reported before the session is Active: {after:?}"
            );
        }
        let redelivered: Vec<u64> = after
            .iter()
            .filter_map(|event| match event {
                Event::App(seq) => Some(*seq),
                _ => None,
            })
            .collect();
        assert_eq!(redelivered, vec![5], "{case}: nothing is redelivered");
        // The watermark write follows `from_app`: wait for it rather than
        // race it.
        let store = Arc::clone(&durable.store);
        until(
            &format!("{case}: the restarted session moves the watermark on"),
            || store.app_watermark() >= 5,
        )
        .await;
        drop(dead);
    }
}

#[tokio::test]
async fn test_initiator_crash_reports_the_lost_span_memory_store() {
    crash_cases(Role::Initiator, Kind::Memory).await;
}

#[tokio::test]
async fn test_initiator_crash_reports_the_lost_span_file_store() {
    crash_cases(Role::Initiator, Kind::File).await;
}

#[tokio::test]
async fn test_acceptor_crash_reports_the_lost_span_memory_store() {
    crash_cases(Role::Acceptor, Kind::Memory).await;
}

#[tokio::test]
async fn test_acceptor_crash_reports_the_lost_span_file_store() {
    crash_cases(Role::Acceptor, Kind::File).await;
}

// ---------------------------------------------------------------------------
// Nothing lost
// ---------------------------------------------------------------------------

/// A session that ends cleanly, on administrative messages (a Heartbeat and
/// a Logout after the last application message), leaves nothing to report:
/// the watermark covers the administrative messages too.
async fn clean_close(role: Role, kind: Kind) {
    let case = format!("{role:?} {kind:?}: clean close");
    let durable = Durable::new(kind, &format!("{role:?}-clean")).await;
    let app = Recorder::new();
    let mut live = start(
        role,
        Arc::clone(&durable.store),
        Arc::clone(&app),
        1,
        false,
        StoreFailurePolicy::Continue,
    )
    .await;
    send(&mut live.peer, role.app_frame(2)).await;
    send(&mut live.peer, role.app_frame(3)).await;
    send(&mut live.peer, role.admin_frame("0", 4)).await;
    send(&mut live.peer, role.admin_frame("5", 5)).await;
    ok(
        timeout(STEP, live.connection.wait_closed()).await,
        "the session closes on the Logout",
    );
    assert_eq!(app.delivered(), vec![2, 3], "{case}");
    assert!(app.losses().is_empty(), "{case}: {:?}", app.events());
    assert_eq!(
        durable.store.app_watermark(),
        5,
        "{case}: the watermark covers the Logout"
    );
    drop(live);
    let durable = durable.restart().await;
    let after = restart_and_continue_at(role, Arc::clone(&durable.store), 6, &case).await;
    assert!(
        !after.iter().any(|event| matches!(event, Event::Lost(..))),
        "{case}: nothing reported at the next start: {after:?}"
    );
}

/// [`restart_and_continue`] with the counterparty continuing at `logon_seq`.
async fn restart_and_continue_at(
    role: Role,
    store: Arc<dyn MessageStore>,
    logon_seq: u64,
    case: &str,
) -> Vec<Event> {
    let app = Recorder::new();
    let mut live = start(
        role,
        store,
        Arc::clone(&app),
        logon_seq,
        false,
        StoreFailurePolicy::Continue,
    )
    .await;
    let next = logon_seq + 1;
    send(&mut live.peer, role.app_frame(next)).await;
    until(&format!("{case}: message {next} delivered"), || {
        app.delivered() == [next]
    })
    .await;
    drop(live);
    app.events()
}

#[tokio::test]
async fn test_clean_close_reports_nothing_initiator() {
    clean_close(Role::Initiator, Kind::Memory).await;
    clean_close(Role::Initiator, Kind::File).await;
}

#[tokio::test]
async fn test_clean_close_reports_nothing_acceptor() {
    clean_close(Role::Acceptor, Kind::Memory).await;
    clean_close(Role::Acceptor, Kind::File).await;
}

// ---------------------------------------------------------------------------
// A reset at the next start
// ---------------------------------------------------------------------------

/// A crash loses message 3; the next session resets the sequence (141=Y).
/// The span is still reported, before the reset, and the reset clears the
/// watermark: the new stream starts its own.
async fn reset_after_a_loss(role: Role, kind: Kind) {
    let case = format!("{role:?} {kind:?}: reset after a loss");
    let durable = Durable::new(kind, &format!("{role:?}-reset")).await;
    let (_, dead) = crash_at(role, &durable, Point::TargetAfter(4), &case).await;
    let durable = durable.restart().await;
    assert_eq!(
        durable.store.app_watermark(),
        2,
        "{case}: before the restart"
    );

    let app = Recorder::new();
    let mut live = start(
        role,
        Arc::clone(&durable.store),
        Arc::clone(&app),
        1,
        true,
        StoreFailurePolicy::Continue,
    )
    .await;
    assert_eq!(
        (field(&live.logon, 34), field(&live.logon, 141)),
        (Some("1".to_string()), Some("Y".to_string())),
        "{case}: the engine declares the reset"
    );
    // The new stream's opening watermark: the Logon (1) has been processed.
    let inner = Arc::clone(&durable.store);
    until(&format!("{case}: the new stream's watermark"), || {
        inner.app_watermark() == 1
    })
    .await;
    send(&mut live.peer, role.app_frame(2)).await;
    until(&format!("{case}: message 2 of the new stream"), || {
        app.delivered() == [2]
    })
    .await;
    assert_eq!(
        app.losses(),
        vec![(3, 3, InboundLossCause::FoundAtStart)],
        "{case}: the old span is reported once"
    );
    assert!(
        matches!(app.events().first(), Some(Event::Lost(3, 3, _))),
        "{case}: reported before the session is Active"
    );
    until(
        &format!("{case}: the watermark follows the new stream"),
        || inner.app_watermark() == 2,
    )
    .await;
    drop(live);
    drop(dead);
}

#[tokio::test]
async fn test_reset_after_a_loss_reports_it_and_clears_the_watermark_initiator() {
    reset_after_a_loss(Role::Initiator, Kind::Memory).await;
    reset_after_a_loss(Role::Initiator, Kind::File).await;
}

#[tokio::test]
async fn test_reset_after_a_loss_reports_it_and_clears_the_watermark_acceptor() {
    reset_after_a_loss(Role::Acceptor, Kind::Memory).await;
    reset_after_a_loss(Role::Acceptor, Kind::File).await;
}

// ---------------------------------------------------------------------------
// The dispatcher stopped at close
// ---------------------------------------------------------------------------

/// `from_app` hangs on message 3; message 4 queues behind it; the
/// counterparty logs out at 5. The dispatcher is aborted after its drain
/// timeout and the span 3..=5 (the Logout included: the span names numbers,
/// not messages) is reported at close, before `on_session_closed`. The next
/// start reports nothing more, and redelivers nothing.
async fn drain_timeout(role: Role, kind: Kind) {
    let case = format!("{role:?} {kind:?}: drain timeout");
    let durable = Durable::new(kind, &format!("{role:?}-drain")).await;
    let app = Recorder::hanging_on(3);
    let mut live = start(
        role,
        Arc::clone(&durable.store),
        Arc::clone(&app),
        1,
        false,
        StoreFailurePolicy::Continue,
    )
    .await;
    send(&mut live.peer, role.app_frame(2)).await;
    let inner = Arc::clone(&durable.store);
    until(&format!("{case}: message 2 delivered"), || {
        app.delivered() == [2] && inner.app_watermark() == 2
    })
    .await;
    send(&mut live.peer, role.app_frame(3)).await;
    send(&mut live.peer, role.app_frame(4)).await;
    send(&mut live.peer, role.admin_frame("5", 5)).await;
    ok(
        timeout(Duration::from_secs(15), live.connection.wait_closed()).await,
        "the session closes once the dispatcher is aborted",
    );
    let events = app.events();
    assert_eq!(app.delivered(), vec![2], "{case}");
    assert_eq!(
        app.losses(),
        vec![(3, 5, InboundLossCause::DispatcherStopped)],
        "{case}: the exact span"
    );
    let lost_at = events
        .iter()
        .position(|event| matches!(event, Event::Lost(..)));
    let closed_at = events.iter().position(|event| *event == Event::Closed);
    assert!(
        matches!((lost_at, closed_at), (Some(lost), Some(closed)) if lost < closed),
        "{case}: reported before on_session_closed: {events:?}"
    );
    assert_eq!(
        durable.store.app_watermark(),
        5,
        "{case}: recorded as reported"
    );
    drop(live);
    drop(inner);
    let durable = durable.restart().await;
    let after = restart_and_continue_at(role, Arc::clone(&durable.store), 6, &case).await;
    assert!(
        !after.iter().any(|event| matches!(event, Event::Lost(..))),
        "{case}: not reported again at the next start: {after:?}"
    );
}

#[tokio::test]
async fn test_drain_timeout_reports_the_unfinished_span_initiator_memory_store() {
    drain_timeout(Role::Initiator, Kind::Memory).await;
}

#[tokio::test]
async fn test_drain_timeout_reports_the_unfinished_span_initiator_file_store() {
    drain_timeout(Role::Initiator, Kind::File).await;
}

#[tokio::test]
async fn test_drain_timeout_reports_the_unfinished_span_acceptor_memory_store() {
    drain_timeout(Role::Acceptor, Kind::Memory).await;
}

#[tokio::test]
async fn test_drain_timeout_reports_the_unfinished_span_acceptor_file_store() {
    drain_timeout(Role::Acceptor, Kind::File).await;
}

/// Under the fail-closed policy a failed watermark write stops the
/// dispatcher and closes the session; message 3, accepted while `from_app`
/// was still busy with 2, never reaches `from_app` and is reported at close.
#[tokio::test]
async fn test_failed_watermark_write_closes_the_session_and_reports_the_rest() {
    for role in [Role::Initiator, Role::Acceptor] {
        let case = format!("{role:?}: failed watermark write");
        let store = Arc::new(FailingWatermark {
            inner: MemoryStore::new(),
            fail_from: 2,
        });
        let app = Recorder::slow_on(2, Duration::from_millis(300));
        let mut live = start(
            role,
            Arc::clone(&store) as Arc<dyn MessageStore>,
            Arc::clone(&app),
            1,
            false,
            StoreFailurePolicy::CloseSession,
        )
        .await;
        send(&mut live.peer, role.app_frame(2)).await;
        send(&mut live.peer, role.app_frame(3)).await;
        until(&format!("{case}: message 3 accepted"), || {
            store.next_target_seq() == 4
        })
        .await;
        ok(
            timeout(STEP, live.connection.wait_closed()).await,
            "the session closes on the failed write",
        );
        let reason = live.connection.close_reason();
        assert!(
            matches!(reason, Some(CloseReason::StoreFailure { .. })),
            "{case}: {reason:?}"
        );
        assert_eq!(
            app.delivered(),
            vec![2],
            "{case}: nothing after the failure"
        );
        assert_eq!(
            app.losses(),
            vec![(3, 3, InboundLossCause::DispatcherStopped)],
            "{case}: the exact span"
        );
        assert_eq!(
            store.app_watermark(),
            1,
            "{case}: only the opening write landed"
        );
    }
}

/// Without a store nothing is persisted, but a dispatcher stopped at close
/// is still reported, from memory.
#[tokio::test]
async fn test_no_store_still_reports_a_drain_timeout() {
    let app = Recorder::hanging_on(2);
    let initiator = Initiator::new(client_config(), Arc::clone(&app));
    let (client_io, venue_io) = tokio::io::duplex(64 * 1024);
    let mut peer = Framed::new(venue_io, FixCodec::new());
    let established = tokio::spawn(async move { initiator.establish(client_io).await });
    let _logon = next_frame(&mut peer).await;
    send(
        &mut peer,
        frame("VENUE", "CLIENT", "A", 1, &[(98, "0"), (108, "30")]),
    )
    .await;
    let connection = ok(
        ok(
            ok(timeout(STEP, established).await, "handshake in time"),
            "handshake task",
        ),
        "establish",
    );
    send(&mut peer, Role::Initiator.app_frame(2)).await;
    send(&mut peer, Role::Initiator.admin_frame("5", 3)).await;
    ok(
        timeout(Duration::from_secs(15), connection.wait_closed()).await,
        "the session closes once the dispatcher is aborted",
    );
    assert_eq!(
        app.losses(),
        vec![(2, 3, InboundLossCause::DispatcherStopped)]
    );
}
