/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 19/10/26
******************************************************************************/

//! Crash and restart tests for the durable owed-reset marker (issue #111,
//! ADR-0029).
//!
//! Every test runs a session over a [`CrashStore`]: a store wrapper armed to
//! "crash" at one store call, before or after the call takes effect. A crash
//! detaches the wrapped store and leaves every later call pending forever, as
//! a dead process would: nothing after the crash point reaches the store. The
//! engine instance is then thrown away, with its in-memory owed-reset record,
//! and a **new** engine is started over the same store (the same
//! `MemoryStore`, or a `FileStore` reopened from disk). The counterparty then
//! asks for the whole stream with a `ResendRequest` (35=2, 7=1, 16=0), and no
//! frame of the previous stream may come back.
//!
//! Covered, in both roles and for both store types:
//!
//! - the initiator's Logon-ack reset (`ResetSeqNumFlag` (141) = Y on the ack
//!   of a Logon that did not ask for it);
//! - a reset declared on the Logon (an owed reset, found in the store's
//!   marker), crashing at each step of the write order of the Logon (file and
//!   persist in one call, spend, write) and of its acknowledgement;
//! - the close-time reset (`reset_on_disconnect`);
//! - the acceptor's reset for a 141=Y Logon, and its close-time reset.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::error::StoreError;
use ironfix_core::message::MsgType;
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::application::NoOpApplication;
use ironfix_engine::{Acceptor, Initiator, OutboundMessage};
use ironfix_session::SessionConfig;
use ironfix_store::{FileStore, FileStoreConfig, MemoryStore, MessageStore, StoredMessage};
use ironfix_tagvalue::{Decoder, Encoder};
use ironfix_transport::FixCodec;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::net::{TcpListener, TcpStream};
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

#[track_caller]
fn comp_id(value: &str) -> CompId {
    ok(CompId::new(value), "test CompId must be valid")
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

fn client_config() -> SessionConfig {
    SessionConfig::new(comp_id("CLIENT"), comp_id("VENUE"), "FIX.4.4")
        .with_heartbeat_interval(Duration::from_secs(30))
}

fn venue_config() -> SessionConfig {
    SessionConfig::new(comp_id("VENUE"), comp_id("CLIENT"), "FIX.4.4")
        .with_heartbeat_interval(Duration::from_secs(30))
}

async fn bind_listener() -> (TcpListener, std::net::SocketAddr) {
    let listener = ok(TcpListener::bind("127.0.0.1:0").await, "bind");
    let addr = ok(listener.local_addr(), "local address");
    (listener, addr)
}

async fn next_frame(framed: &mut Framed<TcpStream, FixCodec>) -> BytesMut {
    match timeout(Duration::from_secs(5), framed.next()).await {
        Ok(Some(Ok(frame))) => frame,
        other => panic!("a frame must arrive within 5s: {other:?}"),
    }
}

/// Every frame that arrives until the stream goes quiet for `quiet`, closes,
/// or fails.
async fn frames_until_quiet(
    framed: &mut Framed<TcpStream, FixCodec>,
    quiet: Duration,
) -> Vec<BytesMut> {
    let mut frames = Vec::new();
    while let Ok(Some(Ok(frame))) = timeout(quiet, framed.next()).await {
        frames.push(frame);
    }
    frames
}

// ---------------------------------------------------------------------------
// The crashing store
// ---------------------------------------------------------------------------

/// A store call a crash can be armed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    /// `set_reset_owed(value)`.
    Marker(bool),
    /// `reset_to`.
    ResetTo,
    /// `reset`.
    Reset,
    /// `file_outbound`.
    FileOutbound,
    /// `set_next_target_seq`.
    Target,
}

/// Whether the crash happens before the call takes effect or after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum When {
    Before,
    After,
}

/// Where a store crashes: the `nth` (from 0) occurrence of `call`, `when`.
#[derive(Debug, Clone, Copy)]
struct CrashPoint {
    call: Call,
    nth: u32,
    when: When,
}

const fn at(call: Call, when: When) -> CrashPoint {
    CrashPoint { call, nth: 0, when }
}

/// Wraps a store; once it crashes the wrapped store is let go and every call
/// hangs forever, so nothing after the crash reaches it.
struct CrashStore {
    inner: Mutex<Option<Arc<dyn MessageStore>>>,
    point: Option<CrashPoint>,
    seen: AtomicU32,
    crashed: AtomicBool,
}

impl CrashStore {
    fn new(inner: Arc<dyn MessageStore>, point: Option<CrashPoint>) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Some(inner)),
            point,
            seen: AtomicU32::new(0),
            crashed: AtomicBool::new(false),
        })
    }

    fn inner(&self) -> Option<Arc<dyn MessageStore>> {
        match self.inner.lock() {
            Ok(inner) => inner.clone(),
            Err(_) => panic!("crash store lock poisoned"),
        }
    }

    /// Crashes now: lets the wrapped store go.
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

    /// Runs before a mutation: hangs if the store has crashed or crashes
    /// here; otherwise returns the wrapped store and whether to crash once
    /// the call has taken effect.
    async fn before(&self, call: Call) -> (Arc<dyn MessageStore>, bool) {
        let mut crash_after = false;
        if let Some(point) = self.point
            && point.call == call
            && !self.has_crashed()
        {
            let seen = self.seen.fetch_add(1, Ordering::SeqCst);
            if seen == point.nth {
                match point.when {
                    When::Before => self.crash(),
                    When::After => crash_after = true,
                }
            }
        }
        match self.inner() {
            Some(inner) => (inner, crash_after),
            None => std::future::pending().await,
        }
    }

    /// Runs after a mutation took effect: crashes and hangs if armed to.
    async fn after(&self, crash_after: bool) {
        if crash_after {
            self.crash();
            std::future::pending::<()>().await;
        }
    }

    async fn alive(&self) -> Arc<dyn MessageStore> {
        match self.inner() {
            Some(inner) => inner,
            None => std::future::pending().await,
        }
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

    async fn get_page(
        &self,
        begin: u64,
        end: u64,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        self.alive().await.get_page(begin, end, limit).await
    }

    async fn file_outbound(
        &self,
        seq_num: u64,
        msg_type: &MsgType,
        message: &[u8],
        next_sender: u64,
    ) -> Result<(), StoreError> {
        let (inner, crash_after) = self.before(Call::FileOutbound).await;
        let result = inner
            .file_outbound(seq_num, msg_type, message, next_sender)
            .await;
        drop(inner);
        self.after(crash_after).await;
        result
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
        let (inner, crash_after) = self.before(Call::Target).await;
        let result = inner.set_next_target_seq(seq).await;
        drop(inner);
        self.after(crash_after).await;
        result
    }

    async fn reset(&self) -> Result<(), StoreError> {
        let (inner, crash_after) = self.before(Call::Reset).await;
        let result = inner.reset().await;
        drop(inner);
        self.after(crash_after).await;
        result
    }

    async fn reset_to(&self, next_sender: u64, next_target: u64) -> Result<(), StoreError> {
        let (inner, crash_after) = self.before(Call::ResetTo).await;
        let result = inner.reset_to(next_sender, next_target).await;
        drop(inner);
        self.after(crash_after).await;
        result
    }

    fn reset_owed(&self) -> bool {
        self.inner().is_some_and(|inner| inner.reset_owed())
    }

    async fn set_reset_owed(&self, owed: bool) -> Result<(), StoreError> {
        let (inner, crash_after) = self.before(Call::Marker(owed)).await;
        let result = inner.set_reset_owed(owed).await;
        drop(inner);
        self.after(crash_after).await;
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

/// Waits until `store` has crashed.
async fn wait_crashed(store: &CrashStore, what: &str) {
    let crashed = timeout(Duration::from_secs(5), async {
        while !store.has_crashed() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        crashed.is_ok(),
        "{what}: the store never reached its crash point"
    );
}

// ---------------------------------------------------------------------------
// The two store types, across a restart
// ---------------------------------------------------------------------------

/// A directory for one test, removed when it ends.
struct TestDir(std::path::PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ironfix-durable-reset-{name}-{}",
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
        let released = timeout(Duration::from_secs(5), async {
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

/// Files the initiator's previous stream: orders 1..=5 marked OLD-SESSION,
/// the next sender number 6 and the next target 4.
async fn seed_initiator_history(store: &dyn MessageStore) {
    for seq in 1..=5u64 {
        let order = frame("CLIENT", "VENUE", "D", seq, &[(11, "OLD-SESSION")]);
        ok(
            store.store(seq, &MsgType::NewOrderSingle, &order).await,
            "seed an old order",
        );
    }
    ok(store.set_next_sender_seq(6).await, "seed the sender");
    ok(store.set_next_target_seq(4).await, "seed the target");
}

/// Files the acceptor's previous stream: execution reports 1..=3 marked
/// OLD-SESSION, the next sender number 4 and the next target 3.
async fn seed_acceptor_history(store: &dyn MessageStore) {
    for seq in 1..=3u64 {
        let report = frame("VENUE", "CLIENT", "8", seq, &[(17, "OLD-SESSION")]);
        ok(
            store.store(seq, &MsgType::ExecutionReport, &report).await,
            "seed an old report",
        );
    }
    ok(store.set_next_sender_seq(4).await, "seed the sender");
    ok(store.set_next_target_seq(3).await, "seed the target");
}

/// Whether any frame is an application message of the previous stream.
fn replays_old(frames: &[BytesMut]) -> bool {
    frames.iter().any(|frame| {
        field(frame, 11).as_deref() == Some("OLD-SESSION")
            || field(frame, 17).as_deref() == Some("OLD-SESSION")
    })
}

// ---------------------------------------------------------------------------
// The session after the restart
// ---------------------------------------------------------------------------

/// What a restarted initiator did: its Logon's `MsgSeqNum` (34) and
/// `ResetSeqNumFlag` (141), and the frames it answered a full
/// `ResendRequest` with.
#[derive(Debug)]
struct Restarted {
    logon: (Option<String>, Option<String>),
    replies: Vec<BytesMut>,
}

/// Starts a new initiator over `store` and plays the venue: acknowledges its
/// Logon (declaring the reset when the Logon does, at 1; otherwise at
/// `ack_seq`), then asks for the whole stream.
async fn restart_initiator(store: Arc<dyn MessageStore>, ack_seq: u64) -> Restarted {
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (socket, _) = ok(listener.accept().await, "accept");
        let mut framed = Framed::new(socket, FixCodec::new());
        let logon = next_frame(&mut framed).await;
        let declared = field(&logon, 141);
        let ack_seq = if declared.as_deref() == Some("Y") {
            1
        } else {
            ack_seq
        };
        let mut ack = vec![(98, "0"), (108, "30")];
        if declared.as_deref() == Some("Y") {
            ack.push((141, "Y"));
        }
        ok(
            framed
                .send(frame("VENUE", "CLIENT", "A", ack_seq, &ack))
                .await,
            "acknowledge",
        );
        let resend_seq = ack_seq + 1;
        ok(
            framed
                .send(frame(
                    "VENUE",
                    "CLIENT",
                    "2",
                    resend_seq,
                    &[(7, "1"), (16, "0")],
                ))
                .await,
            "ask for the whole stream",
        );
        let replies = frames_until_quiet(&mut framed, Duration::from_millis(500)).await;
        Restarted {
            logon: (field(&logon, 34), declared),
            replies,
        }
    });
    let initiator = Initiator::new(client_config(), Arc::new(NoOpApplication)).with_store(store);
    let connection = ok(
        initiator.connect(addr).await,
        "the restarted initiator connects",
    );
    let restarted = ok(
        ok(
            timeout(Duration::from_secs(10), venue).await,
            "venue within 10s",
        ),
        "venue task",
    );
    drop(connection);
    restarted
}

#[track_caller]
fn assert_reset_declared(restarted: &Restarted, case: &str) {
    assert_eq!(
        restarted.logon,
        (Some("1".to_string()), Some("Y".to_string())),
        "{case}: the restarted Logon starts at 1 and declares ResetSeqNumFlag"
    );
    assert!(
        !replays_old(&restarted.replies),
        "{case}: no frame of the previous stream is replayed: {:?}",
        restarted.replies
    );
}

// ---------------------------------------------------------------------------
// Initiator: the reset on the Logon acknowledgement
// ---------------------------------------------------------------------------

/// The first engine logs on at 6 and gets an ack declaring 141=Y; the store
/// crashes at `point`.
async fn crash_during_ack_reset(durable: &Durable, point: CrashPoint, case: &str) {
    let store = CrashStore::new(Arc::clone(&durable.store), Some(point));
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (socket, _) = ok(listener.accept().await, "accept");
        let mut framed = Framed::new(socket, FixCodec::new());
        let logon = next_frame(&mut framed).await;
        let declared = field(&logon, 141);
        ok(
            framed
                .send(frame(
                    "VENUE",
                    "CLIENT",
                    "A",
                    1,
                    &[(98, "0"), (108, "30"), (141, "Y")],
                ))
                .await,
            "acknowledge with a reset",
        );
        let _ = frames_until_quiet(&mut framed, Duration::from_secs(5)).await;
        (field(&logon, 34), declared)
    });
    let initiator = Initiator::new(client_config(), Arc::new(NoOpApplication))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let connect = tokio::spawn(async move { initiator.connect(addr).await.map(drop) });
    wait_crashed(&store, case).await;
    // The process dies: the engine and its in-memory record are gone.
    connect.abort();
    let _ = connect.await;
    let first_logon = ok(
        ok(
            timeout(Duration::from_secs(10), venue).await,
            "venue within 10s",
        ),
        "venue task",
    );
    assert_eq!(
        first_logon,
        (Some("6".to_string()), None),
        "{case}: the first Logon continues the stored stream"
    );
}

async fn ack_reset_crashes(kind: Kind) {
    // Every crash from the durable marker on: the restart resets and
    // declares it.
    let points = [
        ("marker set", at(Call::Marker(true), When::After)),
        ("before the reset", at(Call::ResetTo, When::Before)),
        ("after the reset", at(Call::ResetTo, When::After)),
        ("before the clear", at(Call::Marker(false), When::Before)),
    ];
    for (index, (case, point)) in points.into_iter().enumerate() {
        let case = format!("{kind:?} ack reset, crash {case}");
        let durable = Durable::new(kind, &format!("ack-{index}")).await;
        seed_initiator_history(durable.store.as_ref()).await;
        crash_during_ack_reset(&durable, point, &case).await;
        let durable = durable.restart().await;
        assert!(durable.store.reset_owed(), "{case}: the marker survives");
        let restarted = restart_initiator(Arc::clone(&durable.store), 2).await;
        assert_reset_declared(&restarted, &case);
        assert!(!durable.store.reset_owed(), "{case}: cleared once declared");
    }

    // A crash once the marker is cleared: the reset was made and the store
    // continues the reset stream at 2, with nothing of the old one left.
    let case = format!("{kind:?} ack reset, crash after the clear");
    let durable = Durable::new(kind, "ack-cleared").await;
    seed_initiator_history(durable.store.as_ref()).await;
    crash_during_ack_reset(&durable, at(Call::Marker(false), When::After), &case).await;
    let durable = durable.restart().await;
    assert!(!durable.store.reset_owed(), "{case}");
    let restarted = restart_initiator(Arc::clone(&durable.store), 2).await;
    assert_eq!(restarted.logon, (Some("2".to_string()), None), "{case}");
    assert!(
        !replays_old(&restarted.replies),
        "{case}: {:?}",
        restarted.replies
    );
}

#[tokio::test]
async fn test_initiator_ack_reset_survives_a_crash_memory_store() {
    ack_reset_crashes(Kind::Memory).await;
}

#[tokio::test]
async fn test_initiator_ack_reset_survives_a_crash_file_store() {
    ack_reset_crashes(Kind::File).await;
}

// ---------------------------------------------------------------------------
// Initiator: a reset declared on the Logon, at each step of the write order
// ---------------------------------------------------------------------------

/// The engine restarts over a store whose marker is set (a reset owed by the
/// process before) and crashes at `point` while paying it. When `ack` is
/// false the venue never acknowledges, and the process dies once the Logon
/// is on the wire.
async fn crash_during_owed_reset(
    durable: &Durable,
    point: Option<CrashPoint>,
    ack: bool,
    case: &str,
) {
    let store = CrashStore::new(Arc::clone(&durable.store), point);
    let (listener, addr) = bind_listener().await;
    let (logon_tx, logon_rx) = tokio::sync::oneshot::channel();
    let venue = tokio::spawn(async move {
        let (socket, _) = ok(listener.accept().await, "accept");
        let mut framed = Framed::new(socket, FixCodec::new());
        let logon = next_frame(&mut framed).await;
        let _ = logon_tx.send((field(&logon, 34), field(&logon, 141)));
        if ack {
            ok(
                framed
                    .send(frame(
                        "VENUE",
                        "CLIENT",
                        "A",
                        1,
                        &[(98, "0"), (108, "30"), (141, "Y")],
                    ))
                    .await,
                "acknowledge the reset",
            );
        }
        let _ = frames_until_quiet(&mut framed, Duration::from_secs(5)).await;
    });
    let initiator = Initiator::new(client_config(), Arc::new(NoOpApplication))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let connect = tokio::spawn(async move { initiator.connect(addr).await.map(drop) });
    if point.is_some() {
        wait_crashed(&store, case).await;
    } else {
        // The Logon is written (filed, persisted, spent, on the wire); the
        // process dies before any acknowledgement.
        let logon = ok(
            ok(
                timeout(Duration::from_secs(5), logon_rx).await,
                "Logon within 5s",
            ),
            "Logon seen",
        );
        assert_eq!(
            logon,
            (Some("1".to_string()), Some("Y".to_string())),
            "{case}"
        );
        store.crash();
    }
    connect.abort();
    let _ = connect.await;
    venue.abort();
    let _ = venue.await;
}

async fn owed_reset_crashes(kind: Kind) {
    let points = [
        (
            "before the reset",
            Some(at(Call::ResetTo, When::Before)),
            true,
        ),
        (
            "after the reset",
            Some(at(Call::ResetTo, When::After)),
            true,
        ),
        // File (and persist, in one call), before and after.
        (
            "while the Logon is filed",
            Some(at(Call::FileOutbound, When::Before)),
            true,
        ),
        (
            "once the Logon is filed, before it is spent and written",
            Some(at(Call::FileOutbound, When::After)),
            true,
        ),
        // Spent and written, never acknowledged.
        ("once the Logon is written", None, false),
        // Acknowledged: the ack's target number is persisted.
        (
            "while the ack is persisted",
            Some(at(Call::Target, When::Before)),
            true,
        ),
        (
            "once the ack is persisted",
            Some(at(Call::Target, When::After)),
            true,
        ),
        (
            "before the clear",
            Some(at(Call::Marker(false), When::Before)),
            true,
        ),
    ];
    for (index, (case, point, ack)) in points.into_iter().enumerate() {
        let case = format!("{kind:?} owed reset, crash {case}");
        let durable = Durable::new(kind, &format!("owed-{index}")).await;
        seed_initiator_history(durable.store.as_ref()).await;
        // The previous process owed a reset, and recorded it.
        ok(durable.store.set_reset_owed(true).await, "set the marker");
        let durable = durable.restart().await;
        crash_during_owed_reset(&durable, point, ack, &case).await;
        let durable = durable.restart().await;
        assert!(durable.store.reset_owed(), "{case}: the marker survives");
        let restarted = restart_initiator(Arc::clone(&durable.store), 2).await;
        assert_reset_declared(&restarted, &case);
        assert!(!durable.store.reset_owed(), "{case}: cleared once declared");
    }
}

#[tokio::test]
async fn test_initiator_owed_reset_survives_a_crash_at_each_write_step_memory_store() {
    owed_reset_crashes(Kind::Memory).await;
}

#[tokio::test]
async fn test_initiator_owed_reset_survives_a_crash_at_each_write_step_file_store() {
    owed_reset_crashes(Kind::File).await;
}

// ---------------------------------------------------------------------------
// Initiator: the close-time reset
// ---------------------------------------------------------------------------

async fn close_reset_crashes(kind: Kind) {
    let points = [
        (
            "once the marker is set",
            at(Call::Marker(true), When::After),
        ),
        ("before the reset", at(Call::Reset, When::Before)),
        ("after the reset", at(Call::Reset, When::After)),
        ("before the clear", at(Call::Marker(false), When::Before)),
    ];
    for (index, (case, point)) in points.into_iter().enumerate() {
        let case = format!("{kind:?} close-time reset, crash {case}");
        let durable = Durable::new(kind, &format!("close-{index}")).await;
        let store = CrashStore::new(Arc::clone(&durable.store), Some(point));
        let (listener, addr) = bind_listener().await;
        let venue = tokio::spawn(async move {
            let (socket, _) = ok(listener.accept().await, "accept");
            let mut framed = Framed::new(socket, FixCodec::new());
            let _logon = next_frame(&mut framed).await;
            ok(
                framed
                    .send(frame("VENUE", "CLIENT", "A", 1, &[(98, "0"), (108, "30")]))
                    .await,
                "acknowledge",
            );
            for _ in 0..2 {
                let _order = next_frame(&mut framed).await;
            }
            // The venue drops the connection; both sides reset on it.
        });
        let mut config = client_config();
        config.reset_on_disconnect = true;
        let initiator = Initiator::new(config, Arc::new(NoOpApplication))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
        let connection = ok(initiator.connect(addr).await, "connect");
        for index in 0..2 {
            let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
            order
                .push_str(11, "OLD-SESSION")
                .push_str(55, &format!("SYM{index}"))
                .push_char(54, '1');
            ok(connection.send(order).await, "send an order");
        }
        ok(
            ok(
                timeout(Duration::from_secs(10), venue).await,
                "venue within 10s",
            ),
            "venue task",
        );
        wait_crashed(&store, &case).await;
        drop(connection);
        drop(initiator);
        let durable = durable.restart().await;
        assert!(durable.store.reset_owed(), "{case}: the marker survives");
        let restarted = restart_initiator(Arc::clone(&durable.store), 1).await;
        assert_reset_declared(&restarted, &case);
        assert!(!durable.store.reset_owed(), "{case}: cleared once declared");
    }
}

#[tokio::test]
async fn test_initiator_close_time_reset_survives_a_crash_memory_store() {
    close_reset_crashes(Kind::Memory).await;
}

#[tokio::test]
async fn test_initiator_close_time_reset_survives_a_crash_file_store() {
    close_reset_crashes(Kind::File).await;
}

// ---------------------------------------------------------------------------
// Acceptor
// ---------------------------------------------------------------------------

/// What a restarted acceptor did: its acknowledgement's `MsgSeqNum` (34) and
/// `ResetSeqNumFlag` (141), and the frames it answered a full
/// `ResendRequest` with.
async fn restart_acceptor(store: Arc<dyn MessageStore>, logon_seq: u64) -> Restarted {
    let acceptor =
        Arc::new(Acceptor::new(venue_config(), Arc::new(NoOpApplication)).with_store(store));
    let (listener, addr) = bind_listener().await;
    let shared = Arc::clone(&acceptor);
    let venue = tokio::spawn(async move { shared.accept(&listener).await });
    let stream = ok(TcpStream::connect(addr).await, "connect");
    let mut framed = Framed::new(stream, FixCodec::new());
    // The counterparty continues its own stream and asks for no reset.
    ok(
        framed
            .send(frame(
                "CLIENT",
                "VENUE",
                "A",
                logon_seq,
                &[(98, "0"), (108, "30")],
            ))
            .await,
        "send the Logon",
    );
    let ack = next_frame(&mut framed).await;
    let connection = ok(
        ok(
            timeout(Duration::from_secs(5), venue).await,
            "handshake within 5s",
        ),
        "venue task",
    );
    let connection = ok(connection, "the restarted acceptor establishes the session");
    ok(
        framed
            .send(frame(
                "CLIENT",
                "VENUE",
                "2",
                logon_seq + 1,
                &[(7, "1"), (16, "0")],
            ))
            .await,
        "ask for the whole stream",
    );
    let replies = frames_until_quiet(&mut framed, Duration::from_millis(500)).await;
    drop(connection);
    Restarted {
        logon: (field(&ack, 34), field(&ack, 141)),
        replies,
    }
}

async fn acceptor_crashes(kind: Kind) {
    // The counterparty asks for a reset (141=Y); the acceptor crashes while
    // making it.
    let points = [
        ("before the reset", at(Call::ResetTo, When::Before)),
        ("after the reset", at(Call::ResetTo, When::After)),
        ("once the ack is filed", at(Call::FileOutbound, When::After)),
        ("before the clear", at(Call::Marker(false), When::Before)),
    ];
    for (index, (case, point)) in points.into_iter().enumerate() {
        let case = format!("{kind:?} acceptor 141=Y Logon, crash {case}");
        let durable = Durable::new(kind, &format!("acceptor-{index}")).await;
        seed_acceptor_history(durable.store.as_ref()).await;
        let store = CrashStore::new(Arc::clone(&durable.store), Some(point));
        let acceptor = Arc::new(
            Acceptor::new(venue_config(), Arc::new(NoOpApplication))
                .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
        );
        let (listener, addr) = bind_listener().await;
        let shared = Arc::clone(&acceptor);
        let serve = tokio::spawn(async move { shared.accept(&listener).await.map(drop) });
        let stream = ok(TcpStream::connect(addr).await, "connect");
        let mut framed = Framed::new(stream, FixCodec::new());
        ok(
            framed
                .send(frame(
                    "CLIENT",
                    "VENUE",
                    "A",
                    1,
                    &[(98, "0"), (108, "30"), (141, "Y")],
                ))
                .await,
            "send a resetting Logon",
        );
        wait_crashed(&store, &case).await;
        serve.abort();
        let _ = serve.await;
        drop(acceptor);
        drop(framed);
        let durable = durable.restart().await;
        assert!(durable.store.reset_owed(), "{case}: the marker survives");
        let restarted = restart_acceptor(Arc::clone(&durable.store), 2).await;
        assert_reset_declared(&restarted, &case);
        assert!(!durable.store.reset_owed(), "{case}: cleared once declared");
    }

    // The close-time reset (`reset_on_disconnect`), crashing before it lands.
    let case = format!("{kind:?} acceptor close-time reset, crash before the reset");
    let durable = Durable::new(kind, "acceptor-close").await;
    seed_acceptor_history(durable.store.as_ref()).await;
    let store = CrashStore::new(
        Arc::clone(&durable.store),
        Some(at(Call::Reset, When::Before)),
    );
    let mut config = venue_config();
    config.reset_on_disconnect = true;
    let acceptor = Arc::new(
        Acceptor::new(config, Arc::new(NoOpApplication))
            .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
    );
    let (listener, addr) = bind_listener().await;
    let shared = Arc::clone(&acceptor);
    let serve = tokio::spawn(async move { shared.accept(&listener).await });
    let stream = ok(TcpStream::connect(addr).await, "connect");
    let mut framed = Framed::new(stream, FixCodec::new());
    ok(
        framed
            .send(frame("CLIENT", "VENUE", "A", 3, &[(98, "0"), (108, "30")]))
            .await,
        "send the Logon",
    );
    let _ack = next_frame(&mut framed).await;
    let connection = ok(
        ok(
            timeout(Duration::from_secs(5), serve).await,
            "handshake within 5s",
        ),
        "serve task",
    );
    let connection = ok(connection, "establish");
    drop(framed);
    wait_crashed(&store, &case).await;
    drop(connection);
    drop(acceptor);
    let durable = durable.restart().await;
    assert!(durable.store.reset_owed(), "{case}: the marker survives");
    let restarted = restart_acceptor(Arc::clone(&durable.store), 4).await;
    assert_reset_declared(&restarted, &case);
}

#[tokio::test]
async fn test_acceptor_reset_survives_a_crash_memory_store() {
    acceptor_crashes(Kind::Memory).await;
}

#[tokio::test]
async fn test_acceptor_reset_survives_a_crash_file_store() {
    acceptor_crashes(Kind::File).await;
}

// ---------------------------------------------------------------------------
// No crash: unchanged behaviour
// ---------------------------------------------------------------------------

/// Without a crash a `MemoryStore` session never sets the marker: a plain
/// Logon and close write nothing to it, and a reset paid in the handshake
/// leaves it clear.
#[tokio::test]
async fn test_memory_store_marker_stays_clear_without_a_crash() {
    let store: Arc<dyn MessageStore> = Arc::new(MemoryStore::new());
    seed_initiator_history(store.as_ref()).await;
    let restarted = restart_initiator(Arc::clone(&store), 4).await;
    assert_eq!(restarted.logon, (Some("6".to_string()), None));
    assert!(!store.reset_owed());

    // A Logon ack that resets: the marker is set for the reset and cleared
    // before `on_logon`.
    let durable = Durable::new(Kind::Memory, "no-crash").await;
    seed_initiator_history(durable.store.as_ref()).await;
    let store = CrashStore::new(Arc::clone(&durable.store), None);
    let (listener, addr) = bind_listener().await;
    let venue = tokio::spawn(async move {
        let (socket, _) = ok(listener.accept().await, "accept");
        let mut framed = Framed::new(socket, FixCodec::new());
        let _logon = next_frame(&mut framed).await;
        ok(
            framed
                .send(frame(
                    "VENUE",
                    "CLIENT",
                    "A",
                    1,
                    &[(98, "0"), (108, "30"), (141, "Y")],
                ))
                .await,
            "acknowledge with a reset",
        );
        framed
    });
    let initiator = Initiator::new(client_config(), Arc::new(NoOpApplication))
        .with_store(Arc::clone(&store) as Arc<dyn MessageStore>);
    let connection = ok(initiator.connect(addr).await, "connect");
    assert!(!durable.store.reset_owed(), "cleared before on_logon");
    assert_eq!(durable.store.next_sender_seq(), 2);
    let _framed = ok(venue.await, "venue task");
    drop(connection);
}
