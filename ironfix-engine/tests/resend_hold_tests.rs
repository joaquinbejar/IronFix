/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 19/10/26
******************************************************************************/

//! Integration tests for the hold behind an outbound resend (issue #128), in
//! both roles.
//!
//! While a session answers a `ResendRequest`, every message that takes a new
//! `MsgSeqNum` is held back and written once the resend is done, and a
//! Logout from the counterparty is answered after it. These tests pin the
//! hardening of that hold:
//!
//! - the hold is bounded by bytes as well as by count: a flood of TestRequests
//!   with large `TestReqID` (112) values stops the reading long before 1024 are
//!   held, and a flood of small ones stops it at 1024; every one is answered
//!   afterwards, in order;
//! - the owed Logout's timeout runs from the counterparty's first Logout, not
//!   a repeated one, and is checked between the messages written after the
//!   resend;
//! - a held `ResendRequest` costs a `max_resend_requests` attempt only when it
//!   is written: one a `to_admin` callback drops costs none;
//! - a spanning possible-duplicate gap fill draws no re-request once this
//!   session's Logout is out;
//! - a held `ResendRequest` is skipped when the gap closed meanwhile, a resend
//!   asked for after this session's Logout is still answered, and no
//!   Heartbeat or TestRequest is written inside a resend longer than
//!   `HeartBtInt` (108).
//!
//! A scripted counterparty plays the other role over an in-memory pipe.
//! Timing-dependent tests run on a paused Tokio clock wherever the deadline
//! under test reads it; the two that exercise deadlines still read from
//! `std::time::Instant` in the session layer (the resend retry timeout and the
//! heartbeat interval) run in real time with short intervals.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::error::StoreError;
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::application::{Application, RejectReason, SessionId};
use ironfix_engine::{Acceptor, Connection, Initiator, OutboundMessage};
use ironfix_session::SessionConfig;
use ironfix_store::{MemoryStore, MessageStore, StoredMessage};
use ironfix_tagvalue::{Decoder, Encoder};
use ironfix_transport::FixCodec;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::DuplexStream;
use tokio::time::{Instant, timeout};
use tokio_util::codec::Framed;

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

impl Role {
    /// The engine's (SenderCompID, TargetCompID).
    const fn ids(self) -> (&'static str, &'static str) {
        match self {
            Self::Acceptor => ("VENUE", "CLIENT"),
            Self::Initiator => ("CLIENT", "VENUE"),
        }
    }

    /// The engine's FIX.4.4 configuration with a `heartbeat` interval.
    fn config(self, heartbeat: Duration) -> SessionConfig {
        let (sender, target) = self.ids();
        SessionConfig::new(comp_id(sender), comp_id(target), "FIX.4.4")
            .with_heartbeat_interval(heartbeat)
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

/// A frame's MsgType.
fn msg_type_of(frame: &[u8]) -> String {
    field(frame, 35).unwrap_or_default()
}

/// A frame's `MsgSeqNum`, or 0.
fn seq_of(frame: &[u8]) -> u64 {
    field(frame, 34)
        .and_then(|seq| seq.parse().ok())
        .unwrap_or(0)
}

/// Whether a frame is a possible duplicate (part of a resend).
fn poss_dup(frame: &[u8]) -> bool {
    field(frame, 43).as_deref() == Some("Y")
}

type PeerFramed = Framed<DuplexStream, FixCodec>;

/// Reads the next frame, within 60 s (of the paused clock, where it is).
async fn next_frame(framed: &mut PeerFramed) -> BytesMut {
    match timeout(Duration::from_secs(60), framed.next()).await {
        Ok(Some(Ok(frame))) => frame,
        Ok(Some(Err(err))) => panic!("frame must decode: {err:?}"),
        Ok(None) => panic!("the engine hung up"),
        Err(_) => panic!("no frame within 60s"),
    }
}

/// Asserts the engine sends nothing for `wait`.
async fn assert_silent(framed: &mut PeerFramed, wait: Duration, what: &str) {
    if let Ok(Some(Ok(frame))) = timeout(wait, framed.next()).await {
        panic!(
            "{what}: unexpected {} {}",
            msg_type_of(&frame),
            seq_of(&frame)
        );
    }
}

/// Reads the resend answering a `ResendRequest` from 2 over a backlog of
/// `backlog` messages: the replays 2..=backlog+1, then the gap fill for the
/// engine's Logon (or acknowledgement) at backlog+2. Asserts it is whole and
/// in order.
async fn read_resend(framed: &mut PeerFramed, backlog: u64) {
    for seq in 2..=backlog + 2 {
        let frame = next_frame(framed).await;
        assert_eq!(seq_of(&frame), seq, "resent in order");
        assert!(poss_dup(&frame), "nothing new inside the resend ({seq})");
    }
}

/// Records session events; optionally drops the first `ResendRequest` it is
/// handed by leaving it unframeable.
#[derive(Debug, Default)]
struct App {
    drop_first_resend_request: bool,
    dropped: AtomicBool,
    logged_out: AtomicBool,
}

#[async_trait]
impl Application for App {
    async fn on_create(&self, _session_id: &SessionId) {}

    async fn on_logon(&self, _session_id: &SessionId) {}

    async fn on_logout(&self, _session_id: &SessionId) {
        self.logged_out.store(true, Ordering::SeqCst);
    }

    async fn to_admin(&self, message: &mut OutboundMessage, _session_id: &SessionId) {
        if self.drop_first_resend_request
            && message.msg_type() == &MsgType::ResendRequest
            && !self.dropped.swap(true, Ordering::SeqCst)
        {
            // An empty value has no wire form: the engine drops the message.
            message.push_raw(58, Vec::new());
        }
    }

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
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }
}

/// A store whose page reads and writes can be slowed on the Tokio clock.
#[derive(Debug)]
struct SlowStore {
    inner: MemoryStore,
    page_delay: Duration,
    store_delay: Duration,
    /// Writes are slowed only once armed, after the handshake.
    armed: AtomicBool,
}

impl SlowStore {
    /// The engine's previous stream: its Logon (1) and `backlog` reports (2
    /// to backlog+1), each padded with `pad` bytes of `Text` (58); next
    /// sender backlog+2, next target 3.
    async fn backlog(role: Role, backlog: u64, pad: usize) -> Self {
        let inner = MemoryStore::new();
        ok(
            inner
                .store(
                    1,
                    &MsgType::Logon,
                    &role.engine_msg("A", 1, &[(98, "0"), (108, "30")]),
                )
                .await,
            "seed the Logon",
        );
        let padding = "x".repeat(pad);
        let mut body = vec![(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")];
        if pad > 0 {
            body.push((58, padding.as_str()));
        }
        for seq in 2..=backlog + 1 {
            ok(
                inner
                    .store(
                        seq,
                        &MsgType::ExecutionReport,
                        &role.engine_msg("8", seq, &body),
                    )
                    .await,
                "seed a report",
            );
        }
        ok(
            inner.set_next_sender_seq(backlog + 2).await,
            "seed the sender counter",
        );
        ok(
            inner.set_next_target_seq(3).await,
            "seed the target counter",
        );
        Self {
            inner,
            page_delay: Duration::ZERO,
            store_delay: Duration::ZERO,
            armed: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl MessageStore for SlowStore {
    async fn store(
        &self,
        seq_num: u64,
        msg_type: &MsgType,
        message: &[u8],
    ) -> Result<(), StoreError> {
        if self.armed.load(Ordering::SeqCst) && !self.store_delay.is_zero() {
            tokio::time::sleep(self.store_delay).await;
        }
        self.inner.store(seq_num, msg_type, message).await
    }

    async fn get_range(&self, begin: u64, end: u64) -> Result<Vec<StoredMessage>, StoreError> {
        if !self.page_delay.is_zero() {
            tokio::time::sleep(self.page_delay).await;
        }
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

/// How a test opens its session.
struct Setup {
    role: Role,
    config: SessionConfig,
    store: Option<Arc<SlowStore>>,
    app: Arc<App>,
    /// The pipe's capacity: small, so a resend outgrows it and stays under
    /// way while the peer does not read.
    pipe: usize,
    /// `HeartBtInt` (108) in the peer's Logon or acknowledgement.
    heartbeat: &'static str,
}

impl Setup {
    fn new(role: Role) -> Self {
        Self {
            role,
            config: role.config(Duration::from_secs(30)),
            store: None,
            app: Arc::new(App::default()),
            pipe: 4 * 1024,
            heartbeat: "30",
        }
    }

    /// Logs the session on: the peer's Logon (or acknowledgement) is numbered
    /// `peer_seq`. Returns the peer's end of the pipe and the connection.
    async fn open(&self, peer_seq: u64) -> (PeerFramed, Connection) {
        let (peer_io, engine_io) = tokio::io::duplex(self.pipe);
        let config = self.config.clone();
        let app = Arc::clone(&self.app);
        let store = self
            .store
            .as_ref()
            .map(|store| Arc::clone(store) as Arc<dyn MessageStore>);
        let write_timeout = Duration::from_secs(600);
        let engine = match self.role {
            Role::Acceptor => tokio::spawn(async move {
                let mut acceptor = Acceptor::new(config, app).with_write_timeout(write_timeout);
                if let Some(store) = store {
                    acceptor = acceptor.with_store(store);
                }
                acceptor.serve_stream(engine_io).await
            }),
            Role::Initiator => tokio::spawn(async move {
                let mut initiator = Initiator::new(config, app).with_write_timeout(write_timeout);
                if let Some(store) = store {
                    initiator = initiator.with_store(store);
                }
                initiator.establish(engine_io).await
            }),
        };
        let mut framed = Framed::new(peer_io, FixCodec::new());
        let logon = self
            .role
            .peer_msg("A", peer_seq, &[(98, "0"), (108, self.heartbeat)]);
        if self.role == Role::Initiator {
            let theirs = next_frame(&mut framed).await;
            assert_eq!(msg_type_of(&theirs), "A", "the initiator logs on");
        }
        ok(framed.send(logon).await, "the peer's Logon");
        if self.role == Role::Acceptor {
            let ack = next_frame(&mut framed).await;
            assert_eq!(msg_type_of(&ack), "A", "the Logon is acknowledged");
        }
        let connection = ok(
            ok(
                ok(
                    timeout(Duration::from_secs(5), engine).await,
                    "handshake within 5s",
                ),
                "engine task joins",
            ),
            "the engine establishes the session",
        );
        if let Some(store) = &self.store {
            store.armed.store(true, Ordering::SeqCst);
        }
        (framed, connection)
    }
}

/// A `ResendRequest` (2) from the peer for everything from 2.
fn resend_all(role: Role, seq: u64) -> BytesMut {
    role.peer_msg("2", seq, &[(7, "2"), (16, "0")])
}

// ---------------------------------------------------------------------------
// The hold's bounds
// ---------------------------------------------------------------------------

/// The peer asks for a resend of a padded 300-report backlog, then, without
/// reading, sends `count` TestRequests whose `TestReqID` is `id_len` bytes.
/// The engine stops reading once its hold is full, so the peer's writes block
/// (`expect_blocked`); once the peer reads, the resend comes whole, then a
/// Heartbeat for every TestRequest, in order, under consecutive numbers.
async fn flood_behind_a_resend(role: Role, count: u64, id_len: usize, expect_blocked: bool) {
    let mut setup = Setup::new(role);
    setup.store = Some(Arc::new(SlowStore::backlog(role, 300, 500).await));
    setup.config = setup.config.with_max_message_size(1024 * 1024);
    let (framed, connection) = setup.open(3).await;
    let (mut sink, mut stream) = framed.split();
    let id = "x".repeat(id_len);
    let sender = tokio::spawn(async move {
        ok(sink.send(resend_all(role, 4)).await, "the ResendRequest");
        for n in 0..count {
            let req_id = format!("{n}-{id}");
            ok(
                sink.send(role.peer_msg("1", 5 + n, &[(112, req_id.as_str())]))
                    .await,
                "a TestRequest",
            );
        }
        sink
    });
    let sender = if expect_blocked {
        let mut sender = sender;
        assert!(
            timeout(Duration::from_secs(5), &mut sender).await.is_err(),
            "the engine stopped reading once its hold was full"
        );
        sender
    } else {
        sender
    };
    for seq in 2..=302u64 {
        let frame = match timeout(Duration::from_secs(60), stream.next()).await {
            Ok(Some(Ok(frame))) => frame,
            other => panic!("resend frame {seq}: {other:?}"),
        };
        assert_eq!(seq_of(&frame), seq, "resent in order");
        assert!(poss_dup(&frame), "nothing new inside the resend ({seq})");
    }
    for n in 0..count {
        let frame = match timeout(Duration::from_secs(60), stream.next()).await {
            Ok(Some(Ok(frame))) => frame,
            other => panic!("heartbeat {n}: {other:?}"),
        };
        assert_eq!(
            msg_type_of(&frame),
            "0",
            "a Heartbeat answers TestRequest {n}"
        );
        assert_eq!(seq_of(&frame), 303 + n, "under consecutive numbers");
        let echoed = field(&frame, 112).unwrap_or_default();
        assert!(echoed.starts_with(&format!("{n}-")), "in order: {n}");
        assert_eq!(echoed.len(), format!("{n}-").len() + id_len);
    }
    let _sink = ok(
        timeout(Duration::from_secs(60), sender).await,
        "the peer's writes complete once the hold drains",
    );
    assert!(
        timeout(Duration::from_millis(500), stream.next())
            .await
            .is_err(),
        "nothing more"
    );
    assert!(!connection.is_closed(), "the session stays up");
}

/// Large `TestReqID` echoes fill the byte budget long before the count bound:
/// 120 echoes of 60 KB would hold about 7 MB, so reading stops at about 4 MiB.
#[tokio::test(start_paused = true)]
async fn test_acceptor_hold_is_bounded_by_bytes() {
    flood_behind_a_resend(Role::Acceptor, 120, 60_000, true).await;
}

/// As [`test_acceptor_hold_is_bounded_by_bytes`], with the engine initiating.
#[tokio::test(start_paused = true)]
async fn test_initiator_hold_is_bounded_by_bytes() {
    flood_behind_a_resend(Role::Initiator, 120, 60_000, true).await;
}

/// Small TestRequests go past the 1024 count bound: reading stops there, and
/// every one is still answered after the resend, in order.
#[tokio::test(start_paused = true)]
async fn test_acceptor_hold_goes_past_the_count_bound() {
    flood_behind_a_resend(Role::Acceptor, 1_100, 8, true).await;
}

/// As [`test_acceptor_hold_goes_past_the_count_bound`], with the engine
/// initiating.
#[tokio::test(start_paused = true)]
async fn test_initiator_hold_goes_past_the_count_bound() {
    flood_behind_a_resend(Role::Initiator, 1_100, 8, true).await;
}

// ---------------------------------------------------------------------------
// The owed Logout's clock
// ---------------------------------------------------------------------------

/// The peer asks for a resend that takes about 20 s (a page of 256 entries
/// per second) and logs out right behind it, then logs out again 6 s later.
/// The logout timeout (10 s) runs from the first Logout: the reply comes about
/// 10 s after it, not 10 s after the second.
async fn repeated_logout_keeps_the_first_deadline(role: Role) {
    let mut setup = Setup::new(role);
    let mut store = SlowStore::backlog(role, 256 * 20, 0).await;
    store.page_delay = Duration::from_secs(1);
    setup.store = Some(Arc::new(store));
    setup.config = setup.config.with_logout_timeout(Duration::from_secs(10));
    setup.pipe = 1024 * 1024;
    let (framed, connection) = setup.open(3).await;
    let (mut sink, mut stream) = framed.split();
    let reader = tokio::spawn(async move {
        loop {
            match stream.next().await {
                Some(Ok(frame)) if msg_type_of(&frame) == "5" => break Some(Instant::now()),
                Some(Ok(_)) => {}
                _ => break None,
            }
        }
    });
    ok(sink.send(resend_all(role, 4)).await, "the ResendRequest");
    ok(
        sink.send(role.peer_msg("5", 5, &[(58, "first")])).await,
        "the first Logout",
    );
    let first = Instant::now();
    tokio::time::sleep(Duration::from_secs(6)).await;
    ok(
        sink.send(role.peer_msg("5", 6, &[(58, "second")])).await,
        "a repeated Logout",
    );
    let replied = ok(
        timeout(Duration::from_secs(60), reader).await,
        "the reply within 60s",
    );
    let replied = ok(replied, "reader task").unwrap_or_else(|| panic!("no Logout reply"));
    let waited = replied.duration_since(first);
    assert!(
        waited >= Duration::from_secs(10) && waited < Duration::from_secs(13),
        "the logout timeout runs from the first Logout: replied after {waited:?}"
    );
    ok(
        timeout(Duration::from_secs(30), connection.wait_closed()).await,
        "the session closes",
    );
}

/// A repeated Logout does not restart the owed Logout's clock (acceptor).
#[tokio::test(start_paused = true)]
async fn test_acceptor_repeated_logout_keeps_the_first_deadline() {
    repeated_logout_keeps_the_first_deadline(Role::Acceptor).await;
}

/// A repeated Logout does not restart the owed Logout's clock (initiator).
#[tokio::test(start_paused = true)]
async fn test_initiator_repeated_logout_keeps_the_first_deadline() {
    repeated_logout_keeps_the_first_deadline(Role::Initiator).await;
}

/// The peer asks for a resend, sends 20 TestRequests and logs out, all before
/// reading. Every write to the store takes 1 s, so the 20 Heartbeats held
/// behind the resend would take 20 s to write; the logout timeout (5 s) is
/// checked between them, so the reply cuts them short.
async fn owed_logout_deadline_between_held_messages(role: Role) {
    let mut setup = Setup::new(role);
    let mut store = SlowStore::backlog(role, 300, 500).await;
    store.store_delay = Duration::from_secs(1);
    setup.store = Some(Arc::new(store));
    setup.config = setup.config.with_logout_timeout(Duration::from_secs(5));
    let (mut framed, connection) = setup.open(3).await;
    ok(framed.send(resend_all(role, 4)).await, "the ResendRequest");
    for n in 0..20u64 {
        let req_id = format!("T{n}");
        ok(
            framed
                .send(role.peer_msg("1", 5 + n, &[(112, req_id.as_str())]))
                .await,
            "a TestRequest",
        );
    }
    ok(framed.send(role.peer_msg("5", 25, &[])).await, "the Logout");
    // The engine reads all of it while its resend waits on the pipe.
    tokio::time::sleep(Duration::from_millis(50)).await;
    read_resend(&mut framed, 300).await;
    let mut heartbeats = 0u64;
    loop {
        let frame = next_frame(&mut framed).await;
        match msg_type_of(&frame).as_str() {
            "0" => {
                heartbeats += 1;
                assert_eq!(seq_of(&frame), 302 + heartbeats, "in order");
            }
            "5" => {
                assert_eq!(seq_of(&frame), 303 + heartbeats, "the reply comes last");
                break;
            }
            other => panic!("unexpected {other}"),
        }
    }
    assert!(
        heartbeats < 20,
        "the owed Logout's deadline cut the held Heartbeats short: {heartbeats} written"
    );
    ok(
        timeout(Duration::from_secs(30), connection.wait_closed()).await,
        "the session closes",
    );
}

/// The owed Logout's deadline is checked between held messages (acceptor).
#[tokio::test(start_paused = true)]
async fn test_acceptor_owed_logout_deadline_between_held_messages() {
    owed_logout_deadline_between_held_messages(Role::Acceptor).await;
}

/// The owed Logout's deadline is checked between held messages (initiator).
#[tokio::test(start_paused = true)]
async fn test_initiator_owed_logout_deadline_between_held_messages() {
    owed_logout_deadline_between_held_messages(Role::Initiator).await;
}

// ---------------------------------------------------------------------------
// ResendRequest accounting
// ---------------------------------------------------------------------------

/// With `max_resend_requests` = 1, a gap opens while the engine resends, so
/// its `ResendRequest` is held; `to_admin` then drops that request when it is
/// written. It never went out, so it costs no attempt: once the gap stalls,
/// a real request goes out instead of a Logout.
///
/// Real time: the resend retry timeout reads `std::time::Instant`.
async fn dropped_held_request_costs_no_attempt(role: Role) {
    let mut setup = Setup::new(role);
    setup.store = Some(Arc::new(SlowStore::backlog(role, 300, 500).await));
    setup.config = setup
        .config
        .with_max_resend_requests(1)
        .with_resend_timeout(Duration::from_millis(300));
    setup.app = Arc::new(App {
        drop_first_resend_request: true,
        ..App::default()
    });
    let (mut framed, connection) = setup.open(3).await;
    ok(framed.send(resend_all(role, 4)).await, "the ResendRequest");
    // 5 is skipped: a gap opens while the resend is under way.
    ok(
        framed.send(role.peer_msg("0", 6, &[])).await,
        "a gapped Heartbeat",
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    read_resend(&mut framed, 300).await;
    let next = next_frame(&mut framed).await;
    assert_eq!(
        msg_type_of(&next),
        "2",
        "a real ResendRequest, not a Logout: the dropped one cost no attempt"
    );
    assert_eq!(field(&next, 7).as_deref(), Some("5"));
    assert_eq!(seq_of(&next), 303, "the dropped request spent no number");
    assert!(setup.app.dropped.load(Ordering::SeqCst), "one was dropped");
    assert!(!connection.is_closed());
}

/// A held ResendRequest dropped at write time costs no attempt (acceptor).
#[tokio::test]
async fn test_acceptor_dropped_held_request_costs_no_attempt() {
    dropped_held_request_costs_no_attempt(Role::Acceptor).await;
}

/// A held ResendRequest dropped at write time costs no attempt (initiator).
#[tokio::test]
async fn test_initiator_dropped_held_request_costs_no_attempt() {
    dropped_held_request_costs_no_attempt(Role::Initiator).await;
}

/// A gap opens while the engine resends, so its `ResendRequest` is held;
/// the peer then fills the gap before the resend is done. The held request is
/// skipped: after the resend comes the Heartbeat answering a later
/// TestRequest, and nothing else.
async fn held_request_skipped_when_the_gap_closed(role: Role) {
    let mut setup = Setup::new(role);
    setup.store = Some(Arc::new(SlowStore::backlog(role, 300, 500).await));
    let (mut framed, connection) = setup.open(3).await;
    ok(framed.send(resend_all(role, 4)).await, "the ResendRequest");
    ok(
        framed.send(role.peer_msg("0", 6, &[])).await,
        "a gapped Heartbeat",
    );
    ok(
        framed.send(role.peer_msg("0", 5, &[])).await,
        "the missing 5",
    );
    ok(
        framed.send(role.peer_msg("0", 6, &[])).await,
        "6 again, in order",
    );
    ok(
        framed.send(role.peer_msg("1", 7, &[(112, "END")])).await,
        "a TestRequest",
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    read_resend(&mut framed, 300).await;
    let heartbeat = next_frame(&mut framed).await;
    assert_eq!(
        msg_type_of(&heartbeat),
        "0",
        "no ResendRequest: the gap closed"
    );
    assert_eq!(field(&heartbeat, 112).as_deref(), Some("END"));
    assert_eq!(seq_of(&heartbeat), 303);
    assert_silent(&mut framed, Duration::from_secs(1), "nothing more").await;
    assert!(!connection.is_closed());
}

/// A held ResendRequest is skipped when the gap closed (acceptor).
#[tokio::test(start_paused = true)]
async fn test_acceptor_held_request_skipped_when_the_gap_closed() {
    held_request_skipped_when_the_gap_closed(Role::Acceptor).await;
}

/// A held ResendRequest is skipped when the gap closed (initiator).
#[tokio::test(start_paused = true)]
async fn test_initiator_held_request_skipped_when_the_gap_closed() {
    held_request_skipped_when_the_gap_closed(Role::Initiator).await;
}

// ---------------------------------------------------------------------------
// After this session's own Logout
// ---------------------------------------------------------------------------

/// The engine logs out; the peer then sends a possible-duplicate gap fill
/// below the expectation whose `NewSeqNo` spans past it. While Active this
/// draws a re-request; once the engine's Logout is out it draws nothing.
async fn no_rerequest_after_our_logout(role: Role) {
    let setup = Setup::new(role);
    let (mut framed, connection) = setup.open(1).await;
    ok(connection.logout().await, "the engine logs out");
    let logout = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&logout), "5");
    ok(
        framed
            .send(role.peer_msg(
                "4",
                1,
                &[
                    (43, "Y"),
                    (122, "20261019-12:00:00.000"),
                    (123, "Y"),
                    (36, "5"),
                ],
            ))
            .await,
        "a spanning possible-duplicate gap fill",
    );
    assert_silent(
        &mut framed,
        Duration::from_secs(1),
        "no re-request once the engine's Logout is out",
    )
    .await;
    ok(
        framed.send(role.peer_msg("5", 2, &[])).await,
        "the peer acknowledges",
    );
    ok(
        timeout(Duration::from_secs(30), connection.wait_closed()).await,
        "the session closes",
    );
}

/// No spanning-fill re-request after this session's Logout (acceptor).
#[tokio::test(start_paused = true)]
async fn test_acceptor_no_rerequest_after_our_logout() {
    no_rerequest_after_our_logout(Role::Acceptor).await;
}

/// No spanning-fill re-request after this session's Logout (initiator).
#[tokio::test(start_paused = true)]
async fn test_initiator_no_rerequest_after_our_logout() {
    no_rerequest_after_our_logout(Role::Initiator).await;
}

/// The engine logs out; the peer then asks for a resend. It is still
/// answered (FIX allows it), then the peer's Logout completes the exchange.
async fn resend_after_our_logout_is_answered(role: Role) {
    let mut setup = Setup::new(role);
    setup.store = Some(Arc::new(SlowStore::backlog(role, 300, 0).await));
    let (mut framed, connection) = setup.open(3).await;
    ok(connection.logout().await, "the engine logs out");
    let logout = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&logout), "5");
    assert_eq!(seq_of(&logout), 303);
    ok(framed.send(resend_all(role, 4)).await, "the ResendRequest");
    for seq in 2..=301u64 {
        let frame = next_frame(&mut framed).await;
        assert_eq!(seq_of(&frame), seq, "resent in order");
        assert_eq!(msg_type_of(&frame), "8");
        assert!(poss_dup(&frame));
    }
    let fill = next_frame(&mut framed).await;
    assert_eq!(
        msg_type_of(&fill),
        "4",
        "the Logon and the Logout are gap-filled"
    );
    assert_eq!(seq_of(&fill), 302);
    assert_eq!(field(&fill, 36).as_deref(), Some("304"));
    ok(
        framed.send(role.peer_msg("5", 5, &[])).await,
        "the peer acknowledges",
    );
    ok(
        timeout(Duration::from_secs(30), connection.wait_closed()).await,
        "the session closes",
    );
    assert!(setup.app.logged_out.load(Ordering::SeqCst));
}

/// A resend asked for after this session's Logout is answered (acceptor).
#[tokio::test(start_paused = true)]
async fn test_acceptor_resend_after_our_logout_is_answered() {
    resend_after_our_logout_is_answered(Role::Acceptor).await;
}

/// A resend asked for after this session's Logout is answered (initiator).
#[tokio::test(start_paused = true)]
async fn test_initiator_resend_after_our_logout_is_answered() {
    resend_after_our_logout_is_answered(Role::Initiator).await;
}

// ---------------------------------------------------------------------------
// No idle traffic inside a resend
// ---------------------------------------------------------------------------

/// With `HeartBtInt` 1 s, the peer asks for a resend and does not read for
/// 2.5 s, so the resend lasts longer than the interval. No Heartbeat or
/// TestRequest is written inside it.
///
/// Real time: the heartbeat interval reads `std::time::Instant`.
async fn no_heartbeat_inside_a_long_resend(role: Role) {
    let mut setup = Setup::new(role);
    setup.store = Some(Arc::new(SlowStore::backlog(role, 300, 500).await));
    setup.config = role.config(Duration::from_secs(1));
    setup.heartbeat = "1";
    let (mut framed, connection) = setup.open(3).await;
    ok(framed.send(resend_all(role, 4)).await, "the ResendRequest");
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    read_resend(&mut framed, 300).await;
    assert!(!connection.is_closed(), "the session stays up");
}

/// No Heartbeat or TestRequest inside a long resend (acceptor).
#[tokio::test]
async fn test_acceptor_no_heartbeat_inside_a_long_resend() {
    no_heartbeat_inside_a_long_resend(Role::Acceptor).await;
}

/// No Heartbeat or TestRequest inside a long resend (initiator).
#[tokio::test]
async fn test_initiator_no_heartbeat_inside_a_long_resend() {
    no_heartbeat_inside_a_long_resend(Role::Initiator).await;
}

/// With `max_resend_requests` = 1: while the engine resends, an ordinary gap
/// opens (its request held, to be charged) and closes again; then a
/// possible-duplicate gap fill below the expectation spans past it, opening
/// a new gap whose re-request is not charged. The held request is written
/// for the new gap, which must not inherit the closed gap's charge: when it
/// stalls, one real request still goes out instead of a Logout.
///
/// Real time: the resend retry timeout reads `std::time::Instant`.
async fn closed_gap_charge_does_not_outlive_it(role: Role) {
    let mut setup = Setup::new(role);
    setup.store = Some(Arc::new(SlowStore::backlog(role, 300, 500).await));
    setup.config = setup
        .config
        .with_max_resend_requests(1)
        .with_resend_timeout(Duration::from_millis(300));
    let (mut framed, connection) = setup.open(3).await;
    ok(framed.send(resend_all(role, 4)).await, "the ResendRequest");
    ok(
        framed.send(role.peer_msg("0", 6, &[])).await,
        "a gapped Heartbeat",
    );
    ok(
        framed.send(role.peer_msg("0", 5, &[])).await,
        "the missing 5",
    );
    ok(
        framed.send(role.peer_msg("0", 6, &[])).await,
        "6 again: the gap closed",
    );
    ok(
        framed
            .send(role.peer_msg(
                "4",
                6,
                &[
                    (43, "Y"),
                    (122, "20261019-12:00:00.000"),
                    (123, "Y"),
                    (36, "9"),
                ],
            ))
            .await,
        "a spanning possible-duplicate gap fill",
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    read_resend(&mut framed, 300).await;
    let rerequest = next_frame(&mut framed).await;
    assert_eq!(msg_type_of(&rerequest), "2", "the uncharged re-request");
    assert_eq!(field(&rerequest, 7).as_deref(), Some("7"));
    let retry = next_frame(&mut framed).await;
    assert_eq!(
        msg_type_of(&retry),
        "2",
        "a real retry, not a Logout: the re-request cost no attempt"
    );
    assert_eq!(field(&retry, 7).as_deref(), Some("7"));
    assert!(!connection.is_closed());
}

/// A closed gap's charge does not pass to a later uncharged gap (acceptor).
#[tokio::test]
async fn test_acceptor_closed_gap_charge_does_not_outlive_it() {
    closed_gap_charge_does_not_outlive_it(Role::Acceptor).await;
}

/// A closed gap's charge does not pass to a later uncharged gap (initiator).
#[tokio::test]
async fn test_initiator_closed_gap_charge_does_not_outlive_it() {
    closed_gap_charge_does_not_outlive_it(Role::Initiator).await;
}
