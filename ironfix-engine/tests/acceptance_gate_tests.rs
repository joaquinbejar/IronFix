/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! The joint crash and takeover acceptance gate (issue #89).
//!
//! The pieces this suite composes each have their own tests: the Acceptor's
//! store (#60, ADR-0017), the strict write order and fail-closed policy (#62,
//! ADR-0005), the `FileStore` journal (#78, #112, ADR-0006, ADR-0022), 789 on
//! the Logon (#79, ADR-0021), the durable owed reset (#111, ADR-0029), the
//! inbound loss report (#105, ADR-0030) and the sequence-mismatch report (#80,
//! ADR-0015). This file checks that, together, they keep a FIX session legal
//! across a process crash and a takeover by a standby process.
//!
//! # The harness
//!
//! - **The engine** runs in either role over an in-memory duplex pipe (#63),
//!   with a store attached and [`StoreFailurePolicy::CloseSession`], the only
//!   policy under which the write order is a guarantee.
//! - **The store** is a `FileStore` under `SyncPolicy::EveryWrite` (the
//!   durable configuration), or a `MemoryStore` that outlives the engine. The
//!   `MemoryStore` cases run on a paused clock; the `FileStore` cases cannot,
//!   since the store's writer is an OS thread a paused clock would race, and
//!   they wait on conditions rather than on fixed delays.
//! - **A crash** is a [`CrashStore`] armed at a named point: before or after
//!   a store call takes effect, or between the two halves of a non-atomic
//!   `file_outbound`. At the point it lets the wrapped store go and every later
//!   call hangs forever, as a dead process would: nothing after the crash point
//!   is durable. The dead engine is abandoned, and a **new** engine starts on
//!   the same store (a `FileStore` is dropped without `close` and reopened from
//!   disk). What the store made durable is all the new engine knows.
//! - **The counterparty** is a scripted [`Peer`] that records every frame it
//!   receives, across every engine incarnation, in one [`Ledger`].
//!   [`assert_no_reuse`] checks the ledger after every scenario: no
//!   `MsgSeqNum` ever carries two different messages, and every resent copy is
//!   byte-identical to the original apart from `PossDupFlag` (43),
//!   `OrigSendingTime` (122), `SendingTime` (52), `BodyLength` (9) and
//!   `CheckSum` (10).
//!
//! FIX.4.4 and FIXT.1.1 (FIX.5.0SP2) sessions use `NextExpectedMsgSeqNum`
//! (789) on both sides; FIX.4.2 sessions, which do not define it, recover
//! through `ResendRequest` (2) alone.
//!
//! # What is not tested here
//!
//! An operating-system crash or a power loss: the suite kills the process
//! (the engine and the store object), never the kernel's page cache, so the
//! guarantees of `SyncPolicy::EveryN` and `SyncPolicy::Never` are checked for a
//! process crash only. Fencing, replication and failover time are out of
//! scope (ADR-0015); the split-brain case checks only the single-writer lock
//! and the Acceptor's admission rule. The crashes around a reset declared with
//! `ResetSeqNumFlag` (141), in both roles, are covered by
//! `durable_reset_tests.rs` over the same two store types.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::error::StoreError;
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::application::RejectReason;
use ironfix_engine::{
    Acceptor, Application, CloseReason, Connection, EngineError, InboundLoss, InboundMismatch,
    Initiator, OutboundMessage, OutboundMismatch, SequenceMismatch, SessionId, StoreFailurePolicy,
};
use ironfix_session::SessionConfig;
use ironfix_store::{
    FileStore, FileStoreConfig, MemoryStore, MessageStore, StoredMessage, SyncPolicy,
};
use ironfix_tagvalue::{Decoder, Encoder};
use ironfix_transport::FixCodec;
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::io::DuplexStream;
use tokio::time::timeout;
use tokio_util::codec::Framed;

/// How long any one step may take before the test fails.
const STEP: Duration = Duration::from_secs(10);

/// How long the counterparty listens before it decides nothing more comes.
const QUIET: Duration = Duration::from_millis(300);

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
// Versions and roles
// ---------------------------------------------------------------------------

/// The FIX versions the gate runs: the two that define 789, and FIX.4.2
/// without it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Version {
    Fix42,
    Fix44,
    Fixt11,
}

const VERSIONS: [Version; 3] = [Version::Fix42, Version::Fix44, Version::Fixt11];

impl Version {
    /// The version a `SessionConfig` is built with.
    const fn config(self) -> &'static str {
        match self {
            Self::Fix42 => "FIX.4.2",
            Self::Fix44 => "FIX.4.4",
            Self::Fixt11 => "FIX.5.0SP2",
        }
    }

    /// The `BeginString` (8) on the wire.
    const fn begin_string(self) -> &'static str {
        match self {
            Self::Fix42 => "FIX.4.2",
            Self::Fix44 => "FIX.4.4",
            Self::Fixt11 => "FIXT.1.1",
        }
    }

    /// Whether both sides declare `NextExpectedMsgSeqNum` (789).
    const fn uses_789(self) -> bool {
        !matches!(self, Self::Fix42)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Initiator,
    Acceptor,
}

impl Role {
    /// The engine's own CompID and the counterparty's.
    const fn ids(self) -> (&'static str, &'static str) {
        match self {
            Self::Initiator => ("CLIENT", "VENUE"),
            Self::Acceptor => ("VENUE", "CLIENT"),
        }
    }

    fn config(self, version: Version) -> SessionConfig {
        let (me, them) = self.ids();
        SessionConfig::new(comp_id(me), comp_id(them), version.config())
            .with_heartbeat_interval(Duration::from_secs(30))
            .with_send_next_expected_msg_seq_num(version.uses_789())
    }

    /// An application message the engine sends, tagged `id`.
    fn outbound(self, id: &str) -> OutboundMessage {
        match self {
            Self::Initiator => {
                let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
                order
                    .push_str(11, id)
                    .push_str(55, "EUR/USD")
                    .push_char(54, '1')
                    .push_str(38, "100");
                order
            }
            Self::Acceptor => {
                let mut report = OutboundMessage::new(MsgType::ExecutionReport);
                report
                    .push_str(37, "EX")
                    .push_str(17, id)
                    .push_char(150, '0')
                    .push_char(39, '0');
                report
            }
        }
    }

    /// The tag that carries the id of an application message the engine
    /// sends.
    const fn id_tag(self) -> u32 {
        match self {
            Self::Initiator => 11,
            Self::Acceptor => 17,
        }
    }

    /// An application message type the counterparty sends.
    const fn peer_app_type(self) -> &'static str {
        match self {
            Self::Initiator => "8",
            Self::Acceptor => "D",
        }
    }
}

// ---------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------

fn decode_fields(frame: &[u8]) -> Vec<(u32, Vec<u8>)> {
    let mut decoder = Decoder::new(frame);
    match decoder.decode() {
        Ok(raw) => raw
            .fields()
            .map(|field| (field.tag, field.value.to_vec()))
            .collect(),
        Err(err) => panic!("a recorded frame must decode: {err:?}"),
    }
}

fn field(frame: &[u8], tag: u32) -> Option<String> {
    let mut decoder = Decoder::new(frame);
    match decoder.decode() {
        Ok(raw) => raw.get_field_str(tag).map(str::to_string),
        Err(_) => None,
    }
}

#[track_caller]
fn number(frame: &[u8], tag: u32) -> u64 {
    match field(frame, tag).map(|value| value.parse::<u64>()) {
        Some(Ok(value)) => value,
        other => panic!("tag {tag} must be a number: {other:?}"),
    }
}

fn is_poss_dup(frame: &[u8]) -> bool {
    field(frame, 43).as_deref() == Some("Y")
}

fn is_gap_fill(frame: &[u8]) -> bool {
    field(frame, 35).as_deref() == Some("4") && field(frame, 123).as_deref() == Some("Y")
}

fn is_admin(msg_type: &str) -> bool {
    matches!(msg_type, "0" | "1" | "2" | "3" | "4" | "5" | "A")
}

/// The fields a resend may change, by FIX rule: `BodyLength` (9),
/// `CheckSum` (10), `PossDupFlag` (43), `SendingTime` (52) and
/// `OrigSendingTime` (122). Everything else, in order, must survive.
const RESEND_MAY_CHANGE: [u32; 5] = [9, 10, 43, 52, 122];

fn normalized(frame: &[u8]) -> Vec<(u32, Vec<u8>)> {
    decode_fields(frame)
        .into_iter()
        .filter(|(tag, _)| !RESEND_MAY_CHANGE.contains(tag))
        .collect()
}

// ---------------------------------------------------------------------------
// The counterparty and its ledger
// ---------------------------------------------------------------------------

/// Every frame the counterparty received, from every engine incarnation, in
/// order.
#[derive(Clone, Default)]
struct Ledger(Arc<Mutex<Vec<BytesMut>>>);

impl Ledger {
    fn push(&self, frame: BytesMut) {
        match self.0.lock() {
            Ok(mut frames) => frames.push(frame),
            Err(_) => panic!("ledger lock poisoned"),
        }
    }

    fn frames(&self) -> Vec<BytesMut> {
        match self.0.lock() {
            Ok(frames) => frames.clone(),
            Err(_) => panic!("ledger lock poisoned"),
        }
    }

    /// The next `MsgSeqNum` the counterparty expects: one past the highest
    /// number it has received, a gap fill's `NewSeqNo` (36) included.
    fn next_expected(&self) -> u64 {
        self.frames()
            .iter()
            .map(|frame| {
                let seq = number(frame, 34);
                if is_gap_fill(frame) {
                    number(frame, 36)
                } else {
                    seq + 1
                }
            })
            .max()
            .unwrap_or(1)
    }

    /// The original (not `PossDupFlag`) frame received under `seq`, if any.
    fn original(&self, seq: u64) -> Option<BytesMut> {
        self.frames()
            .into_iter()
            .find(|frame| number(frame, 34) == seq && !is_poss_dup(frame))
    }
}

/// A `MsgSeqNum` the ledger shows carrying content it did not carry before.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Reuse {
    seq: u64,
    msg_type: String,
    poss_dup: bool,
}

/// Every reuse of a `MsgSeqNum` in the ledger:
///
/// - two originals (no `PossDupFlag`) under one number that differ in
///   anything but the fields a resend may change;
/// - a resend (`PossDupFlag` = Y, not a gap fill) whose number carried a
///   different original;
/// - a gap fill over a number whose original was an application message.
fn reuses(ledger: &Ledger) -> Vec<Reuse> {
    let frames = ledger.frames();
    let mut originals: BTreeMap<u64, Vec<(u32, Vec<u8>)>> = BTreeMap::new();
    let mut found = Vec::new();
    for frame in frames.iter().filter(|frame| !is_poss_dup(frame)) {
        let seq = number(frame, 34);
        let body = normalized(frame);
        match originals.get(&seq) {
            Some(first) if *first != body => found.push(Reuse {
                seq,
                msg_type: field(frame, 35).unwrap_or_default(),
                poss_dup: false,
            }),
            Some(_) => {}
            None => {
                originals.insert(seq, body);
            }
        }
    }
    for frame in frames.iter().filter(|frame| is_poss_dup(frame)) {
        let seq = number(frame, 34);
        let Some(original) = originals.get(&seq) else {
            continue;
        };
        let original_type = original
            .iter()
            .find(|(tag, _)| *tag == 35)
            .map(|(_, value)| String::from_utf8_lossy(value).to_string())
            .unwrap_or_default();
        let changed = if is_gap_fill(frame) {
            !is_admin(&original_type)
        } else {
            normalized(frame) != *original
        };
        if changed {
            found.push(Reuse {
                seq,
                msg_type: field(frame, 35).unwrap_or_default(),
                poss_dup: true,
            });
        }
    }
    found
}

/// The shared assertion: no frame the counterparty received reuses a
/// `MsgSeqNum` with different content.
#[track_caller]
fn assert_no_reuse(ledger: &Ledger, case: &str) {
    let found = reuses(ledger);
    assert!(found.is_empty(), "{case}: MsgSeqNum reused: {found:?}");
}

/// The scripted counterparty's end of the pipe.
struct Peer {
    framed: Framed<DuplexStream, FixCodec>,
    ledger: Ledger,
    version: Version,
    /// The counterparty's own CompID and the engine's.
    me: &'static str,
    them: &'static str,
}

impl Peer {
    fn new(io: DuplexStream, ledger: Ledger, version: Version, role: Role) -> Self {
        let (engine, peer) = role.ids();
        Self {
            framed: Framed::new(io, FixCodec::new()),
            ledger,
            version,
            me: peer,
            them: engine,
        }
    }

    /// A frame from the counterparty, numbered `seq`.
    fn frame(&self, msg_type: &str, seq: u64, extra: &[(u32, String)]) -> BytesMut {
        let mut encoder = Encoder::new(self.version.begin_string());
        encoder.put_str(35, msg_type);
        encoder.put_str(49, self.me);
        encoder.put_str(56, self.them);
        encoder.put_uint(34, seq);
        let now = Timestamp::now();
        if extra.iter().any(|(tag, _)| *tag == 43) {
            encoder.put_str(43, "Y");
        }
        encoder.put_str(52, now.format_millis().as_str());
        if extra.iter().any(|(tag, _)| *tag == 43) {
            encoder.put_str(122, now.format_millis().as_str());
        }
        for (tag, value) in extra.iter().filter(|(tag, _)| *tag != 43) {
            encoder.put_str(*tag, value);
        }
        let mut out = BytesMut::new();
        ok(encoder.finish_into(&mut out), "test frame must encode");
        out
    }

    async fn send(&mut self, msg_type: &str, seq: u64, extra: &[(u32, String)]) {
        let frame = self.frame(msg_type, seq, extra);
        ok(self.framed.send(frame).await, "the counterparty sends");
    }

    /// A Logon (or its acknowledgement) numbered `seq`, declaring 789 when
    /// the version uses it.
    async fn logon(&mut self, seq: u64, next_expected: Option<u64>) {
        let mut fields = vec![(98, "0".to_string()), (108, "30".to_string())];
        if self.version == Version::Fixt11 {
            fields.push((1137, "9".to_string()));
        }
        if let Some(next) = next_expected
            && self.version.uses_789()
        {
            fields.push((789, next.to_string()));
        }
        self.send("A", seq, &fields).await;
    }

    async fn app(&mut self, seq: u64) {
        let fields = vec![(11, format!("PEER-{seq}")), (55, "EUR/USD".to_string())];
        let msg_type = if self.me == "VENUE" { "8" } else { "D" };
        self.send(msg_type, seq, &fields).await;
    }

    async fn resend_request(&mut self, seq: u64, begin: u64, end: u64) {
        self.send("2", seq, &[(7, begin.to_string()), (16, end.to_string())])
            .await;
    }

    /// The next frame, recorded; fails the test if none arrives in the step.
    async fn recv(&mut self) -> BytesMut {
        match timeout(STEP, self.framed.next()).await {
            Ok(Some(Ok(frame))) => {
                self.ledger.push(frame.clone());
                frame
            }
            other => panic!("a frame must arrive within the step: {other:?}"),
        }
    }

    /// Reads frames until one of `msg_type` arrives.
    async fn recv_type(&mut self, msg_type: &str) -> BytesMut {
        loop {
            let frame = self.recv().await;
            if field(&frame, 35).as_deref() == Some(msg_type) {
                return frame;
            }
        }
    }

    /// Every frame until the pipe goes quiet, closes or fails, recorded.
    async fn drain(&mut self) -> Vec<BytesMut> {
        let mut frames = Vec::new();
        while let Ok(Some(Ok(frame))) = timeout(QUIET, self.framed.next()).await {
            self.ledger.push(frame.clone());
            frames.push(frame);
        }
        frames
    }
}

// ---------------------------------------------------------------------------
// The recording application
// ---------------------------------------------------------------------------

/// What the application saw, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Logon,
    /// An application message: its `MsgSeqNum` and whether it carried
    /// `PossDupFlag` (43) = Y.
    App(u64, bool),
    Lost(u64, u64),
    Mismatch(SequenceMismatch),
    Closed,
}

/// Records every callback; `from_app` refuses one number when asked to.
#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<Event>>,
    refuse: Option<u64>,
}

impl Recorder {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn refusing(seq: u64) -> Arc<Self> {
        Arc::new(Self {
            refuse: Some(seq),
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

    fn delivered(&self) -> Vec<(u64, bool)> {
        self.events()
            .into_iter()
            .filter_map(|event| match event {
                Event::App(seq, poss_dup) => Some((seq, poss_dup)),
                _ => None,
            })
            .collect()
    }

    fn losses(&self) -> Vec<(u64, u64)> {
        self.events()
            .into_iter()
            .filter_map(|event| match event {
                Event::Lost(first, last) => Some((first, last)),
                _ => None,
            })
            .collect()
    }

    fn mismatches(&self) -> Vec<SequenceMismatch> {
        self.events()
            .into_iter()
            .filter_map(|event| match event {
                Event::Mismatch(mismatch) => Some(mismatch),
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

    async fn from_app(&self, message: &RawMessage<'_>, _: &SessionId) -> Result<(), RejectReason> {
        let seq = message
            .get_field_str(34)
            .and_then(|seq| seq.parse::<u64>().ok())
            .unwrap_or_default();
        if self.refuse == Some(seq) {
            return Err(RejectReason::new(99, "refused by the test application"));
        }
        let poss_dup = message.get_field_str(43) == Some("Y");
        self.push(Event::App(seq, poss_dup));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The crashing store
// ---------------------------------------------------------------------------

/// Where a [`CrashStore`] crashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Point {
    /// Only when [`CrashStore::crash`] is called.
    Manual,
    /// When `file_outbound` is called for this `MsgSeqNum`, before it takes
    /// effect.
    FileBefore(u64),
    /// Once `file_outbound` for this `MsgSeqNum` has taken effect.
    FileAfter(u64),
    /// Within `file_outbound` for this `MsgSeqNum`, split as the trait's
    /// default does it (the frame first, then the counter): after the frame
    /// is stored, before the next sender number is persisted.
    FileSplit(u64),
    /// When `set_next_target_seq(value)` is called, before it takes effect.
    TargetBefore(u64),
    /// Once `set_next_target_seq(value)` has taken effect.
    TargetAfter(u64),
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

    /// The process dies now: the wrapped store is let go.
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

    async fn dead<T>(&self) -> T {
        self.crash();
        std::future::pending().await
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
        if self.point == Point::FileBefore(seq_num) {
            return self.dead().await;
        }
        let inner = self.alive().await;
        if self.point == Point::FileSplit(seq_num) {
            // The default `file_outbound`: the frame, then the counter. The
            // process dies between the two.
            let stored = inner.store(seq_num, msg_type, message).await;
            drop(inner);
            ok(stored, "the split write stores the frame");
            return self.dead().await;
        }
        let result = inner
            .file_outbound(seq_num, msg_type, message, next_sender)
            .await;
        drop(inner);
        if self.point == Point::FileAfter(seq_num) {
            return self.dead().await;
        }
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
        if self.point == Point::TargetBefore(seq) {
            return self.dead().await;
        }
        let inner = self.alive().await;
        let result = inner.set_next_target_seq(seq).await;
        drop(inner);
        if self.point == Point::TargetAfter(seq) {
            return self.dead().await;
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
        self.alive().await.set_app_watermark(watermark).await
    }

    fn creation_time(&self) -> SystemTime {
        self.inner()
            .map_or(SystemTime::UNIX_EPOCH, |inner| inner.creation_time())
    }

    async fn refresh(&self) -> Result<(), StoreError> {
        self.alive().await.refresh().await
    }
}

// ---------------------------------------------------------------------------
// The store across a restart
// ---------------------------------------------------------------------------

/// A directory for one test, removed when it ends.
struct TestDir(std::path::PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("ironfix-acceptance-{name}-{}", std::process::id()));
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
    /// A `MemoryStore` that outlives the engine.
    Memory,
    /// A `FileStore` under `SyncPolicy::EveryWrite`.
    File,
}

/// One store across a restart.
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
            Kind::File => Self::file(name, SyncPolicy::EveryWrite).await,
        }
    }

    async fn file(name: &str, policy: SyncPolicy) -> Self {
        let dir = TestDir::new(name);
        let config =
            ok(FileStoreConfig::try_new(&dir.0, "STORE"), "store config").with_sync_policy(policy);
        let store = ok(
            FileStore::open(config.clone().with_create_if_missing(true)).await,
            "create the file store",
        );
        Self {
            store: Arc::new(store),
            file: Some((config, dir)),
        }
    }

    /// Waits until the dead engine has let the store go.
    async fn released(store: &Arc<dyn MessageStore>) {
        let released = timeout(STEP, async {
            while Arc::strong_count(store) > 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(released.is_ok(), "the dead engine must let the store go");
    }

    /// The restart: the dead engine is gone; a `FileStore` is dropped without
    /// `close`, as a killed process leaves it, and opened again from disk.
    async fn restart(self) -> Self {
        let Self { store, file } = self;
        let Some((config, dir)) = file else {
            return Self { store, file: None };
        };
        Self::released(&store).await;
        drop(store);
        let reopened = ok(FileStore::open(config.clone()).await, "reopen the store");
        Self {
            store: Arc::new(reopened),
            file: Some((config, dir)),
        }
    }

    /// A copy of the journal as it is now, in a directory of its own: the
    /// state a standby holds when its copy ends here.
    fn snapshot(&self, name: &str) -> (FileStoreConfig, TestDir) {
        let Some((config, _)) = &self.file else {
            panic!("only a FileStore can be copied");
        };
        let dir = TestDir::new(name);
        ok(
            std::fs::create_dir_all(&dir.0),
            "create the copy's directory",
        );
        let copy = ok(FileStoreConfig::try_new(&dir.0, "STORE"), "copy config");
        ok(
            std::fs::copy(config.journal_path(), copy.journal_path()),
            "copy the journal",
        );
        (copy, dir)
    }
}

// ---------------------------------------------------------------------------
// Sessions in either role
// ---------------------------------------------------------------------------

/// A Logon exchange: the engine's result, its own Logon or acknowledgement
/// (absent when it sent none), and the counterparty.
struct Live {
    result: Result<Connection, EngineError>,
    own_logon: Option<BytesMut>,
    peer: Peer,
}

impl Live {
    #[track_caller]
    fn connection(&self) -> &Connection {
        match &self.result {
            Ok(connection) => connection,
            Err(err) => panic!("the session must be established: {err:?}"),
        }
    }

    #[track_caller]
    fn own_seq(&self) -> u64 {
        match &self.own_logon {
            Some(logon) => number(logon, 34),
            None => panic!("the engine sent no Logon"),
        }
    }
}

/// How the counterparty's Logon (or acknowledgement) is numbered and what
/// 789 it declares.
#[derive(Debug, Clone, Copy)]
struct PeerLogon {
    seq: u64,
    /// The declared 789; `None` declares what the ledger says the
    /// counterparty expects.
    next_expected: Option<u64>,
}

const fn peer_logon(seq: u64) -> PeerLogon {
    PeerLogon {
        seq,
        next_expected: None,
    }
}

/// Starts an engine of `role` over `store` (strict policy) and runs the Logon
/// exchange with a counterparty that records into `ledger`.
async fn start(
    role: Role,
    version: Version,
    store: Arc<dyn MessageStore>,
    app: Arc<Recorder>,
    ledger: &Ledger,
    logon: PeerLogon,
) -> Live {
    let (engine_io, peer_io) = tokio::io::duplex(256 * 1024);
    let mut peer = Peer::new(peer_io, ledger.clone(), version, role);
    match role {
        Role::Initiator => {
            let initiator = Initiator::new(role.config(version), app)
                .with_store(store)
                .with_store_failure_policy(StoreFailurePolicy::CloseSession);
            let established = tokio::spawn(async move { initiator.establish(engine_io).await });
            let own = peer.recv().await;
            let declared = logon
                .next_expected
                .unwrap_or_else(|| ledger.next_expected());
            peer.logon(logon.seq, Some(declared)).await;
            let result = ok(
                ok(timeout(STEP, established).await, "handshake in time"),
                "handshake task",
            );
            Live {
                result,
                own_logon: Some(own),
                peer,
            }
        }
        Role::Acceptor => {
            let acceptor = Acceptor::new(role.config(version), app)
                .with_store(store)
                .with_store_failure_policy(StoreFailurePolicy::CloseSession);
            let served = tokio::spawn(async move { acceptor.serve_stream(engine_io).await });
            let declared = logon
                .next_expected
                .unwrap_or_else(|| ledger.next_expected());
            peer.logon(logon.seq, Some(declared)).await;
            let result = ok(
                ok(timeout(STEP, served).await, "handshake in time"),
                "handshake task",
            );
            let own = match &result {
                Ok(_) => Some(peer.recv_type("A").await),
                Err(_) => None,
            };
            Live {
                result,
                own_logon: own,
                peer,
            }
        }
    }
}

/// Sends an application message tagged `id` through the engine.
async fn send_app(live: &Live, role: Role, id: &str) {
    ok(
        live.connection().send(role.outbound(id)).await,
        "the engine accepts the message",
    );
}

/// The resend the counterparty receives for a `ResendRequest` from `begin`
/// to infinity: every frame up to the one that answers `last`, then whatever
/// follows until the pipe goes quiet. Waiting for `last` rather than for
/// silence keeps a slow store from cutting the answer short.
async fn ask_resend(peer: &mut Peer, seq: u64, begin: u64, last: u64) -> Vec<BytesMut> {
    peer.resend_request(seq, begin, 0).await;
    recv_resend(peer, last).await
}

/// Reads resent frames until one answers `last`, then drains.
async fn recv_resend(peer: &mut Peer, last: u64) -> Vec<BytesMut> {
    let mut frames = Vec::new();
    loop {
        let frame = peer.recv().await;
        let answered = if is_gap_fill(&frame) {
            number(&frame, 36) > last
        } else {
            is_poss_dup(&frame) && number(&frame, 34) == last
        };
        frames.push(frame);
        if answered {
            break;
        }
    }
    frames.extend(peer.drain().await);
    frames
}

/// Checks a resend answer against the ledger's originals: every number from
/// `first` to `last` is answered exactly once; an application original comes
/// back byte-identical apart from the fields a resend may change, with
/// `OrigSendingTime` (122) equal to the original's `SendingTime` (52); an
/// administrative original or a number the counterparty never received comes
/// back as a gap fill or (when the engine holds it) a replay.
#[track_caller]
fn assert_resend(ledger: &Ledger, replies: &[BytesMut], first: u64, last: u64, case: &str) {
    let mut covered = BTreeSet::new();
    for reply in replies {
        let seq = number(reply, 34);
        assert!(
            is_poss_dup(reply),
            "{case}: resent {seq} without PossDupFlag"
        );
        let span: Vec<u64> = if is_gap_fill(reply) {
            (seq..number(reply, 36)).collect()
        } else {
            vec![seq]
        };
        for covered_seq in span {
            assert!(
                covered.insert(covered_seq),
                "{case}: {covered_seq} answered twice"
            );
        }
        if is_gap_fill(reply) {
            for gap_seq in seq..number(reply, 36) {
                if let Some(original) = ledger.original(gap_seq) {
                    let original_type = field(&original, 35).unwrap_or_default();
                    assert!(
                        is_admin(&original_type),
                        "{case}: application message {gap_seq} gap-filled"
                    );
                }
            }
        } else if let Some(original) = ledger.original(seq) {
            assert_eq!(
                normalized(reply),
                normalized(&original),
                "{case}: {seq} resent with different content"
            );
            assert_eq!(
                field(reply, 122),
                field(&original, 52),
                "{case}: {seq} OrigSendingTime is the original SendingTime"
            );
        }
    }
    let expected: BTreeSet<u64> = (first..=last).collect();
    assert_eq!(
        covered, expected,
        "{case}: the resend covers exactly the range"
    );
}

// ---------------------------------------------------------------------------
// The outbound crash table
// ---------------------------------------------------------------------------

/// The outbound crash points, for one application message numbered N = 2
/// (the Logon or acknowledgement is 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutboundRow {
    /// Frame encoded, before the counter is updated: the store crashes as
    /// `file_outbound` is called, so neither frame N nor counter N+1 is
    /// durable. Under `SyncPolicy::EveryWrite` this is also "store write,
    /// before fsync": `file_outbound` returns only once the write is flushed.
    BeforeCounter,
    /// A store whose `file_outbound` is the trait default (frame, then
    /// counter) dies between the two: the counter can never be ahead of the
    /// frame.
    BetweenFrameAndCounter,
    /// Flushed, before the socket write: frame N and counter N+1 are durable,
    /// the counterparty never saw N.
    BeforeSocket,
    /// On the wire, before the counterparty confirmed it.
    AfterSocket,
}

/// The first session: Logons at 1, then the engine sends `ORDER-2`, which
/// takes N = 2; the process dies at the row's point. Returns the ledger.
async fn outbound_crash(
    role: Role,
    version: Version,
    durable: &Durable,
    row: OutboundRow,
    case: &str,
) -> Ledger {
    let point = match row {
        OutboundRow::BeforeCounter => Point::FileBefore(2),
        OutboundRow::BetweenFrameAndCounter => Point::FileSplit(2),
        OutboundRow::BeforeSocket => Point::FileAfter(2),
        OutboundRow::AfterSocket => Point::Manual,
    };
    let store = CrashStore::new(Arc::clone(&durable.store), point);
    let ledger = Ledger::default();
    let app = Recorder::new();
    let mut live = start(
        role,
        version,
        Arc::clone(&store) as Arc<dyn MessageStore>,
        app,
        &ledger,
        peer_logon(1),
    )
    .await;
    assert_eq!(live.own_seq(), 1, "{case}: the first Logon is 1");
    send_app(&live, role, "ORDER-2").await;
    if row == OutboundRow::AfterSocket {
        let app_type = match role {
            Role::Initiator => "D",
            Role::Acceptor => "8",
        };
        let sent = live.peer.recv_type(app_type).await;
        assert_eq!(number(&sent, 34), 2, "{case}");
        store.crash();
    } else {
        until(&format!("{case}: the store crashes"), || {
            store.has_crashed()
        })
        .await;
    }
    // Whatever the dead engine still writes is recorded.
    let _ = live.peer.drain().await;
    let on_wire = ledger.original(2).is_some();
    assert_eq!(
        on_wire,
        row == OutboundRow::AfterSocket,
        "{case}: N reached the wire only after the socket write"
    );
    drop(live);
    ledger
}

async fn outbound_row(role: Role, kind: Kind, row: OutboundRow) {
    for version in VERSIONS {
        let case = format!("{role:?} {version:?} {kind:?} outbound {row:?}");
        let durable = Durable::new(kind, &format!("out-{role:?}-{version:?}-{row:?}")).await;
        let ledger = outbound_crash(role, version, &durable, row, &case).await;
        let durable = durable.restart().await;

        // What the restart finds.
        // A range above the next sender number holds nothing by definition.
        let stored = match durable.store.get_range(2, 2).await {
            Ok(stored) => stored,
            Err(StoreError::RangeNotAvailable { .. }) => Vec::new(),
            Err(err) => panic!("{case}: read the store: {err:?}"),
        };
        let (next_sender, frame_n) = (durable.store.next_sender_seq(), stored.first().cloned());
        match row {
            OutboundRow::BeforeCounter => {
                assert_eq!(next_sender, 2, "{case}: counter N");
                assert!(frame_n.is_none(), "{case}: no frame N");
            }
            OutboundRow::BetweenFrameAndCounter => {
                assert_eq!(next_sender, 2, "{case}: the counter is never ahead");
                assert!(frame_n.is_some(), "{case}: the frame was first");
            }
            OutboundRow::BeforeSocket | OutboundRow::AfterSocket => {
                assert_eq!(next_sender, 3, "{case}: counter N+1");
                assert!(frame_n.is_some(), "{case}: frame N");
            }
        }

        // The restarted engine. When N never reached the wire the
        // counterparty declares what its ledger says it expects; otherwise
        // it declares 789 = 2, as one that lost N would.
        let reused = matches!(
            row,
            OutboundRow::BeforeCounter | OutboundRow::BetweenFrameAndCounter
        );
        let app = Recorder::new();
        let mut live = start(
            role,
            version,
            Arc::clone(&durable.store),
            Arc::clone(&app),
            &ledger,
            PeerLogon {
                seq: 2,
                next_expected: if reused { None } else { Some(2) },
            },
        )
        .await;
        let restart_seq = live.own_seq();
        assert_eq!(
            restart_seq,
            if reused { 2 } else { 3 },
            "{case}: the restarted Logon"
        );
        if reused {
            // N never reached the wire; the restart takes it, and no gap.
            let replies = live.peer.drain().await;
            assert!(
                replies
                    .iter()
                    .all(|reply| number(reply, 34) != 2 || !is_poss_dup(reply)),
                "{case}: nothing is resent under N"
            );
            let refiled = ok(durable.store.get_range(2, 2).await, "read the store");
            assert_eq!(
                refiled.first().map(|stored| field(stored.payload(), 35)),
                Some(Some("A".to_string())),
                "{case}: N now files the restarted Logon"
            );
        } else {
            // N is never reused. With 789 the counterparty's declaration
            // below the restarted Logon is the resend request; without it,
            // a ResendRequest asks.
            let replies = if version.uses_789() {
                recv_resend(&mut live.peer, 2).await
            } else {
                ask_resend(&mut live.peer, 3, 2, 2).await
            };
            let resent: Vec<&BytesMut> = replies
                .iter()
                .filter(|reply| number(reply, 34) == 2 && is_poss_dup(reply))
                .collect();
            assert_eq!(resent.len(), 1, "{case}: N resent once: {replies:?}");
            let resent = resent[0];
            assert!(!is_gap_fill(resent), "{case}: the original, not a gap fill");
            assert_eq!(
                field(resent, role.id_tag()).as_deref(),
                Some("ORDER-2"),
                "{case}: the original content"
            );
            assert!(field(resent, 122).is_some(), "{case}: OrigSendingTime");
            if let Some(stored) = &frame_n {
                assert_eq!(
                    normalized(resent),
                    normalized(stored.payload()),
                    "{case}: byte-identical to the stored frame"
                );
            }
            if version.uses_789() {
                let mismatches = app.mismatches();
                assert_eq!(mismatches.len(), 1, "{case}: {mismatches:?}");
                assert_eq!(
                    mismatches[0].outbound(),
                    OutboundMismatch::PeerMissed { first: 2, last: 2 },
                    "{case}"
                );
            }
        }
        assert_no_reuse(&ledger, &case);
        drop(live);
    }
}

macro_rules! both_stores {
    ($name:ident, $role:expr, $body:ident $(, $arg:expr)*) => {
        mod $name {
            use super::*;

            #[tokio::test(start_paused = true)]
            async fn memory_store() {
                $body($role, Kind::Memory $(, $arg)*).await;
            }

            #[tokio::test]
            async fn file_store() {
                $body($role, Kind::File $(, $arg)*).await;
            }
        }
    };
}

both_stores!(
    outbound_before_counter_initiator,
    Role::Initiator,
    outbound_row,
    OutboundRow::BeforeCounter
);
both_stores!(
    outbound_before_counter_acceptor,
    Role::Acceptor,
    outbound_row,
    OutboundRow::BeforeCounter
);
both_stores!(
    outbound_between_frame_and_counter_initiator,
    Role::Initiator,
    outbound_row,
    OutboundRow::BetweenFrameAndCounter
);
both_stores!(
    outbound_between_frame_and_counter_acceptor,
    Role::Acceptor,
    outbound_row,
    OutboundRow::BetweenFrameAndCounter
);
both_stores!(
    outbound_before_socket_initiator,
    Role::Initiator,
    outbound_row,
    OutboundRow::BeforeSocket
);
both_stores!(
    outbound_before_socket_acceptor,
    Role::Acceptor,
    outbound_row,
    OutboundRow::BeforeSocket
);
both_stores!(
    outbound_after_socket_initiator,
    Role::Initiator,
    outbound_row,
    OutboundRow::AfterSocket
);
both_stores!(
    outbound_after_socket_acceptor,
    Role::Acceptor,
    outbound_row,
    OutboundRow::AfterSocket
);

/// "Store write, before fsync" under the policies that do not flush every
/// write: a write that returned `Ok` survives a **process** crash (it is in
/// the operating system's hands), so frame N and counter N+1 come back, as
/// in the "before the socket write" row. What these policies lose on an
/// operating-system crash is documented on `SyncPolicy` and not simulated.
async fn unflushed_policy_survives_a_process_crash(role: Role) {
    const EVERY_EIGHT: NonZeroU32 = match NonZeroU32::new(8) {
        Some(every) => every,
        None => panic!("8 is not zero"),
    };
    let policies = [
        ("every-n", SyncPolicy::EveryN(EVERY_EIGHT)),
        ("never", SyncPolicy::Never),
    ];
    for (name, policy) in policies {
        let version = Version::Fix44;
        let case = format!("{role:?} {name} outbound before fsync");
        let durable = Durable::file(&format!("unflushed-{role:?}-{name}"), policy).await;
        let ledger =
            outbound_crash(role, version, &durable, OutboundRow::BeforeSocket, &case).await;
        let durable = durable.restart().await;
        assert_eq!(durable.store.next_sender_seq(), 3, "{case}: counter N+1");
        let stored = ok(durable.store.get_range(2, 2).await, "read the store");
        assert_eq!(stored.len(), 1, "{case}: frame N");
        assert_no_reuse(&ledger, &case);
    }
}

#[tokio::test]
async fn test_unflushed_sync_policies_survive_a_process_crash_initiator() {
    unflushed_policy_survives_a_process_crash(Role::Initiator).await;
}

#[tokio::test]
async fn test_unflushed_sync_policies_survive_a_process_crash_acceptor() {
    unflushed_policy_survives_a_process_crash(Role::Acceptor).await;
}

// ---------------------------------------------------------------------------
// The inbound crash table
// ---------------------------------------------------------------------------

/// The inbound crash points, for one application message numbered M = 2 from
/// the counterparty (its Logon is 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboundRow {
    /// Frame read, before the target counter is updated.
    BeforeTarget,
    /// Target counter updated, before the application handled M.
    BeforeApplication,
}

async fn inbound_row(role: Role, kind: Kind, row: InboundRow) {
    for version in VERSIONS {
        let case = format!("{role:?} {version:?} {kind:?} inbound {row:?}");
        let durable = Durable::new(kind, &format!("in-{role:?}-{version:?}-{row:?}")).await;
        let point = match row {
            InboundRow::BeforeTarget => Point::TargetBefore(3),
            InboundRow::BeforeApplication => Point::TargetAfter(3),
        };
        let store = CrashStore::new(Arc::clone(&durable.store), point);
        let ledger = Ledger::default();
        let first_app = Recorder::new();
        let mut live = start(
            role,
            version,
            Arc::clone(&store) as Arc<dyn MessageStore>,
            Arc::clone(&first_app),
            &ledger,
            peer_logon(1),
        )
        .await;
        live.peer.app(2).await;
        until(&format!("{case}: the store crashes"), || {
            store.has_crashed()
        })
        .await;
        let _ = live.peer.drain().await;
        assert!(
            first_app.delivered().is_empty(),
            "{case}: M never reached from_app before the crash"
        );
        drop(live);
        drop(store);
        let durable = durable.restart().await;
        let expected_target = match row {
            InboundRow::BeforeTarget => 2,
            InboundRow::BeforeApplication => 3,
        };
        assert_eq!(
            durable.store.next_target_seq(),
            expected_target,
            "{case}: the durable receive cursor"
        );

        // The counterparty continues its stream at 3.
        let app = Recorder::new();
        let mut live = start(
            role,
            version,
            Arc::clone(&durable.store),
            Arc::clone(&app),
            &ledger,
            peer_logon(3),
        )
        .await;
        match row {
            InboundRow::BeforeTarget => {
                // The engine expects M again and gets it resent: with 789 the
                // counterparty resends on its own, without it on request.
                if version.uses_789() {
                    assert_eq!(
                        field(live.own_logon.as_deref().unwrap_or_default(), 789).as_deref(),
                        Some("2"),
                        "{case}: the engine declares it expects M"
                    );
                } else {
                    let request = live.peer.recv_type("2").await;
                    assert_eq!(number(&request, 7), 2, "{case}: asks from M");
                }
                live.peer
                    .send(
                        role.peer_app_type(),
                        2,
                        &[
                            (43, "Y".to_string()),
                            (11, "PEER-2".to_string()),
                            (55, "EUR/USD".to_string()),
                        ],
                    )
                    .await;
                if !version.uses_789() {
                    // The ResendRequest ran to infinity: the Logon's number is
                    // gap-filled too.
                    live.peer
                        .send(
                            "4",
                            3,
                            &[
                                (43, "Y".to_string()),
                                (123, "Y".to_string()),
                                (36, "4".to_string()),
                            ],
                        )
                        .await;
                }
                until(&format!("{case}: M delivered"), || {
                    !app.delivered().is_empty()
                })
                .await;
                let inner = Arc::clone(&durable.store);
                until(&format!("{case}: the cursor passes the Logon"), || {
                    inner.next_target_seq() == 4
                })
                .await;
                assert_eq!(
                    app.delivered(),
                    vec![(2, true)],
                    "{case}: M delivered once, flagged as a redelivery"
                );
                assert!(app.losses().is_empty(), "{case}: nothing reported lost");
            }
            InboundRow::BeforeApplication => {
                // At most once, reported: M is reported lost, never asked for
                // again, never redelivered.
                let _ = live.peer.drain().await;
                assert_eq!(app.losses(), vec![(2, 2)], "{case}: M is reported");
                assert!(
                    matches!(app.events().first(), Some(Event::Lost(2, 2))),
                    "{case}: reported before the session is Active"
                );
                assert!(app.delivered().is_empty(), "{case}: not redelivered");
                assert!(
                    !ledger
                        .frames()
                        .iter()
                        .any(|frame| field(frame, 35).as_deref() == Some("2")),
                    "{case}: no ResendRequest for M"
                );
                assert_eq!(durable.store.next_target_seq(), 4, "{case}");
            }
        }
        assert!(app.mismatches().iter().all(|mismatch| {
            !matches!(mismatch.inbound(), Some(InboundMismatch::TooLow { .. }))
        }));
        assert_no_reuse(&ledger, &case);
        drop(live);
    }
}

both_stores!(
    inbound_before_target_initiator,
    Role::Initiator,
    inbound_row,
    InboundRow::BeforeTarget
);
both_stores!(
    inbound_before_target_acceptor,
    Role::Acceptor,
    inbound_row,
    InboundRow::BeforeTarget
);
both_stores!(
    inbound_before_application_initiator,
    Role::Initiator,
    inbound_row,
    InboundRow::BeforeApplication
);
both_stores!(
    inbound_before_application_acceptor,
    Role::Acceptor,
    inbound_row,
    InboundRow::BeforeApplication
);

/// An administrative message (a Heartbeat) and an application message the
/// application refuses consume their inbound numbers: after a crash the
/// receive cursor includes both, and the restart asks for neither.
async fn inbound_consumed_without_delivery(role: Role, kind: Kind) {
    for version in VERSIONS {
        let case = format!("{role:?} {version:?} {kind:?} admin and refused");
        let durable = Durable::new(kind, &format!("consumed-{role:?}-{version:?}")).await;
        let store = CrashStore::new(Arc::clone(&durable.store), Point::Manual);
        let ledger = Ledger::default();
        let first_app = Recorder::refusing(3);
        let mut live = start(
            role,
            version,
            Arc::clone(&store) as Arc<dyn MessageStore>,
            Arc::clone(&first_app),
            &ledger,
            peer_logon(1),
        )
        .await;
        live.peer.send("0", 2, &[]).await;
        live.peer.app(3).await;
        let inner = Arc::clone(&durable.store);
        until(&format!("{case}: both consumed and acted on"), || {
            inner.next_target_seq() == 4 && inner.app_watermark() == 3
        })
        .await;
        let _ = live.peer.drain().await;
        store.crash();
        drop(inner);
        drop(live);
        drop(store);
        assert!(first_app.delivered().is_empty(), "{case}: 3 was refused");
        let durable = durable.restart().await;
        assert_eq!(
            durable.store.next_target_seq(),
            4,
            "{case}: the cursor includes the Heartbeat and the refused message"
        );

        let app = Recorder::new();
        let before = ledger.frames().len();
        let mut live = start(
            role,
            version,
            Arc::clone(&durable.store),
            Arc::clone(&app),
            &ledger,
            peer_logon(4),
        )
        .await;
        let _ = live.peer.drain().await;
        let after = &ledger.frames()[before..];
        assert!(
            !after
                .iter()
                .any(|frame| field(frame, 35).as_deref() == Some("2")),
            "{case}: no ResendRequest"
        );
        assert!(app.losses().is_empty(), "{case}: nothing reported lost");
        assert!(
            app.mismatches().is_empty(),
            "{case}: {:?}",
            app.mismatches()
        );
        assert_no_reuse(&ledger, &case);
        drop(live);
    }
}

both_stores!(
    inbound_admin_and_refused_initiator,
    Role::Initiator,
    inbound_consumed_without_delivery
);
both_stores!(
    inbound_admin_and_refused_acceptor,
    Role::Acceptor,
    inbound_consumed_without_delivery
);

// ---------------------------------------------------------------------------
// Sequence resets followed by a crash
// ---------------------------------------------------------------------------

/// An inbound `SequenceReset` (4), in Reset mode and in GapFill mode, then a
/// crash: the durable target is the new expected number.
async fn inbound_sequence_reset_then_crash(role: Role, kind: Kind) {
    for gap_fill in [false, true] {
        let version = Version::Fix44;
        let mode = if gap_fill { "GapFill" } else { "Reset" };
        let case = format!("{role:?} {kind:?} inbound SequenceReset-{mode}");
        let durable = Durable::new(kind, &format!("seqreset-{role:?}-{mode}")).await;
        let store = CrashStore::new(Arc::clone(&durable.store), Point::Manual);
        let ledger = Ledger::default();
        let mut live = start(
            role,
            version,
            Arc::clone(&store) as Arc<dyn MessageStore>,
            Recorder::new(),
            &ledger,
            peer_logon(1),
        )
        .await;
        let mut fields = vec![(36, "10".to_string())];
        if gap_fill {
            fields.push((123, "Y".to_string()));
        }
        live.peer.send("4", 2, &fields).await;
        let inner = Arc::clone(&durable.store);
        until(
            &format!("{case}: the new expected number is durable"),
            || inner.next_target_seq() == 10,
        )
        .await;
        let _ = live.peer.drain().await;
        store.crash();
        drop(inner);
        drop(live);
        drop(store);
        let durable = durable.restart().await;
        assert_eq!(durable.store.next_target_seq(), 10, "{case}");

        let app = Recorder::new();
        let live = start(
            role,
            version,
            Arc::clone(&durable.store),
            Arc::clone(&app),
            &ledger,
            peer_logon(10),
        )
        .await;
        assert!(live.result.is_ok(), "{case}");
        assert!(
            app.mismatches().is_empty(),
            "{case}: the restart expects 10: {:?}",
            app.mismatches()
        );
        assert_no_reuse(&ledger, &case);
        drop(live);
    }
}

both_stores!(
    inbound_sequence_reset_initiator,
    Role::Initiator,
    inbound_sequence_reset_then_crash
);
both_stores!(
    inbound_sequence_reset_acceptor,
    Role::Acceptor,
    inbound_sequence_reset_then_crash
);

/// An outbound gap fill in answer to a `ResendRequest`, then a crash: the
/// store still replays the original frames under their numbers, since gap
/// fills are never filed over them.
async fn outbound_gap_fill_then_crash(role: Role, kind: Kind) {
    for version in VERSIONS {
        let case = format!("{role:?} {version:?} {kind:?} gap fill then crash");
        let durable = Durable::new(kind, &format!("gapfill-{role:?}-{version:?}")).await;
        let store = CrashStore::new(Arc::clone(&durable.store), Point::Manual);
        let ledger = Ledger::default();
        let mut live = start(
            role,
            version,
            Arc::clone(&store) as Arc<dyn MessageStore>,
            Recorder::new(),
            &ledger,
            peer_logon(1),
        )
        .await;
        send_app(&live, role, "ORDER-2").await;
        send_app(&live, role, "ORDER-3").await;
        let _ = live.peer.drain().await;
        let first = ask_resend(&mut live.peer, 2, 1, 3).await;
        assert_resend(&ledger, &first, 1, 3, &case);
        let inner = Arc::clone(&durable.store);
        until(&format!("{case}: the ResendRequest is consumed"), || {
            inner.next_target_seq() == 3
        })
        .await;
        store.crash();
        drop(inner);
        drop(live);
        drop(store);
        let durable = durable.restart().await;

        let mut live = start(
            role,
            version,
            Arc::clone(&durable.store),
            Recorder::new(),
            &ledger,
            peer_logon(3),
        )
        .await;
        assert_eq!(live.own_seq(), 4, "{case}");
        let _ = live.peer.drain().await;
        let second = ask_resend(&mut live.peer, 4, 1, 4).await;
        assert_resend(&ledger, &second, 1, 4, &case);
        for seq in [2, 3] {
            assert!(
                second
                    .iter()
                    .any(|reply| number(reply, 34) == seq && !is_gap_fill(reply)),
                "{case}: {seq} replayed from the store, not gap-filled"
            );
        }
        assert_no_reuse(&ledger, &case);
        drop(live);
    }
}

both_stores!(
    outbound_gap_fill_initiator,
    Role::Initiator,
    outbound_gap_fill_then_crash
);
both_stores!(
    outbound_gap_fill_acceptor,
    Role::Acceptor,
    outbound_gap_fill_then_crash
);

// ---------------------------------------------------------------------------
// Takeover
// ---------------------------------------------------------------------------

/// The active process's session: Logons at 1; the engine sends 2 and 3; the
/// counterparty sends an application message (2), a Heartbeat (3) and a
/// TestRequest (4), which the engine answers with a Heartbeat (4); the engine
/// sends 5. The store then holds a sender counter of 6 and a target counter
/// of 5. If `copy_after_first` is set, a copy of the journal is taken once
/// the engine has sent 2 and received 2.
async fn active_session(
    role: Role,
    version: Version,
    durable: &Durable,
    ledger: &Ledger,
    copy_at: Option<&str>,
    case: &str,
) -> Option<(FileStoreConfig, TestDir)> {
    let store = CrashStore::new(Arc::clone(&durable.store), Point::Manual);
    let mut live = start(
        role,
        version,
        Arc::clone(&store) as Arc<dyn MessageStore>,
        Recorder::new(),
        ledger,
        peer_logon(1),
    )
    .await;
    send_app(&live, role, "ORDER-2").await;
    live.peer.app(2).await;
    let inner = Arc::clone(&durable.store);
    until(&format!("{case}: 2 sent and 2 received"), || {
        inner.next_sender_seq() == 3 && inner.next_target_seq() == 3 && inner.app_watermark() == 2
    })
    .await;
    let _ = live.peer.drain().await;
    let copy = copy_at.map(|name| durable.snapshot(name));
    send_app(&live, role, "ORDER-3").await;
    until(&format!("{case}: 3 sent"), || inner.next_sender_seq() == 4).await;
    live.peer.send("0", 3, &[]).await;
    live.peer.send("1", 4, &[(112, "PING".to_string())]).await;
    let echo = live.peer.recv_type("0").await;
    assert_eq!(field(&echo, 112).as_deref(), Some("PING"), "{case}");
    send_app(&live, role, "ORDER-5").await;
    until(&format!("{case}: the active session settles"), || {
        inner.next_sender_seq() == 6 && inner.next_target_seq() == 5 && inner.app_watermark() == 4
    })
    .await;
    let _ = live.peer.drain().await;
    // The active process stops: it is killed, nothing more is written.
    store.crash();
    drop(inner);
    drop(live);
    copy
}

/// Complete prefix: the standby opens the store the active left behind, after
/// the active has stopped. Its next expected inbound number is the active's
/// (5, past the counterparty's Heartbeat and TestRequest, not just its last
/// application message); no mismatch is reported; and a `ResendRequest` over
/// the whole session returns every original `MsgSeqNum`, application
/// messages byte-identical and administrative ones gap-filled.
async fn takeover_complete_prefix(role: Role) {
    for version in VERSIONS {
        let case = format!("{role:?} {version:?} complete-prefix takeover");
        let durable = Durable::new(Kind::File, &format!("takeover-{role:?}-{version:?}")).await;
        let ledger = Ledger::default();
        let _ = active_session(role, version, &durable, &ledger, None, &case).await;
        let durable = durable.restart().await;
        assert_eq!(durable.store.next_target_seq(), 5, "{case}: receive cursor");
        assert_eq!(durable.store.next_sender_seq(), 6, "{case}: send counter");

        let app = Recorder::new();
        let mut live = start(
            role,
            version,
            Arc::clone(&durable.store),
            Arc::clone(&app),
            &ledger,
            peer_logon(5),
        )
        .await;
        assert_eq!(live.own_seq(), 6, "{case}: the standby continues at 6");
        assert!(
            app.mismatches().is_empty(),
            "{case}: nothing to report: {:?}",
            app.mismatches()
        );
        assert!(app.events().contains(&Event::Logon), "{case}");
        let opening = live.peer.drain().await;
        assert!(
            !opening
                .iter()
                .any(|frame| field(frame, 35).as_deref() == Some("2")),
            "{case}: the standby asks for nothing"
        );
        let replies = ask_resend(&mut live.peer, 6, 1, 6).await;
        assert_resend(&ledger, &replies, 1, 6, &case);
        for seq in [1, 4, 6] {
            assert!(
                replies.iter().any(|reply| is_gap_fill(reply)
                    && (number(reply, 34)..number(reply, 36)).contains(&seq)),
                "{case}: administrative message {seq} gap-filled"
            );
        }
        for seq in [2, 3, 5] {
            assert!(
                replies
                    .iter()
                    .any(|reply| number(reply, 34) == seq && !is_gap_fill(reply)),
                "{case}: application message {seq} replayed"
            );
        }
        assert_no_reuse(&ledger, &case);
        drop(live);
    }
}

#[tokio::test]
async fn test_takeover_complete_prefix_acceptor() {
    takeover_complete_prefix(Role::Acceptor).await;
}

#[tokio::test]
async fn test_takeover_complete_prefix_initiator() {
    takeover_complete_prefix(Role::Initiator).await;
}

/// Incomplete prefix, with 789: the standby's copy ends after the engine sent
/// 2 and received 2, while the active went on to 5 and 4. The counterparty's
/// Logon (`MsgSeqNum` 5, 789 = 6) is ahead of the standby in both
/// directions. The standby reports both ranges through
/// `on_sequence_mismatch`, refuses the Logon with
/// `EngineError::NextExpectedMsgSeqNum`, never reaches `on_logon`, adopts
/// none of the counterparty's numbers, and retransmits nothing.
async fn takeover_incomplete_prefix(version: Version) {
    let role = Role::Acceptor;
    let case = format!("{version:?} incomplete-prefix takeover");
    let durable = Durable::new(Kind::File, &format!("partial-{version:?}")).await;
    let ledger = Ledger::default();
    let copy = active_session(
        role,
        version,
        &durable,
        &ledger,
        Some(&format!("partial-copy-{version:?}")),
        &case,
    )
    .await;
    let Some((config, _copy_dir)) = copy else {
        panic!("{case}: the copy was taken");
    };
    let standby: Arc<dyn MessageStore> =
        Arc::new(ok(FileStore::open(config).await, "open the standby's copy"));
    assert_eq!(standby.next_sender_seq(), 3, "{case}: the copy's sender");
    assert_eq!(standby.next_target_seq(), 3, "{case}: the copy's target");

    let app = Recorder::new();
    let before = ledger.frames().len();
    let mut live = start(
        role,
        version,
        Arc::clone(&standby),
        Arc::clone(&app),
        &ledger,
        peer_logon(5),
    )
    .await;
    let after_logon = live.peer.drain().await;
    assert!(
        matches!(live.result, Err(EngineError::NextExpectedMsgSeqNum { .. })),
        "{case}: refused: {:?}",
        live.result.as_ref().err()
    );
    assert!(!app.events().contains(&Event::Logon), "{case}: no on_logon");
    let mismatches = app.mismatches();
    assert_eq!(mismatches.len(), 1, "{case}: {mismatches:?}");
    let mismatch = mismatches[0];
    assert_eq!(
        mismatch.inbound(),
        Some(InboundMismatch::Gap { first: 3, last: 4 }),
        "{case}: the inbound range the standby lacks"
    );
    assert_eq!(
        mismatch.outbound(),
        OutboundMismatch::PeerAhead {
            declared: 6,
            next_outbound: 3
        },
        "{case}: the outbound range the standby lacks"
    );
    assert_eq!(mismatch.effective_next_sender(), 3, "{case}");
    assert_eq!(mismatch.effective_next_target(), 3, "{case}");

    // Nothing is retransmitted, and the counterparty's numbers are not
    // adopted: the only frame is the refusal FIX prescribes for a 789 above
    // what was sent, a Logout numbered from the standby's own counter.
    let sent = &ledger.frames()[before..];
    assert!(
        sent.iter().all(|frame| !is_poss_dup(frame)),
        "{case}: no retransmission: {sent:?}"
    );
    let types: Vec<String> = sent
        .iter()
        .map(|frame| field(frame, 35).unwrap_or_default())
        .collect();
    assert_eq!(types, vec!["5".to_string()], "{case}: a Logout alone");
    assert_eq!(
        number(&sent[0], 34),
        3,
        "{case}: from the standby's counter"
    );
    assert!(after_logon.len() <= 1, "{case}");
    assert_eq!(standby.next_target_seq(), 3, "{case}: no counter adopted");
    let found = reuses(&ledger);
    assert_eq!(
        found,
        vec![Reuse {
            seq: 3,
            msg_type: "5".to_string(),
            poss_dup: false,
        }],
        "{case}: the refusal Logout is the only number the standby reuses"
    );
    drop(live);
}

#[tokio::test]
async fn test_takeover_incomplete_prefix_fix44() {
    takeover_incomplete_prefix(Version::Fix44).await;
}

#[tokio::test]
async fn test_takeover_incomplete_prefix_fixt11() {
    takeover_incomplete_prefix(Version::Fixt11).await;
}

/// Incomplete inbound prefix on FIX.4.2 (no 789): the standby's copy holds
/// every outbound message but not the counterparty's last ones. The gap is
/// reported and recovered with a `ResendRequest`.
#[tokio::test]
async fn test_takeover_incomplete_inbound_prefix_fix42() {
    let role = Role::Acceptor;
    let version = Version::Fix42;
    let case = "Fix42 incomplete inbound prefix";
    let durable = Durable::new(Kind::File, "partial-in-fix42").await;
    let store = CrashStore::new(Arc::clone(&durable.store), Point::Manual);
    let ledger = Ledger::default();
    let mut live = start(
        role,
        version,
        Arc::clone(&store) as Arc<dyn MessageStore>,
        Recorder::new(),
        &ledger,
        peer_logon(1),
    )
    .await;
    send_app(&live, role, "ORDER-2").await;
    let inner = Arc::clone(&durable.store);
    until(&format!("{case}: 2 sent"), || inner.next_sender_seq() == 3).await;
    let _ = live.peer.drain().await;
    let (config, _copy_dir) = durable.snapshot("partial-in-fix42-copy");
    live.peer.app(2).await;
    until(&format!("{case}: 2 received"), || {
        inner.next_target_seq() == 3 && inner.app_watermark() == 2
    })
    .await;
    store.crash();
    drop(inner);
    drop(live);

    let standby: Arc<dyn MessageStore> =
        Arc::new(ok(FileStore::open(config).await, "open the standby's copy"));
    let app = Recorder::new();
    let mut live = start(
        role,
        version,
        Arc::clone(&standby),
        Arc::clone(&app),
        &ledger,
        peer_logon(3),
    )
    .await;
    assert_eq!(
        live.own_seq(),
        3,
        "{case}: the standby holds every outbound"
    );
    let mismatches = app.mismatches();
    assert_eq!(mismatches.len(), 1, "{case}: {mismatches:?}");
    assert_eq!(
        mismatches[0].inbound(),
        Some(InboundMismatch::Gap { first: 2, last: 2 }),
        "{case}"
    );
    assert_eq!(
        mismatches[0].outbound(),
        OutboundMismatch::NotDeclared,
        "{case}"
    );
    let request = live.peer.recv_type("2").await;
    assert_eq!(number(&request, 7), 2, "{case}: asks for what it lacks");
    live.peer
        .send(
            role.peer_app_type(),
            2,
            &[(43, "Y".to_string()), (11, "PEER-2".to_string())],
        )
        .await;
    live.peer
        .send(
            "4",
            3,
            &[
                (43, "Y".to_string()),
                (123, "Y".to_string()),
                (36, "4".to_string()),
            ],
        )
        .await;
    until(&format!("{case}: recovered"), || {
        standby.next_target_seq() == 4
    })
    .await;
    assert_eq!(app.delivered(), vec![(2, true)], "{case}");
    assert_no_reuse(&ledger, case);
    drop(live);
}

/// Split brain: while the active process holds the session, a standby on the
/// same files cannot open the store (the single-writer lock), and the active
/// Acceptor refuses a second Logon for the live session without answering
/// it. This is the guard the engine has; it is not a fence (ADR-0015).
#[tokio::test]
async fn test_split_brain_guard() {
    let role = Role::Acceptor;
    let version = Version::Fix44;
    let durable = Durable::new(Kind::File, "split-brain").await;
    let Some((config, _)) = &durable.file else {
        panic!("a file store");
    };
    let second = FileStore::open(config.clone()).await;
    assert!(
        matches!(second, Err(StoreError::Io(_))),
        "a second opener is refused while the first holds the lock"
    );

    let acceptor = Arc::new(
        Acceptor::new(role.config(version), Recorder::new())
            .with_store(Arc::clone(&durable.store))
            .with_store_failure_policy(StoreFailurePolicy::CloseSession),
    );
    let ledger = Ledger::default();
    let (engine_io, peer_io) = tokio::io::duplex(64 * 1024);
    let mut peer = Peer::new(peer_io, ledger.clone(), version, role);
    let shared = Arc::clone(&acceptor);
    let served = tokio::spawn(async move { shared.serve_stream(engine_io).await });
    peer.logon(1, Some(1)).await;
    let live = ok(
        ok(timeout(STEP, served).await, "handshake in time"),
        "handshake task",
    );
    let live = ok(live, "the first Logon is accepted");
    let _ = peer.recv_type("A").await;

    let (engine_io, peer_io) = tokio::io::duplex(64 * 1024);
    let other_ledger = Ledger::default();
    let mut intruder = Peer::new(peer_io, other_ledger.clone(), version, role);
    let shared = Arc::clone(&acceptor);
    let served = tokio::spawn(async move { shared.serve_stream(engine_io).await });
    intruder.logon(2, Some(2)).await;
    let refused = ok(
        ok(timeout(STEP, served).await, "refusal in time"),
        "refusal task",
    );
    assert!(refused.is_err(), "the duplicate Logon is refused");
    let _ = intruder.drain().await;
    assert!(
        other_ledger.frames().is_empty(),
        "the duplicate gets nothing numbered from the live stream"
    );
    assert_eq!(
        durable.store.next_sender_seq(),
        2,
        "the live stream is intact"
    );
    drop(live);
}
