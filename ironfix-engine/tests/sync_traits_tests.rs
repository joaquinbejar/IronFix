/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! The synchronous application and store traits (issue #92, ADR-0002).
//!
//! The first test drives the sans-IO core with no runtime: a
//! `ResendRequest` (2) is checked by a [`SyncApplication`], decided by the
//! core, and answered from a [`MemoryStore`] through [`SyncMessageStore`],
//! with the replay gate vetoing one message. The second runs the same
//! synchronous implementations under the Tokio acceptor through
//! [`SyncApplicationAdapter`] and [`SyncStoreAdapter`], and checks the wire.

use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::application::{RejectReason, SessionId};
use ironfix_engine::{Acceptor, OutboundMessage, SyncApplication, SyncApplicationAdapter};
use ironfix_session::SessionConfig;
use ironfix_session::sans_io::{
    EndSeqNoInfinity, EntryScreen, GapFillRange, PageRead, ReplayAction, ReplayStep, ReplayVerdict,
    ResendReplay, ResendRequestDecision, decide_resend_request,
};
use ironfix_store::{MemoryStore, SyncMessageStore, SyncStoreAdapter};
use ironfix_tagvalue::{Decoder, Encoder};
use ironfix_transport::FixCodec;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::DuplexStream;
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

/// A FIX.4.4 frame from `sender` to `target`.
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

fn field(frame: &[u8], tag: u32) -> Option<String> {
    let mut decoder = Decoder::new(frame);
    let message = decoder.decode().ok()?;
    message.get_field_str(tag).map(str::to_string)
}

fn num(frame: &[u8], tag: u32) -> u64 {
    field(frame, tag)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

/// A synchronous application: accepts every admin message, counts them,
/// and vetoes the replay of the numbers in `veto`.
#[derive(Debug, Default)]
struct SyncApp {
    veto: Vec<u64>,
    admin_seen: Mutex<Vec<String>>,
    replays_asked: Mutex<Vec<u64>>,
}

impl SyncApplication for SyncApp {
    fn on_create(&self, _session_id: &SessionId) {}

    fn on_logon(&self, _session_id: &SessionId) {}

    fn on_logout(&self, _session_id: &SessionId) {}

    fn to_admin(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    fn from_admin(
        &self,
        message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        if let Ok(mut seen) = self.admin_seen.lock() {
            seen.push(message.msg_type().as_str().to_string());
        }
        Ok(())
    }

    fn to_app(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    fn to_app_resend(
        &self,
        message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        let seq = message
            .get_field_str(34)
            .and_then(|seq| seq.parse().ok())
            .unwrap_or(0);
        if let Ok(mut asked) = self.replays_asked.lock() {
            asked.push(seq);
        }
        if self.veto.contains(&seq) {
            Err(RejectReason::new(1, "stale order"))
        } else {
            Ok(())
        }
    }

    fn from_app(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }
}

/// The engine's (VENUE) previous stream, filed through the synchronous
/// trait: its Logon (1), execution reports at 2, 3, 5 and 6, a Heartbeat at
/// 4; next sender 7, next target 3.
fn seeded_store() -> MemoryStore {
    let store = MemoryStore::new();
    let logon = frame("VENUE", "CLIENT", "A", 1, &[(98, "0"), (108, "30")]);
    ok(
        SyncMessageStore::store(&store, 1, &MsgType::Logon, &logon),
        "seed the Logon",
    );
    let body = [(37, "EX-1"), (17, "E-1"), (150, "0"), (39, "0")];
    for seq in [2, 3, 5, 6] {
        let report = frame("VENUE", "CLIENT", "8", seq, &body);
        ok(
            SyncMessageStore::store(&store, seq, &MsgType::ExecutionReport, &report),
            "seed a report",
        );
    }
    let heartbeat = frame("VENUE", "CLIENT", "0", 4, &[]);
    ok(
        SyncMessageStore::store(&store, 4, &MsgType::Heartbeat, &heartbeat),
        "seed a heartbeat",
    );
    ok(
        SyncMessageStore::set_next_sender_seq(&store, 7),
        "sender counter",
    );
    ok(
        SyncMessageStore::set_next_target_seq(&store, 3),
        "target counter",
    );
    store
}

/// What a driver writes for the resend, as the peer would see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Written {
    Replay(u64),
    Fill(u64, u64),
}

fn fill(range: GapFillRange) -> Written {
    Written::Fill(range.at, range.new_seq)
}

/// The sans-IO core answers a ResendRequest from a synchronous store, with
/// a synchronous application checking it and gating each replay: no async
/// runtime anywhere.
#[test]
fn test_sans_io_core_answers_a_resend_request_from_sync_traits() {
    let store = seeded_store();
    let app = SyncApp {
        veto: vec![5],
        ..SyncApp::default()
    };
    let session = SessionId::new("FIX.4.4", "VENUE", "CLIENT");

    // The counterparty asks for everything from 2.
    let request = frame("CLIENT", "VENUE", "2", 3, &[(7, "2"), (16, "0")]);
    let mut decoder = Decoder::new(&request);
    let raw = ok(decoder.decode(), "the ResendRequest decodes");
    ok(app.from_admin(&raw, &session), "the application accepts it");
    let begin_seq = raw.get_field_str(7).and_then(|value| value.parse().ok());
    let end_seq = raw.get_field_str(16).and_then(|value| value.parse().ok());
    let infinity = EndSeqNoInfinity::for_version(ironfix_core::version::FixVersion::Fix44);
    let decision = decide_resend_request(
        begin_seq,
        end_seq,
        SyncMessageStore::next_sender_seq(&store),
        infinity,
    );
    let ResendRequestDecision::Replay { begin_seq, new_seq } = decision else {
        panic!("a valid request is replayed, got {decision:?}");
    };
    assert_eq!((begin_seq, new_seq), (2, 7));

    // The driver loop: poll the core, read pages from the store, gate each
    // candidate with the application, write what the core decides.
    let Some(mut replay) = ResendReplay::new(begin_seq, new_seq, true) else {
        panic!("2..7 is a range");
    };
    let mut written = Vec::new();
    loop {
        match replay.poll_store() {
            ReplayStep::ReadPage(page) => {
                let read = SyncMessageStore::get_page(&store, page.from, page.through, page.limit);
                let messages = ok(read, "the page reads");
                replay.on_page(PageRead::Read {
                    len: messages.len(),
                    furthest: messages.last().map(|message| message.seq_num()),
                });
                for message in &messages {
                    let is_admin = message.msg_type().is_admin();
                    if replay.screen_entry(message.seq_num(), is_admin) == EntryScreen::Skip {
                        continue;
                    }
                    let mut decoder = Decoder::new(message.payload());
                    let stored = ok(decoder.decode(), "a stored frame decodes");
                    let verdict = match app.to_app_resend(&stored, &session) {
                        Ok(()) => ReplayVerdict::Replay,
                        Err(_) => ReplayVerdict::GapFill,
                    };
                    match replay.decide_entry(message.seq_num(), verdict) {
                        ReplayAction::Skip => {}
                        ReplayAction::Replay { seq } => written.push(Written::Replay(seq)),
                        ReplayAction::GapFillThenReplay { gap_fill, seq } => {
                            written.push(fill(gap_fill));
                            written.push(Written::Replay(seq));
                        }
                    }
                }
            }
            ReplayStep::StoreExhausted => {}
            ReplayStep::Complete { gap_fill } => {
                written.extend(gap_fill.map(fill));
                break;
            }
        }
    }

    // The Logon at 1 is outside the request; the Heartbeat at 4 is admin
    // and the report at 5 vetoed, so 4..6 is one fill.
    assert_eq!(
        written,
        [
            Written::Replay(2),
            Written::Replay(3),
            Written::Fill(4, 6),
            Written::Replay(6),
        ]
    );
    assert_eq!(
        app.replays_asked.lock().map(|asked| asked.clone()).ok(),
        Some(vec![2, 3, 5, 6]),
        "the gate is asked about every stored application message, never an admin one"
    );
    assert_eq!(
        app.admin_seen.lock().map(|seen| seen.clone()).ok(),
        Some(vec!["2".to_string()])
    );
}

/// `MemoryStore` answers the same through both traits.
#[tokio::test]
async fn test_memory_store_agrees_through_both_traits() {
    let store = seeded_store();
    let sync_page = ok(SyncMessageStore::get_page(&store, 2, 6, 10), "sync page");
    let async_page = ok(
        ironfix_store::MessageStore::get_page(&store, 2, 6, 10).await,
        "async page",
    );
    assert_eq!(sync_page, async_page);
    let adapter = SyncStoreAdapter::new(store);
    ok(
        ironfix_store::MessageStore::file_outbound(
            &adapter,
            7,
            &MsgType::Heartbeat,
            &frame("VENUE", "CLIENT", "0", 7, &[]),
            8,
        )
        .await,
        "a write through the adapter",
    );
    assert_eq!(SyncMessageStore::next_sender_seq(adapter.inner()), 8);
    assert!(adapter.inner().contains(7));
}

type PeerFramed = Framed<DuplexStream, FixCodec>;

async fn next_frame(framed: &mut PeerFramed) -> BytesMut {
    match timeout(Duration::from_secs(5), framed.next()).await {
        Ok(Some(Ok(frame))) => frame,
        Ok(Some(Err(err))) => panic!("frame must decode: {err:?}"),
        Ok(None) => panic!("the engine hung up"),
        Err(_) => panic!("no frame within 5s"),
    }
}

/// The same synchronous application and store, adapted, run under the
/// Tokio acceptor: a ResendRequest is answered from the store with the
/// vetoed report gap-filled, as the sans-IO run above decided.
#[tokio::test]
async fn test_sync_traits_run_under_the_tokio_acceptor() {
    let app = Arc::new(SyncApplicationAdapter::new(SyncApp {
        veto: vec![5],
        ..SyncApp::default()
    }));
    let store = Arc::new(SyncStoreAdapter::new(seeded_store()));
    let config = SessionConfig::new(comp_id("VENUE"), comp_id("CLIENT"), "FIX.4.4")
        .with_heartbeat_interval(Duration::from_secs(30));
    let (peer_io, engine_io) = tokio::io::duplex(64 * 1024);
    let engine_app = Arc::clone(&app);
    let engine = tokio::spawn(async move {
        Acceptor::new(config, engine_app)
            .with_store(store)
            .serve_stream(engine_io)
            .await
    });
    let mut framed = Framed::new(peer_io, FixCodec::new());
    ok(
        framed
            .send(frame("CLIENT", "VENUE", "A", 3, &[(98, "0"), (108, "30")]))
            .await,
        "the peer's Logon",
    );
    let ack = next_frame(&mut framed).await;
    assert_eq!(field(&ack, 35).as_deref(), Some("A"), "Logon acknowledged");
    assert_eq!(num(&ack, 34), 7);
    let connection = ok(
        ok(
            ok(timeout(Duration::from_secs(5), engine).await, "handshake"),
            "engine task joins",
        ),
        "the engine establishes the session",
    );
    ok(
        framed
            .send(frame("CLIENT", "VENUE", "2", 4, &[(7, "2"), (16, "0")]))
            .await,
        "the ResendRequest",
    );
    // 2..8: the acknowledgement at 7 is admin, so the trailing fill covers it.
    let mut seen = Vec::new();
    loop {
        let frame = next_frame(&mut framed).await;
        let seq = num(&frame, 34);
        let item = match field(&frame, 35).as_deref() {
            Some("8") => {
                assert_eq!(field(&frame, 43).as_deref(), Some("Y"), "43=Y on {seq}");
                Written::Replay(seq)
            }
            Some("4") => Written::Fill(seq, num(&frame, 36)),
            other => panic!("unexpected MsgType {other:?} at {seq} inside the resend"),
        };
        let reached = match item {
            Written::Replay(seq) => seq + 1,
            Written::Fill(_, new_seq) => new_seq,
        };
        seen.push(item);
        if reached >= 8 {
            break;
        }
    }
    assert_eq!(
        seen,
        [
            Written::Replay(2),
            Written::Replay(3),
            Written::Fill(4, 6),
            Written::Replay(6),
            Written::Fill(7, 8),
        ]
    );
    let asked = app
        .inner()
        .replays_asked
        .lock()
        .map(|asked| asked.clone())
        .ok();
    assert_eq!(asked, Some(vec![2, 3, 5, 6]));
    assert!(!connection.is_closed());
}
