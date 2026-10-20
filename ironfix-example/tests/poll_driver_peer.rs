/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! The poll-driven initiator of `examples/poll_driver` (issue #93) against a
//! scripted raw peer over `std::net`, for the protocol cases the Tokio
//! acceptor never produces: an acknowledgement without `HeartBtInt` (108), a
//! TestRequest above a gap, a GapFill that does not advance, a replay of a
//! message with a LENGTH/DATA pair, and a store that reports itself
//! corrupted. Everything runs on the test thread, with no runtime.

#[path = "../examples/poll_driver/mod.rs"]
mod poll_driver;

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use ironfix_core::error::StoreError;
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::application::{RejectReason, SessionId};
use ironfix_engine::{OutboundMessage, SyncApplication};
use ironfix_session::SessionConfig;
use ironfix_store::{MemoryStore, StoredMessage, SyncMessageStore};
use ironfix_tagvalue::{Decoder as FrameDecoder, Encoder};
use ironfix_transport::FixCodec;
use poll_driver::{Ended, PollSession};
use tokio_util::codec::Decoder;

#[track_caller]
fn ok<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{what}: {err:?}"),
    }
}

#[derive(Debug, Default)]
struct App;

impl SyncApplication for App {
    fn on_create(&self, _session_id: &SessionId) {}

    fn on_logon(&self, _session_id: &SessionId) {}

    fn on_logout(&self, _session_id: &SessionId) {}

    fn to_admin(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    fn from_admin(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }

    fn to_app(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    fn from_app(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }
}

/// A store whose page reads report corruption; everything else is a
/// `MemoryStore`.
#[derive(Debug, Default)]
struct CorruptStore {
    inner: MemoryStore,
}

impl SyncMessageStore for CorruptStore {
    fn store(&self, seq_num: u64, msg_type: &MsgType, message: &[u8]) -> Result<(), StoreError> {
        SyncMessageStore::store(&self.inner, seq_num, msg_type, message)
    }

    fn get_range(&self, _begin: u64, _end: u64) -> Result<Vec<StoredMessage>, StoreError> {
        Err(StoreError::Corrupted {
            reason: "test".to_string(),
        })
    }

    fn get_page(
        &self,
        _begin: u64,
        _end: u64,
        _limit: usize,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        Err(StoreError::Corrupted {
            reason: "test".to_string(),
        })
    }

    fn next_sender_seq(&self) -> u64 {
        SyncMessageStore::next_sender_seq(&self.inner)
    }

    fn next_target_seq(&self) -> u64 {
        SyncMessageStore::next_target_seq(&self.inner)
    }

    fn set_next_sender_seq(&self, seq: u64) -> Result<(), StoreError> {
        SyncMessageStore::set_next_sender_seq(&self.inner, seq)
    }

    fn set_next_target_seq(&self, seq: u64) -> Result<(), StoreError> {
        SyncMessageStore::set_next_target_seq(&self.inner, seq)
    }

    fn reset(&self) -> Result<(), StoreError> {
        SyncMessageStore::reset(&self.inner)
    }

    fn creation_time(&self) -> std::time::SystemTime {
        SyncMessageStore::creation_time(&self.inner)
    }
}

/// A frame from the peer (VENUE) to the client.
fn peer_frame(msg_type: &str, seq: u64, body: &[(u32, &str)]) -> Vec<u8> {
    let mut encoder = Encoder::new("FIX.4.4");
    encoder.put_str(35, msg_type);
    encoder.put_str(49, "VENUE");
    encoder.put_str(56, "CLIENT");
    encoder.put_uint(34, seq);
    encoder.put_str(52, Timestamp::now().format_millis().as_str());
    for (tag, value) in body {
        encoder.put_str(*tag, value);
    }
    ok(encoder.finish(), "a peer frame encodes").to_vec()
}

fn field(frame: &[u8], tag: u32) -> Option<String> {
    let mut decoder = FrameDecoder::new(frame);
    let message = decoder.decode().ok()?;
    message.get_field_str(tag).map(str::to_string)
}

/// The scripted peer's end: a blocking socket with a short read timeout,
/// and a codec over what it read.
struct Peer {
    stream: TcpStream,
    codec: FixCodec,
    buf: BytesMut,
}

impl Peer {
    fn send(&mut self, frame: &[u8]) {
        ok(self.stream.write_all(frame), "the peer writes");
    }

    /// The next frame from the client, polling the client meanwhile.
    fn next<S: SyncMessageStore>(&mut self, client: &mut PollSession<App, S>) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(frame) = ok(self.codec.decode(&mut self.buf), "the peer frames") {
                return frame.to_vec();
            }
            assert!(
                Instant::now() < deadline,
                "no frame from the client within 5s"
            );
            client.poll(Instant::now());
            let mut chunk = [0_u8; 4096];
            match self.stream.read(&mut chunk) {
                Ok(0) => panic!("the client closed before sending a frame"),
                Ok(read) => self.buf.extend_from_slice(&chunk[..read]),
                Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(err) => panic!("the peer read failed: {err}"),
            }
        }
    }
}

/// Connects a client with `store` to a fresh peer, and reads its Logon.
fn connect<S: SyncMessageStore>(store: S) -> (PollSession<App, S>, Peer, Vec<u8>) {
    let listener = ok(TcpListener::bind("127.0.0.1:0"), "bind");
    let addr = ok(listener.local_addr(), "addr");
    let config = SessionConfig::new(
        ok(CompId::new("CLIENT"), "comp id"),
        ok(CompId::new("VENUE"), "comp id"),
        "FIX.4.4",
    )
    .with_heartbeat_interval(Duration::from_secs(30));
    let client = ok(
        PollSession::connect(addr, config, App, store, Instant::now()),
        "the client connects",
    );
    let (stream, _) = ok(listener.accept(), "accept");
    ok(
        stream.set_read_timeout(Some(Duration::from_millis(5))),
        "read timeout",
    );
    let mut peer = Peer {
        stream,
        codec: FixCodec::new(),
        buf: BytesMut::new(),
    };
    let mut client = client;
    let logon = peer.next(&mut client);
    assert_eq!(field(&logon, 35).as_deref(), Some("A"));
    (client, peer, logon)
}

/// Connects and completes the Logon exchange with the peer's ack at 1.
fn logged_on<S: SyncMessageStore>(store: S) -> (PollSession<App, S>, Peer) {
    let (mut client, mut peer, _) = connect(store);
    peer.send(&peer_frame("A", 1, &[(98, "0"), (108, "30")]));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !client.is_active() {
        assert!(client.ended().is_none(), "ended: {:?}", client.ended());
        assert!(Instant::now() < deadline, "the client logs on");
        if !client.poll(Instant::now()) {
            thread::sleep(Duration::from_millis(1));
        }
    }
    (client, peer)
}

#[test]
fn test_ack_without_heartbeat_interval_is_rejected_and_ends_the_session() {
    let (mut client, mut peer, _) = connect(MemoryStore::new());
    peer.send(&peer_frame("A", 1, &[(98, "0")]));
    let reject = peer.next(&mut client);
    assert_eq!(field(&reject, 35).as_deref(), Some("3"));
    assert_eq!(field(&reject, 371).as_deref(), Some("108"));
    assert_eq!(field(&reject, 373).as_deref(), Some("1"));
    let logout = peer.next(&mut client);
    assert_eq!(field(&logout, 35).as_deref(), Some("5"));
    assert!(matches!(client.ended(), Some(Ended::Protocol(_))));
    assert!(!client.is_active());
}

#[test]
fn test_ack_heartbeat_interval_is_adopted() {
    let (mut client, mut peer, _) = connect(MemoryStore::new());
    // The peer confirms a different interval: the session runs on it, so a
    // Heartbeat is due after 1 s of silence rather than 30.
    peer.send(&peer_frame("A", 1, &[(98, "0"), (108, "1")]));
    let heartbeat = peer.next(&mut client);
    assert_eq!(field(&heartbeat, 35).as_deref(), Some("0"));
    assert!(client.is_active());
}

#[test]
fn test_test_request_above_a_gap_is_still_answered() {
    let (mut client, mut peer) = logged_on(MemoryStore::new());
    // The client expects 2; a TestRequest at 4 opens a gap.
    peer.send(&peer_frame("1", 4, &[(112, "PING")]));
    let request = peer.next(&mut client);
    assert_eq!(
        field(&request, 35).as_deref(),
        Some("2"),
        "the gap is requested"
    );
    assert_eq!(field(&request, 7).as_deref(), Some("2"));
    let heartbeat = peer.next(&mut client);
    assert_eq!(field(&heartbeat, 35).as_deref(), Some("0"));
    assert_eq!(field(&heartbeat, 112).as_deref(), Some("PING"));
}

#[test]
fn test_a_rejected_in_sequence_gap_fill_still_consumes_its_number() {
    let (mut client, mut peer) = logged_on(MemoryStore::new());
    // A GapFill at 2 whose NewSeqNo does not pass it: rejected, consumed.
    peer.send(&peer_frame("4", 2, &[(123, "Y"), (36, "2")]));
    let reject = peer.next(&mut client);
    assert_eq!(field(&reject, 35).as_deref(), Some("3"));
    assert_eq!(field(&reject, 45).as_deref(), Some("2"));
    assert_eq!(field(&reject, 373).as_deref(), Some("5"));
    // So 3 is in sequence: a TestRequest at 3 is answered with no
    // ResendRequest first.
    peer.send(&peer_frame("1", 3, &[(112, "NEXT")]));
    let reply = peer.next(&mut client);
    assert_eq!(field(&reply, 35).as_deref(), Some("0"), "no gap at 3");
    assert_eq!(field(&reply, 112).as_deref(), Some("NEXT"));
    assert!(client.is_active());
}

#[test]
fn test_a_replay_keeps_a_length_data_pair() {
    let store = MemoryStore::new();
    // A stored order with EncodedTextLen (354) / EncodedText (355) whose
    // payload carries an SOH.
    let mut encoder = Encoder::new("FIX.4.4");
    encoder.put_str(35, "D");
    encoder.put_str(49, "CLIENT");
    encoder.put_str(56, "VENUE");
    encoder.put_uint(34, 2);
    encoder.put_str(52, Timestamp::now().format_millis().as_str());
    encoder.put_str(11, "ORD-2");
    encoder.put_data(354, 355, b"a\x01b");
    let order = ok(encoder.finish(), "the stored order encodes").to_vec();
    ok(
        SyncMessageStore::store(&store, 2, &MsgType::NewOrderSingle, &order),
        "seed",
    );
    ok(SyncMessageStore::set_next_sender_seq(&store, 3), "sender");
    let (mut client, mut peer) = logged_on(store);
    peer.send(&peer_frame("2", 2, &[(7, "2"), (16, "0")]));
    let replay = peer.next(&mut client);
    assert_eq!(
        field(&replay, 35).as_deref(),
        Some("D"),
        "replayed, not filled"
    );
    assert_eq!(field(&replay, 34).as_deref(), Some("2"));
    assert_eq!(field(&replay, 43).as_deref(), Some("Y"));
    assert_eq!(field(&replay, 354).as_deref(), Some("3"));
}

#[test]
fn test_a_corrupted_store_ends_the_session_instead_of_gap_filling() {
    let store = CorruptStore::default();
    let order = peer_frame("D", 2, &[(11, "ORD-2")]);
    ok(
        SyncMessageStore::store(&store, 2, &MsgType::NewOrderSingle, &order),
        "seed",
    );
    ok(SyncMessageStore::set_next_sender_seq(&store, 3), "sender");
    let (mut client, mut peer) = logged_on(store);
    peer.send(&peer_frame("2", 2, &[(7, "2"), (16, "0")]));
    let logout = peer.next(&mut client);
    assert_eq!(
        field(&logout, 35).as_deref(),
        Some("5"),
        "a Logout, never a GapFill over filed messages"
    );
    assert!(matches!(client.ended(), Some(Ended::Protocol(_))));
}
