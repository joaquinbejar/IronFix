/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! The poll-driven initiator of `examples/poll_driver` (issue #93) against
//! the Tokio `Acceptor`.
//!
//! The client runs on the test thread with no async runtime; the acceptor
//! runs on a Tokio runtime of its own thread. The client resumes a previous
//! stream from its store (messages 1 to 4 filed, its Logon at 5) while the
//! acceptor expects 2, so the acceptor asks for 2 onwards with a
//! `ResendRequest` (2) and the client answers from its store through the
//! sans-IO replay decisions: the two filed orders resent with
//! `PossDupFlag` (43) = Y, and its Heartbeat and Logon gap-filled. The
//! client then sends a new order and logs out.

#[path = "../examples/poll_driver/mod.rs"]
mod poll_driver;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::application::{Application, RejectReason, SessionId};
use ironfix_engine::{Acceptor, OutboundMessage, SyncApplication};
use ironfix_session::SessionConfig;
use ironfix_store::{MemoryStore, MessageStore, SyncMessageStore};
use ironfix_tagvalue::Encoder;
use poll_driver::{Ended, PollSession};

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

/// What the acceptor's application saw: (MsgSeqNum, MsgType, 43=Y).
type Seen = (u64, String, bool);

#[derive(Debug, Default)]
struct ServerApp {
    seen: Mutex<Vec<Seen>>,
    logged_out: Mutex<bool>,
}

#[async_trait]
impl Application for ServerApp {
    async fn on_create(&self, _session_id: &SessionId) {}

    async fn on_logon(&self, _session_id: &SessionId) {}

    async fn on_logout(&self, _session_id: &SessionId) {
        if let Ok(mut logged_out) = self.logged_out.lock() {
            *logged_out = true;
        }
    }

    async fn to_admin(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

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
        message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        let seq = message
            .get_field_str(34)
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        if let Ok(mut seen) = self.seen.lock() {
            seen.push((
                seq,
                message.msg_type().as_str().to_string(),
                message.get_field_str(43) == Some("Y"),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct ClientApp {
    rejected: Mutex<u32>,
}

impl SyncApplication for ClientApp {
    fn on_create(&self, _session_id: &SessionId) {}

    fn on_logon(&self, _session_id: &SessionId) {}

    fn on_logout(&self, _session_id: &SessionId) {}

    fn to_admin(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    fn from_admin(
        &self,
        message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        if *message.msg_type() == MsgType::Reject
            && let Ok(mut rejected) = self.rejected.lock()
        {
            *rejected += 1;
        }
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

/// A frame the client sent in its previous stream.
fn client_frame(msg_type: &str, seq: u64, body: &[(u32, &str)]) -> Vec<u8> {
    let mut encoder = Encoder::new("FIX.4.4");
    encoder.put_str(35, msg_type);
    encoder.put_str(49, "CLIENT");
    encoder.put_str(56, "VENUE");
    encoder.put_uint(34, seq);
    encoder.put_str(52, Timestamp::now().format_millis().as_str());
    for (tag, value) in body {
        encoder.put_str(*tag, value);
    }
    ok(encoder.finish(), "a seed frame encodes").to_vec()
}

fn order_body(id: &str) -> [(u32, &str); 5] {
    [(11, id), (55, "AAPL"), (54, "1"), (38, "100"), (40, "1")]
}

/// The client's previous stream: Logon 1, orders 2 and 3, a Heartbeat at 4;
/// next sender 5, next target 1 (the acceptor starts fresh).
fn client_store() -> MemoryStore {
    let store = MemoryStore::new();
    let seed = [
        (
            1,
            MsgType::Logon,
            client_frame("A", 1, &[(98, "0"), (108, "30")]),
        ),
        (
            2,
            MsgType::NewOrderSingle,
            client_frame("D", 2, &order_body("OLD-2")),
        ),
        (
            3,
            MsgType::NewOrderSingle,
            client_frame("D", 3, &order_body("OLD-3")),
        ),
        (4, MsgType::Heartbeat, client_frame("0", 4, &[])),
    ];
    for (seq, msg_type, frame) in seed {
        ok(
            SyncMessageStore::store(&store, seq, &msg_type, &frame),
            "seed",
        );
    }
    ok(SyncMessageStore::set_next_sender_seq(&store, 5), "sender");
    store
}

/// Starts the Tokio acceptor on its own thread, with a store that expects
/// the client's 2. Returns its address.
fn spawn_acceptor(app: Arc<ServerApp>) -> SocketAddr {
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let runtime = ok(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build(),
            "the acceptor's runtime",
        );
        runtime.block_on(async move {
            let listener = ok(tokio::net::TcpListener::bind("127.0.0.1:0").await, "bind");
            ok(addr_tx.send(ok(listener.local_addr(), "addr")), "send addr");
            let (socket, _) = ok(listener.accept().await, "accept");
            let store = MemoryStore::new();
            ok(MessageStore::set_next_target_seq(&store, 2).await, "acceptor target");
            let config = SessionConfig::new(comp_id("VENUE"), comp_id("CLIENT"), "FIX.4.4")
                .with_heartbeat_interval(Duration::from_secs(30));
            let connection = ok(
                Acceptor::new(config, app)
                    .with_store(Arc::new(store))
                    .serve(socket)
                    .await,
                "the acceptor establishes the session",
            );
            connection.wait_closed().await;
        });
    });
    ok(
        addr_rx.recv_timeout(Duration::from_secs(5)),
        "the acceptor binds",
    )
}

/// Polls until `done` holds, within 10 s.
fn poll_until(
    session: &mut PollSession<ClientApp, MemoryStore>,
    what: &str,
    done: impl Fn(&PollSession<ClientApp, MemoryStore>) -> bool,
) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done(session) {
        assert!(
            session.ended().is_none(),
            "the session ended while waiting for {what}: {:?}",
            session.ended()
        );
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        if !session.poll(Instant::now()) {
            thread::sleep(Duration::from_millis(1));
        }
    }
}

#[test]
fn test_poll_initiator_against_the_tokio_acceptor() {
    let server = Arc::new(ServerApp::default());
    let addr = spawn_acceptor(Arc::clone(&server));
    let config = SessionConfig::new(comp_id("CLIENT"), comp_id("VENUE"), "FIX.4.4")
        .with_heartbeat_interval(Duration::from_secs(30));
    let mut session = ok(
        PollSession::connect(
            addr,
            config,
            ClientApp::default(),
            client_store(),
            Instant::now(),
        ),
        "the client connects",
    );
    poll_until(&mut session, "the Logon", PollSession::is_active);

    // The acceptor expected 2 and saw the Logon at 5: it asks for 2
    // onwards, and the client's replay resends the two orders.
    let seen = |server: &ServerApp| {
        server
            .seen
            .lock()
            .map(|seen| seen.clone())
            .unwrap_or_default()
    };
    poll_until(&mut session, "the resend", |_| seen(&server).len() >= 2);
    assert_eq!(
        seen(&server),
        [(2, "D".to_string(), true), (3, "D".to_string(), true),],
        "the filed orders are resent as possible duplicates"
    );

    // A new order after the resend takes the next number, unflagged.
    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    for (tag, value) in order_body("NEW-6") {
        order.push_str(tag, value);
    }
    let seq = ok(session.send_app(order, Instant::now()), "the new order");
    assert_eq!(seq, 6, "the gap fill covered 4 and 5, so the next is 6");
    poll_until(&mut session, "the new order", |_| seen(&server).len() >= 3);
    assert_eq!(seen(&server)[2], (6, "D".to_string(), false));

    session.logout(Instant::now());
    poll_until(&mut session, "the Logout", |session| {
        session.ended().is_some()
    });
    assert_eq!(session.ended(), Some(&Ended::LoggedOut));
    assert_eq!(
        session.app().rejected.lock().map(|rejected| *rejected).ok(),
        Some(0),
        "the acceptor rejected nothing the client sent"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !server.logged_out.lock().map(|done| *done).unwrap_or(false) {
        assert!(Instant::now() < deadline, "the acceptor closed the session");
        thread::sleep(Duration::from_millis(5));
    }
}
