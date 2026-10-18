/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Integration tests for the `AcceptorRegistry`: several sessions on one
//! loopback `TcpListener`, each inbound Logon routed by the identity it claims.
//!
//! The acceptance tests for issue #61: two real `Initiator`s with different
//! CompIDs reach Active on the right session with independent sequence
//! numbers and stores; a Logon for an unregistered CompID pair is closed with
//! no reply, no callback and no store access; a second concurrent Logon for a
//! live session is refused while the first continues, even when its version
//! or encryption is wrong; a `SessionLookup` can admit a session not
//! registered at startup, keeps one admission slot for it when two lookups
//! race, can refuse one, and can fail; a session it admits is evicted unless
//! a handshake gets past `from_admin`, and the cap bounds how many it holds;
//! an over-long, illegal or repeated CompID is refused before the lookup is
//! asked; and the routing phase is bounded by the registry's logon timeout.
//! The routing codec, the switch to the session's codec, FIXT.1.1, sub-ID and
//! location-ID routing are exercised over real sockets. Scripted peers play
//! the counterparty where a real `Initiator` cannot send what the test needs.

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::error::StoreError;
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::{CompId, Timestamp};
use ironfix_engine::application::{Application, RejectReason, SessionId};
use ironfix_engine::{
    Acceptor, AcceptorRegistry, Connection, EngineError, Initiator, LogonIdentity, LookupError,
    OutboundMessage, SessionLookup,
};
use ironfix_session::SessionConfig;
use ironfix_store::{MemoryStore, MessageStore, StoredMessage};
use ironfix_tagvalue::{Decoder, Encoder};
use ironfix_transport::FixCodec;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Barrier, mpsc};
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

/// Binds an ephemeral loopback listener.
async fn bind_listener() -> (TcpListener, std::net::SocketAddr) {
    let listener = ok(
        TcpListener::bind("127.0.0.1:0").await,
        "listener must bind to loopback",
    );
    let addr = ok(listener.local_addr(), "listener must report its address");
    (listener, addr)
}

/// The venue's session for `member`: sender is VENUE, target the member.
fn venue_for(member: &str) -> SessionConfig {
    SessionConfig::new(comp_id("VENUE"), comp_id(member), "FIX.4.4")
        .with_heartbeat_interval(Duration::from_secs(30))
}

/// The member's own session: sender is the member, target VENUE.
fn member_config(member: &str) -> SessionConfig {
    SessionConfig::new(comp_id(member), comp_id("VENUE"), "FIX.4.4")
        .with_heartbeat_interval(Duration::from_secs(30))
}

/// `config` with checksum validation off.
fn without_checksums(mut config: SessionConfig) -> SessionConfig {
    config.validate_checksum = false;
    config
}

/// Records every callback with the session it ran for, and forwards each
/// application message as `(session, MsgType)`. On demand it refuses every
/// Logon in `from_admin`, or parks there.
#[derive(Debug)]
struct RecordingApp {
    events: Mutex<Vec<String>>,
    app_tx: mpsc::UnboundedSender<(String, String)>,
    refuse_logons: AtomicBool,
    hang_logons: AtomicBool,
}

impl RecordingApp {
    fn new() -> (Arc<Self>, mpsc::UnboundedReceiver<(String, String)>) {
        let (app_tx, app_rx) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                events: Mutex::new(Vec::new()),
                app_tx,
                refuse_logons: AtomicBool::new(false),
                hang_logons: AtomicBool::new(false),
            }),
            app_rx,
        )
    }

    #[track_caller]
    fn record(&self, event: &str, session_id: &SessionId) {
        match self.events.lock() {
            Ok(mut events) => events.push(format!("{event} {session_id}")),
            Err(_) => panic!("event lock poisoned"),
        }
    }

    #[track_caller]
    fn events(&self) -> Vec<String> {
        match self.events.lock() {
            Ok(events) => events.clone(),
            Err(_) => panic!("event lock poisoned"),
        }
    }

    #[track_caller]
    fn count(&self, event: &str) -> usize {
        self.events()
            .iter()
            .filter(|recorded| recorded.starts_with(&format!("{event} ")))
            .count()
    }
}

#[async_trait]
impl Application for RecordingApp {
    async fn on_create(&self, session_id: &SessionId) {
        self.record("create", session_id);
    }

    async fn on_logon(&self, session_id: &SessionId) {
        self.record("logon", session_id);
    }

    async fn on_logout(&self, session_id: &SessionId) {
        self.record("logout", session_id);
    }

    async fn to_admin(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_admin(
        &self,
        message: &RawMessage<'_>,
        session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        if message.msg_type() == &MsgType::Logon {
            self.record("from_admin", session_id);
            if self.hang_logons.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            if self.refuse_logons.load(Ordering::SeqCst) {
                return Err(RejectReason::new(0, "credentials refused"));
            }
        }
        Ok(())
    }

    async fn to_app(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_app(
        &self,
        message: &RawMessage<'_>,
        session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        let _ = self.app_tx.send((
            session_id.to_string(),
            message.msg_type().as_str().to_string(),
        ));
        Ok(())
    }
}

/// A store that counts every call the engine makes on it, so a test can
/// assert the engine never touched it. Reads through `inner` are not counted.
#[derive(Debug)]
struct ProbeStore {
    inner: MemoryStore,
    calls: AtomicU64,
}

impl ProbeStore {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: MemoryStore::new(),
            calls: AtomicU64::new(0),
        })
    }

    fn touched(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }

    fn count(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl MessageStore for ProbeStore {
    async fn store(
        &self,
        seq_num: u64,
        msg_type: &MsgType,
        message: &[u8],
    ) -> Result<(), StoreError> {
        self.count();
        self.inner.store(seq_num, msg_type, message).await
    }

    async fn get_range(&self, begin: u64, end: u64) -> Result<Vec<StoredMessage>, StoreError> {
        self.count();
        self.inner.get_range(begin, end).await
    }

    fn next_sender_seq(&self) -> u64 {
        self.count();
        self.inner.next_sender_seq()
    }

    fn next_target_seq(&self) -> u64 {
        self.count();
        self.inner.next_target_seq()
    }

    async fn set_next_sender_seq(&self, seq: u64) -> Result<(), StoreError> {
        self.count();
        self.inner.set_next_sender_seq(seq).await
    }

    async fn set_next_target_seq(&self, seq: u64) -> Result<(), StoreError> {
        self.count();
        self.inner.set_next_target_seq(seq).await
    }

    async fn reset(&self) -> Result<(), StoreError> {
        self.count();
        self.inner.reset().await
    }

    fn creation_time(&self) -> std::time::SystemTime {
        self.count();
        self.inner.creation_time()
    }

    async fn refresh(&self) -> Result<(), StoreError> {
        self.count();
        Ok(())
    }
}

/// A lookup that admits any member asking for VENUE (unless told to refuse
/// or to fail), recording every identity it is asked about. With a barrier it
/// waits until that many lookups are in flight, so a race is forced rather
/// than hoped for. With `stores` it gives each admitted session a fresh store
/// of its own and keeps it, so a test can check it was never touched.
struct Directory {
    application: Arc<RecordingApp>,
    asked: Mutex<Vec<String>>,
    admit: bool,
    fail: bool,
    barrier: Option<Barrier>,
    hang: bool,
    stores: Option<Mutex<Vec<Arc<ProbeStore>>>>,
}

impl Directory {
    fn admitting(application: &Arc<RecordingApp>) -> Self {
        Self {
            application: Arc::clone(application),
            asked: Mutex::new(Vec::new()),
            admit: true,
            fail: false,
            barrier: None,
            hang: false,
            stores: None,
        }
    }

    #[track_caller]
    fn asked(&self) -> Vec<String> {
        match self.asked.lock() {
            Ok(asked) => asked.clone(),
            Err(_) => panic!("lookup lock poisoned"),
        }
    }

    #[track_caller]
    fn stores(&self) -> Vec<Arc<ProbeStore>> {
        match &self.stores {
            Some(stores) => match stores.lock() {
                Ok(stores) => stores.clone(),
                Err(_) => panic!("store lock poisoned"),
            },
            None => Vec::new(),
        }
    }
}

#[async_trait]
impl SessionLookup<RecordingApp> for Directory {
    async fn lookup(
        &self,
        identity: &LogonIdentity,
    ) -> Result<Option<Acceptor<RecordingApp>>, LookupError> {
        match self.asked.lock() {
            Ok(mut asked) => asked.push(identity.to_string()),
            Err(_) => panic!("lookup lock poisoned"),
        }
        if self.hang {
            std::future::pending::<()>().await;
        }
        if let Some(barrier) = &self.barrier {
            barrier.wait().await;
        }
        if self.fail {
            return Err(LookupError::new("directory unavailable"));
        }
        if !self.admit || identity.target_comp_id().as_str() != "VENUE" {
            return Ok(None);
        }
        let config = SessionConfig::new(
            identity.target_comp_id().clone(),
            identity.sender_comp_id().clone(),
            "FIX.4.4",
        )
        .with_heartbeat_interval(Duration::from_secs(30));
        let acceptor = Acceptor::new(config, Arc::clone(&self.application));
        let acceptor = match &self.stores {
            Some(stores) => {
                let store = ProbeStore::new();
                match stores.lock() {
                    Ok(mut stores) => stores.push(Arc::clone(&store)),
                    Err(_) => panic!("store lock poisoned"),
                }
                acceptor.with_store(store as Arc<dyn MessageStore>)
            }
            None => acceptor,
        };
        Ok(Some(acceptor))
    }
}

/// A scripted counterparty's frame in `begin_string` from `sender` to
/// `target`, numbered `seq`.
#[track_caller]
fn peer_msg_in(
    begin_string: &str,
    sender: &str,
    target: &str,
    msg_type: &str,
    seq: u64,
    extra: &[(u32, &str)],
) -> BytesMut {
    let mut encoder = Encoder::new(begin_string);
    encoder.put_str(35, msg_type);
    encoder.put_str(49, sender);
    encoder.put_str(56, target);
    encoder.put_uint(34, seq);
    encoder.put_str(52, Timestamp::now().format_millis().as_str());
    for (tag, value) in extra {
        encoder.put_str(*tag, value);
    }
    let mut frame = BytesMut::new();
    ok(encoder.finish_into(&mut frame), "test frame must encode");
    frame
}

/// A scripted counterparty's FIX.4.4 frame from `sender` to `target`.
#[track_caller]
fn peer_msg(
    sender: &str,
    target: &str,
    msg_type: &str,
    seq: u64,
    extra: &[(u32, &str)],
) -> BytesMut {
    peer_msg_in("FIX.4.4", sender, target, msg_type, seq, extra)
}

/// A Logon numbered 1 from `sender` to `target`.
fn logon(sender: &str, target: &str) -> BytesMut {
    peer_msg(sender, target, "A", 1, &[(98, "0"), (108, "30")])
}

/// Builds a frame around `body` with a correct BodyLength and CheckSum,
/// bypassing the encoder, so a value can carry any byte.
fn raw_frame(body: &[u8]) -> BytesMut {
    let mut frame = Vec::with_capacity(body.len() + 32);
    frame.extend_from_slice(b"8=FIX.4.4\x01");
    frame.extend_from_slice(format!("9={}\x01", body.len()).as_bytes());
    frame.extend_from_slice(body);
    let sum: u64 = frame.iter().map(|&b| u64::from(b)).sum();
    frame.extend_from_slice(format!("10={:03}\x01", sum % 256).as_bytes());
    BytesMut::from(&frame[..])
}

/// Returns `frame` with its CheckSum (10) value off by one: it still frames,
/// but fails checksum validation.
#[track_caller]
fn with_wrong_checksum(frame: &[u8]) -> BytesMut {
    let digits_at = some(frame.len().checked_sub(4), "frame must carry a trailer");
    let (head, trailer) = frame.split_at(digits_at);
    let digits = some(trailer.get(..3), "trailer must carry three digits");
    let text = ok(std::str::from_utf8(digits), "checksum digits are ASCII");
    let declared: u16 = ok(text.parse(), "checksum digits are decimal");
    let mut garbled = BytesMut::from(head);
    garbled.extend_from_slice(format!("{:03}\x01", (declared + 1) % 256).as_bytes());
    garbled
}

/// Extracts a field from a framed message.
fn field(frame: &[u8], tag: u32) -> Option<String> {
    let mut decoder = Decoder::new(frame);
    match decoder.decode() {
        Ok(raw) => raw.get_field_str(tag).map(str::to_string),
        Err(_) => None,
    }
}

/// Connects a scripted counterparty to `addr`.
async fn connect_peer(addr: std::net::SocketAddr) -> Framed<TcpStream, FixCodec> {
    let stream = ok(TcpStream::connect(addr).await, "peer connects");
    Framed::new(stream, FixCodec::new())
}

/// Connects a scripted counterparty whose own codec does not validate
/// checksums, so it can receive whatever a session sends back.
async fn connect_lenient_peer(addr: std::net::SocketAddr) -> Framed<TcpStream, FixCodec> {
    let stream = ok(TcpStream::connect(addr).await, "peer connects");
    Framed::new(stream, FixCodec::new().with_checksum_validation(false))
}

/// Reads the next frame the registry's session sends, within 5 s.
async fn next_frame(framed: &mut Framed<TcpStream, FixCodec>) -> BytesMut {
    let polled = ok(
        timeout(Duration::from_secs(5), framed.next()).await,
        "frame must arrive within 5s",
    );
    ok(some(polled, "stream must stay open"), "frame must decode")
}

/// Asserts the registry closes the connection without sending anything.
async fn assert_closed_without_reply(framed: &mut Framed<TcpStream, FixCodec>) {
    match timeout(Duration::from_secs(5), framed.next()).await {
        Ok(None) | Ok(Some(Err(_))) => {}
        Ok(Some(Ok(frame))) => panic!("expected no reply, got MsgType {:?}", field(&frame, 35)),
        Err(_) => panic!("the connection must be closed within 5s"),
    }
}

/// Awaits a spawned task within 5 s.
async fn joined<T>(task: tokio::task::JoinHandle<T>, what: &str) -> T {
    ok(ok(timeout(Duration::from_secs(5), task).await, what), what)
}

/// Serves `connections` inbound connections on `registry`, one task each,
/// and reports each result as `serve` returns it.
fn serve_connections(
    registry: &Arc<AcceptorRegistry<RecordingApp>>,
    listener: TcpListener,
    connections: usize,
) -> mpsc::UnboundedReceiver<Result<Connection, EngineError>> {
    let (tx, rx) = mpsc::unbounded_channel();
    let registry = Arc::clone(registry);
    tokio::spawn(async move {
        for _ in 0..connections {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let registry = Arc::clone(&registry);
            let tx = tx.clone();
            tokio::spawn(async move {
                let _ = tx.send(registry.serve(stream).await);
            });
        }
    });
    rx
}

/// Awaits the next result `serve` reports.
async fn next_result(
    rx: &mut mpsc::UnboundedReceiver<Result<Connection, EngineError>>,
) -> Result<Connection, EngineError> {
    some(
        ok(
            timeout(Duration::from_secs(5), rx.recv()).await,
            "a connection is decided within 5s",
        ),
        "the server must stay up",
    )
}

/// Awaits the next served connection, which must have succeeded.
async fn next_served(
    rx: &mut mpsc::UnboundedReceiver<Result<Connection, EngineError>>,
) -> Connection {
    ok(next_result(rx).await, "the routed session is established")
}

/// Sends `count` NewOrderSingles on `connection`.
async fn send_orders(connection: &Connection, count: usize) {
    for index in 0..count {
        let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
        order
            .push_str(11, &format!("ORDER-{index}"))
            .push_str(55, "EUR/USD")
            .push_char(54, '1')
            .push_uint(38, 100);
        ok(connection.send(order).await, "the member sends an order");
    }
}

/// Sends `count` ExecutionReports on `connection`.
async fn send_reports(connection: &Connection, count: usize) {
    for index in 0..count {
        let mut exec = OutboundMessage::new(MsgType::ExecutionReport);
        exec.push_str(37, &format!("EX-{index}"))
            .push_str(17, &format!("E-{index}"))
            .push_char(150, '0')
            .push_char(39, '0');
        ok(connection.send(exec).await, "the venue sends a report");
    }
}

/// Receives `count` application messages and returns them.
async fn receive(
    rx: &mut mpsc::UnboundedReceiver<(String, String)>,
    count: usize,
) -> Vec<(String, String)> {
    let mut received = Vec::with_capacity(count);
    for _ in 0..count {
        let message = some(
            ok(
                timeout(Duration::from_secs(5), rx.recv()).await,
                "an application message arrives within 5s",
            ),
            "the application channel must stay open",
        );
        received.push(message);
    }
    received
}

/// Asserts that a scripted peer's session is alive: a TestRequest numbered
/// `seq` is answered with a Heartbeat echoing it.
async fn assert_alive(framed: &mut Framed<TcpStream, FixCodec>, member: &str, seq: u64) {
    ok(
        framed
            .send(peer_msg(member, "VENUE", "1", seq, &[(112, "STILL-THERE")]))
            .await,
        "the peer sends a TestRequest",
    );
    let heartbeat = next_frame(framed).await;
    assert_eq!(field(&heartbeat, 35).as_deref(), Some("0"));
    assert_eq!(field(&heartbeat, 112).as_deref(), Some("STILL-THERE"));
}

/// A registry whose lookup is `directory`.
fn looked_up(directory: &Arc<Directory>) -> AcceptorRegistry<RecordingApp> {
    AcceptorRegistry::new()
        .with_lookup(Arc::clone(directory) as Arc<dyn SessionLookup<RecordingApp>>)
}

/// Two sessions on one listener: two real initiators with different CompIDs
/// each reach Active on their own session, and each session numbers its
/// messages and fills its store independently of the other.
#[tokio::test]
async fn test_registry_routes_two_sessions_with_independent_sequences() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let store_a = ProbeStore::new();
    let store_b = ProbeStore::new();
    let registry = Arc::new(AcceptorRegistry::new());
    ok(
        registry.register(
            Acceptor::new(venue_for("MEMBER_A"), Arc::clone(&venue_app))
                .with_store(Arc::clone(&store_a) as Arc<dyn MessageStore>),
        ),
        "MEMBER_A registers",
    );
    ok(
        registry.register(
            Acceptor::new(venue_for("MEMBER_B"), Arc::clone(&venue_app))
                .with_store(Arc::clone(&store_b) as Arc<dyn MessageStore>),
        ),
        "MEMBER_B registers",
    );
    let mut served = serve_connections(&registry, listener, 2);

    let (member_app_a, mut member_rx_a) = RecordingApp::new();
    let (member_app_b, mut member_rx_b) = RecordingApp::new();
    let member_a = ok(
        Initiator::new(member_config("MEMBER_A"), member_app_a)
            .connect(addr)
            .await,
        "MEMBER_A logs on",
    );
    let venue_a = next_served(&mut served).await;
    let member_b = ok(
        Initiator::new(member_config("MEMBER_B"), member_app_b)
            .connect(addr)
            .await,
        "MEMBER_B logs on",
    );
    let venue_b = next_served(&mut served).await;

    // Each connection is the right session.
    assert_eq!(venue_a.session_id().to_string(), "FIX.4.4:VENUE->MEMBER_A");
    assert_eq!(venue_b.session_id().to_string(), "FIX.4.4:VENUE->MEMBER_B");

    // Three orders on A, one on B, each delivered for its own session.
    send_orders(&member_a, 3).await;
    send_orders(&member_b, 1).await;
    let mut received = receive(&mut venue_rx, 4).await;
    received.sort();
    assert_eq!(
        received,
        [
            ("FIX.4.4:VENUE->MEMBER_A".to_string(), "D".to_string()),
            ("FIX.4.4:VENUE->MEMBER_A".to_string(), "D".to_string()),
            ("FIX.4.4:VENUE->MEMBER_A".to_string(), "D".to_string()),
            ("FIX.4.4:VENUE->MEMBER_B".to_string(), "D".to_string()),
        ]
    );

    // Two reports on A, none on B.
    send_reports(&venue_a, 2).await;
    let reports = receive(&mut member_rx_a, 2).await;
    assert!(reports.iter().all(|(_, msg_type)| msg_type == "8"));

    // Independent numbering: A's Logon and three orders against B's Logon and
    // one order, A's ack and two reports against B's ack alone.
    assert_eq!(venue_a.next_target_seq(), 5);
    assert_eq!(venue_b.next_target_seq(), 3);
    assert_eq!(venue_a.next_sender_seq(), 4);
    assert_eq!(venue_b.next_sender_seq(), 2);
    assert_eq!(member_b.next_sender_seq(), 3);

    // Independent stores, each holding its own session's counters and frames.
    assert_eq!(store_a.inner.next_target_seq(), 5);
    assert_eq!(store_b.inner.next_target_seq(), 3);
    assert_eq!(store_a.inner.next_sender_seq(), 4);
    assert_eq!(store_b.inner.next_sender_seq(), 2);
    let filed_a = ok(store_a.inner.get_range(1, 10).await, "store A reads");
    let filed_b = ok(store_b.inner.get_range(1, 10).await, "store B reads");
    assert_eq!(filed_a.len(), 3);
    assert_eq!(filed_b.len(), 1);

    // Both sessions logged on, each under its own identifier.
    let events = venue_app.events();
    for session in ["FIX.4.4:VENUE->MEMBER_A", "FIX.4.4:VENUE->MEMBER_B"] {
        assert!(events.contains(&format!("create {session}")), "{events:?}");
        assert!(events.contains(&format!("logon {session}")), "{events:?}");
    }

    for (member, venue) in [(&member_a, &venue_a), (&member_b, &venue_b)] {
        ok(member.logout().await, "the member logs out");
        ok(
            timeout(Duration::from_secs(5), member.wait_closed()).await,
            "the member session closes within 5s",
        );
        ok(
            timeout(Duration::from_secs(5), venue.wait_closed()).await,
            "the venue session closes within 5s",
        );
    }
    // Nothing reached the other member.
    assert!(member_rx_b.try_recv().is_err());
}

/// A Logon whose CompID pair no session is registered for is closed with no
/// reply: no callback runs and no store is touched.
#[tokio::test]
async fn test_registry_unregistered_comp_ids_are_closed_without_reply() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let store = ProbeStore::new();
    let registry: AcceptorRegistry<RecordingApp> = AcceptorRegistry::new();
    ok(
        registry.register(
            Acceptor::new(venue_for("MEMBER_A"), Arc::clone(&venue_app))
                .with_store(Arc::clone(&store) as Arc<dyn MessageStore>),
        ),
        "MEMBER_A registers",
    );
    let venue = tokio::spawn(async move { registry.accept(&listener).await });

    let mut peer = connect_peer(addr).await;
    ok(
        peer.send(logon("STRANGER", "VENUE")).await,
        "the stranger logs on",
    );
    assert_closed_without_reply(&mut peer).await;

    match joined(venue, "venue task").await {
        Err(EngineError::UnknownSession { identity }) => {
            assert_eq!(identity.sender_comp_id().as_str(), "STRANGER");
            assert_eq!(identity.to_string(), "49=STRANGER 56=VENUE");
        }
        other => panic!("expected UnknownSession, got {other:?}"),
    }
    assert!(venue_app.events().is_empty(), "{:?}", venue_app.events());
    assert_eq!(store.touched(), 0, "the store must not be touched");
}

/// A known sender asking for the wrong target is as unknown as a stranger.
#[tokio::test]
async fn test_registry_known_sender_with_another_target_is_unknown() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let registry: AcceptorRegistry<RecordingApp> = AcceptorRegistry::new();
    ok(
        registry.register(Acceptor::new(venue_for("MEMBER_A"), Arc::clone(&venue_app))),
        "MEMBER_A registers",
    );
    let venue = tokio::spawn(async move { registry.accept(&listener).await });

    let mut peer = connect_peer(addr).await;
    ok(
        peer.send(logon("MEMBER_A", "OTHER_VENUE")).await,
        "the member logs on",
    );
    assert_closed_without_reply(&mut peer).await;

    assert!(matches!(
        joined(venue, "venue task").await,
        Err(EngineError::UnknownSession { .. })
    ));
    assert!(venue_app.events().is_empty());
}

/// A second Logon for a session that is already live is refused without a
/// reply, and the live session carries on.
#[tokio::test]
async fn test_registry_second_logon_for_a_live_session_is_refused() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let registry = Arc::new(AcceptorRegistry::new());
    ok(
        registry.register(Acceptor::new(venue_for("MEMBER_A"), Arc::clone(&venue_app))),
        "MEMBER_A registers",
    );
    let mut served = serve_connections(&registry, listener, 2);

    let mut first = connect_peer(addr).await;
    ok(
        first.send(logon("MEMBER_A", "VENUE")).await,
        "the first peer logs on",
    );
    let ack = next_frame(&mut first).await;
    assert_eq!(field(&ack, 35).as_deref(), Some("A"));
    let live = next_served(&mut served).await;

    let mut second = connect_peer(addr).await;
    ok(
        second.send(logon("MEMBER_A", "VENUE")).await,
        "the second peer logs on",
    );
    assert_closed_without_reply(&mut second).await;
    match next_result(&mut served).await {
        Err(EngineError::LogonRejected { reason }) => {
            assert!(reason.contains("already active"), "got {reason}");
        }
        other => panic!("expected a duplicate refusal, got {other:?}"),
    }

    // The first session is untouched: a TestRequest is still answered.
    assert_alive(&mut first, "MEMBER_A", 2).await;
    assert!(!live.is_closed());
    assert_eq!(venue_app.count("logon"), 1);
}

/// While a session is live, a second Logon for it gets no reply even when its
/// BeginString or EncryptMethod is wrong (no store attached, where a refused
/// Logon would otherwise be answered): anything it could be sent would be
/// numbered from the live session's stream.
#[tokio::test]
async fn test_registry_live_session_answers_no_wrong_version_or_encryption_logon() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let registry = Arc::new(AcceptorRegistry::new());
    ok(
        registry.register(Acceptor::new(venue_for("MEMBER_A"), Arc::clone(&venue_app))),
        "MEMBER_A registers",
    );
    let mut served = serve_connections(&registry, listener, 3);

    let mut first = connect_peer(addr).await;
    ok(
        first.send(logon("MEMBER_A", "VENUE")).await,
        "the first peer logs on",
    );
    let _ack = next_frame(&mut first).await;
    let live = next_served(&mut served).await;

    // The wrong version, routed to the live session.
    let mut wrong_version = connect_peer(addr).await;
    ok(
        wrong_version
            .send(peer_msg_in(
                "FIX.4.2",
                "MEMBER_A",
                "VENUE",
                "A",
                1,
                &[(98, "0"), (108, "30")],
            ))
            .await,
        "a FIX.4.2 Logon is sent",
    );
    assert_closed_without_reply(&mut wrong_version).await;
    match next_result(&mut served).await {
        Err(EngineError::LogonRejected { reason }) => {
            assert!(reason.contains("BeginString"), "got {reason}");
        }
        other => panic!("expected a version refusal, got {other:?}"),
    }

    // An encryption method the engine does not implement.
    let mut wrong_encryption = connect_peer(addr).await;
    ok(
        wrong_encryption
            .send(peer_msg(
                "MEMBER_A",
                "VENUE",
                "A",
                1,
                &[(98, "1"), (108, "30")],
            ))
            .await,
        "an encrypted Logon is sent",
    );
    assert_closed_without_reply(&mut wrong_encryption).await;
    match next_result(&mut served).await {
        Err(EngineError::LogonRejected { reason }) => {
            assert!(reason.contains("EncryptMethod"), "got {reason}");
        }
        other => panic!("expected an encryption refusal, got {other:?}"),
    }

    assert_alive(&mut first, "MEMBER_A", 2).await;
    assert!(!live.is_closed());
}

/// The lookup admits a session that was not registered at startup; once a
/// Logon for it is authenticated it stays, so a later Logon is routed without
/// asking the lookup again.
#[tokio::test]
async fn test_registry_lookup_admits_an_unknown_session() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let directory = Arc::new(Directory::admitting(&venue_app));
    let registry = Arc::new(looked_up(&directory));
    let mut served = serve_connections(&registry, listener, 2);

    for round in 0..2 {
        let (member_app, _member_rx) = RecordingApp::new();
        let member = ok(
            Initiator::new(member_config("NEWCOMER"), member_app)
                .connect(addr)
                .await,
            "the newcomer logs on",
        );
        let venue = next_served(&mut served).await;
        assert_eq!(venue.session_id().to_string(), "FIX.4.4:VENUE->NEWCOMER");
        ok(member.logout().await, "the newcomer logs out");
        ok(
            timeout(Duration::from_secs(5), venue.wait_closed()).await,
            "the venue session closes within 5s",
        );
        // The admission slot is freed once the session's task has ended.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            directory.asked(),
            ["49=NEWCOMER 56=VENUE"],
            "round {round}: the lookup is asked once"
        );
    }
    let ids: Vec<String> = registry
        .session_ids()
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(ids, ["FIX.4.4:VENUE->NEWCOMER"]);
}

/// The lookup can refuse: the Logon is closed with no reply and no callback.
#[tokio::test]
async fn test_registry_lookup_can_refuse_a_session() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let directory = Arc::new(Directory {
        admit: false,
        ..Directory::admitting(&venue_app)
    });
    let registry = looked_up(&directory);
    let venue = tokio::spawn(async move { registry.accept(&listener).await });

    let mut peer = connect_peer(addr).await;
    ok(
        peer.send(peer_msg(
            "BARRED",
            "VENUE",
            "A",
            1,
            &[(98, "0"), (108, "30"), (553, "user"), (554, "secret")],
        ))
        .await,
        "the barred member logs on",
    );
    assert_closed_without_reply(&mut peer).await;

    assert!(matches!(
        joined(venue, "venue task").await,
        Err(EngineError::UnknownSession { .. })
    ));
    // The lookup saw the identity, never the credentials.
    assert_eq!(directory.asked(), ["49=BARRED 56=VENUE"]);
    assert!(venue_app.events().is_empty());
}

/// A lookup that cannot decide is reported as such, not as a refusal, and the
/// Logon is closed without a reply.
#[tokio::test]
async fn test_registry_lookup_failure_is_reported_apart_from_a_refusal() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let directory = Arc::new(Directory {
        fail: true,
        ..Directory::admitting(&venue_app)
    });
    let registry = looked_up(&directory);
    let venue = tokio::spawn(async move { registry.accept(&listener).await });

    let mut peer = connect_peer(addr).await;
    ok(
        peer.send(logon("NEWCOMER", "VENUE")).await,
        "the peer logs on",
    );
    assert_closed_without_reply(&mut peer).await;

    match joined(venue, "venue task").await {
        Err(EngineError::Lookup(err)) => assert_eq!(err.reason(), "directory unavailable"),
        other => panic!("expected a lookup failure, got {other:?}"),
    }
    assert!(venue_app.events().is_empty());
}

/// Two concurrent Logons for the same unknown identity, each looked up while
/// the other is: the registry keeps one acceptor for the session, so exactly
/// one is admitted and the other is refused as a duplicate.
#[tokio::test]
async fn test_registry_racing_lookups_admit_one_session() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let directory = Arc::new(Directory {
        barrier: Some(Barrier::new(2)),
        ..Directory::admitting(&venue_app)
    });
    let registry = Arc::new(looked_up(&directory));
    let mut served = serve_connections(&registry, listener, 2);

    let mut peer_a = connect_peer(addr).await;
    let mut peer_b = connect_peer(addr).await;
    ok(
        peer_a.send(logon("NEWCOMER", "VENUE")).await,
        "peer A logs on",
    );
    ok(
        peer_b.send(logon("NEWCOMER", "VENUE")).await,
        "peer B logs on",
    );

    let mut results = Vec::new();
    for _ in 0..2 {
        results.push(next_result(&mut served).await);
    }
    let admitted = results.iter().filter(|result| result.is_ok()).count();
    let duplicates = results
        .iter()
        .filter(|result| {
            matches!(result, Err(EngineError::LogonRejected { reason }) if reason.contains("already active"))
        })
        .count();
    assert_eq!(admitted, 1, "{results:?}");
    assert_eq!(duplicates, 1, "{results:?}");
    assert_eq!(directory.asked().len(), 2, "both Logons were looked up");
    assert_eq!(registry.session_ids().len(), 1);

    // The admitted peer got its ack; the refused one got nothing.
    let first_a = timeout(Duration::from_secs(5), peer_a.next()).await;
    let first_b = timeout(Duration::from_secs(5), peer_b.next()).await;
    let acked = [&first_a, &first_b]
        .iter()
        .filter(|polled| matches!(polled, Ok(Some(Ok(frame))) if field(frame, 35).as_deref() == Some("A")))
        .count();
    let closed = [&first_a, &first_b]
        .iter()
        .filter(|polled| matches!(polled, Ok(None) | Ok(Some(Err(_)))))
        .count();
    assert_eq!((acked, closed), (1, 1));
}

/// A peer cycling fresh identities the lookup admits, whose credentials
/// `from_admin` refuses each time, leaves the registry as it found it: every
/// provisional session is evicted, and the store each one was given was
/// never touched.
#[tokio::test]
async fn test_registry_failed_authentication_evicts_lookup_sessions() {
    const ATTEMPTS: usize = 5;
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    venue_app.refuse_logons.store(true, Ordering::SeqCst);
    let directory = Arc::new(Directory {
        stores: Some(Mutex::new(Vec::new())),
        ..Directory::admitting(&venue_app)
    });
    let registry = Arc::new(looked_up(&directory));
    let mut served = serve_connections(&registry, listener, ATTEMPTS);

    for attempt in 0..ATTEMPTS {
        let mut peer = connect_peer(addr).await;
        let identity = format!("FRESH_{attempt}");
        ok(
            peer.send(logon(&identity, "VENUE")).await,
            "the peer logs on",
        );
        match next_result(&mut served).await {
            Err(EngineError::LogonRejected { reason }) => {
                assert!(reason.contains("credentials refused"), "got {reason}");
            }
            other => panic!("expected a credentials refusal, got {other:?}"),
        }
        // With a store attached the refusal gets no reply.
        assert_closed_without_reply(&mut peer).await;
        assert!(
            registry.session_ids().is_empty(),
            "attempt {attempt}: {:?}",
            registry.session_ids()
        );
    }

    assert_eq!(directory.asked().len(), ATTEMPTS);
    assert_eq!(venue_app.count("from_admin"), ATTEMPTS);
    let stores = directory.stores();
    assert_eq!(stores.len(), ATTEMPTS);
    assert!(stores.iter().all(|store| store.touched() == 0));
    // Evicted sessions dropped their acceptors, and with them their store
    // references: only the directory's record and this test's copy remain.
    assert!(stores.iter().all(|store| Arc::strong_count(store) == 2));
}

/// Concurrent failed handshakes for one lookup-admitted session, ending on
/// different worker threads, never leave it behind: each round's four Logons
/// are looked up together (a barrier holds every lookup until all four are in
/// flight), so all four connections claim one provisional session, then all
/// fail before authentication and release their claims concurrently. With a
/// cap of one lookup-admitted session, a session leaked by any round would
/// make every later round's admission fail with `SessionLimit`.
///
/// This checks that claims stay balanced end to end; it cannot force the
/// one interleaving a reference count got wrong (a release landing between
/// another release and that guard's drop). That interleaving is pinned
/// deterministically by the registry's unit test
/// `test_release_evicts_when_the_last_claim_goes_whatever_references_remain`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_registry_concurrent_failed_handshakes_never_leak_a_session() {
    const ROUNDS: usize = 25;
    const CONCURRENT: usize = 4;
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    venue_app.refuse_logons.store(true, Ordering::SeqCst);
    let directory = Arc::new(Directory {
        barrier: Some(Barrier::new(CONCURRENT)),
        ..Directory::admitting(&venue_app)
    });
    let registry = Arc::new(looked_up(&directory).with_max_sessions(1));
    let mut served = serve_connections(&registry, listener, ROUNDS * CONCURRENT);

    for round in 0..ROUNDS {
        let identity = format!("RACE_{round}");
        let mut peers = Vec::with_capacity(CONCURRENT);
        for _ in 0..CONCURRENT {
            let mut peer = connect_peer(addr).await;
            ok(peer.send(logon(&identity, "VENUE")).await, "a peer logs on");
            peers.push(peer);
        }
        for _ in 0..CONCURRENT {
            // `serve` returns only once the connection's claim is released.
            match next_result(&mut served).await {
                Err(EngineError::LogonRejected { .. }) => {}
                other => panic!("round {round}: expected a refused Logon, got {other:?}"),
            }
        }
        assert!(
            registry.session_ids().is_empty(),
            "round {round} left {:?}",
            registry.session_ids()
        );
    }
    assert_eq!(directory.asked().len(), ROUNDS * CONCURRENT);
}

/// A Logon refused after `from_admin` accepted it (here for its HeartBtInt)
/// confirms the lookup-admitted session: the peer was authenticated, so the
/// session stays and the lookup is not asked about it again.
#[tokio::test]
async fn test_registry_authenticated_refusal_keeps_the_lookup_session() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let directory = Arc::new(Directory::admitting(&venue_app));
    let registry = Arc::new(looked_up(&directory));
    let mut served = serve_connections(&registry, listener, 2);

    let mut peer = connect_peer(addr).await;
    ok(
        peer.send(peer_msg("NEWCOMER", "VENUE", "A", 1, &[(98, "0")]))
            .await,
        "a Logon without HeartBtInt is sent",
    );
    match next_result(&mut served).await {
        Err(EngineError::LogonRejected { reason }) => {
            assert!(reason.contains("HeartBtInt"), "got {reason}");
        }
        other => panic!("expected a HeartBtInt refusal, got {other:?}"),
    }
    assert_eq!(registry.session_ids().len(), 1);

    // The next Logon is routed to the kept session without a lookup.
    let mut retry = connect_peer(addr).await;
    ok(
        retry.send(logon("NEWCOMER", "VENUE")).await,
        "the peer logs on again",
    );
    let _connection = next_served(&mut served).await;
    assert_eq!(directory.asked().len(), 1);
}

/// A `serve` dropped while a lookup-admitted session's handshake is waiting
/// on `from_admin` settles the session as unauthenticated: it is evicted.
#[tokio::test]
async fn test_registry_dropped_serve_evicts_a_provisional_session() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    venue_app.hang_logons.store(true, Ordering::SeqCst);
    let directory = Arc::new(Directory::admitting(&venue_app));
    let registry = looked_up(&directory);

    let mut peer = connect_peer(addr).await;
    ok(
        peer.send(logon("NEWCOMER", "VENUE")).await,
        "the peer logs on",
    );
    let (stream, _) = ok(listener.accept().await, "the connection is taken");
    let served = timeout(Duration::from_millis(500), registry.serve(stream)).await;

    assert!(served.is_err(), "serve must still be in from_admin");
    assert_eq!(venue_app.count("from_admin"), 1);
    assert!(registry.session_ids().is_empty());
}

/// The cap bounds the lookup-admitted sessions held at once: beyond it a
/// lookup admission is refused without a reply.
#[tokio::test]
async fn test_registry_max_sessions_refuses_beyond_the_cap() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let directory = Arc::new(Directory::admitting(&venue_app));
    let registry = Arc::new(looked_up(&directory).with_max_sessions(2));
    let mut served = serve_connections(&registry, listener, 3);

    let mut live = Vec::new();
    for member in ["NEW_A", "NEW_B"] {
        let mut peer = connect_peer(addr).await;
        ok(peer.send(logon(member, "VENUE")).await, "a member logs on");
        let _ack = next_frame(&mut peer).await;
        live.push((peer, next_served(&mut served).await));
    }

    let mut third = connect_peer(addr).await;
    ok(
        third.send(logon("NEW_C", "VENUE")).await,
        "a third member logs on",
    );
    assert_closed_without_reply(&mut third).await;
    match next_result(&mut served).await {
        Err(EngineError::SessionLimit { max }) => assert_eq!(max, 2),
        other => panic!("expected the session cap, got {other:?}"),
    }
    assert_eq!(registry.session_ids().len(), 2);
    assert_eq!(venue_app.count("create"), 2);
}

/// An over-long, illegal or repeated CompID is refused before any session or
/// the lookup is consulted, with no reply.
#[tokio::test]
async fn test_registry_refuses_an_unroutable_comp_id_before_the_lookup() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let directory = Arc::new(Directory::admitting(&venue_app));
    let registry = Arc::new(looked_up(&directory));
    let mut served = serve_connections(&registry, listener, 3);

    // A SenderCompID one byte above the bound.
    let long = "M".repeat(33);
    let mut peer = connect_peer(addr).await;
    ok(peer.send(logon(&long, "VENUE")).await, "the peer logs on");
    assert_closed_without_reply(&mut peer).await;
    match next_result(&mut served).await {
        Err(EngineError::UnroutableLogon { tag, detail }) => {
            assert_eq!(tag, 49);
            assert!(!detail.contains(&long), "the value must not be quoted");
        }
        other => panic!("expected UnroutableLogon for 49, got {other:?}"),
    }

    // A TargetCompID carrying a byte outside printable ASCII.
    let mut peer = connect_peer(addr).await;
    ok(
        peer.send(raw_frame(
            b"35=A\x0149=NEWCOMER\x0156=VEN\xffUE\x0134=1\x0152=20261018-10:00:00.000\x0198=0\x01108=30\x01",
        ))
        .await,
        "the peer logs on",
    );
    assert_closed_without_reply(&mut peer).await;
    match next_result(&mut served).await {
        Err(EngineError::UnroutableLogon { tag, detail }) => {
            assert_eq!(tag, 56);
            assert!(detail.contains("0xff"), "got {detail}");
        }
        other => panic!("expected UnroutableLogon for 56, got {other:?}"),
    }

    // A SenderCompID repeated in the header (SessionRejectReason 13).
    let mut peer = connect_peer(addr).await;
    ok(
        peer.send(raw_frame(
            b"35=A\x0149=NEWCOMER\x0156=VENUE\x0149=OTHER\x0134=1\x0152=20261018-10:00:00.000\x0198=0\x01108=30\x01",
        ))
        .await,
        "the peer logs on",
    );
    assert_closed_without_reply(&mut peer).await;
    match next_result(&mut served).await {
        Err(EngineError::UnroutableLogon { tag, detail }) => {
            assert_eq!(tag, 49);
            assert!(detail.contains("more than once"), "got {detail}");
        }
        other => panic!("expected UnroutableLogon for a repeated 49, got {other:?}"),
    }

    assert!(directory.asked().is_empty(), "the lookup must not be asked");
    assert!(venue_app.events().is_empty());
}

/// Waiting for the Logon is bounded by the registry's logon timeout.
#[tokio::test]
async fn test_registry_logon_timeout_bounds_the_read() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let registry: AcceptorRegistry<RecordingApp> =
        AcceptorRegistry::new().with_logon_timeout(Duration::from_millis(300));
    ok(
        registry.register(Acceptor::new(venue_for("MEMBER_A"), Arc::clone(&venue_app))),
        "MEMBER_A registers",
    );
    let venue = tokio::spawn(async move { registry.accept(&listener).await });

    // Connect, never log on.
    let _peer = connect_peer(addr).await;
    match joined(venue, "venue task").await {
        Err(EngineError::LogonTimeout(waited)) => {
            assert_eq!(waited, Duration::from_millis(300));
        }
        other => panic!("expected LogonTimeout, got {other:?}"),
    }
    assert!(venue_app.events().is_empty());
}

/// A lookup that never answers is bounded by the same logon timeout.
#[tokio::test]
async fn test_registry_logon_timeout_bounds_the_lookup() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let directory = Arc::new(Directory {
        hang: true,
        ..Directory::admitting(&venue_app)
    });
    let registry = looked_up(&directory).with_logon_timeout(Duration::from_millis(300));
    let venue = tokio::spawn(async move { registry.accept(&listener).await });

    let mut peer = connect_peer(addr).await;
    ok(
        peer.send(logon("NEWCOMER", "VENUE")).await,
        "the peer logs on",
    );
    assert_closed_without_reply(&mut peer).await;

    assert!(matches!(
        joined(venue, "venue task").await,
        Err(EngineError::LogonTimeout(_))
    ));
    assert_eq!(directory.asked().len(), 1);
    assert!(venue_app.events().is_empty());
}

/// A first frame that is not a Logon cannot be routed and gets no reply.
#[tokio::test]
async fn test_registry_first_frame_not_logon_is_refused() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let registry: AcceptorRegistry<RecordingApp> = AcceptorRegistry::new();
    ok(
        registry.register(Acceptor::new(venue_for("MEMBER_A"), Arc::clone(&venue_app))),
        "MEMBER_A registers",
    );
    let venue = tokio::spawn(async move { registry.accept(&listener).await });

    let mut peer = connect_peer(addr).await;
    ok(
        peer.send(peer_msg("MEMBER_A", "VENUE", "0", 1, &[])).await,
        "the peer sends a Heartbeat first",
    );
    assert_closed_without_reply(&mut peer).await;

    match joined(venue, "venue task").await {
        Err(EngineError::UnexpectedMessage { msg_type }) => assert_eq!(msg_type, "0"),
        other => panic!("expected UnexpectedMessage, got {other:?}"),
    }
    assert!(venue_app.events().is_empty());
}

/// Once routed, the Logon is held to the session's own message-size ceiling,
/// which is below the registry's: it is refused as the session's codec would
/// have refused it, without a reply.
#[tokio::test]
async fn test_registry_logon_is_held_to_the_session_ceiling() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let registry: AcceptorRegistry<RecordingApp> = AcceptorRegistry::new();
    ok(
        registry.register(Acceptor::new(
            venue_for("MEMBER_A").with_max_message_size(512),
            Arc::clone(&venue_app),
        )),
        "MEMBER_A registers",
    );
    let venue = tokio::spawn(async move { registry.accept(&listener).await });

    let padding = "P".repeat(600);
    let mut peer = connect_peer(addr).await;
    ok(
        peer.send(peer_msg(
            "MEMBER_A",
            "VENUE",
            "A",
            1,
            &[(98, "0"), (108, "30"), (58, padding.as_str())],
        ))
        .await,
        "the peer sends an oversized Logon",
    );
    assert_closed_without_reply(&mut peer).await;

    match joined(venue, "venue task").await {
        Err(EngineError::Codec(err)) => {
            assert!(err.to_string().contains("exceeds maximum 512"), "got {err}");
        }
        other => panic!("expected a codec refusal, got {other:?}"),
    }
    let events = venue_app.events();
    assert_eq!(events, ["create FIX.4.4:VENUE->MEMBER_A"]);
}

/// The Logon's checksum is validated while it is routed, even for a session
/// configured not to validate checksums: the frame comes from an unknown
/// peer. A Logon with a bad checksum is skipped as garbled, so the read ends
/// in the logon timeout.
#[tokio::test]
async fn test_registry_validates_the_logon_checksum_whatever_the_session() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let registry: AcceptorRegistry<RecordingApp> =
        AcceptorRegistry::new().with_logon_timeout(Duration::from_millis(300));
    ok(
        registry.register(Acceptor::new(
            without_checksums(venue_for("MEMBER_A")),
            Arc::clone(&venue_app),
        )),
        "MEMBER_A registers",
    );
    let venue = tokio::spawn(async move { registry.accept(&listener).await });

    let mut peer = connect_peer(addr).await;
    ok(
        peer.send(with_wrong_checksum(&logon("MEMBER_A", "VENUE")))
            .await,
        "the peer sends a Logon with a bad checksum",
    );
    assert_closed_without_reply(&mut peer).await;

    assert!(matches!(
        joined(venue, "venue task").await,
        Err(EngineError::LogonTimeout(_))
    ));
    assert!(venue_app.events().is_empty());
}

/// A garbled frame before the Logon is skipped on the registry path, as on
/// `Acceptor::serve`, and the Logon behind it is routed.
#[tokio::test]
async fn test_registry_skips_a_garbled_frame_before_the_logon() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let registry: AcceptorRegistry<RecordingApp> = AcceptorRegistry::new();
    ok(
        registry.register(Acceptor::new(venue_for("MEMBER_A"), Arc::clone(&venue_app))),
        "MEMBER_A registers",
    );
    let venue = tokio::spawn(async move { registry.accept(&listener).await });

    let mut peer = connect_peer(addr).await;
    let mut bytes = with_wrong_checksum(&logon("MEMBER_A", "VENUE"));
    bytes.extend_from_slice(&logon("MEMBER_A", "VENUE"));
    ok(
        peer.get_mut().write_all_buf(&mut bytes).await,
        "garbage and a Logon are sent",
    );
    let ack = next_frame(&mut peer).await;
    assert_eq!(field(&ack, 35).as_deref(), Some("A"));

    let connection = ok(
        joined(venue, "venue task").await,
        "the session is established",
    );
    assert_eq!(connection.next_target_seq(), 2);
}

/// A frame pipelined right behind the Logon, in the same write, is decoded
/// by the session's codec once the Logon is routed. The session does not
/// validate checksums, the registry does: the TestRequest, sent with a bad
/// checksum, is answered only because the session's codec framed it.
#[tokio::test]
async fn test_registry_frame_after_the_logon_is_framed_by_the_session_codec() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let registry: AcceptorRegistry<RecordingApp> = AcceptorRegistry::new();
    ok(
        registry.register(Acceptor::new(
            without_checksums(venue_for("MEMBER_A")),
            Arc::clone(&venue_app),
        )),
        "MEMBER_A registers",
    );
    let venue = tokio::spawn(async move { registry.accept(&listener).await });

    let mut peer = connect_lenient_peer(addr).await;
    let mut bytes = logon("MEMBER_A", "VENUE");
    bytes.extend_from_slice(&with_wrong_checksum(&peer_msg(
        "MEMBER_A",
        "VENUE",
        "1",
        2,
        &[(112, "PIPELINED")],
    )));
    ok(
        peer.get_mut().write_all_buf(&mut bytes).await,
        "a Logon and a TestRequest are sent in one write",
    );
    let ack = next_frame(&mut peer).await;
    assert_eq!(field(&ack, 35).as_deref(), Some("A"));
    let heartbeat = next_frame(&mut peer).await;
    assert_eq!(field(&heartbeat, 35).as_deref(), Some("0"));
    assert_eq!(field(&heartbeat, 112).as_deref(), Some("PIPELINED"));

    let _connection = ok(
        joined(venue, "venue task").await,
        "the session is established",
    );
}

/// A Logon routed to a session but carrying another BeginString is refused by
/// the session's own version check (no store, so with a Logout).
#[tokio::test]
async fn test_registry_routed_session_refuses_a_mismatched_begin_string() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let registry: AcceptorRegistry<RecordingApp> = AcceptorRegistry::new();
    ok(
        registry.register(Acceptor::new(venue_for("MEMBER_A"), Arc::clone(&venue_app))),
        "MEMBER_A registers",
    );
    let venue = tokio::spawn(async move { registry.accept(&listener).await });

    let mut peer = connect_peer(addr).await;
    ok(
        peer.send(peer_msg_in(
            "FIX.4.2",
            "MEMBER_A",
            "VENUE",
            "A",
            1,
            &[(98, "0"), (108, "30")],
        ))
        .await,
        "a FIX.4.2 Logon is sent",
    );

    match joined(venue, "venue task").await {
        Err(EngineError::LogonRejected { reason }) => {
            assert!(reason.contains("BeginString"), "got {reason}");
        }
        other => panic!("expected a version refusal, got {other:?}"),
    }
    assert_eq!(venue_app.count("create"), 1);
    assert_eq!(venue_app.count("logon"), 0);
}

/// A FIX 5.0 SP2 session (`FIXT.1.1` on the wire) routes end to end.
#[tokio::test]
async fn test_registry_routes_a_fixt_session_end_to_end() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, mut venue_rx) = RecordingApp::new();
    let registry = Arc::new(AcceptorRegistry::new());
    ok(
        registry.register(Acceptor::new(
            SessionConfig::new(comp_id("VENUE"), comp_id("MEMBER_A"), "FIX.5.0SP2")
                .with_heartbeat_interval(Duration::from_secs(30)),
            Arc::clone(&venue_app),
        )),
        "the FIXT session registers",
    );
    ok(
        registry.register(Acceptor::new(venue_for("MEMBER_B"), Arc::clone(&venue_app))),
        "a FIX.4.4 session registers beside it",
    );
    let mut served = serve_connections(&registry, listener, 1);

    let (member_app, _member_rx) = RecordingApp::new();
    let member = ok(
        Initiator::new(
            SessionConfig::new(comp_id("MEMBER_A"), comp_id("VENUE"), "FIX.5.0SP2")
                .with_heartbeat_interval(Duration::from_secs(30)),
            member_app,
        )
        .connect(addr)
        .await,
        "the FIXT member logs on",
    );
    let venue = next_served(&mut served).await;
    assert_eq!(venue.session_id().to_string(), "FIX.5.0SP2:VENUE->MEMBER_A");

    send_orders(&member, 1).await;
    let received = receive(&mut venue_rx, 1).await;
    assert_eq!(
        received,
        [("FIX.5.0SP2:VENUE->MEMBER_A".to_string(), "D".to_string())]
    );
}

/// Two sessions with the same CompIDs and different sub IDs on one listener:
/// each real initiator is routed by the `SenderSubID` (50) it stamps.
#[tokio::test]
async fn test_registry_routes_by_sub_id_over_a_socket() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let registry = Arc::new(AcceptorRegistry::new());
    for desk in ["DESK1", "DESK2"] {
        ok(
            registry.register(Acceptor::new(
                venue_for("MEMBER").with_target_sub_id(desk),
                Arc::clone(&venue_app),
            )),
            "a desk session registers",
        );
    }
    let mut served = serve_connections(&registry, listener, 2);

    for desk in ["DESK2", "DESK1"] {
        let (member_app, _member_rx) = RecordingApp::new();
        let member = ok(
            Initiator::new(member_config("MEMBER").with_sender_sub_id(desk), member_app)
                .connect(addr)
                .await,
            "the desk logs on",
        );
        let venue = next_served(&mut served).await;
        assert_eq!(venue.session_id().target_sub_id.as_deref(), Some(desk));
        assert_eq!(member.next_sender_seq(), 2);
    }
}

/// Location IDs route a Logon and are enforced by the routed session: a real
/// initiator stamping the configured locations reaches Active (each side
/// checks the other's 142/143), and a Logon from another location is unknown.
#[tokio::test]
async fn test_registry_routes_by_location_id_and_the_session_enforces_it() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let mut venue = venue_for("MEMBER");
    venue.sender_location_id = Some("NYC".to_string());
    venue.target_location_id = Some("LON".to_string());
    let registry = Arc::new(AcceptorRegistry::new());
    ok(
        registry.register(Acceptor::new(venue, Arc::clone(&venue_app))),
        "the located session registers",
    );
    let mut served = serve_connections(&registry, listener, 2);

    let mut member = member_config("MEMBER");
    member.sender_location_id = Some("LON".to_string());
    member.target_location_id = Some("NYC".to_string());
    let (member_app, _member_rx) = RecordingApp::new();
    let connection = ok(
        Initiator::new(member, member_app).connect(addr).await,
        "the located member logs on",
    );
    let _venue = next_served(&mut served).await;
    send_orders(&connection, 1).await;

    let mut elsewhere = connect_peer(addr).await;
    ok(
        elsewhere
            .send(peer_msg(
                "MEMBER",
                "VENUE",
                "A",
                1,
                &[(142, "PAR"), (98, "0"), (108, "30")],
            ))
            .await,
        "a Logon from another location is sent",
    );
    assert_closed_without_reply(&mut elsewhere).await;
    assert!(matches!(
        next_result(&mut served).await,
        Err(EngineError::UnknownSession { .. })
    ));
}

/// A lookup returning a session that overlaps a registered one is refused:
/// the registry would otherwise hold two sessions one Logon could match.
#[tokio::test]
async fn test_registry_lookup_overlapping_a_registered_session_is_refused() {
    let (listener, addr) = bind_listener().await;
    let (venue_app, _venue_rx) = RecordingApp::new();
    let directory = Arc::new(Directory::admitting(&venue_app));
    let registry = looked_up(&directory);
    ok(
        registry.register(Acceptor::new(
            venue_for("MEMBER").with_target_sub_id("DESK1"),
            Arc::clone(&venue_app),
        )),
        "the DESK1 session registers",
    );
    let registry = Arc::new(registry);
    let mut served = serve_connections(&registry, listener, 1);

    // DESK2 matches nothing registered; the lookup answers with a catch-all
    // session for MEMBER, which overlaps DESK1.
    let mut peer = connect_peer(addr).await;
    ok(
        peer.send(peer_msg(
            "MEMBER",
            "VENUE",
            "A",
            1,
            &[(50, "DESK2"), (98, "0"), (108, "30")],
        ))
        .await,
        "the DESK2 Logon is sent",
    );
    assert_closed_without_reply(&mut peer).await;
    match next_result(&mut served).await {
        Err(EngineError::Configuration(detail)) => {
            assert!(detail.contains("overlaps"), "got {detail}");
        }
        other => panic!("expected an overlap refusal, got {other:?}"),
    }
    assert_eq!(directory.asked().len(), 1);
    assert_eq!(registry.session_ids().len(), 1);
    assert!(venue_app.events().is_empty());
}

/// Unusable registry settings are reported before a connection is taken.
#[tokio::test]
async fn test_registry_accept_refuses_unusable_settings_before_accepting() {
    let (listener, _addr) = bind_listener().await;
    let registry: AcceptorRegistry<RecordingApp> =
        AcceptorRegistry::new().with_logon_timeout(Duration::ZERO);

    match timeout(Duration::from_secs(5), registry.accept(&listener)).await {
        Ok(Err(EngineError::Configuration(detail))) => {
            assert!(detail.contains("logon timeout"), "got {detail}");
        }
        other => panic!("expected a configuration refusal, got {other:?}"),
    }
}
