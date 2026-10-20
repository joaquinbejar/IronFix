/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! End-to-end tests of FIXP over SOFH in the engine (issue #96).
//!
//! Engine against engine, over a real `TcpListener` and over an in-memory
//! duplex: Negotiate, Establish, application messages both ways, Terminate.
//! Engine against a scripted peer (the `ironfix-fixp` core driven by hand
//! over `Framed<_, SofhCodec>`), in both roles: a retransmission requested
//! by the engine and one served by it, a finalized identifier refused, a
//! malformed session message, and the credentials kept out of every log
//! line.

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use ironfix_engine::fixp::ironfix_fixp::{
    ClockAnchor, Credentials, Delivery, Event, FinishedSending, FixpClient, FixpConfig, FixpServer,
    FlowType, Nanotime, NegotiationRejectCode, Output, RetransmitRequest, SeqNum, Sequence,
    SessionId, SessionMessage, SessionStatus, Terminate, TerminationCode, Timestamp,
    is_session_message,
};
use ironfix_engine::fixp::ironfix_sofh::{EncodingType, SofhCodec, SofhFrame};
use ironfix_engine::fixp::{
    EstablishRequest, EstablishmentDecision, FixpAcceptor, FixpApplication, FixpConnection,
    FixpEngineError, FixpInbound, FixpInitiator, NegotiateRequest, NegotiationDecision,
};
use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

const SECRET: &[u8] = b"s3cr3t-fixp-credential";
const WAIT: Duration = Duration::from_secs(5);

#[track_caller]
fn ok<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{what}: {error:?}"),
    }
}

fn session_id(seed: u8) -> SessionId {
    SessionId::from_bytes([seed; 16])
}

fn credentials() -> Credentials {
    ok(Credentials::try_new(SECRET.to_vec()), "credentials")
}

fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

fn clock() -> ClockAnchor {
    ClockAnchor::new(now(), Timestamp::now())
}

/// An application message payload: opaque bytes for the session.
fn payload(n: u8) -> Bytes {
    Bytes::from(vec![b'A', b'P', b'P', n])
}

// ---------------------------------------------------------------------------
// The engine-side application
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Recorder {
    messages: Mutex<Vec<FixpInbound>>,
    events: Mutex<Vec<Event>>,
    connection: Mutex<Option<FixpConnection>>,
    negotiations: Mutex<Vec<NegotiateRequest>>,
    establishments: Mutex<Vec<EstablishRequest>>,
    closed: Mutex<u32>,
}

impl Recorder {
    fn messages(&self) -> Vec<(Option<u64>, bool, Bytes)> {
        let messages = self.messages.lock().unwrap_or_else(|p| p.into_inner());
        messages
            .iter()
            .map(|m| (m.seq.map(SeqNum::value), m.retransmitted, m.payload.clone()))
            .collect()
    }

    fn events(&self) -> Vec<Event> {
        self.events
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn connection(&self) -> Option<FixpConnection> {
        self.connection
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn closed(&self) -> u32 {
        *self.closed.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[derive(Clone)]
struct App(Arc<Recorder>);

#[async_trait]
impl FixpApplication for App {
    async fn on_negotiate(&self, request: &NegotiateRequest) -> NegotiationDecision {
        let accepted = request
            .credentials
            .as_ref()
            .is_some_and(|c| c.expose() == SECRET);
        self.0
            .negotiations
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(request.clone());
        if accepted {
            NegotiationDecision::Accept {
                server_flow: FlowType::Recoverable,
                credentials: None,
            }
        } else {
            NegotiationDecision::Reject {
                code: NegotiationRejectCode::Credentials,
                reason: "bad credentials".to_owned(),
            }
        }
    }

    async fn on_establish(&self, request: &EstablishRequest) -> EstablishmentDecision {
        self.0
            .establishments
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(request.clone());
        EstablishmentDecision::Accept
    }

    async fn on_established(&self, connection: FixpConnection) {
        *self.0.connection.lock().unwrap_or_else(|p| p.into_inner()) = Some(connection);
    }

    async fn on_message(&self, _session_id: SessionId, message: FixpInbound) {
        self.0
            .messages
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(message);
    }

    async fn on_event(&self, _session_id: Option<SessionId>, event: &Event) {
        self.0
            .events
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(event.clone());
    }

    async fn on_closed(&self, _session_id: Option<SessionId>) {
        *self.0.closed.lock().unwrap_or_else(|p| p.into_inner()) += 1;
    }
}

/// Polls `condition` until it holds, or fails the test after [`WAIT`].
async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !condition() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn wait_closed(connection: &FixpConnection) {
    ok(
        tokio::time::timeout(WAIT, connection.wait_closed()).await,
        "connection closed in time",
    );
}

fn has_event(recorder: &Recorder, matches: impl Fn(&Event) -> bool) -> bool {
    recorder.events().iter().any(matches)
}

// ---------------------------------------------------------------------------
// Engine against engine
// ---------------------------------------------------------------------------

/// Application messages both ways, then a graceful Terminate by the client.
async fn exchange_and_terminate(
    client: &FixpConnection,
    client_app: &Recorder,
    server_app: &Recorder,
) {
    wait_until("the server's connection", || {
        server_app.connection().is_some()
    })
    .await;
    let Some(server) = server_app.connection() else {
        panic!("no server connection");
    };
    assert_eq!(server.session_id(), client.session_id());

    for n in 1..=3 {
        let seq = ok(client.send(payload(n)).await, "client send");
        assert_eq!(seq.map(SeqNum::value), Some(u64::from(n)));
    }
    for n in 1..=2 {
        let seq = ok(server.send(payload(10 + n)).await, "server send");
        assert_eq!(seq.map(SeqNum::value), Some(u64::from(n)));
    }
    wait_until("three messages at the server", || {
        server_app.messages().len() == 3
    })
    .await;
    wait_until("two messages at the client", || {
        client_app.messages().len() == 2
    })
    .await;
    assert_eq!(
        server_app.messages(),
        (1..=3)
            .map(|n| (Some(u64::from(n)), false, payload(n)))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        client_app.messages(),
        (1..=2)
            .map(|n| (Some(u64::from(n)), false, payload(10 + n)))
            .collect::<Vec<_>>()
    );

    ok(client.terminate("done").await, "client terminate");
    wait_closed(client).await;
    wait_closed(&server).await;
    assert!(client.is_closed() && server.is_closed());
    // The client sent Terminate Finished; the server answered with one.
    assert!(has_event(server_app, |e| matches!(
        e,
        Event::Terminated {
            code: TerminationCode::Finished,
            ..
        }
    )));
    assert!(has_event(client_app, |e| matches!(
        e,
        Event::Terminated {
            code: TerminationCode::Finished,
            ..
        }
    )));
    wait_until("both on_closed", || {
        client_app.closed() == 1 && server_app.closed() == 1
    })
    .await;
    // After the close the handle refuses commands.
    assert!(matches!(
        client.send(payload(9)).await,
        Err(FixpEngineError::Closed)
    ));
}

fn negotiated_with_secret(server_app: &Recorder) {
    let negotiations = server_app
        .negotiations
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    assert_eq!(negotiations.len(), 1);
    assert_eq!(negotiations[0].client_flow, FlowType::Recoverable);
    assert_eq!(
        negotiations[0]
            .credentials
            .as_ref()
            .map(Credentials::expose),
        Some(SECRET)
    );
    drop(negotiations);
    let establishments = server_app
        .establishments
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    assert_eq!(establishments.len(), 1);
    assert_eq!(
        establishments[0].next_seq_no.map(SeqNum::value),
        Some(1),
        "a sequenced client flow announces NextSeqNo (section 4.3.1)"
    );
}

#[tokio::test]
async fn test_engine_client_and_server_over_tcp() {
    let server_app = Arc::new(Recorder::default());
    let client_app = Arc::new(Recorder::default());
    let listener = ok(TcpListener::bind("127.0.0.1:0").await, "bind");
    let addr = ok(listener.local_addr(), "address");
    let acceptor = FixpAcceptor::new(App(Arc::clone(&server_app)), FixpConfig::default());
    let serving = tokio::spawn({
        let acceptor = acceptor.clone();
        async move { acceptor.serve(listener).await }
    });

    let client = ok(
        FixpInitiator::new(
            App(Arc::clone(&client_app)),
            FixpConfig::default(),
            session_id(0x11),
            FlowType::Recoverable,
        )
        .with_credentials(credentials())
        .connect(addr)
        .await,
        "connect",
    );
    assert_eq!(client.session_id(), session_id(0x11));
    assert!(has_event(&client_app, |e| matches!(
        e,
        Event::Established { .. }
    )));
    negotiated_with_secret(&server_app);

    exchange_and_terminate(&client, &client_app, &server_app).await;
    assert!(!acceptor.is_finalized(session_id(0x11)));
    serving.abort();
}

#[tokio::test]
async fn test_engine_client_and_server_over_duplex() {
    let server_app = Arc::new(Recorder::default());
    let client_app = Arc::new(Recorder::default());
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let acceptor = FixpAcceptor::new(App(Arc::clone(&server_app)), FixpConfig::default());
    let initiator = FixpInitiator::new(
        App(Arc::clone(&client_app)),
        FixpConfig::default(),
        session_id(0x22),
        FlowType::Recoverable,
    )
    .with_credentials(credentials());
    let (server, client) = tokio::join!(
        acceptor.accept_stream(server_io),
        initiator.connect_stream(client_io)
    );
    let server = ok(server, "accept");
    let client = ok(client, "connect");
    assert_eq!(server.session_id(), session_id(0x22));
    negotiated_with_secret(&server_app);
    exchange_and_terminate(&client, &client_app, &server_app).await;
}

#[tokio::test]
async fn test_negotiation_rejected_by_the_application_is_a_typed_error() {
    let server_app = Arc::new(Recorder::default());
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let acceptor = FixpAcceptor::new(App(Arc::clone(&server_app)), FixpConfig::default());
    let initiator = FixpInitiator::new(
        App(Arc::new(Recorder::default())),
        FixpConfig::default(),
        session_id(0x33),
        FlowType::Recoverable,
    )
    .with_credentials(ok(Credentials::try_new(b"wrong".to_vec()), "credentials"));
    let (server, client) = tokio::join!(
        acceptor.accept_stream(server_io),
        initiator.connect_stream(client_io)
    );
    assert!(server.is_err());
    match client {
        Err(FixpEngineError::NegotiationRejected { code, .. }) => {
            assert_eq!(code, NegotiationRejectCode::Credentials);
        }
        other => panic!("expected NegotiationRejected, got {other:?}"),
    }
    wait_until("server driver ended", || server_app.closed() == 1).await;
}

// ---------------------------------------------------------------------------
// A scripted peer: the session core driven by hand
// ---------------------------------------------------------------------------

trait Core {
    fn poll(&mut self) -> Option<Output>;
    fn message(&mut self, message: &SessionMessage, now: Instant);
    fn application(&mut self, now: Instant) -> Delivery;
    fn send(&mut self, now: Instant) -> Option<SeqNum>;
    fn retransmit(&mut self, count: u32, now: Instant);
}

macro_rules! core_impl {
    ($role:ty) => {
        impl Core for $role {
            fn poll(&mut self) -> Option<Output> {
                self.poll_output()
            }
            fn message(&mut self, message: &SessionMessage, now: Instant) {
                self.handle_message(message, now);
            }
            fn application(&mut self, now: Instant) -> Delivery {
                self.on_application_message(now)
            }
            fn send(&mut self, now: Instant) -> Option<SeqNum> {
                ok(self.send_application(now), "peer send_application")
            }
            fn retransmit(&mut self, count: u32, now: Instant) {
                let Some(count) = NonZeroU32::new(count) else {
                    panic!("zero retransmit count");
                };
                let _ = ok(self.retransmit(count, now), "peer retransmit");
            }
        }
    };
}
core_impl!(FixpClient);
core_impl!(FixpServer);

#[derive(Debug, Clone)]
enum Received {
    Session(SessionMessage),
    Application(Bytes),
}

struct Peer<C, S> {
    core: C,
    framed: Framed<S, SofhCodec>,
    stored: BTreeMap<u64, Bytes>,
    events: Vec<Event>,
    applications: Vec<(Option<u64>, bool, Bytes)>,
    closed: bool,
}

impl<C: Core, S: AsyncRead + AsyncWrite + Unpin> Peer<C, S> {
    fn new(core: C, stream: S) -> Self {
        Self {
            core,
            framed: Framed::new(stream, SofhCodec::new()),
            stored: BTreeMap::new(),
            events: Vec::new(),
            applications: Vec::new(),
            closed: false,
        }
    }

    async fn write_session(&mut self, message: &SessionMessage) {
        let mut bytes = Vec::new();
        ok(message.encode(&mut bytes), "encode");
        let frame = ok(
            SofhFrame::new(EncodingType::SbeV1LittleEndian, bytes),
            "frame",
        );
        ok(self.framed.send(frame).await, "peer write");
    }

    async fn write_application(&mut self, bytes: Bytes) {
        let frame = ok(
            SofhFrame::new(EncodingType::SbeV1LittleEndian, bytes),
            "frame",
        );
        ok(self.framed.send(frame).await, "peer write");
    }

    /// Carries out the core's outputs, serving a retransmission from
    /// `stored`.
    async fn flush(&mut self) {
        let mut replay = Vec::new();
        loop {
            while let Some(output) = self.core.poll() {
                match output {
                    Output::Send(message) | Output::SendApplication { message, .. } => {
                        self.write_session(&message).await;
                    }
                    Output::CloseTransport => self.closed = true,
                    Output::Event(event) => {
                        if let Event::RetransmitRequested { from, count } = &event {
                            self.core.retransmit(*count, now());
                            for seq in from.value()..from.value() + u64::from(*count) {
                                let Some(bytes) = self.stored.get(&seq) else {
                                    panic!("peer has no message {seq}");
                                };
                                replay.push(bytes.clone());
                            }
                        }
                        self.events.push(event);
                    }
                    other => panic!("unexpected output {other:?}"),
                }
            }
            if replay.is_empty() {
                break;
            }
            for bytes in std::mem::take(&mut replay) {
                self.write_application(bytes).await;
            }
        }
    }

    /// Reads one frame and decodes it, without feeding the core.
    async fn read(&mut self) -> Option<Received> {
        let frame = ok(
            tokio::time::timeout(WAIT, self.framed.next()).await,
            "peer read",
        )?;
        let frame = ok(frame, "peer framing");
        let payload = frame.into_payload();
        if is_session_message(&payload) {
            let (message, _) = ok(SessionMessage::decode(&payload), "peer decode");
            Some(Received::Session(message))
        } else {
            Some(Received::Application(payload))
        }
    }

    /// Reads one frame, feeds it to the core and flushes.
    async fn step(&mut self) -> Option<Received> {
        let received = self.read().await?;
        match &received {
            Received::Session(message) => self.core.message(message, now()),
            Received::Application(bytes) => {
                if let Delivery::Accept { seq, retransmitted } = self.core.application(now()) {
                    self.applications
                        .push((seq.map(SeqNum::value), retransmitted, bytes.clone()));
                }
            }
        }
        self.flush().await;
        Some(received)
    }

    async fn step_until(&mut self, what: &str, done: impl Fn(&Self) -> bool) {
        while !done(self) {
            if self.step().await.is_none() {
                panic!("transport ended waiting for {what}");
            }
        }
    }

    fn saw(&self, matches: impl Fn(&Event) -> bool) -> bool {
        self.events.iter().any(matches)
    }

    /// Numbers and sends an application message, keeping it for a
    /// retransmission. With `drop` it is numbered and kept but not written.
    async fn send_app(&mut self, bytes: Bytes, drop: bool) -> Option<SeqNum> {
        let seq = self.core.send(now());
        self.flush().await;
        if let Some(seq) = seq {
            self.stored.insert(seq.value(), bytes.clone());
        }
        if !drop {
            self.write_application(bytes).await;
        }
        seq
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Peer<FixpServer, S> {
    async fn accept(stream: S) -> Self {
        let mut peer = Self::new(
            FixpServer::new(FixpConfig::default(), clock(), now()),
            stream,
        );
        peer.step_until("Negotiate", |p| {
            p.saw(|e| matches!(e, Event::NegotiateReceived { .. }))
        })
        .await;
        ok(
            peer.core
                .accept_negotiation(FlowType::Recoverable, None, now()),
            "accept negotiation",
        );
        peer.flush().await;
        peer.step_until("Establish", |p| {
            p.saw(|e| matches!(e, Event::EstablishReceived { .. }))
        })
        .await;
        ok(
            peer.core.accept_establishment(now()),
            "accept establishment",
        );
        peer.flush().await;
        assert_eq!(peer.core.status(), SessionStatus::Established);
        peer
    }

    fn session_id(&self) -> SessionId {
        let Some(id) = self.core.session_id() else {
            panic!("no session id");
        };
        id
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Peer<FixpClient, S> {
    async fn connect(stream: S, id: SessionId) -> Self {
        let client = FixpClient::new(
            FixpConfig::default(),
            clock(),
            id,
            FlowType::Recoverable,
            Some(credentials()),
        );
        let mut peer = Self::new(client, stream);
        ok(peer.core.negotiate(now()), "negotiate");
        peer.flush().await;
        peer.step_until("NegotiationResponse", |p| {
            p.saw(|e| matches!(e, Event::Negotiated { .. }))
        })
        .await;
        ok(peer.core.establish(now()), "establish");
        peer.flush().await;
        peer.step_until("EstablishmentAck", |p| {
            p.saw(|e| matches!(e, Event::Established { .. }))
        })
        .await;
        peer
    }
}

async fn tcp_pair() -> (TcpListener, std::net::SocketAddr) {
    let listener = ok(TcpListener::bind("127.0.0.1:0").await, "bind");
    let addr = ok(listener.local_addr(), "address");
    (listener, addr)
}

/// The peer numbers three messages but writes only 1 and 3, the second
/// behind a Sequence announcing 3: the engine sees a gap at 2 (FIXP v1.1
/// section 3.5), requests it (section 4.6.1) and receives it in a
/// Retransmission (section 4.6.2).
async fn engine_requests_a_retransmission<C: Core, S: AsyncRead + AsyncWrite + Unpin>(
    peer: &mut Peer<C, S>,
    engine: &FixpConnection,
    engine_app: &Recorder,
) {
    let first = peer.send_app(payload(1), false).await;
    assert_eq!(first.map(SeqNum::value), Some(1));
    let second = peer.send_app(payload(2), true).await;
    assert_eq!(second.map(SeqNum::value), Some(2));
    // Message 3 goes behind a Sequence that reveals the gap.
    let third = peer.core.send(now());
    assert_eq!(third.map(SeqNum::value), Some(3));
    peer.flush().await;
    peer.stored.insert(3, payload(3));
    peer.write_session(&SessionMessage::Sequence(Sequence { next_seq_no: 3 }))
        .await;
    peer.write_application(payload(3)).await;

    // The RetransmitRequest; the peer's core answers it from `stored`.
    peer.step_until("RetransmitRequest", |p| {
        p.saw(|e| matches!(e, Event::RetransmitRequested { .. }))
    })
    .await;
    wait_until("three messages at the engine", || {
        engine_app.messages().len() == 3
    })
    .await;
    assert_eq!(
        engine_app.messages(),
        vec![
            (Some(1), false, payload(1)),
            (Some(3), false, payload(3)),
            (Some(2), true, payload(2)),
        ]
    );
    assert!(has_event(engine_app, |e| matches!(
        e,
        Event::SequenceGap { count: 1, .. }
    )));
    wait_until("recovery complete", || {
        has_event(engine_app, |e| matches!(e, Event::RecoveryComplete))
    })
    .await;

    // The engine terminates; the peer's core answers.
    ok(engine.terminate("done").await, "engine terminate");
    peer.step_until("Terminate", |p| {
        p.saw(|e| matches!(e, Event::Terminated { .. }))
    })
    .await;
    wait_closed(engine).await;
}

/// The engine sends three messages; the peer asks for 2 again with a
/// RetransmitRequest written by hand (its own core never saw a gap). The
/// engine answers with a Retransmission header and the stored message
/// (FIXP v1.1 section 4.6.2), then answers the peer's Terminate.
async fn engine_serves_a_retransmission<C: Core, S: AsyncRead + AsyncWrite + Unpin>(
    peer: &mut Peer<C, S>,
    id: SessionId,
    engine: &FixpConnection,
) {
    for n in 1..=3 {
        let seq = ok(engine.send(payload(n)).await, "engine send");
        assert_eq!(seq.map(SeqNum::value), Some(u64::from(n)));
    }
    peer.step_until("three messages", |p| p.applications.len() == 3)
        .await;

    peer.write_session(&SessionMessage::RetransmitRequest(RetransmitRequest {
        session_id: id,
        timestamp: Nanotime::from_nanos(1_760_000_000_000_000_042),
        from_seq_no: 2,
        count: 1,
    }))
    .await;
    // Read raw: the core did not ask, so it must not see the answer.
    let mut answer = Vec::new();
    while answer.len() < 2 {
        match peer.read().await {
            Some(Received::Session(SessionMessage::Sequence(_))) => {}
            Some(other) => answer.push(other),
            None => panic!("transport ended before the retransmission"),
        }
    }
    match &answer[0] {
        Received::Session(SessionMessage::Retransmission(header)) => {
            assert_eq!(header.session_id, id);
            assert_eq!(header.next_seq_no, 2);
            assert_eq!(header.count, 1);
            assert_eq!(
                header.request_timestamp,
                Nanotime::from_nanos(1_760_000_000_000_000_042)
            );
        }
        other => panic!("expected a Retransmission header, got {other:?}"),
    }
    match &answer[1] {
        Received::Application(bytes) => assert_eq!(bytes, &payload(2)),
        other => panic!("expected the retransmitted message, got {other:?}"),
    }

    peer.write_session(&SessionMessage::Terminate(Terminate {
        session_id: id,
        code: TerminationCode::Finished,
        reason: String::new(),
    }))
    .await;
    loop {
        match peer.read().await {
            Some(Received::Session(SessionMessage::Terminate(t))) => {
                assert_eq!(t.code, TerminationCode::Finished);
                break;
            }
            Some(_) => {}
            None => panic!("transport ended before the Terminate answer"),
        }
    }
    let _ = SinkExt::<SofhFrame>::close(&mut peer.framed).await;
    wait_closed(engine).await;
}

#[tokio::test]
async fn test_engine_client_requests_a_retransmission_over_tcp() {
    let (listener, addr) = tcp_pair().await;
    let peer = tokio::spawn(async move {
        let (stream, _) = ok(listener.accept().await, "accept");
        Peer::accept(stream).await
    });
    let app = Arc::new(Recorder::default());
    let engine = ok(
        FixpInitiator::new(
            App(Arc::clone(&app)),
            FixpConfig::default(),
            session_id(0x44),
            FlowType::Recoverable,
        )
        .connect(addr)
        .await,
        "connect",
    );
    let mut peer = ok(peer.await, "peer task");
    engine_requests_a_retransmission(&mut peer, &engine, &app).await;
}

#[tokio::test]
async fn test_engine_client_requests_a_retransmission_over_duplex() {
    let (engine_io, peer_io) = tokio::io::duplex(64 * 1024);
    let app = Arc::new(Recorder::default());
    let initiator = FixpInitiator::new(
        App(Arc::clone(&app)),
        FixpConfig::default(),
        session_id(0x45),
        FlowType::Recoverable,
    );
    let (engine, mut peer) =
        tokio::join!(initiator.connect_stream(engine_io), Peer::accept(peer_io));
    let engine = ok(engine, "connect");
    engine_requests_a_retransmission(&mut peer, &engine, &app).await;
}

#[tokio::test]
async fn test_engine_server_requests_a_retransmission_over_tcp() {
    let (listener, addr) = tcp_pair().await;
    let app = Arc::new(Recorder::default());
    let acceptor = FixpAcceptor::new(App(Arc::clone(&app)), FixpConfig::default());
    let serving = tokio::spawn({
        let acceptor = acceptor.clone();
        async move { acceptor.serve(listener).await }
    });
    let stream = ok(TcpStream::connect(addr).await, "dial");
    let mut peer = Peer::connect(stream, session_id(0x46)).await;
    wait_until("the server's connection", || app.connection().is_some()).await;
    let Some(engine) = app.connection() else {
        panic!("no connection");
    };
    engine_requests_a_retransmission(&mut peer, &engine, &app).await;
    serving.abort();
}

#[tokio::test]
async fn test_engine_server_serves_a_retransmission_over_tcp() {
    let (listener, addr) = tcp_pair().await;
    let app = Arc::new(Recorder::default());
    let acceptor = FixpAcceptor::new(App(Arc::clone(&app)), FixpConfig::default());
    let serving = tokio::spawn({
        let acceptor = acceptor.clone();
        async move { acceptor.serve(listener).await }
    });
    let stream = ok(TcpStream::connect(addr).await, "dial");
    let mut peer = Peer::connect(stream, session_id(0x47)).await;
    wait_until("the server's connection", || app.connection().is_some()).await;
    let Some(engine) = app.connection() else {
        panic!("no connection");
    };
    engine_serves_a_retransmission(&mut peer, session_id(0x47), &engine).await;
    serving.abort();
}

#[tokio::test]
async fn test_engine_client_serves_a_retransmission_over_duplex() {
    let (engine_io, peer_io) = tokio::io::duplex(64 * 1024);
    let app = Arc::new(Recorder::default());
    let initiator = FixpInitiator::new(
        App(Arc::clone(&app)),
        FixpConfig::default(),
        session_id(0x48),
        FlowType::Recoverable,
    );
    let (engine, mut peer) =
        tokio::join!(initiator.connect_stream(engine_io), Peer::accept(peer_io));
    let engine = ok(engine, "connect");
    let id = peer.session_id();
    engine_serves_a_retransmission(&mut peer, id, &engine).await;
}

#[tokio::test]
async fn test_a_request_for_messages_no_longer_kept_is_rejected() {
    let (engine_io, peer_io) = tokio::io::duplex(64 * 1024);
    let initiator = FixpInitiator::new(
        App(Arc::new(Recorder::default())),
        FixpConfig::default(),
        session_id(0x49),
        FlowType::Recoverable,
    )
    .with_retransmit_capacity(1);
    let (engine, mut peer) =
        tokio::join!(initiator.connect_stream(engine_io), Peer::accept(peer_io));
    let engine = ok(engine, "connect");
    for n in 1..=2 {
        let _ = ok(engine.send(payload(n)).await, "engine send");
    }
    peer.step_until("two messages", |p| p.applications.len() == 2)
        .await;
    peer.write_session(&SessionMessage::RetransmitRequest(RetransmitRequest {
        session_id: session_id(0x49),
        timestamp: Nanotime::from_nanos(1_760_000_000_000_000_007),
        from_seq_no: 1,
        count: 1,
    }))
    .await;
    loop {
        match peer.read().await {
            Some(Received::Session(SessionMessage::RetransmitReject(reject))) => {
                assert_eq!(
                    reject.code,
                    ironfix_engine::fixp::ironfix_fixp::RetransmitRejectCode::OutOfRange
                );
                break;
            }
            Some(Received::Session(SessionMessage::Sequence(_))) => {}
            other => panic!("expected a RetransmitReject, got {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Finalization, untrusted input, credentials
// ---------------------------------------------------------------------------

/// FIXP v1.1 sections 4.7.2 and 6.3: once finalized, an identifier is never
/// negotiated again. The core forgets it with its transport; the acceptor
/// remembers it.
#[tokio::test]
async fn test_acceptor_refuses_a_finalized_session_id() {
    let (listener, addr) = tcp_pair().await;
    let app = Arc::new(Recorder::default());
    let acceptor = FixpAcceptor::new(App(Arc::clone(&app)), FixpConfig::default());
    let serving = tokio::spawn({
        let acceptor = acceptor.clone();
        async move { acceptor.serve(listener).await }
    });
    let id = session_id(0x55);
    let stream = ok(TcpStream::connect(addr).await, "dial");
    let mut peer = Peer::connect(stream, id).await;
    wait_until("the server's connection", || app.connection().is_some()).await;

    // The peer finishes sending (nothing sent: no LastSeqNo past 0 needed,
    // but a sequenced flow must populate it).
    peer.write_session(&SessionMessage::FinishedSending(FinishedSending {
        session_id: id,
        last_seq_no: Some(0),
    }))
    .await;
    loop {
        match peer.read().await {
            Some(Received::Session(SessionMessage::FinishedReceiving(_))) => break,
            Some(_) => {}
            None => panic!("transport ended before FinishedReceiving"),
        }
    }
    peer.write_session(&SessionMessage::Terminate(Terminate {
        session_id: id,
        code: TerminationCode::Finished,
        reason: String::new(),
    }))
    .await;
    loop {
        match peer.read().await {
            Some(Received::Session(SessionMessage::Terminate(_))) => break,
            Some(_) => {}
            None => panic!("transport ended before the Terminate answer"),
        }
    }
    let _ = SinkExt::<SofhFrame>::close(&mut peer.framed).await;
    wait_until("finalized", || acceptor.is_finalized(id)).await;
    assert!(has_event(&app, |e| matches!(
        e,
        Event::SessionFinalized { .. }
    )));

    // The same identifier again: NegotiationReject DuplicateId.
    let stream = ok(TcpStream::connect(addr).await, "dial again");
    let client = FixpClient::new(
        FixpConfig::default(),
        clock(),
        id,
        FlowType::Recoverable,
        Some(credentials()),
    );
    let mut peer = Peer::new(client, stream);
    ok(peer.core.negotiate(now()), "negotiate");
    peer.flush().await;
    peer.step_until("NegotiationReject", |p| {
        p.saw(|e| matches!(e, Event::NegotiationRejected { .. }))
    })
    .await;
    assert!(peer.saw(|e| matches!(
        e,
        Event::NegotiationRejected {
            code: NegotiationRejectCode::DuplicateId,
            ..
        }
    )));
    serving.abort();
}

/// A frame naming the FIXP schema that does not decode: Terminate
/// `UnspecifiedError` and a close (FIXP v1.1 section 6.3), never a panic.
#[tokio::test]
async fn test_a_malformed_session_message_terminates() {
    let (engine_io, peer_io) = tokio::io::duplex(64 * 1024);
    let app = Arc::new(Recorder::default());
    let initiator = FixpInitiator::new(
        App(Arc::clone(&app)),
        FixpConfig::default(),
        session_id(0x66),
        FlowType::Recoverable,
    );
    let (engine, mut peer) =
        tokio::join!(initiator.connect_stream(engine_io), Peer::accept(peer_io));
    let engine = ok(engine, "connect");
    // An SBE header naming schema 2748, template 99, then nothing.
    let mut garbage = vec![0u8; 8];
    garbage[2..4].copy_from_slice(&99u16.to_le_bytes());
    garbage[4..6].copy_from_slice(&2748u16.to_le_bytes());
    peer.write_application(Bytes::from(garbage)).await;
    loop {
        match peer.read().await {
            Some(Received::Session(SessionMessage::Terminate(t))) => {
                assert_eq!(t.code, TerminationCode::UnspecifiedError);
                break;
            }
            Some(_) => {}
            None => panic!("transport ended before the Terminate"),
        }
    }
    let _ = SinkExt::<SofhFrame>::close(&mut peer.framed).await;
    wait_closed(&engine).await;
}

/// A payload that names the FIXP schema is refused before a sequence number
/// is spent.
#[tokio::test]
async fn test_sending_a_session_schema_payload_is_refused() {
    let (engine_io, peer_io) = tokio::io::duplex(64 * 1024);
    let initiator = FixpInitiator::new(
        App(Arc::new(Recorder::default())),
        FixpConfig::default(),
        session_id(0x77),
        FlowType::Recoverable,
    )
    .with_max_message_size(64);
    let (engine, _peer) = tokio::join!(initiator.connect_stream(engine_io), Peer::accept(peer_io));
    let engine = ok(engine, "connect");
    let mut encoded = Vec::new();
    ok(
        SessionMessage::Sequence(Sequence { next_seq_no: 1 }).encode(&mut encoded),
        "encode",
    );
    assert!(matches!(
        engine.send(encoded).await,
        Err(FixpEngineError::ReservedSchema)
    ));
    assert!(matches!(
        engine.send(vec![0u8; 64]).await,
        Err(FixpEngineError::PayloadTooLarge { len: 64, max: 64 })
    ));
    // Nothing was spent: the next message is still number 1.
    let seq = ok(engine.send(payload(1)).await, "send");
    assert_eq!(seq.map(SeqNum::value), Some(1));
}

/// Every log line both engine roles emit through a handshake with
/// credentials and a termination is free of the credential bytes.
#[tokio::test]
async fn test_tracing_output_never_contains_credentials() {
    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let sink = Sink::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let server_app = Arc::new(Recorder::default());
    let client_app = Arc::new(Recorder::default());
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let acceptor = FixpAcceptor::new(App(Arc::clone(&server_app)), FixpConfig::default());
    let initiator = FixpInitiator::new(
        App(Arc::clone(&client_app)),
        FixpConfig::default(),
        session_id(0x88),
        FlowType::Recoverable,
    )
    .with_credentials(credentials());
    tracing::debug!(initiator = ?initiator, "initiator");
    let (server, client) = tokio::join!(
        acceptor.accept_stream(server_io),
        initiator.connect_stream(client_io)
    );
    let _server = ok(server, "accept");
    let client = ok(client, "connect");
    let negotiations = format!(
        "{:?}",
        server_app
            .negotiations
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    );
    tracing::debug!(%negotiations, "negotiations");
    ok(client.terminate("done").await, "terminate");
    wait_closed(&client).await;

    let logged = sink.0.lock().unwrap_or_else(|p| p.into_inner()).clone();
    assert!(!logged.is_empty(), "the subscriber captured nothing");
    assert!(
        !logged.windows(SECRET.len()).any(|w| w == SECRET),
        "a credential reached a log line"
    );
}

// ---------------------------------------------------------------------------
// Callbacks that await their own connection (no deadlock)
// ---------------------------------------------------------------------------

/// Sends from inside its callbacks and awaits the result: `HELLO` from
/// `on_established`, `PONG` from `on_message` for every `PING`, a send from
/// `on_event` on `Established` once the handle is stored, and one from
/// `on_closed`.
#[derive(Default)]
struct Echo {
    received: Mutex<Vec<Bytes>>,
    connection: Mutex<Option<FixpConnection>>,
    sent_from_callbacks: Mutex<Vec<&'static str>>,
    closed_send: Mutex<Option<bool>>,
}

impl Echo {
    fn connection(&self) -> Option<FixpConnection> {
        self.connection
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn received(&self) -> Vec<Bytes> {
        self.received
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

#[derive(Clone)]
struct EchoApp(Arc<Echo>);

impl EchoApp {
    fn record(&self, what: &'static str) {
        self.0
            .sent_from_callbacks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(what);
    }
}

#[async_trait]
impl FixpApplication for EchoApp {
    async fn on_negotiate(&self, _request: &NegotiateRequest) -> NegotiationDecision {
        NegotiationDecision::Accept {
            server_flow: FlowType::Recoverable,
            credentials: None,
        }
    }

    async fn on_established(&self, connection: FixpConnection) {
        ok(
            connection.send(Bytes::from_static(b"HELLO")).await,
            "send from on_established",
        );
        self.record("on_established");
        *self.0.connection.lock().unwrap_or_else(|p| p.into_inner()) = Some(connection);
    }

    async fn on_message(&self, _session_id: SessionId, message: FixpInbound) {
        self.0
            .received
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(message.payload.clone());
        if message.payload.as_ref() == b"PING"
            && let Some(connection) = self.0.connection()
        {
            ok(
                connection.send(Bytes::from_static(b"PONG")).await,
                "send from on_message",
            );
            self.record("on_message");
        }
    }

    async fn on_event(&self, _session_id: Option<SessionId>, event: &Event) {
        // Any event: awaiting the connection from on_event must not block.
        if matches!(event, Event::SequenceGap { .. })
            && let Some(connection) = self.0.connection()
        {
            let _ = connection.send(Bytes::from_static(b"EVENT")).await;
        }
    }

    async fn on_closed(&self, _session_id: Option<SessionId>) {
        if let Some(connection) = self.0.connection() {
            let refused = matches!(
                connection.send(Bytes::from_static(b"LATE")).await,
                Err(FixpEngineError::Closed)
            );
            *self.0.closed_send.lock().unwrap_or_else(|p| p.into_inner()) = Some(refused);
        }
    }
}

async fn ping_pong_both_ways(client: &FixpConnection, client_app: &Echo, server_app: &Echo) {
    let ping = Bytes::from_static(b"PING");
    let pong = Bytes::from_static(b"PONG");
    let hello = Bytes::from_static(b"HELLO");
    wait_until("HELLO both ways", || {
        client_app.received().contains(&hello) && server_app.received().contains(&hello)
    })
    .await;
    // Client to server: the server's on_message answers.
    ok(client.send(ping.clone()).await, "client PING");
    wait_until("PONG at the client", || {
        client_app.received().contains(&pong)
    })
    .await;
    // Server to client: the client's on_message answers.
    let Some(server) = server_app.connection() else {
        panic!("no server connection");
    };
    ok(server.send(ping).await, "server PING");
    wait_until("PONG at the server", || {
        server_app.received().contains(&pong)
    })
    .await;
    for echo in [client_app, server_app] {
        let sent = echo
            .sent_from_callbacks
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        assert_eq!(sent, vec!["on_established", "on_message"]);
    }
    ok(client.terminate("done").await, "terminate");
    wait_closed(client).await;
    wait_closed(&server).await;
    for echo in [client_app, server_app] {
        wait_until("on_closed ran its send", || {
            echo.closed_send
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_some()
        })
        .await;
        assert_eq!(
            *echo.closed_send.lock().unwrap_or_else(|p| p.into_inner()),
            Some(true),
            "a send after the close is refused, not left hanging"
        );
    }
}

#[tokio::test]
async fn test_callbacks_may_await_their_own_connection_over_tcp() {
    let outcome = tokio::time::timeout(Duration::from_secs(10), async {
        let (listener, addr) = tcp_pair().await;
        let server_app = Arc::new(Echo::default());
        let client_app = Arc::new(Echo::default());
        let acceptor = FixpAcceptor::new(EchoApp(Arc::clone(&server_app)), FixpConfig::default());
        let serving = tokio::spawn({
            let acceptor = acceptor.clone();
            async move { acceptor.serve(listener).await }
        });
        let client = ok(
            FixpInitiator::new(
                EchoApp(Arc::clone(&client_app)),
                FixpConfig::default(),
                session_id(0x91),
                FlowType::Recoverable,
            )
            .connect(addr)
            .await,
            "connect",
        );
        wait_until("the server's connection", || {
            server_app.connection().is_some()
        })
        .await;
        ping_pong_both_ways(&client, &client_app, &server_app).await;
        serving.abort();
    })
    .await;
    assert!(
        outcome.is_ok(),
        "a callback awaiting its connection deadlocked"
    );
}

#[tokio::test]
async fn test_callbacks_may_await_their_own_connection_over_duplex() {
    let outcome = tokio::time::timeout(Duration::from_secs(10), async {
        let server_app = Arc::new(Echo::default());
        let client_app = Arc::new(Echo::default());
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let acceptor = FixpAcceptor::new(EchoApp(Arc::clone(&server_app)), FixpConfig::default());
        let initiator = FixpInitiator::new(
            EchoApp(Arc::clone(&client_app)),
            FixpConfig::default(),
            session_id(0x92),
            FlowType::Recoverable,
        );
        let (server, client) = tokio::join!(
            acceptor.accept_stream(server_io),
            initiator.connect_stream(client_io)
        );
        let _server = ok(server, "accept");
        let client = ok(client, "connect");
        ping_pong_both_ways(&client, &client_app, &server_app).await;
    })
    .await;
    assert!(
        outcome.is_ok(),
        "a callback awaiting its connection deadlocked"
    );
}

/// The engine as requester sends from `on_event` when it reports the gap.
#[tokio::test]
async fn test_on_event_may_await_its_own_connection() {
    let outcome = tokio::time::timeout(Duration::from_secs(10), async {
        let (engine_io, peer_io) = tokio::io::duplex(64 * 1024);
        let app = Arc::new(Echo::default());
        let initiator = FixpInitiator::new(
            EchoApp(Arc::clone(&app)),
            FixpConfig::default(),
            session_id(0x93),
            FlowType::Recoverable,
        );
        let (engine, mut peer) =
            tokio::join!(initiator.connect_stream(engine_io), Peer::accept(peer_io));
        let engine = ok(engine, "connect");
        wait_until("the handle stored", || app.connection().is_some()).await;
        let _ = peer.send_app(payload(1), false).await;
        let _ = peer.send_app(payload(2), true).await;
        let _ = peer.core.send(now());
        peer.flush().await;
        peer.stored.insert(3, payload(3));
        peer.write_session(&SessionMessage::Sequence(Sequence { next_seq_no: 3 }))
            .await;
        peer.write_application(payload(3)).await;
        // HELLO, then EVENT sent from on_event on the gap.
        let event = Bytes::from_static(b"EVENT");
        while !peer.applications.iter().any(|(_, _, b)| *b == event) {
            if peer.step().await.is_none() {
                panic!("transport ended before EVENT");
            }
        }
        ok(engine.terminate("done").await, "terminate");
    })
    .await;
    assert!(
        outcome.is_ok(),
        "on_event awaiting its connection deadlocked"
    );
}

// ---------------------------------------------------------------------------
// Writes never block reads
// ---------------------------------------------------------------------------

/// Both sides write more than the transport buffers while neither has read:
/// a driver whose pending write stopped its reads would deadlock against its
/// counterparty (the failure #126 fixed in the tag=value reactor). Over a
/// 64-byte duplex, each side sends 100 messages of 128 bytes at once.
#[tokio::test]
async fn test_bilateral_sends_over_a_tiny_duplex_do_not_deadlock() {
    let outcome = tokio::time::timeout(Duration::from_secs(10), async {
        let server_app = Arc::new(Recorder::default());
        let client_app = Arc::new(Recorder::default());
        let (client_io, server_io) = tokio::io::duplex(64);
        let acceptor = FixpAcceptor::new(App(Arc::clone(&server_app)), FixpConfig::default());
        let initiator = FixpInitiator::new(
            App(Arc::clone(&client_app)),
            FixpConfig::default(),
            session_id(0xa1),
            FlowType::Recoverable,
        )
        .with_credentials(credentials());
        let (server, client) = tokio::join!(
            acceptor.accept_stream(server_io),
            initiator.connect_stream(client_io)
        );
        let server = ok(server, "accept");
        let client = ok(client, "connect");
        let burst = |connection: FixpConnection, tag: u8| async move {
            for n in 0..100u8 {
                let mut bytes = vec![tag; 128];
                bytes[0] = n;
                ok(connection.send(bytes).await, "burst send");
            }
        };
        tokio::join!(burst(client.clone(), b'C'), burst(server.clone(), b'S'));
        wait_until("100 messages each way", || {
            client_app.messages().len() == 100 && server_app.messages().len() == 100
        })
        .await;
        for (n, (seq, _, bytes)) in server_app.messages().into_iter().enumerate() {
            assert_eq!(seq, Some(n as u64 + 1));
            assert_eq!(bytes.len(), 128);
            assert_eq!(bytes[1], b'C');
        }
        for (_, _, bytes) in client_app.messages() {
            assert_eq!(bytes[1], b'S');
        }
        ok(client.terminate("done").await, "terminate");
        wait_closed(&client).await;
        wait_closed(&server).await;
    })
    .await;
    assert!(outcome.is_ok(), "bilateral sends deadlocked");
}

// ---------------------------------------------------------------------------
// Handshake decisions are bounded and release the identifier
// ---------------------------------------------------------------------------

/// Never answers the first Negotiate or Establish it is asked about (per the
/// flags); answers every later one like [`App`].
struct Hang {
    inner: App,
    hang_negotiate: std::sync::atomic::AtomicBool,
    hang_establish: std::sync::atomic::AtomicBool,
}

#[derive(Clone)]
struct HangApp(Arc<Hang>);

impl HangApp {
    fn new(recorder: &Arc<Recorder>, negotiate: bool, establish: bool) -> Self {
        Self(Arc::new(Hang {
            inner: App(Arc::clone(recorder)),
            hang_negotiate: std::sync::atomic::AtomicBool::new(negotiate),
            hang_establish: std::sync::atomic::AtomicBool::new(establish),
        }))
    }
}

#[async_trait]
impl FixpApplication for HangApp {
    async fn on_negotiate(&self, request: &NegotiateRequest) -> NegotiationDecision {
        if self
            .0
            .hang_negotiate
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            std::future::pending::<()>().await;
        }
        self.0.inner.on_negotiate(request).await
    }

    async fn on_establish(&self, request: &EstablishRequest) -> EstablishmentDecision {
        if self
            .0
            .hang_establish
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            std::future::pending::<()>().await;
        }
        self.0.inner.on_establish(request).await
    }

    async fn on_established(&self, connection: FixpConnection) {
        self.0.inner.on_established(connection).await;
    }

    async fn on_message(&self, session_id: SessionId, message: FixpInbound) {
        self.0.inner.on_message(session_id, message).await;
    }

    async fn on_event(&self, session_id: Option<SessionId>, event: &Event) {
        self.0.inner.on_event(session_id, event).await;
    }

    async fn on_closed(&self, session_id: Option<SessionId>) {
        self.0.inner.on_closed(session_id).await;
    }
}

fn short_handshake() -> FixpConfig {
    ok(
        FixpConfig::builder()
            .handshake_timeout(Duration::from_millis(300))
            .build(),
        "config",
    )
}

/// Reads until the engine closes the transport, within [`WAIT`].
async fn expect_closed<C: Core, S: AsyncRead + AsyncWrite + Unpin>(peer: &mut Peer<C, S>) {
    loop {
        match tokio::time::timeout(WAIT, peer.framed.next()).await {
            Ok(None | Some(Err(_))) => return,
            Ok(Some(Ok(_))) => {}
            Err(_) => panic!("the engine kept the transport open"),
        }
    }
}

/// Negotiates and establishes `id` afresh: proves the acceptor no longer
/// holds it (a held id gets NegotiationReject `DuplicateId`).
async fn negotiates_again(addr: std::net::SocketAddr, id: SessionId) {
    let stream = ok(TcpStream::connect(addr).await, "dial again");
    let peer = Peer::connect(stream, id).await;
    assert!(!peer.saw(|e| matches!(e, Event::NegotiationRejected { .. })));
}

async fn serve_hanging(
    negotiate: bool,
    establish: bool,
) -> (
    Arc<Recorder>,
    std::net::SocketAddr,
    tokio::task::JoinHandle<Result<(), FixpEngineError>>,
) {
    let (listener, addr) = tcp_pair().await;
    let recorder = Arc::new(Recorder::default());
    let acceptor = FixpAcceptor::new(
        HangApp::new(&recorder, negotiate, establish),
        short_handshake(),
    );
    let serving = tokio::spawn(async move { acceptor.serve(listener).await });
    (recorder, addr, serving)
}

fn negotiating_client(stream: TcpStream, id: SessionId) -> Peer<FixpClient, TcpStream> {
    let client = FixpClient::new(
        FixpConfig::default(),
        clock(),
        id,
        FlowType::Recoverable,
        Some(credentials()),
    );
    Peer::new(client, stream)
}

#[tokio::test]
async fn test_a_pending_negotiate_decision_is_bounded_and_releases_the_id() {
    let (recorder, addr, serving) = serve_hanging(true, false).await;
    let id = session_id(0xb1);
    let stream = ok(TcpStream::connect(addr).await, "dial");
    let mut peer = negotiating_client(stream, id);
    ok(peer.core.negotiate(now()), "negotiate");
    peer.flush().await;
    // The application never answers: the handshake deadline closes it.
    expect_closed(&mut peer).await;
    wait_until("server driver ended", || recorder.closed() == 1).await;
    assert!(has_event(&recorder, |e| matches!(
        e,
        Event::HandshakeTimedOut { .. }
    )));
    negotiates_again(addr, id).await;
    serving.abort();
}

#[tokio::test]
async fn test_a_pending_establish_decision_is_bounded_and_releases_the_id() {
    let (recorder, addr, serving) = serve_hanging(false, true).await;
    let id = session_id(0xb2);
    let stream = ok(TcpStream::connect(addr).await, "dial");
    let mut peer = negotiating_client(stream, id);
    ok(peer.core.negotiate(now()), "negotiate");
    peer.flush().await;
    peer.step_until("NegotiationResponse", |p| {
        p.saw(|e| matches!(e, Event::Negotiated { .. }))
    })
    .await;
    ok(peer.core.establish(now()), "establish");
    peer.flush().await;
    expect_closed(&mut peer).await;
    wait_until("server driver ended", || recorder.closed() == 1).await;
    negotiates_again(addr, id).await;
    serving.abort();
}

#[tokio::test]
async fn test_a_disconnect_during_a_pending_decision_releases_the_id() {
    // A handshake timeout long enough that only the disconnect can end it.
    let (listener, addr) = tcp_pair().await;
    let recorder = Arc::new(Recorder::default());
    let acceptor = FixpAcceptor::new(HangApp::new(&recorder, true, false), FixpConfig::default());
    let serving = tokio::spawn(async move { acceptor.serve(listener).await });
    let id = session_id(0xb3);
    let stream = ok(TcpStream::connect(addr).await, "dial");
    let mut peer = negotiating_client(stream, id);
    ok(peer.core.negotiate(now()), "negotiate");
    peer.flush().await;
    wait_until("Negotiate reported", || {
        has_event(&recorder, |e| matches!(e, Event::NegotiateReceived { .. }))
    })
    .await;
    drop(peer);
    wait_until("server driver ended on the disconnect", || {
        recorder.closed() == 1
    })
    .await;
    negotiates_again(addr, id).await;
    serving.abort();
}
