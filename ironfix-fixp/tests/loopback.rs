/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! A client and a server driven end to end through the public API, the way a
//! driver would: encoded bytes move between them, application messages are
//! opaque payloads kept in a store for retransmission, and time is synthetic.
//!
//! The scenario: negotiate with credentials, establish, exchange messages in
//! both directions, lose two server messages in transit and recover them by
//! retransmission, terminate gracefully, then re-establish the same session
//! on a new transport with the sequence numbers carried over.

use ironfix_core::{SeqNum, Timestamp};
use ironfix_fixp::{
    ClockAnchor, Credentials, Delivery, Event, FixpClient, FixpConfig, FixpServer, FlowType,
    Output, SessionId, SessionMessage, SessionStatus, TerminationCode, is_session_message,
};
use std::collections::{BTreeMap, VecDeque};
use std::num::NonZeroU32;
use std::time::{Duration, Instant};

const SESSION: SessionId = SessionId::from_bytes([
    0x9f, 0x1c, 0x2b, 0x3a, 0x4d, 0x5e, 0x46, 0x7f, 0x80, 0x91, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7,
]);

/// What travels on the simulated transport.
#[derive(Debug, Clone)]
enum Frame {
    /// An encoded FIXP session message.
    Session(Vec<u8>),
    /// An application message: opaque bytes, numbered implicitly.
    Application(Vec<u8>),
}

/// Either role, behind the methods a driver needs.
trait Role {
    fn poll(&mut self) -> Option<Output>;
    fn message(&mut self, message: &SessionMessage, now: Instant);
    fn application(&mut self, now: Instant) -> Delivery;
    fn send(&mut self, now: Instant) -> Result<Option<SeqNum>, ironfix_fixp::FixpError>;
    fn retransmit(&mut self, count: NonZeroU32, now: Instant) -> ironfix_fixp::RetransmitBatch;
}

impl Role for FixpClient {
    fn poll(&mut self) -> Option<Output> {
        self.poll_output()
    }
    fn message(&mut self, message: &SessionMessage, now: Instant) {
        self.handle_message(message, now);
    }
    fn application(&mut self, now: Instant) -> Delivery {
        self.on_application_message(now)
    }
    fn send(&mut self, now: Instant) -> Result<Option<SeqNum>, ironfix_fixp::FixpError> {
        self.send_application(now)
    }
    fn retransmit(&mut self, count: NonZeroU32, now: Instant) -> ironfix_fixp::RetransmitBatch {
        match self.retransmit(count, now) {
            Ok(batch) => batch,
            Err(error) => panic!("client retransmit failed: {error}"),
        }
    }
}

impl Role for FixpServer {
    fn poll(&mut self) -> Option<Output> {
        self.poll_output()
    }
    fn message(&mut self, message: &SessionMessage, now: Instant) {
        self.handle_message(message, now);
    }
    fn application(&mut self, now: Instant) -> Delivery {
        self.on_application_message(now)
    }
    fn send(&mut self, now: Instant) -> Result<Option<SeqNum>, ironfix_fixp::FixpError> {
        self.send_application(now)
    }
    fn retransmit(&mut self, count: NonZeroU32, now: Instant) -> ironfix_fixp::RetransmitBatch {
        match self.retransmit(count, now) {
            Ok(batch) => batch,
            Err(error) => panic!("server retransmit failed: {error}"),
        }
    }
}

/// One side of the link: the session plus what its driver keeps.
struct Side<R> {
    role: R,
    /// Frames received, not yet processed.
    inbox: VecDeque<Frame>,
    /// Application messages sent, by sequence number, for retransmission.
    store: BTreeMap<u64, Vec<u8>>,
    /// Application messages delivered: sequence number, retransmitted, bytes.
    delivered: Vec<(Option<SeqNum>, bool, Vec<u8>)>,
    events: Vec<Event>,
    /// Decoded session messages received, for inspection.
    seen: Vec<SessionMessage>,
    close_requested: bool,
}

impl<R: Role> Side<R> {
    fn new(role: R) -> Self {
        Self {
            role,
            inbox: VecDeque::new(),
            store: BTreeMap::new(),
            delivered: Vec::new(),
            events: Vec::new(),
            seen: Vec::new(),
            close_requested: false,
        }
    }

    /// Carries out every queued output; frames go to `out`.
    fn flush(&mut self, out: &mut VecDeque<Frame>) {
        while let Some(output) = self.role.poll() {
            match output {
                Output::Send(message) => out.push_back(Frame::Session(encode(&message))),
                Output::SendApplication { seq, message } => {
                    let bytes = encode(&message);
                    if let Some(seq) = seq {
                        self.store.insert(seq.value(), bytes.clone());
                    }
                    out.push_back(Frame::Session(bytes));
                }
                Output::CloseTransport => self.close_requested = true,
                Output::Event(event) => self.events.push(event),
                other => panic!("unexpected output {other:?}"),
            }
        }
    }

    /// Sends one application message; returns its frame for the transport.
    fn send(&mut self, payload: &[u8], now: Instant, out: &mut VecDeque<Frame>) -> Option<SeqNum> {
        let seq = match self.role.send(now) {
            Ok(seq) => seq,
            Err(error) => panic!("send_application failed: {error}"),
        };
        // A Sequence may have to precede the message: flush first.
        self.flush(out);
        if let Some(seq) = seq {
            self.store.insert(seq.value(), payload.to_vec());
        }
        out.push_back(Frame::Application(payload.to_vec()));
        seq
    }

    /// Processes every frame in the inbox.
    fn process(&mut self, now: Instant, out: &mut VecDeque<Frame>) {
        while let Some(frame) = self.inbox.pop_front() {
            match frame {
                Frame::Session(bytes) => {
                    assert!(is_session_message(&bytes));
                    let message = match SessionMessage::decode(&bytes) {
                        Ok((message, used)) => {
                            assert_eq!(used, bytes.len());
                            message
                        }
                        Err(error) => panic!("decode failed: {error}"),
                    };
                    self.role.message(&message, now);
                    self.seen.push(message);
                }
                Frame::Application(bytes) => match self.role.application(now) {
                    Delivery::Accept { seq, retransmitted } => {
                        self.delivered.push((seq, retransmitted, bytes));
                    }
                    Delivery::Discard => {}
                    other => panic!("unexpected delivery {other:?}"),
                },
            }
            self.flush(out);
        }
        self.flush(out);
    }

    /// Serves a counterparty RetransmitRequest from the store.
    fn serve_retransmission(
        &mut self,
        from: u64,
        count: u32,
        now: Instant,
        out: &mut VecDeque<Frame>,
    ) {
        let Some(count) = NonZeroU32::new(count) else {
            return;
        };
        let batch = self.role.retransmit(count, now);
        self.flush(out);
        for seq in batch.from.value()..batch.from.value() + u64::from(batch.count) {
            match self.store.get(&seq) {
                Some(bytes) => out.push_back(Frame::Application(bytes.clone())),
                None => panic!("message {seq} is not stored"),
            }
        }
        assert_eq!(batch.from.value(), from);
    }
}

fn encode(message: &SessionMessage) -> Vec<u8> {
    let mut bytes = Vec::new();
    match message.encode(&mut bytes) {
        Ok(_) => bytes,
        Err(error) => panic!("encode failed: {error}"),
    }
}

fn config() -> FixpConfig {
    match FixpConfig::builder()
        .keepalive_interval(Duration::from_secs(1))
        .build()
    {
        Ok(config) => config,
        Err(error) => panic!("invalid config: {error}"),
    }
}

fn anchor(origin: Instant) -> ClockAnchor {
    match Timestamp::from_nanos(1_760_000_000_000_000_000) {
        Ok(wall) => ClockAnchor::new(origin, wall),
        Err(error) => panic!("invalid wall clock: {error}"),
    }
}

/// Moves frames between the two sides until both are quiet.
fn pump(client: &mut Side<FixpClient>, server: &mut Side<FixpServer>, now: Instant) {
    for _ in 0..16 {
        let mut to_server = VecDeque::new();
        let mut to_client = VecDeque::new();
        client.process(now, &mut to_server);
        server.process(now, &mut to_client);
        if to_server.is_empty() && to_client.is_empty() {
            return;
        }
        server.inbox.extend(to_server);
        client.inbox.extend(to_client);
    }
    panic!("the link never went quiet");
}

#[test]
fn test_fixp_session_end_to_end() {
    let origin = Instant::now();
    let credentials = Credentials::try_new(b"trader-7:secret".to_vec()).ok();
    let mut client = Side::new(FixpClient::new(
        config(),
        anchor(origin),
        SESSION,
        FlowType::Idempotent,
        credentials,
    ));
    let mut server = Side::new(FixpServer::new(config(), anchor(origin), origin));

    // Negotiation: the server checks the credentials in the decoded message.
    assert!(client.role.negotiate(origin).is_ok());
    let mut wire = VecDeque::new();
    client.flush(&mut wire);
    server.inbox.extend(wire);
    let mut wire = VecDeque::new();
    server.process(origin, &mut wire);
    assert!(wire.is_empty());
    match server.seen.last() {
        Some(SessionMessage::Negotiate(negotiate)) => {
            assert_eq!(
                negotiate.credentials.as_ref().map(Credentials::expose),
                Some(&b"trader-7:secret"[..])
            );
        }
        other => panic!("expected a Negotiate, got {other:?}"),
    }
    assert!(server.events.contains(&Event::NegotiateReceived {
        session_id: SESSION,
        client_flow: FlowType::Idempotent,
    }));
    assert!(
        server
            .role
            .accept_negotiation(FlowType::Recoverable, None, origin)
            .is_ok()
    );
    let mut wire = VecDeque::new();
    server.flush(&mut wire);
    client.inbox.extend(wire);
    pump(&mut client, &mut server, origin);
    assert_eq!(client.role.status(), SessionStatus::Negotiated);

    // Establishment.
    assert!(client.role.establish(origin).is_ok());
    let mut wire = VecDeque::new();
    client.flush(&mut wire);
    server.inbox.extend(wire);
    pump(&mut client, &mut server, origin);
    assert_eq!(server.role.status(), SessionStatus::EstablishPending);
    assert!(server.role.accept_establishment(origin).is_ok());
    let mut wire = VecDeque::new();
    server.flush(&mut wire);
    client.inbox.extend(wire);
    pump(&mut client, &mut server, origin);
    assert_eq!(client.role.status(), SessionStatus::Established);
    assert_eq!(server.role.status(), SessionStatus::Established);

    // Client to server: three orders, numbered 1 to 3.
    let mut wire = VecDeque::new();
    for order in [b"order-1", b"order-2", b"order-3"] {
        client.send(order, origin, &mut wire);
    }
    server.inbox.extend(wire);
    pump(&mut client, &mut server, origin);
    let numbers: Vec<_> = server.delivered.iter().map(|(seq, _, _)| *seq).collect();
    assert_eq!(
        numbers,
        vec![
            Some(SeqNum::new(1)),
            Some(SeqNum::new(2)),
            Some(SeqNum::new(3))
        ]
    );

    // Server to client: three reports arrive.
    let t1 = origin + Duration::from_millis(100);
    let mut wire = VecDeque::new();
    for report in [b"report-1", b"report-2", b"report-3"] {
        server.send(report, t1, &mut wire);
    }
    client.inbox.extend(wire);
    pump(&mut client, &mut server, t1);
    assert_eq!(client.role.next_inbound_seq(), Some(SeqNum::new(4)));

    // Two more reports go out as the connection drops: they never arrive.
    // On a stream transport this is how a gap happens; inside one
    // connection TCP loses nothing, and implicit numbering relies on that.
    let mut lost = VecDeque::new();
    server.send(b"report-4", t1, &mut lost);
    server.send(b"report-5", t1, &mut lost);
    drop(lost);
    client.role.on_transport_closed();
    server.role.on_transport_closed();
    client.flush(&mut VecDeque::new());
    server.flush(&mut VecDeque::new());
    assert_eq!(client.role.status(), SessionStatus::Negotiated);
    assert_eq!(server.role.status(), SessionStatus::Negotiated);

    // A new transport: the same session is established again without
    // negotiating (FIXP v1.1 sections 3.4.3 and 4.1). The client announces
    // its next number, 4; the server's EstablishmentAck announces 6, which
    // reveals the gap (section 4.3.2).
    let t2 = origin + Duration::from_secs(2);
    assert!(client.role.establish(t2).is_ok());
    let mut wire = VecDeque::new();
    client.flush(&mut wire);
    server.inbox.extend(wire);
    pump(&mut client, &mut server, t2);
    match server.seen.last() {
        Some(SessionMessage::Establish(establish)) => assert_eq!(establish.next_seq_no, Some(4)),
        other => panic!("expected an Establish, got {other:?}"),
    }
    assert!(server.role.accept_establishment(t2).is_ok());
    let mut to_client = VecDeque::new();
    server.flush(&mut to_client);
    client.inbox.extend(to_client);
    let mut to_server = VecDeque::new();
    client.process(t2, &mut to_server);
    assert_eq!(client.role.status(), SessionStatus::Established);
    assert!(client.events.contains(&Event::SequenceGap {
        from: SeqNum::new(4),
        count: 2,
    }));
    assert!(client.role.has_pending_recovery());
    server.inbox.extend(to_server);
    let mut to_client = VecDeque::new();
    server.process(t2, &mut to_client);
    assert!(server.events.contains(&Event::RetransmitRequested {
        from: SeqNum::new(4),
        count: 2,
    }));
    server.serve_retransmission(4, 2, t2, &mut to_client);
    client.inbox.extend(to_client);
    pump(&mut client, &mut server, t2);
    assert!(client.events.contains(&Event::RecoveryComplete));
    assert!(!client.role.has_pending_recovery());
    let retransmitted: Vec<_> = client
        .delivered
        .iter()
        .filter(|(_, retransmitted, _)| *retransmitted)
        .map(|(seq, _, bytes)| (*seq, bytes.clone()))
        .collect();
    assert_eq!(
        retransmitted,
        vec![
            (Some(SeqNum::new(4)), b"report-4".to_vec()),
            (Some(SeqNum::new(5)), b"report-5".to_vec()),
        ]
    );
    assert_eq!(client.role.next_inbound_seq(), Some(SeqNum::new(6)));

    // Numbering carried over in the other direction too.
    let mut wire = VecDeque::new();
    let seq = client.send(b"order-4", t2, &mut wire);
    assert_eq!(seq, Some(SeqNum::new(4)));
    server.inbox.extend(wire);
    pump(&mut client, &mut server, t2);
    assert_eq!(
        server.delivered.last().map(|(seq, _, _)| *seq),
        Some(Some(SeqNum::new(4)))
    );

    // Graceful termination: the client starts it, the server answers, and
    // the initiator closes the transport (section 4.4.2).
    assert!(
        client
            .role
            .terminate(TerminationCode::Finished, "end of day", t2)
            .is_ok()
    );
    let mut wire = VecDeque::new();
    client.flush(&mut wire);
    server.inbox.extend(wire);
    pump(&mut client, &mut server, t2);
    assert!(client.close_requested, "the initiator closes the transport");
    assert!(!server.close_requested, "the responder waits for it");
    assert_eq!(client.role.status(), SessionStatus::Negotiated);
    assert_eq!(server.role.status(), SessionStatus::Closing);
    client.role.on_transport_closed();
    server.role.on_transport_closed();
    assert_eq!(server.role.status(), SessionStatus::Negotiated);

    // Nothing in any output ever showed the credentials.
    let rendered = format!("{:?} {:?} {:?}", client.events, server.events, server.seen);
    assert!(!rendered.contains("secret"), "{rendered}");
}
