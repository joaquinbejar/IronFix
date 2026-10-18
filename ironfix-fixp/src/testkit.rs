/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Test support: a fixed configuration and clock, and a client and a server
//! that talk through the real encoder and decoder.
//!
//! Every message passed between the two goes through
//! [`SessionMessage::encode`] and [`SessionMessage::decode`], so the state
//! machine tests also exercise the codec. Time is synthetic: a test takes one
//! `Instant` as its origin and moves forward from it in milliseconds.

use crate::{
    ClockAnchor, Delivery, Event, FixpClient, FixpConfig, FixpServer, FlowType, Output, SessionId,
    SessionMessage, SessionStatus,
};
use ironfix_core::Timestamp;
use std::num::NonZeroU32;
use std::time::{Duration, Instant};

/// Keepalive interval of both sides in tests.
pub(crate) const KEEPALIVE: Duration = Duration::from_secs(1);

/// Handshake timeout in tests.
pub(crate) const HANDSHAKE: Duration = Duration::from_secs(5);

/// Retransmission stall timeout in tests.
pub(crate) const RETRANSMIT_TIMEOUT: Duration = Duration::from_secs(3);

/// Largest RetransmitRequest count in tests.
pub(crate) const MAX_RETRANSMIT: u32 = 100;

/// Wall-clock time of the clock anchor, in nanoseconds since the epoch.
pub(crate) const WALL: u64 = 1_700_000_000_000_000_000;

/// The session identifier the test client uses.
pub(crate) const SESSION: SessionId = SessionId::from_bytes([
    0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x42, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00,
]);

/// Another valid session identifier.
pub(crate) const OTHER_SESSION: SessionId = SessionId::from_bytes([0x77; 16]);

pub(crate) fn config() -> FixpConfig {
    let built = FixpConfig::builder()
        .keepalive_interval(KEEPALIVE)
        .peer_keepalive_range(Duration::from_millis(100), Duration::from_secs(60))
        .handshake_timeout(HANDSHAKE)
        .retransmit_timeout(RETRANSMIT_TIMEOUT)
        .max_retransmit_count(NonZeroU32::new(MAX_RETRANSMIT).unwrap_or(NonZeroU32::MIN))
        .build();
    match built {
        Ok(config) => config,
        Err(error) => panic!("test config is invalid: {error}"),
    }
}

pub(crate) fn anchor(origin: Instant) -> ClockAnchor {
    match Timestamp::from_nanos(WALL) {
        Ok(wall) => ClockAnchor::new(origin, wall),
        Err(error) => panic!("test wall clock is invalid: {error}"),
    }
}

/// `origin` plus `millis` milliseconds.
pub(crate) fn at(origin: Instant, millis: u64) -> Instant {
    origin + Duration::from_millis(millis)
}

pub(crate) fn client(origin: Instant, flow: FlowType) -> FixpClient {
    FixpClient::new(config(), anchor(origin), SESSION, flow, None)
}

pub(crate) fn server(origin: Instant) -> FixpServer {
    FixpServer::new(config(), anchor(origin), origin)
}

/// Either role, as the test helpers drive it.
pub(crate) trait Endpoint {
    fn next_output(&mut self) -> Option<Output>;
    fn deliver(&mut self, message: &SessionMessage, now: Instant);
    fn application(&mut self, now: Instant) -> Delivery;
}

impl Endpoint for FixpClient {
    fn next_output(&mut self) -> Option<Output> {
        self.poll_output()
    }
    fn deliver(&mut self, message: &SessionMessage, now: Instant) {
        self.handle_message(message, now);
    }
    fn application(&mut self, now: Instant) -> Delivery {
        self.on_application_message(now)
    }
}

impl Endpoint for FixpServer {
    fn next_output(&mut self) -> Option<Output> {
        self.poll_output()
    }
    fn deliver(&mut self, message: &SessionMessage, now: Instant) {
        self.handle_message(message, now);
    }
    fn application(&mut self, now: Instant) -> Delivery {
        self.on_application_message(now)
    }
}

/// Takes every queued output.
pub(crate) fn drain(endpoint: &mut impl Endpoint) -> Vec<Output> {
    std::iter::from_fn(|| endpoint.next_output()).collect()
}

/// The messages among `outputs`, session and session-generated application
/// messages alike, in order.
pub(crate) fn sent(outputs: &[Output]) -> Vec<SessionMessage> {
    outputs
        .iter()
        .filter_map(|output| match output {
            Output::Send(message) | Output::SendApplication { message, .. } => {
                Some(message.clone())
            }
            Output::CloseTransport | Output::Event(_) => None,
        })
        .collect()
}

/// The events among `outputs`, in order.
pub(crate) fn events(outputs: &[Output]) -> Vec<Event> {
    outputs
        .iter()
        .filter_map(|output| match output {
            Output::Event(event) => Some(event.clone()),
            Output::Send(_) | Output::SendApplication { .. } | Output::CloseTransport => None,
        })
        .collect()
}

/// `true` if `outputs` ask for the transport to be closed.
pub(crate) fn closes(outputs: &[Output]) -> bool {
    outputs
        .iter()
        .any(|output| matches!(output, Output::CloseTransport))
}

/// Encodes and decodes `message`, as a transport would carry it.
pub(crate) fn through_wire(message: &SessionMessage) -> SessionMessage {
    let mut wire = Vec::new();
    if let Err(error) = message.encode(&mut wire) {
        panic!("{} failed to encode: {error}", message.name());
    }
    match SessionMessage::decode(&wire) {
        Ok((decoded, used)) => {
            assert_eq!(used, wire.len());
            decoded
        }
        Err(error) => panic!("{} failed to decode: {error}", message.name()),
    }
}

/// Delivers the messages among `outputs` to `to`, through the wire.
pub(crate) fn deliver_all(outputs: &[Output], to: &mut impl Endpoint, now: Instant) {
    for message in sent(outputs) {
        to.deliver(&through_wire(&message), now);
    }
}

/// A client and a server that have negotiated, with every output drained.
pub(crate) fn negotiated_pair(
    origin: Instant,
    client_flow: FlowType,
    server_flow: FlowType,
) -> (FixpClient, FixpServer) {
    negotiate_pair(
        client(origin, client_flow),
        server(origin),
        server_flow,
        origin,
    )
}

/// Negotiates `client` with `server`, with every output drained.
pub(crate) fn negotiate_pair(
    mut client: FixpClient,
    mut server: FixpServer,
    server_flow: FlowType,
    origin: Instant,
) -> (FixpClient, FixpServer) {
    assert_eq!(client.negotiate(origin), Ok(()));
    let negotiate = drain(&mut client);
    deliver_all(&negotiate, &mut server, origin);
    let _ = drain(&mut server);
    assert_eq!(server.accept_negotiation(server_flow, None, origin), Ok(()));
    let response = drain(&mut server);
    deliver_all(&response, &mut client, origin);
    let _ = drain(&mut client);
    assert_eq!(client.status(), SessionStatus::Negotiated);
    assert_eq!(server.status(), SessionStatus::Negotiated);
    (client, server)
}

/// Binds a negotiated pair at `now`, with every output drained.
pub(crate) fn establish(client: &mut FixpClient, server: &mut FixpServer, now: Instant) {
    assert_eq!(client.establish(now), Ok(()));
    let establish = drain(client);
    deliver_all(&establish, server, now);
    let _ = drain(server);
    assert_eq!(server.accept_establishment(now), Ok(()));
    let ack = drain(server);
    deliver_all(&ack, client, now);
    let _ = drain(client);
    assert_eq!(client.status(), SessionStatus::Established);
    assert_eq!(server.status(), SessionStatus::Established);
}

/// A client and a server bound at `origin`, with every output drained.
pub(crate) fn established_pair(
    origin: Instant,
    client_flow: FlowType,
    server_flow: FlowType,
) -> (FixpClient, FixpServer) {
    let (mut client, mut server) = negotiated_pair(origin, client_flow, server_flow);
    establish(&mut client, &mut server, origin);
    (client, server)
}

/// Sends `count` application messages from `from` and delivers them to `to`,
/// returning the deliveries.
pub(crate) fn send_apps(
    from: &mut impl Sender,
    to: &mut impl Endpoint,
    count: usize,
    now: Instant,
) -> Vec<Delivery> {
    let mut deliveries = Vec::with_capacity(count);
    for _ in 0..count {
        assert!(from.send_app(now).is_ok());
        let outputs = from.drain_outputs();
        deliver_all(&outputs, to, now);
        deliveries.push(to.application(now));
    }
    deliveries
}

/// A role that can send application messages.
pub(crate) trait Sender {
    fn send_app(&mut self, now: Instant) -> Result<Option<ironfix_core::SeqNum>, crate::FixpError>;
    fn drain_outputs(&mut self) -> Vec<Output>;
}

impl Sender for FixpClient {
    fn send_app(&mut self, now: Instant) -> Result<Option<ironfix_core::SeqNum>, crate::FixpError> {
        self.send_application(now)
    }
    fn drain_outputs(&mut self) -> Vec<Output> {
        drain(self)
    }
}

impl Sender for FixpServer {
    fn send_app(&mut self, now: Instant) -> Result<Option<ironfix_core::SeqNum>, crate::FixpError> {
        self.send_application(now)
    }
    fn drain_outputs(&mut self) -> Vec<Output> {
        drain(self)
    }
}
