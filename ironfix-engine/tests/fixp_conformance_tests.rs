/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! FIXP v1.1 / SOFH v1.0 conformance suite for the engine (issue #97).
//!
//! The counterparty here is a **raw peer**: it writes SOFH headers and SBE
//! session messages built byte by byte from the FIXP schema
//! (`ironfix-fixp/spec/SBEschemaForFIXP.xml`, schema id 2748, version 0,
//! little-endian) and reads the engine's frames the same way. It uses
//! neither `ironfix_sofh::SofhCodec` nor the `ironfix_fixp` codec, so the
//! suite does not test IronFix against itself.
//!
//! Every test names the section and printed page of the FIXP v1.1 Draft
//! Standard (April 18, 2019) it checks:
//! <https://github.com/FIXTradingCommunity/fixp-specification/blob/master/v1-1/doc/publication/FIXP-Technical-Draft-Standard-v1.1.pdf>.
//! A case marked **local policy** checks a behaviour the specification
//! leaves open or only shows in the informative Appendix A; the decision is
//! recorded in `doc/fixp_operations.md`.
//!
//! Timing: every wait is bounded by [`WAIT`]; the few timers the cases rely
//! on (keepalive, handshake timeout) are configured an order of magnitude
//! below it, so a case either sees the behaviour or fails, never hangs.

use async_trait::async_trait;
use ironfix_engine::fixp::ironfix_fixp::{
    Credentials, EstablishmentRejectCode, Event, FixpConfig, FlowType, HandshakeStage,
    NegotiationRejectCode, RetransmitRejectCode, SeqNum, SessionId, TerminatedBy, TerminationCode,
};
use ironfix_engine::fixp::ironfix_sofh::EncodingType;
use ironfix_engine::fixp::{
    EstablishRequest, EstablishmentDecision, FixpAcceptor, FixpApplication, FixpConnection,
    FixpEngineError, FixpInbound, FixpInitiator, NegotiateRequest, NegotiationDecision,
};
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Upper bound on every wait of the suite.
const WAIT: Duration = Duration::from_secs(5);

const SECRET: &[u8] = b"conformance-secret";

#[track_caller]
fn ok<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{what}: {error:?}"),
    }
}

fn session_id(seed: u8) -> [u8; 16] {
    let mut id = [seed; 16];
    // A version 4, variant 1 UUID shape (FIXP v1.1 section 3.4.1, p. 13).
    id[6] = 0x40 | (seed & 0x0F);
    id[8] = 0x80 | (seed & 0x3F);
    id
}

// ---------------------------------------------------------------------------
// The wire, by hand: SOFH v1.0 header and FIXP SBE session messages
// ---------------------------------------------------------------------------

/// SOFH `Encoding_Type` of SBE 1.0 little-endian.
const SBE_LE: u16 = 0xEB50;
/// FIXP schema id, version 0.
const SCHEMA_ID: u16 = 2748;
/// SBE message header: blockLength, templateId, schemaId, version.
const HEADER: usize = 8;

mod template {
    pub const NEGOTIATE: u16 = 1;
    pub const NEGOTIATION_RESPONSE: u16 = 2;
    pub const NEGOTIATION_REJECT: u16 = 3;
    pub const TOPIC: u16 = 4;
    pub const ESTABLISH: u16 = 5;
    pub const ESTABLISHMENT_ACK: u16 = 6;
    pub const ESTABLISHMENT_REJECT: u16 = 7;
    pub const SEQUENCE: u16 = 8;
    pub const CONTEXT: u16 = 9;
    pub const UNSEQUENCED_HEARTBEAT: u16 = 10;
    pub const RETRANSMIT_REQUEST: u16 = 11;
    pub const RETRANSMISSION: u16 = 12;
    pub const RETRANSMIT_REJECT: u16 = 13;
    pub const TERMINATE: u16 = 14;
    pub const FINISHED_SENDING: u16 = 15;
    pub const FINISHED_RECEIVING: u16 = 16;
    pub const APPLIED: u16 = 17;
    pub const NOT_APPLIED: u16 = 18;
    pub const MESSAGE_TEMPLATE: u16 = 19;
}

/// Wire values of the schema's enumerations.
mod wire {
    pub const RECOVERABLE: u8 = 0;
    pub const IDEMPOTENT: u8 = 1;
    pub const UNSEQUENCED: u8 = 2;
    pub const NONE: u8 = 3;
    /// `uint64` null value of an optional `ordinal`.
    pub const NULL_U64: u64 = u64::MAX;
}

/// An SBE message: header, root block, variable-length fields (each a
/// `uint16` length and its bytes).
fn sbe(template: u16, block: &[u8], var: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    let block_len = ok(u16::try_from(block.len()), "block length");
    out.extend_from_slice(&block_len.to_le_bytes());
    out.extend_from_slice(&template.to_le_bytes());
    out.extend_from_slice(&SCHEMA_ID.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(block);
    for data in var {
        let len = ok(u16::try_from(data.len()), "var length");
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(data);
    }
    out
}

/// A root block, field by field in schema order.
#[derive(Default)]
struct Block(Vec<u8>);

impl Block {
    fn uuid(mut self, id: [u8; 16]) -> Self {
        self.0.extend_from_slice(&id);
        self
    }
    fn u64(mut self, v: u64) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u32(mut self, v: u32) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u8(mut self, v: u8) -> Self {
        self.0.push(v);
        self
    }
}

fn negotiate(id: [u8; 16], ts: u64, flow: u8, creds: &[u8]) -> Vec<u8> {
    let b = Block::default().uuid(id).u64(ts).u8(flow);
    sbe(template::NEGOTIATE, &b.0, &[creds])
}
fn negotiation_response(id: [u8; 16], ts: u64, flow: u8) -> Vec<u8> {
    let b = Block::default().uuid(id).u64(ts).u8(flow);
    sbe(template::NEGOTIATION_RESPONSE, &b.0, &[b""])
}
fn negotiation_reject(id: [u8; 16], ts: u64, code: u8) -> Vec<u8> {
    let b = Block::default().uuid(id).u64(ts).u8(code);
    sbe(template::NEGOTIATION_REJECT, &b.0, &[b"refused"])
}
fn topic(id: [u8; 16]) -> Vec<u8> {
    let b = Block::default().uuid(id).u8(wire::IDEMPOTENT).u32(1000);
    sbe(template::TOPIC, &b.0, &[b""])
}
fn establish(id: [u8; 16], ts: u64, keepalive_ms: u32, next: Option<u64>) -> Vec<u8> {
    let b = Block::default()
        .uuid(id)
        .u64(ts)
        .u32(keepalive_ms)
        .u64(next.unwrap_or(wire::NULL_U64));
    sbe(template::ESTABLISH, &b.0, &[SECRET])
}
fn establishment_ack(id: [u8; 16], ts: u64, keepalive_ms: u32, next: Option<u64>) -> Vec<u8> {
    let b = Block::default()
        .uuid(id)
        .u64(ts)
        .u32(keepalive_ms)
        .u64(next.unwrap_or(wire::NULL_U64));
    sbe(template::ESTABLISHMENT_ACK, &b.0, &[])
}
fn establishment_reject(id: [u8; 16], ts: u64, code: u8) -> Vec<u8> {
    let b = Block::default().uuid(id).u64(ts).u8(code);
    sbe(template::ESTABLISHMENT_REJECT, &b.0, &[b"refused"])
}
fn sequence(next: u64) -> Vec<u8> {
    sbe(template::SEQUENCE, &Block::default().u64(next).0, &[])
}
fn context(id: [u8; 16], next: u64) -> Vec<u8> {
    sbe(
        template::CONTEXT,
        &Block::default().uuid(id).u64(next).0,
        &[],
    )
}
fn unsequenced_heartbeat() -> Vec<u8> {
    sbe(template::UNSEQUENCED_HEARTBEAT, &[], &[])
}
fn retransmit_request(id: [u8; 16], ts: u64, from: u64, count: u32) -> Vec<u8> {
    let b = Block::default().uuid(id).u64(ts).u64(from).u32(count);
    sbe(template::RETRANSMIT_REQUEST, &b.0, &[])
}
fn retransmission(id: [u8; 16], ts: u64, next: u64, count: u32) -> Vec<u8> {
    let b = Block::default().uuid(id).u64(ts).u64(next).u32(count);
    sbe(template::RETRANSMISSION, &b.0, &[])
}
fn retransmit_reject(id: [u8; 16], ts: u64, code: u8) -> Vec<u8> {
    let b = Block::default().uuid(id).u64(ts).u8(code);
    sbe(template::RETRANSMIT_REJECT, &b.0, &[b"refused"])
}
fn terminate(id: [u8; 16], code: u8) -> Vec<u8> {
    let b = Block::default().uuid(id).u8(code);
    sbe(template::TERMINATE, &b.0, &[b"bye"])
}
fn finished_sending(id: [u8; 16], last: Option<u64>) -> Vec<u8> {
    let b = Block::default()
        .uuid(id)
        .u64(last.unwrap_or(wire::NULL_U64));
    sbe(template::FINISHED_SENDING, &b.0, &[])
}
fn finished_receiving(id: [u8; 16]) -> Vec<u8> {
    sbe(
        template::FINISHED_RECEIVING,
        &Block::default().uuid(id).0,
        &[],
    )
}
fn applied(from: u64, count: u32) -> Vec<u8> {
    let b = Block::default().u64(from).u32(count);
    sbe(template::APPLIED, &b.0, &[])
}
fn not_applied(from: u64, count: u32) -> Vec<u8> {
    let b = Block::default().u64(from).u32(count);
    sbe(template::NOT_APPLIED, &b.0, &[])
}

/// An application payload: an SBE header naming schema 99, so it is not a
/// FIXP session message, then `n`.
fn app(n: u8) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&99u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.push(n);
    out
}

/// A SOFH frame: `Message_Length` (header included) and `Encoding_Type`,
/// both big-endian (SOFH v1.0).
fn sofh(encoding: u16, payload: &[u8]) -> Vec<u8> {
    let len = ok(u32::try_from(payload.len() + 6), "frame length");
    let mut out = Vec::with_capacity(payload.len() + 6);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&encoding.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Root block length and number of variable-length fields of each
/// template of the FIXP schema (id 2748, version 0).
const fn layout(template: u16) -> Option<(usize, usize)> {
    Some(match template {
        template::NEGOTIATE | template::NEGOTIATION_RESPONSE | template::NEGOTIATION_REJECT => {
            (25, 1)
        }
        template::TOPIC => (21, 1),
        template::ESTABLISH => (36, 1),
        template::ESTABLISHMENT_ACK => (36, 0),
        template::ESTABLISHMENT_REJECT | template::RETRANSMIT_REJECT => (25, 1),
        template::SEQUENCE => (8, 0),
        template::CONTEXT | template::FINISHED_SENDING => (24, 0),
        template::UNSEQUENCED_HEARTBEAT => (0, 0),
        template::RETRANSMIT_REQUEST | template::RETRANSMISSION => (36, 0),
        template::TERMINATE => (17, 1),
        template::FINISHED_RECEIVING => (16, 0),
        template::APPLIED | template::NOT_APPLIED => (12, 0),
        template::MESSAGE_TEMPLATE => (12, 2),
        _ => return None,
    })
}

/// Reads one SOFH frame. `Ok(None)` only at end of stream before any byte
/// of a frame; a partial header, a partial body, a `Message_Length` below
/// the 7-byte minimum or above the 1 MiB ceiling, or a FIXP session message
/// that does not match the schema is an error.
async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Frame>, String> {
    let mut header = [0u8; 6];
    let mut got = 0;
    while got < header.len() {
        match reader.read(&mut header[got..]).await {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(format!("stream ended after {got} of 6 SOFH header bytes")),
            Ok(n) => got += n,
            // A reset at a frame boundary is a close.
            Err(_) if got == 0 => return Ok(None),
            Err(error) => return Err(format!("read failed inside a SOFH header: {error}")),
        }
    }
    let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let encoding = u16::from_be_bytes([header[4], header[5]]);
    if !(7..=1024 * 1024).contains(&len) {
        return Err(format!("SOFH Message_Length {len} outside 7..=1 MiB"));
    }
    let body = usize::try_from(len).map_err(|e| e.to_string())? - 6;
    let mut payload = vec![0u8; body];
    if let Err(error) = reader.read_exact(&mut payload).await {
        return Err(format!("stream ended inside a {len}-byte frame: {error}"));
    }
    let frame = Frame { encoding, payload };
    frame.validate()?;
    Ok(Some(frame))
}

/// A frame read from the engine.
#[derive(Debug, Clone)]
struct Frame {
    encoding: u16,
    payload: Vec<u8>,
}

impl Frame {
    fn le16(&self, at: usize) -> u16 {
        u16::from_le_bytes([self.payload[at], self.payload[at + 1]])
    }

    /// `true` when the frame names the FIXP schema: SOFH SBE 1.0
    /// little-endian and an SBE header with schema id 2748.
    fn names_fixp_schema(&self) -> bool {
        self.encoding == SBE_LE && self.payload.len() >= HEADER && self.le16(4) == SCHEMA_ID
    }

    /// Checks a frame naming the FIXP schema against the schema, before any
    /// field is read at a fixed offset: schema version 0, a known template,
    /// a root block at least as long as the schema's (a longer one is a
    /// valid extension), and the variable-length fields the template
    /// declares ending exactly at the end of the SOFH frame.
    fn validate(&self) -> Result<(), String> {
        if !self.names_fixp_schema() {
            return Ok(());
        }
        let block = usize::from(self.le16(0));
        let template = self.le16(2);
        let version = self.le16(6);
        if version != 0 {
            return Err(format!("schema version {version}, expected 0"));
        }
        let Some((root, var_fields)) = layout(template) else {
            return Err(format!("unknown template {template}"));
        };
        if block < root {
            return Err(format!(
                "template {template}: blockLength {block} below the schema's {root}"
            ));
        }
        let mut at = HEADER
            .checked_add(block)
            .ok_or_else(|| "blockLength overflows".to_owned())?;
        if at > self.payload.len() {
            return Err(format!(
                "template {template}: root block of {block} bytes past the frame's {}",
                self.payload.len()
            ));
        }
        for field in 0..var_fields {
            let Some(len) = self.payload.get(at..at + 2) else {
                return Err(format!(
                    "template {template}: var field {field} length missing"
                ));
            };
            let len = usize::from(u16::from_le_bytes([len[0], len[1]]));
            at += 2 + len;
            if at > self.payload.len() {
                return Err(format!(
                    "template {template}: var field {field} past the frame"
                ));
            }
        }
        if at != self.payload.len() {
            return Err(format!(
                "template {template}: message of {at} bytes in a SOFH frame of {} payload bytes",
                self.payload.len()
            ));
        }
        Ok(())
    }

    /// The FIXP template id, if this is a FIXP session message. A frame
    /// naming the FIXP schema that does not match the schema fails the test.
    fn template(&self) -> Option<u16> {
        if !self.names_fixp_schema() {
            return None;
        }
        if let Err(error) = self.validate() {
            panic!("malformed FIXP session message from the engine: {error}: {self:?}");
        }
        Some(self.le16(2))
    }

    fn is_heartbeat(&self) -> bool {
        matches!(
            self.template(),
            Some(template::SEQUENCE | template::UNSEQUENCED_HEARTBEAT)
        )
    }

    /// `width` bytes of the root block at `offset` from its start. The frame
    /// must be a well-formed session message and the field inside the root
    /// block the schema defines for its template.
    fn root(&self, offset: usize, width: usize) -> &[u8] {
        let Some(template) = self.template() else {
            panic!("reading a session field from a non-session frame: {self:?}");
        };
        let Some((root, _)) = layout(template) else {
            panic!("unknown template {template}");
        };
        assert!(
            offset + width <= root,
            "field at {offset}+{width} outside the {root}-byte root block of template {template}"
        );
        &self.payload[HEADER + offset..HEADER + offset + width]
    }
    fn u8(&self, offset: usize) -> u8 {
        self.root(offset, 1)[0]
    }
    fn u32(&self, offset: usize) -> u32 {
        let mut b = [0; 4];
        b.copy_from_slice(self.root(offset, 4));
        u32::from_le_bytes(b)
    }
    fn u64(&self, offset: usize) -> u64 {
        let mut b = [0; 8];
        b.copy_from_slice(self.root(offset, 8));
        u64::from_le_bytes(b)
    }
    fn uuid(&self) -> [u8; 16] {
        let mut b = [0; 16];
        b.copy_from_slice(self.root(0, 16));
        b
    }
    /// The first variable-length field, after the declared root block.
    fn var(&self) -> Vec<u8> {
        assert!(self.template().is_some(), "not a session message");
        let at = HEADER + usize::from(self.le16(0));
        let len = usize::from(u16::from_le_bytes([self.payload[at], self.payload[at + 1]]));
        self.payload[at + 2..at + 2 + len].to_vec()
    }
}

/// The counterparty: raw bytes over a TCP socket.
struct Peer {
    stream: TcpStream,
}

impl Peer {
    async fn connect(addr: SocketAddr) -> Self {
        let stream = ok(
            ok(
                tokio::time::timeout(WAIT, TcpStream::connect(addr)).await,
                "connect in time",
            ),
            "connect",
        );
        ok(stream.set_nodelay(true), "nodelay");
        Self { stream }
    }

    async fn raw(&mut self, bytes: &[u8]) {
        ok(self.stream.write_all(bytes).await, "peer write");
    }

    /// Sends a FIXP session message.
    async fn send(&mut self, message: Vec<u8>) {
        self.raw(&sofh(SBE_LE, &message)).await;
    }

    /// Sends an application message.
    async fn send_app(&mut self, n: u8) {
        self.raw(&sofh(SBE_LE, &app(n))).await;
    }

    /// The next frame, or `None` at end of stream. Fails after [`WAIT`].
    async fn read(&mut self) -> Option<Frame> {
        let read = read_frame(&mut self.stream);
        let result = ok(tokio::time::timeout(WAIT, read).await, "a frame in time");
        match result {
            Ok(frame) => frame,
            Err(error) => panic!("malformed output from the engine: {error}"),
        }
    }

    /// The next frame; the stream must not end.
    async fn recv(&mut self) -> Frame {
        match self.read().await {
            Some(frame) => frame,
            None => panic!("the engine closed the transport"),
        }
    }

    /// The next frame that is not a heartbeat (Sequence or
    /// UnsequencedHeartbeat).
    async fn recv_skipping_heartbeats(&mut self) -> Frame {
        loop {
            let frame = self.recv().await;
            if !frame.is_heartbeat() {
                return frame;
            }
        }
    }

    /// The next frame, which must be the session message `expected`.
    async fn expect(&mut self, expected: u16) -> Frame {
        let frame = self.recv().await;
        assert_eq!(
            frame.template(),
            Some(expected),
            "unexpected frame {frame:?}"
        );
        frame
    }

    /// The next non-heartbeat frame, which must be `expected`.
    async fn expect_skipping_heartbeats(&mut self, expected: u16) -> Frame {
        let frame = self.recv_skipping_heartbeats().await;
        assert_eq!(
            frame.template(),
            Some(expected),
            "unexpected frame {frame:?}"
        );
        frame
    }

    /// Reads up to a NotApplied; returns it with the `NextSeqNo` of the
    /// Sequence right before it, if one was.
    async fn until_not_applied(&mut self) -> (Option<u64>, Frame) {
        let mut previous: Option<Frame> = None;
        loop {
            let frame = self.recv().await;
            if frame.template() == Some(template::NOT_APPLIED) {
                let seq = previous
                    .filter(|p| p.template() == Some(template::SEQUENCE))
                    .map(|p| p.u64(0));
                return (seq, frame);
            }
            previous = Some(frame);
        }
    }

    /// Reads until the engine closes the transport; returns what came first.
    async fn until_closed(&mut self) -> Vec<Frame> {
        let mut frames = Vec::new();
        while let Some(frame) = self.read().await {
            frames.push(frame);
        }
        frames
    }

    /// The engine closes without another session message but heartbeats.
    async fn expect_closed_silently(&mut self) {
        let frames = self.until_closed().await;
        assert!(
            frames.iter().all(Frame::is_heartbeat),
            "expected a close with no session message, got {frames:?}"
        );
    }

    /// The engine sends Terminate with `code`, then closes.
    async fn expect_terminate_then_close(&mut self, id: [u8; 16], code: TerminationCode) {
        let frame = self.expect_skipping_heartbeats(template::TERMINATE).await;
        assert_eq!(frame.uuid(), id, "Terminate names the session");
        assert_eq!(frame.u8(16), code.as_u8(), "Terminate code");
        // Section 4.4 (p. 22): nothing may follow a Terminate.
        let rest = self.until_closed().await;
        assert!(rest.is_empty(), "frames after Terminate: {rest:?}");
    }
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
    fn messages(&self) -> Vec<(Option<u64>, bool, Vec<u8>)> {
        let messages = self.messages.lock().unwrap_or_else(|p| p.into_inner());
        messages
            .iter()
            .map(|m| {
                (
                    m.seq.map(SeqNum::value),
                    m.retransmitted,
                    m.payload.to_vec(),
                )
            })
            .collect()
    }
    fn inbound(&self) -> Vec<FixpInbound> {
        self.messages
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
    fn events(&self) -> Vec<Event> {
        self.events
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
    fn has_event(&self, matches: impl Fn(&Event) -> bool) -> bool {
        self.events().iter().any(matches)
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

/// When the server application answers a handshake request.
#[derive(Clone, Copy, Debug)]
enum Decide {
    /// At once.
    Now,
    /// After a delay.
    After(Duration),
    /// Never: the decision task panics (an application bug).
    Panic,
    /// Never: the decision task never returns.
    Never,
}

impl Decide {
    async fn wait(self) {
        match self {
            Self::Now => {}
            Self::After(delay) => tokio::time::sleep(delay).await,
            Self::Panic => panic!("the application's decision fails (intended by the test)"),
            Self::Never => std::future::pending::<()>().await,
        }
    }
}

/// The engine application: records everything; the server decisions are
/// set per test.
#[derive(Clone)]
struct App {
    rec: Arc<Recorder>,
    server_flow: FlowType,
    negotiation_reject: Option<NegotiationRejectCode>,
    establishment_reject: Option<EstablishmentRejectCode>,
    negotiate_when: Decide,
    establish_when: Decide,
}

impl App {
    fn new() -> Self {
        Self {
            rec: Arc::new(Recorder::default()),
            server_flow: FlowType::Recoverable,
            negotiation_reject: None,
            establishment_reject: None,
            negotiate_when: Decide::Now,
            establish_when: Decide::Now,
        }
    }
    fn with_server_flow(mut self, flow: FlowType) -> Self {
        self.server_flow = flow;
        self
    }
}

#[async_trait]
impl FixpApplication for App {
    async fn on_negotiate(&self, request: &NegotiateRequest) -> NegotiationDecision {
        self.rec
            .negotiations
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(request.clone());
        self.negotiate_when.wait().await;
        match self.negotiation_reject {
            Some(code) => NegotiationDecision::Reject {
                code,
                reason: "refused by the application".to_owned(),
            },
            None => NegotiationDecision::Accept {
                server_flow: self.server_flow,
                credentials: None,
            },
        }
    }

    async fn on_establish(&self, request: &EstablishRequest) -> EstablishmentDecision {
        self.rec
            .establishments
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(request.clone());
        self.establish_when.wait().await;
        match self.establishment_reject {
            Some(code) => EstablishmentDecision::Reject {
                code,
                reason: "refused by the application".to_owned(),
            },
            None => EstablishmentDecision::Accept,
        }
    }

    async fn on_established(&self, connection: FixpConnection) {
        *self
            .rec
            .connection
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(connection);
    }

    async fn on_message(&self, _session_id: SessionId, message: FixpInbound) {
        self.rec
            .messages
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(message);
    }

    async fn on_event(&self, _session_id: Option<SessionId>, event: &Event) {
        self.rec
            .events
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(event.clone());
    }

    async fn on_closed(&self, _session_id: Option<SessionId>) {
        *self.rec.closed.lock().unwrap_or_else(|p| p.into_inner()) += 1;
    }
}

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

fn config() -> FixpConfig {
    FixpConfig::default()
}

/// A configuration with short timers, for the timing cases.
fn fast_config(keepalive_ms: u64) -> FixpConfig {
    ok(
        FixpConfig::builder()
            .keepalive_interval(Duration::from_millis(keepalive_ms))
            .peer_keepalive_range(Duration::from_millis(50), Duration::from_secs(60))
            .peer_silence_grace(Duration::from_millis(100))
            .handshake_timeout(Duration::from_millis(300))
            .build(),
        "config",
    )
}

// ---------------------------------------------------------------------------
// Harness: the engine as the server, the raw peer as the client
// ---------------------------------------------------------------------------

struct Server {
    acceptor: FixpAcceptor<App>,
    addr: SocketAddr,
    app: App,
    _serving: JoinHandle<Result<(), FixpEngineError>>,
}

async fn engine_server_with(app: App, config: FixpConfig) -> Server {
    let listener = ok(TcpListener::bind("127.0.0.1:0").await, "bind");
    let addr = ok(listener.local_addr(), "address");
    let acceptor = FixpAcceptor::new(app.clone(), config);
    let serving = tokio::spawn({
        let acceptor = acceptor.clone();
        async move { acceptor.serve(listener).await }
    });
    Server {
        acceptor,
        addr,
        app,
        _serving: serving,
    }
}

async fn engine_server() -> Server {
    engine_server_with(App::new(), config()).await
}

/// Negotiates `id` with `flow` and checks the NegotiationResponse.
async fn raw_negotiate(peer: &mut Peer, id: [u8; 16], flow: u8, server_flow: FlowType) {
    let ts = 1_000;
    peer.send(negotiate(id, ts, flow, SECRET)).await;
    let response = peer.expect(template::NEGOTIATION_RESPONSE).await;
    // Section 4.2.2 (p. 18): SessionId, RequestTimestamp = Negotiate.Timestamp,
    // ServerFlow.
    assert_eq!(response.uuid(), id);
    assert_eq!(response.u64(16), ts);
    assert_eq!(response.u8(24), server_flow.as_u8());
}

/// Establishes `id`; returns the EstablishmentAck.
async fn raw_establish(
    peer: &mut Peer,
    id: [u8; 16],
    keepalive_ms: u32,
    next: Option<u64>,
) -> Frame {
    let ts = 2_000;
    peer.send(establish(id, ts, keepalive_ms, next)).await;
    let ack = peer.expect(template::ESTABLISHMENT_ACK).await;
    // Section 4.3.2 (p. 20): SessionId, RequestTimestamp =
    // Establish.Timestamp, the server's KeepaliveInterval.
    assert_eq!(ack.uuid(), id);
    assert_eq!(ack.u64(16), ts);
    ack
}

/// A raw client established on the engine server, with the server's
/// connection handle.
async fn established_client(
    server: &Server,
    id: [u8; 16],
    client_flow: u8,
    keepalive_ms: u32,
) -> (Peer, FixpConnection) {
    let mut peer = Peer::connect(server.addr).await;
    raw_negotiate(&mut peer, id, client_flow, server.app.server_flow).await;
    let next = (client_flow == wire::RECOVERABLE || client_flow == wire::IDEMPOTENT).then_some(1);
    raw_establish(&mut peer, id, keepalive_ms, next).await;
    wait_until("the server's connection", || {
        server.app.rec.connection().is_some()
    })
    .await;
    let Some(connection) = server.app.rec.connection() else {
        panic!("no connection");
    };
    (peer, connection)
}

// ---------------------------------------------------------------------------
// Harness: the engine as the client, the raw peer as the server
// ---------------------------------------------------------------------------

struct Client {
    peer: Peer,
    app: App,
    connect: JoinHandle<Result<FixpConnection, FixpEngineError>>,
    id: [u8; 16],
}

async fn engine_client_with(config: FixpConfig, id: [u8; 16], flow: FlowType) -> Client {
    let listener = ok(TcpListener::bind("127.0.0.1:0").await, "bind");
    let addr = ok(listener.local_addr(), "address");
    let app = App::new();
    let initiator = FixpInitiator::new(app.clone(), config, SessionId::from_bytes(id), flow)
        .with_credentials(ok(Credentials::try_new(SECRET.to_vec()), "credentials"));
    let connect = tokio::spawn(initiator.connect(addr));
    let (stream, _) = ok(
        ok(
            tokio::time::timeout(WAIT, listener.accept()).await,
            "accept in time",
        ),
        "accept",
    );
    Client {
        peer: Peer { stream },
        app,
        connect,
        id,
    }
}

impl Client {
    /// Reads the engine's Negotiate; returns its timestamp.
    async fn read_negotiate(&mut self, flow: FlowType) -> u64 {
        let frame = self.peer.expect(template::NEGOTIATE).await;
        // Section 4.2.1 (p. 17-18): SessionId, Timestamp, ClientFlow,
        // Credentials.
        assert_eq!(frame.uuid(), self.id);
        assert_eq!(frame.u8(24), flow.as_u8());
        assert_eq!(frame.var(), SECRET);
        frame.u64(16)
    }

    /// Reads the engine's Establish; returns its timestamp and NextSeqNo.
    async fn read_establish(&mut self) -> (u64, u64) {
        let frame = self.peer.expect(template::ESTABLISH).await;
        assert_eq!(frame.uuid(), self.id);
        (frame.u64(16), frame.u64(28))
    }

    /// Answers the handshake; returns the engine's connection.
    async fn accept(
        &mut self,
        flow: FlowType,
        server_flow: u8,
        keepalive_ms: u32,
        next: Option<u64>,
    ) -> FixpConnection {
        let ts = self.read_negotiate(flow).await;
        self.peer
            .send(negotiation_response(self.id, ts, server_flow))
            .await;
        let (ts, _) = self.read_establish().await;
        self.peer
            .send(establishment_ack(self.id, ts, keepalive_ms, next))
            .await;
        let connect = &mut self.connect;
        let joined = ok(
            tokio::time::timeout(WAIT, connect).await,
            "connect returns in time",
        );
        ok(ok(joined, "connect task"), "connect")
    }

    async fn connect_error(self) -> FixpEngineError {
        let joined = ok(
            tokio::time::timeout(WAIT, self.connect).await,
            "connect returns in time",
        );
        match ok(joined, "connect task") {
            Ok(_) => panic!("the handshake succeeded"),
            Err(error) => error,
        }
    }
}

/// An engine client established against the raw server, with a
/// Recoverable flow both ways and the server's numbering starting at 1.
async fn established_server(
    id: [u8; 16],
    flow: FlowType,
    server_flow: u8,
) -> (Client, FixpConnection) {
    let mut client = engine_client_with(config(), id, flow).await;
    let next = (server_flow == wire::RECOVERABLE || server_flow == wire::IDEMPOTENT).then_some(1);
    let connection = client.accept(flow, server_flow, 5_000, next).await;
    (client, connection)
}

async fn wait_closed(connection: &FixpConnection) {
    ok(
        tokio::time::timeout(WAIT, connection.wait_closed()).await,
        "the engine closed in time",
    );
}

// ===========================================================================
// SOFH framing and untrusted input
// ===========================================================================

/// FIXP 3.3.3 (p. 12), 4.4 (p. 22): "a transport should be terminated if an
/// unrecoverable error occurs in message parsing or framing". A SOFH
/// `Message_Length` above the engine's ceiling has no resynchronisation
/// point, so the transport is closed without another message. Server role,
/// before any handshake.
#[tokio::test]
async fn test_server_closes_on_an_oversized_sofh_length() {
    let server = engine_server().await;
    let mut peer = Peer::connect(server.addr).await;
    let mut header = Vec::new();
    header.extend_from_slice(&u32::MAX.to_be_bytes());
    header.extend_from_slice(&SBE_LE.to_be_bytes());
    peer.raw(&header).await;
    peer.expect_closed_silently().await;
    assert!(
        server
            .app
            .rec
            .negotiations
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty()
    );
}

/// FIXP 3.3.3 (p. 12), 4.4 (p. 22): the same once established, client role.
/// The engine closes the transport and reports the closed connection.
#[tokio::test]
async fn test_client_closes_on_an_oversized_sofh_length_when_established() {
    let (mut client, connection) =
        established_server(session_id(0x02), FlowType::Recoverable, wire::RECOVERABLE).await;
    let mut header = Vec::new();
    header.extend_from_slice(&(2 * 1024 * 1024u32).to_be_bytes());
    header.extend_from_slice(&SBE_LE.to_be_bytes());
    client.peer.raw(&header).await;
    client.peer.expect_closed_silently().await;
    wait_closed(&connection).await;
    wait_until("on_closed", || client.app.rec.closed() == 1).await;
}

/// FIXP 3.3.3 (p. 12), 4.4 (p. 22): a `Message_Length` below the 7-byte
/// minimum (it cannot even cover its header) is a framing error too.
#[tokio::test]
async fn test_server_closes_on_a_sofh_length_below_the_header() {
    let server = engine_server().await;
    let mut peer = Peer::connect(server.addr).await;
    peer.raw(&[0, 0, 0, 3, 0xEB, 0x50]).await;
    peer.expect_closed_silently().await;
}

/// FIXP 3.3.3 (p. 12): the framing header "identifies the encoding of the
/// message that follows"; FIXP allows application messages in another
/// encoding than session messages (3.3, p. 12). A frame with an encoding
/// type SOFH v1.0 does not register is therefore an application message,
/// numbered and handed to the application with its raw encoding type.
/// **Local policy**: routing on encoding type plus SBE schema id is the
/// engine's; FIXP leaves it to the encoding supplements.
#[tokio::test]
async fn test_server_delivers_an_unknown_encoding_type_as_an_application_message() {
    let server = engine_server().await;
    let id = session_id(0x04);
    let (mut peer, _connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    peer.send(sequence(1)).await;
    peer.raw(&sofh(0x1234, b"opaque")).await;
    wait_until("the message", || server.app.rec.inbound().len() == 1).await;
    let inbound = server.app.rec.inbound();
    assert_eq!(inbound[0].seq.map(SeqNum::value), Some(1));
    assert_eq!(inbound[0].encoding_type, EncodingType::from_u16(0x1234));
    assert_eq!(inbound[0].payload.as_ref(), b"opaque");
}

/// FIXP 6.3 (p. 39): "Sending an application message on a point-to-point
/// session that is not in established state" is a violation. A frame of an
/// unknown encoding type is an application message, so before the
/// handshake the engine closes the transport (no session to terminate).
#[tokio::test]
async fn test_server_refuses_an_unknown_encoding_type_before_establishment() {
    let server = engine_server().await;
    let mut peer = Peer::connect(server.addr).await;
    peer.raw(&sofh(0x1234, b"opaque")).await;
    peer.expect_closed_silently().await;
    assert!(server.app.rec.inbound().is_empty());
}

/// FIXP 4.4 (p. 22), 6.3 (p. 39): a truncated SBE session message (schema
/// 2748, a block shorter than the schema's) once established is a protocol
/// violation: Terminate `UnspecifiedError`, then the transport closes.
#[tokio::test]
async fn test_server_terminates_on_a_truncated_session_message() {
    let server = engine_server().await;
    let id = session_id(0x06);
    let (mut peer, connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    let mut truncated = retransmit_request(id, 9, 1, 1);
    truncated.truncate(HEADER + 10);
    peer.send(truncated).await;
    peer.expect_terminate_then_close(id, TerminationCode::UnspecifiedError)
        .await;
    wait_closed(&connection).await;
}

/// FIXP 4.4 (p. 22): a truncated Negotiate, before any session exists,
/// closes the transport with no answer.
#[tokio::test]
async fn test_server_closes_on_a_truncated_negotiate() {
    let server = engine_server().await;
    let mut peer = Peer::connect(server.addr).await;
    let mut truncated = negotiate(session_id(0x07), 1, wire::RECOVERABLE, b"");
    truncated.truncate(HEADER + 20);
    peer.send(truncated).await;
    peer.expect_closed_silently().await;
}

/// FIXP 4.4 (p. 22): a truncated NegotiationResponse ends the client's
/// handshake with a decode error and closes the transport.
#[tokio::test]
async fn test_client_closes_on_a_truncated_negotiation_response() {
    let id = session_id(0x08);
    let mut client = engine_client_with(config(), id, FlowType::Recoverable).await;
    let ts = client.read_negotiate(FlowType::Recoverable).await;
    let mut truncated = negotiation_response(id, ts, wire::RECOVERABLE);
    truncated.truncate(HEADER + 12);
    client.peer.send(truncated).await;
    client.peer.expect_closed_silently().await;
    let error = client.connect_error().await;
    assert!(matches!(error, FixpEngineError::Decode(_)), "{error:?}");
}

/// FIXP 3.3.1 (p. 12), 6.3 (p. 39): a schema-2748 frame naming a template
/// the schema does not define is a malformed session message: Terminate
/// `UnspecifiedError` once established. Client role.
#[tokio::test]
async fn test_client_terminates_on_an_unknown_session_template() {
    let id = session_id(0x09);
    let (mut client, _connection) =
        established_server(id, FlowType::Recoverable, wire::RECOVERABLE).await;
    client.peer.send(sbe(99, &[0; 8], &[])).await;
    client
        .peer
        .expect_terminate_then_close(id, TerminationCode::UnspecifiedError)
        .await;
}

// ===========================================================================
// Negotiation (section 4.2) and establishment (section 4.3)
// ===========================================================================

/// FIXP 4.2.1 (p. 17-18), 4.3.1 (p. 20): the engine client's Negotiate
/// carries its session id, a timestamp, its flow and its credentials; its
/// Establish the same id, a fresh timestamp, its keepalive interval and,
/// on a sequenced flow, `NextSeqNo`. After the EstablishmentAck the
/// application messages flow (4.1, p. 17).
#[tokio::test]
async fn test_client_handshake_fields() {
    let id = session_id(0x10);
    let mut client = engine_client_with(config(), id, FlowType::Recoverable).await;
    let ts = client.read_negotiate(FlowType::Recoverable).await;
    assert_ne!(ts, 0, "Timestamp is the time of the request");
    client
        .peer
        .send(negotiation_response(id, ts, wire::RECOVERABLE))
        .await;
    let establish = client.peer.expect(template::ESTABLISH).await;
    assert_eq!(establish.uuid(), id);
    assert_eq!(
        u64::from(establish.u32(24)),
        5_000,
        "KeepaliveInterval in ms"
    );
    assert_eq!(establish.u64(28), 1, "NextSeqNo of the client flow");
    assert_eq!(establish.var(), SECRET, "Credentials");
    client
        .peer
        .send(establishment_ack(id, establish.u64(16), 5_000, Some(1)))
        .await;
    let joined = ok(tokio::time::timeout(WAIT, client.connect).await, "in time");
    let connection = ok(ok(joined, "task"), "connect");
    assert_eq!(
        connection
            .send(app(1))
            .await
            .ok()
            .flatten()
            .map(SeqNum::value),
        Some(1)
    );
    let seq = client.peer.expect(template::SEQUENCE).await;
    assert_eq!(seq.u64(0), 1, "3.5.1 (p. 14): a Sequence starts the flow");
    let message = client.peer.recv().await;
    assert_eq!(message.payload, app(1));
}

/// FIXP 4.2.2 (p. 18), 4.3.2 (p. 20-21): the engine server answers
/// Negotiate with NegotiationResponse (timestamp echoed, its flow) and
/// Establish with EstablishmentAck (timestamp echoed, its keepalive, and on
/// its Recoverable flow `NextSeqNo`); the application saw the credentials.
#[tokio::test]
async fn test_server_handshake_fields() {
    let server = engine_server().await;
    let id = session_id(0x11);
    let mut peer = Peer::connect(server.addr).await;
    raw_negotiate(&mut peer, id, wire::RECOVERABLE, FlowType::Recoverable).await;
    let ack = raw_establish(&mut peer, id, 5_000, Some(1)).await;
    assert_eq!(ack.u32(24), 5_000, "the server's KeepaliveInterval");
    assert_eq!(ack.u64(28), 1, "NextSeqNo of the server's Recoverable flow");
    let negotiations = server
        .app
        .rec
        .negotiations
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    assert_eq!(negotiations.len(), 1);
    assert_eq!(negotiations[0].client_flow, FlowType::Recoverable);
    assert_eq!(
        negotiations[0]
            .credentials
            .as_ref()
            .map(Credentials::expose),
        Some(SECRET)
    );
    let establishments = server
        .app
        .rec
        .establishments
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    assert_eq!(
        establishments[0].keepalive_interval,
        Duration::from_millis(5_000)
    );
    assert_eq!(establishments[0].next_seq_no.map(SeqNum::value), Some(1));
}

/// FIXP 4.2.3 (p. 18-19): each NegotiationRejectCode the server sends ends
/// the engine client's handshake with that code; the transport closes.
#[tokio::test]
async fn test_client_reports_every_negotiation_reject_code() {
    for (seed, code) in [
        (0x20, NegotiationRejectCode::Credentials),
        (0x21, NegotiationRejectCode::FlowTypeNotSupported),
        (0x22, NegotiationRejectCode::DuplicateId),
        (0x23, NegotiationRejectCode::Unspecified),
    ] {
        let id = session_id(seed);
        let mut client = engine_client_with(config(), id, FlowType::Recoverable).await;
        let ts = client.read_negotiate(FlowType::Recoverable).await;
        client
            .peer
            .send(negotiation_reject(id, ts, code.as_u8()))
            .await;
        client.peer.expect_closed_silently().await;
        match client.connect_error().await {
            FixpEngineError::NegotiationRejected { code: got, reason } => {
                assert_eq!(got, code);
                assert_eq!(reason, "refused");
            }
            other => panic!("{code:?}: {other:?}"),
        }
    }
}

/// FIXP 4.2.3 (p. 18-19): the engine server sends NegotiationReject with
/// the application's code and the request timestamp, then "the transport
/// should be terminated".
#[tokio::test]
async fn test_server_sends_every_negotiation_reject_code() {
    for (seed, code) in [
        (0x24, NegotiationRejectCode::Credentials),
        (0x25, NegotiationRejectCode::FlowTypeNotSupported),
        (0x26, NegotiationRejectCode::DuplicateId),
        (0x27, NegotiationRejectCode::Unspecified),
    ] {
        let mut app = App::new();
        app.negotiation_reject = Some(code);
        let server = engine_server_with(app, config()).await;
        let id = session_id(seed);
        let mut peer = Peer::connect(server.addr).await;
        peer.send(negotiate(id, 77, wire::RECOVERABLE, SECRET))
            .await;
        let reject = peer.expect(template::NEGOTIATION_REJECT).await;
        assert_eq!(reject.uuid(), id);
        assert_eq!(reject.u64(16), 77, "RequestTimestamp");
        assert_eq!(reject.u8(24), code.as_u8(), "Code");
        peer.expect_closed_silently().await;
    }
}

/// FIXP 3.4.1 (p. 13), 4.2.3 (p. 18): a session id live on another
/// transport is "non-unique": NegotiationReject `DuplicateId`.
#[tokio::test]
async fn test_server_rejects_a_live_session_id_with_duplicate_id() {
    let server = engine_server().await;
    let id = session_id(0x28);
    let (_first, _connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    let mut second = Peer::connect(server.addr).await;
    second
        .send(negotiate(id, 5, wire::RECOVERABLE, SECRET))
        .await;
    let reject = second.expect(template::NEGOTIATION_REJECT).await;
    assert_eq!(reject.u8(24), NegotiationRejectCode::DuplicateId.as_u8());
    second.expect_closed_silently().await;
}

/// FIXP 4.3.3 (p. 21): each EstablishmentRejectCode the server sends ends
/// the engine client's handshake with that code.
#[tokio::test]
async fn test_client_reports_every_establishment_reject_code() {
    for (seed, code) in [
        (0x30, EstablishmentRejectCode::Unnegotiated),
        (0x31, EstablishmentRejectCode::AlreadyEstablished),
        (0x32, EstablishmentRejectCode::SessionBlocked),
        (0x33, EstablishmentRejectCode::KeepaliveInterval),
        (0x34, EstablishmentRejectCode::Credentials),
        (0x35, EstablishmentRejectCode::Unspecified),
    ] {
        let id = session_id(seed);
        let mut client = engine_client_with(config(), id, FlowType::Recoverable).await;
        let ts = client.read_negotiate(FlowType::Recoverable).await;
        client
            .peer
            .send(negotiation_response(id, ts, wire::RECOVERABLE))
            .await;
        let (ts, _) = client.read_establish().await;
        client
            .peer
            .send(establishment_reject(id, ts, code.as_u8()))
            .await;
        client.peer.expect_closed_silently().await;
        match client.connect_error().await {
            FixpEngineError::EstablishmentRejected { code: got, .. } => assert_eq!(got, code),
            other => panic!("{code:?}: {other:?}"),
        }
    }
}

/// FIXP 4.3.3 (p. 21): `SessionBlocked` and `Credentials` are the
/// application's decisions; the engine server sends them with the request
/// timestamp.
#[tokio::test]
async fn test_server_sends_application_establishment_reject_codes() {
    for (seed, code) in [
        (0x36, EstablishmentRejectCode::SessionBlocked),
        (0x37, EstablishmentRejectCode::Credentials),
    ] {
        let mut app = App::new();
        app.establishment_reject = Some(code);
        let server = engine_server_with(app, config()).await;
        let id = session_id(seed);
        let mut peer = Peer::connect(server.addr).await;
        raw_negotiate(&mut peer, id, wire::RECOVERABLE, FlowType::Recoverable).await;
        peer.send(establish(id, 33, 5_000, Some(1))).await;
        let reject = peer.expect(template::ESTABLISHMENT_REJECT).await;
        assert_eq!(reject.uuid(), id);
        assert_eq!(reject.u64(16), 33, "RequestTimestamp");
        assert_eq!(reject.u8(24), code.as_u8());
    }
}

/// FIXP 4.3.3 (p. 21), 6.3 (p. 39): an Establish "not preceded by a
/// Negotiation" is refused with `Unnegotiated`; 6.3 lists it as a protocol
/// violation after which the session "should be immediately terminated",
/// so the transport closes at once, not at the handshake timeout (10 s by
/// default here, twice the suite's bound).
#[tokio::test]
async fn test_server_rejects_an_establish_without_negotiation() {
    let server = engine_server().await;
    let id = session_id(0x38);
    let mut peer = Peer::connect(server.addr).await;
    peer.send(establish(id, 44, 5_000, Some(1))).await;
    let reject = peer.expect(template::ESTABLISHMENT_REJECT).await;
    assert_eq!(reject.u8(24), EstablishmentRejectCode::Unnegotiated.as_u8());
    assert_eq!(reject.u64(16), 44);
    peer.expect_closed_silently().await;
}

/// FIXP 6.3 (p. 39): an Establish for a session other than the one
/// negotiated on this transport was not negotiated: `Unnegotiated`, then
/// the transport closes at once.
#[tokio::test]
async fn test_server_rejects_an_establish_for_another_session_and_closes() {
    let server = engine_server().await;
    let id = session_id(0x3F);
    let mut peer = Peer::connect(server.addr).await;
    raw_negotiate(&mut peer, id, wire::RECOVERABLE, FlowType::Recoverable).await;
    peer.send(establish(session_id(0x4F), 45, 5_000, Some(1)))
        .await;
    let reject = peer.expect(template::ESTABLISHMENT_REJECT).await;
    assert_eq!(reject.u8(24), EstablishmentRejectCode::Unnegotiated.as_u8());
    peer.expect_closed_silently().await;
}

/// FIXP 4.3.3 (p. 21): "EstablishmentAck was already sent; Establish was
/// redundant": `AlreadyEstablished`.
#[tokio::test]
async fn test_server_rejects_a_redundant_establish() {
    let server = engine_server().await;
    let id = session_id(0x39);
    let (mut peer, _connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    peer.send(establish(id, 45, 5_000, Some(1))).await;
    let reject = peer
        .expect_skipping_heartbeats(template::ESTABLISHMENT_REJECT)
        .await;
    assert_eq!(
        reject.u8(24),
        EstablishmentRejectCode::AlreadyEstablished.as_u8()
    );
}

/// FIXP 4.3.1 (p. 20), 4.3.3 (p. 21): "Counterparties may agree on a valid
/// range for KeepaliveInterval"; outside it, `KeepaliveInterval`. The range
/// is configuration (**local policy** for its bounds).
#[tokio::test]
async fn test_server_rejects_a_keepalive_out_of_range() {
    let server = engine_server().await;
    let id = session_id(0x3A);
    let mut peer = Peer::connect(server.addr).await;
    raw_negotiate(&mut peer, id, wire::RECOVERABLE, FlowType::Recoverable).await;
    // The default range starts at 100 ms.
    peer.send(establish(id, 46, 10, Some(1))).await;
    let reject = peer.expect(template::ESTABLISHMENT_REJECT).await;
    assert_eq!(
        reject.u8(24),
        EstablishmentRejectCode::KeepaliveInterval.as_u8()
    );
}

/// FIXP 4.3.3 (p. 21) "Unspecified: any other reason": a `NextSeqNo` of
/// zero on a sequenced client flow. **Local policy**: the code for this
/// case is the engine's choice.
#[tokio::test]
async fn test_server_rejects_a_next_seq_no_of_zero_with_unspecified() {
    let server = engine_server().await;
    let id = session_id(0x3B);
    let mut peer = Peer::connect(server.addr).await;
    raw_negotiate(&mut peer, id, wire::RECOVERABLE, FlowType::Recoverable).await;
    peer.send(establish(id, 47, 5_000, Some(0))).await;
    let reject = peer.expect(template::ESTABLISHMENT_REJECT).await;
    assert_eq!(reject.u8(24), EstablishmentRejectCode::Unspecified.as_u8());
}

/// FIXP 4.3.1 (p. 20): "There is no specific timeout value"; the engine
/// bounds every handshake step (**local policy**, `handshake_timeout`). A
/// server that never answers Negotiate ends the client's handshake.
#[tokio::test]
async fn test_client_negotiation_times_out() {
    let id = session_id(0x3C);
    let mut client = engine_client_with(fast_config(1_000), id, FlowType::Recoverable).await;
    let _ = client.read_negotiate(FlowType::Recoverable).await;
    client.peer.expect_closed_silently().await;
    let error = client.connect_error().await;
    assert!(
        matches!(
            error,
            FixpEngineError::HandshakeTimedOut {
                stage: HandshakeStage::Negotiation
            }
        ),
        "{error:?}"
    );
}

/// FIXP 4.3.1 (p. 20), **local policy**: the same for an Establish that is
/// never answered.
#[tokio::test]
async fn test_client_establishment_times_out() {
    let id = session_id(0x3D);
    let mut client = engine_client_with(fast_config(1_000), id, FlowType::Recoverable).await;
    let ts = client.read_negotiate(FlowType::Recoverable).await;
    client
        .peer
        .send(negotiation_response(id, ts, wire::RECOVERABLE))
        .await;
    let _ = client.read_establish().await;
    client.peer.expect_closed_silently().await;
    let error = client.connect_error().await;
    assert!(
        matches!(
            error,
            FixpEngineError::HandshakeTimedOut {
                stage: HandshakeStage::Establishment
            }
        ),
        "{error:?}"
    );
}

/// **Local policy** (FIXP 4.3.1, p. 20, sets no timeout): a server
/// transport on which no Negotiate arrives is closed after the handshake
/// timeout.
#[tokio::test]
async fn test_server_closes_a_silent_transport_after_the_handshake_timeout() {
    let server = engine_server_with(App::new(), fast_config(1_000)).await;
    let mut peer = Peer::connect(server.addr).await;
    peer.expect_closed_silently().await;
}

/// FIXP Appendix A 7.1.7.5 (p. 43, informative): a NegotiationResponse
/// whose RequestTimestamp matches no request is ignored; the handshake then
/// times out (**local policy**).
#[tokio::test]
async fn test_client_ignores_a_negotiation_response_for_another_request() {
    let id = session_id(0x3E);
    let mut client = engine_client_with(fast_config(1_000), id, FlowType::Recoverable).await;
    let ts = client.read_negotiate(FlowType::Recoverable).await;
    client
        .peer
        .send(negotiation_response(id, ts ^ 1, wire::RECOVERABLE))
        .await;
    client.peer.expect_closed_silently().await;
    let error = client.connect_error().await;
    assert!(
        matches!(error, FixpEngineError::HandshakeTimedOut { .. }),
        "{error:?}"
    );
}

/// FIXP 3.4.4.1 (p. 14): "Only one of the flows may be None". A
/// NegotiationResponse naming None for the server while the client's flow
/// is None is refused (the engine client cannot be established).
#[tokio::test]
async fn test_client_refuses_both_flows_none() {
    let id = session_id(0x3F);
    let mut client = engine_client_with(fast_config(1_000), id, FlowType::None).await;
    let ts = client.read_negotiate(FlowType::None).await;
    client
        .peer
        .send(negotiation_response(id, ts, wire::NONE))
        .await;
    client.peer.expect_closed_silently().await;
    let _ = client.connect_error().await;
}

/// FIXP 6.3 (p. 39): an application message before EstablishmentAck is a
/// violation; with no session established the engine server closes.
#[tokio::test]
async fn test_server_refuses_an_application_message_before_establishment() {
    let server = engine_server().await;
    let id = session_id(0x40);
    let mut peer = Peer::connect(server.addr).await;
    raw_negotiate(&mut peer, id, wire::RECOVERABLE, FlowType::Recoverable).await;
    peer.send_app(1).await;
    peer.expect_closed_silently().await;
    assert!(server.app.rec.inbound().is_empty());
}

/// FIXP 3.4.4.1 (p. 14), 4.3.2 (p. 20): the server's first `NextSeqNo`
/// sets where its numbering starts; the engine client numbers from it.
#[tokio::test]
async fn test_client_numbers_from_the_announced_next_seq_no() {
    let id = session_id(0x41);
    let mut client = engine_client_with(config(), id, FlowType::Recoverable).await;
    let _connection = client
        .accept(FlowType::Recoverable, wire::RECOVERABLE, 5_000, Some(100))
        .await;
    client.peer.send(sequence(100)).await;
    client.peer.send_app(1).await;
    client.peer.send_app(2).await;
    wait_until("two messages", || client.app.rec.inbound().len() == 2).await;
    let got: Vec<_> = client.app.rec.messages().into_iter().map(|m| m.0).collect();
    assert_eq!(got, vec![Some(100), Some(101)]);
}

/// **Local policy** (FIXP 4.3.1, p. 20: a range "may" be agreed): an
/// EstablishmentAck keepalive outside the configured range terminates.
#[tokio::test]
async fn test_client_terminates_on_a_server_keepalive_out_of_range() {
    let id = session_id(0x42);
    let mut client = engine_client_with(config(), id, FlowType::Recoverable).await;
    let ts = client.read_negotiate(FlowType::Recoverable).await;
    client
        .peer
        .send(negotiation_response(id, ts, wire::RECOVERABLE))
        .await;
    let (ts, _) = client.read_establish().await;
    client
        .peer
        .send(establishment_ack(id, ts, 10, Some(1)))
        .await;
    client
        .peer
        .expect_terminate_then_close(id, TerminationCode::UnspecifiedError)
        .await;
}

// ===========================================================================
// Sequencing (section 3.5) and flows (sections 3.4.4, 4.6, 4.8)
// ===========================================================================

/// FIXP 3.5.1 (p. 14): messages after a Sequence are numbered implicitly
/// from its `NextSeqNo`. Server role, Recoverable client flow.
#[tokio::test]
async fn test_server_numbers_messages_after_a_sequence() {
    let server = engine_server().await;
    let id = session_id(0x50);
    let (mut peer, _connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    peer.send(sequence(1)).await;
    for n in 1..=3 {
        peer.send_app(n).await;
    }
    wait_until("three messages", || server.app.rec.inbound().len() == 3).await;
    assert_eq!(
        server.app.rec.messages(),
        (1..=3)
            .map(|n| (Some(u64::from(n)), false, app(n)))
            .collect::<Vec<_>>()
    );
}

/// FIXP 4.6.1 (p. 26), 4.6.2 (p. 26-27): a gap on the counterparty's
/// Recoverable flow is requested with RetransmitRequest (session id,
/// timestamp, FromSeqNo, Count); messages after the gap are accepted; the
/// Retransmission batch (timestamp echoed) is delivered as retransmitted.
/// Server role.
#[tokio::test]
async fn test_server_requests_and_receives_a_retransmission() {
    let server = engine_server().await;
    let id = session_id(0x51);
    let (mut peer, _connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    peer.send(sequence(1)).await;
    peer.send_app(1).await;
    peer.send(sequence(4)).await;
    peer.send_app(4).await;
    let request = peer
        .expect_skipping_heartbeats(template::RETRANSMIT_REQUEST)
        .await;
    assert_eq!(request.uuid(), id);
    assert_eq!(request.u64(24), 2, "FromSeqNo");
    assert_eq!(request.u32(32), 2, "Count");
    let ts = request.u64(16);
    peer.send(retransmission(id, ts, 2, 2)).await;
    peer.send_app(2).await;
    peer.send_app(3).await;
    // 3.5.4 (p. 15): real-time messages resume behind a Sequence.
    peer.send(sequence(5)).await;
    peer.send_app(5).await;
    wait_until("five messages", || server.app.rec.inbound().len() == 5).await;
    assert_eq!(
        server.app.rec.messages(),
        vec![
            (Some(1), false, app(1)),
            (Some(4), false, app(4)),
            (Some(2), true, app(2)),
            (Some(3), true, app(3)),
            (Some(5), false, app(5)),
        ]
    );
    assert!(
        server
            .app
            .rec
            .has_event(|e| matches!(e, Event::RecoveryComplete))
    );
}

/// FIXP 4.6.1 (p. 26), 4.3.2 (p. 20-21): the same in the client role, with
/// the gap revealed by a Sequence.
#[tokio::test]
async fn test_client_requests_and_receives_a_retransmission() {
    let id = session_id(0x52);
    let (mut client, _connection) =
        established_server(id, FlowType::Recoverable, wire::RECOVERABLE).await;
    client.peer.send(sequence(3)).await;
    let request = client
        .peer
        .expect_skipping_heartbeats(template::RETRANSMIT_REQUEST)
        .await;
    assert_eq!((request.u64(24), request.u32(32)), (1, 2));
    client
        .peer
        .send(retransmission(id, request.u64(16), 1, 2))
        .await;
    client.peer.send_app(1).await;
    client.peer.send_app(2).await;
    wait_until("two messages", || client.app.rec.inbound().len() == 2).await;
    assert_eq!(
        client.app.rec.messages(),
        vec![(Some(1), true, app(1)), (Some(2), true, app(2))]
    );
    assert!(
        client
            .app
            .rec
            .has_event(|e| matches!(e, Event::RecoveryComplete))
    );
}

/// FIXP 4.6.2.3 (p. 28): each RetransmitRejectCode received abandons the
/// requested range and is reported with its code. Server role.
#[tokio::test]
async fn test_server_reports_every_retransmit_reject_code() {
    for (seed, code) in [
        (0x53, RetransmitRejectCode::OutOfRange),
        (0x54, RetransmitRejectCode::InvalidSession),
        (0x55, RetransmitRejectCode::RequestLimitExceeded),
    ] {
        let server = engine_server().await;
        let id = session_id(seed);
        let (mut peer, _connection) =
            established_client(&server, id, wire::RECOVERABLE, 5_000).await;
        peer.send(sequence(3)).await;
        let request = peer
            .expect_skipping_heartbeats(template::RETRANSMIT_REQUEST)
            .await;
        peer.send(retransmit_reject(id, request.u64(16), code.as_u8()))
            .await;
        wait_until("the reject reported", || {
            server.app.rec.has_event(|e| {
                matches!(e, Event::RetransmitRejected { code: got, count: 2, .. } if *got == code)
            })
        })
        .await;
    }
}

/// FIXP 4.6.2.3 (p. 28): the same, client role.
#[tokio::test]
async fn test_client_reports_a_retransmit_reject() {
    let id = session_id(0x56);
    let (mut client, _connection) =
        established_server(id, FlowType::Recoverable, wire::RECOVERABLE).await;
    client.peer.send(sequence(2)).await;
    let request = client
        .peer
        .expect_skipping_heartbeats(template::RETRANSMIT_REQUEST)
        .await;
    client
        .peer
        .send(retransmit_reject(
            id,
            request.u64(16),
            RetransmitRejectCode::OutOfRange.as_u8(),
        ))
        .await;
    wait_until("the reject reported", || {
        client.app.rec.has_event(|e| {
            matches!(
                e,
                Event::RetransmitRejected {
                    code: RetransmitRejectCode::OutOfRange,
                    ..
                }
            )
        })
    })
    .await;
}

/// Sends three messages from the engine and reads them at the peer.
async fn engine_sends_three(connection: &FixpConnection, peer: &mut Peer) -> Vec<Frame> {
    for n in 1..=3 {
        let seq = ok(connection.send(app(n)).await, "send");
        assert_eq!(seq.map(SeqNum::value), Some(u64::from(n)));
    }
    let seq = peer.expect(template::SEQUENCE).await;
    assert_eq!(seq.u64(0), 1);
    let mut frames = Vec::new();
    for _ in 0..3 {
        frames.push(peer.recv().await);
    }
    frames
}

/// FIXP 4.6.2 (p. 26-27): as the provider, the engine answers a valid
/// RetransmitRequest with Retransmission (session id, RequestTimestamp
/// echoed, NextSeqNo, Count) followed by the same messages, then resumes
/// real time behind a Sequence (3.5.4, p. 15). Server role.
#[tokio::test]
async fn test_server_serves_a_retransmission() {
    let server = engine_server().await;
    let id = session_id(0x57);
    let (mut peer, connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    let sent = engine_sends_three(&connection, &mut peer).await;
    peer.send(retransmit_request(id, 4242, 2, 2)).await;
    let header = peer
        .expect_skipping_heartbeats(template::RETRANSMISSION)
        .await;
    assert_eq!(header.uuid(), id);
    assert_eq!(header.u64(16), 4242, "RequestTimestamp");
    assert_eq!(header.u64(24), 2, "NextSeqNo");
    assert_eq!(header.u32(32), 2, "Count");
    assert_eq!(peer.recv().await.payload, sent[1].payload);
    assert_eq!(peer.recv().await.payload, sent[2].payload);
    assert_eq!(
        ok(connection.send(app(4)).await, "send").map(SeqNum::value),
        Some(4)
    );
    let resume = peer.expect(template::SEQUENCE).await;
    assert_eq!(resume.u64(0), 4);
    assert_eq!(peer.recv().await.payload, app(4));
}

/// FIXP 4.6.2 (p. 26-27): the same, client role.
#[tokio::test]
async fn test_client_serves_a_retransmission() {
    let id = session_id(0x58);
    let (mut client, connection) =
        established_server(id, FlowType::Recoverable, wire::RECOVERABLE).await;
    let sent = engine_sends_three(&connection, &mut client.peer).await;
    client.peer.send(retransmit_request(id, 99, 1, 3)).await;
    let header = client
        .peer
        .expect_skipping_heartbeats(template::RETRANSMISSION)
        .await;
    assert_eq!((header.u64(16), header.u64(24), header.u32(32)), (99, 1, 3));
    for frame in &sent {
        assert_eq!(client.peer.recv().await.payload, frame.payload);
    }
}

/// FIXP 4.6.2.3 (p. 28): the engine provider's automatic RetransmitReject
/// codes: `InvalidSession` (another session id), `RequestLimitExceeded`
/// (Count above the local maximum), `OutOfRange` (numbers not yet sent;
/// 4.6.2.3 names the code, 6.3 (p. 39) also calls it a violation; the
/// engine rejects rather than terminates, see the decisions table).
#[tokio::test]
async fn test_server_sends_every_retransmit_reject_code() {
    let config = ok(
        FixpConfig::builder()
            .max_retransmit_count(ok(NonZeroU32::new(2).ok_or("zero"), "two"))
            .build(),
        "config",
    );
    let server = engine_server_with(App::new(), config).await;
    let id = session_id(0x59);
    let (mut peer, connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    let _ = engine_sends_three(&connection, &mut peer).await;
    for (ts, request_id, from, count, code) in [
        (
            1,
            session_id(0x5A),
            1,
            1,
            RetransmitRejectCode::InvalidSession,
        ),
        (2, id, 1, 3, RetransmitRejectCode::RequestLimitExceeded),
        (3, id, 3, 2, RetransmitRejectCode::OutOfRange),
        (4, id, 0, 1, RetransmitRejectCode::OutOfRange),
    ] {
        peer.send(retransmit_request(request_id, ts, from, count))
            .await;
        let reject = peer
            .expect_skipping_heartbeats(template::RETRANSMIT_REJECT)
            .await;
        assert_eq!(reject.u64(16), ts, "RequestTimestamp");
        assert_eq!(reject.u8(24), code.as_u8(), "request {ts}");
    }
}

/// **Local policy** (FIXP 4.6.2.3, p. 28, names `OutOfRange` for numbers
/// "beyond the range"): a request for messages the engine no longer keeps
/// is refused with `OutOfRange`. Client role.
#[tokio::test]
async fn test_client_rejects_a_request_for_messages_no_longer_kept() {
    let id = session_id(0x5B);
    let listener = ok(TcpListener::bind("127.0.0.1:0").await, "bind");
    let addr = ok(listener.local_addr(), "address");
    let app_ = App::new();
    let initiator = FixpInitiator::new(
        app_.clone(),
        config(),
        SessionId::from_bytes(id),
        FlowType::Recoverable,
    )
    .with_credentials(ok(Credentials::try_new(SECRET.to_vec()), "credentials"))
    .with_retransmit_capacity(1);
    let connect = tokio::spawn(initiator.connect(addr));
    let (stream, _) = ok(listener.accept().await, "accept");
    let mut client = Client {
        peer: Peer { stream },
        app: app_,
        connect,
        id,
    };
    let connection = client
        .accept(FlowType::Recoverable, wire::RECOVERABLE, 5_000, Some(1))
        .await;
    let _ = engine_sends_three(&connection, &mut client.peer).await;
    client.peer.send(retransmit_request(id, 5, 1, 1)).await;
    let reject = client
        .peer
        .expect_skipping_heartbeats(template::RETRANSMIT_REJECT)
        .await;
    assert_eq!(reject.u8(24), RetransmitRejectCode::OutOfRange.as_u8());
}

/// FIXP 4.6.1 (p. 26): "Sending a RetransmitRequest to the sender of an
/// Idempotent, Unsequenced or None flow is a protocol violation. In that
/// case, the session must be terminated."
#[tokio::test]
async fn test_server_terminates_on_a_retransmit_request_to_a_flow_that_is_not_recoverable() {
    for (seed, flow) in [
        (0x5C, FlowType::Idempotent),
        (0x5D, FlowType::Unsequenced),
        (0x5E, FlowType::None),
    ] {
        let server = engine_server_with(App::new().with_server_flow(flow), config()).await;
        let id = session_id(seed);
        let (mut peer, _connection) =
            established_client(&server, id, wire::RECOVERABLE, 5_000).await;
        peer.send(retransmit_request(id, 1, 1, 1)).await;
        peer.expect_terminate_then_close(id, TerminationCode::UnspecifiedError)
            .await;
    }
}

/// FIXP Appendix A 7.3.4 (p. 60-63, informative), 6.3 (p. 39): a
/// Retransmission that answers no request is a violation; the engine
/// terminates (**local policy** for the code).
#[tokio::test]
async fn test_client_terminates_on_an_unsolicited_retransmission() {
    let id = session_id(0x5F);
    let (mut client, _connection) =
        established_server(id, FlowType::Recoverable, wire::RECOVERABLE).await;
    client.peer.send(retransmission(id, 1, 1, 1)).await;
    client
        .peer
        .expect_terminate_then_close(id, TerminationCode::UnspecifiedError)
        .await;
}

/// FIXP 4.8.2 (p. 33): on an Idempotent flow a gap is answered with
/// NotApplied, "immediately", as an application message of the return flow
/// (it "consumes a sequence number", so it goes behind a Sequence), and
/// later messages are still accepted.
#[tokio::test]
async fn test_server_sends_not_applied_on_an_idempotent_gap() {
    let server = engine_server().await;
    let id = session_id(0x60);
    let (mut peer, _connection) = established_client(&server, id, wire::IDEMPOTENT, 5_000).await;
    peer.send(sequence(1)).await;
    peer.send_app(1).await;
    peer.send(sequence(4)).await;
    peer.send_app(4).await;
    let (seq, not_applied) = peer.until_not_applied().await;
    assert_eq!(seq, Some(1), "NotApplied is number 1 of the server flow");
    assert_eq!((not_applied.u64(0), not_applied.u32(8)), (2, 2));
    wait_until("two messages", || server.app.rec.inbound().len() == 2).await;
    assert_eq!(
        server
            .app
            .rec
            .messages()
            .into_iter()
            .map(|m| m.0)
            .collect::<Vec<_>>(),
        vec![Some(1), Some(4)]
    );
}

/// FIXP 4.8.2 (p. 33): the same, client role, with an Idempotent server
/// flow.
#[tokio::test]
async fn test_client_sends_not_applied_on_an_idempotent_gap() {
    let id = session_id(0x61);
    let (mut client, _connection) =
        established_server(id, FlowType::Recoverable, wire::IDEMPOTENT).await;
    client.peer.send(sequence(5)).await;
    let (seq, not_applied) = client.peer.until_not_applied().await;
    assert_eq!(seq, Some(1), "NotApplied is number 1 of the client flow");
    assert_eq!((not_applied.u64(0), not_applied.u32(8)), (1, 4));
}

/// FIXP 4.8.1 (p. 33), 4.8.2 (p. 33): Applied and NotApplied received for
/// the engine's Idempotent flow are numbered as application messages and
/// reported.
#[tokio::test]
async fn test_client_reports_applied_and_not_applied() {
    let id = session_id(0x62);
    let (mut client, _connection) =
        established_server(id, FlowType::Idempotent, wire::RECOVERABLE).await;
    client.peer.send(sequence(1)).await;
    client.peer.send(applied(1, 2)).await;
    client.peer.send(not_applied(3, 1)).await;
    client.peer.send_app(9).await;
    wait_until("the message after them", || {
        client.app.rec.inbound().len() == 1
    })
    .await;
    assert_eq!(
        client.app.rec.messages()[0].0,
        Some(3),
        "Applied and NotApplied consumed numbers 1 and 2"
    );
    let events = client.app.rec.events();
    assert!(events.contains(&Event::Applied {
        from_seq_no: 1,
        count: 2
    }));
    assert!(events.contains(&Event::NotApplied {
        from_seq_no: 3,
        count: 1
    }));
}

/// FIXP 4.8.2 (p. 33): "Sending NotApplied for a Recoverable, Unsequenced or
/// None flow is a protocol violation."
#[tokio::test]
async fn test_client_terminates_on_not_applied_for_a_recoverable_flow() {
    let id = session_id(0x63);
    let (mut client, _connection) =
        established_server(id, FlowType::Recoverable, wire::RECOVERABLE).await;
    client.peer.send(sequence(1)).await;
    client.peer.send(not_applied(1, 1)).await;
    client
        .peer
        .expect_terminate_then_close(id, TerminationCode::UnspecifiedError)
        .await;
}

/// FIXP 3.5.1 (p. 14): an Unsequenced flow carries no numbers, and
/// "Sending a Sequence or Context message on an Unsequenced or None flow is
/// a protocol violation".
#[tokio::test]
async fn test_server_unsequenced_flow_has_no_numbers_and_refuses_a_sequence() {
    let server = engine_server().await;
    let id = session_id(0x64);
    let (mut peer, _connection) = established_client(&server, id, wire::UNSEQUENCED, 5_000).await;
    // 4.5 (p. 25-26): the heartbeat of an Unsequenced flow.
    peer.send(unsequenced_heartbeat()).await;
    peer.send_app(1).await;
    wait_until("the message", || server.app.rec.inbound().len() == 1).await;
    assert_eq!(server.app.rec.messages()[0].0, None);
    peer.send(sequence(1)).await;
    peer.expect_terminate_then_close(id, TerminationCode::UnspecifiedError)
        .await;
}

/// FIXP 3.5.1 (p. 14): a Context on a None flow is a violation too.
#[tokio::test]
async fn test_server_none_flow_refuses_a_context() {
    let server = engine_server().await;
    let id = session_id(0x65);
    let (mut peer, _connection) = established_client(&server, id, wire::NONE, 5_000).await;
    peer.send(context(id, 1)).await;
    peer.expect_terminate_then_close(id, TerminationCode::UnspecifiedError)
        .await;
}

/// FIXP 3.4.4 (p. 14): "None: No application messages should be sent in
/// one direction"; one that arrives is a violation (6.3, p. 39).
#[tokio::test]
async fn test_server_terminates_on_an_application_message_on_a_none_flow() {
    let server = engine_server().await;
    let id = session_id(0x66);
    let (mut peer, _connection) = established_client(&server, id, wire::NONE, 5_000).await;
    peer.send_app(1).await;
    peer.expect_terminate_then_close(id, TerminationCode::UnspecifiedError)
        .await;
    assert!(server.app.rec.inbound().is_empty());
}

/// FIXP 3.5.3 (p. 15): a Context naming this session acts as a Sequence.
#[tokio::test]
async fn test_server_accepts_a_context_for_its_session() {
    let server = engine_server().await;
    let id = session_id(0x67);
    let (mut peer, _connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    peer.send(context(id, 1)).await;
    peer.send_app(1).await;
    wait_until("the message", || server.app.rec.inbound().len() == 1).await;
    assert_eq!(server.app.rec.messages()[0].0, Some(1));
}

/// FIXP Appendix A 7.3.1.2 (p. 56-57, informative), 7.2.2 (p. 51): a
/// Sequence with a lower `NextSeqNo` than expected ends the binding;
/// Terminate `UnspecifiedError` is **local policy**.
#[tokio::test]
async fn test_server_terminates_on_a_lower_next_seq_no() {
    let server = engine_server().await;
    let id = session_id(0x68);
    let (mut peer, _connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    peer.send(sequence(1)).await;
    peer.send_app(1).await;
    peer.send_app(2).await;
    peer.send(sequence(2)).await;
    peer.expect_terminate_then_close(id, TerminationCode::UnspecifiedError)
        .await;
}

/// FIXP 6.1 (p. 38): Topic is a multicast message; on a point-to-point
/// session it is "inappropriate", a violation (6.3, p. 39).
#[tokio::test]
async fn test_client_terminates_on_a_topic() {
    let id = session_id(0x69);
    let (mut client, _connection) =
        established_server(id, FlowType::Recoverable, wire::RECOVERABLE).await;
    client.peer.send(topic(id)).await;
    client
        .peer
        .expect_terminate_then_close(id, TerminationCode::UnspecifiedError)
        .await;
}

// ===========================================================================
// Keepalive (section 4.5)
// ===========================================================================

/// FIXP 4.5 (p. 25): "Each peer must send a heartbeat message during each
/// interval in which no application messages were sent"; on a sequenced
/// flow the heartbeat is a Sequence carrying the next number. Server role.
#[tokio::test]
async fn test_server_heartbeats_with_a_sequence() {
    let server = engine_server_with(App::new(), fast_config(100)).await;
    let id = session_id(0x70);
    let (mut peer, _connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    for _ in 0..3 {
        let beat = peer.expect(template::SEQUENCE).await;
        assert_eq!(beat.u64(0), 1);
    }
}

/// FIXP 4.5 (p. 25-26): on an Unsequenced flow the heartbeat is
/// UnsequencedHeartbeat. Client role.
#[tokio::test]
async fn test_client_heartbeats_with_an_unsequenced_heartbeat() {
    let id = session_id(0x71);
    let mut client = engine_client_with(fast_config(100), id, FlowType::Unsequenced).await;
    let _connection = client
        .accept(FlowType::Unsequenced, wire::RECOVERABLE, 5_000, Some(1))
        .await;
    for _ in 0..3 {
        let _ = client.peer.expect(template::UNSEQUENCED_HEARTBEAT).await;
    }
}

/// FIXP 4.5 (p. 25), 4.4 (p. 22): silence longer than the counterparty's
/// keepalive interval ends the session: Terminate, then the transport
/// closes. The grace on top of the interval is **local policy** (4.4 asks
/// for "some leniency").
#[tokio::test]
async fn test_server_terminates_a_silent_client() {
    let server = engine_server_with(App::new(), fast_config(5_000)).await;
    let id = session_id(0x72);
    let (mut peer, connection) = established_client(&server, id, wire::RECOVERABLE, 200).await;
    peer.expect_terminate_then_close(id, TerminationCode::UnspecifiedError)
        .await;
    wait_closed(&connection).await;
    assert!(
        server
            .app
            .rec
            .has_event(|e| matches!(e, Event::KeepaliveLapsed))
    );
}

/// FIXP 4.5 (p. 25): the same in the client role; a heartbeating server
/// keeps the session up, a silent one does not.
#[tokio::test]
async fn test_client_terminates_a_silent_server_but_not_a_heartbeating_one() {
    let id = session_id(0x73);
    let mut client = engine_client_with(fast_config(5_000), id, FlowType::Recoverable).await;
    let connection = client
        .accept(FlowType::Recoverable, wire::RECOVERABLE, 400, Some(1))
        .await;
    // Heartbeats every 100 ms for a second: no lapse.
    for _ in 0..10 {
        client.peer.send(sequence(1)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!connection.is_closed());
    assert!(
        !client
            .app
            .rec
            .has_event(|e| matches!(e, Event::KeepaliveLapsed))
    );
    // Then silence.
    client
        .peer
        .expect_terminate_then_close(id, TerminationCode::UnspecifiedError)
        .await;
    assert!(
        client
            .app
            .rec
            .has_event(|e| matches!(e, Event::KeepaliveLapsed))
    );
}

// ===========================================================================
// Termination (section 4.4)
// ===========================================================================

/// FIXP 4.4.1 (p. 23): "Upon receiving a Terminate message, the receiver
/// must respond with a Terminate message", whatever its code; the answer
/// carries `Finished` (**local policy**: 4.4.1 does not name the code).
/// Each TerminationCode received is reported. Server role.
#[tokio::test]
async fn test_server_answers_every_terminate_code() {
    for (seed, code) in [
        (0x80, TerminationCode::Finished),
        (0x81, TerminationCode::UnspecifiedError),
        (0x82, TerminationCode::ReRequestOutOfBounds),
        (0x83, TerminationCode::ReRequestInProgress),
    ] {
        let server = engine_server().await;
        let id = session_id(seed);
        let (mut peer, connection) =
            established_client(&server, id, wire::RECOVERABLE, 5_000).await;
        peer.send(terminate(id, code.as_u8())).await;
        let answer = peer.expect_skipping_heartbeats(template::TERMINATE).await;
        assert_eq!(answer.uuid(), id);
        assert_eq!(answer.u8(16), TerminationCode::Finished.as_u8());
        // 4.4.2 (p. 23): the initiator closes; the engine follows.
        drop(peer);
        wait_closed(&connection).await;
        assert!(server.app.rec.has_event(|e| matches!(
            e,
            Event::Terminated { code: got, by: TerminatedBy::Peer, .. } if *got == code
        )));
    }
}

/// FIXP 4.4.1 (p. 23): the same, client role.
#[tokio::test]
async fn test_client_answers_a_terminate() {
    let id = session_id(0x84);
    let (mut client, connection) =
        established_server(id, FlowType::Recoverable, wire::RECOVERABLE).await;
    client
        .peer
        .send(terminate(id, TerminationCode::UnspecifiedError.as_u8()))
        .await;
    let answer = client
        .peer
        .expect_skipping_heartbeats(template::TERMINATE)
        .await;
    assert_eq!(answer.u8(16), TerminationCode::Finished.as_u8());
    drop(client.peer);
    wait_closed(&connection).await;
}

/// FIXP 4.4 (p. 22): "Any messages sent after Terminate are a protocol
/// violation and should be ignored": an application message after the
/// peer's Terminate is not delivered.
#[tokio::test]
async fn test_server_ignores_messages_after_the_peer_terminate() {
    let server = engine_server().await;
    let id = session_id(0x85);
    let (mut peer, _connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    peer.send(sequence(1)).await;
    peer.send(terminate(id, TerminationCode::Finished.as_u8()))
        .await;
    peer.send_app(1).await;
    let _ = peer.expect_skipping_heartbeats(template::TERMINATE).await;
    wait_until("the message ignored", || {
        server
            .app
            .rec
            .has_event(|e| matches!(e, Event::Ignored { .. }))
    })
    .await;
    assert!(server.app.rec.inbound().is_empty());
}

/// FIXP 4.4.1 (p. 23), 4.4.2 (p. 23): the engine's own Terminate carries
/// `Finished`; once the peer answers, the engine "should close the
/// transport immediately". Client role.
#[tokio::test]
async fn test_client_orderly_terminate() {
    let id = session_id(0x86);
    let (mut client, connection) =
        established_server(id, FlowType::Recoverable, wire::RECOVERABLE).await;
    ok(connection.terminate("done").await, "terminate");
    let frame = client
        .peer
        .expect_skipping_heartbeats(template::TERMINATE)
        .await;
    assert_eq!(frame.uuid(), id);
    assert_eq!(frame.u8(16), TerminationCode::Finished.as_u8());
    assert_eq!(frame.var(), b"done");
    client
        .peer
        .send(terminate(id, TerminationCode::Finished.as_u8()))
        .await;
    let rest = client.peer.until_closed().await;
    assert!(rest.is_empty(), "nothing after Terminate: {rest:?}");
    wait_closed(&connection).await;
    assert!(client.app.rec.has_event(|e| matches!(
        e,
        Event::Terminated {
            code: TerminationCode::Finished,
            by: TerminatedBy::Local,
            ..
        }
    )));
}

/// FIXP 4.4.1 (p. 23): "If the peer is unresponsive to Terminate for a
/// heartbeat interval, then the initiator of termination should consider
/// the session terminated anyway." Server role.
#[tokio::test]
async fn test_server_closes_when_its_terminate_is_not_answered() {
    let server = engine_server_with(App::new(), fast_config(200)).await;
    let id = session_id(0x87);
    let (mut peer, connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    ok(connection.terminate("done").await, "terminate");
    let started = tokio::time::Instant::now();
    peer.expect_terminate_then_close(id, TerminationCode::Finished)
        .await;
    assert!(started.elapsed() < WAIT);
    wait_closed(&connection).await;
}

/// FIXP 4.4 (p. 22): "The transport was abruptly disconnected": the session
/// stops being established, the application is told, the handle closes.
/// Both roles.
#[tokio::test]
async fn test_abrupt_disconnect_in_both_roles() {
    let server = engine_server().await;
    let id = session_id(0x88);
    let (peer, connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    drop(peer);
    wait_closed(&connection).await;
    wait_until("server on_closed", || server.app.rec.closed() == 1).await;
    assert!(
        server
            .app
            .rec
            .has_event(|e| matches!(e, Event::TransportClosed))
    );

    let id = session_id(0x89);
    let (client, connection) =
        established_server(id, FlowType::Recoverable, wire::RECOVERABLE).await;
    drop(client.peer);
    wait_closed(&connection).await;
    wait_until("client on_closed", || client.app.rec.closed() == 1).await;
    assert!(matches!(
        connection.send(app(1)).await,
        Err(FixpEngineError::Closed)
    ));
}

// ===========================================================================
// Finalization (section 4.7)
// ===========================================================================

/// FIXP 4.7.1 (p. 31), 4.7.2 (p. 31), 6.3 (p. 39), 3.4.1 (p. 13): the peer
/// finalizes: FinishedSending with LastSeqNo, the engine answers
/// FinishedReceiving, the peer's Terminate is answered, the session is
/// finalized, and its id is refused afterwards (`DuplicateId`). Finalizing
/// only on a `Finished` Terminate is **local policy**. Server role.
#[tokio::test]
async fn test_server_finalization_and_reuse_refused() {
    let server = engine_server().await;
    let id = session_id(0x90);
    let (mut peer, connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    peer.send(sequence(1)).await;
    peer.send_app(1).await;
    peer.send_app(2).await;
    peer.send(finished_sending(id, Some(2))).await;
    let received = peer
        .expect_skipping_heartbeats(template::FINISHED_RECEIVING)
        .await;
    assert_eq!(received.uuid(), id);
    // 6.3 (p. 39): the responder sends no application message after it.
    assert!(connection.send(app(9)).await.is_err());
    peer.send(terminate(id, TerminationCode::Finished.as_u8()))
        .await;
    let _ = peer.expect_skipping_heartbeats(template::TERMINATE).await;
    drop(peer);
    wait_closed(&connection).await;
    wait_until("finalized", || {
        server.acceptor.is_finalized(SessionId::from_bytes(id))
    })
    .await;

    let mut again = Peer::connect(server.addr).await;
    again
        .send(negotiate(id, 3, wire::RECOVERABLE, SECRET))
        .await;
    let reject = again.expect(template::NEGOTIATION_REJECT).await;
    assert_eq!(reject.u8(24), NegotiationRejectCode::DuplicateId.as_u8());
    again.expect_closed_silently().await;

    // Establishing the finalized id directly is refused with `Unnegotiated`
    // and the transport closes at once (6.3, p. 39).
    let mut direct = Peer::connect(server.addr).await;
    direct.send(establish(id, 4, 5_000, Some(3))).await;
    let reject = direct.expect(template::ESTABLISHMENT_REJECT).await;
    assert_eq!(reject.u8(24), EstablishmentRejectCode::Unnegotiated.as_u8());
    direct.expect_closed_silently().await;
}

/// FIXP 4.7.1 (p. 31): "If received on a recoverable flow, the peer may
/// send a RetransmitRequest to recover any missed messages before
/// acknowledging finalization"; 4.7.2 (p. 31): FinishedReceiving follows
/// the last message "possibly received on a retransmission". Client role.
#[tokio::test]
async fn test_client_recovers_up_to_last_seq_no_before_finished_receiving() {
    let id = session_id(0x91);
    let (mut client, _connection) =
        established_server(id, FlowType::Recoverable, wire::RECOVERABLE).await;
    client.peer.send(sequence(1)).await;
    client.peer.send_app(1).await;
    client.peer.send(finished_sending(id, Some(3))).await;
    let request = client
        .peer
        .expect_skipping_heartbeats(template::RETRANSMIT_REQUEST)
        .await;
    assert_eq!((request.u64(24), request.u32(32)), (2, 2));
    client
        .peer
        .send(retransmission(id, request.u64(16), 2, 2))
        .await;
    client.peer.send_app(2).await;
    client.peer.send_app(3).await;
    let received = client
        .peer
        .expect_skipping_heartbeats(template::FINISHED_RECEIVING)
        .await;
    assert_eq!(received.uuid(), id);
    client
        .peer
        .send(terminate(id, TerminationCode::Finished.as_u8()))
        .await;
    let _ = client
        .peer
        .expect_skipping_heartbeats(template::TERMINATE)
        .await;
    drop(client.peer);
    wait_until("finalized", || {
        client
            .app
            .rec
            .has_event(|e| matches!(e, Event::SessionFinalized { .. }))
    })
    .await;
}

/// FIXP 6.3 (p. 39): "Sending FinishedReceiving without having received
/// FinishedSending from the peer" is a violation.
#[tokio::test]
async fn test_server_terminates_on_an_unsolicited_finished_receiving() {
    let server = engine_server().await;
    let id = session_id(0x92);
    let (mut peer, _connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    peer.send(finished_receiving(id)).await;
    peer.expect_terminate_then_close(id, TerminationCode::UnspecifiedError)
        .await;
}

/// FIXP 6.3 (p. 39): "Sending an application message after logical flow
/// has been finalized with FinishedSending" is a violation; the message is
/// ignored and the session terminated.
#[tokio::test]
async fn test_client_terminates_on_an_application_message_after_finished_sending() {
    let id = session_id(0x93);
    let (mut client, _connection) =
        established_server(id, FlowType::Recoverable, wire::RECOVERABLE).await;
    client.peer.send(sequence(1)).await;
    client.peer.send_app(1).await;
    client.peer.send(finished_sending(id, Some(1))).await;
    let _ = client
        .peer
        .expect_skipping_heartbeats(template::FINISHED_RECEIVING)
        .await;
    client.peer.send_app(2).await;
    client
        .peer
        .expect_terminate_then_close(id, TerminationCode::UnspecifiedError)
        .await;
    assert_eq!(client.app.rec.inbound().len(), 1);
}

/// FIXP 4.7.1 (p. 31): LastSeqNo "Must be populated for an idempotent or
/// recoverable flow"; without it the engine terminates (**local policy**:
/// FIXP does not say how to treat the omission).
#[tokio::test]
async fn test_server_terminates_on_finished_sending_without_last_seq_no() {
    let server = engine_server().await;
    let id = session_id(0x94);
    let (mut peer, _connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    peer.send(finished_sending(id, None)).await;
    peer.expect_terminate_then_close(id, TerminationCode::UnspecifiedError)
        .await;
}

/// FIXP 4.7.1 (p. 31): on an Unsequenced flow LastSeqNo is not needed;
/// FinishedReceiving answers at once.
#[tokio::test]
async fn test_server_answers_finished_sending_on_an_unsequenced_flow() {
    let server = engine_server().await;
    let id = session_id(0x95);
    let (mut peer, _connection) = established_client(&server, id, wire::UNSEQUENCED, 5_000).await;
    peer.send(finished_sending(id, None)).await;
    let _ = peer
        .expect_skipping_heartbeats(template::FINISHED_RECEIVING)
        .await;
}

/// FIXP 4.7.1 (p. 31): a repeated FinishedSending is the finalizing side's
/// heartbeat and gets no second FinishedReceiving (Appendix A 7.4.2, p. 71,
/// informative).
#[tokio::test]
async fn test_server_answers_finished_sending_once() {
    let server = engine_server().await;
    let id = session_id(0x96);
    let (mut peer, connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    peer.send(sequence(1)).await;
    peer.send_app(1).await;
    peer.send(finished_sending(id, Some(1))).await;
    let _ = peer
        .expect_skipping_heartbeats(template::FINISHED_RECEIVING)
        .await;
    peer.send(finished_sending(id, Some(1))).await;
    peer.send(terminate(id, TerminationCode::Finished.as_u8()))
        .await;
    let next = peer.recv_skipping_heartbeats().await;
    assert_eq!(
        next.template(),
        Some(template::TERMINATE),
        "no second FinishedReceiving"
    );
    drop(peer);
    wait_closed(&connection).await;
}

// ===========================================================================
// Further hostile and edge input
// ===========================================================================

/// FIXP 3.3.3 (p. 12): SOFH gives "its overall length", so a frame split
/// across many reads is reassembled; here a Negotiate arrives one byte per
/// write.
#[tokio::test]
async fn test_server_reassembles_a_frame_split_into_single_bytes() {
    let server = engine_server().await;
    let id = session_id(0xA0);
    let mut peer = Peer::connect(server.addr).await;
    for byte in sofh(SBE_LE, &negotiate(id, 1, wire::RECOVERABLE, SECRET)) {
        peer.raw(&[byte]).await;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let response = peer.expect(template::NEGOTIATION_RESPONSE).await;
    assert_eq!(response.uuid(), id);
}

/// FIXP 3.3.3 (p. 12): several frames in one write are split by their
/// lengths: a Sequence and three messages arrive in one segment.
#[tokio::test]
async fn test_server_splits_coalesced_frames() {
    let server = engine_server().await;
    let id = session_id(0xA1);
    let (mut peer, _connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    let mut burst = sofh(SBE_LE, &sequence(1));
    for n in 1..=3 {
        burst.extend(sofh(SBE_LE, &app(n)));
    }
    peer.raw(&burst).await;
    wait_until("three messages", || server.app.rec.inbound().len() == 3).await;
    assert_eq!(
        server.app.rec.messages(),
        (1..=3)
            .map(|n| (Some(u64::from(n)), false, app(n)))
            .collect::<Vec<_>>()
    );
}

/// FIXP 6.3 (p. 39): "Sending Establish without having successfully
/// negotiated a session. That is, a NegotiationResponse must have been
/// received". An Establish sent right behind the Negotiate, before the
/// answer, is a violation: the engine closes the transport.
#[tokio::test]
async fn test_server_refuses_an_establish_sent_before_the_negotiation_response() {
    // The answer cannot come before the Establish is read, whatever the
    // scheduling.
    let mut app = App::new();
    app.negotiate_when = Decide::After(Duration::from_millis(500));
    let server = engine_server_with(app, config()).await;
    let id = session_id(0xAC);
    let mut peer = Peer::connect(server.addr).await;
    let mut burst = sofh(SBE_LE, &negotiate(id, 1, wire::RECOVERABLE, SECRET));
    burst.extend(sofh(SBE_LE, &establish(id, 2, 5_000, Some(1))));
    peer.raw(&burst).await;
    peer.expect_closed_silently().await;
    assert!(server.app.rec.connection().is_none());
}

/// FIXP 4.6.1 (p. 26): "Only one RetransmitRequest is allowed in-flight at
/// a time per session. Another RetransmitRequest must not be sent until a
/// response has been received". A second gap waits for the first answer.
#[tokio::test]
async fn test_server_keeps_one_retransmit_request_in_flight() {
    let server = engine_server().await;
    let id = session_id(0xA2);
    let (mut peer, _connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    peer.send(sequence(3)).await;
    let first = peer
        .expect_skipping_heartbeats(template::RETRANSMIT_REQUEST)
        .await;
    assert_eq!((first.u64(24), first.u32(32)), (1, 2));
    peer.send_app(3).await;
    peer.send(sequence(6)).await;
    peer.send_app(6).await;
    wait_until("the second gap seen", || {
        server.app.rec.has_event(|e| match e {
            Event::SequenceGap { from, .. } => from.value() == 4,
            _ => false,
        })
    })
    .await;
    // Nothing goes out while the first request is unanswered.
    let quiet = tokio::time::timeout(Duration::from_millis(200), peer.read()).await;
    assert!(
        quiet.is_err(),
        "a frame while a request is in flight: {quiet:?}"
    );
    peer.send(retransmission(id, first.u64(16), 1, 2)).await;
    peer.send_app(1).await;
    peer.send_app(2).await;
    let second = peer
        .expect_skipping_heartbeats(template::RETRANSMIT_REQUEST)
        .await;
    assert_eq!((second.u64(24), second.u32(32)), (4, 2));
    assert_ne!(second.u64(16), first.u64(16), "a new request timestamp");
}

/// FIXP 4.6.2.3 (p. 28): "OutOfRange: NextSeqNo + Count is beyond the range
/// of sequence numbers": a range that overflows `u64` is refused without
/// arithmetic overflow; an empty one (Count 0) too (**local policy** for
/// the empty range).
#[tokio::test]
async fn test_server_rejects_overflowing_and_empty_retransmit_requests() {
    let server = engine_server().await;
    let id = session_id(0xA3);
    let (mut peer, connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    let _ = engine_sends_three(&connection, &mut peer).await;
    for (ts, from, count) in [(1, u64::MAX - 1, 5), (2, 1, 0)] {
        peer.send(retransmit_request(id, ts, from, count)).await;
        let reject = peer
            .expect_skipping_heartbeats(template::RETRANSMIT_REJECT)
            .await;
        assert_eq!(reject.u64(16), ts);
        assert_eq!(reject.u8(24), RetransmitRejectCode::OutOfRange.as_u8());
    }
}

/// **Local policy** (FIXP does not bound a gap): a Sequence that jumps by
/// more than `max_gap_len` (here to `u64::MAX`) terminates instead of
/// requesting an unbounded range, and nothing overflows.
#[tokio::test]
async fn test_server_terminates_on_a_sequence_jump_above_the_gap_bound() {
    let server = engine_server().await;
    let id = session_id(0xA4);
    let (mut peer, _connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    peer.send(sequence(u64::MAX)).await;
    peer.expect_terminate_then_close(id, TerminationCode::UnspecifiedError)
        .await;
}

/// FIXP 4.4 (p. 22): the Terminate's SessionId "is redundant and included
/// only for robustness"; one naming another session is treated as a
/// violation (**local policy**).
#[tokio::test]
async fn test_server_terminates_on_a_terminate_for_another_session() {
    let server = engine_server().await;
    let id = session_id(0xA5);
    let (mut peer, _connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    peer.send(terminate(
        session_id(0xA6),
        TerminationCode::Finished.as_u8(),
    ))
    .await;
    peer.expect_terminate_then_close(id, TerminationCode::UnspecifiedError)
        .await;
}

/// FIXP 3.5.3 (p. 15): multiplexing is not supported, so a Context naming
/// another session is a violation (**local policy**).
#[tokio::test]
async fn test_server_terminates_on_a_context_for_another_session() {
    let server = engine_server().await;
    let id = session_id(0xA7);
    let (mut peer, _connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    peer.send(context(session_id(0xA8), 1)).await;
    peer.expect_terminate_then_close(id, TerminationCode::UnspecifiedError)
        .await;
}

/// FIXP 3.4.1 (p. 13) and Appendix A 7.1.7.3 (p. 42, informative): the nil
/// UUID is not a valid session id; the Negotiate is refused.
#[tokio::test]
async fn test_server_rejects_a_nil_session_id() {
    let server = engine_server().await;
    let mut peer = Peer::connect(server.addr).await;
    peer.send(negotiate([0; 16], 1, wire::RECOVERABLE, SECRET))
        .await;
    let reject = peer.expect(template::NEGOTIATION_REJECT).await;
    assert_eq!(reject.u8(24), NegotiationRejectCode::Unspecified.as_u8());
    peer.expect_closed_silently().await;
}

/// FIXP 6.3 (p. 39), 4.4 (p. 22): a server-only message (here
/// NegotiationResponse) sent by the client once established is a violation.
#[tokio::test]
async fn test_server_terminates_on_a_server_only_message() {
    let server = engine_server().await;
    let id = session_id(0xA9);
    let (mut peer, _connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    peer.send(negotiation_response(id, 9, wire::RECOVERABLE))
        .await;
    peer.expect_terminate_then_close(id, TerminationCode::UnspecifiedError)
        .await;
}

/// FIXP 4.4 (p. 22): "No other messages may be sent on the session after
/// sending a Terminate message": once the engine has terminated, a send is
/// refused and nothing follows the Terminate.
#[tokio::test]
async fn test_server_sends_nothing_after_its_terminate() {
    let server = engine_server_with(App::new(), fast_config(300)).await;
    let id = session_id(0xAA);
    let (mut peer, connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    ok(connection.terminate("bye").await, "terminate");
    assert!(matches!(
        connection.send(app(1)).await,
        Err(FixpEngineError::Session(_))
    ));
    peer.expect_terminate_then_close(id, TerminationCode::Finished)
        .await;
}

/// **Local policy, a deliberate departure from FIXP 6.3 (p. 39)**, which
/// recommends immediate termination; a later handshake timeout does not
/// meet that timing. After an automatic
/// EstablishmentReject the client can fix (here `KeepaliveInterval`), the
/// transport stays open for a retry on it (Appendix A 7.1.12.4, p. 46 to
/// 47, shows the reject and no close), bounded by the handshake timeout.
/// A retry with a valid interval is established on the same transport.
#[tokio::test]
async fn test_server_allows_a_retry_after_a_keepalive_reject() {
    let server = engine_server().await;
    let id = session_id(0xAB);
    let mut peer = Peer::connect(server.addr).await;
    raw_negotiate(&mut peer, id, wire::RECOVERABLE, FlowType::Recoverable).await;
    peer.send(establish(id, 46, 10, Some(1))).await;
    let reject = peer.expect(template::ESTABLISHMENT_REJECT).await;
    assert_eq!(
        reject.u8(24),
        EstablishmentRejectCode::KeepaliveInterval.as_u8()
    );
    let _ = raw_establish(&mut peer, id, 5_000, Some(1)).await;
}

/// **Local policy**: the same, without a retry: the transport closes when
/// the handshake timeout lapses.
#[tokio::test]
async fn test_server_bounds_the_transport_after_a_keepalive_reject() {
    let server = engine_server_with(App::new(), fast_config(1_000)).await;
    let id = session_id(0xAD);
    let mut peer = Peer::connect(server.addr).await;
    raw_negotiate(&mut peer, id, wire::RECOVERABLE, FlowType::Recoverable).await;
    peer.send(establish(id, 46, 10, Some(1))).await;
    let _ = peer.expect(template::ESTABLISHMENT_REJECT).await;
    peer.expect_closed_silently().await;
}

/// **Local policy**: a Negotiate on an established session is answered with
/// NegotiationReject `DuplicateId` and then Terminate `UnspecifiedError`.
/// FIXP 4.2.3 (p. 18) says no further message should follow a
/// NegotiationReject, and 6.3 (p. 39) makes the Negotiate a violation that
/// ends the session; the engine keeps both answers (the reject tells the
/// client why, the Terminate unbinds the established session). This
/// sequence is the engine's choice, not one the specification mandates.
#[tokio::test]
async fn test_server_answers_a_negotiate_on_an_established_session() {
    let server = engine_server().await;
    let id = session_id(0xAE);
    let (mut peer, _connection) = established_client(&server, id, wire::RECOVERABLE, 5_000).await;
    peer.send(negotiate(id, 9, wire::RECOVERABLE, SECRET)).await;
    let reject = peer
        .expect_skipping_heartbeats(template::NEGOTIATION_REJECT)
        .await;
    assert_eq!(reject.u8(24), NegotiationRejectCode::DuplicateId.as_u8());
    peer.expect_terminate_then_close(id, TerminationCode::UnspecifiedError)
        .await;
}

// ===========================================================================
// Regressions: a refused handshake is always answered (defect found by #97)
// ===========================================================================

/// A raw client whose Negotiate reaches an engine server running `app`;
/// returns the first frame the engine answers with, then checks the close.
async fn negotiate_against(app: App, config: FixpConfig, seed: u8, flow: u8) -> Frame {
    let server = engine_server_with(app, config).await;
    let mut peer = Peer::connect(server.addr).await;
    peer.send(negotiate(session_id(seed), 7, flow, SECRET))
        .await;
    let answer = peer.recv().await;
    peer.expect_closed_silently().await;
    answer
}

/// Checks a NegotiationReject for request timestamp 7 with `code`.
fn assert_negotiation_reject(frame: &Frame, seed: u8, code: NegotiationRejectCode) {
    assert_eq!(
        frame.template(),
        Some(template::NEGOTIATION_REJECT),
        "{frame:?}"
    );
    assert_eq!(frame.uuid(), session_id(seed));
    assert_eq!(frame.u64(16), 7, "RequestTimestamp");
    assert_eq!(frame.u8(24), code.as_u8());
}

/// FIXP 4.2.3 (p. 18): "When a session cannot be created, a server must
/// send NegotiationReject". An application that accepts a None client flow
/// with a None server flow (3.4.4.1, p. 14: only one may be None) cannot
/// create the session; the engine used to close without a word, it now
/// rejects with `FlowTypeNotSupported`.
#[tokio::test]
async fn test_server_rejects_a_negotiation_with_both_flows_none() {
    let app = App::new().with_server_flow(FlowType::None);
    let answer = negotiate_against(app, config(), 0xB0, wire::NONE).await;
    assert_negotiation_reject(&answer, 0xB0, NegotiationRejectCode::FlowTypeNotSupported);
}

/// FIXP 4.2.3 (p. 18): a negotiation decision that fails (the application
/// panicked) is answered with NegotiationReject `Unspecified`, not a silent
/// close.
#[tokio::test]
async fn test_server_rejects_a_negotiation_when_the_application_fails() {
    let mut app = App::new();
    app.negotiate_when = Decide::Panic;
    let answer = negotiate_against(app, config(), 0xB1, wire::RECOVERABLE).await;
    assert_negotiation_reject(&answer, 0xB1, NegotiationRejectCode::Unspecified);
}

/// FIXP 4.2.3 (p. 18): a negotiation decision that never comes is bounded
/// by the handshake timeout (**local policy**) and then answered with
/// NegotiationReject `Unspecified`.
#[tokio::test]
async fn test_server_rejects_a_negotiation_not_answered_in_time() {
    let mut app = App::new();
    app.negotiate_when = Decide::Never;
    let answer = negotiate_against(app, fast_config(1_000), 0xB2, wire::RECOVERABLE).await;
    assert_negotiation_reject(&answer, 0xB2, NegotiationRejectCode::Unspecified);
}

/// A raw client negotiated on an engine server running `app`, whose
/// Establish (timestamp 8) gets the returned answer; checks the close.
async fn establish_against(app: App, config: FixpConfig, seed: u8) -> Frame {
    let server = engine_server_with(app, config).await;
    let id = session_id(seed);
    let mut peer = Peer::connect(server.addr).await;
    raw_negotiate(&mut peer, id, wire::RECOVERABLE, FlowType::Recoverable).await;
    peer.send(establish(id, 8, 5_000, Some(1))).await;
    let answer = peer.recv().await;
    peer.expect_closed_silently().await;
    answer
}

fn assert_establishment_reject(frame: &Frame, seed: u8) {
    assert_eq!(
        frame.template(),
        Some(template::ESTABLISHMENT_REJECT),
        "{frame:?}"
    );
    assert_eq!(frame.uuid(), session_id(seed));
    assert_eq!(frame.u64(16), 8, "RequestTimestamp");
    assert_eq!(frame.u8(24), EstablishmentRejectCode::Unspecified.as_u8());
}

/// FIXP 4.3 (p. 19): "The response to Establish is either EstablishmentAck
/// or EstablishmentReject". A failed establishment decision is answered
/// with EstablishmentReject `Unspecified`, then the transport closes.
#[tokio::test]
async fn test_server_rejects_an_establishment_when_the_application_fails() {
    let mut app = App::new();
    app.establish_when = Decide::Panic;
    let answer = establish_against(app, config(), 0xB3).await;
    assert_establishment_reject(&answer, 0xB3);
}

/// FIXP 4.3 (p. 19): the same for a decision that never comes, after the
/// handshake timeout (**local policy**).
#[tokio::test]
async fn test_server_rejects_an_establishment_not_answered_in_time() {
    let mut app = App::new();
    app.establish_when = Decide::Never;
    let answer = establish_against(app, fast_config(1_000), 0xB4).await;
    assert_establishment_reject(&answer, 0xB4);
}

// ===========================================================================
// Oracle controls: the raw peer's own checks fail on malformed output
// ===========================================================================

/// A well-formed NegotiationReject message, as the engine sends one.
fn good_reject_message() -> Vec<u8> {
    negotiation_reject(
        session_id(0xC0),
        7,
        NegotiationRejectCode::Credentials.as_u8(),
    )
}

/// Reads `bytes` as the engine's output with the suite's frame oracle.
async fn oracle(bytes: &[u8]) -> Result<Option<Frame>, String> {
    let mut reader = bytes;
    read_frame(&mut reader).await
}

/// `true` when `check` panics.
fn panics(check: impl FnOnce() + std::panic::UnwindSafe) -> bool {
    std::panic::catch_unwind(check).is_err()
}

/// The NegotiationReject with `edit` applied to its SBE bytes.
fn mutated(edit: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut message = good_reject_message();
    edit(&mut message);
    message
}

fn set_le16(message: &mut [u8], at: usize, value: u16) {
    message[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

/// The close oracle: only end of stream before any frame byte is a clean
/// close; a partial header (three bytes included), a partial body and an
/// invalid `Message_Length` fail.
#[tokio::test]
async fn test_oracle_close_requires_zero_bytes_before_eof() {
    assert!(matches!(oracle(&[]).await, Ok(None)));
    let frame = sofh(SBE_LE, &good_reject_message());
    for cut in 1..frame.len() {
        assert!(
            oracle(&frame[..cut]).await.is_err(),
            "a frame cut at {cut} bytes passed as a clean close"
        );
    }
    assert!(oracle(&[0, 0, 0, 6, 0xEB, 0x50]).await.is_err(), "length 6");
    assert!(
        oracle(&[0, 0x20, 0, 0, 0xEB, 0x50]).await.is_err(),
        "2 MiB length"
    );
    assert!(matches!(oracle(&frame).await, Ok(Some(_))));
}

/// The decode oracle checks blockLength, templateId, version and the
/// message length against the SOFH length before any field is read; a
/// longer root block is a valid extension.
#[tokio::test]
async fn test_oracle_rejects_malformed_session_headers() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("blockLength 0", mutated(|m| set_le16(m, 0, 0))),
        ("blockLength 24", mutated(|m| set_le16(m, 0, 24))),
        (
            "blockLength past the frame",
            mutated(|m| set_le16(m, 0, 200)),
        ),
        ("unknown template", mutated(|m| set_le16(m, 2, 99))),
        ("version 1", mutated(|m| set_le16(m, 6, 1))),
        (
            "var length past the frame",
            mutated(|m| set_le16(m, HEADER + 25, 500)),
        ),
        ("var field missing", mutated(|m| m.truncate(HEADER + 25))),
        ("trailing bytes", mutated(|m| m.push(0))),
    ];
    for (what, message) in cases {
        assert!(
            oracle(&sofh(SBE_LE, &message)).await.is_err(),
            "{what} passed the oracle"
        );
    }
    let extended = mutated(|m| {
        set_le16(m, 0, 26);
        m.insert(HEADER + 25, 0xAA);
    });
    let frame = oracle(&sofh(SBE_LE, &extended)).await;
    assert!(
        matches!(&frame, Ok(Some(f)) if f.var() == b"refused" && f.u8(24) == 0),
        "{frame:?}"
    );
}

fn as_frame(encoding: u16, payload: Vec<u8>) -> Frame {
    Frame { encoding, payload }
}

/// The shared assertion helpers fail on mutated outputs: a header that does
/// not match the schema, another template, another schema, another
/// encoding type, and wrong field values.
#[test]
fn test_oracle_assertion_helpers_fail_on_mutated_output() {
    let good = as_frame(SBE_LE, good_reject_message());
    assert!(!panics(move || assert_negotiation_reject(
        &good,
        0xC0,
        NegotiationRejectCode::Credentials
    )));
    let mutations: Vec<(&str, Frame)> = vec![
        (
            "blockLength 0",
            as_frame(SBE_LE, mutated(|m| set_le16(m, 0, 0))),
        ),
        (
            "template",
            as_frame(
                SBE_LE,
                mutated(|m| set_le16(m, 2, template::NEGOTIATION_RESPONSE)),
            ),
        ),
        (
            "schema",
            as_frame(SBE_LE, mutated(|m| set_le16(m, 4, 2749))),
        ),
        ("version", as_frame(SBE_LE, mutated(|m| set_le16(m, 6, 1)))),
        ("session id", as_frame(SBE_LE, mutated(|m| m[HEADER] ^= 1))),
        (
            "request timestamp",
            as_frame(SBE_LE, mutated(|m| m[HEADER + 16] ^= 1)),
        ),
        ("code", as_frame(SBE_LE, mutated(|m| m[HEADER + 24] = 3))),
        ("encoding type", as_frame(0x5BE0, good_reject_message())),
    ];
    for (what, bad) in mutations {
        assert!(
            panics(move || assert_negotiation_reject(
                &bad,
                0xC0,
                NegotiationRejectCode::Credentials
            )),
            "assert_negotiation_reject accepted a mutated {what}"
        );
    }

    let establishment = |edit: fn(&mut Vec<u8>)| {
        let mut message = establishment_reject(
            session_id(0xC1),
            8,
            EstablishmentRejectCode::Unspecified.as_u8(),
        );
        edit(&mut message);
        as_frame(SBE_LE, message)
    };
    assert!(!panics(move || assert_establishment_reject(
        &establishment(|_| {}),
        0xC1
    )));
    assert!(panics(move || assert_establishment_reject(
        &establishment(|m| set_le16(m, 0, 0)),
        0xC1
    )));
    assert!(panics(move || assert_establishment_reject(
        &establishment(|m| m[HEADER + 24] = 0),
        0xC1
    )));

    // A field outside the template's root block is never read.
    let sequence_frame = as_frame(SBE_LE, sequence(1));
    assert!(panics(move || {
        let _ = sequence_frame.u64(8);
    }));
    // Classifying a heartbeat validates it too.
    let mut short = sequence(1);
    set_le16(&mut short, 0, 4);
    let short = as_frame(SBE_LE, short);
    assert!(panics(move || {
        let _ = short.is_heartbeat();
    }));
}
