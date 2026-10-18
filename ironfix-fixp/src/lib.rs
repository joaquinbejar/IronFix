/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! # IronFix FIXP
//!
//! The FIX Performance Session Layer (FIXP) for the IronFix protocol engine:
//! a sans-IO session core for point-to-point sessions, in both roles
//! ([`FixpClient`] and [`FixpServer`]), with the SBE encoding of the FIXP
//! session messages ([`SessionMessage`]).
//!
//! ## Specification
//!
//! This crate implements the **FIX Performance Session Layer Technical
//! Specification, version 1.1, Draft Standard of April 18, 2019**, the
//! highest version FIX Trading Community publishes
//! (<https://www.fixtrading.org/standards/fixp/>). Version 1.0 is the
//! Technical Standard, approved in April 2021; its point-to-point chapter
//! says the same as v1.1 save for wording and the WebSocket guidance v1.1
//! adds. Section numbers in this crate refer to the v1.1 Draft Standard PDF.
//!
//! The wire format is the FIXP SBE message schema (`package="FIXP"`, schema id
//! [`SCHEMA_ID`] 2748, [`SCHEMA_VERSION`] 0, little-endian) from the
//! FIX Trading Community repository
//! <https://github.com/FIXTradingCommunity/fixp-specification>, file
//! `v1-1/resources/SBEschemaForFIXP.xml` at commit `af0e9d7e`, identical to
//! the v1.0 Technical Standard's copy. The schema is © FIX Protocol Ltd. and
//! licensed CC BY-ND 4.0. It is vendored byte for byte in the IronFix
//! repository under `ironfix-fixp/spec/`, with its license and provenance, as
//! the input of a conformance test; it is **not** part of the published
//! package, which is all MIT. The codec here is written by hand on
//! `ironsbe-core`'s SBE primitives, and that test checks it field by field
//! against the schema.
//!
//! ## Sans-IO
//!
//! Following ADR-0002 the core performs no I/O, runs no timers and reads no
//! clock. A driver owns the transport and feeds the session:
//!
//! - decoded session messages, through `handle_message`;
//! - the arrival of each application message, through
//!   `on_application_message`, which returns its implicit sequence number
//!   ([`Delivery`]);
//! - local commands: `negotiate` / `establish` (client),
//!   `accept_*` / `reject_*` (server), `send_application`, `terminate`,
//!   `retransmit`;
//! - transport changes: `on_transport_closed` (both roles) and, on a server
//!   whose session waits for its client to come back, `on_transport_opened`;
//! - timer ticks, through `handle_timeout`, at the instant `poll_timeout`
//!   names.
//!
//! Every input carries the current monotonic [`Instant`](std::time::Instant).
//! Request timestamps, which FIXP sends as wall-clock nanoseconds, are derived
//! from a [`ClockAnchor`] the driver supplies once. After each input the
//! driver drains `poll_output` and carries out each [`Output`] in order:
//! encode and write a message, close the transport, or report an [`Event`].
//!
//! ### Which transport an output belongs to
//!
//! A session has at most one transport at a time, and its outputs go to that
//! one:
//!
//! - the outputs drained right after `handle_message` or
//!   `on_application_message` belong to the transport that input came from;
//! - the outputs of `handle_timeout` and of a command belong to the
//!   transport currently bound to the session (for a client's `negotiate` or
//!   `establish`, the transport the driver has just opened).
//!
//! After [`Output::CloseTransport`] the session considers that transport
//! gone: what still arrives on it is reported as [`Event::Ignored`], and a
//! command that would send ([`FixpClient::establish`], for instance) fails
//! with [`FixpError::TransportClosing`] until the driver calls
//! `on_transport_closed`. Only then may it attach a new transport. A server
//! session left negotiated without a transport has no timer at all; the
//! driver that routes sessions decides when to evict it.
//!
//! The core does not frame bytes (`ironfix-sofh` does, and the engine will
//! compose the two) and does not store application messages: on a
//! Recoverable flow the driver keeps what it sends, by sequence number, and
//! replays it when the session asks (`retransmit` returns the range).
//!
//! ## What is implemented
//!
//! - **Negotiation** (section 4.2): Negotiate, NegotiationResponse,
//!   NegotiationReject, with optional credentials both ways. The server
//!   leaves the credential check to the application (`accept_negotiation` or
//!   `reject_negotiation`) and refuses a nil session identifier itself.
//! - **Establishment** (section 4.3): Establish, EstablishmentAck,
//!   EstablishmentReject, including re-establishment of a negotiated session
//!   on a new transport with its sequence numbers. The server refuses on its
//!   own an Establish without negotiation (`Unnegotiated`), a keepalive
//!   interval out of the configured range (`KeepaliveInterval`), a redundant
//!   Establish (`AlreadyEstablished`) and a `NextSeqNo` of zero or one that
//!   goes backwards (`Unspecified`); the application decides the rest
//!   (`accept_establishment` or `reject_establishment`).
//! - **Handshake timeouts**: every wait, on either side, is bounded by
//!   `handshake_timeout`, and a lapse closes the transport.
//! - **Sequencing** (section 3.5): implicit numbering after Sequence,
//!   EstablishmentAck or Retransmission, from 1 unless the first
//!   establishment announces another start; a Sequence before the first
//!   application message after any context switch; Context accepted as a
//!   Sequence when it names this session.
//! - **Recoverable flow** (section 4.6): gap detection, RetransmitRequest
//!   with one request in flight, chunked to `max_retransmit_count`, at most
//!   `max_pending_gaps` gaps of at most `max_gap_len` each, Retransmission
//!   batches validated against the request, RetransmitReject, and a
//!   configurable [`RetransmitStallPolicy`]. As the provider: requests
//!   validated and refused with `InvalidSession`, `RequestLimitExceeded` or
//!   `OutOfRange`, a request while one is answered terminated with
//!   `ReRequestInProgress`, answers in one or several batches.
//! - **Idempotent flow** (section 4.8): a gap is reported with NotApplied,
//!   numbered on this side's return flow; NotApplied and Applied from the
//!   counterparty are reported as events.
//! - **Unsequenced and None flows**: they fall out of the same machine.
//!   UnsequencedHeartbeat is their keepalive; Sequence, Context with a
//!   number and Retransmission on them, and any application message on a
//!   None flow, are protocol violations.
//! - **Keepalive** (section 4.5): a heartbeat whenever this side's interval
//!   passes without an application message, and termination when the
//!   counterparty is silent longer than its interval plus a grace period.
//! - **Termination** (section 4.4): Terminate and its answer, the initiator
//!   closing the transport, a keepalive interval to wait for the answer,
//!   in-flight messages (retransmitted ones included) still numbered while
//!   waiting, and messages after a Terminate ignored.
//! - **Receiving a finalization** (section 4.7): a counterparty's
//!   FinishedSending is answered with FinishedReceiving once every message
//!   up to its `LastSeqNo` is accounted for, after which this side waits for
//!   the counterparty's Terminate.
//!
//! ## Untrusted input
//!
//! A malformed message is a [`FixpDecodeError`], never a panic, and the
//! decoder copies at most the bytes present in its input. A well-formed
//! message that breaks the protocol is answered on the wire as FIXP v1.1
//! section 6.3 asks (Terminate once established, otherwise the transport
//! closed) and reported as [`Event::ProtocolViolation`]. Every sequence
//! number is computed with checked arithmetic: the outbound counter stops
//! with [`FixpError::SequenceExhausted`] before it would reach the `uint64`
//! null value, an inbound counter that would overflow terminates the session,
//! and a single jump in the counterparty's numbering above `max_gap_len`
//! terminates rather than being requested. Every timer setting is bounded by
//! [`MAX_TIMER`], so no deadline overflows and silently never fires. Every
//! `match` on a state or a message names its variants, and the crate denies
//! `clippy::wildcard_enum_match_arm` so it stays that way.
//!
//! Credentials are never logged or shown: [`Credentials`] prints only its
//! length in `Debug`, and a test captures every `tracing` line the session
//! emits through a handshake with credentials and checks none contains them.
//!
//! ## Decisions the specification leaves open
//!
//! Each is documented where it is implemented; in short:
//!
//! - A RetransmitRequest for numbers not yet sent gets RetransmitReject
//!   `OutOfRange` (section 4.6.2.3 and Appendix A 7.3.5), not a Terminate
//!   (section 6.3 lists it as a violation). A `Count` of zero is
//!   `OutOfRange` too.
//! - A Terminate is answered with code `Finished`.
//! - A `NextSeqNo` lower than expected terminates (Appendix A 7.2.2, 7.2.3);
//!   on a server's re-establishment it is refused with EstablishmentReject
//!   `Unspecified` instead.
//! - Numbering starts at 1 unless the first establishment announces another
//!   start (Appendix A 7.2.2 and 7.3.1 start at 100, 200 and 1000).
//! - A stalled RetransmitRequest is handled by the [`RetransmitStallPolicy`];
//!   the default asks again only after a Sequence cut a batch short
//!   (section 3.5.4), because a second request while the provider is still
//!   serving is a violation (sections 4.6.1, 4.6.4, 6.3).
//! - A RetransmitReject abandons the requested range: those messages are not
//!   requested again, and [`Event::RetransmitRejected`] says so.
//! - The counterparty's silence ends the session after its keepalive
//!   interval plus a grace equal to that interval by default.
//! - Session identifiers: any 16 bytes but the nil UUID are accepted; the
//!   RFC 4122 version bits are not checked.
//! - NotApplied is sent on this side's flow, and not at all when this side's
//!   flow is None. Applied is reported whatever this side's flow: FIXP names
//!   no violation for it, unlike NotApplied.
//! - A Context `NextSeqNo` of `u64::MAX`, the SBE null value, means "no
//!   number given".
//!
//! ## Not implemented
//!
//! - **Sending a finalization** (section 4.7): this side never sends
//!   FinishedSending, so it never finalizes a logical session itself; a
//!   FinishedReceiving from the counterparty is therefore a violation.
//! - **Multiplexing** (section 3.5.3): one session per transport. A Context
//!   naming another session terminates.
//! - **Datagram transports** (section 3.5.2): the core assumes a stream; it
//!   does not open every datagram with a Sequence.
//! - **Multicast** (section 5): Topic is a protocol violation here.
//! - **WebSocket** (section 4.9) and in-band templates (section 3.6:
//!   MessageTemplate is decoded and passed over, not applied).
//! - **Persistence**: sequence numbers live in memory, so a session cannot be
//!   re-established by a new process.
//! - **Engine wiring**: no driver exists yet; FIXP over SOFH in
//!   `ironfix-engine` is ADR-0003's follow-up.
//!
//! ## Example
//!
//! A client and a server negotiating and establishing in memory:
//!
//! ```
//! use ironfix_core::Timestamp;
//! use ironfix_fixp::{
//!     ClockAnchor, FixpClient, FixpConfig, FixpServer, FlowType, Output, SessionId,
//!     SessionMessage, SessionStatus,
//! };
//! use std::time::Instant;
//!
//! /// Encodes and decodes each queued message, as a transport would, and
//! /// delivers it.
//! fn relay(outputs: Vec<Output>, deliver: &mut dyn FnMut(&SessionMessage)) {
//!     for output in outputs {
//!         if let Output::Send(message) = output {
//!             let mut wire = Vec::new();
//!             if message.encode(&mut wire).is_ok() {
//!                 if let Ok((decoded, _)) = SessionMessage::decode(&wire) {
//!                     deliver(&decoded);
//!                 }
//!             }
//!         }
//!     }
//! }
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let now = Instant::now();
//!     let clock = ClockAnchor::new(now, Timestamp::from_nanos(1_760_000_000_000_000_000)?);
//!     let session_id = SessionId::from_bytes([0x42; 16]);
//!
//!     let mut client =
//!         FixpClient::new(FixpConfig::default(), clock, session_id, FlowType::Idempotent, None);
//!     let mut server = FixpServer::new(FixpConfig::default(), clock, now);
//!
//!     client.negotiate(now)?;
//!     relay(std::iter::from_fn(|| client.poll_output()).collect(), &mut |m| {
//!         server.handle_message(m, now)
//!     });
//!     // The server's application would check the credentials here.
//!     server.accept_negotiation(FlowType::Recoverable, None, now)?;
//!     relay(std::iter::from_fn(|| server.poll_output()).collect(), &mut |m| {
//!         client.handle_message(m, now)
//!     });
//!
//!     client.establish(now)?;
//!     relay(std::iter::from_fn(|| client.poll_output()).collect(), &mut |m| {
//!         server.handle_message(m, now)
//!     });
//!     server.accept_establishment(now)?;
//!     relay(std::iter::from_fn(|| server.poll_output()).collect(), &mut |m| {
//!         client.handle_message(m, now)
//!     });
//!
//!     assert_eq!(client.status(), SessionStatus::Established);
//!     assert_eq!(server.status(), SessionStatus::Established);
//!     // The first application message is number 1, behind a Sequence.
//!     assert_eq!(client.send_application(now)?.map(|seq| seq.value()), Some(1));
//!     Ok(())
//! }
//! ```

#![deny(clippy::wildcard_enum_match_arm)]

mod client;
mod clock;
mod codec;
mod config;
mod error;
mod messages;
mod output;
mod role;
mod server;
mod session;
#[cfg(test)]
mod testkit;
mod types;

pub use client::FixpClient;
pub use clock::ClockAnchor;
pub use codec::is_session_message;
pub use config::{
    DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_KEEPALIVE_INTERVAL, DEFAULT_MAX_GAP_LEN,
    DEFAULT_MAX_PEER_KEEPALIVE, DEFAULT_MAX_PENDING_GAPS, DEFAULT_MAX_RETRANSMIT_COUNT,
    DEFAULT_MIN_PEER_KEEPALIVE, DEFAULT_RETRANSMIT_TIMEOUT, FixpConfig, FixpConfigBuilder,
    FixpConfigError, MAX_TIMER, RetransmitStallPolicy,
};
pub use error::{FixpDecodeError, FixpEncodeError, FixpError};
pub use messages::{
    Applied, Context, Establish, EstablishmentAck, EstablishmentReject, FinishedReceiving,
    FinishedSending, MessageTemplate, Negotiate, NegotiationReject, NegotiationResponse,
    NotApplied, Retransmission, RetransmitReject, RetransmitRequest, SCHEMA_ID, SCHEMA_VERSION,
    Sequence, SessionMessage, Terminate, Topic, UnsequencedHeartbeat,
};
pub use output::{
    Delivery, Event, HandshakeStage, Output, RetransmitBatch, SessionStatus, TerminatedBy,
};
pub use server::FixpServer;
pub use types::{
    Credentials, EstablishmentRejectCode, FlowType, MAX_VAR_DATA_LEN, Nanotime,
    NegotiationRejectCode, RetransmitRejectCode, SessionId, TerminationCode,
};

/// Re-exported from `ironfix-core`: [`ClockAnchor::new`] takes a
/// [`Timestamp`], and sequence numbers in this API are [`SeqNum`]s, so a
/// driver does not need its own `ironfix-core` dependency.
pub use ironfix_core::{SeqNum, Timestamp};
