/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! FIXP v1.1 over SOFH, in both roles (issue #96, ADR-0003). Compiled with
//! the `fixp` feature only.
//!
//! [`FixpInitiator`] and [`FixpAcceptor`] mirror the tag=value
//! [`Initiator`](crate::Initiator) and [`Acceptor`](crate::Acceptor): each
//! transport gets a driver task that frames bytes with
//! [`ironfix_sofh::SofhCodec`] and feeds the sans-IO session core of
//! [`ironfix_fixp`] (ADR-0002), with timers from the tokio clock. The
//! application sees the handshake decisions, opaque application messages
//! ([`FixpInbound`]: the bytes after the SOFH header; decoding a business
//! schema is the application's job) and every core [`Event`].
//!
//! What the driver adds to the core:
//!
//! - **Routing** (SOFH v1.0; FIXP v1.1 section 3.1): a frame with encoding
//!   type SBE 1.0 little-endian whose SBE header names the FIXP schema
//!   (id 2748) is a session message; anything else is an application
//!   message, numbered implicitly by the core (section 3.5.1). Sending an
//!   application payload that names the FIXP schema is refused
//!   ([`FixpEngineError::ReservedSchema`]).
//! - **Retransmission** (section 4.6.2): on a Recoverable outbound flow the
//!   driver keeps the last [`DEFAULT_RETRANSMIT_CAPACITY`] messages (a
//!   setting), in memory, and answers a RetransmitRequest in one batch: the
//!   stored frames are written right after the Retransmission header. A
//!   request for messages no longer kept gets RetransmitReject `OutOfRange`
//!   (section 4.6.2.3).
//! - **Finalized identifiers** (sections 4.7.2, 6.3): the core records
//!   finalization per role instance only, so [`FixpAcceptor`] remembers
//!   finalized (and live) identifiers across its transports and refuses a
//!   Negotiate naming one with NegotiationReject `DuplicateId`.
//! - **Untrusted input**: a SOFH framing error closes the transport (SOFH
//!   has no resynchronisation point); a frame naming the FIXP schema that
//!   does not decode is a protocol violation, answered with Terminate
//!   `UnspecifiedError` once established (section 6.3) and by closing the
//!   transport before. Neither panics.
//! - **Credentials** are never logged: [`Credentials`](ironfix_fixp::Credentials),
//!   and every engine type that holds them, print only their length.
//!
//! Not implemented: re-establishing an unbound session on a new transport
//! (the core supports it; these entry points do not drive it), persistence
//! of sequence numbers or sent messages across processes, multiplexing
//! (section 3.5.3), and sending a finalization (FinishedSending,
//! section 4.7). No performance figure is claimed for this path.

mod acceptor;
mod application;
mod connection;
mod driver;
mod error;
mod initiator;

use std::time::Duration;

pub use acceptor::FixpAcceptor;
pub use application::{
    EstablishRequest, EstablishmentDecision, FixpApplication, FixpInbound, NegotiateRequest,
    NegotiationDecision,
};
pub use connection::FixpConnection;
pub use error::FixpEngineError;
pub use initiator::{DEFAULT_FIXP_CONNECT_TIMEOUT, FixpInitiator};

/// The crates this module composes, re-exported so that an application
/// needs no dependency of its own on them: the session core (configuration,
/// flows, identifiers, events, session messages) and SOFH framing.
pub use ironfix_fixp;
pub use ironfix_sofh;

pub use ironfix_fixp::Event;

/// Default number of sent application messages kept for retransmission on a
/// Recoverable flow.
pub const DEFAULT_RETRANSMIT_CAPACITY: usize = 10_000;

/// Default bound on one write and flush.
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
