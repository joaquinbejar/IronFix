/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! What the session core hands back to its driver.
//!
//! The core never touches a transport. After every input the driver drains
//! [`Output`]s with `poll_output` and carries them out in order: encode and
//! write the messages, close the transport, report the events. The order
//! matters: a [`Output::Send`] of a Sequence queued by `send_application` must
//! reach the wire before the application message it announces.

use crate::messages::SessionMessage;
use crate::types::{
    EstablishmentRejectCode, FlowType, NegotiationRejectCode, RetransmitRejectCode, SessionId,
    TerminationCode,
};
use ironfix_core::SeqNum;
use std::time::Duration;

/// One thing for the driver to do.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Output {
    /// Encode this session message and write it to the transport.
    Send(SessionMessage),
    /// Encode this message and write it to the transport. It is an
    /// application message the session generated itself (a NotApplied,
    /// FIXP v1.1 section 4.8.2): on a sequenced flow it consumes `seq`, so
    /// the driver keeps it for retransmission exactly like the application
    /// messages it sends itself.
    SendApplication {
        /// The sequence number it consumes, `None` on an Unsequenced flow.
        seq: Option<SeqNum>,
        /// The message.
        message: SessionMessage,
    },
    /// Close the transport.
    CloseTransport,
    /// Report this to the application.
    Event(Event),
}

/// Which side started the unbinding of a transport.
///
/// Not named `Initiator`: `ironfix_engine::Initiator` is the tag=value
/// client engine, and the engine's FIXP wiring imports both crates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminatedBy {
    /// This side.
    Local,
    /// The counterparty.
    Peer,
}

/// Which handshake ran out of time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HandshakeStage {
    /// Negotiation: a client waiting for NegotiationResponse, or a server
    /// waiting for Negotiate or for the application's answer to one.
    Negotiation,
    /// Establishment: a client waiting for EstablishmentAck, or a server
    /// waiting for an Establish on a transport or for the application's
    /// answer to one.
    Establishment,
}

/// Something the application should know.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// Server: a Negotiate arrived. Check its credentials (in the decoded
    /// message) and answer with `accept_negotiation` or `reject_negotiation`.
    NegotiateReceived {
        /// The session the client asks for.
        session_id: SessionId,
        /// The flow type the client asks for.
        client_flow: FlowType,
    },
    /// Both roles: the logical session exists (FIXP v1.1 section 4.2.2).
    Negotiated {
        /// The session identifier.
        session_id: SessionId,
        /// Flow type from client to server.
        client_flow: FlowType,
        /// Flow type from server to client.
        server_flow: FlowType,
    },
    /// Client: the server refused the Negotiate (FIXP v1.1 section 4.2.3).
    /// The session is closed; negotiate again with a new session identifier.
    NegotiationRejected {
        /// The server's reason code.
        code: NegotiationRejectCode,
        /// The server's reason text, empty if none.
        reason: String,
    },
    /// Server: an acceptable Establish arrived. Check its credentials (in
    /// the decoded message) and answer with `accept_establishment` or
    /// `reject_establishment`.
    EstablishReceived {
        /// The session being bound.
        session_id: SessionId,
        /// The client's keepalive interval.
        keepalive_interval: Duration,
        /// The client's next sequence number, if it sent one.
        next_seq_no: Option<SeqNum>,
    },
    /// Both roles: the session is bound to the transport and application
    /// messages may flow (FIXP v1.1 section 4.3).
    Established {
        /// The counterparty's keepalive interval.
        peer_keepalive_interval: Duration,
        /// The counterparty's next sequence number, if it sent one.
        peer_next_seq_no: Option<SeqNum>,
    },
    /// Client: the server refused the Establish (FIXP v1.1 section 4.3.3).
    /// The session stays negotiated unless the code is `Unnegotiated`.
    EstablishmentRejected {
        /// The server's reason code.
        code: EstablishmentRejectCode,
        /// The server's reason text, empty if none.
        reason: String,
    },
    /// This side refused a counterparty request on its own, on the wire.
    Refused {
        /// The reject message sent: NegotiationReject, EstablishmentReject
        /// or RetransmitReject.
        message: &'static str,
        /// Why.
        reason: &'static str,
    },
    /// A handshake response did not arrive in time.
    HandshakeTimedOut {
        /// Which handshake.
        stage: HandshakeStage,
    },
    /// The counterparty's sequenced flow skipped `count` messages from
    /// `from`. On a Recoverable flow the session requests them; on an
    /// Idempotent flow it sends NotApplied (FIXP v1.1 sections 4.6 and 4.8.2).
    SequenceGap {
        /// The first missing sequence number.
        from: SeqNum,
        /// How many are missing.
        count: u64,
    },
    /// No gap remains outstanding on the counterparty's Recoverable flow:
    /// every one was retransmitted or abandoned (see
    /// [`Event::RetransmitRejected`]). Messages queued behind a gap can be
    /// processed in order.
    RecoveryComplete,
    /// The counterparty asked this side to retransmit. Answer with
    /// `retransmit` batches, or refuse with `reject_retransmit_request`.
    RetransmitRequested {
        /// The first sequence number requested.
        from: SeqNum,
        /// How many messages.
        count: u32,
    },
    /// The counterparty refused this side's RetransmitRequest. The requested
    /// range is abandoned: those messages will not be recovered.
    RetransmitRejected {
        /// The first sequence number requested.
        from: SeqNum,
        /// How many messages were requested.
        count: u32,
        /// The counterparty's reason code.
        code: RetransmitRejectCode,
        /// The counterparty's reason text, empty if none.
        reason: String,
    },
    /// This side's RetransmitRequest went `retransmit_timeout` without a
    /// retransmitted message. What happens next depends on
    /// [`RetransmitStallPolicy`](crate::RetransmitStallPolicy): nothing more,
    /// a new request for what is missing (visible as a queued
    /// RetransmitRequest), or a Terminate. Reported once per stall.
    RetransmitTimedOut {
        /// The first sequence number of the request that stalled.
        from: SeqNum,
        /// How many messages it asked for.
        count: u32,
    },
    /// The counterparty reports operations of this side's Idempotent flow it
    /// did not apply (FIXP v1.1 section 4.8.2). Recovery, if any, is the
    /// application's decision.
    NotApplied {
        /// The first sequence number not applied, as received.
        from_seq_no: u64,
        /// How many, as received.
        count: u32,
    },
    /// The counterparty acknowledges operations of this side's flow
    /// (FIXP v1.1 section 4.8.1).
    Applied {
        /// The first sequence number applied, as received.
        from_seq_no: u64,
        /// How many, as received.
        count: u32,
    },
    /// The binding ended with a Terminate (FIXP v1.1 section 4.4). The
    /// logical session survives: a client may Establish it again.
    Terminated {
        /// The termination code of the side that started it.
        code: TerminationCode,
        /// Its reason text, empty if none.
        reason: String,
        /// Which side started it.
        by: TerminatedBy,
    },
    /// The counterparty was silent longer than its keepalive interval plus
    /// the grace period; the session terminated (FIXP v1.1 section 4.5).
    KeepaliveLapsed,
    /// The counterparty violated the protocol (FIXP v1.1 section 6.3). The
    /// session answered on the wire as the specification requires (a
    /// Terminate once established, otherwise closing the transport).
    ProtocolViolation {
        /// What the counterparty did.
        reason: &'static str,
    },
    /// The counterparty sent FinishedSending: its flow is ending (FIXP v1.1
    /// section 4.7.1). The session answers with FinishedReceiving once every
    /// message up to `last_seq_no` is accounted for (retransmitted, or
    /// reported with NotApplied), then waits for the counterparty's
    /// Terminate. Application messages after it are protocol violations.
    PeerFinishedSending {
        /// The counterparty's last sequence number, as received.
        last_seq_no: Option<u64>,
    },
    /// The driver reported the transport closed.
    TransportClosed,
    /// A message was ignored without answering: a response that matches no
    /// outstanding request (FIXP v1.1 Appendix A 7.1.7.5 and 7.1.12.8),
    /// anything after a Terminate (section 4.4), or anything still arriving
    /// on a transport this side has asked the driver to close.
    Ignored {
        /// The message name.
        message: &'static str,
        /// Why.
        reason: &'static str,
    },
}

/// What to do with an application message just received, as decided by
/// `on_application_message`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Delivery {
    /// Deliver it to the application.
    Accept {
        /// Its implicit sequence number on a sequenced flow, `None` on an
        /// Unsequenced flow.
        seq: Option<SeqNum>,
        /// `true` if it arrived in a retransmission batch.
        retransmitted: bool,
    },
    /// Ignore it, for one of three reasons:
    ///
    /// - it broke the protocol, and the session has already answered that;
    /// - it arrived after a Terminate (FIXP v1.1 sections 4.4 and 6.3);
    /// - it is a valid retransmission of a number this session already
    ///   delivered live, discarded so that a Recoverable flow stays exactly
    ///   once (section 3.4.4).
    Discard,
}

/// The messages to replay after a `retransmit` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RetransmitBatch {
    /// The sequence number of the first message to replay.
    pub from: SeqNum,
    /// How many consecutive messages to replay.
    pub count: u32,
}

/// The externally visible state of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionStatus {
    /// Client: nothing sent yet.
    Idle,
    /// Client: Negotiate sent, waiting for the answer.
    Negotiating,
    /// Server: waiting for a Negotiate.
    AwaitingNegotiate,
    /// Server: Negotiate received, waiting for the application's decision.
    NegotiationPending,
    /// Both: the logical session exists but is not bound to a transport.
    Negotiated,
    /// Client: Establish sent, waiting for the answer.
    Establishing,
    /// Server: Establish received, waiting for the application's decision.
    EstablishPending,
    /// Both: bound; application messages may flow.
    Established,
    /// Both: this side sent a Terminate and waits for the answer.
    Terminating,
    /// Both: this side answered the counterparty's Terminate and waits for
    /// the transport to close.
    Closing,
    /// Both: the session is over; this object accepts no more commands.
    Closed,
}
