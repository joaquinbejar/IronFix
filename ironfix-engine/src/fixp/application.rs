/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! The callbacks a FIXP application implements, and the decisions it returns.

use crate::fixp::connection::FixpConnection;
use async_trait::async_trait;
use bytes::Bytes;
use ironfix_core::SeqNum;
use ironfix_fixp::{
    Credentials, EstablishmentRejectCode, Event, FlowType, NegotiationRejectCode, SessionId,
};
use ironfix_sofh::EncodingType;
use std::time::Duration;

/// A Negotiate the server received (FIXP v1.1 section 4.2.1), for the
/// application to accept or refuse.
///
/// `Debug` shows the credentials' length only, never their bytes.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NegotiateRequest {
    /// The identifier the client chose for the session.
    pub session_id: SessionId,
    /// The flow type the client announces for client-to-server messages.
    pub client_flow: FlowType,
    /// The client's credentials, if it sent any. Checking them is the
    /// application's job: FIXP leaves their format to the counterparties.
    pub credentials: Option<Credentials>,
}

/// An Establish the server received (FIXP v1.1 section 4.3.1), for the
/// application to accept or refuse. The core has already refused, on its
/// own, the ones FIXP makes invalid (no negotiation, a keepalive out of
/// range, a `NextSeqNo` that goes backwards).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EstablishRequest {
    /// The session being bound.
    pub session_id: SessionId,
    /// The client's keepalive interval.
    pub keepalive_interval: Duration,
    /// The client's next outbound sequence number, on a sequenced flow.
    pub next_seq_no: Option<SeqNum>,
    /// The client's credentials, if it sent any (they travel in every
    /// Establish).
    pub credentials: Option<Credentials>,
}

/// The server application's answer to a Negotiate.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum NegotiationDecision {
    /// Accept, serving server-to-client messages on `server_flow`, with
    /// optional server credentials for mutual authentication
    /// (section 4.2.2).
    Accept {
        /// The flow type of server-to-client messages.
        server_flow: FlowType,
        /// Credentials identifying the server, if any.
        credentials: Option<Credentials>,
    },
    /// Refuse with a NegotiationReject (section 4.2.3); the transport is
    /// closed.
    Reject {
        /// The code sent to the client.
        code: NegotiationRejectCode,
        /// A free-text reason sent to the client.
        reason: String,
    },
}

/// The server application's answer to an Establish.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum EstablishmentDecision {
    /// Bind the session with an EstablishmentAck (section 4.3.2).
    Accept,
    /// Refuse with an EstablishmentReject (section 4.3.3); the transport is
    /// closed.
    Reject {
        /// The code sent to the client.
        code: EstablishmentRejectCode,
        /// A free-text reason sent to the client.
        reason: String,
    },
}

/// An application message received from the counterparty.
///
/// FIXP carries business messages opaquely: decoding them, with whatever
/// SBE schema the counterparties agreed, is the application's job. `Debug`
/// shows the payload's length only.
#[derive(Clone)]
#[non_exhaustive]
pub struct FixpInbound {
    /// The message's implicit sequence number (FIXP v1.1 section 3.5.1), on
    /// a sequenced flow.
    pub seq: Option<SeqNum>,
    /// `true` when it arrived in a Retransmission batch (section 4.6.2).
    pub retransmitted: bool,
    /// The SOFH encoding type the counterparty framed it with.
    pub encoding_type: EncodingType,
    /// The message bytes, SOFH header excluded. A view of the read buffer:
    /// copy it before keeping many of them.
    pub payload: Bytes,
}

impl std::fmt::Debug for FixpInbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FixpInbound")
            .field("seq", &self.seq)
            .field("retransmitted", &self.retransmitted)
            .field("encoding_type", &self.encoding_type)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// The callbacks of a FIXP session, in either role.
///
/// `on_established`, `on_message`, `on_event` and `on_closed` run in order
/// in a callback task of their own, never in the driver task, so they may
/// await [`FixpConnection::send`], `terminate` or `wait_closed` on their own
/// session without deadlocking. While more than 1024 callbacks wait to run,
/// the driver stops reading the transport (backpressure) but keeps sending,
/// answering commands and running its timers.
///
/// `on_negotiate` and `on_establish` each run in a task of their own while
/// the driver keeps reading and running the core's handshake deadline
/// (`FixpConfig::handshake_timeout`). If that deadline lapses or the
/// counterparty disconnects first, the task is aborted, the transport is
/// closed and the acceptor releases the session id; a late answer is
/// dropped. A request left undecided (the deadline lapsed, the task
/// panicked, or the core refused the acceptance, as for two None flows) is
/// answered with NegotiationReject or EstablishmentReject before the close
/// (FIXP v1.1 sections 4.2.3 and 4.3). The session has no handle yet, so
/// they cannot wait on it.
#[async_trait]
pub trait FixpApplication: Send + Sync + 'static {
    /// A client asks to negotiate a session (server role only).
    ///
    /// The default refuses with `Credentials`: a server must decide who may
    /// open a session, so accepting is an explicit choice.
    async fn on_negotiate(&self, request: &NegotiateRequest) -> NegotiationDecision {
        let _ = request;
        NegotiationDecision::Reject {
            code: NegotiationRejectCode::Credentials,
            reason: "negotiation not accepted".to_owned(),
        }
    }

    /// A client asks to bind its negotiated session (server role only).
    ///
    /// The default accepts: the identity was checked at negotiation.
    async fn on_establish(&self, request: &EstablishRequest) -> EstablishmentDecision {
        let _ = request;
        EstablishmentDecision::Accept
    }

    /// The session is established; `connection` sends on it.
    async fn on_established(&self, connection: FixpConnection) {
        let _ = connection;
    }

    /// An application message arrived and the session accepted it.
    async fn on_message(&self, session_id: SessionId, message: FixpInbound);

    /// Every event the session core reports (gaps, recovery, termination,
    /// violations, finalization...), in order.
    async fn on_event(&self, session_id: Option<SessionId>, event: &Event) {
        let _ = (session_id, event);
    }

    /// The transport is closed and the driver task is ending.
    async fn on_closed(&self, session_id: Option<SessionId>) {
        let _ = session_id;
    }
}
