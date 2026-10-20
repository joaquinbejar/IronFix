/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! The server (acceptor) role of a FIXP point-to-point session.
//!
//! ```text
//!                      Negotiate                accept_negotiation              Establish
//!   AwaitingNegotiate ──────────▶ NegotiationPending ──────────▶ Negotiated ──────────▶ EstablishPending
//!         │ nil id, timeout          │ reject_negotiation          ▲   ▲                   │
//!         ▼                          ▼                             │   └ reject_establishment
//!       Closed ◀───────────────── Closed                          │                       │ accept_establishment
//!                                    Terminate, violation,         │                       ▼
//!                                    keepalive lapse, closed ──────┴─────────────── Established
//!                                                                              (Terminating, Closing)
//! ```
//!
//! Credentials are the application's to check: the server stops at
//! `NegotiationPending` and `EstablishPending`, reports the request as an
//! event, and continues when the application calls `accept_*` or `reject_*`.
//! The decisions the protocol fixes are taken here, on the wire: a nil
//! session identifier, an Establish before any negotiation, a keepalive
//! interval out of range, a `NextSeqNo` that goes backwards, and a redundant
//! Establish (FIXP v1.1 sections 4.2.3 and 4.3.3; Appendix A 7.1.7.3 and
//! 7.1.12).
//!
//! Every wait is bounded by [`FixpConfig::handshake_timeout`]: for a
//! Negotiate, for the application's answer to it, for an Establish on a
//! transport, and for the application's answer to that. When one lapses the
//! server asks for the transport to be closed; a Negotiate or Establish the
//! application left unanswered is first refused with NegotiationReject or
//! EstablishmentReject `Unspecified`, since FIXP v1.1 answers every such
//! request (section 4.2.3, p. 18: a server "must send NegotiationReject";
//! section 4.3, p. 19: the response to Establish "is either
//! EstablishmentAck or EstablishmentReject").
//!
//! One `FixpServer` serves one session. A driver serving several routes each
//! Negotiate and Establish by session identifier
//! ([`SessionMessage::session_id`]); duplicate-identifier detection across
//! sessions (`DuplicateId`) needs that registry and is the application's
//! call through `reject_negotiation`.
//!
//! # Transports
//!
//! A negotiated session outlives its transport. When a client comes back on
//! a new one, the driver reports the old transport closed
//! (`on_transport_closed`), then the new one opened (`on_transport_opened`,
//! which arms the Establish deadline), then routes the Establish here. A
//! Negotiate or Establish still arriving on a transport that is being
//! unbound (this side terminating, or answering the counterparty's
//! Terminate) is not answered: it is reported as
//! [`Event::Ignored`], and the client must retry on a
//! new transport. A session left negotiated with no transport has no timer;
//! evicting it is the driver's policy.

use crate::client::elapsed;
use crate::clock::{ClockAnchor, RequestClock};
use crate::config::FixpConfig;
use crate::error::FixpError;
use crate::messages::{
    Establish, EstablishmentAck, EstablishmentReject, Negotiate, NegotiationReject,
    NegotiationResponse, SessionMessage,
};
use crate::output::{Event, HandshakeStage, SessionStatus, TerminatedBy};
use crate::role::bound_api;
use crate::session::{
    APPLICATION_MESSAGE, Binding, Bound, Classified, Core, HandshakeMessage, PeerMessage, Session,
    check_reason, classify,
};
use crate::types::{
    Credentials, EstablishmentRejectCode, FlowType, Nanotime, NegotiationRejectCode, SessionId,
};
use ironfix_core::SeqNum;
use std::time::{Duration, Instant};

/// Why a server is closed for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClosedReason {
    NegotiationRejected,
    HandshakeTimedOut,
    ProtocolViolation,
    TransportClosed,
    /// The logical session is finalized (FIXP v1.1 section 4.7.2); its
    /// identifier may not be negotiated or established again (section 6.3).
    Finalized(SessionId),
}

#[derive(Debug)]
enum ServerState {
    AwaitingNegotiate {
        since: Instant,
    },
    NegotiationPending {
        session_id: SessionId,
        request: Nanotime,
        client_flow: FlowType,
        /// When the transport is closed if the application has not answered.
        deadline: Option<Instant>,
    },
    Negotiated {
        session: Box<Session>,
        /// When this transport is closed if no Establish arrives.
        deadline: Option<Instant>,
    },
    EstablishPending {
        session: Box<Session>,
        request: Nanotime,
        keepalive: u32,
        next_seq_no: Option<u64>,
        /// When the transport is closed if the application has not answered.
        deadline: Option<Instant>,
    },
    Bound {
        session: Box<Session>,
        binding: Binding,
    },
    Closed(ClosedReason),
}

impl ServerState {
    const fn status(&self) -> SessionStatus {
        match self {
            Self::AwaitingNegotiate { .. } => SessionStatus::AwaitingNegotiate,
            Self::NegotiationPending { .. } => SessionStatus::NegotiationPending,
            Self::Negotiated { .. } => SessionStatus::Negotiated,
            Self::EstablishPending { .. } => SessionStatus::EstablishPending,
            Self::Bound { binding, .. } => binding.status(),
            Self::Closed(ClosedReason::Finalized(_)) => SessionStatus::Finalized,
            Self::Closed(
                ClosedReason::NegotiationRejected
                | ClosedReason::HandshakeTimedOut
                | ClosedReason::ProtocolViolation
                | ClosedReason::TransportClosed,
            ) => SessionStatus::Closed,
        }
    }
}

/// A FIXP server: the side that accepts negotiations and establishments.
///
/// Sans-IO, like [`FixpClient`](crate::FixpClient): decoded session
/// messages, application-message arrivals, commands and timer ticks in, each
/// with the current [`Instant`]; [`Output`](crate::Output)s out.
#[derive(Debug)]
pub struct FixpServer {
    core: Core,
    state: ServerState,
}

impl FixpServer {
    /// Creates a server for a transport accepted at `now`, waiting for a
    /// Negotiate. Without one within the handshake timeout the transport is
    /// closed.
    #[must_use]
    pub fn new(config: FixpConfig, clock: ClockAnchor, now: Instant) -> Self {
        Self {
            core: Core::new(config, RequestClock::new(clock)),
            state: ServerState::AwaitingNegotiate { since: now },
        }
    }

    /// The current state.
    #[must_use]
    pub const fn status(&self) -> SessionStatus {
        self.state.status()
    }

    /// The session identifier, once a Negotiate has named it. A finalized
    /// session keeps it, so a driver can refuse to route it again.
    #[must_use]
    pub fn session_id(&self) -> Option<SessionId> {
        match &self.state {
            ServerState::NegotiationPending { session_id, .. } => Some(*session_id),
            ServerState::Negotiated { session, .. }
            | ServerState::EstablishPending { session, .. }
            | ServerState::Bound { session, .. } => Some(session.id()),
            ServerState::Closed(ClosedReason::Finalized(session_id)) => Some(*session_id),
            ServerState::AwaitingNegotiate { .. }
            | ServerState::Closed(
                ClosedReason::NegotiationRejected
                | ClosedReason::HandshakeTimedOut
                | ClosedReason::ProtocolViolation
                | ClosedReason::TransportClosed,
            ) => None,
        }
    }

    /// The flow type from client to server, once a Negotiate has named it.
    #[must_use]
    pub fn client_flow(&self) -> Option<FlowType> {
        match &self.state {
            ServerState::NegotiationPending { client_flow, .. } => Some(*client_flow),
            ServerState::Negotiated { session, .. }
            | ServerState::EstablishPending { session, .. }
            | ServerState::Bound { session, .. } => Some(session.remote_flow()),
            ServerState::AwaitingNegotiate { .. } | ServerState::Closed(_) => None,
        }
    }

    /// The flow type from server to client, once negotiated.
    #[must_use]
    pub fn server_flow(&self) -> Option<FlowType> {
        self.session().map(Session::local_flow)
    }

    /// Accepts the pending Negotiate with server flow `server_flow`
    /// (FIXP v1.1 section 4.2.2). `credentials` identify the server to the
    /// client, for mutual authentication.
    ///
    /// # Errors
    /// [`FixpError::InvalidState`] unless a Negotiate is pending, and
    /// [`FixpError::BothFlowsNone`] when the client flow is None too
    /// (section 3.4.4.1); the Negotiate stays pending.
    pub fn accept_negotiation(
        &mut self,
        server_flow: FlowType,
        credentials: Option<Credentials>,
        now: Instant,
    ) -> Result<(), FixpError> {
        let state = std::mem::replace(
            &mut self.state,
            ServerState::Closed(ClosedReason::TransportClosed),
        );
        match state {
            ServerState::NegotiationPending {
                session_id,
                request,
                client_flow,
                deadline,
            } => {
                if client_flow == FlowType::None && server_flow == FlowType::None {
                    self.state = ServerState::NegotiationPending {
                        session_id,
                        request,
                        client_flow,
                        deadline,
                    };
                    return Err(FixpError::BothFlowsNone);
                }
                tracing::debug!(%session_id, ?client_flow, ?server_flow, "fixp negotiation accepted");
                self.core
                    .send(SessionMessage::NegotiationResponse(NegotiationResponse {
                        session_id,
                        request_timestamp: request,
                        server_flow,
                        credentials,
                    }));
                self.core.event(Event::Negotiated {
                    session_id,
                    client_flow,
                    server_flow,
                });
                self.state = ServerState::Negotiated {
                    session: Box::new(Session::new(session_id, server_flow, client_flow)),
                    deadline: now.checked_add(self.core.config().handshake_timeout()),
                };
                Ok(())
            }
            other @ (ServerState::AwaitingNegotiate { .. }
            | ServerState::Negotiated { .. }
            | ServerState::EstablishPending { .. }
            | ServerState::Bound { .. }
            | ServerState::Closed(_)) => self.refuse_command(other, "accept_negotiation"),
        }
    }

    /// Refuses the pending Negotiate (FIXP v1.1 section 4.2.3) and closes
    /// the transport.
    ///
    /// # Errors
    /// [`FixpError::InvalidState`] unless a Negotiate is pending, and
    /// [`FixpError::ReasonTooLong`].
    pub fn reject_negotiation(
        &mut self,
        code: NegotiationRejectCode,
        reason: impl Into<String>,
    ) -> Result<(), FixpError> {
        let reason = reason.into();
        check_reason(&reason)?;
        let state = std::mem::replace(
            &mut self.state,
            ServerState::Closed(ClosedReason::TransportClosed),
        );
        match state {
            ServerState::NegotiationPending {
                session_id,
                request,
                ..
            } => {
                tracing::debug!(%session_id, ?code, "fixp negotiation rejected");
                self.core
                    .send(SessionMessage::NegotiationReject(NegotiationReject {
                        session_id,
                        request_timestamp: request,
                        code,
                        reason,
                    }));
                self.core.close_transport();
                self.state = ServerState::Closed(ClosedReason::NegotiationRejected);
                Ok(())
            }
            other @ (ServerState::AwaitingNegotiate { .. }
            | ServerState::Negotiated { .. }
            | ServerState::EstablishPending { .. }
            | ServerState::Bound { .. }
            | ServerState::Closed(_)) => self.refuse_command(other, "reject_negotiation"),
        }
    }

    /// Accepts the pending Establish (FIXP v1.1 section 4.3.2): sends
    /// EstablishmentAck and binds the session.
    ///
    /// On a sequenced server flow the Ack announces the next outbound
    /// sequence number. If the client's `NextSeqNo` shows messages this side
    /// missed, a RetransmitRequest (Recoverable client flow) or NotApplied
    /// (Idempotent) follows the Ack (section 4.3.1).
    ///
    /// # Errors
    /// [`FixpError::InvalidState`] unless an Establish is pending.
    pub fn accept_establishment(&mut self, now: Instant) -> Result<(), FixpError> {
        let state = std::mem::replace(
            &mut self.state,
            ServerState::Closed(ClosedReason::TransportClosed),
        );
        match state {
            ServerState::EstablishPending {
                mut session,
                request,
                keepalive,
                next_seq_no,
                ..
            } => {
                let local = self.core.config().keepalive_interval();
                let remote = Duration::from_millis(u64::from(keepalive));
                let mut binding = session.bind(now, local, remote);
                tracing::debug!(session_id = %session.id(), "fixp established");
                self.core
                    .send(SessionMessage::EstablishmentAck(EstablishmentAck {
                        session_id: session.id(),
                        request_timestamp: request,
                        keepalive_interval: self.core.config().keepalive_millis(),
                        next_seq_no: session.announced_next_seq(),
                    }));
                self.core.event(Event::Established {
                    peer_keepalive_interval: remote,
                    peer_next_seq_no: next_seq_no.map(SeqNum::new),
                });
                self.state =
                    match session.on_established(&mut self.core, &mut binding, next_seq_no, now) {
                        Bound::Stay => ServerState::Bound { session, binding },
                        Bound::Unbind => ServerState::Negotiated {
                            session,
                            deadline: None,
                        },
                    };
                Ok(())
            }
            other @ (ServerState::AwaitingNegotiate { .. }
            | ServerState::NegotiationPending { .. }
            | ServerState::Negotiated { .. }
            | ServerState::Bound { .. }
            | ServerState::Closed(_)) => self.refuse_command(other, "accept_establishment"),
        }
    }

    /// Refuses the pending Establish (FIXP v1.1 section 4.3.3). The session
    /// stays negotiated, and the client may retry on this transport within
    /// the handshake timeout.
    ///
    /// # Errors
    /// [`FixpError::InvalidState`] unless an Establish is pending, and
    /// [`FixpError::ReasonTooLong`].
    pub fn reject_establishment(
        &mut self,
        code: EstablishmentRejectCode,
        reason: impl Into<String>,
        now: Instant,
    ) -> Result<(), FixpError> {
        let reason = reason.into();
        check_reason(&reason)?;
        let state = std::mem::replace(
            &mut self.state,
            ServerState::Closed(ClosedReason::TransportClosed),
        );
        match state {
            ServerState::EstablishPending {
                session, request, ..
            } => {
                tracing::debug!(session_id = %session.id(), ?code, "fixp establishment rejected");
                self.core
                    .send(SessionMessage::EstablishmentReject(EstablishmentReject {
                        session_id: session.id(),
                        request_timestamp: request,
                        code,
                        reason,
                    }));
                self.state = ServerState::Negotiated {
                    session,
                    deadline: now.checked_add(self.core.config().handshake_timeout()),
                };
                Ok(())
            }
            other @ (ServerState::AwaitingNegotiate { .. }
            | ServerState::NegotiationPending { .. }
            | ServerState::Negotiated { .. }
            | ServerState::Bound { .. }
            | ServerState::Closed(_)) => self.refuse_command(other, "reject_establishment"),
        }
    }

    /// Handles a session message decoded from the transport.
    ///
    /// After the session has asked for the transport to be closed
    /// ([`Output::CloseTransport`](crate::Output::CloseTransport)), and until
    /// [`on_transport_closed`](Self::on_transport_closed), whatever still
    /// arrives on it is ignored with
    /// [`Event::Ignored`].
    pub fn handle_message(&mut self, message: &SessionMessage, now: Instant) {
        if self.core.transport_closing() {
            self.core.ignore(message.name(), "the transport is closing");
            return;
        }
        let state = std::mem::replace(
            &mut self.state,
            ServerState::Closed(ClosedReason::TransportClosed),
        );
        self.state = match classify(message) {
            Classified::Handshake(message) => self.on_handshake(state, message, now),
            Classified::Peer(message) => self.on_peer(state, message, now),
        };
    }

    /// Tells a negotiated session without a transport that the driver has
    /// routed a new transport to it, at `now`: an Establish must arrive on it
    /// within the handshake timeout, or the server asks for it to be closed.
    ///
    /// # Errors
    /// [`FixpError::TransportClosing`] until the previous transport is
    /// reported closed, and [`FixpError::InvalidState`] unless the session
    /// is negotiated with no transport attached.
    pub fn on_transport_opened(&mut self, now: Instant) -> Result<(), FixpError> {
        if self.core.transport_closing() {
            return Err(FixpError::TransportClosing {
                operation: "on_transport_opened",
            });
        }
        let handshake_timeout = self.core.config().handshake_timeout();
        let status = self.state.status();
        match &mut self.state {
            ServerState::Negotiated {
                deadline: deadline @ None,
                ..
            } => {
                *deadline = now.checked_add(handshake_timeout);
                Ok(())
            }
            ServerState::Negotiated {
                deadline: Some(_), ..
            }
            | ServerState::AwaitingNegotiate { .. }
            | ServerState::NegotiationPending { .. }
            | ServerState::EstablishPending { .. }
            | ServerState::Bound { .. }
            | ServerState::Closed(_) => Err(FixpError::InvalidState {
                operation: "on_transport_opened",
                status,
            }),
        }
    }

    /// Runs the timers due at `now`: heartbeats, the counterparty silence
    /// check, retransmission stalls, and handshake and termination timeouts.
    pub fn handle_timeout(&mut self, now: Instant) {
        let handshake_timeout = self.core.config().handshake_timeout();
        let state = std::mem::replace(
            &mut self.state,
            ServerState::Closed(ClosedReason::TransportClosed),
        );
        self.state = match state {
            ServerState::AwaitingNegotiate { since } => {
                if elapsed(since, handshake_timeout, now) {
                    tracing::warn!("fixp server: no Negotiate before the handshake timeout");
                    self.core.event(Event::HandshakeTimedOut {
                        stage: HandshakeStage::Negotiation,
                    });
                    self.core.close_transport();
                    ServerState::Closed(ClosedReason::HandshakeTimedOut)
                } else {
                    ServerState::AwaitingNegotiate { since }
                }
            }
            ServerState::Negotiated { session, deadline } => {
                if deadline.is_some_and(|deadline| now >= deadline) {
                    tracing::warn!(session_id = %session.id(), "fixp server: no Establish before the handshake timeout");
                    self.core.event(Event::HandshakeTimedOut {
                        stage: HandshakeStage::Establishment,
                    });
                    self.core.close_transport();
                    ServerState::Negotiated {
                        session,
                        deadline: None,
                    }
                } else {
                    ServerState::Negotiated { session, deadline }
                }
            }
            ServerState::NegotiationPending {
                session_id,
                request,
                client_flow,
                deadline,
            } => {
                if deadline.is_some_and(|deadline| now >= deadline) {
                    tracing::warn!(%session_id, "fixp server: the application did not answer the Negotiate in time");
                    // Section 4.2.3 (p. 18): "When a session cannot be
                    // created, a server must send NegotiationReject".
                    self.core
                        .send(SessionMessage::NegotiationReject(NegotiationReject {
                            session_id,
                            request_timestamp: request,
                            code: NegotiationRejectCode::Unspecified,
                            reason: "negotiation not answered in time".to_owned(),
                        }));
                    self.core.event(Event::HandshakeTimedOut {
                        stage: HandshakeStage::Negotiation,
                    });
                    self.core.close_transport();
                    ServerState::Closed(ClosedReason::HandshakeTimedOut)
                } else {
                    ServerState::NegotiationPending {
                        session_id,
                        request,
                        client_flow,
                        deadline,
                    }
                }
            }
            ServerState::EstablishPending {
                session,
                request,
                keepalive,
                next_seq_no,
                deadline,
            } => {
                if deadline.is_some_and(|deadline| now >= deadline) {
                    tracing::warn!(session_id = %session.id(), "fixp server: the application did not answer the Establish in time");
                    // Section 4.3 (p. 19): "The response to Establish is
                    // either EstablishmentAck or EstablishmentReject."
                    self.core
                        .send(SessionMessage::EstablishmentReject(EstablishmentReject {
                            session_id: session.id(),
                            request_timestamp: request,
                            code: EstablishmentRejectCode::Unspecified,
                            reason: "establishment not answered in time".to_owned(),
                        }));
                    self.core.event(Event::HandshakeTimedOut {
                        stage: HandshakeStage::Establishment,
                    });
                    self.core.close_transport();
                    ServerState::Negotiated {
                        session,
                        deadline: None,
                    }
                } else {
                    ServerState::EstablishPending {
                        session,
                        request,
                        keepalive,
                        next_seq_no,
                        deadline,
                    }
                }
            }
            ServerState::Bound {
                mut session,
                mut binding,
            } => match session.on_timeout(&mut self.core, &mut binding, now) {
                Bound::Stay => ServerState::Bound { session, binding },
                Bound::Unbind => self.unbound(session),
            },
            other @ ServerState::Closed(_) => other,
        };
    }

    /// The next instant at which [`handle_timeout`](Self::handle_timeout)
    /// has work to do, if any.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        match &self.state {
            ServerState::AwaitingNegotiate { since } => {
                since.checked_add(self.core.config().handshake_timeout())
            }
            ServerState::Negotiated { deadline, .. }
            | ServerState::NegotiationPending { deadline, .. }
            | ServerState::EstablishPending { deadline, .. } => *deadline,
            ServerState::Bound { session, binding } => {
                session.next_deadline(self.core.config(), binding)
            }
            ServerState::Closed(_) => None,
        }
    }

    /// Tells the session the transport is closed. A negotiated session stays
    /// negotiated: the client may establish it again on a new transport,
    /// which the driver routes here by session identifier.
    pub fn on_transport_closed(&mut self) {
        self.core.transport_closed();
        let state = std::mem::replace(
            &mut self.state,
            ServerState::Closed(ClosedReason::TransportClosed),
        );
        self.state = match state {
            ServerState::AwaitingNegotiate { .. } | ServerState::NegotiationPending { .. } => {
                self.core.event(Event::TransportClosed);
                ServerState::Closed(ClosedReason::TransportClosed)
            }
            ServerState::Negotiated { session, .. }
            | ServerState::EstablishPending { session, .. } => {
                self.core.event(Event::TransportClosed);
                ServerState::Negotiated {
                    session,
                    deadline: None,
                }
            }
            ServerState::Bound { mut session, .. } => {
                session.release_binding_state();
                self.core.event(Event::TransportClosed);
                self.unbound(session)
            }
            ServerState::Closed(reason) => ServerState::Closed(reason),
        };
    }

    // ----- role internals used by `bound_api!` -------------------------------

    fn session(&self) -> Option<&Session> {
        match &self.state {
            ServerState::Negotiated { session, .. }
            | ServerState::EstablishPending { session, .. }
            | ServerState::Bound { session, .. } => Some(session),
            ServerState::AwaitingNegotiate { .. }
            | ServerState::NegotiationPending { .. }
            | ServerState::Closed(_) => None,
        }
    }

    fn bound_parts(
        &mut self,
        operation: &'static str,
    ) -> Result<(&mut Core, &mut Session, &mut Binding), FixpError> {
        let status = self.state.status();
        match &mut self.state {
            ServerState::Bound { session, binding } => Ok((&mut self.core, session, binding)),
            ServerState::AwaitingNegotiate { .. }
            | ServerState::NegotiationPending { .. }
            | ServerState::Negotiated { .. }
            | ServerState::EstablishPending { .. }
            | ServerState::Closed(_) => Err(FixpError::InvalidState { operation, status }),
        }
    }

    fn after(&mut self, bound: Bound) {
        if bound == Bound::Stay {
            return;
        }
        let state = std::mem::replace(
            &mut self.state,
            ServerState::Closed(ClosedReason::TransportClosed),
        );
        self.state = match state {
            ServerState::Bound { session, .. } => self.unbound(session),
            other @ (ServerState::AwaitingNegotiate { .. }
            | ServerState::NegotiationPending { .. }
            | ServerState::Negotiated { .. }
            | ServerState::EstablishPending { .. }
            | ServerState::Closed(_)) => other,
        };
    }

    fn application_before_established(&mut self) {
        // Still arriving on a transport this side asked to close: nothing to
        // answer, and reported like a session message would be.
        if self.core.transport_closing() {
            self.core
                .ignore(APPLICATION_MESSAGE, "the transport is closing");
            return;
        }
        if let ServerState::Closed(_) = self.state {
            self.core
                .ignore(APPLICATION_MESSAGE, "the session is closed");
            return;
        }
        let state = std::mem::replace(
            &mut self.state,
            ServerState::Closed(ClosedReason::TransportClosed),
        );
        self.state = self.violation(state, "application message before establishment");
    }

    /// Where a bound server goes when its binding ends: negotiated, waiting
    /// for the client to establish again, unless the logical session is
    /// finalized (FIXP v1.1 section 4.7.2), whose identifier may not be
    /// established again (section 6.3).
    fn unbound(&mut self, session: Box<Session>) -> ServerState {
        if session.is_finalized() {
            self.core.event(Event::SessionFinalized {
                session_id: session.id(),
            });
            return ServerState::Closed(ClosedReason::Finalized(session.id()));
        }
        ServerState::Negotiated {
            session,
            deadline: None,
        }
    }

    /// Restores `state` and refuses a command that is illegal in it.
    fn refuse_command(
        &mut self,
        state: ServerState,
        operation: &'static str,
    ) -> Result<(), FixpError> {
        let status = state.status();
        self.state = state;
        Err(FixpError::InvalidState { operation, status })
    }

    // ----- message handling --------------------------------------------------

    fn on_peer(
        &mut self,
        state: ServerState,
        message: PeerMessage<'_>,
        now: Instant,
    ) -> ServerState {
        match state {
            ServerState::Bound {
                mut session,
                mut binding,
            } => match session.on_peer(&mut self.core, &mut binding, message, now) {
                Bound::Stay => ServerState::Bound { session, binding },
                Bound::Unbind => self.unbound(session),
            },
            ServerState::Closed(reason) => ServerState::Closed(reason),
            unbound @ (ServerState::AwaitingNegotiate { .. }
            | ServerState::NegotiationPending { .. }
            | ServerState::Negotiated { .. }
            | ServerState::EstablishPending { .. }) => match message {
                // Section 3.6: MessageTemplate may be sent at any time.
                PeerMessage::MessageTemplate => unbound,
                PeerMessage::Terminate(terminate) => {
                    self.core.event(Event::Terminated {
                        code: terminate.code,
                        reason: terminate.reason.clone(),
                        by: TerminatedBy::Peer,
                    });
                    self.core.close_transport();
                    Self::after_unbound_failure(unbound)
                }
                PeerMessage::Topic
                | PeerMessage::Sequence(_)
                | PeerMessage::Context(_)
                | PeerMessage::UnsequencedHeartbeat
                | PeerMessage::RetransmitRequest(_)
                | PeerMessage::Retransmission(_)
                | PeerMessage::RetransmitReject(_)
                | PeerMessage::FinishedSending(_)
                | PeerMessage::FinishedReceiving
                | PeerMessage::Applied(_)
                | PeerMessage::NotApplied(_) => {
                    self.violation(unbound, "session message before establishment")
                }
            },
        }
    }

    fn on_handshake(
        &mut self,
        state: ServerState,
        message: HandshakeMessage<'_>,
        now: Instant,
    ) -> ServerState {
        match message {
            HandshakeMessage::Negotiate(m) => self.on_negotiate(state, m, now),
            HandshakeMessage::Establish(m) => self.on_establish(state, m, now),
            HandshakeMessage::NegotiationResponse(_)
            | HandshakeMessage::NegotiationReject(_)
            | HandshakeMessage::EstablishmentAck(_)
            | HandshakeMessage::EstablishmentReject(_) => {
                self.violation(state, "a server-only message sent by the client")
            }
        }
    }

    fn on_negotiate(&mut self, state: ServerState, m: &Negotiate, now: Instant) -> ServerState {
        match state {
            ServerState::AwaitingNegotiate { .. } => {
                // Appendix A 7.1.7.3: a session id that is no UUID is refused.
                if m.session_id.is_nil() {
                    self.refuse_negotiate(
                        m,
                        NegotiationRejectCode::Unspecified,
                        "invalid session id",
                    );
                    self.core.close_transport();
                    return ServerState::Closed(ClosedReason::NegotiationRejected);
                }
                tracing::debug!(session_id = %m.session_id, client_flow = ?m.client_flow, "fixp negotiate received");
                self.core.event(Event::NegotiateReceived {
                    session_id: m.session_id,
                    client_flow: m.client_flow,
                });
                ServerState::NegotiationPending {
                    session_id: m.session_id,
                    request: m.timestamp,
                    client_flow: m.client_flow,
                    deadline: now.checked_add(self.core.config().handshake_timeout()),
                }
            }
            ServerState::NegotiationPending { .. } => {
                self.violation(state, "Negotiate while a Negotiate is pending")
            }
            // Section 4.2.3: a Negotiate after the first, in any state, is
            // refused, and the transport is closed: it is not left usable.
            ServerState::Negotiated { session, deadline } => {
                self.refuse_renegotiation(&session, m);
                self.violation(
                    ServerState::Negotiated { session, deadline },
                    "Negotiate on a negotiated session",
                )
            }
            ServerState::EstablishPending {
                session,
                request,
                keepalive,
                next_seq_no,
                deadline,
            } => {
                self.refuse_renegotiation(&session, m);
                self.violation(
                    ServerState::EstablishPending {
                        session,
                        request,
                        keepalive,
                        next_seq_no,
                        deadline,
                    },
                    "Negotiate on a negotiated session",
                )
            }
            ServerState::Bound { session, binding } => {
                if binding.status() == SessionStatus::Established {
                    // Section 4.2.3: a Negotiate on an established session is
                    // refused, and the session is terminated and its
                    // transport closed; it is not left usable.
                    self.refuse_renegotiation(&session, m);
                    return self.violation(
                        ServerState::Bound { session, binding },
                        "Negotiate on an established session",
                    );
                } else {
                    // The binding is ending: nothing more may be sent on it.
                    self.core
                        .ignore(Negotiate::NAME, "the transport is being unbound");
                }
                ServerState::Bound { session, binding }
            }
            // Section 6.3: reusing a finalized session identifier is a
            // violation; it is refused as a duplicate.
            ServerState::Closed(ClosedReason::Finalized(session_id)) => {
                if m.session_id == session_id {
                    self.refuse_negotiate(
                        m,
                        NegotiationRejectCode::DuplicateId,
                        "session finalized",
                    );
                    self.core
                        .violation_unbound("Negotiate for a finalized session");
                }
                ServerState::Closed(ClosedReason::Finalized(session_id))
            }
            ServerState::Closed(reason) => ServerState::Closed(reason),
        }
    }

    /// A Negotiate for a session that exists: reusing an identifier is a
    /// violation (section 6.3), and this server holds one session only.
    fn refuse_renegotiation(&mut self, session: &Session, m: &Negotiate) {
        if m.session_id == session.id() {
            self.refuse_negotiate(
                m,
                NegotiationRejectCode::DuplicateId,
                "session already negotiated",
            );
        } else {
            self.refuse_negotiate(
                m,
                NegotiationRejectCode::Unspecified,
                "multiplexed sessions are not supported",
            );
        }
    }

    fn refuse_negotiate(
        &mut self,
        m: &Negotiate,
        code: NegotiationRejectCode,
        reason: &'static str,
    ) {
        tracing::debug!(session_id = %m.session_id, ?code, reason, "fixp negotiate refused");
        self.core
            .send(SessionMessage::NegotiationReject(NegotiationReject {
                session_id: m.session_id,
                request_timestamp: m.timestamp,
                code,
                reason: reason.to_owned(),
            }));
        self.core.event(Event::Refused {
            message: NegotiationReject::NAME,
            reason,
        });
    }

    fn on_establish(&mut self, state: ServerState, m: &Establish, now: Instant) -> ServerState {
        match state {
            // Appendix A 7.1.12.1: Establish without negotiation.
            ServerState::AwaitingNegotiate { since } => {
                self.refuse_establish(
                    m,
                    EstablishmentRejectCode::Unnegotiated,
                    "establish without negotiation",
                );
                ServerState::AwaitingNegotiate { since }
            }
            ServerState::NegotiationPending { .. } => {
                self.violation(state, "Establish before the negotiation was answered")
            }
            ServerState::Negotiated { session, deadline } => {
                if m.session_id != session.id() {
                    self.refuse_establish(
                        m,
                        EstablishmentRejectCode::Unnegotiated,
                        "unknown session",
                    );
                    return ServerState::Negotiated { session, deadline };
                }
                // Section 4.3.3, Appendix A 7.1.12.4.
                if !self
                    .core
                    .config()
                    .accepts_peer_keepalive(m.keepalive_interval)
                {
                    self.refuse_establish(
                        m,
                        EstablishmentRejectCode::KeepaliveInterval,
                        "keepalive interval out of the accepted range",
                    );
                    return ServerState::Negotiated { session, deadline };
                }
                // A sequenced flow numbers from 1 at least (section 3.5.1).
                if session.remote_flow().is_sequenced() && m.next_seq_no == Some(0) {
                    self.refuse_establish(
                        m,
                        EstablishmentRejectCode::Unspecified,
                        "NextSeqNo of zero",
                    );
                    return ServerState::Negotiated { session, deadline };
                }
                if session.regresses(m.next_seq_no) {
                    self.refuse_establish(
                        m,
                        EstablishmentRejectCode::Unspecified,
                        "NextSeqNo lower than expected",
                    );
                    return ServerState::Negotiated { session, deadline };
                }
                let keepalive = Duration::from_millis(u64::from(m.keepalive_interval));
                tracing::debug!(session_id = %m.session_id, "fixp establish received");
                self.core.event(Event::EstablishReceived {
                    session_id: m.session_id,
                    keepalive_interval: keepalive,
                    next_seq_no: m.next_seq_no.map(SeqNum::new),
                });
                ServerState::EstablishPending {
                    session,
                    request: m.timestamp,
                    keepalive: m.keepalive_interval,
                    next_seq_no: m.next_seq_no,
                    deadline: now.checked_add(self.core.config().handshake_timeout()),
                }
            }
            ServerState::EstablishPending { .. } => {
                self.violation(state, "Establish while an Establish is pending")
            }
            // Appendix A 7.1.12.2: redundant Establish.
            ServerState::Bound { session, binding } => {
                if binding.status() == SessionStatus::Established {
                    self.refuse_establish(
                        m,
                        EstablishmentRejectCode::AlreadyEstablished,
                        "session already established",
                    );
                } else {
                    // The binding is ending: nothing more may be sent on it.
                    // The client retries on a new transport.
                    self.core
                        .ignore(Establish::NAME, "the transport is being unbound");
                }
                ServerState::Bound { session, binding }
            }
            // Section 6.3: establishing a finalized session is a violation.
            // `Unnegotiated` tells the client to negotiate a new session.
            ServerState::Closed(ClosedReason::Finalized(session_id)) => {
                if m.session_id == session_id {
                    self.refuse_establish(
                        m,
                        EstablishmentRejectCode::Unnegotiated,
                        "session finalized",
                    );
                    self.core
                        .violation_unbound("Establish for a finalized session");
                }
                ServerState::Closed(ClosedReason::Finalized(session_id))
            }
            ServerState::Closed(reason) => ServerState::Closed(reason),
        }
    }

    fn refuse_establish(
        &mut self,
        m: &Establish,
        code: EstablishmentRejectCode,
        reason: &'static str,
    ) {
        tracing::debug!(session_id = %m.session_id, ?code, reason, "fixp establish refused");
        self.core
            .send(SessionMessage::EstablishmentReject(EstablishmentReject {
                session_id: m.session_id,
                request_timestamp: m.timestamp,
                code,
                reason: reason.to_owned(),
            }));
        self.core.event(Event::Refused {
            message: EstablishmentReject::NAME,
            reason,
        });
    }

    /// The client broke the protocol in `state`.
    fn violation(&mut self, state: ServerState, reason: &'static str) -> ServerState {
        match state {
            ServerState::Bound {
                mut session,
                mut binding,
            } => {
                let _ = session.violation(&mut self.core, &mut binding, reason);
                self.unbound(session)
            }
            ServerState::Closed(reason) => ServerState::Closed(reason),
            unbound @ (ServerState::AwaitingNegotiate { .. }
            | ServerState::NegotiationPending { .. }
            | ServerState::Negotiated { .. }
            | ServerState::EstablishPending { .. }) => {
                self.core.violation_unbound(reason);
                Self::after_unbound_failure(unbound)
            }
        }
    }

    /// Where an unbound server goes when its transport is closed on a
    /// failure: before negotiation it is done, after it the session is kept.
    fn after_unbound_failure(state: ServerState) -> ServerState {
        match state {
            ServerState::AwaitingNegotiate { .. } | ServerState::NegotiationPending { .. } => {
                ServerState::Closed(ClosedReason::ProtocolViolation)
            }
            ServerState::Negotiated { session, .. }
            | ServerState::EstablishPending { session, .. } => ServerState::Negotiated {
                session,
                deadline: None,
            },
            other @ (ServerState::Bound { .. } | ServerState::Closed(_)) => other,
        }
    }
}

bound_api!(FixpServer);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{Sequence, Terminate};
    use crate::output::{Delivery, Output};
    use crate::testkit::{
        HANDSHAKE, KEEPALIVE, OTHER_SESSION, SESSION, at, closes, drain, establish,
        established_pair, events, negotiated_pair, sent, server,
    };
    use crate::types::TerminationCode;

    fn negotiate(session_id: SessionId, flow: FlowType) -> SessionMessage {
        SessionMessage::Negotiate(Negotiate {
            session_id,
            timestamp: Nanotime::from_nanos(41),
            client_flow: flow,
            credentials: Credentials::try_new(b"cred".to_vec()).ok(),
        })
    }

    fn establish_message(
        session_id: SessionId,
        keepalive: u32,
        next: Option<u64>,
    ) -> SessionMessage {
        SessionMessage::Establish(Establish {
            session_id,
            timestamp: Nanotime::from_nanos(42),
            keepalive_interval: keepalive,
            next_seq_no: next,
            credentials: None,
        })
    }

    /// The single EstablishmentReject the server just sent.
    fn establishment_reject(outputs: &[Output]) -> EstablishmentReject {
        match sent(outputs).as_slice() {
            [SessionMessage::EstablishmentReject(reject)] => reject.clone(),
            other => panic!("expected one EstablishmentReject, got {other:?}"),
        }
    }

    /// A server with a pending Negotiate.
    fn pending(origin: Instant, flow: FlowType) -> FixpServer {
        let mut server = server(origin);
        server.handle_message(&negotiate(SESSION, flow), origin);
        let _ = drain(&mut server);
        server
    }

    #[test]
    fn test_server_negotiate_waits_for_the_application() {
        let origin = Instant::now();
        let mut server = server(origin);
        assert_eq!(server.status(), SessionStatus::AwaitingNegotiate);
        assert_eq!(server.poll_timeout(), Some(origin + HANDSHAKE));
        assert_eq!(server.session_id(), None);
        server.handle_message(&negotiate(SESSION, FlowType::Idempotent), origin);
        let outputs = drain(&mut server);
        assert_eq!(
            events(&outputs),
            vec![Event::NegotiateReceived {
                session_id: SESSION,
                client_flow: FlowType::Idempotent,
            }]
        );
        assert!(sent(&outputs).is_empty());
        assert_eq!(server.status(), SessionStatus::NegotiationPending);
        assert_eq!(server.session_id(), Some(SESSION));
        assert_eq!(server.client_flow(), Some(FlowType::Idempotent));
        assert_eq!(server.server_flow(), None);
        // The application's answer is bounded by the handshake timeout too.
        assert_eq!(server.poll_timeout(), Some(origin + HANDSHAKE));
    }

    #[test]
    fn test_server_rejects_a_nil_session_id() {
        // FIXP v1.1 Appendix A 7.1.7.3.
        let origin = Instant::now();
        let mut server = server(origin);
        server.handle_message(&negotiate(SessionId::NIL, FlowType::Idempotent), origin);
        let outputs = drain(&mut server);
        match sent(&outputs).as_slice() {
            [SessionMessage::NegotiationReject(reject)] => {
                assert_eq!(reject.code, NegotiationRejectCode::Unspecified);
                assert_eq!(reject.request_timestamp, Nanotime::from_nanos(41));
            }
            other => panic!("expected a NegotiationReject, got {other:?}"),
        }
        assert!(closes(&outputs));
        assert_eq!(server.status(), SessionStatus::Closed);
    }

    #[test]
    fn test_server_accept_negotiation_answers_and_negotiates() {
        let origin = Instant::now();
        let mut server = pending(origin, FlowType::Idempotent);
        let credentials = Credentials::try_new(b"server".to_vec()).ok();
        assert_eq!(
            server.accept_negotiation(FlowType::Recoverable, credentials.clone(), origin),
            Ok(())
        );
        let outputs = drain(&mut server);
        assert_eq!(
            sent(&outputs),
            vec![SessionMessage::NegotiationResponse(NegotiationResponse {
                session_id: SESSION,
                request_timestamp: Nanotime::from_nanos(41),
                server_flow: FlowType::Recoverable,
                credentials,
            })]
        );
        assert_eq!(
            events(&outputs),
            vec![Event::Negotiated {
                session_id: SESSION,
                client_flow: FlowType::Idempotent,
                server_flow: FlowType::Recoverable,
            }]
        );
        assert_eq!(server.status(), SessionStatus::Negotiated);
        assert_eq!(server.server_flow(), Some(FlowType::Recoverable));
        assert_eq!(server.poll_timeout(), Some(origin + HANDSHAKE));
    }

    #[test]
    fn test_server_accept_negotiation_refuses_both_flows_none() {
        // FIXP v1.1 section 3.4.4.1.
        let origin = Instant::now();
        let mut server = pending(origin, FlowType::None);
        assert_eq!(
            server.accept_negotiation(FlowType::None, None, origin),
            Err(FixpError::BothFlowsNone)
        );
        assert_eq!(server.status(), SessionStatus::NegotiationPending);
        assert!(drain(&mut server).is_empty());
        assert_eq!(
            server.accept_negotiation(FlowType::Unsequenced, None, origin),
            Ok(())
        );
    }

    #[test]
    fn test_server_reject_negotiation_closes() {
        let origin = Instant::now();
        let mut server = pending(origin, FlowType::Recoverable);
        assert_eq!(
            server.reject_negotiation(
                NegotiationRejectCode::FlowTypeNotSupported,
                "Client Recoverable Flow Prohibited"
            ),
            Ok(())
        );
        let outputs = drain(&mut server);
        assert_eq!(
            sent(&outputs),
            vec![SessionMessage::NegotiationReject(NegotiationReject {
                session_id: SESSION,
                request_timestamp: Nanotime::from_nanos(41),
                code: NegotiationRejectCode::FlowTypeNotSupported,
                reason: "Client Recoverable Flow Prohibited".to_owned(),
            })]
        );
        assert!(closes(&outputs));
        assert_eq!(server.status(), SessionStatus::Closed);
    }

    #[test]
    fn test_server_commands_in_the_wrong_state_are_refused() {
        let origin = Instant::now();
        let mut server = server(origin);
        assert_eq!(
            server.accept_negotiation(FlowType::Recoverable, None, origin),
            Err(FixpError::InvalidState {
                operation: "accept_negotiation",
                status: SessionStatus::AwaitingNegotiate,
            })
        );
        assert!(matches!(
            server.reject_negotiation(NegotiationRejectCode::Unspecified, ""),
            Err(FixpError::InvalidState { .. })
        ));
        assert!(matches!(
            server.accept_establishment(origin),
            Err(FixpError::InvalidState { .. })
        ));
        assert!(matches!(
            server.reject_establishment(EstablishmentRejectCode::Unspecified, "", origin),
            Err(FixpError::InvalidState { .. })
        ));
        assert!(matches!(
            server.terminate(TerminationCode::Finished, "", origin),
            Err(FixpError::InvalidState { .. })
        ));
        assert_eq!(server.status(), SessionStatus::AwaitingNegotiate);
        let mut pending = pending(origin, FlowType::Recoverable);
        assert_eq!(
            pending.reject_negotiation(NegotiationRejectCode::Unspecified, "x".repeat(70_000)),
            Err(FixpError::ReasonTooLong {
                len: 70_000,
                max: 65_534,
            })
        );
        assert_eq!(pending.status(), SessionStatus::NegotiationPending);
    }

    #[test]
    fn test_server_rejects_establish_without_negotiation() {
        // FIXP v1.1 Appendix A 7.1.12.1.
        let origin = Instant::now();
        let mut server = server(origin);
        server.handle_message(&establish_message(SESSION, 1_000, None), origin);
        let outputs = drain(&mut server);
        let reject = establishment_reject(&outputs);
        assert_eq!(reject.code, EstablishmentRejectCode::Unnegotiated);
        assert_eq!(reject.request_timestamp, Nanotime::from_nanos(42));
        assert!(matches!(
            events(&outputs).as_slice(),
            [Event::Refused {
                message: "EstablishmentReject",
                ..
            }]
        ));
        assert_eq!(server.status(), SessionStatus::AwaitingNegotiate);
    }

    #[test]
    fn test_server_rejects_establish_for_another_session() {
        let origin = Instant::now();
        let (_client, mut server) =
            negotiated_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        server.handle_message(&establish_message(OTHER_SESSION, 1_000, None), origin);
        assert_eq!(
            establishment_reject(&drain(&mut server)).code,
            EstablishmentRejectCode::Unnegotiated
        );
        assert_eq!(server.status(), SessionStatus::Negotiated);
    }

    #[test]
    fn test_server_rejects_a_keepalive_out_of_range() {
        // FIXP v1.1 section 4.3.3, Appendix A 7.1.12.4.
        let origin = Instant::now();
        let (_client, mut server) =
            negotiated_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        for keepalive in [0, 1, 99, 60_001, u32::MAX] {
            server.handle_message(&establish_message(SESSION, keepalive, Some(1)), origin);
            assert_eq!(
                establishment_reject(&drain(&mut server)).code,
                EstablishmentRejectCode::KeepaliveInterval,
                "keepalive {keepalive}"
            );
            assert_eq!(server.status(), SessionStatus::Negotiated);
        }
    }

    #[test]
    fn test_server_accept_establishment_acks_with_its_keepalive_and_next_seq() {
        let origin = Instant::now();
        let (_client, mut server) =
            negotiated_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        server.handle_message(&establish_message(SESSION, 2_000, Some(7)), origin);
        assert_eq!(
            events(&drain(&mut server)),
            vec![Event::EstablishReceived {
                session_id: SESSION,
                keepalive_interval: Duration::from_secs(2),
                next_seq_no: Some(SeqNum::new(7)),
            }]
        );
        assert_eq!(server.status(), SessionStatus::EstablishPending);
        assert_eq!(server.accept_establishment(origin), Ok(()));
        let outputs = drain(&mut server);
        assert_eq!(
            sent(&outputs),
            vec![SessionMessage::EstablishmentAck(EstablishmentAck {
                session_id: SESSION,
                request_timestamp: Nanotime::from_nanos(42),
                keepalive_interval: 1_000,
                next_seq_no: Some(1),
            })]
        );
        assert_eq!(server.status(), SessionStatus::Established);
        assert_eq!(server.next_inbound_seq(), Some(SeqNum::new(7)));
        assert_eq!(server.poll_timeout(), Some(origin + KEEPALIVE));
    }

    #[test]
    fn test_server_ack_on_an_unsequenced_flow_carries_no_next_seq() {
        let origin = Instant::now();
        let (_client, mut server) =
            negotiated_pair(origin, FlowType::Unsequenced, FlowType::Unsequenced);
        server.handle_message(&establish_message(SESSION, 1_000, None), origin);
        let _ = drain(&mut server);
        assert_eq!(server.accept_establishment(origin), Ok(()));
        match sent(&drain(&mut server)).as_slice() {
            [SessionMessage::EstablishmentAck(ack)] => assert_eq!(ack.next_seq_no, None),
            other => panic!("expected an EstablishmentAck, got {other:?}"),
        }
    }

    #[test]
    fn test_server_reject_establishment_keeps_the_session() {
        // FIXP v1.1 Appendix A 7.1.12.3.
        let origin = Instant::now();
        let (_client, mut server) =
            negotiated_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        server.handle_message(&establish_message(SESSION, 1_000, Some(1)), origin);
        let _ = drain(&mut server);
        let later = at(origin, 100);
        assert_eq!(
            server.reject_establishment(
                EstablishmentRejectCode::SessionBlocked,
                "Session Has Been Blocked",
                later
            ),
            Ok(())
        );
        let reject = establishment_reject(&drain(&mut server));
        assert_eq!(reject.code, EstablishmentRejectCode::SessionBlocked);
        assert_eq!(server.status(), SessionStatus::Negotiated);
        assert_eq!(server.poll_timeout(), Some(later + HANDSHAKE));
        server.handle_message(&establish_message(SESSION, 1_000, Some(1)), later);
        assert_eq!(server.status(), SessionStatus::EstablishPending);
    }

    #[test]
    fn test_server_rejects_a_redundant_establish() {
        // FIXP v1.1 Appendix A 7.1.12.2.
        let origin = Instant::now();
        let (_client, mut server) =
            established_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        server.handle_message(&establish_message(SESSION, 1_000, Some(1)), origin);
        assert_eq!(
            establishment_reject(&drain(&mut server)).code,
            EstablishmentRejectCode::AlreadyEstablished
        );
        assert_eq!(server.status(), SessionStatus::Established);
    }

    #[test]
    fn test_server_rejects_a_second_negotiate() {
        let origin = Instant::now();
        let (_client, mut server) =
            established_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        server.handle_message(&negotiate(SESSION, FlowType::Recoverable), origin);
        // Section 4.2.3: refused, then the session is terminated and the
        // transport closed; it is not left usable.
        let outputs = drain(&mut server);
        match sent(&outputs).as_slice() {
            [
                SessionMessage::NegotiationReject(reject),
                SessionMessage::Terminate(_),
            ] => {
                assert_eq!(reject.code, NegotiationRejectCode::DuplicateId);
            }
            other => panic!("expected a NegotiationReject and a Terminate, got {other:?}"),
        }
        assert!(outputs.iter().any(|o| matches!(o, Output::CloseTransport)));
        assert_eq!(server.status(), SessionStatus::Negotiated);
        assert!(server.send_application(origin).is_err());
        let (_client, mut server) =
            established_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        server.handle_message(&negotiate(OTHER_SESSION, FlowType::Recoverable), origin);
        match sent(&drain(&mut server)).as_slice() {
            [
                SessionMessage::NegotiationReject(reject),
                SessionMessage::Terminate(_),
            ] => {
                assert_eq!(reject.code, NegotiationRejectCode::Unspecified);
                assert_eq!(reject.session_id, OTHER_SESSION);
            }
            other => panic!("expected a NegotiationReject and a Terminate, got {other:?}"),
        }
        assert_eq!(server.status(), SessionStatus::Negotiated);
    }

    #[test]
    fn test_server_rejects_a_next_seq_that_goes_backwards() {
        let origin = Instant::now();
        let (mut client, mut server) =
            established_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        // Five client messages: the server now expects 6.
        let _ = crate::testkit::send_apps(&mut client, &mut server, 5, origin);
        assert_eq!(server.next_inbound_seq(), Some(SeqNum::new(6)));
        server.on_transport_closed();
        let _ = drain(&mut server);
        server.handle_message(&establish_message(SESSION, 1_000, Some(3)), origin);
        let reject = establishment_reject(&drain(&mut server));
        assert_eq!(reject.code, EstablishmentRejectCode::Unspecified);
        assert_eq!(server.status(), SessionStatus::Negotiated);
    }

    #[test]
    fn test_server_handshake_timeouts() {
        let origin = Instant::now();
        let mut idle = server(origin);
        idle.handle_timeout(origin + HANDSHAKE - Duration::from_millis(1));
        assert!(drain(&mut idle).is_empty());
        idle.handle_timeout(origin + HANDSHAKE);
        let outputs = drain(&mut idle);
        assert_eq!(
            events(&outputs),
            vec![Event::HandshakeTimedOut {
                stage: HandshakeStage::Negotiation
            }]
        );
        assert!(closes(&outputs));
        assert_eq!(idle.status(), SessionStatus::Closed);

        let (_client, mut negotiated) =
            negotiated_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        negotiated.handle_timeout(origin + HANDSHAKE);
        let outputs = drain(&mut negotiated);
        assert_eq!(
            events(&outputs),
            vec![Event::HandshakeTimedOut {
                stage: HandshakeStage::Establishment
            }]
        );
        assert!(closes(&outputs));
        assert_eq!(negotiated.status(), SessionStatus::Negotiated);
        assert_eq!(
            negotiated.poll_timeout(),
            None,
            "the session waits for a new transport"
        );
    }

    #[test]
    fn test_server_treats_client_only_messages_as_violations() {
        let origin = Instant::now();
        let response = SessionMessage::NegotiationResponse(NegotiationResponse {
            session_id: SESSION,
            request_timestamp: Nanotime::from_nanos(1),
            server_flow: FlowType::Recoverable,
            credentials: None,
        });
        let mut fresh = server(origin);
        fresh.handle_message(&response, origin);
        let outputs = drain(&mut fresh);
        assert!(closes(&outputs));
        assert_eq!(fresh.status(), SessionStatus::Closed);

        let (_client, mut bound) =
            established_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        bound.handle_message(&response, origin);
        let outputs = drain(&mut bound);
        assert!(matches!(
            sent(&outputs).as_slice(),
            [SessionMessage::Terminate(_)]
        ));
        assert!(closes(&outputs));
        assert_eq!(bound.status(), SessionStatus::Negotiated);
    }

    #[test]
    fn test_server_out_of_order_handshake_messages_are_violations() {
        let origin = Instant::now();
        // A second Negotiate before the first is answered.
        let mut first = pending(origin, FlowType::Recoverable);
        first.handle_message(&negotiate(SESSION, FlowType::Recoverable), origin);
        assert!(closes(&drain(&mut first)));
        assert_eq!(first.status(), SessionStatus::Closed);
        // An Establish before the Negotiate is answered.
        let mut second = pending(origin, FlowType::Recoverable);
        second.handle_message(&establish_message(SESSION, 1_000, None), origin);
        assert!(closes(&drain(&mut second)));
        assert_eq!(second.status(), SessionStatus::Closed);
        // A second Establish before the first is answered.
        let (_client, mut third) =
            negotiated_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        third.handle_message(&establish_message(SESSION, 1_000, None), origin);
        third.handle_message(&establish_message(SESSION, 1_000, None), origin);
        assert!(closes(&drain(&mut third)));
        assert_eq!(third.status(), SessionStatus::Negotiated);
    }

    #[test]
    fn test_server_session_messages_before_establishment_are_violations() {
        let origin = Instant::now();
        let (_client, mut server) =
            negotiated_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        server.handle_message(
            &SessionMessage::Sequence(Sequence { next_seq_no: 1 }),
            origin,
        );
        let outputs = drain(&mut server);
        assert!(matches!(
            events(&outputs).as_slice(),
            [Event::ProtocolViolation { .. }]
        ));
        assert!(closes(&outputs));
        assert_eq!(server.status(), SessionStatus::Negotiated);
        // The transport is closing: what still arrives is ignored, with no
        // second violation and no second close.
        assert_eq!(server.on_application_message(origin), Delivery::Discard);
        server.handle_message(
            &SessionMessage::Terminate(Terminate {
                session_id: SESSION,
                code: TerminationCode::Finished,
                reason: String::new(),
            }),
            origin,
        );
        assert_eq!(
            drain(&mut server),
            vec![
                Output::Event(Event::Ignored {
                    message: "application message",
                    reason: "the transport is closing",
                }),
                Output::Event(Event::Ignored {
                    message: "Terminate",
                    reason: "the transport is closing",
                }),
            ]
        );
        // On a fresh transport a Terminate before establishment closes it.
        server.on_transport_closed();
        let _ = drain(&mut server);
        server.handle_message(
            &SessionMessage::Terminate(Terminate {
                session_id: SESSION,
                code: TerminationCode::Finished,
                reason: String::new(),
            }),
            origin,
        );
        assert!(closes(&drain(&mut server)));
    }

    #[test]
    fn test_server_application_answers_are_bounded_by_the_handshake_timeout() {
        let origin = Instant::now();
        // A Negotiate the application never answers.
        let mut negotiating = pending(origin, FlowType::Recoverable);
        negotiating.handle_timeout(origin + HANDSHAKE - Duration::from_millis(1));
        assert!(drain(&mut negotiating).is_empty());
        negotiating.handle_timeout(origin + HANDSHAKE);
        let outputs = drain(&mut negotiating);
        assert_eq!(
            events(&outputs),
            vec![Event::HandshakeTimedOut {
                stage: HandshakeStage::Negotiation
            }]
        );
        // Section 4.2.3 (p. 18): a session that cannot be created is
        // answered with NegotiationReject, then the transport closes.
        assert!(matches!(
            sent(&outputs).as_slice(),
            [SessionMessage::NegotiationReject(NegotiationReject {
                code: NegotiationRejectCode::Unspecified,
                ..
            })]
        ));
        assert!(closes(&outputs));
        assert_eq!(negotiating.status(), SessionStatus::Closed);
        // An Establish the application never answers.
        let (_client, mut establishing) =
            negotiated_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        let received = at(origin, 100);
        establishing.handle_message(&establish_message(SESSION, 1_000, Some(1)), received);
        let _ = drain(&mut establishing);
        assert_eq!(establishing.poll_timeout(), Some(received + HANDSHAKE));
        establishing.handle_timeout(received + HANDSHAKE);
        let outputs = drain(&mut establishing);
        assert_eq!(
            events(&outputs),
            vec![Event::HandshakeTimedOut {
                stage: HandshakeStage::Establishment
            }]
        );
        // Section 4.3 (p. 19): an Establish is answered with
        // EstablishmentAck or EstablishmentReject.
        match sent(&outputs).as_slice() {
            [SessionMessage::EstablishmentReject(reject)] => {
                assert_eq!(reject.code, EstablishmentRejectCode::Unspecified);
                assert_eq!(reject.session_id, SESSION);
            }
            other => panic!("expected one EstablishmentReject, got {other:?}"),
        }
        assert!(closes(&outputs));
        assert_eq!(establishing.status(), SessionStatus::Negotiated);
        assert!(matches!(
            establishing.accept_establishment(received + HANDSHAKE),
            Err(FixpError::InvalidState { .. })
        ));
    }

    #[test]
    fn test_server_on_transport_opened_arms_the_establish_deadline() {
        let origin = Instant::now();
        let (mut client, mut server) =
            established_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        server.on_transport_closed();
        client.on_transport_closed();
        let _ = drain(&mut server);
        let _ = drain(&mut client);
        assert_eq!(server.poll_timeout(), None, "no transport, no timer");
        let opened = at(origin, 1_000);
        assert_eq!(server.on_transport_opened(opened), Ok(()));
        assert_eq!(server.poll_timeout(), Some(opened + HANDSHAKE));
        assert!(matches!(
            server.on_transport_opened(opened),
            Err(FixpError::InvalidState { .. })
        ));
        // No Establish on the new transport in time: it is closed again.
        server.handle_timeout(opened + HANDSHAKE);
        let outputs = drain(&mut server);
        assert!(closes(&outputs));
        assert_eq!(
            server.on_transport_opened(opened + HANDSHAKE),
            Err(FixpError::TransportClosing {
                operation: "on_transport_opened"
            })
        );
        server.on_transport_closed();
        let _ = drain(&mut server);
        // A new transport, and this time the client establishes.
        let again = opened + HANDSHAKE + Duration::from_millis(10);
        assert_eq!(server.on_transport_opened(again), Ok(()));
        establish(&mut client, &mut server, again);
        let mut fresh = super::super::testkit::server(origin);
        assert!(matches!(
            fresh.on_transport_opened(origin),
            Err(FixpError::InvalidState { .. })
        ));
    }

    #[test]
    fn test_server_rejects_an_establish_with_next_seq_zero() {
        let origin = Instant::now();
        let (_client, mut server) =
            negotiated_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        server.handle_message(&establish_message(SESSION, 1_000, Some(0)), origin);
        let outputs = drain(&mut server);
        let reject = establishment_reject(&outputs);
        assert_eq!(reject.code, EstablishmentRejectCode::Unspecified);
        assert_eq!(reject.reason, "NextSeqNo of zero");
        assert!(!closes(&outputs));
        assert_eq!(server.status(), SessionStatus::Negotiated);
        // On an unsequenced client flow NextSeqNo is not looked at.
        let (_client, mut unsequenced) =
            negotiated_pair(origin, FlowType::Unsequenced, FlowType::Recoverable);
        unsequenced.handle_message(&establish_message(SESSION, 1_000, Some(0)), origin);
        assert_eq!(unsequenced.status(), SessionStatus::EstablishPending);
    }

    #[test]
    fn test_server_handshake_messages_while_unbinding_are_ignored() {
        // A client retrying on a transport that is being unbound gets no
        // answer there; it must use a new transport.
        let origin = Instant::now();
        let (mut client, mut server) =
            established_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        assert_eq!(
            client.terminate(TerminationCode::Finished, "", origin),
            Ok(())
        );
        crate::testkit::deliver_all(&drain(&mut client), &mut server, origin);
        let _ = drain(&mut server);
        assert_eq!(server.status(), SessionStatus::Closing);
        server.handle_message(&establish_message(SESSION, 1_000, Some(1)), origin);
        server.handle_message(&negotiate(SESSION, FlowType::Recoverable), origin);
        assert_eq!(
            drain(&mut server),
            vec![
                Output::Event(Event::Ignored {
                    message: "Establish",
                    reason: "the transport is being unbound",
                }),
                Output::Event(Event::Ignored {
                    message: "Negotiate",
                    reason: "the transport is being unbound",
                }),
            ]
        );
        // The same while this side is the one terminating.
        let (_client, mut terminating) =
            established_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        assert_eq!(
            terminating.terminate(TerminationCode::Finished, "", origin),
            Ok(())
        );
        let _ = drain(&mut terminating);
        terminating.handle_message(&establish_message(SESSION, 1_000, Some(1)), origin);
        assert!(matches!(
            drain(&mut terminating).as_slice(),
            [Output::Event(Event::Ignored {
                message: "Establish",
                ..
            })]
        ));
    }

    #[test]
    fn test_server_transport_closed_keeps_a_negotiated_session() {
        let origin = Instant::now();
        let mut fresh = server(origin);
        fresh.on_transport_closed();
        assert_eq!(events(&drain(&mut fresh)), vec![Event::TransportClosed]);
        assert_eq!(fresh.status(), SessionStatus::Closed);

        let (mut client, mut server) =
            established_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        server.on_transport_closed();
        assert_eq!(events(&drain(&mut server)), vec![Event::TransportClosed]);
        assert_eq!(server.status(), SessionStatus::Negotiated);
        client.on_transport_closed();
        let _ = drain(&mut client);
        establish(&mut client, &mut server, at(origin, 50));
    }
}
