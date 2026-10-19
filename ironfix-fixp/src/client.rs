/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! The client (initiator) role of a FIXP point-to-point session.
//!
//! ```text
//!          negotiate           NegotiationResponse         establish
//!   Idle ─────────────▶ Negotiating ─────────────▶ Negotiated ─────────▶ Establishing
//!                         │  NegotiationReject,       ▲   ▲                   │
//!                         │  timeout                  │   │ EstablishmentReject, timeout
//!                         ▼                           │   └───────────────────┤
//!                       Closed      Terminate, violation,                     │ EstablishmentAck
//!                                   keepalive lapse, transport closed         ▼
//!                                   ◀──────────────────────────────── Established
//!                                                                  (Terminating, Closing)
//! ```
//!
//! "Negotiated" is the logical session without a transport: the state after
//! the first negotiation and after any unbinding. `establish` binds it again
//! with the same session identifier and sequence numbers (FIXP v1.1
//! section 4.1). An EstablishmentReject with code `Unnegotiated` closes the
//! client: the server no longer knows the session.

use crate::clock::{ClockAnchor, RequestClock};
use crate::config::FixpConfig;
use crate::error::FixpError;
use crate::messages::{
    Establish, EstablishmentAck, EstablishmentReject, Negotiate, NegotiationReject,
    NegotiationResponse, SessionMessage,
};
use crate::output::{Event, HandshakeStage, SessionStatus};
use crate::role::bound_api;
use crate::session::{
    Binding, Bound, Classified, Core, HandshakeMessage, PeerMessage, Session, classify,
};
use crate::types::{Credentials, EstablishmentRejectCode, FlowType, Nanotime, SessionId};
use ironfix_core::SeqNum;
use std::time::{Duration, Instant};

/// Why a client is closed for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClosedReason {
    NegotiationRejected,
    NegotiationTimedOut,
    Unnegotiated,
    ProtocolViolation,
    TransportClosed,
}

#[derive(Debug)]
enum ClientState {
    Idle,
    Negotiating {
        request: Nanotime,
        sent_at: Instant,
    },
    Negotiated {
        session: Box<Session>,
    },
    Establishing {
        session: Box<Session>,
        request: Nanotime,
        sent_at: Instant,
    },
    Bound {
        session: Box<Session>,
        binding: Binding,
    },
    Closed(ClosedReason),
}

impl ClientState {
    const fn status(&self) -> SessionStatus {
        match self {
            Self::Idle => SessionStatus::Idle,
            Self::Negotiating { .. } => SessionStatus::Negotiating,
            Self::Negotiated { .. } => SessionStatus::Negotiated,
            Self::Establishing { .. } => SessionStatus::Establishing,
            Self::Bound { binding, .. } => binding.status(),
            Self::Closed(_) => SessionStatus::Closed,
        }
    }
}

/// A FIXP client: the side that negotiates and establishes a session.
///
/// Sans-IO: it takes decoded session messages, application-message arrivals,
/// commands and timer ticks, each with the current [`Instant`], and queues
/// [`Output`](crate::Output)s for the driver. See the crate documentation for
/// the driver loop.
#[derive(Debug)]
pub struct FixpClient {
    core: Core,
    session_id: SessionId,
    flow: FlowType,
    credentials: Option<Credentials>,
    state: ClientState,
}

impl FixpClient {
    /// Creates a client for the session `session_id` with client flow `flow`.
    ///
    /// `session_id` should be a fresh RFC 4122 version 4 UUID: FIXP never
    /// reuses one (section 3.4.1), and this crate reads no entropy to make
    /// one. `credentials` go in Negotiate and in every Establish.
    #[must_use]
    pub fn new(
        config: FixpConfig,
        clock: ClockAnchor,
        session_id: SessionId,
        flow: FlowType,
        credentials: Option<Credentials>,
    ) -> Self {
        Self {
            core: Core::new(config, RequestClock::new(clock)),
            session_id,
            flow,
            credentials,
            state: ClientState::Idle,
        }
    }

    /// The session identifier.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// The flow type from client to server.
    #[must_use]
    pub const fn client_flow(&self) -> FlowType {
        self.flow
    }

    /// The flow type from server to client, once negotiated.
    #[must_use]
    pub fn server_flow(&self) -> Option<FlowType> {
        self.session().map(Session::remote_flow)
    }

    /// The current state.
    #[must_use]
    pub const fn status(&self) -> SessionStatus {
        self.state.status()
    }

    /// Sends Negotiate (FIXP v1.1 section 4.2.1).
    ///
    /// # Errors
    /// [`FixpError::InvalidState`] unless idle,
    /// [`FixpError::TransportClosing`] while the session waits for the
    /// driver to report the transport closed, and
    /// [`FixpError::ClockOutOfRange`].
    pub fn negotiate(&mut self, now: Instant) -> Result<(), FixpError> {
        if self.core.transport_closing() {
            return Err(FixpError::TransportClosing {
                operation: "negotiate",
            });
        }
        match self.state {
            ClientState::Idle => {}
            ClientState::Negotiating { .. }
            | ClientState::Negotiated { .. }
            | ClientState::Establishing { .. }
            | ClientState::Bound { .. }
            | ClientState::Closed(_) => {
                return Err(FixpError::InvalidState {
                    operation: "negotiate",
                    status: self.status(),
                });
            }
        }
        let request = self.core.request_timestamp(now)?;
        tracing::debug!(session_id = %self.session_id, flow = ?self.flow, "fixp negotiate");
        self.core.send(SessionMessage::Negotiate(Negotiate {
            session_id: self.session_id,
            timestamp: request,
            client_flow: self.flow,
            credentials: self.credentials.clone(),
        }));
        self.state = ClientState::Negotiating {
            request,
            sent_at: now,
        };
        Ok(())
    }

    /// Sends Establish to bind the negotiated session to the transport
    /// (FIXP v1.1 section 4.3.1), the first time or after an unbinding.
    ///
    /// On a sequenced client flow it announces the next outbound sequence
    /// number as `NextSeqNo`.
    ///
    /// # Errors
    /// [`FixpError::InvalidState`] unless negotiated and unbound,
    /// [`FixpError::TransportClosing`] while the session waits for the
    /// driver to report the previous transport closed, and
    /// [`FixpError::ClockOutOfRange`].
    pub fn establish(&mut self, now: Instant) -> Result<(), FixpError> {
        if self.core.transport_closing() {
            return Err(FixpError::TransportClosing {
                operation: "establish",
            });
        }
        let state = std::mem::replace(&mut self.state, ClientState::Idle);
        match state {
            ClientState::Negotiated { session } => match self.core.request_timestamp(now) {
                Ok(request) => {
                    tracing::debug!(session_id = %self.session_id, "fixp establish");
                    self.core.send(SessionMessage::Establish(Establish {
                        session_id: self.session_id,
                        timestamp: request,
                        keepalive_interval: self.core.config().keepalive_millis(),
                        next_seq_no: session.announced_next_seq(),
                        credentials: self.credentials.clone(),
                    }));
                    self.state = ClientState::Establishing {
                        session,
                        request,
                        sent_at: now,
                    };
                    Ok(())
                }
                Err(error) => {
                    self.state = ClientState::Negotiated { session };
                    Err(error)
                }
            },
            other @ (ClientState::Idle
            | ClientState::Negotiating { .. }
            | ClientState::Establishing { .. }
            | ClientState::Bound { .. }
            | ClientState::Closed(_)) => {
                let status = other.status();
                self.state = other;
                Err(FixpError::InvalidState {
                    operation: "establish",
                    status,
                })
            }
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
        let state = std::mem::replace(&mut self.state, ClientState::Idle);
        self.state = match classify(message) {
            Classified::Handshake(message) => self.on_handshake(state, message, now),
            Classified::Peer(message) => self.on_peer(state, message, now),
        };
    }

    /// Runs the timers due at `now`: heartbeats, the counterparty silence
    /// check, retransmission stalls, and handshake and termination timeouts.
    pub fn handle_timeout(&mut self, now: Instant) {
        let handshake_timeout = self.core.config().handshake_timeout();
        let state = std::mem::replace(&mut self.state, ClientState::Idle);
        self.state = match state {
            ClientState::Negotiating { request, sent_at } => {
                if elapsed(sent_at, handshake_timeout, now) {
                    tracing::warn!(session_id = %self.session_id, "fixp negotiation timed out");
                    self.core.event(Event::HandshakeTimedOut {
                        stage: HandshakeStage::Negotiation,
                    });
                    // A late answer would arrive on this transport; a new
                    // negotiation needs a new identifier and transport
                    // (Appendix A 7.1.7.6).
                    self.core.close_transport();
                    ClientState::Closed(ClosedReason::NegotiationTimedOut)
                } else {
                    ClientState::Negotiating { request, sent_at }
                }
            }
            ClientState::Establishing {
                session,
                request,
                sent_at,
            } => {
                if elapsed(sent_at, handshake_timeout, now) {
                    tracing::warn!(session_id = %self.session_id, "fixp establishment timed out");
                    self.core.event(Event::HandshakeTimedOut {
                        stage: HandshakeStage::Establishment,
                    });
                    // The session stays negotiated; the retry of Appendix A
                    // 7.1.12.9 goes on a new transport.
                    self.core.close_transport();
                    ClientState::Negotiated { session }
                } else {
                    ClientState::Establishing {
                        session,
                        request,
                        sent_at,
                    }
                }
            }
            ClientState::Bound {
                mut session,
                mut binding,
            } => match session.on_timeout(&mut self.core, &mut binding, now) {
                Bound::Stay => ClientState::Bound { session, binding },
                Bound::Unbind => ClientState::Negotiated { session },
            },
            other @ (ClientState::Idle
            | ClientState::Negotiated { .. }
            | ClientState::Closed(_)) => other,
        };
    }

    /// The next instant at which [`handle_timeout`](Self::handle_timeout)
    /// has work to do, if any.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        let handshake_timeout = self.core.config().handshake_timeout();
        match &self.state {
            ClientState::Negotiating { sent_at, .. }
            | ClientState::Establishing { sent_at, .. } => sent_at.checked_add(handshake_timeout),
            ClientState::Bound { session, binding } => {
                session.next_deadline(self.core.config(), binding)
            }
            ClientState::Idle | ClientState::Negotiated { .. } | ClientState::Closed(_) => None,
        }
    }

    /// Tells the session the transport is closed, by either side or by a
    /// failure. A bound session becomes negotiated and can be established
    /// again on a new transport (FIXP v1.1 section 3.4.3).
    pub fn on_transport_closed(&mut self) {
        self.core.transport_closed();
        let state = std::mem::replace(&mut self.state, ClientState::Idle);
        self.state = match state {
            ClientState::Idle => ClientState::Idle,
            ClientState::Negotiating { .. } => {
                self.core.event(Event::TransportClosed);
                ClientState::Closed(ClosedReason::TransportClosed)
            }
            ClientState::Negotiated { session } | ClientState::Establishing { session, .. } => {
                self.core.event(Event::TransportClosed);
                ClientState::Negotiated { session }
            }
            ClientState::Bound { mut session, .. } => {
                session.release_binding_state();
                self.core.event(Event::TransportClosed);
                ClientState::Negotiated { session }
            }
            ClientState::Closed(reason) => ClientState::Closed(reason),
        };
    }

    // ----- role internals used by `bound_api!` -------------------------------

    fn session(&self) -> Option<&Session> {
        match &self.state {
            ClientState::Negotiated { session }
            | ClientState::Establishing { session, .. }
            | ClientState::Bound { session, .. } => Some(session),
            ClientState::Idle | ClientState::Negotiating { .. } | ClientState::Closed(_) => None,
        }
    }

    fn bound_parts(
        &mut self,
        operation: &'static str,
    ) -> Result<(&mut Core, &mut Session, &mut Binding), FixpError> {
        let status = self.state.status();
        match &mut self.state {
            ClientState::Bound { session, binding } => Ok((&mut self.core, session, binding)),
            ClientState::Idle
            | ClientState::Negotiating { .. }
            | ClientState::Negotiated { .. }
            | ClientState::Establishing { .. }
            | ClientState::Closed(_) => Err(FixpError::InvalidState { operation, status }),
        }
    }

    fn after(&mut self, bound: Bound) {
        if bound == Bound::Stay {
            return;
        }
        let state = std::mem::replace(&mut self.state, ClientState::Idle);
        self.state = match state {
            ClientState::Bound { session, .. } => ClientState::Negotiated { session },
            other @ (ClientState::Idle
            | ClientState::Negotiating { .. }
            | ClientState::Negotiated { .. }
            | ClientState::Establishing { .. }
            | ClientState::Closed(_)) => other,
        };
    }

    fn application_before_established(&mut self) {
        // Still arriving on a transport this side asked to close: nothing to
        // answer, it is simply dropped.
        if self.core.transport_closing() {
            return;
        }
        let state = std::mem::replace(&mut self.state, ClientState::Idle);
        self.state = self.violation(state, "application message before establishment");
    }

    // ----- message handling --------------------------------------------------

    fn on_peer(
        &mut self,
        state: ClientState,
        message: PeerMessage<'_>,
        now: Instant,
    ) -> ClientState {
        match state {
            ClientState::Bound {
                mut session,
                mut binding,
            } => match session.on_peer(&mut self.core, &mut binding, message, now) {
                Bound::Stay => ClientState::Bound { session, binding },
                Bound::Unbind => ClientState::Negotiated { session },
            },
            ClientState::Closed(reason) => ClientState::Closed(reason),
            unbound @ (ClientState::Idle
            | ClientState::Negotiating { .. }
            | ClientState::Negotiated { .. }
            | ClientState::Establishing { .. }) => match message {
                // Section 3.6: MessageTemplate may be sent at any time.
                PeerMessage::MessageTemplate => unbound,
                PeerMessage::Terminate(terminate) => {
                    self.core.event(Event::Terminated {
                        code: terminate.code,
                        reason: terminate.reason.clone(),
                        by: crate::output::TerminatedBy::Peer,
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
        state: ClientState,
        message: HandshakeMessage<'_>,
        now: Instant,
    ) -> ClientState {
        match message {
            HandshakeMessage::NegotiationResponse(m) => self.on_negotiation_response(state, m),
            HandshakeMessage::NegotiationReject(m) => self.on_negotiation_reject(state, m),
            HandshakeMessage::EstablishmentAck(m) => self.on_establishment_ack(state, m, now),
            HandshakeMessage::EstablishmentReject(m) => self.on_establishment_reject(state, m),
            HandshakeMessage::Negotiate(_) | HandshakeMessage::Establish(_) => {
                self.violation(state, "a client-only message sent by the server")
            }
        }
    }

    fn on_negotiation_response(
        &mut self,
        state: ClientState,
        m: &NegotiationResponse,
    ) -> ClientState {
        match state {
            ClientState::Negotiating { request, sent_at } => {
                // Appendix A 7.1.7.5: a mismatched answer is ignored.
                if m.session_id != self.session_id || m.request_timestamp != request {
                    self.core.ignore(
                        NegotiationResponse::NAME,
                        "session id or request timestamp does not match the Negotiate",
                    );
                    return ClientState::Negotiating { request, sent_at };
                }
                // Section 3.4.4.1: only one flow of a session may be None.
                if self.flow == FlowType::None && m.server_flow == FlowType::None {
                    self.core
                        .violation_unbound("both flows of the session are None");
                    return ClientState::Closed(ClosedReason::ProtocolViolation);
                }
                tracing::debug!(session_id = %self.session_id, server_flow = ?m.server_flow, "fixp negotiated");
                self.core.event(Event::Negotiated {
                    session_id: self.session_id,
                    client_flow: self.flow,
                    server_flow: m.server_flow,
                });
                ClientState::Negotiated {
                    session: Box::new(Session::new(self.session_id, self.flow, m.server_flow)),
                }
            }
            other @ (ClientState::Idle
            | ClientState::Negotiated { .. }
            | ClientState::Establishing { .. }
            | ClientState::Bound { .. }
            | ClientState::Closed(_)) => {
                self.core
                    .ignore(NegotiationResponse::NAME, "no Negotiate is outstanding");
                other
            }
        }
    }

    fn on_negotiation_reject(&mut self, state: ClientState, m: &NegotiationReject) -> ClientState {
        match state {
            ClientState::Negotiating { request, sent_at } => {
                if m.session_id != self.session_id || m.request_timestamp != request {
                    self.core.ignore(
                        NegotiationReject::NAME,
                        "session id or request timestamp does not match the Negotiate",
                    );
                    return ClientState::Negotiating { request, sent_at };
                }
                tracing::warn!(session_id = %self.session_id, code = ?m.code, "fixp negotiation rejected");
                self.core.event(Event::NegotiationRejected {
                    code: m.code,
                    reason: m.reason.clone(),
                });
                // Section 4.2.3: the transport is terminated after a reject.
                self.core.close_transport();
                ClientState::Closed(ClosedReason::NegotiationRejected)
            }
            other @ (ClientState::Idle
            | ClientState::Negotiated { .. }
            | ClientState::Establishing { .. }
            | ClientState::Bound { .. }
            | ClientState::Closed(_)) => {
                self.core
                    .ignore(NegotiationReject::NAME, "no Negotiate is outstanding");
                other
            }
        }
    }

    fn on_establishment_ack(
        &mut self,
        state: ClientState,
        m: &EstablishmentAck,
        now: Instant,
    ) -> ClientState {
        match state {
            ClientState::Establishing {
                mut session,
                request,
                sent_at,
            } => {
                // Appendix A 7.1.12.8: a mismatched answer is ignored.
                if m.session_id != self.session_id || m.request_timestamp != request {
                    self.core.ignore(
                        EstablishmentAck::NAME,
                        "session id or request timestamp does not match the Establish",
                    );
                    return ClientState::Establishing {
                        session,
                        request,
                        sent_at,
                    };
                }
                let local = self.core.config().keepalive_interval();
                let remote = Duration::from_millis(u64::from(m.keepalive_interval));
                let mut binding = session.bind(now, local, remote);
                if !self
                    .core
                    .config()
                    .accepts_peer_keepalive(m.keepalive_interval)
                {
                    let _ = session.violation(
                        &mut self.core,
                        &mut binding,
                        "server keepalive interval out of the accepted range",
                    );
                    return ClientState::Negotiated { session };
                }
                tracing::debug!(session_id = %self.session_id, "fixp established");
                self.core.event(Event::Established {
                    peer_keepalive_interval: remote,
                    peer_next_seq_no: m.next_seq_no.map(SeqNum::new),
                });
                match session.on_established(&mut self.core, &mut binding, m.next_seq_no, now) {
                    Bound::Stay => ClientState::Bound { session, binding },
                    Bound::Unbind => ClientState::Negotiated { session },
                }
            }
            other @ (ClientState::Idle
            | ClientState::Negotiating { .. }
            | ClientState::Negotiated { .. }
            | ClientState::Bound { .. }
            | ClientState::Closed(_)) => {
                self.core
                    .ignore(EstablishmentAck::NAME, "no Establish is outstanding");
                other
            }
        }
    }

    fn on_establishment_reject(
        &mut self,
        state: ClientState,
        m: &EstablishmentReject,
    ) -> ClientState {
        match state {
            ClientState::Establishing {
                session,
                request,
                sent_at,
            } => {
                if m.session_id != self.session_id || m.request_timestamp != request {
                    self.core.ignore(
                        EstablishmentReject::NAME,
                        "session id or request timestamp does not match the Establish",
                    );
                    return ClientState::Establishing {
                        session,
                        request,
                        sent_at,
                    };
                }
                tracing::warn!(session_id = %self.session_id, code = ?m.code, "fixp establishment rejected");
                self.core.event(Event::EstablishmentRejected {
                    code: m.code,
                    reason: m.reason.clone(),
                });
                match m.code {
                    // The server does not know the session: negotiate anew.
                    EstablishmentRejectCode::Unnegotiated => {
                        ClientState::Closed(ClosedReason::Unnegotiated)
                    }
                    EstablishmentRejectCode::AlreadyEstablished
                    | EstablishmentRejectCode::SessionBlocked
                    | EstablishmentRejectCode::KeepaliveInterval
                    | EstablishmentRejectCode::Credentials
                    | EstablishmentRejectCode::Unspecified => ClientState::Negotiated { session },
                }
            }
            other @ (ClientState::Idle
            | ClientState::Negotiating { .. }
            | ClientState::Negotiated { .. }
            | ClientState::Bound { .. }
            | ClientState::Closed(_)) => {
                self.core
                    .ignore(EstablishmentReject::NAME, "no Establish is outstanding");
                other
            }
        }
    }

    /// The server broke the protocol in `state`.
    fn violation(&mut self, state: ClientState, reason: &'static str) -> ClientState {
        match state {
            ClientState::Bound {
                mut session,
                mut binding,
            } => {
                let _ = session.violation(&mut self.core, &mut binding, reason);
                ClientState::Negotiated { session }
            }
            ClientState::Closed(closed) => ClientState::Closed(closed),
            unbound @ (ClientState::Idle
            | ClientState::Negotiating { .. }
            | ClientState::Negotiated { .. }
            | ClientState::Establishing { .. }) => {
                self.core.violation_unbound(reason);
                Self::after_unbound_failure(unbound)
            }
        }
    }

    /// Where an unbound client goes when its transport is closed on a
    /// failure: a negotiation in flight is lost, a negotiated session is kept.
    fn after_unbound_failure(state: ClientState) -> ClientState {
        match state {
            ClientState::Negotiating { .. } => ClientState::Closed(ClosedReason::ProtocolViolation),
            ClientState::Establishing { session, .. } => ClientState::Negotiated { session },
            other @ (ClientState::Idle
            | ClientState::Negotiated { .. }
            | ClientState::Bound { .. }
            | ClientState::Closed(_)) => other,
        }
    }
}

bound_api!(FixpClient);

/// `true` once `timeout` has passed since `since`.
pub(crate) fn elapsed(since: Instant, timeout: Duration, now: Instant) -> bool {
    since
        .checked_add(timeout)
        .is_some_and(|deadline| now >= deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{MessageTemplate, Sequence, Terminate};
    use crate::output::{Delivery, Output, TerminatedBy};
    use crate::testkit::{
        HANDSHAKE, KEEPALIVE, OTHER_SESSION, SESSION, WALL, anchor, at, client, closes, config,
        deliver_all, drain, established_pair, events, negotiated_pair, sent,
    };
    use crate::types::{NegotiationRejectCode, TerminationCode};

    /// The Negotiate the client just queued.
    fn negotiate_sent(client: &mut FixpClient) -> Negotiate {
        match sent(&drain(client)).as_slice() {
            [SessionMessage::Negotiate(negotiate)] => negotiate.clone(),
            other => panic!("expected one Negotiate, got {other:?}"),
        }
    }

    /// The Establish the client just queued.
    fn establish_sent(client: &mut FixpClient) -> Establish {
        match sent(&drain(client)).as_slice() {
            [SessionMessage::Establish(establish)] => establish.clone(),
            other => panic!("expected one Establish, got {other:?}"),
        }
    }

    fn response(request: Nanotime, server_flow: FlowType) -> SessionMessage {
        SessionMessage::NegotiationResponse(NegotiationResponse {
            session_id: SESSION,
            request_timestamp: request,
            server_flow,
            credentials: None,
        })
    }

    fn ack(request: Nanotime, keepalive: u32, next_seq_no: Option<u64>) -> SessionMessage {
        SessionMessage::EstablishmentAck(EstablishmentAck {
            session_id: SESSION,
            request_timestamp: request,
            keepalive_interval: keepalive,
            next_seq_no,
        })
    }

    /// A client negotiated with a Recoverable server flow, Establish sent.
    fn establishing(origin: Instant) -> (FixpClient, Nanotime) {
        let mut client = client(origin, FlowType::Idempotent);
        assert_eq!(client.negotiate(origin), Ok(()));
        let negotiate = negotiate_sent(&mut client);
        client.handle_message(
            &response(negotiate.timestamp, FlowType::Recoverable),
            origin,
        );
        let _ = drain(&mut client);
        assert_eq!(client.establish(origin), Ok(()));
        let establish = establish_sent(&mut client);
        (client, establish.timestamp)
    }

    #[test]
    fn test_client_negotiate_sends_negotiate_and_waits() {
        let origin = Instant::now();
        let credentials = Credentials::try_new(b"user:pass".to_vec()).ok();
        let mut client = FixpClient::new(
            config(),
            anchor(origin),
            SESSION,
            FlowType::Idempotent,
            credentials.clone(),
        );
        assert_eq!(client.status(), SessionStatus::Idle);
        assert_eq!(client.poll_timeout(), None);
        assert_eq!(client.negotiate(origin), Ok(()));
        let negotiate = negotiate_sent(&mut client);
        assert_eq!(negotiate.session_id, SESSION);
        assert_eq!(negotiate.timestamp, Nanotime::from_nanos(WALL));
        assert_eq!(negotiate.client_flow, FlowType::Idempotent);
        assert_eq!(negotiate.credentials, credentials);
        assert_eq!(client.status(), SessionStatus::Negotiating);
        assert_eq!(client.poll_timeout(), Some(origin + HANDSHAKE));
        assert_eq!(client.session_id(), SESSION);
        assert_eq!(client.client_flow(), FlowType::Idempotent);
        assert_eq!(client.server_flow(), None);
    }

    #[test]
    fn test_client_negotiate_twice_is_refused() {
        let origin = Instant::now();
        let mut client = client(origin, FlowType::Recoverable);
        assert_eq!(client.negotiate(origin), Ok(()));
        assert_eq!(
            client.negotiate(origin),
            Err(FixpError::InvalidState {
                operation: "negotiate",
                status: SessionStatus::Negotiating,
            })
        );
    }

    #[test]
    fn test_client_negotiation_response_negotiates() {
        let origin = Instant::now();
        let mut client = client(origin, FlowType::Idempotent);
        assert_eq!(client.negotiate(origin), Ok(()));
        let negotiate = negotiate_sent(&mut client);
        client.handle_message(
            &response(negotiate.timestamp, FlowType::Recoverable),
            origin,
        );
        assert_eq!(
            events(&drain(&mut client)),
            vec![Event::Negotiated {
                session_id: SESSION,
                client_flow: FlowType::Idempotent,
                server_flow: FlowType::Recoverable,
            }]
        );
        assert_eq!(client.status(), SessionStatus::Negotiated);
        assert_eq!(client.server_flow(), Some(FlowType::Recoverable));
        assert_eq!(client.poll_timeout(), None);
        assert_eq!(client.next_outbound_seq(), Some(SeqNum::new(1)));
        // A sequenced flow numbers from 1 unless the first establishment
        // says otherwise.
        assert_eq!(client.next_inbound_seq(), Some(SeqNum::new(1)));
    }

    #[test]
    fn test_client_ignores_a_response_for_another_request() {
        // FIXP v1.1 Appendix A 7.1.7.5.
        let origin = Instant::now();
        let mut client = client(origin, FlowType::Recoverable);
        assert_eq!(client.negotiate(origin), Ok(()));
        let negotiate = negotiate_sent(&mut client);
        let wrong_timestamp = response(
            Nanotime::from_nanos(negotiate.timestamp.as_nanos() + 1),
            FlowType::Recoverable,
        );
        let wrong_session = SessionMessage::NegotiationResponse(NegotiationResponse {
            session_id: OTHER_SESSION,
            request_timestamp: negotiate.timestamp,
            server_flow: FlowType::Recoverable,
            credentials: None,
        });
        let wrong_reject = SessionMessage::NegotiationReject(NegotiationReject {
            session_id: OTHER_SESSION,
            request_timestamp: negotiate.timestamp,
            code: NegotiationRejectCode::Unspecified,
            reason: String::new(),
        });
        for message in [wrong_timestamp, wrong_session, wrong_reject] {
            client.handle_message(&message, origin);
            let outputs = drain(&mut client);
            assert!(matches!(
                events(&outputs).as_slice(),
                [Event::Ignored { .. }]
            ));
            assert!(sent(&outputs).is_empty());
            assert_eq!(client.status(), SessionStatus::Negotiating);
        }
    }

    #[test]
    fn test_client_ignores_answers_with_nothing_outstanding() {
        let origin = Instant::now();
        let mut client = client(origin, FlowType::Recoverable);
        let unsolicited = [
            response(Nanotime::from_nanos(1), FlowType::Recoverable),
            SessionMessage::NegotiationReject(NegotiationReject {
                session_id: SESSION,
                request_timestamp: Nanotime::from_nanos(1),
                code: NegotiationRejectCode::Unspecified,
                reason: String::new(),
            }),
            ack(Nanotime::from_nanos(1), 1_000, None),
            SessionMessage::EstablishmentReject(EstablishmentReject {
                session_id: SESSION,
                request_timestamp: Nanotime::from_nanos(1),
                code: EstablishmentRejectCode::Unspecified,
                reason: String::new(),
            }),
        ];
        for message in unsolicited {
            client.handle_message(&message, origin);
            assert!(matches!(
                events(&drain(&mut client)).as_slice(),
                [Event::Ignored { .. }]
            ));
            assert_eq!(client.status(), SessionStatus::Idle);
        }
    }

    #[test]
    fn test_client_negotiation_reject_closes_the_session() {
        let origin = Instant::now();
        let mut client = client(origin, FlowType::Recoverable);
        assert_eq!(client.negotiate(origin), Ok(()));
        let negotiate = negotiate_sent(&mut client);
        client.handle_message(
            &SessionMessage::NegotiationReject(NegotiationReject {
                session_id: SESSION,
                request_timestamp: negotiate.timestamp,
                code: NegotiationRejectCode::Credentials,
                reason: "Invalid Trader ID".to_owned(),
            }),
            origin,
        );
        let outputs = drain(&mut client);
        assert_eq!(
            events(&outputs),
            vec![Event::NegotiationRejected {
                code: NegotiationRejectCode::Credentials,
                reason: "Invalid Trader ID".to_owned(),
            }]
        );
        assert!(closes(&outputs));
        assert_eq!(client.status(), SessionStatus::Closed);
        // Nothing more goes on the closing transport...
        assert_eq!(
            client.establish(origin),
            Err(FixpError::TransportClosing {
                operation: "establish"
            })
        );
        // ...and once it is closed, a rejected client stays closed.
        client.on_transport_closed();
        assert!(matches!(
            client.establish(origin),
            Err(FixpError::InvalidState { .. })
        ));
        assert!(matches!(
            client.negotiate(origin),
            Err(FixpError::InvalidState { .. })
        ));
    }

    #[test]
    fn test_client_negotiation_times_out() {
        let origin = Instant::now();
        let mut client = client(origin, FlowType::Recoverable);
        assert_eq!(client.negotiate(origin), Ok(()));
        let _ = drain(&mut client);
        client.handle_timeout(origin + HANDSHAKE - Duration::from_millis(1));
        assert!(drain(&mut client).is_empty());
        assert_eq!(client.status(), SessionStatus::Negotiating);
        client.handle_timeout(origin + HANDSHAKE);
        let outputs = drain(&mut client);
        assert_eq!(
            events(&outputs),
            vec![Event::HandshakeTimedOut {
                stage: HandshakeStage::Negotiation
            }]
        );
        assert!(
            closes(&outputs),
            "a late answer must not reach a new client"
        );
        assert_eq!(client.status(), SessionStatus::Closed);
        assert_eq!(client.poll_timeout(), None);
    }

    #[test]
    fn test_client_refuses_a_response_with_both_flows_none() {
        // FIXP v1.1 section 3.4.4.1.
        let origin = Instant::now();
        let mut client = client(origin, FlowType::None);
        assert_eq!(client.negotiate(origin), Ok(()));
        let negotiate = negotiate_sent(&mut client);
        client.handle_message(&response(negotiate.timestamp, FlowType::None), origin);
        let outputs = drain(&mut client);
        assert!(matches!(
            events(&outputs).as_slice(),
            [Event::ProtocolViolation { .. }]
        ));
        assert!(closes(&outputs));
        assert_eq!(client.status(), SessionStatus::Closed);
    }

    #[test]
    fn test_client_establish_requires_a_negotiated_session() {
        let origin = Instant::now();
        let mut client = client(origin, FlowType::Recoverable);
        assert_eq!(
            client.establish(origin),
            Err(FixpError::InvalidState {
                operation: "establish",
                status: SessionStatus::Idle,
            })
        );
        assert_eq!(client.status(), SessionStatus::Idle);
    }

    #[test]
    fn test_client_establish_announces_keepalive_next_seq_and_credentials() {
        let origin = Instant::now();
        let credentials = Credentials::try_new(b"token".to_vec()).ok();
        let mut client = FixpClient::new(
            config(),
            anchor(origin),
            SESSION,
            FlowType::Recoverable,
            credentials.clone(),
        );
        assert_eq!(client.negotiate(origin), Ok(()));
        let negotiate = negotiate_sent(&mut client);
        client.handle_message(
            &response(negotiate.timestamp, FlowType::Recoverable),
            origin,
        );
        let _ = drain(&mut client);
        let later = at(origin, 20);
        assert_eq!(client.establish(later), Ok(()));
        let establish = establish_sent(&mut client);
        assert_eq!(establish.session_id, SESSION);
        assert_eq!(establish.keepalive_interval, 1_000);
        assert_eq!(establish.next_seq_no, Some(1));
        assert_eq!(establish.credentials, credentials);
        assert_eq!(
            establish.timestamp,
            Nanotime::from_nanos(WALL + 20_000_000),
            "request timestamps advance with the monotonic clock"
        );
        assert_eq!(client.status(), SessionStatus::Establishing);
        assert_eq!(client.poll_timeout(), Some(later + HANDSHAKE));
    }

    #[test]
    fn test_client_establish_on_an_unsequenced_flow_sends_no_next_seq() {
        let origin = Instant::now();
        let (mut client, _server) =
            negotiated_pair(origin, FlowType::Unsequenced, FlowType::Recoverable);
        assert_eq!(client.establish(origin), Ok(()));
        assert_eq!(establish_sent(&mut client).next_seq_no, None);
        assert_eq!(client.next_outbound_seq(), None);
    }

    #[test]
    fn test_client_establishment_ack_establishes() {
        let origin = Instant::now();
        let (mut client, request) = establishing(origin);
        client.handle_message(&ack(request, 2_000, Some(1_000)), origin);
        let outputs = drain(&mut client);
        assert_eq!(
            events(&outputs),
            vec![Event::Established {
                peer_keepalive_interval: Duration::from_secs(2),
                peer_next_seq_no: Some(SeqNum::new(1_000)),
            }]
        );
        assert!(sent(&outputs).is_empty());
        assert_eq!(client.status(), SessionStatus::Established);
        assert_eq!(client.next_inbound_seq(), Some(SeqNum::new(1_000)));
        // The next deadline is the heartbeat, one keepalive interval later.
        assert_eq!(client.poll_timeout(), Some(origin + KEEPALIVE));
    }

    #[test]
    fn test_client_ignores_a_mismatched_establishment_answer() {
        // FIXP v1.1 Appendix A 7.1.12.8.
        let origin = Instant::now();
        let (mut client, request) = establishing(origin);
        let wrong = Nanotime::from_nanos(request.as_nanos() + 5);
        client.handle_message(&ack(wrong, 1_000, Some(1)), origin);
        client.handle_message(
            &SessionMessage::EstablishmentReject(EstablishmentReject {
                session_id: SESSION,
                request_timestamp: wrong,
                code: EstablishmentRejectCode::Unspecified,
                reason: String::new(),
            }),
            origin,
        );
        let outputs = drain(&mut client);
        assert!(matches!(
            events(&outputs).as_slice(),
            [
                Event::Ignored {
                    message: "EstablishmentAck",
                    ..
                },
                Event::Ignored {
                    message: "EstablishmentReject",
                    ..
                }
            ]
        ));
        assert_eq!(client.status(), SessionStatus::Establishing);
    }

    #[test]
    fn test_client_terminates_on_a_server_keepalive_out_of_range() {
        let origin = Instant::now();
        let (mut client, request) = establishing(origin);
        client.handle_message(&ack(request, 10, Some(1)), origin);
        let outputs = drain(&mut client);
        assert!(matches!(
            sent(&outputs).as_slice(),
            [SessionMessage::Terminate(Terminate {
                code: TerminationCode::UnspecifiedError,
                ..
            })]
        ));
        assert!(closes(&outputs));
        assert_eq!(client.status(), SessionStatus::Negotiated);
    }

    #[test]
    fn test_client_establishment_reject_keeps_the_session_negotiated() {
        let origin = Instant::now();
        let (mut client, request) = establishing(origin);
        client.handle_message(
            &SessionMessage::EstablishmentReject(EstablishmentReject {
                session_id: SESSION,
                request_timestamp: request,
                code: EstablishmentRejectCode::KeepaliveInterval,
                reason: "Invalid KeepAlive Interval".to_owned(),
            }),
            origin,
        );
        assert_eq!(
            events(&drain(&mut client)),
            vec![Event::EstablishmentRejected {
                code: EstablishmentRejectCode::KeepaliveInterval,
                reason: "Invalid KeepAlive Interval".to_owned(),
            }]
        );
        assert_eq!(client.status(), SessionStatus::Negotiated);
        assert_eq!(
            client.establish(at(origin, 1)),
            Ok(()),
            "a retry is allowed"
        );
    }

    #[test]
    fn test_client_unnegotiated_reject_closes_the_session() {
        let origin = Instant::now();
        let (mut client, request) = establishing(origin);
        client.handle_message(
            &SessionMessage::EstablishmentReject(EstablishmentReject {
                session_id: SESSION,
                request_timestamp: request,
                code: EstablishmentRejectCode::Unnegotiated,
                reason: String::new(),
            }),
            origin,
        );
        let _ = drain(&mut client);
        assert_eq!(client.status(), SessionStatus::Closed);
    }

    #[test]
    fn test_client_establishment_times_out_and_can_retry() {
        // FIXP v1.1 Appendix A 7.1.12.9.
        let origin = Instant::now();
        let (mut client, _request) = establishing(origin);
        client.handle_timeout(origin + HANDSHAKE);
        let outputs = drain(&mut client);
        assert_eq!(
            events(&outputs),
            vec![Event::HandshakeTimedOut {
                stage: HandshakeStage::Establishment
            }]
        );
        assert!(closes(&outputs), "the retry goes on a new transport");
        assert_eq!(client.status(), SessionStatus::Negotiated);
        assert_eq!(
            client.establish(origin + HANDSHAKE),
            Err(FixpError::TransportClosing {
                operation: "establish"
            })
        );
        client.on_transport_closed();
        assert_eq!(events(&drain(&mut client)), vec![Event::TransportClosed]);
        assert_eq!(client.establish(origin + HANDSHAKE), Ok(()));
    }

    #[test]
    fn test_client_treats_server_only_messages_as_violations() {
        let origin = Instant::now();
        let negotiate = SessionMessage::Negotiate(Negotiate {
            session_id: SESSION,
            timestamp: Nanotime::from_nanos(1),
            client_flow: FlowType::Recoverable,
            credentials: None,
        });
        // Before establishment: the transport is closed, the session kept.
        let (mut negotiated, _server) =
            negotiated_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        negotiated.handle_message(&negotiate, origin);
        let outputs = drain(&mut negotiated);
        assert!(closes(&outputs));
        assert!(sent(&outputs).is_empty());
        assert_eq!(negotiated.status(), SessionStatus::Negotiated);
        // Once established: Terminate, then close.
        let (mut client, _server) =
            established_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        let establish = SessionMessage::Establish(Establish {
            session_id: SESSION,
            timestamp: Nanotime::from_nanos(1),
            keepalive_interval: 1_000,
            next_seq_no: None,
            credentials: None,
        });
        client.handle_message(&establish, origin);
        let outputs = drain(&mut client);
        assert!(matches!(
            sent(&outputs).as_slice(),
            [SessionMessage::Terminate(_)]
        ));
        assert!(closes(&outputs));
        assert_eq!(client.status(), SessionStatus::Negotiated);
    }

    #[test]
    fn test_client_session_messages_before_establishment() {
        let origin = Instant::now();
        let mut client = client(origin, FlowType::Recoverable);
        assert_eq!(client.negotiate(origin), Ok(()));
        let _ = drain(&mut client);
        // MessageTemplate may be sent at any time (section 3.6).
        client.handle_message(
            &SessionMessage::MessageTemplate(MessageTemplate {
                encoding_type: 1,
                effective_time: None,
                version: Vec::new(),
                template: b"t".to_vec(),
            }),
            origin,
        );
        assert!(drain(&mut client).is_empty());
        assert_eq!(client.status(), SessionStatus::Negotiating);
        // A Sequence before establishment is a violation (section 6.3).
        client.handle_message(
            &SessionMessage::Sequence(Sequence { next_seq_no: 1 }),
            origin,
        );
        let outputs = drain(&mut client);
        assert!(matches!(
            events(&outputs).as_slice(),
            [Event::ProtocolViolation { .. }]
        ));
        assert!(closes(&outputs));
        assert_eq!(client.status(), SessionStatus::Closed);
        // Until the driver reports the transport closed, what still arrives
        // on it is ignored: no second violation, no second close.
        client.handle_message(
            &SessionMessage::Sequence(Sequence { next_seq_no: 1 }),
            origin,
        );
        assert_eq!(
            drain(&mut client),
            vec![Output::Event(Event::Ignored {
                message: "Sequence",
                reason: "the transport is closing",
            })]
        );
        assert_eq!(client.on_application_message(origin), Delivery::Discard);
        assert!(drain(&mut client).is_empty());
        // A closed client ignores everything.
        client.on_transport_closed();
        let _ = drain(&mut client);
        client.handle_message(
            &SessionMessage::Sequence(Sequence { next_seq_no: 1 }),
            origin,
        );
        assert!(drain(&mut client).is_empty());
    }

    #[test]
    fn test_client_terminate_before_establishment_closes_the_transport() {
        let origin = Instant::now();
        let (mut client, _request) = establishing(origin);
        client.handle_message(
            &SessionMessage::Terminate(Terminate {
                session_id: SESSION,
                code: TerminationCode::Finished,
                reason: String::new(),
            }),
            origin,
        );
        let outputs = drain(&mut client);
        assert_eq!(
            events(&outputs),
            vec![Event::Terminated {
                code: TerminationCode::Finished,
                reason: String::new(),
                by: TerminatedBy::Peer,
            }]
        );
        assert!(closes(&outputs));
        assert_eq!(client.status(), SessionStatus::Negotiated);
    }

    #[test]
    fn test_client_application_message_before_establishment_is_discarded() {
        // FIXP v1.1 section 6.3.
        let origin = Instant::now();
        let (mut client, _server) =
            negotiated_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        assert_eq!(client.on_application_message(origin), Delivery::Discard);
        let outputs = drain(&mut client);
        assert!(closes(&outputs));
        assert_eq!(client.status(), SessionStatus::Negotiated);
        assert_eq!(
            client.send_application(origin),
            Err(FixpError::InvalidState {
                operation: "send_application",
                status: SessionStatus::Negotiated,
            })
        );
    }

    #[test]
    fn test_client_transport_closed_while_negotiating_closes_the_session() {
        let origin = Instant::now();
        let mut client = client(origin, FlowType::Recoverable);
        client.on_transport_closed();
        assert!(drain(&mut client).is_empty(), "nothing happens when idle");
        assert_eq!(client.negotiate(origin), Ok(()));
        let _ = drain(&mut client);
        client.on_transport_closed();
        assert_eq!(events(&drain(&mut client)), vec![Event::TransportClosed]);
        assert_eq!(client.status(), SessionStatus::Closed);
        client.on_transport_closed();
        assert!(drain(&mut client).is_empty());
    }

    #[test]
    fn test_client_reestablishes_after_the_transport_closes() {
        // FIXP v1.1 section 4.1: a client may re-establish without negotiating.
        let origin = Instant::now();
        let (mut client, mut server) =
            established_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        assert_eq!(client.send_application(origin), Ok(Some(SeqNum::new(1))));
        assert_eq!(client.send_application(origin), Ok(Some(SeqNum::new(2))));
        let _ = drain(&mut client);
        client.on_transport_closed();
        server.on_transport_closed();
        assert_eq!(events(&drain(&mut client)), vec![Event::TransportClosed]);
        let _ = drain(&mut server);
        assert_eq!(client.status(), SessionStatus::Negotiated);
        let later = at(origin, 500);
        assert_eq!(client.establish(later), Ok(()));
        let outputs = drain(&mut client);
        match sent(&outputs).as_slice() {
            [SessionMessage::Establish(establish)] => {
                assert_eq!(establish.next_seq_no, Some(3), "numbering continues");
            }
            other => panic!("expected an Establish, got {other:?}"),
        }
        deliver_all(&outputs, &mut server, later);
        let _ = drain(&mut server);
        assert_eq!(server.accept_establishment(later), Ok(()));
        let ack = drain(&mut server);
        deliver_all(&ack, &mut client, later);
        let _ = drain(&mut client);
        assert_eq!(client.status(), SessionStatus::Established);
        assert_eq!(client.send_application(later), Ok(Some(SeqNum::new(3))));
    }

    #[test]
    fn test_client_terminates_on_a_lower_next_seq_at_reestablishment() {
        // FIXP v1.1 Appendix A 7.2.3.
        let origin = Instant::now();
        let mut client = client(origin, FlowType::Idempotent);
        assert_eq!(client.negotiate(origin), Ok(()));
        let negotiate = negotiate_sent(&mut client);
        client.handle_message(
            &response(negotiate.timestamp, FlowType::Recoverable),
            origin,
        );
        assert_eq!(client.establish(origin), Ok(()));
        let request = establish_sent(&mut client).timestamp;
        client.handle_message(&ack(request, 1_000, Some(1_000)), origin);
        let _ = drain(&mut client);
        client.on_transport_closed();
        assert_eq!(client.establish(at(origin, 10)), Ok(()));
        let request = establish_sent(&mut client).timestamp;
        client.handle_message(&ack(request, 1_000, Some(100)), at(origin, 10));
        let outputs = drain(&mut client);
        assert!(matches!(
            sent(&outputs).as_slice(),
            [SessionMessage::Terminate(Terminate {
                code: TerminationCode::UnspecifiedError,
                ..
            })]
        ));
        assert!(closes(&outputs));
        assert_eq!(client.status(), SessionStatus::Negotiated);
    }

    #[test]
    fn test_client_debug_never_shows_credentials() {
        let origin = Instant::now();
        let credentials = Credentials::try_new(b"s3cr3t-password".to_vec()).ok();
        let mut client = FixpClient::new(
            config(),
            anchor(origin),
            SESSION,
            FlowType::Recoverable,
            credentials,
        );
        assert_eq!(client.negotiate(origin), Ok(()));
        let debug = format!("{client:?}");
        assert!(!debug.contains("s3cr3t"), "{debug}");
        assert!(debug.contains("redacted"));
        let outputs = drain(&mut client);
        let rendered = format!("{outputs:?}");
        assert!(!rendered.contains("s3cr3t"), "{rendered}");
        assert!(matches!(outputs.first(), Some(Output::Send(_))));
    }

    #[test]
    fn test_tracing_output_never_contains_credentials() {
        // Captures every log line both roles emit through a handshake with
        // credentials both ways, a violation and a termination.
        let capture = crate::testkit::capture_logs(|| {
            let origin = Instant::now();
            let mut client = FixpClient::new(
                config(),
                anchor(origin),
                SESSION,
                FlowType::Idempotent,
                Credentials::try_new(b"s3cr3t-client".to_vec()).ok(),
            );
            let mut server = crate::testkit::server(origin);
            assert_eq!(client.negotiate(origin), Ok(()));
            deliver_all(&drain(&mut client), &mut server, origin);
            let _ = drain(&mut server);
            assert_eq!(
                server.accept_negotiation(
                    FlowType::Recoverable,
                    Credentials::try_new(b"s3cr3t-server".to_vec()).ok(),
                    origin,
                ),
                Ok(())
            );
            deliver_all(&drain(&mut server), &mut client, origin);
            let _ = drain(&mut client);
            assert_eq!(client.establish(origin), Ok(()));
            deliver_all(&drain(&mut client), &mut server, origin);
            let _ = drain(&mut server);
            assert_eq!(server.accept_establishment(origin), Ok(()));
            deliver_all(&drain(&mut server), &mut client, origin);
            let _ = drain(&mut client);
            client.handle_message(
                &SessionMessage::Sequence(Sequence { next_seq_no: 0 }),
                origin,
            );
            let _ = drain(&mut client);
            assert_eq!(
                server.terminate(TerminationCode::Finished, "", origin),
                Ok(())
            );
            let _ = drain(&mut server);
        });
        let lines = capture.lines();
        assert!(
            lines.iter().any(|line| line.contains("fixp negotiate")),
            "the capture saw the session's logs: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("fixp protocol violation"))
        );
        for line in &lines {
            assert!(!line.contains("s3cr3t"), "credentials logged: {line}");
        }
    }

    #[test]
    fn test_client_and_server_handshake_through_the_wire() {
        let origin = Instant::now();
        let (client, server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        assert_eq!(client.server_flow(), Some(FlowType::Recoverable));
        assert_eq!(server.client_flow(), Some(FlowType::Idempotent));
        assert_eq!(server.server_flow(), Some(FlowType::Recoverable));
        assert_eq!(server.session_id(), Some(SESSION));
    }
}
