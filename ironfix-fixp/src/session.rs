/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! The role-independent part of a FIXP session: what both a client and a
//! server do once a session is negotiated and bound.
//!
//! - [`Core`] holds what every state needs: the configuration, the request
//!   clock and the output queue.
//! - [`Session`] is the logical session (FIXP v1.1 section 3.4.3): its
//!   identifier, both flow types, the outbound and inbound sequence state,
//!   unrecovered gaps, and a counterparty retransmission being answered. It
//!   outlives any one transport.
//! - [`Binding`] is the session bound to one transport (section 4.3):
//!   keepalive intervals and timers, and whether it is established,
//!   terminating, or closing.
//!
//! Every handler that can end the binding returns [`Bound`], and the role
//! state machine maps [`Bound::Unbind`] to its "negotiated, not bound" state.
//! Every `match` here names its variants; none has a wildcard arm.

use crate::clock::RequestClock;
use crate::config::{FixpConfig, RetransmitStallPolicy};
use crate::error::FixpError;
use crate::messages::{
    Applied, Context, Establish, EstablishmentAck, EstablishmentReject, FinishedReceiving,
    FinishedSending, Negotiate, NegotiationReject, NegotiationResponse, NotApplied, Retransmission,
    RetransmitReject, RetransmitRequest, Sequence, SessionMessage, Terminate, UnsequencedHeartbeat,
};
use crate::output::{Delivery, Event, Output, RetransmitBatch, SessionStatus, TerminatedBy};
use crate::types::{
    FlowType, MAX_VAR_DATA_LEN, Nanotime, RetransmitRejectCode, SessionId, TerminationCode,
};
use ironfix_core::SeqNum;
use std::collections::VecDeque;
use std::num::NonZeroU32;
use std::time::{Duration, Instant};

/// The `uint64` null value: the one sequence number a `NextSeqNo` field
/// cannot carry, so the outbound counter never reaches it.
const SEQ_NULL: u64 = u64::MAX;

/// State every session state needs, whatever the role and phase.
#[derive(Debug)]
pub(crate) struct Core {
    config: FixpConfig,
    clock: RequestClock,
    outputs: VecDeque<Output>,
    /// Set when this side asks the driver to close the transport, cleared
    /// when the driver reports it closed. Meanwhile whatever still arrives on
    /// it is ignored, and nothing new is sent on it.
    transport_closing: bool,
}

impl Core {
    pub(crate) fn new(config: FixpConfig, clock: RequestClock) -> Self {
        Self {
            config,
            clock,
            outputs: VecDeque::new(),
            transport_closing: false,
        }
    }

    pub(crate) const fn config(&self) -> &FixpConfig {
        &self.config
    }

    pub(crate) fn send(&mut self, message: SessionMessage) {
        self.outputs.push_back(Output::Send(message));
    }

    pub(crate) fn send_application(&mut self, seq: Option<SeqNum>, message: SessionMessage) {
        self.outputs
            .push_back(Output::SendApplication { seq, message });
    }

    pub(crate) fn event(&mut self, event: Event) {
        self.outputs.push_back(Output::Event(event));
    }

    pub(crate) fn close_transport(&mut self) {
        self.outputs.push_back(Output::CloseTransport);
        self.transport_closing = true;
    }

    /// `true` between asking the driver to close the transport and the
    /// driver reporting it closed.
    pub(crate) const fn transport_closing(&self) -> bool {
        self.transport_closing
    }

    /// The driver reported the transport closed.
    pub(crate) const fn transport_closed(&mut self) {
        self.transport_closing = false;
    }

    pub(crate) fn request_timestamp(&mut self, now: Instant) -> Result<Nanotime, FixpError> {
        self.clock.next(now)
    }

    pub(crate) fn poll_output(&mut self) -> Option<Output> {
        self.outputs.pop_front()
    }

    /// A counterparty violation before the session is bound: there is no
    /// binding to Terminate, so the transport is closed (FIXP v1.1
    /// section 6.3).
    pub(crate) fn violation_unbound(&mut self, reason: &'static str) {
        tracing::warn!(reason, "fixp protocol violation before establishment");
        self.event(Event::ProtocolViolation { reason });
        self.close_transport();
    }

    /// A response that matches no outstanding request (FIXP v1.1 Appendix A
    /// 7.1.7.5 and 7.1.12.8: ignore it and raise an internal alert).
    pub(crate) fn ignore(&mut self, message: &'static str, reason: &'static str) {
        tracing::debug!(message, reason, "fixp message ignored");
        self.event(Event::Ignored { message, reason });
    }
}

/// A session message either role may receive once bound.
#[derive(Debug, Clone, Copy)]
pub(crate) enum PeerMessage<'a> {
    Topic,
    Sequence(&'a Sequence),
    Context(&'a Context),
    UnsequencedHeartbeat,
    RetransmitRequest(&'a RetransmitRequest),
    Retransmission(&'a Retransmission),
    RetransmitReject(&'a RetransmitReject),
    Terminate(&'a Terminate),
    FinishedSending(&'a FinishedSending),
    FinishedReceiving,
    Applied(&'a Applied),
    NotApplied(&'a NotApplied),
    MessageTemplate,
}

impl PeerMessage<'_> {
    /// The message name, for events.
    pub(crate) const fn name(&self) -> &'static str {
        match self {
            Self::Topic => crate::messages::Topic::NAME,
            Self::Sequence(_) => Sequence::NAME,
            Self::Context(_) => Context::NAME,
            Self::UnsequencedHeartbeat => UnsequencedHeartbeat::NAME,
            Self::RetransmitRequest(_) => RetransmitRequest::NAME,
            Self::Retransmission(_) => Retransmission::NAME,
            Self::RetransmitReject(_) => RetransmitReject::NAME,
            Self::Terminate(_) => Terminate::NAME,
            Self::FinishedSending(_) => FinishedSending::NAME,
            Self::FinishedReceiving => FinishedReceiving::NAME,
            Self::Applied(_) => Applied::NAME,
            Self::NotApplied(_) => NotApplied::NAME,
            Self::MessageTemplate => crate::messages::MessageTemplate::NAME,
        }
    }
}

/// A negotiation or establishment message, whose handling depends on the role.
#[derive(Debug, Clone, Copy)]
pub(crate) enum HandshakeMessage<'a> {
    Negotiate(&'a Negotiate),
    NegotiationResponse(&'a NegotiationResponse),
    NegotiationReject(&'a NegotiationReject),
    Establish(&'a Establish),
    EstablishmentAck(&'a EstablishmentAck),
    EstablishmentReject(&'a EstablishmentReject),
}

/// A session message sorted by who handles it.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Classified<'a> {
    Handshake(HandshakeMessage<'a>),
    Peer(PeerMessage<'a>),
}

/// Sorts a session message into handshake and peer messages.
pub(crate) const fn classify(message: &SessionMessage) -> Classified<'_> {
    match message {
        SessionMessage::Negotiate(m) => Classified::Handshake(HandshakeMessage::Negotiate(m)),
        SessionMessage::NegotiationResponse(m) => {
            Classified::Handshake(HandshakeMessage::NegotiationResponse(m))
        }
        SessionMessage::NegotiationReject(m) => {
            Classified::Handshake(HandshakeMessage::NegotiationReject(m))
        }
        SessionMessage::Establish(m) => Classified::Handshake(HandshakeMessage::Establish(m)),
        SessionMessage::EstablishmentAck(m) => {
            Classified::Handshake(HandshakeMessage::EstablishmentAck(m))
        }
        SessionMessage::EstablishmentReject(m) => {
            Classified::Handshake(HandshakeMessage::EstablishmentReject(m))
        }
        SessionMessage::Topic(_) => Classified::Peer(PeerMessage::Topic),
        SessionMessage::Sequence(m) => Classified::Peer(PeerMessage::Sequence(m)),
        SessionMessage::Context(m) => Classified::Peer(PeerMessage::Context(m)),
        SessionMessage::UnsequencedHeartbeat(_) => {
            Classified::Peer(PeerMessage::UnsequencedHeartbeat)
        }
        SessionMessage::RetransmitRequest(m) => Classified::Peer(PeerMessage::RetransmitRequest(m)),
        SessionMessage::Retransmission(m) => Classified::Peer(PeerMessage::Retransmission(m)),
        SessionMessage::RetransmitReject(m) => Classified::Peer(PeerMessage::RetransmitReject(m)),
        SessionMessage::Terminate(m) => Classified::Peer(PeerMessage::Terminate(m)),
        SessionMessage::FinishedSending(m) => Classified::Peer(PeerMessage::FinishedSending(m)),
        SessionMessage::FinishedReceiving(_) => Classified::Peer(PeerMessage::FinishedReceiving),
        SessionMessage::Applied(m) => Classified::Peer(PeerMessage::Applied(m)),
        SessionMessage::NotApplied(m) => Classified::Peer(PeerMessage::NotApplied(m)),
        SessionMessage::MessageTemplate(_) => Classified::Peer(PeerMessage::MessageTemplate),
    }
}

/// Whether a handler kept or ended the binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) enum Bound {
    /// The binding continues (possibly in another [`BindState`]).
    Stay,
    /// The binding is over; the session is negotiated but not bound.
    Unbind,
}

/// Where a binding is in its lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BindState {
    /// Application messages may flow.
    Established,
    /// This side sent a graceful Terminate and waits up to its keepalive
    /// interval for the answer (FIXP v1.1 section 4.4.1).
    Terminating {
        sent_at: Instant,
        code: TerminationCode,
        reason: String,
    },
    /// This side answered the counterparty's Terminate. The counterparty
    /// closes the transport (section 4.4.2); past the deadline this side
    /// does.
    Closing { deadline: Option<Instant> },
}

/// A session bound to one transport.
#[derive(Debug, Clone)]
pub(crate) struct Binding {
    pub(crate) state: BindState,
    local_keepalive: Duration,
    remote_keepalive: Duration,
    /// When this side last sent an application message or a heartbeat.
    last_keepalive: Instant,
    /// When the counterparty last sent anything.
    last_received: Instant,
    /// Whether the receiver can number this side's next application message
    /// implicitly. Cleared by anything that switches context (section 3.5.4).
    in_sequence: bool,
}

impl Binding {
    pub(crate) const fn status(&self) -> SessionStatus {
        match self.state {
            BindState::Established => SessionStatus::Established,
            BindState::Terminating { .. } => SessionStatus::Terminating,
            BindState::Closing { .. } => SessionStatus::Closing,
        }
    }

    const fn is_established(&self) -> bool {
        match self.state {
            BindState::Established => true,
            BindState::Terminating { .. } | BindState::Closing { .. } => false,
        }
    }
}

/// A half-open range of missing sequence numbers, `from..end`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Gap {
    from: u64,
    end: u64,
}

/// This side's RetransmitRequest in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Outstanding {
    timestamp: Nanotime,
    from: u64,
    count: u32,
    delivered: u32,
    last_progress: Instant,
    /// A Sequence or Context cut the last batch short of its `Count`: the
    /// provider stopped serving it (section 3.5.4).
    interrupted: bool,
    /// The current stall was reported and is waited out; no timer runs
    /// until the provider makes progress again.
    stall_reported: bool,
}

/// The counterparty has sent FinishedSending (section 4.7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeerFinished {
    /// FinishedReceiving has gone out (section 4.7.2).
    receiving_sent: bool,
    /// On a sequenced flow, `LastSeqNo + 1`: no `NextSeqNo` may go past it
    /// any more (section 6.3; Appendix A 7.4.5).
    end: Option<u64>,
}

/// A retransmission batch being received: the next message is `next`, and
/// `remaining` more belong to it. A batch with nothing left is no batch, so
/// `remaining` cannot be zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Replay {
    next: u64,
    remaining: NonZeroU32,
}

/// A counterparty RetransmitRequest being answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Provider {
    request_timestamp: Nanotime,
    from: u64,
    count: u32,
    sent: u32,
}

/// The logical session: identity, flows and sequence state.
#[derive(Debug, Clone)]
pub(crate) struct Session {
    id: SessionId,
    local_flow: FlowType,
    remote_flow: FlowType,
    /// Sequence number of this side's next application message.
    outbound_next: u64,
    /// Sequence number of the counterparty's next real-time application
    /// message, on a sequenced counterparty flow. Holds the fallback 1 while
    /// `start_pending`.
    inbound_next: Option<u64>,
    /// Nothing has fixed where the counterparty's numbering stands yet: no
    /// `NextSeqNo` (establishment, Sequence, Context) and no application
    /// message. The first `NextSeqNo` sets it; an application message first
    /// takes the fallback 1.
    start_pending: bool,
    /// Unrecovered gaps of a Recoverable inbound flow, in order.
    missing: VecDeque<Gap>,
    outstanding: Option<Outstanding>,
    replay: Option<Replay>,
    provider: Option<Provider>,
    peer_finished: Option<PeerFinished>,
}

impl Session {
    pub(crate) fn new(id: SessionId, local_flow: FlowType, remote_flow: FlowType) -> Self {
        Self {
            id,
            local_flow,
            remote_flow,
            outbound_next: 1,
            // The fallback start, used only if an application message comes
            // before any NextSeqNo: numbering from 1 (section 5.1.1;
            // Appendix A 7.1.8).
            inbound_next: if remote_flow.is_sequenced() {
                Some(1)
            } else {
                None
            },
            start_pending: remote_flow.is_sequenced(),
            missing: VecDeque::new(),
            outstanding: None,
            replay: None,
            provider: None,
            peer_finished: None,
        }
    }

    pub(crate) const fn id(&self) -> SessionId {
        self.id
    }

    pub(crate) const fn local_flow(&self) -> FlowType {
        self.local_flow
    }

    pub(crate) const fn remote_flow(&self) -> FlowType {
        self.remote_flow
    }

    pub(crate) const fn next_outbound_seq(&self) -> Option<SeqNum> {
        if self.local_flow.is_sequenced() {
            Some(SeqNum::new(self.outbound_next))
        } else {
            None
        }
    }

    pub(crate) const fn next_inbound_seq(&self) -> Option<SeqNum> {
        match self.inbound_next {
            Some(next) => Some(SeqNum::new(next)),
            None => None,
        }
    }

    pub(crate) fn has_pending_recovery(&self) -> bool {
        !self.missing.is_empty()
    }

    /// The `NextSeqNo` this side announces in Establish or EstablishmentAck:
    /// its next outbound sequence number on a sequenced flow.
    pub(crate) const fn announced_next_seq(&self) -> Option<u64> {
        if self.local_flow.is_sequenced() {
            Some(self.outbound_next)
        } else {
            None
        }
    }

    /// Returns `true` if a counterparty `NextSeqNo` would move its sequenced
    /// flow backwards. Until something fixes where the numbering stands, the
    /// first `NextSeqNo` sets it, so nothing regresses.
    pub(crate) fn regresses(&self, next: Option<u64>) -> bool {
        if self.start_pending {
            return false;
        }
        match (self.remote_flow.is_sequenced(), next, self.inbound_next) {
            (true, Some(next), Some(expected)) => next < expected,
            (true, Some(_) | None, _) | (false, _, _) => false,
        }
    }

    /// Binds the session to a transport at `now`.
    pub(crate) fn bind(
        &mut self,
        now: Instant,
        local_keepalive: Duration,
        remote_keepalive: Duration,
    ) -> Binding {
        self.release_binding_state();
        Binding {
            state: BindState::Established,
            local_keepalive,
            remote_keepalive,
            last_keepalive: now,
            last_received: now,
            in_sequence: false,
        }
    }

    /// Applies the counterparty's `NextSeqNo` from Establish or
    /// EstablishmentAck and resumes the recovery of earlier gaps
    /// (FIXP v1.1 sections 4.3.1 and 4.3.2).
    ///
    /// Until something has fixed where the counterparty's numbering stands,
    /// the announced number sets it: Appendix A 7.2.2 and 7.3.1 start at 100,
    /// 200 and 1000. Afterwards it is checked against what arrived, and a
    /// higher one is a gap. See [`Session::on_next_seq`].
    pub(crate) fn on_established(
        &mut self,
        core: &mut Core,
        binding: &mut Binding,
        next: Option<u64>,
        now: Instant,
    ) -> Bound {
        if let (true, Some(next)) = (self.remote_flow.is_sequenced(), next)
            && self.on_next_seq(core, binding, next, now) == Bound::Unbind
        {
            return Bound::Unbind;
        }
        if self.request_missing(core, binding, now) == Bound::Unbind {
            return Bound::Unbind;
        }
        self.maybe_finish_receiving(core, binding);
        Bound::Stay
    }

    /// Drops what only made sense on the transport just lost: a retransmission
    /// in flight either way. Messages already retransmitted stay recovered.
    pub(crate) fn release_binding_state(&mut self) {
        if let Some(outstanding) = self.outstanding.take() {
            self.consume_missing(u64::from(outstanding.delivered));
        }
        self.replay = None;
        self.provider = None;
    }

    // ----- inbound -----------------------------------------------------------

    /// Handles a session message received while bound.
    pub(crate) fn on_peer(
        &mut self,
        core: &mut Core,
        binding: &mut Binding,
        message: PeerMessage<'_>,
        now: Instant,
    ) -> Bound {
        match binding.state {
            // FIXP v1.1 section 4.4: anything after a Terminate is ignored.
            BindState::Closing { .. } => {
                core.ignore(
                    message.name(),
                    "it arrived after the counterparty's Terminate",
                );
                return Bound::Stay;
            }
            BindState::Established | BindState::Terminating { .. } => {}
        }
        binding.last_received = now;
        match message {
            PeerMessage::Terminate(m) => self.on_terminate(core, binding, m, now),
            PeerMessage::Sequence(m) => self.on_next_seq(core, binding, m.next_seq_no, now),
            PeerMessage::Context(m) => {
                if m.session_id != self.id {
                    return self.violation(
                        core,
                        binding,
                        "Context for another session: multiplexed transports are not supported",
                    );
                }
                // Section 3.5.3 marks NextSeqNo optional; its SBE null value
                // means "no number given", not a number.
                if m.next_seq_no == SEQ_NULL {
                    return Bound::Stay;
                }
                self.on_next_seq(core, binding, m.next_seq_no, now)
            }
            PeerMessage::UnsequencedHeartbeat => {
                if self.remote_flow.is_sequenced() {
                    return self.violation(
                        core,
                        binding,
                        "UnsequencedHeartbeat on a sequenced flow",
                    );
                }
                Bound::Stay
            }
            PeerMessage::RetransmitRequest(m) => self.on_retransmit_request(core, binding, m),
            PeerMessage::Retransmission(m) => self.on_retransmission(core, binding, m, now),
            PeerMessage::RetransmitReject(m) => self.on_retransmit_reject(core, binding, m, now),
            PeerMessage::Applied(m) => {
                // Unlike NotApplied (section 4.8.2), FIXP names no violation
                // for Applied on any flow (sections 4.8.1 and 6.3), so its
                // flow is not checked: it is numbered and reported as is.
                let (delivery, bound) = self.on_application(core, binding, now);
                if let Delivery::Accept { .. } = delivery {
                    core.event(Event::Applied {
                        from_seq_no: m.from_seq_no,
                        count: m.count,
                    });
                }
                bound
            }
            PeerMessage::NotApplied(m) => {
                // Section 4.8.2: NotApplied reports on an Idempotent flow only.
                if self.local_flow != FlowType::Idempotent {
                    return self.violation(
                        core,
                        binding,
                        "NotApplied for a flow that is not Idempotent",
                    );
                }
                let (delivery, bound) = self.on_application(core, binding, now);
                if let Delivery::Accept { .. } = delivery {
                    core.event(Event::NotApplied {
                        from_seq_no: m.from_seq_no,
                        count: m.count,
                    });
                }
                bound
            }
            PeerMessage::Topic => self.violation(core, binding, "Topic is a multicast message"),
            PeerMessage::FinishedSending(m) => self.on_finished_sending(core, binding, m, now),
            // Section 6.3: this side never sends FinishedSending, so any
            // FinishedReceiving answers nothing.
            PeerMessage::FinishedReceiving => {
                self.violation(core, binding, "FinishedReceiving without a FinishedSending")
            }
            PeerMessage::MessageTemplate => Bound::Stay,
        }
    }

    /// Numbers an application message just received (FIXP v1.1 sections
    /// 3.5.1 and 4.6.2).
    pub(crate) fn on_application(
        &mut self,
        core: &mut Core,
        binding: &mut Binding,
        now: Instant,
    ) -> (Delivery, Bound) {
        match binding.state {
            BindState::Closing { .. } => return (Delivery::Discard, Bound::Stay),
            BindState::Established | BindState::Terminating { .. } => {}
        }
        binding.last_received = now;
        if let Some(replay) = self.replay {
            let seq = replay.next;
            let Some(following) = seq.checked_add(1) else {
                return (
                    Delivery::Discard,
                    self.violation(core, binding, "retransmitted sequence numbers overflow"),
                );
            };
            // `remaining` is at least one; the batch ends when it reaches zero.
            self.replay = replay
                .remaining
                .get()
                .checked_sub(1)
                .and_then(NonZeroU32::new)
                .map(|remaining| Replay {
                    next: following,
                    remaining,
                });
            // A batch never exceeds what is left of its request
            // (`on_retransmission`), so `delivered` stays within `count`.
            let complete = match self.outstanding.as_mut() {
                Some(outstanding) => match outstanding.delivered.checked_add(1) {
                    Some(delivered) => {
                        outstanding.delivered = delivered;
                        outstanding.last_progress = now;
                        outstanding.stall_reported = false;
                        delivered >= outstanding.count
                    }
                    None => true,
                },
                None => false,
            };
            let bound = if complete {
                self.complete_outstanding(core, binding, now)
            } else {
                Bound::Stay
            };
            return (
                Delivery::Accept {
                    seq: Some(SeqNum::new(seq)),
                    retransmitted: true,
                },
                bound,
            );
        }
        // Section 6.3: no new application message after FinishedSending;
        // retransmitted ones (above) still come.
        if self.peer_finished.is_some() {
            return (
                Delivery::Discard,
                self.violation(core, binding, "application message after FinishedSending"),
            );
        }
        match self.remote_flow {
            FlowType::None => (
                Delivery::Discard,
                self.violation(core, binding, "application message on a None flow"),
            ),
            FlowType::Unsequenced => (
                Delivery::Accept {
                    seq: None,
                    retransmitted: false,
                },
                Bound::Stay,
            ),
            FlowType::Recoverable | FlowType::Idempotent => {
                // An application message before any NextSeqNo: the fallback
                // start of 1 now stands.
                self.start_pending = false;
                let Some(seq) = self.inbound_next else {
                    return (
                        Delivery::Discard,
                        self.violation(core, binding, "application message before any Sequence"),
                    );
                };
                let Some(following) = seq.checked_add(1) else {
                    return (
                        Delivery::Discard,
                        self.violation(core, binding, "inbound sequence numbers exhausted"),
                    );
                };
                self.inbound_next = Some(following);
                (
                    Delivery::Accept {
                        seq: Some(SeqNum::new(seq)),
                        retransmitted: false,
                    },
                    Bound::Stay,
                )
            }
        }
    }

    /// Handles a `NextSeqNo` from Sequence, Context, Establish or
    /// EstablishmentAck (FIXP v1.1 sections 3.5 and 4.3).
    fn on_next_seq(
        &mut self,
        core: &mut Core,
        binding: &mut Binding,
        next: u64,
        now: Instant,
    ) -> Bound {
        if !self.remote_flow.is_sequenced() {
            return self.violation(core, binding, "Sequence or Context on an unsequenced flow");
        }
        if next == 0 {
            return self.violation(core, binding, "NextSeqNo of zero");
        }
        // Section 6.3 and Appendix A 7.4.5: after FinishedSending the
        // counterparty's flow is over, so no NextSeqNo may announce numbers
        // past its LastSeqNo, and no gap is opened there.
        if let Some(PeerFinished { end: Some(end), .. }) = self.peer_finished
            && next > end
        {
            return self.violation(
                core,
                binding,
                "NextSeqNo past the LastSeqNo of FinishedSending",
            );
        }
        // Section 3.5.4: a context switch ends a retransmission batch. One
        // still short of its Count was cut off: the provider stopped it. A
        // stall already reported is waited out again from the cut, now as an
        // interrupted batch, so the stall policy can act on it.
        if self.replay.take().is_some()
            && let Some(outstanding) = self.outstanding.as_mut()
        {
            outstanding.interrupted = true;
            outstanding.stall_reported = false;
            outstanding.last_progress = now;
        }
        // Nothing has fixed where the counterparty's numbering stands: on a
        // stream nothing can precede its first NextSeqNo, so that is where it
        // starts (Appendix A 7.2.2 and 7.3.1), not a gap after 1.
        if self.start_pending {
            self.start_pending = false;
            self.inbound_next = Some(next);
            return Bound::Stay;
        }
        let Some(expected) = self.inbound_next else {
            self.inbound_next = Some(next);
            return Bound::Stay;
        };
        match next.checked_sub(expected) {
            Some(0) => Bound::Stay,
            Some(count) if count > core.config().max_gap_len().get() => {
                self.violation(core, binding, "sequence gap larger than max_gap_len")
            }
            Some(count) => self.on_gap(core, binding, expected, next, count, now),
            // Appendix A 7.2.2 and 7.2.3: a lower NextSeqNo terminates.
            None => self.violation(core, binding, "NextSeqNo lower than expected"),
        }
    }

    /// The counterparty's flow skipped `count` messages, from `expected` to
    /// `next`.
    fn on_gap(
        &mut self,
        core: &mut Core,
        binding: &mut Binding,
        expected: u64,
        next: u64,
        count: u64,
        now: Instant,
    ) -> Bound {
        tracing::debug!(session_id = %self.id, from = expected, count, "fixp sequence gap");
        core.event(Event::SequenceGap {
            from: SeqNum::new(expected),
            count,
        });
        self.inbound_next = Some(next);
        match self.remote_flow {
            // Section 4.6.1: accept what follows the gap, request the gap.
            FlowType::Recoverable => {
                if !self.record_gap(core.config(), expected, next) {
                    return self.violation(core, binding, "too many unrecovered sequence gaps");
                }
                self.request_missing(core, binding, now)
            }
            // Section 4.8.2: report the gap with NotApplied, keep accepting.
            FlowType::Idempotent => {
                let Ok(count) = u32::try_from(count) else {
                    return self.violation(
                        core,
                        binding,
                        "sequence gap too large for a NotApplied",
                    );
                };
                self.send_not_applied(core, binding, expected, count, now)
            }
            FlowType::Unsequenced | FlowType::None => Bound::Stay,
        }
    }

    /// Adds `from..end` to the unrecovered gaps, merging with the last one
    /// when contiguous. Returns `false` past `max_pending_gaps`.
    fn record_gap(&mut self, config: &FixpConfig, from: u64, end: u64) -> bool {
        if let Some(last) = self.missing.back_mut()
            && last.end == from
        {
            last.end = end;
            return true;
        }
        if self.missing.len() >= config.max_pending_gaps().get() {
            return false;
        }
        self.missing.push_back(Gap { from, end });
        true
    }

    /// Marks the first `count` sequence numbers of the first gap recovered
    /// (or abandoned). Requests are cut from the front of the first gap and
    /// never exceed it, so `count` reaching or passing its end means the whole
    /// gap is gone.
    fn consume_missing(&mut self, count: u64) {
        if count == 0 {
            return;
        }
        let Some(front) = self.missing.front_mut() else {
            return;
        };
        match front.from.checked_add(count) {
            Some(from) if from < front.end => front.from = from,
            Some(_) | None => {
                self.missing.pop_front();
            }
        }
    }

    /// Requests the start of the first unrecovered gap, if nothing is in
    /// flight (section 4.6.1: one RetransmitRequest at a time).
    fn request_missing(&mut self, core: &mut Core, binding: &mut Binding, now: Instant) -> Bound {
        if !binding.is_established()
            || self.remote_flow != FlowType::Recoverable
            || self.outstanding.is_some()
        {
            return Bound::Stay;
        }
        let Some(front) = self.missing.front().copied() else {
            return Bound::Stay;
        };
        // A recorded gap is never empty (`record_gap` is only called with
        // `from < end`, and `consume_missing` drops a gap it empties).
        let Some(len) = front.end.checked_sub(front.from).filter(|len| *len > 0) else {
            return Bound::Stay;
        };
        let max = core.config().max_retransmit_count().get();
        let count = match u32::try_from(len) {
            Ok(len) => len.min(max),
            Err(_) => max,
        };
        let Ok(timestamp) = core.request_timestamp(now) else {
            return self.fail(
                core,
                binding,
                TerminationCode::UnspecifiedError,
                "session clock out of range",
            );
        };
        tracing::debug!(session_id = %self.id, from = front.from, count, "fixp retransmit request");
        core.send(SessionMessage::RetransmitRequest(RetransmitRequest {
            session_id: self.id,
            timestamp,
            from_seq_no: front.from,
            count,
        }));
        self.outstanding = Some(Outstanding {
            timestamp,
            from: front.from,
            count,
            delivered: 0,
            last_progress: now,
            interrupted: false,
            stall_reported: false,
        });
        Bound::Stay
    }

    /// The request in flight was answered in full.
    fn complete_outstanding(
        &mut self,
        core: &mut Core,
        binding: &mut Binding,
        now: Instant,
    ) -> Bound {
        if let Some(outstanding) = self.outstanding.take() {
            self.consume_missing(u64::from(outstanding.count));
        }
        self.replay = None;
        if self.missing.is_empty() {
            core.event(Event::RecoveryComplete);
            self.maybe_finish_receiving(core, binding);
            return Bound::Stay;
        }
        self.request_missing(core, binding, now)
    }

    /// A Retransmission header (FIXP v1.1 section 4.6.2).
    fn on_retransmission(
        &mut self,
        core: &mut Core,
        binding: &mut Binding,
        message: &Retransmission,
        now: Instant,
    ) -> Bound {
        if self.remote_flow != FlowType::Recoverable {
            // Appendix A 7.3.4: Retransmission on another flow terminates.
            return self.violation(
                core,
                binding,
                "Retransmission on a flow that is not Recoverable",
            );
        }
        if message.session_id != self.id {
            return self.violation(core, binding, "Retransmission for another session");
        }
        let Some(outstanding) = self.outstanding else {
            return self.violation(core, binding, "Retransmission without a RetransmitRequest");
        };
        if message.request_timestamp != outstanding.timestamp {
            return self.violation(core, binding, "Retransmission answers another request");
        }
        let expected = outstanding
            .from
            .checked_add(u64::from(outstanding.delivered));
        let remaining = outstanding.count.checked_sub(outstanding.delivered);
        let batch = NonZeroU32::new(message.count)
            .filter(|count| remaining.is_some_and(|remaining| count.get() <= remaining));
        let (Some(batch), true) = (batch, Some(message.next_seq_no) == expected) else {
            return self.violation(core, binding, "Retransmission outside the requested range");
        };
        self.replay = Some(Replay {
            next: message.next_seq_no,
            remaining: batch,
        });
        if let Some(outstanding) = self.outstanding.as_mut() {
            outstanding.last_progress = now;
            outstanding.interrupted = false;
            outstanding.stall_reported = false;
        }
        Bound::Stay
    }

    /// The counterparty refused this side's RetransmitRequest
    /// (section 4.6.2.3): the range is abandoned.
    fn on_retransmit_reject(
        &mut self,
        core: &mut Core,
        binding: &mut Binding,
        message: &RetransmitReject,
        now: Instant,
    ) -> Bound {
        let outstanding = match self.outstanding {
            Some(outstanding)
                if outstanding.timestamp == message.request_timestamp
                    && message.session_id == self.id =>
            {
                outstanding
            }
            Some(_) | None => {
                core.ignore(
                    RetransmitReject::NAME,
                    "it answers no outstanding RetransmitRequest",
                );
                return Bound::Stay;
            }
        };
        tracing::warn!(
            session_id = %self.id,
            from = outstanding.from,
            count = outstanding.count,
            code = ?message.code,
            "fixp retransmit request rejected; range abandoned"
        );
        core.event(Event::RetransmitRejected {
            from: SeqNum::new(outstanding.from),
            count: outstanding.count,
            code: message.code,
            reason: message.reason.clone(),
        });
        self.outstanding = None;
        self.replay = None;
        self.consume_missing(u64::from(outstanding.count));
        if self.missing.is_empty() {
            core.event(Event::RecoveryComplete);
            self.maybe_finish_receiving(core, binding);
            return Bound::Stay;
        }
        self.request_missing(core, binding, now)
    }

    /// A counterparty RetransmitRequest (FIXP v1.1 sections 4.6.1 to 4.6.4).
    fn on_retransmit_request(
        &mut self,
        core: &mut Core,
        binding: &mut Binding,
        message: &RetransmitRequest,
    ) -> Bound {
        if !binding.is_established() {
            // This side already sent its Terminate: nothing more may follow.
            core.ignore(RetransmitRequest::NAME, "this side has sent its Terminate");
            return Bound::Stay;
        }
        if self.local_flow != FlowType::Recoverable {
            return self.violation(
                core,
                binding,
                "RetransmitRequest to a flow that is not Recoverable",
            );
        }
        if message.session_id != self.id {
            return self.refuse_retransmit(
                core,
                message,
                RetransmitRejectCode::InvalidSession,
                "unknown session",
            );
        }
        if self.provider.is_some() {
            tracing::warn!(session_id = %self.id, "fixp retransmit request while one is answered");
            core.event(Event::ProtocolViolation {
                reason: "RetransmitRequest while a retransmission is in progress",
            });
            return self.fail(
                core,
                binding,
                TerminationCode::ReRequestInProgress,
                "RetransmitRequest while a retransmission is in progress",
            );
        }
        if message.count == 0 {
            return self.refuse_retransmit(
                core,
                message,
                RetransmitRejectCode::OutOfRange,
                "empty range",
            );
        }
        if message.count > core.config().max_retransmit_count().get() {
            return self.refuse_retransmit(
                core,
                message,
                RetransmitRejectCode::RequestLimitExceeded,
                "count exceeds the retransmission limit",
            );
        }
        let end = message.from_seq_no.checked_add(u64::from(message.count));
        let in_range = message.from_seq_no >= 1 && end.is_some_and(|end| end <= self.outbound_next);
        if !in_range {
            return self.refuse_retransmit(
                core,
                message,
                RetransmitRejectCode::OutOfRange,
                "range not yet sent",
            );
        }
        self.provider = Some(Provider {
            request_timestamp: message.timestamp,
            from: message.from_seq_no,
            count: message.count,
            sent: 0,
        });
        core.event(Event::RetransmitRequested {
            from: SeqNum::new(message.from_seq_no),
            count: message.count,
        });
        Bound::Stay
    }

    fn refuse_retransmit(
        &mut self,
        core: &mut Core,
        message: &RetransmitRequest,
        code: RetransmitRejectCode,
        reason: &'static str,
    ) -> Bound {
        core.send(SessionMessage::RetransmitReject(RetransmitReject {
            session_id: message.session_id,
            request_timestamp: message.timestamp,
            code,
            reason: reason.to_owned(),
        }));
        core.event(Event::Refused {
            message: RetransmitReject::NAME,
            reason,
        });
        Bound::Stay
    }

    /// A counterparty Terminate (FIXP v1.1 section 4.4).
    fn on_terminate(
        &mut self,
        core: &mut Core,
        binding: &mut Binding,
        message: &Terminate,
        now: Instant,
    ) -> Bound {
        if message.session_id != self.id {
            return self.violation(core, binding, "Terminate for another session");
        }
        match &binding.state {
            // The answer to this side's Terminate: the initiator closes the
            // transport (section 4.4.2).
            BindState::Terminating { code, reason, .. } => {
                core.event(Event::Terminated {
                    code: *code,
                    reason: reason.clone(),
                    by: TerminatedBy::Local,
                });
                core.close_transport();
                self.release_binding_state();
                Bound::Unbind
            }
            // Section 4.4.1: answer with a Terminate, the last message sent.
            BindState::Established => {
                core.send(SessionMessage::Terminate(Terminate {
                    session_id: self.id,
                    code: TerminationCode::Finished,
                    reason: String::new(),
                }));
                core.event(Event::Terminated {
                    code: message.code,
                    reason: message.reason.clone(),
                    by: TerminatedBy::Peer,
                });
                self.release_binding_state();
                binding.state = BindState::Closing {
                    deadline: now.checked_add(binding.local_keepalive),
                };
                Bound::Stay
            }
            BindState::Closing { .. } => Bound::Stay,
        }
    }

    /// A counterparty FinishedSending: its flow is ending (FIXP v1.1
    /// section 4.7.1). It is answered with FinishedReceiving once every
    /// message up to its `LastSeqNo` is accounted for (section 4.7.2), and
    /// this side then waits for the counterparty's Terminate.
    fn on_finished_sending(
        &mut self,
        core: &mut Core,
        binding: &mut Binding,
        message: &FinishedSending,
        now: Instant,
    ) -> Bound {
        if message.session_id != self.id {
            return self.violation(core, binding, "FinishedSending for another session");
        }
        if self.peer_finished.is_some() {
            // Section 4.7.1: repeated as the sender's heartbeat until it is
            // answered; one answer is enough (Appendix A 7.4.2).
            return Bound::Stay;
        }
        core.event(Event::PeerFinishedSending {
            last_seq_no: message.last_seq_no,
        });
        let mut end = None;
        if self.remote_flow.is_sequenced() {
            // Section 4.7.1: it must carry LastSeqNo on a numbered flow.
            let Some(last) = message.last_seq_no else {
                return self.violation(
                    core,
                    binding,
                    "FinishedSending without LastSeqNo on a sequenced flow",
                );
            };
            let Some(next) = last.checked_add(1) else {
                return self.violation(core, binding, "LastSeqNo out of range");
            };
            if self.inbound_next.is_some_and(|expected| next < expected) {
                return self.violation(
                    core,
                    binding,
                    "LastSeqNo below the messages already received",
                );
            }
            // A LastSeqNo past what arrived is a gap: requested on a
            // Recoverable flow, reported with NotApplied on an Idempotent one.
            if self.on_next_seq(core, binding, next, now) == Bound::Unbind {
                return Bound::Unbind;
            }
            end = Some(next);
        }
        self.peer_finished = Some(PeerFinished {
            receiving_sent: false,
            end,
        });
        self.maybe_finish_receiving(core, binding);
        Bound::Stay
    }

    /// Sends FinishedReceiving once the counterparty has finished sending and
    /// no gap of its flow is still being recovered (section 4.7.2).
    fn maybe_finish_receiving(&mut self, core: &mut Core, binding: &Binding) {
        let Some(finished) = self.peer_finished.as_mut() else {
            return;
        };
        if finished.receiving_sent
            || !binding.is_established()
            || !self.missing.is_empty()
            || self.outstanding.is_some()
        {
            return;
        }
        core.send(SessionMessage::FinishedReceiving(FinishedReceiving {
            session_id: self.id,
        }));
        finished.receiving_sent = true;
    }

    /// The counterparty broke the protocol: terminate (section 6.3).
    pub(crate) fn violation(
        &mut self,
        core: &mut Core,
        binding: &mut Binding,
        reason: &'static str,
    ) -> Bound {
        tracing::warn!(session_id = %self.id, reason, "fixp protocol violation");
        core.event(Event::ProtocolViolation { reason });
        self.fail(core, binding, TerminationCode::UnspecifiedError, reason)
    }

    /// Ends the binding on an error: Terminate if this side may still send,
    /// then close the transport without waiting for an answer (Appendix A
    /// 7.2.1: termination due to an error does not wait).
    fn fail(
        &mut self,
        core: &mut Core,
        binding: &mut Binding,
        code: TerminationCode,
        reason: &'static str,
    ) -> Bound {
        match binding.state {
            BindState::Established => {
                core.send(SessionMessage::Terminate(Terminate {
                    session_id: self.id,
                    code,
                    reason: reason.to_owned(),
                }));
                core.event(Event::Terminated {
                    code,
                    reason: reason.to_owned(),
                    by: TerminatedBy::Local,
                });
            }
            BindState::Terminating { .. } | BindState::Closing { .. } => {}
        }
        core.close_transport();
        self.release_binding_state();
        Bound::Unbind
    }

    // ----- outbound ----------------------------------------------------------

    /// Numbers this side's next application message, sending a Sequence
    /// first when the receiver could not number it implicitly.
    fn allocate_outbound(
        &mut self,
        core: &mut Core,
        binding: &mut Binding,
    ) -> Result<SeqNum, FixpError> {
        let seq = self.outbound_next;
        let following = seq
            .checked_add(1)
            .filter(|following| *following != SEQ_NULL)
            .ok_or(FixpError::SequenceExhausted)?;
        if !binding.in_sequence {
            core.send(SessionMessage::Sequence(Sequence { next_seq_no: seq }));
            binding.in_sequence = true;
        }
        self.outbound_next = following;
        Ok(SeqNum::new(seq))
    }

    /// Reports a gap of the counterparty's Idempotent flow (section 4.8.2).
    fn send_not_applied(
        &mut self,
        core: &mut Core,
        binding: &mut Binding,
        from: u64,
        count: u32,
        now: Instant,
    ) -> Bound {
        if !binding.is_established() {
            return Bound::Stay;
        }
        let message = SessionMessage::NotApplied(NotApplied {
            from_seq_no: from,
            count,
        });
        match self.local_flow {
            FlowType::None => {
                // A None flow carries no application message, NotApplied
                // included: the gap is reported to the application only.
                tracing::warn!(session_id = %self.id, from, count, "fixp gap not reported: own flow is None");
                Bound::Stay
            }
            FlowType::Unsequenced => {
                core.send_application(None, message);
                binding.last_keepalive = now;
                Bound::Stay
            }
            FlowType::Recoverable | FlowType::Idempotent => {
                match self.allocate_outbound(core, binding) {
                    Ok(seq) => {
                        core.send_application(Some(seq), message);
                        binding.last_keepalive = now;
                        Bound::Stay
                    }
                    Err(_) => self.fail(
                        core,
                        binding,
                        TerminationCode::UnspecifiedError,
                        "outbound sequence numbers exhausted",
                    ),
                }
            }
        }
    }

    fn require_established(binding: &Binding, operation: &'static str) -> Result<(), FixpError> {
        if binding.is_established() {
            Ok(())
        } else {
            Err(FixpError::InvalidState {
                operation,
                status: binding.status(),
            })
        }
    }

    /// Numbers an application message this side is about to send.
    pub(crate) fn send_application(
        &mut self,
        core: &mut Core,
        binding: &mut Binding,
        now: Instant,
    ) -> Result<Option<SeqNum>, FixpError> {
        Self::require_established(binding, "send_application")?;
        match self.local_flow {
            FlowType::None => Err(FixpError::FlowCarriesNoApplicationMessages {
                flow: self.local_flow,
            }),
            FlowType::Unsequenced => {
                binding.last_keepalive = now;
                Ok(None)
            }
            FlowType::Recoverable | FlowType::Idempotent => {
                let seq = self.allocate_outbound(core, binding)?;
                binding.last_keepalive = now;
                Ok(Some(seq))
            }
        }
    }

    /// Starts unbinding the transport (FIXP v1.1 section 4.4).
    pub(crate) fn terminate(
        &mut self,
        core: &mut Core,
        binding: &mut Binding,
        code: TerminationCode,
        reason: String,
        now: Instant,
    ) -> Result<Bound, FixpError> {
        Self::require_established(binding, "terminate")?;
        check_reason(&reason)?;
        core.send(SessionMessage::Terminate(Terminate {
            session_id: self.id,
            code,
            reason: reason.clone(),
        }));
        match code {
            // A graceful Terminate waits for the answer (section 4.4.1), and
            // in-flight messages are still processed meanwhile: a
            // retransmission batch arriving now keeps its numbers. Only the
            // retransmission this side was serving ends, since nothing may
            // follow its Terminate. The rest is released when the binding
            // ends.
            TerminationCode::Finished => {
                self.provider = None;
                binding.state = BindState::Terminating {
                    sent_at: now,
                    code,
                    reason,
                };
                Ok(Bound::Stay)
            }
            // Appendix A 7.2.1: termination due to an error does not wait.
            TerminationCode::UnspecifiedError
            | TerminationCode::ReRequestOutOfBounds
            | TerminationCode::ReRequestInProgress => {
                self.release_binding_state();
                core.event(Event::Terminated {
                    code,
                    reason,
                    by: TerminatedBy::Local,
                });
                core.close_transport();
                Ok(Bound::Unbind)
            }
        }
    }

    /// Answers the counterparty RetransmitRequest being served with the next
    /// `count` messages (FIXP v1.1 section 4.6.2).
    pub(crate) fn retransmit(
        &mut self,
        core: &mut Core,
        binding: &mut Binding,
        count: NonZeroU32,
        now: Instant,
    ) -> Result<RetransmitBatch, FixpError> {
        Self::require_established(binding, "retransmit")?;
        let Some(provider) = self.provider.as_mut() else {
            return Err(FixpError::NoRetransmissionInProgress);
        };
        // `sent` never exceeds `count`: every batch is checked against what
        // is left before it is counted.
        let remaining = provider
            .count
            .checked_sub(provider.sent)
            .ok_or(FixpError::NoRetransmissionInProgress)?;
        if count.get() > remaining {
            return Err(FixpError::RetransmissionOverrun {
                count: count.get(),
                remaining,
            });
        }
        let from = provider
            .from
            .checked_add(u64::from(provider.sent))
            .ok_or(FixpError::SequenceExhausted)?;
        core.send(SessionMessage::Retransmission(Retransmission {
            session_id: self.id,
            request_timestamp: provider.request_timestamp,
            next_seq_no: from,
            count: count.get(),
        }));
        // `count <= remaining`, so the sum is at most `provider.count`.
        let sent =
            provider
                .sent
                .checked_add(count.get())
                .ok_or(FixpError::RetransmissionOverrun {
                    count: count.get(),
                    remaining,
                })?;
        provider.sent = sent;
        if sent >= provider.count {
            self.provider = None;
        }
        // Section 4.6.2.2: real-time messages resume after a Sequence.
        binding.in_sequence = false;
        binding.last_keepalive = now;
        Ok(RetransmitBatch {
            from: SeqNum::new(from),
            count: count.get(),
        })
    }

    /// Refuses the counterparty RetransmitRequest being served
    /// (section 4.6.2.3).
    pub(crate) fn reject_retransmit_request(
        &mut self,
        core: &mut Core,
        binding: &Binding,
        code: RetransmitRejectCode,
        reason: String,
    ) -> Result<(), FixpError> {
        Self::require_established(binding, "reject_retransmit_request")?;
        check_reason(&reason)?;
        let provider = self
            .provider
            .take()
            .ok_or(FixpError::NoRetransmissionInProgress)?;
        core.send(SessionMessage::RetransmitReject(RetransmitReject {
            session_id: self.id,
            request_timestamp: provider.request_timestamp,
            code,
            reason,
        }));
        Ok(())
    }

    /// Stops serving the counterparty RetransmitRequest before all of it was
    /// sent; the requester asks again for the rest (section 4.6.2.2).
    pub(crate) fn end_retransmission(&mut self, binding: &Binding) -> Result<(), FixpError> {
        Self::require_established(binding, "end_retransmission")?;
        self.provider
            .take()
            .map(|_| ())
            .ok_or(FixpError::NoRetransmissionInProgress)
    }

    // ----- time --------------------------------------------------------------

    fn silence_deadline(&self, config: &FixpConfig, binding: &Binding) -> Option<Instant> {
        let grace = config
            .peer_silence_grace()
            .unwrap_or(binding.remote_keepalive);
        binding
            .remote_keepalive
            .checked_add(grace)
            .and_then(|allowed| binding.last_received.checked_add(allowed))
    }

    fn stall_deadline(&self, config: &FixpConfig) -> Option<Instant> {
        self.outstanding
            .filter(|outstanding| !outstanding.stall_reported)
            .and_then(|outstanding| {
                outstanding
                    .last_progress
                    .checked_add(config.retransmit_timeout())
            })
    }

    /// The next instant at which [`Session::on_timeout`] has work to do.
    pub(crate) fn next_deadline(&self, config: &FixpConfig, binding: &Binding) -> Option<Instant> {
        match &binding.state {
            BindState::Established => [
                self.silence_deadline(config, binding),
                binding.last_keepalive.checked_add(binding.local_keepalive),
                self.stall_deadline(config),
            ]
            .into_iter()
            .flatten()
            .min(),
            BindState::Terminating { sent_at, .. } => sent_at.checked_add(binding.local_keepalive),
            BindState::Closing { deadline } => *deadline,
        }
    }

    /// Runs the timers that are due at `now`.
    pub(crate) fn on_timeout(
        &mut self,
        core: &mut Core,
        binding: &mut Binding,
        now: Instant,
    ) -> Bound {
        match &binding.state {
            BindState::Established => {
                if self
                    .silence_deadline(core.config(), binding)
                    .is_some_and(|deadline| now >= deadline)
                {
                    tracing::warn!(session_id = %self.id, "fixp keepalive interval lapsed");
                    core.event(Event::KeepaliveLapsed);
                    return self.fail(
                        core,
                        binding,
                        TerminationCode::UnspecifiedError,
                        "keepalive interval lapsed",
                    );
                }
                if self
                    .stall_deadline(core.config())
                    .is_some_and(|deadline| now >= deadline)
                    && let Some(outstanding) = self.outstanding
                    && self.on_stall(core, binding, outstanding, now) == Bound::Unbind
                {
                    return Bound::Unbind;
                }
                if binding
                    .last_keepalive
                    .checked_add(binding.local_keepalive)
                    .is_some_and(|due| now >= due)
                {
                    self.heartbeat(core, binding, now);
                }
                Bound::Stay
            }
            BindState::Terminating {
                sent_at,
                code,
                reason,
            } => {
                // Section 4.4.1: no answer within a heartbeat interval.
                let lapsed = sent_at
                    .checked_add(binding.local_keepalive)
                    .is_some_and(|deadline| now >= deadline);
                if !lapsed {
                    return Bound::Stay;
                }
                core.event(Event::Terminated {
                    code: *code,
                    reason: reason.clone(),
                    by: TerminatedBy::Local,
                });
                core.close_transport();
                self.release_binding_state();
                Bound::Unbind
            }
            BindState::Closing { deadline } => {
                if deadline.is_some_and(|deadline| now >= deadline) {
                    core.close_transport();
                    return Bound::Unbind;
                }
                Bound::Stay
            }
        }
    }

    /// This side's RetransmitRequest went `retransmit_timeout` without a
    /// retransmitted message: apply the configured policy.
    fn on_stall(
        &mut self,
        core: &mut Core,
        binding: &mut Binding,
        outstanding: Outstanding,
        now: Instant,
    ) -> Bound {
        tracing::warn!(
            session_id = %self.id,
            from = outstanding.from,
            count = outstanding.count,
            delivered = outstanding.delivered,
            "fixp retransmission stalled"
        );
        core.event(Event::RetransmitTimedOut {
            from: SeqNum::new(outstanding.from),
            count: outstanding.count,
        });
        match core.config().retransmit_stall_policy() {
            RetransmitStallPolicy::Terminate => self.fail(
                core,
                binding,
                TerminationCode::UnspecifiedError,
                "retransmission stalled",
            ),
            // The provider cut its batch short with a context switch: it has
            // stopped serving, so asking again is not premature.
            RetransmitStallPolicy::ReRequestAfterContextSwitch if outstanding.interrupted => {
                self.outstanding = None;
                self.replay = None;
                self.consume_missing(u64::from(outstanding.delivered));
                self.request_missing(core, binding, now)
            }
            // The provider may still be pacing its batches: a second request
            // now could be terminated as premature (sections 4.6.1, 4.6.4).
            RetransmitStallPolicy::ReRequestAfterContextSwitch
            | RetransmitStallPolicy::EventOnly => {
                if let Some(outstanding) = self.outstanding.as_mut() {
                    outstanding.stall_reported = true;
                }
                Bound::Stay
            }
        }
    }

    /// Sends the heartbeat of this side's flow (FIXP v1.1 section 4.5).
    fn heartbeat(&mut self, core: &mut Core, binding: &mut Binding, now: Instant) {
        if self.local_flow.is_sequenced() {
            core.send(SessionMessage::Sequence(Sequence {
                next_seq_no: self.outbound_next,
            }));
            binding.in_sequence = true;
        } else {
            core.send(SessionMessage::UnsequencedHeartbeat(UnsequencedHeartbeat));
        }
        binding.last_keepalive = now;
    }
}

/// Checks a reason fits its `CharacterString` length prefix.
pub(crate) fn check_reason(reason: &str) -> Result<(), FixpError> {
    if reason.len() > MAX_VAR_DATA_LEN {
        return Err(FixpError::ReasonTooLong {
            len: reason.len(),
            max: MAX_VAR_DATA_LEN,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_gap_merges_contiguous_gaps_and_bounds_the_rest() {
        let config = FixpConfig::builder()
            .max_pending_gaps(std::num::NonZeroUsize::MIN)
            .build()
            .unwrap_or_default();
        let mut session = Session::new(
            SessionId::from_bytes([1; 16]),
            FlowType::Recoverable,
            FlowType::Recoverable,
        );
        assert!(session.record_gap(&config, 10, 20));
        assert!(session.record_gap(&config, 20, 30), "contiguous gaps merge");
        assert_eq!(session.missing.front(), Some(&Gap { from: 10, end: 30 }));
        assert!(
            !session.record_gap(&config, 40, 50),
            "a second gap exceeds the bound of one"
        );
        session.consume_missing(5);
        assert_eq!(session.missing.front(), Some(&Gap { from: 15, end: 30 }));
        session.consume_missing(15);
        assert!(session.missing.is_empty());
        session.consume_missing(3);
        assert!(session.missing.is_empty());
    }

    #[test]
    fn test_regresses_compares_only_sequenced_flows() {
        let mut session = Session::new(
            SessionId::from_bytes([1; 16]),
            FlowType::Recoverable,
            FlowType::Idempotent,
        );
        session.inbound_next = Some(10);
        assert!(
            !session.regresses(Some(9)),
            "the first NextSeqNo sets the numbering"
        );
        session.start_pending = false;
        assert!(session.regresses(Some(9)));
        assert!(!session.regresses(Some(10)));
        assert!(!session.regresses(None));
        let unsequenced = Session::new(
            SessionId::from_bytes([1; 16]),
            FlowType::Recoverable,
            FlowType::Unsequenced,
        );
        assert!(!unsequenced.regresses(Some(0)));
    }

    #[test]
    fn test_check_reason_bounds_the_length_prefix() {
        assert!(check_reason("ok").is_ok());
        assert_eq!(
            check_reason(&"x".repeat(MAX_VAR_DATA_LEN + 1)),
            Err(FixpError::ReasonTooLong {
                len: MAX_VAR_DATA_LEN + 1,
                max: MAX_VAR_DATA_LEN,
            })
        );
    }

    /// A bare session bound at `origin`, with its core.
    fn bare(origin: Instant, local: FlowType, remote: FlowType) -> (Core, Session, Binding) {
        bare_with(crate::testkit::config(), origin, local, remote)
    }

    /// A bare session with `config`, bound at `origin`.
    fn bare_with(
        config: FixpConfig,
        origin: Instant,
        local: FlowType,
        remote: FlowType,
    ) -> (Core, Session, Binding) {
        let core = Core::new(config, RequestClock::new(crate::testkit::anchor(origin)));
        let mut session = Session::new(crate::testkit::SESSION, local, remote);
        let binding = session.bind(origin, crate::testkit::KEEPALIVE, crate::testkit::KEEPALIVE);
        (core, session, binding)
    }

    #[test]
    fn test_outbound_sequence_exhaustion_is_a_typed_error() {
        let origin = Instant::now();
        let (mut core, mut session, mut binding) =
            bare(origin, FlowType::Recoverable, FlowType::Recoverable);
        session.outbound_next = u64::MAX - 2;
        assert_eq!(
            session.send_application(&mut core, &mut binding, origin),
            Ok(Some(SeqNum::new(u64::MAX - 2)))
        );
        assert_eq!(session.outbound_next, u64::MAX - 1, "never the null value");
        assert_eq!(
            session.send_application(&mut core, &mut binding, origin),
            Err(FixpError::SequenceExhausted)
        );
        assert_eq!(session.outbound_next, u64::MAX - 1, "untouched on error");
    }

    #[test]
    fn test_inbound_sequence_overflow_terminates() {
        let origin = Instant::now();
        let (mut core, mut session, mut binding) =
            bare(origin, FlowType::Recoverable, FlowType::Recoverable);
        session.inbound_next = Some(u64::MAX);
        let (delivery, bound) = session.on_application(&mut core, &mut binding, origin);
        assert_eq!(delivery, Delivery::Discard);
        assert_eq!(bound, Bound::Unbind);
        assert!(
            std::iter::from_fn(|| core.poll_output()).any(|output| matches!(
                output,
                Output::Event(Event::ProtocolViolation {
                    reason: "inbound sequence numbers exhausted"
                })
            ))
        );
    }

    #[test]
    fn test_a_gap_too_large_for_not_applied_terminates() {
        let origin = Instant::now();
        // Lift max_gap_len out of the way to reach NotApplied's own limit.
        let Ok(config) = FixpConfig::builder()
            .max_gap_len(std::num::NonZeroU64::MAX)
            .build()
        else {
            panic!("invalid config");
        };
        let (mut core, mut session, mut binding) =
            bare_with(config, origin, FlowType::Recoverable, FlowType::Idempotent);
        session.inbound_next = Some(1);
        session.start_pending = false;
        let bound = session.on_next_seq(&mut core, &mut binding, u64::MAX, origin);
        assert_eq!(bound, Bound::Unbind);
        assert!(
            std::iter::from_fn(|| core.poll_output()).any(|output| matches!(
                output,
                Output::Event(Event::ProtocolViolation {
                    reason: "sequence gap too large for a NotApplied"
                })
            ))
        );
    }

    #[test]
    fn test_a_gap_above_max_gap_len_terminates() {
        let origin = Instant::now();
        let Ok(config) = FixpConfig::builder()
            .max_gap_len(std::num::NonZeroU64::new(10).unwrap_or(std::num::NonZeroU64::MIN))
            .build()
        else {
            panic!("invalid config");
        };
        let (mut core, mut session, mut binding) =
            bare_with(config, origin, FlowType::Recoverable, FlowType::Recoverable);
        session.start_pending = false;
        // A gap of exactly the bound is accepted and requested...
        assert_eq!(
            session.on_next_seq(&mut core, &mut binding, 11, origin),
            Bound::Stay
        );
        assert!(session.has_pending_recovery());
        // ...one past it terminates.
        assert_eq!(
            session.on_next_seq(&mut core, &mut binding, 22, origin),
            Bound::Unbind
        );
        assert!(
            std::iter::from_fn(|| core.poll_output()).any(|output| matches!(
                output,
                Output::Event(Event::ProtocolViolation {
                    reason: "sequence gap larger than max_gap_len"
                })
            ))
        );
    }
}

/// Established-session behaviour, driven through a client and a server that
/// talk through the codec.
#[cfg(test)]
mod flow_tests {
    use crate::messages::{
        Applied, Context, FinishedSending, MessageTemplate, NotApplied, Retransmission,
        RetransmitReject, RetransmitRequest, Sequence, SessionMessage, Terminate, Topic,
        UnsequencedHeartbeat,
    };
    use crate::output::{Delivery, Event, Output, RetransmitBatch, SessionStatus, TerminatedBy};
    use crate::testkit::{
        KEEPALIVE, MAX_RETRANSMIT, OTHER_SESSION, RETRANSMIT_TIMEOUT, SESSION, anchor, at, closes,
        config, deliver_all, drain, established_pair, events, negotiate_pair, send_apps, sent,
        server,
    };
    use crate::types::{FlowType, Nanotime, RetransmitRejectCode, TerminationCode};
    use crate::{FixpClient, FixpConfig, FixpError, FixpServer};
    use ironfix_core::SeqNum;
    use std::num::{NonZeroU32, NonZeroUsize};
    use std::time::{Duration, Instant};

    fn sequence(next_seq_no: u64) -> SessionMessage {
        SessionMessage::Sequence(Sequence { next_seq_no })
    }

    fn accepted(seq: u64, retransmitted: bool) -> Delivery {
        Delivery::Accept {
            seq: Some(SeqNum::new(seq)),
            retransmitted,
        }
    }

    fn count(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap_or(NonZeroU32::MIN)
    }

    /// Asserts `outputs` terminate the session with `code`: a Terminate is
    /// sent and the transport closed.
    fn assert_terminates(outputs: &[Output], code: TerminationCode) {
        assert!(
            sent(outputs).iter().any(|message| matches!(
                message,
                SessionMessage::Terminate(Terminate { code: sent_code, .. }) if *sent_code == code
            )),
            "no Terminate {code:?} in {outputs:?}"
        );
        assert!(closes(outputs), "the transport is not closed: {outputs:?}");
    }

    /// The RetransmitRequests among `outputs`.
    fn requests(outputs: &[Output]) -> Vec<RetransmitRequest> {
        sent(outputs)
            .into_iter()
            .filter_map(|message| match message {
                SessionMessage::RetransmitRequest(request) => Some(request),
                SessionMessage::Negotiate(_)
                | SessionMessage::NegotiationResponse(_)
                | SessionMessage::NegotiationReject(_)
                | SessionMessage::Topic(_)
                | SessionMessage::Establish(_)
                | SessionMessage::EstablishmentAck(_)
                | SessionMessage::EstablishmentReject(_)
                | SessionMessage::Sequence(_)
                | SessionMessage::Context(_)
                | SessionMessage::UnsequencedHeartbeat(_)
                | SessionMessage::Retransmission(_)
                | SessionMessage::RetransmitReject(_)
                | SessionMessage::Terminate(_)
                | SessionMessage::FinishedSending(_)
                | SessionMessage::FinishedReceiving(_)
                | SessionMessage::Applied(_)
                | SessionMessage::NotApplied(_)
                | SessionMessage::MessageTemplate(_) => None,
            })
            .collect()
    }

    /// The single RetransmitRequest among `outputs`.
    fn one_request(outputs: &[Output]) -> RetransmitRequest {
        match requests(outputs).as_slice() {
            [request] => *request,
            other => panic!("expected one RetransmitRequest, got {other:?}"),
        }
    }

    /// Answers `request` with a Retransmission of `count` messages from
    /// `from`, delivered to `client`, and returns the deliveries.
    fn replay(
        client: &mut FixpClient,
        request: &RetransmitRequest,
        from: u64,
        count: u32,
        now: Instant,
    ) -> Vec<Delivery> {
        client.handle_message(
            &SessionMessage::Retransmission(Retransmission {
                session_id: SESSION,
                request_timestamp: request.timestamp,
                next_seq_no: from,
                count,
            }),
            now,
        );
        (0..count)
            .map(|_| client.on_application_message(now))
            .collect()
    }

    // ----- outbound ----------------------------------------------------------

    #[test]
    fn test_send_application_opens_with_a_sequence_then_numbers_implicitly() {
        // FIXP v1.1 section 3.5.1.
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        assert_eq!(client.send_application(origin), Ok(Some(SeqNum::new(1))));
        assert_eq!(sent(&drain(&mut client)), vec![sequence(1)]);
        assert_eq!(client.send_application(origin), Ok(Some(SeqNum::new(2))));
        assert!(
            drain(&mut client).is_empty(),
            "no Sequence while in sequence"
        );
        assert_eq!(client.next_outbound_seq(), Some(SeqNum::new(3)));
    }

    #[test]
    fn test_send_application_on_an_unsequenced_flow_has_no_number() {
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Unsequenced, FlowType::Recoverable);
        assert_eq!(client.send_application(origin), Ok(None));
        assert!(drain(&mut client).is_empty());
    }

    #[test]
    fn test_send_application_on_a_none_flow_is_refused() {
        // FIXP v1.1 section 3.4.4.
        let origin = Instant::now();
        let (mut client, _server) = established_pair(origin, FlowType::None, FlowType::Recoverable);
        assert_eq!(
            client.send_application(origin),
            Err(FixpError::FlowCarriesNoApplicationMessages {
                flow: FlowType::None
            })
        );
    }

    // ----- keepalive ---------------------------------------------------------

    #[test]
    fn test_heartbeat_of_a_sequenced_flow_is_a_sequence() {
        // FIXP v1.1 section 4.5.
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        assert_eq!(client.poll_timeout(), Some(origin + KEEPALIVE));
        client.handle_timeout(origin + KEEPALIVE - Duration::from_millis(1));
        assert!(drain(&mut client).is_empty());
        client.handle_timeout(origin + KEEPALIVE);
        assert_eq!(sent(&drain(&mut client)), vec![sequence(1)]);
        // The heartbeat put the flow in sequence: the next message needs none.
        assert_eq!(
            client.send_application(origin + KEEPALIVE),
            Ok(Some(SeqNum::new(1)))
        );
        assert!(drain(&mut client).is_empty());
    }

    #[test]
    fn test_heartbeat_of_an_unsequenced_flow_is_an_unsequenced_heartbeat() {
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Unsequenced, FlowType::Recoverable);
        client.handle_timeout(origin + KEEPALIVE);
        assert_eq!(
            sent(&drain(&mut client)),
            vec![SessionMessage::UnsequencedHeartbeat(UnsequencedHeartbeat)]
        );
    }

    #[test]
    fn test_application_traffic_defers_the_heartbeat() {
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        assert!(client.send_application(at(origin, 500)).is_ok());
        let _ = drain(&mut client);
        client.handle_timeout(origin + KEEPALIVE);
        assert!(sent(&drain(&mut client)).is_empty());
        client.handle_timeout(at(origin, 1_500));
        assert_eq!(sent(&drain(&mut client)), vec![sequence(2)]);
    }

    #[test]
    fn test_peer_silence_terminates_after_its_interval_plus_grace() {
        // FIXP v1.1 sections 4.4 and 4.5; Appendix A 7.2.1.
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        // A Sequence from the server at 1.5 s moves the deadline to 3.5 s.
        client.handle_message(&sequence(1), at(origin, 1_500));
        client.handle_timeout(at(origin, 3_499));
        let outputs = drain(&mut client);
        assert!(!closes(&outputs));
        assert_eq!(client.status(), SessionStatus::Established);
        client.handle_timeout(at(origin, 3_500));
        let outputs = drain(&mut client);
        assert!(events(&outputs).contains(&Event::KeepaliveLapsed));
        assert!(events(&outputs).contains(&Event::Terminated {
            code: TerminationCode::UnspecifiedError,
            reason: "keepalive interval lapsed".to_owned(),
            by: TerminatedBy::Local,
        }));
        assert_terminates(&outputs, TerminationCode::UnspecifiedError);
        assert_eq!(client.status(), SessionStatus::Negotiated);
    }

    #[test]
    fn test_peer_silence_grace_is_configurable() {
        let origin = Instant::now();
        let custom = FixpConfig::builder()
            .keepalive_interval(KEEPALIVE)
            .peer_silence_grace(Duration::from_millis(200))
            .build();
        let Ok(custom) = custom else {
            panic!("invalid config");
        };
        let client = FixpClient::new(custom, anchor(origin), SESSION, FlowType::Recoverable, None);
        let (mut client, mut server) =
            negotiate_pair(client, server(origin), FlowType::Recoverable, origin);
        crate::testkit::establish(&mut client, &mut server, origin);
        assert_eq!(client.poll_timeout(), Some(origin + KEEPALIVE));
        client.handle_timeout(origin + KEEPALIVE);
        let _ = drain(&mut client);
        assert_eq!(client.poll_timeout(), Some(at(origin, 1_200)));
        client.handle_timeout(at(origin, 1_200));
        assert!(events(&drain(&mut client)).contains(&Event::KeepaliveLapsed));
    }

    // ----- inbound sequencing -------------------------------------------------

    #[test]
    fn test_inbound_messages_are_numbered_from_the_announced_next_seq() {
        let origin = Instant::now();
        let (mut client, mut server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        assert_eq!(client.next_inbound_seq(), Some(SeqNum::new(1)));
        assert_eq!(
            send_apps(&mut server, &mut client, 3, origin),
            vec![accepted(1, false), accepted(2, false), accepted(3, false)]
        );
        assert_eq!(client.next_inbound_seq(), Some(SeqNum::new(4)));
        // A Sequence equal to the expected number is a heartbeat.
        client.handle_message(&sequence(4), origin);
        assert!(drain(&mut client).is_empty());
        assert!(!client.has_pending_recovery());
    }

    #[test]
    fn test_a_lower_next_seq_terminates() {
        // FIXP v1.1 Appendix A 7.3.1.2.
        let origin = Instant::now();
        let (mut client, mut server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        let _ = send_apps(&mut server, &mut client, 3, origin);
        client.handle_message(&sequence(2), origin);
        let outputs = drain(&mut client);
        assert!(events(&outputs).contains(&Event::ProtocolViolation {
            reason: "NextSeqNo lower than expected"
        }));
        assert_terminates(&outputs, TerminationCode::UnspecifiedError);
        assert_eq!(client.status(), SessionStatus::Negotiated);
    }

    #[test]
    fn test_a_next_seq_of_zero_terminates() {
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        client.handle_message(&sequence(0), origin);
        assert_terminates(&drain(&mut client), TerminationCode::UnspecifiedError);
    }

    #[test]
    fn test_without_an_announced_start_the_first_sequence_sets_it() {
        // An EstablishmentAck without NextSeqNo is legal (sections 4.3.1 and
        // 4.3.2 limit when it is sent). On a stream nothing can precede the
        // counterparty's first Sequence, so a first Sequence(5) is where its
        // numbering starts, not a gap of 1 to 4.
        let origin = Instant::now();
        let mut client = FixpClient::new(
            config(),
            anchor(origin),
            SESSION,
            FlowType::Idempotent,
            None,
        );
        let mut server = server(origin);
        assert_eq!(client.negotiate(origin), Ok(()));
        deliver_all(&drain(&mut client), &mut server, origin);
        let _ = drain(&mut server);
        assert_eq!(
            server.accept_negotiation(FlowType::Recoverable, None, origin),
            Ok(())
        );
        deliver_all(&drain(&mut server), &mut client, origin);
        let _ = drain(&mut client);
        assert_eq!(client.establish(origin), Ok(()));
        let request = match sent(&drain(&mut client)).as_slice() {
            [SessionMessage::Establish(establish)] => establish.timestamp,
            other => panic!("expected an Establish, got {other:?}"),
        };
        client.handle_message(
            &SessionMessage::EstablishmentAck(crate::messages::EstablishmentAck {
                session_id: SESSION,
                request_timestamp: request,
                keepalive_interval: 1_000,
                next_seq_no: None,
            }),
            origin,
        );
        let _ = drain(&mut client);
        client.handle_message(&sequence(5), origin);
        assert!(drain(&mut client).is_empty(), "no gap, no request");
        assert!(!client.has_pending_recovery());
        assert_eq!(client.next_inbound_seq(), Some(SeqNum::new(5)));
        assert_eq!(client.on_application_message(origin), accepted(5, false));
        // From then on numbering is checked: a jump is a gap.
        client.handle_message(&sequence(9), origin);
        let request = one_request(&drain(&mut client));
        assert_eq!((request.from_seq_no, request.count), (6, 3));
    }

    #[test]
    fn test_server_takes_the_first_sequence_of_an_unannounced_client_flow() {
        // The client's Establish announces nothing and its first Sequence is
        // 100: no NotApplied for 1 to 99.
        let origin = Instant::now();
        let mut server = server(origin);
        server.handle_message(
            &SessionMessage::Negotiate(crate::messages::Negotiate {
                session_id: SESSION,
                timestamp: Nanotime::from_nanos(1),
                client_flow: FlowType::Idempotent,
                credentials: None,
            }),
            origin,
        );
        assert_eq!(
            server.accept_negotiation(FlowType::Recoverable, None, origin),
            Ok(())
        );
        server.handle_message(
            &SessionMessage::Establish(crate::messages::Establish {
                session_id: SESSION,
                timestamp: Nanotime::from_nanos(2),
                keepalive_interval: 1_000,
                next_seq_no: None,
                credentials: None,
            }),
            origin,
        );
        assert_eq!(server.accept_establishment(origin), Ok(()));
        let _ = drain(&mut server);
        server.handle_message(&sequence(100), origin);
        assert!(drain(&mut server).is_empty(), "no NotApplied");
        assert_eq!(server.on_application_message(origin), accepted(100, false));
    }

    #[test]
    fn test_an_application_message_with_no_sequence_is_number_one() {
        let origin = Instant::now();
        let mut client = FixpClient::new(
            config(),
            anchor(origin),
            SESSION,
            FlowType::Idempotent,
            None,
        );
        let mut server = server(origin);
        assert_eq!(client.negotiate(origin), Ok(()));
        deliver_all(&drain(&mut client), &mut server, origin);
        let _ = drain(&mut server);
        assert_eq!(
            server.accept_negotiation(FlowType::Recoverable, None, origin),
            Ok(())
        );
        deliver_all(&drain(&mut server), &mut client, origin);
        let _ = drain(&mut client);
        assert_eq!(client.establish(origin), Ok(()));
        let request = match sent(&drain(&mut client)).as_slice() {
            [SessionMessage::Establish(establish)] => establish.timestamp,
            other => panic!("expected an Establish, got {other:?}"),
        };
        client.handle_message(
            &SessionMessage::EstablishmentAck(crate::messages::EstablishmentAck {
                session_id: SESSION,
                request_timestamp: request,
                keepalive_interval: 1_000,
                next_seq_no: None,
            }),
            origin,
        );
        let _ = drain(&mut client);
        // An application message before any NextSeqNo takes the fallback 1,
        // and fixes the numbering: a Sequence(5) next is a gap of 2 to 4.
        assert_eq!(client.on_application_message(origin), accepted(1, false));
        client.handle_message(&sequence(5), origin);
        let outputs = drain(&mut client);
        assert!(events(&outputs).contains(&Event::SequenceGap {
            from: SeqNum::new(2),
            count: 3,
        }));
        let request = one_request(&outputs);
        assert_eq!((request.from_seq_no, request.count), (2, 3));
    }

    #[test]
    fn test_the_first_establishment_sets_where_numbering_starts() {
        // Appendix A 7.2.2 and 7.3.1 start the server's flow at 1000 on the
        // first establishment: no gap. On a re-establishment the same jump
        // would be one.
        let origin = Instant::now();
        let mut client = FixpClient::new(
            config(),
            anchor(origin),
            SESSION,
            FlowType::Idempotent,
            None,
        );
        let mut server = server(origin);
        assert_eq!(client.negotiate(origin), Ok(()));
        deliver_all(&drain(&mut client), &mut server, origin);
        let _ = drain(&mut server);
        assert_eq!(
            server.accept_negotiation(FlowType::Recoverable, None, origin),
            Ok(())
        );
        deliver_all(&drain(&mut server), &mut client, origin);
        let _ = drain(&mut client);
        let ack = |client: &mut FixpClient, next: u64, now: Instant| {
            assert_eq!(client.establish(now), Ok(()));
            let request = match sent(&drain(client)).as_slice() {
                [SessionMessage::Establish(establish)] => establish.timestamp,
                other => panic!("expected an Establish, got {other:?}"),
            };
            client.handle_message(
                &SessionMessage::EstablishmentAck(crate::messages::EstablishmentAck {
                    session_id: SESSION,
                    request_timestamp: request,
                    keepalive_interval: 1_000,
                    next_seq_no: Some(next),
                }),
                now,
            );
            drain(client)
        };
        let first = ack(&mut client, 1_000, origin);
        assert!(requests(&first).is_empty());
        assert_eq!(client.next_inbound_seq(), Some(SeqNum::new(1_000)));
        client.on_transport_closed();
        let _ = drain(&mut client);
        let second = ack(&mut client, 1_005, at(origin, 10));
        let request = one_request(&second);
        assert_eq!((request.from_seq_no, request.count), (1_000, 5));
    }

    #[test]
    fn test_sequence_on_an_unsequenced_flow_is_a_violation() {
        // FIXP v1.1 section 3.5.1; Appendix A 7.3.1.
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Recoverable, FlowType::Unsequenced);
        client.handle_message(&sequence(1), origin);
        assert_terminates(&drain(&mut client), TerminationCode::UnspecifiedError);
    }

    #[test]
    fn test_unsequenced_heartbeat_on_a_sequenced_flow_is_a_violation() {
        // FIXP v1.1 sections 4.5 and 6.3.
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        client.handle_message(
            &SessionMessage::UnsequencedHeartbeat(UnsequencedHeartbeat),
            origin,
        );
        assert_terminates(&drain(&mut client), TerminationCode::UnspecifiedError);
    }

    #[test]
    fn test_unsequenced_inbound_flow_delivers_without_numbers() {
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Recoverable, FlowType::Unsequenced);
        client.handle_message(
            &SessionMessage::UnsequencedHeartbeat(UnsequencedHeartbeat),
            origin,
        );
        assert!(drain(&mut client).is_empty());
        assert_eq!(
            client.on_application_message(origin),
            Delivery::Accept {
                seq: None,
                retransmitted: false
            }
        );
    }

    #[test]
    fn test_application_message_on_a_none_flow_is_a_violation() {
        // FIXP v1.1 section 3.4.4.
        let origin = Instant::now();
        let (mut client, _server) = established_pair(origin, FlowType::Recoverable, FlowType::None);
        assert_eq!(client.on_application_message(origin), Delivery::Discard);
        assert_terminates(&drain(&mut client), TerminationCode::UnspecifiedError);
    }

    #[test]
    fn test_context_for_this_session_acts_as_a_sequence() {
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        client.handle_message(
            &SessionMessage::Context(Context {
                session_id: SESSION,
                next_seq_no: 1,
            }),
            origin,
        );
        assert!(drain(&mut client).is_empty());
        client.handle_message(
            &SessionMessage::Context(Context {
                session_id: OTHER_SESSION,
                next_seq_no: 1,
            }),
            origin,
        );
        assert_terminates(&drain(&mut client), TerminationCode::UnspecifiedError);
    }

    #[test]
    fn test_topic_is_a_violation() {
        // FIXP v1.1 section 5.1.1.1: Topic belongs to multicast.
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        client.handle_message(
            &SessionMessage::Topic(Topic {
                session_id: SESSION,
                flow: FlowType::Idempotent,
                keepalive_interval: 1_000,
                classification: b"X".to_vec(),
            }),
            origin,
        );
        assert_terminates(&drain(&mut client), TerminationCode::UnspecifiedError);
    }

    fn finished_sending(last_seq_no: Option<u64>) -> SessionMessage {
        SessionMessage::FinishedSending(FinishedSending {
            session_id: SESSION,
            last_seq_no,
        })
    }

    fn finished_receiving() -> SessionMessage {
        SessionMessage::FinishedReceiving(crate::messages::FinishedReceiving {
            session_id: SESSION,
        })
    }

    #[test]
    fn test_finished_sending_is_answered_then_the_terminate_awaited() {
        // FIXP v1.1 sections 4.7.1 and 4.7.2; Appendix A 7.4.1.
        let origin = Instant::now();
        let (mut client, mut server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        assert_eq!(send_apps(&mut server, &mut client, 2, origin).len(), 2);
        client.handle_message(&finished_sending(Some(2)), origin);
        let outputs = drain(&mut client);
        assert_eq!(
            events(&outputs),
            vec![Event::PeerFinishedSending {
                last_seq_no: Some(2)
            }]
        );
        assert_eq!(sent(&outputs), vec![finished_receiving()]);
        assert!(!closes(&outputs));
        assert_eq!(client.status(), SessionStatus::Established);
        // Repeated as a heartbeat: one answer is enough (Appendix A 7.4.2).
        client.handle_message(&finished_sending(Some(2)), origin);
        assert!(drain(&mut client).is_empty());
        // No new application message after it (section 6.3).
        assert_eq!(client.on_application_message(origin), Delivery::Discard);
        assert_terminates(&drain(&mut client), TerminationCode::UnspecifiedError);
    }

    #[test]
    fn test_finished_sending_then_terminate_ends_the_binding_gracefully() {
        let origin = Instant::now();
        let (mut client, mut server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        client.handle_message(&finished_sending(Some(0)), origin);
        assert_eq!(sent(&drain(&mut client)), vec![finished_receiving()]);
        // The initiator of the finalization then unbinds (section 4.7.2).
        assert_eq!(
            server.terminate(TerminationCode::Finished, "", origin),
            Ok(())
        );
        deliver_all(&drain(&mut server), &mut client, origin);
        let outputs = drain(&mut client);
        assert!(matches!(
            sent(&outputs).as_slice(),
            [SessionMessage::Terminate(Terminate {
                code: TerminationCode::Finished,
                ..
            })]
        ));
        assert_eq!(client.status(), SessionStatus::Closing);
    }

    #[test]
    fn test_finished_sending_with_a_gap_is_answered_after_recovery() {
        // FIXP v1.1 section 4.7.1; Appendix A 7.4.3.
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        assert_eq!(client.on_application_message(origin), accepted(1, false));
        // The server's last message was 4: 2 to 4 are missing.
        client.handle_message(&finished_sending(Some(4)), origin);
        let outputs = drain(&mut client);
        let request = one_request(&outputs);
        assert_eq!((request.from_seq_no, request.count), (2, 3));
        assert!(
            !sent(&outputs).contains(&finished_receiving()),
            "not before the gap is filled"
        );
        let deliveries = replay(&mut client, &request, 2, 3, origin);
        assert_eq!(deliveries.last(), Some(&accepted(4, true)));
        let outputs = drain(&mut client);
        assert!(events(&outputs).contains(&Event::RecoveryComplete));
        assert_eq!(sent(&outputs), vec![finished_receiving()]);
    }

    #[test]
    fn test_finished_sending_on_an_idempotent_flow_reports_the_gap_then_answers() {
        let origin = Instant::now();
        let (_client, mut server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        server.handle_message(&finished_sending(Some(3)), origin);
        let outputs = drain(&mut server);
        let messages = sent(&outputs);
        assert!(messages.contains(&SessionMessage::NotApplied(NotApplied {
            from_seq_no: 1,
            count: 3,
        })));
        assert_eq!(messages.last(), Some(&finished_receiving()));
    }

    #[test]
    fn test_no_next_seq_past_last_seq_no_after_finished_sending() {
        // Section 6.3 and Appendix A 7.4.5: once the counterparty has sent
        // FinishedSending its flow is over. A Sequence that announces numbers
        // past LastSeqNo terminates, and no gap (no NotApplied, no
        // RetransmitRequest) is opened for numbers it never sent.
        let origin = Instant::now();
        let (mut client, mut server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        assert_eq!(send_apps(&mut client, &mut server, 2, origin).len(), 2);
        server.handle_message(&finished_sending(Some(2)), origin);
        assert_eq!(sent(&drain(&mut server)), vec![finished_receiving()]);
        // LastSeqNo + 1 announces nothing new: tolerated.
        server.handle_message(&sequence(3), origin);
        assert!(drain(&mut server).is_empty());
        // Past it: terminated, with no NotApplied for 3 to 6.
        server.handle_message(&sequence(7), origin);
        let outputs = drain(&mut server);
        assert!(events(&outputs).contains(&Event::ProtocolViolation {
            reason: "NextSeqNo past the LastSeqNo of FinishedSending"
        }));
        assert!(
            !sent(&outputs)
                .iter()
                .any(|message| matches!(message, SessionMessage::NotApplied(_)))
        );
        assert_terminates(&outputs, TerminationCode::UnspecifiedError);
        // The same for a Context on a Recoverable flow: no RetransmitRequest.
        let (mut client, mut server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        let _ = send_apps(&mut server, &mut client, 2, origin);
        client.handle_message(&finished_sending(Some(2)), origin);
        let _ = drain(&mut client);
        client.handle_message(
            &SessionMessage::Context(Context {
                session_id: SESSION,
                next_seq_no: 10,
            }),
            origin,
        );
        let outputs = drain(&mut client);
        assert!(requests(&outputs).is_empty());
        assert_terminates(&outputs, TerminationCode::UnspecifiedError);
    }

    #[test]
    fn test_invalid_finalization_messages_are_violations() {
        let origin = Instant::now();
        // Section 6.3: FinishedReceiving answers nothing this side sent.
        let (mut client, _server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        client.handle_message(&finished_receiving(), origin);
        assert_terminates(&drain(&mut client), TerminationCode::UnspecifiedError);
        // Section 4.7.1: LastSeqNo is required on a sequenced flow.
        let (mut client, _server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        client.handle_message(&finished_sending(None), origin);
        assert_terminates(&drain(&mut client), TerminationCode::UnspecifiedError);
        // A LastSeqNo below what already arrived.
        let (mut client, mut server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        let _ = send_apps(&mut server, &mut client, 3, origin);
        client.handle_message(&finished_sending(Some(1)), origin);
        assert_terminates(&drain(&mut client), TerminationCode::UnspecifiedError);
        // Another session.
        let (mut client, _server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        client.handle_message(
            &SessionMessage::FinishedSending(FinishedSending {
                session_id: OTHER_SESSION,
                last_seq_no: Some(0),
            }),
            origin,
        );
        assert_terminates(&drain(&mut client), TerminationCode::UnspecifiedError);
    }

    #[test]
    fn test_finished_sending_on_an_unsequenced_flow_needs_no_last_seq() {
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Recoverable, FlowType::Unsequenced);
        client.handle_message(&finished_sending(None), origin);
        assert_eq!(sent(&drain(&mut client)), vec![finished_receiving()]);
    }

    #[test]
    fn test_message_template_is_accepted_while_established() {
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        client.handle_message(
            &SessionMessage::MessageTemplate(MessageTemplate {
                encoding_type: 0x5BE0,
                effective_time: None,
                version: Vec::new(),
                template: b"<schema/>".to_vec(),
            }),
            at(origin, 1_500),
        );
        assert!(drain(&mut client).is_empty());
        // It counts as traffic: the silence deadline moved.
        client.handle_timeout(at(origin, 2_000));
        assert!(!events(&drain(&mut client)).contains(&Event::KeepaliveLapsed));
    }

    // ----- recoverable flow: gap and retransmission ---------------------------

    #[test]
    fn test_gap_on_a_recoverable_flow_is_recovered_end_to_end() {
        // FIXP v1.1 sections 4.5, 4.6.1, 4.6.2 and 4.6.2.2.
        let origin = Instant::now();
        let (mut client, mut server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        // The server sends 1, 2 and 3; only 1 reaches the client.
        assert_eq!(
            send_apps(&mut server, &mut client, 1, origin),
            vec![accepted(1, false)]
        );
        assert!(server.send_application(origin).is_ok());
        assert!(server.send_application(origin).is_ok());
        // The server's heartbeat reveals the gap.
        server.handle_timeout(origin + KEEPALIVE);
        let heartbeat = drain(&mut server);
        assert_eq!(sent(&heartbeat), vec![sequence(4)]);
        deliver_all(&heartbeat, &mut client, origin + KEEPALIVE);
        let outputs = drain(&mut client);
        assert!(events(&outputs).contains(&Event::SequenceGap {
            from: SeqNum::new(2),
            count: 2,
        }));
        let request = one_request(&outputs);
        assert_eq!((request.from_seq_no, request.count), (2, 2));
        assert!(client.has_pending_recovery());
        // Real-time traffic after the gap is accepted meanwhile.
        assert_eq!(
            send_apps(&mut server, &mut client, 1, origin + KEEPALIVE),
            vec![accepted(4, false)]
        );
        // The server serves the request.
        deliver_all(&outputs, &mut server, origin + KEEPALIVE);
        assert_eq!(
            events(&drain(&mut server)),
            vec![Event::RetransmitRequested {
                from: SeqNum::new(2),
                count: 2,
            }]
        );
        assert_eq!(
            server.retransmit(count(2), origin + KEEPALIVE),
            Ok(RetransmitBatch {
                from: SeqNum::new(2),
                count: 2,
            })
        );
        let header = drain(&mut server);
        assert_eq!(
            sent(&header),
            vec![SessionMessage::Retransmission(Retransmission {
                session_id: SESSION,
                request_timestamp: request.timestamp,
                next_seq_no: 2,
                count: 2,
            })]
        );
        deliver_all(&header, &mut client, origin + KEEPALIVE);
        assert_eq!(
            client.on_application_message(origin + KEEPALIVE),
            accepted(2, true)
        );
        assert_eq!(
            client.on_application_message(origin + KEEPALIVE),
            accepted(3, true)
        );
        assert_eq!(events(&drain(&mut client)), vec![Event::RecoveryComplete]);
        assert!(!client.has_pending_recovery());
        // Real-time traffic resumes behind a Sequence (section 4.6.2.2).
        assert_eq!(
            server.send_application(origin + KEEPALIVE),
            Ok(Some(SeqNum::new(5)))
        );
        assert_eq!(sent(&drain(&mut server)), vec![sequence(5)]);
    }

    #[test]
    fn test_a_large_gap_is_requested_in_chunks() {
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        client.handle_message(&sequence(251), origin);
        let first = one_request(&drain(&mut client));
        assert_eq!((first.from_seq_no, first.count), (1, MAX_RETRANSMIT));
        let deliveries = replay(&mut client, &first, 1, MAX_RETRANSMIT, origin);
        assert_eq!(deliveries.first(), Some(&accepted(1, true)));
        assert_eq!(deliveries.last(), Some(&accepted(100, true)));
        let second = one_request(&drain(&mut client));
        assert_eq!((second.from_seq_no, second.count), (101, MAX_RETRANSMIT));
        assert!(
            second.timestamp > first.timestamp,
            "every request has its own timestamp"
        );
        let _ = replay(&mut client, &second, 101, MAX_RETRANSMIT, origin);
        let third = one_request(&drain(&mut client));
        assert_eq!((third.from_seq_no, third.count), (201, 50));
        let _ = replay(&mut client, &third, 201, 50, origin);
        assert_eq!(events(&drain(&mut client)), vec![Event::RecoveryComplete]);
        assert_eq!(client.next_inbound_seq(), Some(SeqNum::new(251)));
    }

    #[test]
    fn test_only_one_retransmit_request_is_in_flight() {
        // FIXP v1.1 section 4.6.1.
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        client.handle_message(&sequence(5), origin);
        let first = one_request(&drain(&mut client));
        assert_eq!((first.from_seq_no, first.count), (1, 4));
        // A real-time message, then a second gap while the first is open.
        assert_eq!(client.on_application_message(origin), accepted(5, false));
        client.handle_message(&sequence(9), origin);
        let outputs = drain(&mut client);
        assert!(requests(&outputs).is_empty(), "no second request in flight");
        assert!(events(&outputs).contains(&Event::SequenceGap {
            from: SeqNum::new(6),
            count: 3,
        }));
        let _ = replay(&mut client, &first, 1, 4, origin);
        let second = one_request(&drain(&mut client));
        assert_eq!((second.from_seq_no, second.count), (6, 3));
    }

    #[test]
    fn test_a_paced_retransmission_may_interleave_real_time_messages() {
        // FIXP v1.1 section 4.6.2.2; Appendix A 7.3.4.2.
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        client.handle_message(&sequence(11), origin);
        let request = one_request(&drain(&mut client));
        assert_eq!((request.from_seq_no, request.count), (1, 10));
        let _ = replay(&mut client, &request, 1, 5, origin);
        // Real-time traffic between the two batches.
        client.handle_message(&sequence(11), origin);
        assert_eq!(client.on_application_message(origin), accepted(11, false));
        assert!(client.has_pending_recovery());
        let deliveries = replay(&mut client, &request, 6, 5, origin);
        assert_eq!(deliveries.first(), Some(&accepted(6, true)));
        assert_eq!(deliveries.last(), Some(&accepted(10, true)));
        assert_eq!(events(&drain(&mut client)), vec![Event::RecoveryComplete]);
    }

    #[test]
    fn test_retransmission_outside_a_request_terminates() {
        let origin = Instant::now();
        let request_timestamp = |client: &mut FixpClient| {
            client.handle_message(&sequence(11), origin);
            one_request(&drain(client)).timestamp
        };
        let retransmission = |timestamp: Nanotime, next: u64, count: u32| {
            SessionMessage::Retransmission(Retransmission {
                session_id: SESSION,
                request_timestamp: timestamp,
                next_seq_no: next,
                count,
            })
        };
        // Unsolicited.
        let (mut client, _server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        client.handle_message(&retransmission(Nanotime::from_nanos(1), 1, 1), origin);
        assert_terminates(&drain(&mut client), TerminationCode::UnspecifiedError);
        // Wrong request timestamp, wrong first number, too many, none.
        for (timestamp_offset, next, count) in [(1, 1, 1), (0, 2, 1), (0, 1, 11), (0, 1, 0)] {
            let (mut client, _server) =
                established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
            let timestamp = request_timestamp(&mut client);
            let timestamp = Nanotime::from_nanos(timestamp.as_nanos() + timestamp_offset);
            client.handle_message(&retransmission(timestamp, next, count), origin);
            assert_terminates(&drain(&mut client), TerminationCode::UnspecifiedError);
        }
        // Retransmission on an Idempotent flow (Appendix A 7.3.4).
        let (mut server, mut client) = {
            let (client, server) =
                established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
            (server, client)
        };
        server.handle_message(&retransmission(Nanotime::from_nanos(1), 1, 1), origin);
        assert_terminates(&drain(&mut server), TerminationCode::UnspecifiedError);
        let _ = drain(&mut client);
    }

    #[test]
    fn test_retransmit_reject_abandons_the_requested_range() {
        // FIXP v1.1 section 4.6.2.3.
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        client.handle_message(&sequence(6), origin);
        let request = one_request(&drain(&mut client));
        // A reject for another request is ignored.
        client.handle_message(
            &SessionMessage::RetransmitReject(RetransmitReject {
                session_id: SESSION,
                request_timestamp: Nanotime::from_nanos(request.timestamp.as_nanos() + 9),
                code: RetransmitRejectCode::OutOfRange,
                reason: String::new(),
            }),
            origin,
        );
        assert!(matches!(
            events(&drain(&mut client)).as_slice(),
            [Event::Ignored {
                message: "RetransmitReject",
                ..
            }]
        ));
        client.handle_message(
            &SessionMessage::RetransmitReject(RetransmitReject {
                session_id: SESSION,
                request_timestamp: request.timestamp,
                code: RetransmitRejectCode::OutOfRange,
                reason: "Messages No Longer Available".to_owned(),
            }),
            origin,
        );
        let outputs = drain(&mut client);
        assert_eq!(
            events(&outputs),
            vec![
                Event::RetransmitRejected {
                    from: SeqNum::new(1),
                    count: 5,
                    code: RetransmitRejectCode::OutOfRange,
                    reason: "Messages No Longer Available".to_owned(),
                },
                Event::RecoveryComplete,
            ]
        );
        assert!(requests(&outputs).is_empty());
        assert!(!client.has_pending_recovery());
        assert_eq!(client.status(), SessionStatus::Established);
    }

    /// A server that has sent `sent` messages none of which reached the
    /// client, and the client's RetransmitRequest for all of them delivered
    /// to the server.
    fn lost_and_requested(
        client: &mut FixpClient,
        server: &mut FixpServer,
        sent: u64,
        now: Instant,
    ) -> RetransmitRequest {
        for _ in 0..sent {
            assert!(server.send_application(now).is_ok());
        }
        let _ = drain(server);
        client.handle_message(&sequence(sent + 1), now);
        let outputs = drain(client);
        let request = one_request(&outputs);
        deliver_all(&outputs, server, now);
        assert!(matches!(
            events(&drain(server)).as_slice(),
            [Event::RetransmitRequested { .. }]
        ));
        request
    }

    /// The provider answers with a batch of `count`, delivered to `client`
    /// together with the replayed messages; returns the deliveries.
    fn serve(
        server: &mut FixpServer,
        client: &mut FixpClient,
        count: u32,
        now: Instant,
    ) -> Vec<Delivery> {
        assert!(server.retransmit(self::count(count), now).is_ok());
        deliver_all(&drain(server), client, now);
        (0..count)
            .map(|_| client.on_application_message(now))
            .collect()
    }

    /// Heartbeats both ways at `now`, so neither side's silence timer fires.
    fn keep_alive(client: &mut FixpClient, server: &mut FixpServer, now: Instant) {
        server.handle_timeout(now);
        deliver_all(&drain(server), client, now);
        client.handle_timeout(now);
        let outputs = drain(client);
        assert!(
            requests(&outputs).is_empty(),
            "no request while keeping alive"
        );
        deliver_all(&outputs, server, now);
        let _ = drain(server);
    }

    /// A client and a server that both use `config`, established at `origin`.
    fn client_with(config: FixpConfig, origin: Instant) -> (FixpClient, FixpServer) {
        let client = FixpClient::new(
            config.clone(),
            anchor(origin),
            SESSION,
            FlowType::Idempotent,
            None,
        );
        let server = FixpServer::new(config, anchor(origin), origin);
        let (mut client, mut server) =
            negotiate_pair(client, server, FlowType::Recoverable, origin);
        crate::testkit::establish(&mut client, &mut server, origin);
        (client, server)
    }

    /// A 10 s keepalive on both sides, longer than `retransmit_timeout`: the
    /// counterparty's heartbeat Sequence can then come after a stall.
    fn with_policy(policy: crate::RetransmitStallPolicy) -> FixpConfig {
        match FixpConfig::builder()
            .keepalive_interval(Duration::from_secs(10))
            .retransmit_timeout(RETRANSMIT_TIMEOUT)
            .retransmit_stall_policy(policy)
            .build()
        {
            Ok(config) => config,
            Err(error) => panic!("invalid config: {error}"),
        }
    }

    #[test]
    fn test_terminate_during_a_retransmission_batch_keeps_its_numbers() {
        // FIXP v1.1 sections 3.5 and 4.4.1: in-flight messages are still
        // processed while terminating. The rest of a batch keeps its
        // numbers, and the session re-establishes without a false gap
        // (Appendix A 7.2.3).
        let origin = Instant::now();
        let (mut client, mut server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        let _ = lost_and_requested(&mut client, &mut server, 10, origin);
        assert!(server.retransmit(count(10), origin).is_ok());
        deliver_all(&drain(&mut server), &mut client, origin);
        for seq in 1..=3 {
            assert_eq!(client.on_application_message(origin), accepted(seq, true));
        }
        assert_eq!(
            client.terminate(TerminationCode::Finished, "", origin),
            Ok(())
        );
        let terminate = drain(&mut client);
        for seq in 4..=10 {
            assert_eq!(client.on_application_message(origin), accepted(seq, true));
        }
        assert!(events(&drain(&mut client)).contains(&Event::RecoveryComplete));
        assert_eq!(client.next_inbound_seq(), Some(SeqNum::new(11)));
        assert!(!client.has_pending_recovery());
        // The answer to the Terminate, then a new transport.
        deliver_all(&terminate, &mut server, origin);
        deliver_all(&drain(&mut server), &mut client, origin);
        assert!(closes(&drain(&mut client)));
        client.on_transport_closed();
        server.on_transport_closed();
        let _ = drain(&mut client);
        let _ = drain(&mut server);
        let later = at(origin, 100);
        assert_eq!(client.establish(later), Ok(()));
        deliver_all(&drain(&mut client), &mut server, later);
        let _ = drain(&mut server);
        assert_eq!(server.accept_establishment(later), Ok(()));
        deliver_all(&drain(&mut server), &mut client, later);
        let outputs = drain(&mut client);
        assert!(
            sent(&outputs).is_empty(),
            "no Terminate, no request: {outputs:?}"
        );
        assert_eq!(client.status(), SessionStatus::Established);
        assert_eq!(client.next_inbound_seq(), Some(SeqNum::new(11)));
    }

    #[test]
    fn test_terminate_answered_mid_batch_requests_the_rest_after_reestablishment() {
        let origin = Instant::now();
        let (mut client, mut server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        let _ = lost_and_requested(&mut client, &mut server, 10, origin);
        let deliveries = serve(&mut server, &mut client, 3, origin);
        assert_eq!(deliveries.last(), Some(&accepted(3, true)));
        assert_eq!(
            client.terminate(TerminationCode::Finished, "", origin),
            Ok(())
        );
        deliver_all(&drain(&mut client), &mut server, origin);
        deliver_all(&drain(&mut server), &mut client, origin);
        assert!(closes(&drain(&mut client)));
        assert!(client.has_pending_recovery(), "4 to 10 are still missing");
        client.on_transport_closed();
        server.on_transport_closed();
        let _ = drain(&mut client);
        let _ = drain(&mut server);
        let later = at(origin, 100);
        assert_eq!(client.establish(later), Ok(()));
        deliver_all(&drain(&mut client), &mut server, later);
        let _ = drain(&mut server);
        assert_eq!(server.accept_establishment(later), Ok(()));
        deliver_all(&drain(&mut server), &mut client, later);
        let request = one_request(&drain(&mut client));
        assert_eq!((request.from_seq_no, request.count), (4, 7));
    }

    #[test]
    fn test_default_stall_policy_waits_for_a_paced_ironfix_provider() {
        // IronFix against IronFix: the provider answers 4 of 10, then paces
        // the rest later than retransmit_timeout. The requester must not ask
        // again while the provider is still serving (sections 4.6.1, 4.6.4).
        let origin = Instant::now();
        let (mut client, mut server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        let _ = lost_and_requested(&mut client, &mut server, 10, origin);
        let first = serve(&mut server, &mut client, 4, origin);
        assert_eq!(first.last(), Some(&accepted(4, true)));
        keep_alive(&mut client, &mut server, at(origin, 1_000));
        keep_alive(&mut client, &mut server, at(origin, 2_000));
        let stall = origin + RETRANSMIT_TIMEOUT;
        client.handle_timeout(stall);
        let outputs = drain(&mut client);
        assert!(events(&outputs).contains(&Event::RetransmitTimedOut {
            from: SeqNum::new(1),
            count: 10,
        }));
        assert!(requests(&outputs).is_empty(), "no premature second request");
        deliver_all(&outputs, &mut server, stall);
        assert!(!closes(&drain(&mut server)));
        assert_eq!(server.status(), SessionStatus::Established);
        // Reported once: the timer does not fire again for the same stall.
        client.handle_timeout(stall + Duration::from_millis(10));
        assert!(
            !events(&drain(&mut client))
                .iter()
                .any(|event| matches!(event, Event::RetransmitTimedOut { .. }))
        );
        // The provider sends the rest.
        let rest = serve(&mut server, &mut client, 6, stall);
        assert_eq!(rest.first(), Some(&accepted(5, true)));
        assert_eq!(rest.last(), Some(&accepted(10, true)));
        assert!(events(&drain(&mut client)).contains(&Event::RecoveryComplete));
        assert_eq!(client.status(), SessionStatus::Established);
        assert_eq!(server.status(), SessionStatus::Established);
    }

    #[test]
    fn test_default_stall_policy_asks_again_after_an_interrupted_batch() {
        // A Sequence cut the batch short of its Count (section 3.5.4): the
        // provider stopped serving, so the rest is requested again
        // retransmit_timeout after the cut.
        let origin = Instant::now();
        let (mut client, _server) = client_with(
            with_policy(crate::RetransmitStallPolicy::ReRequestAfterContextSwitch),
            origin,
        );
        client.handle_message(&sequence(11), origin);
        let first = one_request(&drain(&mut client));
        client.handle_message(
            &SessionMessage::Retransmission(Retransmission {
                session_id: SESSION,
                request_timestamp: first.timestamp,
                next_seq_no: 1,
                count: 10,
            }),
            origin,
        );
        for seq in 1..=4 {
            assert_eq!(client.on_application_message(origin), accepted(seq, true));
        }
        let cut = at(origin, 1_500);
        client.handle_message(&sequence(11), cut);
        let stall = cut + RETRANSMIT_TIMEOUT;
        assert_eq!(client.poll_timeout(), Some(stall));
        client.handle_timeout(stall - Duration::from_millis(1));
        assert!(requests(&drain(&mut client)).is_empty());
        client.handle_timeout(stall);
        let outputs = drain(&mut client);
        assert!(events(&outputs).contains(&Event::RetransmitTimedOut {
            from: SeqNum::new(1),
            count: 10,
        }));
        let second = one_request(&outputs);
        assert_eq!((second.from_seq_no, second.count), (5, 6));
        assert!(second.timestamp > first.timestamp);
    }

    #[test]
    fn test_default_stall_policy_asks_again_when_the_cut_follows_the_stall() {
        // The batch goes quiet first: the stall is reported and waited out.
        // The provider's heartbeat Sequence then cuts the batch short. The
        // cut must restart the stall timer, or the request stays outstanding
        // for good and nothing is ever requested again on this binding.
        let origin = Instant::now();
        let (mut client, _server) = client_with(
            with_policy(crate::RetransmitStallPolicy::ReRequestAfterContextSwitch),
            origin,
        );
        client.handle_message(&sequence(11), origin);
        let first = one_request(&drain(&mut client));
        client.handle_message(
            &SessionMessage::Retransmission(Retransmission {
                session_id: SESSION,
                request_timestamp: first.timestamp,
                next_seq_no: 1,
                count: 10,
            }),
            origin,
        );
        for seq in 1..=4 {
            assert_eq!(client.on_application_message(origin), accepted(seq, true));
        }
        // Quiet for retransmit_timeout, not cut: reported, no request.
        let stall = origin + RETRANSMIT_TIMEOUT;
        client.handle_timeout(stall);
        let outputs = drain(&mut client);
        assert!(events(&outputs).contains(&Event::RetransmitTimedOut {
            from: SeqNum::new(1),
            count: 10,
        }));
        assert!(requests(&outputs).is_empty());
        // Then the cut, and the timer runs again from it.
        let cut = stall + Duration::from_millis(500);
        client.handle_message(&sequence(11), cut);
        assert!(drain(&mut client).is_empty());
        assert_eq!(client.poll_timeout(), Some(cut + RETRANSMIT_TIMEOUT));
        client.handle_timeout(cut + RETRANSMIT_TIMEOUT - Duration::from_millis(1));
        assert!(requests(&drain(&mut client)).is_empty());
        client.handle_timeout(cut + RETRANSMIT_TIMEOUT);
        let outputs = drain(&mut client);
        let second = one_request(&outputs);
        assert_eq!((second.from_seq_no, second.count), (5, 6));
        // The answer recovers the rest.
        let answered = cut + RETRANSMIT_TIMEOUT;
        let deliveries = replay(&mut client, &second, 5, 6, answered);
        assert_eq!(deliveries.last(), Some(&accepted(10, true)));
        assert!(events(&drain(&mut client)).contains(&Event::RecoveryComplete));
        assert!(!client.has_pending_recovery());
        // Nothing is left outstanding: a later gap is requested at once.
        client.handle_message(&sequence(15), answered);
        let later = one_request(&drain(&mut client));
        assert_eq!((later.from_seq_no, later.count), (11, 4));
    }

    #[test]
    fn test_event_only_stall_policy_never_asks_again() {
        let origin = Instant::now();
        let (mut client, _server) =
            client_with(with_policy(crate::RetransmitStallPolicy::EventOnly), origin);
        client.handle_message(&sequence(11), origin);
        let first = one_request(&drain(&mut client));
        client.handle_message(
            &SessionMessage::Retransmission(Retransmission {
                session_id: SESSION,
                request_timestamp: first.timestamp,
                next_seq_no: 1,
                count: 10,
            }),
            origin,
        );
        let _ = client.on_application_message(origin);
        // Even an interrupted batch is only reported.
        let cut = at(origin, 1_500);
        client.handle_message(&sequence(11), cut);
        client.handle_timeout(cut + RETRANSMIT_TIMEOUT);
        let outputs = drain(&mut client);
        assert!(events(&outputs).contains(&Event::RetransmitTimedOut {
            from: SeqNum::new(1),
            count: 10,
        }));
        assert!(requests(&outputs).is_empty());
        assert!(client.has_pending_recovery());
        assert_eq!(client.status(), SessionStatus::Established);
    }

    #[test]
    fn test_terminate_stall_policy_unbinds_and_asks_again_after_reestablishment() {
        let origin = Instant::now();
        let (mut client, mut server) =
            client_with(with_policy(crate::RetransmitStallPolicy::Terminate), origin);
        let _ = lost_and_requested(&mut client, &mut server, 10, origin);
        let _ = serve(&mut server, &mut client, 4, origin);
        keep_alive(&mut client, &mut server, at(origin, 1_000));
        keep_alive(&mut client, &mut server, at(origin, 2_000));
        let stall = origin + RETRANSMIT_TIMEOUT;
        client.handle_timeout(stall);
        let outputs = drain(&mut client);
        assert!(events(&outputs).contains(&Event::RetransmitTimedOut {
            from: SeqNum::new(1),
            count: 10,
        }));
        assert_terminates(&outputs, TerminationCode::UnspecifiedError);
        assert_eq!(client.status(), SessionStatus::Negotiated);
        // The server learns of the unbinding; its provider stops.
        deliver_all(&outputs, &mut server, stall);
        let _ = drain(&mut server);
        client.on_transport_closed();
        server.on_transport_closed();
        let _ = drain(&mut client);
        let _ = drain(&mut server);
        // No retransmission can be in progress on a new binding: 5 to 10 are
        // requested again and served.
        let later = stall + Duration::from_millis(100);
        assert_eq!(client.establish(later), Ok(()));
        deliver_all(&drain(&mut client), &mut server, later);
        let _ = drain(&mut server);
        assert_eq!(server.accept_establishment(later), Ok(()));
        deliver_all(&drain(&mut server), &mut client, later);
        let outputs = drain(&mut client);
        let again = one_request(&outputs);
        assert_eq!((again.from_seq_no, again.count), (5, 6));
        deliver_all(&outputs, &mut server, later);
        assert_eq!(
            events(&drain(&mut server)),
            vec![Event::RetransmitRequested {
                from: SeqNum::new(5),
                count: 6,
            }]
        );
    }

    #[test]
    fn test_context_with_the_null_next_seq_changes_nothing() {
        // Section 3.5.3 makes NextSeqNo optional; u64::MAX is its SBE null.
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        let null = SessionMessage::Context(Context {
            session_id: SESSION,
            next_seq_no: u64::MAX,
        });
        client.handle_message(&null, origin);
        assert!(drain(&mut client).is_empty());
        assert_eq!(client.next_inbound_seq(), Some(SeqNum::new(1)));
        assert!(!client.has_pending_recovery());
        // A Sequence of u64::MAX is a number, and a gap past max_gap_len.
        client.handle_message(&sequence(u64::MAX), origin);
        let outputs = drain(&mut client);
        assert!(events(&outputs).contains(&Event::ProtocolViolation {
            reason: "sequence gap larger than max_gap_len"
        }));
        assert!(requests(&outputs).is_empty());
        // On an unsequenced flow a numberless Context is no violation.
        let (mut unsequenced, _server) =
            established_pair(origin, FlowType::Recoverable, FlowType::Unsequenced);
        unsequenced.handle_message(&null, origin);
        assert!(drain(&mut unsequenced).is_empty());
    }

    #[test]
    fn test_messages_after_an_unbind_are_ignored_until_the_transport_closes() {
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        client.handle_message(&sequence(0), origin);
        let outputs = drain(&mut client);
        assert_terminates(&outputs, TerminationCode::UnspecifiedError);
        assert_eq!(
            outputs
                .iter()
                .filter(|output| matches!(output, Output::CloseTransport))
                .count(),
            1
        );
        // Still arriving on the closing transport: ignored, not violations.
        client.handle_message(&sequence(0), origin);
        assert_eq!(
            drain(&mut client),
            vec![Output::Event(Event::Ignored {
                message: "Sequence",
                reason: "the transport is closing",
            })]
        );
        assert_eq!(client.on_application_message(origin), Delivery::Discard);
        assert!(drain(&mut client).is_empty());
        assert_eq!(
            client.establish(origin),
            Err(FixpError::TransportClosing {
                operation: "establish"
            })
        );
        client.on_transport_closed();
        assert_eq!(events(&drain(&mut client)), vec![Event::TransportClosed]);
        assert_eq!(client.establish(origin), Ok(()));
    }

    #[test]
    fn test_applied_is_reported_whatever_this_side_flow() {
        // FIXP names no violation for Applied (sections 4.8.1 and 6.3),
        // unlike NotApplied; it is numbered and reported as received.
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        client.handle_message(
            &SessionMessage::Applied(Applied {
                from_seq_no: 1,
                count: 1,
            }),
            origin,
        );
        assert_eq!(
            events(&drain(&mut client)),
            vec![Event::Applied {
                from_seq_no: 1,
                count: 1
            }]
        );
        assert_eq!(client.status(), SessionStatus::Established);
    }

    #[test]
    fn test_too_many_unrecovered_gaps_terminate() {
        let origin = Instant::now();
        let bounded = FixpConfig::builder()
            .max_pending_gaps(NonZeroUsize::new(2).unwrap_or(NonZeroUsize::MIN))
            .build();
        let Ok(bounded) = bounded else {
            panic!("invalid config");
        };
        let client = FixpClient::new(bounded, anchor(origin), SESSION, FlowType::Idempotent, None);
        let (mut client, mut server) =
            negotiate_pair(client, server(origin), FlowType::Recoverable, origin);
        crate::testkit::establish(&mut client, &mut server, origin);
        // Gaps 1..3, 4..6 and 7..9, each separated by one received message.
        client.handle_message(&sequence(3), origin);
        assert_eq!(client.on_application_message(origin), accepted(3, false));
        client.handle_message(&sequence(6), origin);
        assert_eq!(client.on_application_message(origin), accepted(6, false));
        assert_eq!(client.status(), SessionStatus::Established);
        client.handle_message(&sequence(9), origin);
        let outputs = drain(&mut client);
        assert!(events(&outputs).contains(&Event::ProtocolViolation {
            reason: "too many unrecovered sequence gaps"
        }));
        assert_terminates(&outputs, TerminationCode::UnspecifiedError);
    }

    #[test]
    fn test_unrecovered_gaps_are_requested_again_after_reestablishment() {
        let origin = Instant::now();
        let (mut client, mut server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        for _ in 0..6 {
            assert!(server.send_application(origin).is_ok());
        }
        let _ = drain(&mut server);
        client.handle_message(&sequence(7), origin);
        let first = one_request(&drain(&mut client));
        let _ = replay(&mut client, &first, 1, 2, origin);
        // The transport drops mid-retransmission.
        client.on_transport_closed();
        server.on_transport_closed();
        let _ = drain(&mut client);
        let _ = drain(&mut server);
        let later = at(origin, 100);
        assert_eq!(client.establish(later), Ok(()));
        deliver_all(&drain(&mut client), &mut server, later);
        let _ = drain(&mut server);
        assert_eq!(server.accept_establishment(later), Ok(()));
        deliver_all(&drain(&mut server), &mut client, later);
        let outputs = drain(&mut client);
        let again = one_request(&outputs);
        assert_eq!(
            (again.from_seq_no, again.count),
            (3, 4),
            "1 and 2 were recovered"
        );
    }

    // ----- idempotent flow: NotApplied ----------------------------------------

    #[test]
    fn test_gap_on_an_idempotent_flow_sends_not_applied() {
        // FIXP v1.1 section 4.8.2: NotApplied consumes a sequence number of
        // the flow that carries it.
        let origin = Instant::now();
        let (mut client, mut server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        assert_eq!(
            send_apps(&mut client, &mut server, 1, origin),
            vec![accepted(1, false)]
        );
        server.handle_message(&sequence(10), origin);
        let outputs = drain(&mut server);
        assert!(events(&outputs).contains(&Event::SequenceGap {
            from: SeqNum::new(2),
            count: 8,
        }));
        let applications: Vec<_> = outputs
            .iter()
            .filter_map(|output| match output {
                Output::SendApplication { seq, message } => Some((*seq, message.clone())),
                Output::Send(_) | Output::CloseTransport | Output::Event(_) => None,
            })
            .collect();
        assert_eq!(
            applications,
            vec![(
                Some(SeqNum::new(1)),
                SessionMessage::NotApplied(NotApplied {
                    from_seq_no: 2,
                    count: 8
                })
            )]
        );
        assert_eq!(
            sent(&outputs).first(),
            Some(&sequence(1)),
            "a Sequence opens the flow"
        );
        assert_eq!(
            server.next_inbound_seq(),
            Some(SeqNum::new(10)),
            "it keeps accepting"
        );
        // The client learns which of its operations were not applied.
        deliver_all(&outputs, &mut client, origin);
        assert_eq!(
            events(&drain(&mut client)),
            vec![Event::NotApplied {
                from_seq_no: 2,
                count: 8
            }]
        );
        assert_eq!(
            client.next_inbound_seq(),
            Some(SeqNum::new(2)),
            "it consumed number 1"
        );
    }

    #[test]
    fn test_not_applied_on_an_unsequenced_return_flow_has_no_number() {
        let origin = Instant::now();
        let (_client, mut server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Unsequenced);
        server.handle_message(&sequence(1), origin);
        server.handle_message(&sequence(4), origin);
        let outputs = drain(&mut server);
        assert!(outputs.iter().any(|output| matches!(
            output,
            Output::SendApplication {
                seq: None,
                message: SessionMessage::NotApplied(_)
            }
        )));
    }

    #[test]
    fn test_gap_without_a_return_flow_is_only_reported() {
        let origin = Instant::now();
        let (_client, mut server) = established_pair(origin, FlowType::Idempotent, FlowType::None);
        server.handle_message(&sequence(1), origin);
        server.handle_message(&sequence(4), origin);
        let outputs = drain(&mut server);
        assert!(
            sent(&outputs).is_empty(),
            "a None flow carries no NotApplied"
        );
        assert_eq!(
            events(&outputs),
            vec![Event::SequenceGap {
                from: SeqNum::new(1),
                count: 3
            }]
        );
    }

    #[test]
    fn test_not_applied_for_a_recoverable_flow_is_a_violation() {
        // FIXP v1.1 section 4.8.2.
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Recoverable, FlowType::Recoverable);
        client.handle_message(
            &SessionMessage::NotApplied(NotApplied {
                from_seq_no: 1,
                count: 1,
            }),
            origin,
        );
        assert_terminates(&drain(&mut client), TerminationCode::UnspecifiedError);
    }

    #[test]
    fn test_applied_is_reported_and_numbered() {
        // FIXP v1.1 section 4.8.1.
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        client.handle_message(
            &SessionMessage::Applied(Applied {
                from_seq_no: 1,
                count: 3,
            }),
            origin,
        );
        assert_eq!(
            events(&drain(&mut client)),
            vec![Event::Applied {
                from_seq_no: 1,
                count: 3
            }]
        );
        assert_eq!(client.next_inbound_seq(), Some(SeqNum::new(2)));
    }

    // ----- providing retransmissions ------------------------------------------

    /// A server that has sent ten messages, and its client.
    fn provider(origin: Instant) -> (FixpClient, FixpServer) {
        let (client, mut server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        for _ in 0..10 {
            assert!(server.send_application(origin).is_ok());
        }
        let _ = drain(&mut server);
        (client, server)
    }

    fn request(session_id: crate::types::SessionId, from: u64, count: u32) -> SessionMessage {
        SessionMessage::RetransmitRequest(RetransmitRequest {
            session_id,
            timestamp: Nanotime::from_nanos(99),
            from_seq_no: from,
            count,
        })
    }

    #[test]
    fn test_provider_refuses_invalid_requests_with_the_right_code() {
        // FIXP v1.1 section 4.6.2.3; Appendix A 7.3.5.
        let origin = Instant::now();
        let (_client, mut server) = provider(origin);
        let cases = [
            (
                request(OTHER_SESSION, 1, 1),
                RetransmitRejectCode::InvalidSession,
            ),
            (request(SESSION, 1, 0), RetransmitRejectCode::OutOfRange),
            (
                request(SESSION, 1, MAX_RETRANSMIT + 1),
                RetransmitRejectCode::RequestLimitExceeded,
            ),
            (request(SESSION, 0, 1), RetransmitRejectCode::OutOfRange),
            (request(SESSION, 5, 7), RetransmitRejectCode::OutOfRange),
            (request(SESSION, 11, 1), RetransmitRejectCode::OutOfRange),
            (
                request(SESSION, u64::MAX, 2),
                RetransmitRejectCode::OutOfRange,
            ),
        ];
        for (message, code) in cases {
            server.handle_message(&message, origin);
            let outputs = drain(&mut server);
            match sent(&outputs).as_slice() {
                [SessionMessage::RetransmitReject(reject)] => {
                    assert_eq!(reject.code, code, "{message:?}");
                    assert_eq!(reject.request_timestamp, Nanotime::from_nanos(99));
                    assert_eq!(Some(reject.session_id), message.session_id());
                }
                other => panic!("expected a RetransmitReject for {message:?}, got {other:?}"),
            }
            assert!(matches!(
                events(&outputs).as_slice(),
                [Event::Refused {
                    message: "RetransmitReject",
                    ..
                }]
            ));
            assert_eq!(server.status(), SessionStatus::Established);
        }
    }

    #[test]
    fn test_provider_answers_in_batches() {
        let origin = Instant::now();
        let (_client, mut server) = provider(origin);
        server.handle_message(&request(SESSION, 3, 5), origin);
        assert_eq!(
            events(&drain(&mut server)),
            vec![Event::RetransmitRequested {
                from: SeqNum::new(3),
                count: 5
            }]
        );
        assert_eq!(
            server.retransmit(count(3), origin),
            Ok(RetransmitBatch {
                from: SeqNum::new(3),
                count: 3
            })
        );
        assert_eq!(
            sent(&drain(&mut server)),
            vec![SessionMessage::Retransmission(Retransmission {
                session_id: SESSION,
                request_timestamp: Nanotime::from_nanos(99),
                next_seq_no: 3,
                count: 3,
            })]
        );
        assert_eq!(
            server.retransmit(count(3), origin),
            Err(FixpError::RetransmissionOverrun {
                count: 3,
                remaining: 2
            })
        );
        assert_eq!(
            server.retransmit(count(2), origin),
            Ok(RetransmitBatch {
                from: SeqNum::new(6),
                count: 2
            })
        );
        let _ = drain(&mut server);
        assert_eq!(
            server.retransmit(count(1), origin),
            Err(FixpError::NoRetransmissionInProgress)
        );
        // A new request is welcome once the last one is answered.
        server.handle_message(&request(SESSION, 1, 1), origin);
        assert!(matches!(
            events(&drain(&mut server)).as_slice(),
            [Event::RetransmitRequested { .. }]
        ));
    }

    #[test]
    fn test_provider_can_reject_or_end_a_request() {
        let origin = Instant::now();
        let (_client, mut server) = provider(origin);
        assert_eq!(
            server.reject_retransmit_request(RetransmitRejectCode::OutOfRange, "gone"),
            Err(FixpError::NoRetransmissionInProgress)
        );
        assert_eq!(
            server.end_retransmission(),
            Err(FixpError::NoRetransmissionInProgress)
        );
        server.handle_message(&request(SESSION, 1, 4), origin);
        let _ = drain(&mut server);
        assert_eq!(
            server.reject_retransmit_request(
                RetransmitRejectCode::OutOfRange,
                "Messages No Longer Available"
            ),
            Ok(())
        );
        assert_eq!(
            sent(&drain(&mut server)),
            vec![SessionMessage::RetransmitReject(RetransmitReject {
                session_id: SESSION,
                request_timestamp: Nanotime::from_nanos(99),
                code: RetransmitRejectCode::OutOfRange,
                reason: "Messages No Longer Available".to_owned(),
            })]
        );
        server.handle_message(&request(SESSION, 1, 4), origin);
        let _ = drain(&mut server);
        assert!(server.retransmit(count(1), origin).is_ok());
        assert_eq!(server.end_retransmission(), Ok(()));
        server.handle_message(&request(SESSION, 2, 3), origin);
        assert!(matches!(
            events(&drain(&mut server)).as_slice(),
            [Event::RetransmitRequested { .. }]
        ));
    }

    #[test]
    fn test_a_request_while_one_is_answered_terminates_with_re_request_in_progress() {
        // FIXP v1.1 sections 4.6.4 and 6.3; Appendix A 7.3.4.1.
        let origin = Instant::now();
        let (_client, mut server) = provider(origin);
        server.handle_message(&request(SESSION, 1, 4), origin);
        let _ = drain(&mut server);
        server.handle_message(&request(SESSION, 5, 2), origin);
        let outputs = drain(&mut server);
        assert_terminates(&outputs, TerminationCode::ReRequestInProgress);
        assert_eq!(server.status(), SessionStatus::Negotiated);
    }

    #[test]
    fn test_a_request_to_a_flow_that_is_not_recoverable_terminates() {
        // FIXP v1.1 section 4.6.1.
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        client.handle_message(&request(SESSION, 1, 1), origin);
        assert_terminates(&drain(&mut client), TerminationCode::UnspecifiedError);
    }

    // ----- termination ---------------------------------------------------------

    #[test]
    fn test_graceful_terminate_waits_for_the_answer() {
        // FIXP v1.1 sections 4.4.1 and 4.4.2; Appendix A 7.2.4.
        let origin = Instant::now();
        let (mut client, mut server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        assert_eq!(
            client.terminate(TerminationCode::Finished, "", origin),
            Ok(())
        );
        let terminate = drain(&mut client);
        assert!(!closes(&terminate), "the initiator waits for the answer");
        assert_eq!(client.status(), SessionStatus::Terminating);
        deliver_all(&terminate, &mut server, origin);
        let answer = drain(&mut server);
        assert_eq!(
            sent(&answer),
            vec![SessionMessage::Terminate(Terminate {
                session_id: SESSION,
                code: TerminationCode::Finished,
                reason: String::new(),
            })]
        );
        assert_eq!(
            events(&answer),
            vec![Event::Terminated {
                code: TerminationCode::Finished,
                reason: String::new(),
                by: TerminatedBy::Peer,
            }]
        );
        assert!(!closes(&answer), "the responder lets the initiator close");
        assert_eq!(server.status(), SessionStatus::Closing);
        deliver_all(&answer, &mut client, origin);
        let closed = drain(&mut client);
        assert_eq!(
            events(&closed),
            vec![Event::Terminated {
                code: TerminationCode::Finished,
                reason: String::new(),
                by: TerminatedBy::Local,
            }]
        );
        assert!(closes(&closed));
        assert_eq!(client.status(), SessionStatus::Negotiated);
        server.on_transport_closed();
        assert_eq!(server.status(), SessionStatus::Negotiated);
    }

    #[test]
    fn test_terminating_gives_up_after_a_keepalive_interval() {
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        assert_eq!(
            client.terminate(TerminationCode::Finished, "done", origin),
            Ok(())
        );
        let _ = drain(&mut client);
        assert_eq!(client.poll_timeout(), Some(origin + KEEPALIVE));
        client.handle_timeout(origin + KEEPALIVE);
        let outputs = drain(&mut client);
        assert_eq!(
            events(&outputs),
            vec![Event::Terminated {
                code: TerminationCode::Finished,
                reason: "done".to_owned(),
                by: TerminatedBy::Local,
            }]
        );
        assert!(closes(&outputs));
        assert_eq!(client.status(), SessionStatus::Negotiated);
    }

    #[test]
    fn test_an_error_terminate_closes_at_once() {
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        assert_eq!(
            client.terminate(TerminationCode::UnspecifiedError, "bad", origin),
            Ok(())
        );
        let outputs = drain(&mut client);
        assert_terminates(&outputs, TerminationCode::UnspecifiedError);
        assert_eq!(client.status(), SessionStatus::Negotiated);
        assert!(matches!(
            client.terminate(TerminationCode::Finished, "", origin),
            Err(FixpError::InvalidState { .. })
        ));
    }

    #[test]
    fn test_in_flight_messages_are_processed_while_terminating() {
        // FIXP v1.1 section 4.4.1.
        let origin = Instant::now();
        let (mut client, mut server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        assert_eq!(
            client.terminate(TerminationCode::Finished, "", origin),
            Ok(())
        );
        let _ = drain(&mut client);
        assert_eq!(
            send_apps(&mut server, &mut client, 1, origin),
            vec![accepted(1, false)]
        );
        assert_eq!(
            client.send_application(origin),
            Err(FixpError::InvalidState {
                operation: "send_application",
                status: SessionStatus::Terminating,
            })
        );
        // A gap seen now is recorded but not requested: Terminate was the
        // last message this side may send.
        client.handle_message(&sequence(9), origin);
        let outputs = drain(&mut client);
        assert!(requests(&outputs).is_empty());
        assert!(client.has_pending_recovery());
    }

    #[test]
    fn test_messages_after_a_terminate_are_ignored() {
        // FIXP v1.1 section 4.4.
        let origin = Instant::now();
        let (mut client, mut server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        assert_eq!(
            client.terminate(TerminationCode::Finished, "", origin),
            Ok(())
        );
        deliver_all(&drain(&mut client), &mut server, origin);
        let _ = drain(&mut server);
        assert_eq!(server.status(), SessionStatus::Closing);
        server.handle_message(&sequence(5), origin);
        assert_eq!(
            drain(&mut server),
            vec![Output::Event(Event::Ignored {
                message: "Sequence",
                reason: "it arrived after the counterparty's Terminate",
            })]
        );
        assert_eq!(server.on_application_message(origin), Delivery::Discard);
        assert!(drain(&mut server).is_empty());
        assert!(matches!(
            server.send_application(origin),
            Err(FixpError::InvalidState {
                status: SessionStatus::Closing,
                ..
            })
        ));
        // Past a keepalive interval the responder closes the transport itself.
        server.handle_timeout(origin + KEEPALIVE);
        assert!(closes(&drain(&mut server)));
        assert_eq!(server.status(), SessionStatus::Negotiated);
    }

    #[test]
    fn test_terminate_for_another_session_is_a_violation() {
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        client.handle_message(
            &SessionMessage::Terminate(Terminate {
                session_id: OTHER_SESSION,
                code: TerminationCode::Finished,
                reason: String::new(),
            }),
            origin,
        );
        assert_terminates(&drain(&mut client), TerminationCode::UnspecifiedError);
    }

    #[test]
    fn test_terminate_refuses_a_reason_above_the_length_prefix() {
        let origin = Instant::now();
        let (mut client, _server) =
            established_pair(origin, FlowType::Idempotent, FlowType::Recoverable);
        assert_eq!(
            client.terminate(TerminationCode::Finished, "x".repeat(65_536), origin),
            Err(FixpError::ReasonTooLong {
                len: 65_536,
                max: 65_534
            })
        );
        assert_eq!(client.status(), SessionStatus::Established);
    }
}
