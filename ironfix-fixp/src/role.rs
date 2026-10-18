/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! The part of the public API that [`crate::FixpClient`] and
//! [`crate::FixpServer`] share: everything a bound session does whatever its
//! role. It is written once, as a macro, so the two roles cannot drift.
//!
//! Each role provides two private methods the macro relies on:
//!
//! - `bound_parts(&mut self, operation)`: the core, the session and the
//!   binding when the session is bound, or [`crate::FixpError::InvalidState`];
//! - `after(&mut self, bound)`: moves the role to its "negotiated, not bound"
//!   state when a handler returns `Bound::Unbind`;
//!
//! and `application_before_established(&mut self)`, the answer to an
//! application message that arrives before the session is bound.

/// Implements the shared, bound-session API on a role type.
macro_rules! bound_api {
    ($role:ident) => {
        impl $role {
            /// Records an application message just received and says what to do
            /// with it.
            ///
            /// Call it once per application message, in arrival order, before
            /// handing the message to the application. On a sequenced flow it
            /// returns the message's implicit sequence number (FIXP v1.1
            /// section 3.5.1) and whether it was retransmitted. While
            /// [`has_pending_recovery`](Self::has_pending_recovery) is true,
            /// messages after a gap are delivered as they arrive, and the
            /// application should queue them for in-order processing
            /// (section 4.6.1).
            ///
            /// An application message before establishment, on a None flow,
            /// before any Sequence on a sequenced flow, or after a Terminate is
            /// [`Delivery::Discard`](crate::Delivery::Discard); the session
            /// answers the violation itself.
            pub fn on_application_message(
                &mut self,
                now: std::time::Instant,
            ) -> crate::output::Delivery {
                match self.bound_parts("on_application_message") {
                    Ok((core, session, binding)) => {
                        let (delivery, bound) = session.on_application(core, binding, now);
                        self.after(bound);
                        delivery
                    }
                    Err(_) => {
                        self.application_before_established();
                        crate::output::Delivery::Discard
                    }
                }
            }

            /// Numbers an application message this side is about to send and
            /// returns its sequence number (`None` on an Unsequenced flow).
            ///
            /// Drain [`poll_output`](Self::poll_output) before writing the
            /// message: a Sequence that must precede it may have been queued
            /// (FIXP v1.1 sections 3.5.1 and 3.5.4). On a Recoverable flow the
            /// driver keeps the message under this number for retransmission.
            ///
            /// # Errors
            /// [`FixpError::InvalidState`](crate::FixpError::InvalidState)
            /// unless established,
            /// [`FixpError::FlowCarriesNoApplicationMessages`](crate::FixpError::FlowCarriesNoApplicationMessages)
            /// on a None flow, and
            /// [`FixpError::SequenceExhausted`](crate::FixpError::SequenceExhausted)
            /// when no sequence number is left.
            pub fn send_application(
                &mut self,
                now: std::time::Instant,
            ) -> Result<Option<ironfix_core::SeqNum>, crate::error::FixpError> {
                let (core, session, binding) = self.bound_parts("send_application")?;
                session.send_application(core, binding, now)
            }

            /// Unbinds the transport with a Terminate (FIXP v1.1 section 4.4).
            ///
            /// With [`TerminationCode::Finished`](crate::TerminationCode::Finished)
            /// the session waits up to its keepalive interval for the
            /// counterparty's Terminate, then asks for the transport to be
            /// closed (section 4.4.1). Any other code is an error termination
            /// and the transport is closed at once. The logical session
            /// survives either way: a client may Establish it again.
            ///
            /// # Errors
            /// [`FixpError::InvalidState`](crate::FixpError::InvalidState)
            /// unless established, and
            /// [`FixpError::ReasonTooLong`](crate::FixpError::ReasonTooLong).
            pub fn terminate(
                &mut self,
                code: crate::types::TerminationCode,
                reason: impl Into<String>,
                now: std::time::Instant,
            ) -> Result<(), crate::error::FixpError> {
                let (core, session, binding) = self.bound_parts("terminate")?;
                let bound = session.terminate(core, binding, code, reason.into(), now)?;
                self.after(bound);
                Ok(())
            }

            /// Answers the counterparty's RetransmitRequest (announced by
            /// [`Event::RetransmitRequested`](crate::Event::RetransmitRequested))
            /// with a batch of `count` messages (FIXP v1.1 section 4.6.2).
            ///
            /// Queues the Retransmission header and returns the range to
            /// replay: drain [`poll_output`](Self::poll_output), then write the
            /// stored messages of that range, in order, immediately. Several
            /// smaller batches may answer one request (section 4.6.2.2).
            ///
            /// # Errors
            /// [`FixpError::InvalidState`](crate::FixpError::InvalidState)
            /// unless established,
            /// [`FixpError::NoRetransmissionInProgress`](crate::FixpError::NoRetransmissionInProgress),
            /// and
            /// [`FixpError::RetransmissionOverrun`](crate::FixpError::RetransmissionOverrun)
            /// for a batch larger than what is left of the request.
            pub fn retransmit(
                &mut self,
                count: std::num::NonZeroU32,
                now: std::time::Instant,
            ) -> Result<crate::output::RetransmitBatch, crate::error::FixpError> {
                let (core, session, binding) = self.bound_parts("retransmit")?;
                session.retransmit(core, binding, count, now)
            }

            /// Refuses the counterparty's RetransmitRequest being served, for
            /// example because the messages are no longer stored (FIXP v1.1
            /// section 4.6.2.3).
            ///
            /// # Errors
            /// [`FixpError::InvalidState`](crate::FixpError::InvalidState)
            /// unless established,
            /// [`FixpError::NoRetransmissionInProgress`](crate::FixpError::NoRetransmissionInProgress),
            /// and [`FixpError::ReasonTooLong`](crate::FixpError::ReasonTooLong).
            pub fn reject_retransmit_request(
                &mut self,
                code: crate::types::RetransmitRejectCode,
                reason: impl Into<String>,
            ) -> Result<(), crate::error::FixpError> {
                let (core, session, binding) = self.bound_parts("reject_retransmit_request")?;
                session.reject_retransmit_request(core, binding, code, reason.into())
            }

            /// Stops serving the counterparty's RetransmitRequest before all of
            /// it was sent. The requester asks again for the rest
            /// (FIXP v1.1 section 4.6.2.2).
            ///
            /// # Errors
            /// [`FixpError::InvalidState`](crate::FixpError::InvalidState)
            /// unless established, and
            /// [`FixpError::NoRetransmissionInProgress`](crate::FixpError::NoRetransmissionInProgress).
            pub fn end_retransmission(&mut self) -> Result<(), crate::error::FixpError> {
                let (_, session, binding) = self.bound_parts("end_retransmission")?;
                session.end_retransmission(binding)
            }

            /// Takes the next output, in the order the session produced them.
            ///
            /// Drain it after every call that takes input.
            #[must_use = "outputs must be carried out in order"]
            pub fn poll_output(&mut self) -> Option<crate::output::Output> {
                self.core.poll_output()
            }

            /// The sequence number this side's next application message will
            /// get, on a sequenced flow, once negotiated.
            #[must_use]
            pub fn next_outbound_seq(&self) -> Option<ironfix_core::SeqNum> {
                self.session()
                    .and_then(crate::session::Session::next_outbound_seq)
            }

            /// The sequence number expected for the counterparty's next
            /// real-time application message, on a sequenced flow, once
            /// negotiated. Until the counterparty announces where its
            /// numbering stands (an establishment `NextSeqNo`, a Sequence
            /// or a Context), this is the fallback 1 that an application
            /// message arriving first would get.
            #[must_use]
            pub fn next_inbound_seq(&self) -> Option<ironfix_core::SeqNum> {
                self.session()
                    .and_then(crate::session::Session::next_inbound_seq)
            }

            /// `true` while a gap of the counterparty's Recoverable flow is
            /// unrecovered (FIXP v1.1 section 4.6.1).
            #[must_use]
            pub fn has_pending_recovery(&self) -> bool {
                self.session()
                    .is_some_and(crate::session::Session::has_pending_recovery)
            }
        }
    };
}

pub(crate) use bound_api;
