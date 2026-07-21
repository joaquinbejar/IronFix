/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! Session state machine using the typestate pattern.
//!
//! This module implements a compile-time checked state machine for FIX sessions.
//! State transitions are enforced by the type system, preventing invalid operations.
//!
//! # States carry their data
//!
//! [`Session`] stores its state value, not a `PhantomData<S>`, so the data a
//! state is defined by is reachable: when the session is in [`LogonSent`] it
//! *has* the instant the Logon went out, and only then. That is what lets a
//! caller enforce the logon and logout timeouts from the state machine rather
//! than tracking deadlines beside it — `ironfix-engine`'s reactor times its
//! Logout out through `Session<LogoutPending>::sent_at`.
//!
//! The states with no data ([`Disconnected`], [`Connecting`], [`Active`]) stay
//! zero-sized, so the typestate still costs nothing for them.

use std::time::Instant;

/// Marker trait for session states.
pub trait SessionState: private::Sealed {}

mod private {
    pub trait Sealed {}
}

/// Disconnected state - no connection established.
#[derive(Debug, Clone, Copy)]
pub struct Disconnected;

impl private::Sealed for Disconnected {}
impl SessionState for Disconnected {}

/// Connecting state - TCP connection in progress.
#[derive(Debug, Clone, Copy)]
pub struct Connecting;

impl private::Sealed for Connecting {}
impl SessionState for Connecting {}

/// LogonSent state - Logon message sent, awaiting response.
#[derive(Debug, Clone, Copy)]
pub struct LogonSent {
    /// Time when Logon was sent, for the `logon_timeout`.
    pub sent_at: Instant,
}

impl private::Sealed for LogonSent {}
impl SessionState for LogonSent {}

/// LogonReceived state - Logon received from counterparty (acceptor side),
/// pending authentication.
#[derive(Debug, Clone, Copy)]
pub struct LogonReceived {
    /// Time when the Logon was received, for the authentication deadline.
    pub received_at: Instant,
}

impl private::Sealed for LogonReceived {}
impl SessionState for LogonReceived {}

/// Active state - session is fully established.
#[derive(Debug, Clone, Copy)]
pub struct Active;

impl private::Sealed for Active {}
impl SessionState for Active {}

/// Resending state - processing a resend request.
#[derive(Debug, Clone, Copy)]
pub struct Resending {
    /// Begin sequence number of the gap, `BeginSeqNo` (7).
    pub begin_seq: u64,
    /// End sequence number of the gap, `EndSeqNo` (16).
    ///
    /// `0` carries the FIX convention "through the last message sent"
    /// (`doc/fix_operations.md`, "Resend Request"), not an empty range.
    pub end_seq: u64,
}

impl private::Sealed for Resending {}
impl SessionState for Resending {}

/// LogoutPending state - Logout sent, awaiting confirmation.
#[derive(Debug, Clone, Copy)]
pub struct LogoutPending {
    /// Time when Logout was sent, for the `logout_timeout`.
    pub sent_at: Instant,
}

impl private::Sealed for LogoutPending {}
impl SessionState for LogoutPending {}

/// Session wrapper with typestate for compile-time state checking.
///
/// The type parameter `S` represents the current session state, and the value
/// of that state is stored: see the module documentation.
#[derive(Debug)]
pub struct Session<S: SessionState> {
    /// Session identifier.
    pub session_id: String,
    /// The current state and its data.
    state: S,
}

impl<S: SessionState> Session<S> {
    /// Returns the session identifier.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the current state and its data.
    #[must_use]
    pub const fn state(&self) -> &S {
        &self.state
    }

    /// Moves to `next`, carrying the session identity across.
    ///
    /// Private: the only way to reach a state is through the transition that
    /// names it, which is what keeps an illegal transition uncompilable.
    fn transition<N: SessionState>(self, next: N) -> Session<N> {
        Session {
            session_id: self.session_id,
            state: next,
        }
    }
}

impl Session<Disconnected> {
    /// Creates a new disconnected session.
    ///
    /// # Arguments
    /// * `session_id` - Unique identifier for this session
    #[must_use]
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            state: Disconnected,
        }
    }

    /// Transitions to the Connecting state (initiator side).
    #[must_use]
    pub fn connect(self) -> Session<Connecting> {
        self.transition(Connecting)
    }

    /// Transitions to the Connecting state after accepting an inbound
    /// TCP connection (acceptor side).
    #[must_use]
    pub fn accept(self) -> Session<Connecting> {
        self.transition(Connecting)
    }
}

impl Session<Connecting> {
    /// Transitions to the LogonSent state after sending Logon (initiator
    /// side), recording the send instant for the logon timeout.
    #[must_use]
    pub fn send_logon(self) -> Session<LogonSent> {
        self.transition(LogonSent {
            sent_at: Instant::now(),
        })
    }

    /// Transitions to the LogonReceived state when a Logon arrives from
    /// the counterparty (acceptor side), recording the arrival instant.
    #[must_use]
    pub fn on_logon_received(self) -> Session<LogonReceived> {
        self.transition(LogonReceived {
            received_at: Instant::now(),
        })
    }

    /// Transitions back to Disconnected on connection failure.
    #[must_use]
    pub fn disconnect(self) -> Session<Disconnected> {
        self.transition(Disconnected)
    }
}

impl Session<LogonSent> {
    /// Returns when the Logon was sent, for the `logon_timeout`.
    #[must_use]
    pub const fn sent_at(&self) -> Instant {
        self.state.sent_at
    }

    /// Transitions to Active state on successful Logon acknowledgement.
    #[must_use]
    pub fn on_logon_ack(self) -> Session<Active> {
        self.transition(Active)
    }

    /// Transitions to Disconnected on Logon rejection or timeout.
    #[must_use]
    pub fn on_logon_reject(self) -> Session<Disconnected> {
        self.transition(Disconnected)
    }
}

impl Session<LogonReceived> {
    /// Returns when the counterparty's Logon arrived, for the authentication
    /// deadline.
    #[must_use]
    pub const fn received_at(&self) -> Instant {
        self.state.received_at
    }

    /// Transitions to Active after successful authentication, once the
    /// Logon acknowledgement has been sent back to the counterparty.
    #[must_use]
    pub fn accept_logon(self) -> Session<Active> {
        self.transition(Active)
    }

    /// Transitions to Disconnected when authentication fails and the
    /// Logon is rejected (Logout/Reject sent, connection dropped).
    #[must_use]
    pub fn reject_logon(self) -> Session<Disconnected> {
        self.transition(Disconnected)
    }

    /// Transitions to Disconnected when authentication does not complete
    /// within the allowed time.
    #[must_use]
    pub fn on_timeout(self) -> Session<Disconnected> {
        self.transition(Disconnected)
    }
}

impl Session<Active> {
    /// Transitions to Resending state when a gap is detected, carrying the
    /// range the resend covers.
    ///
    /// # Arguments
    /// * `begin_seq` - `BeginSeqNo` (7) of the gap
    /// * `end_seq` - `EndSeqNo` (16) of the gap; `0` means "through the last
    ///   message sent", the FIX convention
    #[must_use]
    pub fn start_resend(self, begin_seq: u64, end_seq: u64) -> Session<Resending> {
        self.transition(Resending { begin_seq, end_seq })
    }

    /// Transitions to LogoutPending state, recording the send instant for the
    /// logout timeout.
    #[must_use]
    pub fn initiate_logout(self) -> Session<LogoutPending> {
        self.transition(LogoutPending {
            sent_at: Instant::now(),
        })
    }

    /// Transitions to Disconnected on unexpected disconnect.
    #[must_use]
    pub fn disconnect(self) -> Session<Disconnected> {
        self.transition(Disconnected)
    }
}

impl Session<Resending> {
    /// Returns `BeginSeqNo` (7) of the range being resent.
    #[must_use]
    pub const fn begin_seq(&self) -> u64 {
        self.state.begin_seq
    }

    /// Returns `EndSeqNo` (16) of the range being resent; `0` means "through
    /// the last message sent".
    #[must_use]
    pub const fn end_seq(&self) -> u64 {
        self.state.end_seq
    }

    /// Transitions back to Active when resend is complete.
    #[must_use]
    pub fn resend_complete(self) -> Session<Active> {
        self.transition(Active)
    }

    /// Transitions to Disconnected on error.
    #[must_use]
    pub fn disconnect(self) -> Session<Disconnected> {
        self.transition(Disconnected)
    }
}

impl Session<LogoutPending> {
    /// Returns when the Logout was sent, for the `logout_timeout`.
    #[must_use]
    pub const fn sent_at(&self) -> Instant {
        self.state.sent_at
    }

    /// Transitions to Disconnected on Logout acknowledgement or timeout.
    #[must_use]
    pub fn on_logout_ack(self) -> Session<Disconnected> {
        self.transition(Disconnected)
    }

    /// Transitions to Disconnected on timeout.
    #[must_use]
    pub fn on_timeout(self) -> Session<Disconnected> {
        self.transition(Disconnected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_state_transitions() {
        let session = Session::<Disconnected>::new("TEST");
        assert_eq!(session.session_id(), "TEST");

        let session = session.connect();
        let session = session.send_logon();
        let session = session.on_logon_ack();

        // Now in Active state
        let session = session.initiate_logout();
        let _session = session.on_logout_ack();
    }

    #[test]
    fn test_acceptor_flow() {
        let session = Session::<Disconnected>::new("ACCEPTOR");
        let session = session.accept();
        let session = session.on_logon_received();
        let session = session.accept_logon();

        // Now in Active state
        let session = session.initiate_logout();
        let _session = session.on_logout_ack();
    }

    #[test]
    fn test_acceptor_reject_flow() {
        let session = Session::<Disconnected>::new("ACCEPTOR");
        let session = session.accept();
        let session = session.on_logon_received();
        let _session = session.reject_logon();
    }

    #[test]
    fn test_acceptor_timeout_flow() {
        let session = Session::<Disconnected>::new("ACCEPTOR");
        let session = session.accept();
        let session = session.on_logon_received();
        let _session = session.on_timeout();
    }

    #[test]
    fn test_resend_flow() {
        let session = Session::<Disconnected>::new("TEST");
        let session = session.connect();
        let session = session.send_logon();
        let session = session.on_logon_ack();

        let session = session.start_resend(1, 5);
        let _session = session.resend_complete();
    }

    // --- States carry their data --------------------------------------------

    #[test]
    fn test_send_logon_records_the_send_instant() {
        let before = Instant::now();
        let session = Session::<Disconnected>::new("TEST").connect().send_logon();
        let after = Instant::now();

        assert!(session.sent_at() >= before);
        assert!(session.sent_at() <= after);
        assert_eq!(session.state().sent_at, session.sent_at());
    }

    #[test]
    fn test_on_logon_received_records_the_arrival_instant() {
        let before = Instant::now();
        let session = Session::<Disconnected>::new("ACCEPTOR")
            .accept()
            .on_logon_received();
        let after = Instant::now();

        assert!(session.received_at() >= before);
        assert!(session.received_at() <= after);
    }

    #[test]
    fn test_initiate_logout_records_the_send_instant() {
        let before = Instant::now();
        let session = Session::<Disconnected>::new("TEST")
            .connect()
            .send_logon()
            .on_logon_ack()
            .initiate_logout();
        let after = Instant::now();

        assert!(session.sent_at() >= before);
        assert!(session.sent_at() <= after);
    }

    #[test]
    fn test_start_resend_keeps_the_requested_range() {
        let session = Session::<Disconnected>::new("TEST")
            .connect()
            .send_logon()
            .on_logon_ack()
            .start_resend(7, 16);

        assert_eq!(session.begin_seq(), 7);
        assert_eq!(session.end_seq(), 16);
        assert_eq!(session.state().begin_seq, 7);
    }

    #[test]
    fn test_start_resend_keeps_the_open_ended_range() {
        // EndSeqNo (16) = 0 is the FIX "through the last message" convention
        // and must survive the transition unchanged.
        let session = Session::<Disconnected>::new("TEST")
            .connect()
            .send_logon()
            .on_logon_ack()
            .start_resend(42, 0);

        assert_eq!(session.begin_seq(), 42);
        assert_eq!(session.end_seq(), 0);
    }

    #[test]
    fn test_session_id_survives_every_transition() {
        let session = Session::<Disconnected>::new("PERSISTENT")
            .connect()
            .send_logon()
            .on_logon_ack();
        assert_eq!(session.session_id(), "PERSISTENT");

        let session = session.start_resend(1, 2).resend_complete();
        assert_eq!(session.session_id(), "PERSISTENT");

        let session = session.initiate_logout();
        assert_eq!(session.session_id(), "PERSISTENT");

        let session = session.on_logout_ack();
        assert_eq!(session.session_id(), "PERSISTENT");
    }

    #[test]
    fn test_stateless_states_stay_zero_sized() {
        use std::mem::size_of;

        assert_eq!(size_of::<Disconnected>(), 0);
        assert_eq!(size_of::<Connecting>(), 0);
        assert_eq!(size_of::<Active>(), 0);
        assert_eq!(size_of::<Session<Active>>(), size_of::<String>());
    }
}
