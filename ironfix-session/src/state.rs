/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! Session state machine using the typestate pattern.
//!
//! This module implements a compile-time checked state machine for FIX sessions.
//! State transitions are enforced by the type system, preventing invalid operations.

use std::marker::PhantomData;
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
#[derive(Debug, Clone)]
pub struct LogonSent {
    /// Time when Logon was sent.
    pub sent_at: Instant,
}

impl private::Sealed for LogonSent {}
impl SessionState for LogonSent {}

/// LogonReceived state - Logon received from counterparty (acceptor side),
/// pending authentication.
#[derive(Debug, Clone)]
pub struct LogonReceived {
    /// Time when the Logon was received.
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
#[derive(Debug, Clone)]
pub struct Resending {
    /// Begin sequence number of the gap.
    pub begin_seq: u64,
    /// End sequence number of the gap.
    pub end_seq: u64,
}

impl private::Sealed for Resending {}
impl SessionState for Resending {}

/// LogoutPending state - Logout sent, awaiting confirmation.
#[derive(Debug, Clone)]
pub struct LogoutPending {
    /// Time when Logout was sent.
    pub sent_at: Instant,
}

impl private::Sealed for LogoutPending {}
impl SessionState for LogoutPending {}

/// Session wrapper with typestate for compile-time state checking.
///
/// The type parameter `S` represents the current session state.
#[derive(Debug)]
pub struct Session<S: SessionState> {
    /// Session identifier.
    pub session_id: String,
    /// Phantom data for the state type.
    _state: PhantomData<S>,
}

impl<S: SessionState> Session<S> {
    /// Returns the session identifier.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
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
            _state: PhantomData,
        }
    }

    /// Transitions to the Connecting state (initiator side).
    #[must_use]
    pub fn connect(self) -> Session<Connecting> {
        Session {
            session_id: self.session_id,
            _state: PhantomData,
        }
    }

    /// Transitions to the Connecting state after accepting an inbound
    /// TCP connection (acceptor side).
    #[must_use]
    pub fn accept(self) -> Session<Connecting> {
        Session {
            session_id: self.session_id,
            _state: PhantomData,
        }
    }
}

impl Session<Connecting> {
    /// Transitions to the LogonSent state after sending Logon (initiator side).
    #[must_use]
    pub fn send_logon(self) -> Session<LogonSent> {
        Session {
            session_id: self.session_id,
            _state: PhantomData,
        }
    }

    /// Transitions to the LogonReceived state when a Logon arrives from
    /// the counterparty (acceptor side).
    #[must_use]
    pub fn on_logon_received(self) -> Session<LogonReceived> {
        Session {
            session_id: self.session_id,
            _state: PhantomData,
        }
    }

    /// Transitions back to Disconnected on connection failure.
    #[must_use]
    pub fn disconnect(self) -> Session<Disconnected> {
        Session {
            session_id: self.session_id,
            _state: PhantomData,
        }
    }
}

impl Session<LogonSent> {
    /// Transitions to Active state on successful Logon acknowledgement.
    #[must_use]
    pub fn on_logon_ack(self) -> Session<Active> {
        Session {
            session_id: self.session_id,
            _state: PhantomData,
        }
    }

    /// Transitions to Disconnected on Logon rejection or timeout.
    #[must_use]
    pub fn on_logon_reject(self) -> Session<Disconnected> {
        Session {
            session_id: self.session_id,
            _state: PhantomData,
        }
    }
}

impl Session<LogonReceived> {
    /// Transitions to Active after successful authentication, once the
    /// Logon acknowledgement has been sent back to the counterparty.
    #[must_use]
    pub fn accept_logon(self) -> Session<Active> {
        Session {
            session_id: self.session_id,
            _state: PhantomData,
        }
    }

    /// Transitions to Disconnected when authentication fails and the
    /// Logon is rejected (Logout/Reject sent, connection dropped).
    #[must_use]
    pub fn reject_logon(self) -> Session<Disconnected> {
        Session {
            session_id: self.session_id,
            _state: PhantomData,
        }
    }

    /// Transitions to Disconnected when authentication does not complete
    /// within the allowed time.
    #[must_use]
    pub fn on_timeout(self) -> Session<Disconnected> {
        Session {
            session_id: self.session_id,
            _state: PhantomData,
        }
    }
}

impl Session<Active> {
    /// Transitions to Resending state when a gap is detected.
    ///
    /// # Arguments
    /// * `begin_seq` - Begin sequence number of the gap
    /// * `end_seq` - End sequence number of the gap
    #[must_use]
    pub fn start_resend(self, _begin_seq: u64, _end_seq: u64) -> Session<Resending> {
        Session {
            session_id: self.session_id,
            _state: PhantomData,
        }
    }

    /// Transitions to LogoutPending state.
    #[must_use]
    pub fn initiate_logout(self) -> Session<LogoutPending> {
        Session {
            session_id: self.session_id,
            _state: PhantomData,
        }
    }

    /// Transitions to Disconnected on unexpected disconnect.
    #[must_use]
    pub fn disconnect(self) -> Session<Disconnected> {
        Session {
            session_id: self.session_id,
            _state: PhantomData,
        }
    }
}

impl Session<Resending> {
    /// Transitions back to Active when resend is complete.
    #[must_use]
    pub fn resend_complete(self) -> Session<Active> {
        Session {
            session_id: self.session_id,
            _state: PhantomData,
        }
    }

    /// Transitions to Disconnected on error.
    #[must_use]
    pub fn disconnect(self) -> Session<Disconnected> {
        Session {
            session_id: self.session_id,
            _state: PhantomData,
        }
    }
}

impl Session<LogoutPending> {
    /// Transitions to Disconnected on Logout acknowledgement or timeout.
    #[must_use]
    pub fn on_logout_ack(self) -> Session<Disconnected> {
        Session {
            session_id: self.session_id,
            _state: PhantomData,
        }
    }

    /// Transitions to Disconnected on timeout.
    #[must_use]
    pub fn on_timeout(self) -> Session<Disconnected> {
        Session {
            session_id: self.session_id,
            _state: PhantomData,
        }
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
}
