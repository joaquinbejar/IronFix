/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! Sans-IO core, stage 6b: the phase of a live session.
//!
//! Once the Logon exchange is done a session is in one of three phases:
//! established, logging out with its own Logout (5) not yet written whole,
//! or logging out with that Logout sent and its acknowledgement awaited.
//! [`SessionPhase`] wraps the typestate [`Session`] of each, so a driver can
//! hold the phase in one value and still move it only through the consuming
//! typestate transitions: no transition here can produce a state the
//! typestate does not allow.
//!
//! Like the rest of the core it performs no I/O and reads no clock: the one
//! transition that timestamps ([`SessionPhase::advance_logout`]) takes `now`
//! from the driver.

use std::time::Instant;

use crate::logout::{LogoutPhase, decide_logout_advance};
use crate::state::{Active, Disconnected, LogoutPending, Session};

/// The phase of a live session, wrapping its typestate.
///
/// Every variant carries the typestate session by value, so moving between
/// phases consumes it: a driver hands the phase to a handler and gets the
/// next one back, or a close.
#[derive(Debug)]
pub enum SessionPhase {
    /// The session is established.
    Active(Session<Active>),
    /// This session's own Logout is in the driver's output and has not all
    /// been written yet. The session already behaves as one logging out (no
    /// new application message, an inbound Logout completes the exchange),
    /// but the logout timeout has not started: the Logout has not been sent.
    /// Once its last byte is written the phase moves to
    /// [`SessionPhase::LogoutPending`] ([`SessionPhase::advance_logout`]).
    LogoutQueued(Session<Active>),
    /// This session's own Logout has been sent and is awaiting
    /// acknowledgement, within the logout timeout from
    /// [`Session::sent_at`](crate::state::Session::sent_at).
    LogoutPending(Session<LogoutPending>),
}

impl SessionPhase {
    /// The phase as the core's Logout decisions read it.
    #[must_use]
    pub const fn logout_phase(&self) -> LogoutPhase {
        match self {
            Self::Active(_) => LogoutPhase::Active,
            Self::LogoutQueued(_) => LogoutPhase::Queued,
            Self::LogoutPending(_) => LogoutPhase::Pending,
        }
    }

    /// Whether the session is established, with no Logout of its own fed.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Active(_))
    }

    /// Moves a session whose Logout has now been written whole from
    /// [`SessionPhase::LogoutQueued`] to [`SessionPhase::LogoutPending`],
    /// recording `now` as the moment the Logout was sent; the logout timeout
    /// runs from it. Any other phase is handed back as it is.
    ///
    /// `take_written` reports, and consumes, whether the Logout's last byte
    /// was written; it is asked only in the queued phase
    /// ([`decide_logout_advance`]).
    #[must_use]
    pub fn advance_logout(self, take_written: impl FnOnce() -> bool, now: Instant) -> Self {
        let advance = decide_logout_advance(self.logout_phase(), take_written);
        match self {
            // Typestate: Active -> LogoutPending, as the Logout is sent.
            Self::LogoutQueued(session) if advance => {
                Self::LogoutPending(session.initiate_logout(now))
            }
            phase => phase,
        }
    }

    /// Ends the session abnormally, driving its typestate to Disconnected:
    /// a disconnect from an established or queued phase, a timeout from a
    /// pending Logout.
    pub fn teardown(self) -> Session<Disconnected> {
        match self {
            Self::Active(session) | Self::LogoutQueued(session) => session.disconnect(),
            Self::LogoutPending(session) => session.on_timeout(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn active() -> Session<Active> {
        Session::new("S")
            .connect()
            .send_logon(Instant::now())
            .on_logon_ack()
    }

    #[test]
    fn test_logout_phase_of_each_variant() {
        let now = Instant::now();
        assert_eq!(
            SessionPhase::Active(active()).logout_phase(),
            LogoutPhase::Active
        );
        assert_eq!(
            SessionPhase::LogoutQueued(active()).logout_phase(),
            LogoutPhase::Queued
        );
        assert_eq!(
            SessionPhase::LogoutPending(active().initiate_logout(now)).logout_phase(),
            LogoutPhase::Pending
        );
        assert!(SessionPhase::Active(active()).is_active());
        assert!(!SessionPhase::LogoutQueued(active()).is_active());
    }

    #[test]
    fn test_queued_logout_advances_only_once_written() {
        let now = Instant::now();
        let phase = SessionPhase::LogoutQueued(active()).advance_logout(|| false, now);
        assert!(matches!(phase, SessionPhase::LogoutQueued(_)));
        let later = now + Duration::from_secs(1);
        let phase = phase.advance_logout(|| true, later);
        match phase {
            SessionPhase::LogoutPending(session) => assert_eq!(session.sent_at(), later),
            other => panic!("expected LogoutPending, got {other:?}"),
        }
    }

    #[test]
    fn test_advance_leaves_other_phases_and_never_asks() {
        let now = Instant::now();
        let asked = |phase: SessionPhase| {
            let mut called = false;
            let next = phase.advance_logout(
                || {
                    called = true;
                    true
                },
                now,
            );
            (next.logout_phase(), called)
        };
        assert_eq!(
            asked(SessionPhase::Active(active())),
            (LogoutPhase::Active, false)
        );
        assert_eq!(
            asked(SessionPhase::LogoutPending(active().initiate_logout(now))),
            (LogoutPhase::Pending, false)
        );
    }

    #[test]
    fn test_teardown_reaches_disconnected_from_every_phase() {
        let now = Instant::now();
        for phase in [
            SessionPhase::Active(active()),
            SessionPhase::LogoutQueued(active()),
            SessionPhase::LogoutPending(active().initiate_logout(now)),
        ] {
            let session = phase.teardown();
            assert_eq!(session.session_id(), "S");
        }
    }
}
