/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! Sans-IO session core: the protocol decisions a driver acts on.
//!
//! ADR-0002 (option 2) moves the decisions the Tokio reactor in
//! `ironfix-engine` makes into a core that performs no I/O, reads no clock
//! and never awaits. A driver feeds it what it observed (the time, the state
//! of its output) and gets back what to do; the driver then encodes the
//! intent, writes it and runs the callbacks. The Tokio reactor is one such
//! driver. Issue #91 builds the core in stages, one handler family at a time.
//!
//! # Where it lives
//!
//! The core is a module of `ironfix-session`, not a new crate: it needs
//! nothing but `ironfix-core` and the session's own state, and the session
//! crate already is the "pure protocol logic, no I/O" layer. Because this
//! crate must not depend on `ironfix-tagvalue`, the core decides *what* to
//! send (an [`LivenessAction`]) and the driver builds and encodes the frame.
//!
//! # Stage 1: heartbeat, TestRequest and the logout deadline
//!
//! This stage extracts the liveness family, the periodic checks a driver runs
//! on every tick:
//!
//! - [`decide_liveness`]: whether the session has timed out waiting for the
//!   counterparty, owes a TestRequest (1) after inbound silence, or owes an
//!   idle Heartbeat (0), given what the driver's output looks like
//!   ([`LivenessGate`]).
//! - [`logout_timed_out`]: whether a Logout the session sent has waited past
//!   the logout timeout for its acknowledgement.
//! - [`test_request_reply_id`]: the `TestReqID` (112) a Heartbeat answering a
//!   TestRequest echoes.
//!
//! Sequence validation and gap recovery, resend replay, the Logout handshake
//! and the two Logon handshakes are still decided inside the engine's
//! reactor; they move here in later stages.
//!
//! # Time
//!
//! Every function takes `now` from the driver (ADR-0002, "Time source
//! contract"). The Tokio driver passes its own clock, converted at the
//! boundary, so a paused-clock test drives these decisions deterministically.

use crate::heartbeat::HeartbeatManager;
use crate::state::{LogoutPending, Session};
use std::time::{Duration, Instant};

/// What the driver's output allows a liveness check to add to it.
///
/// The core does not see the driver's write buffer; the driver summarises it
/// here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessGate {
    /// Only the deadline may be checked; nothing new is written. A driver
    /// uses this while a resend it owes is under way (resent frames are
    /// traffic, so no probe is due) and while its output is saturated (a
    /// stream that never completes a write must stop making progress, so the
    /// write timeout can close the session).
    DeadlinesOnly,
    /// A probe may be written if one is due.
    Probe {
        /// A TestRequest has been handed to the output and not yet written
        /// whole. Its reply deadline has not started, and no second one is
        /// sent meanwhile.
        test_request_unwritten: bool,
        /// Output is waiting to be written. That output is traffic the
        /// counterparty is about to receive, so an idle Heartbeat is not due.
        output_waiting: bool,
    },
}

/// What a liveness check tells the driver to do.
///
/// Deliberately not `#[non_exhaustive]`: a driver matches every action, so a
/// new one is a compile error in each driver rather than an arm that silently
/// does nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessAction {
    /// Nothing is due.
    Idle,
    /// A TestRequest went unanswered past its deadline: the session ends with
    /// a heartbeat timeout.
    CloseHeartbeatTimeout,
    /// Inbound has been silent past the heartbeat interval plus the grace:
    /// send a TestRequest (1). The driver generates the `TestReqID` (112) and
    /// starts its reply deadline once the frame is written whole
    /// ([`HeartbeatManager::on_test_request_sent`]).
    SendTestRequest,
    /// Nothing has been sent for the heartbeat interval: send a Heartbeat (0)
    /// without a `TestReqID`.
    SendHeartbeat,
}

/// Decides the periodic liveness step at `now`.
///
/// The timeout is checked first and wins over everything else. Under
/// [`LivenessGate::Probe`], a due TestRequest is sent unless one is already
/// waiting to be written; when no TestRequest is sent, a due Heartbeat is
/// sent unless output is already waiting. With `HeartBtInt` (108) = 0 the
/// manager reports nothing due, so this returns [`LivenessAction::Idle`].
#[must_use]
pub fn decide_liveness(
    heartbeat: &HeartbeatManager,
    now: Instant,
    gate: LivenessGate,
) -> LivenessAction {
    if heartbeat.is_timed_out(now) {
        return LivenessAction::CloseHeartbeatTimeout;
    }
    match gate {
        LivenessGate::DeadlinesOnly => LivenessAction::Idle,
        LivenessGate::Probe {
            test_request_unwritten,
            output_waiting,
        } => {
            if heartbeat.should_send_test_request(now) && !test_request_unwritten {
                LivenessAction::SendTestRequest
            } else if heartbeat.should_send_heartbeat(now) && !output_waiting {
                LivenessAction::SendHeartbeat
            } else {
                LivenessAction::Idle
            }
        }
    }
}

/// Whether the Logout `session` sent has waited at least `logout_timeout`
/// for the counterparty's Logout by `now`.
///
/// The deadline runs from [`Session::sent_at`], the instant the Logout was
/// written whole. A `now` earlier than that instant counts as no time
/// elapsed.
#[must_use]
pub fn logout_timed_out(
    session: &Session<LogoutPending>,
    now: Instant,
    logout_timeout: Duration,
) -> bool {
    let waited = now
        .checked_duration_since(session.sent_at())
        .unwrap_or(Duration::ZERO);
    waited >= logout_timeout
}

/// The `TestReqID` (112) a Heartbeat answering a TestRequest echoes, from the
/// TestRequest's own 112.
///
/// A `112=` with no value is a malformed TestRequest: there is nothing to
/// echo, and an empty field has no legal wire form, so the Heartbeat goes
/// without a `TestReqID` rather than the session ending over the peer's
/// mistake.
#[must_use]
pub fn test_request_reply_id(test_req_id: Option<&str>) -> Option<&str> {
    test_req_id.filter(|id| !id.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heartbeat::HeartbeatManager;

    const INTERVAL: Duration = Duration::from_secs(30);

    fn probe(test_request_unwritten: bool, output_waiting: bool) -> LivenessGate {
        LivenessGate::Probe {
            test_request_unwritten,
            output_waiting,
        }
    }

    /// A manager whose last send and receive were both at `t0`.
    fn manager(t0: Instant) -> HeartbeatManager {
        HeartbeatManager::new(INTERVAL, t0)
    }

    /// A manager with a TestRequest sent at `t0 + INTERVAL + grace` after
    /// inbound silence, so its reply deadline runs from there.
    fn probing(t0: Instant) -> (HeartbeatManager, Instant) {
        let mut hb = manager(t0);
        let sent = t0 + INTERVAL + hb.test_request_grace();
        hb.on_test_request_sent("TR1".to_owned(), sent);
        (hb, sent)
    }

    #[test]
    fn test_nothing_is_due_right_after_traffic() {
        let t0 = Instant::now();
        let hb = manager(t0);
        assert_eq!(
            decide_liveness(&hb, t0, probe(false, false)),
            LivenessAction::Idle
        );
    }

    #[test]
    fn test_heartbeat_is_due_after_an_idle_interval() {
        let t0 = Instant::now();
        let mut hb = manager(t0);
        // Inbound kept arriving, so only the send side is idle.
        hb.on_message_received(false, None, t0 + INTERVAL);
        assert_eq!(
            decide_liveness(&hb, t0 + INTERVAL, probe(false, false)),
            LivenessAction::SendHeartbeat
        );
    }

    #[test]
    fn test_heartbeat_waits_while_output_is_waiting() {
        let t0 = Instant::now();
        let mut hb = manager(t0);
        hb.on_message_received(false, None, t0 + INTERVAL);
        assert_eq!(
            decide_liveness(&hb, t0 + INTERVAL, probe(false, true)),
            LivenessAction::Idle
        );
    }

    #[test]
    fn test_test_request_is_due_after_inbound_silence_and_grace() {
        let t0 = Instant::now();
        let hb = manager(t0);
        let at = t0 + INTERVAL + hb.test_request_grace();
        assert_eq!(
            decide_liveness(&hb, at, probe(false, false)),
            LivenessAction::SendTestRequest
        );
        // Before the grace has run, the silence alone only makes a
        // Heartbeat due (nothing was sent either).
        assert_eq!(
            decide_liveness(&hb, t0 + INTERVAL, probe(false, false)),
            LivenessAction::SendHeartbeat
        );
    }

    #[test]
    fn test_unwritten_test_request_falls_back_to_the_heartbeat_check() {
        let t0 = Instant::now();
        let hb = manager(t0);
        let at = t0 + INTERVAL + hb.test_request_grace();
        assert_eq!(
            decide_liveness(&hb, at, probe(true, false)),
            LivenessAction::SendHeartbeat
        );
        assert_eq!(
            decide_liveness(&hb, at, probe(true, true)),
            LivenessAction::Idle
        );
    }

    #[test]
    fn test_unanswered_test_request_times_out_under_every_gate() {
        let t0 = Instant::now();
        let (hb, sent) = probing(t0);
        let late = sent + INTERVAL;
        assert!(hb.is_timed_out(late));
        for gate in [
            LivenessGate::DeadlinesOnly,
            probe(false, false),
            probe(true, true),
        ] {
            assert_eq!(
                decide_liveness(&hb, late, gate),
                LivenessAction::CloseHeartbeatTimeout
            );
        }
    }

    #[test]
    fn test_answered_test_request_does_not_time_out() {
        let t0 = Instant::now();
        let (mut hb, sent) = probing(t0);
        hb.on_message_received(true, Some("TR1"), sent + Duration::from_secs(1));
        assert_ne!(
            decide_liveness(&hb, sent + INTERVAL, LivenessGate::DeadlinesOnly),
            LivenessAction::CloseHeartbeatTimeout
        );
    }

    #[test]
    fn test_deadlines_only_never_probes() {
        let t0 = Instant::now();
        let hb = manager(t0);
        let at = t0 + INTERVAL + hb.test_request_grace();
        assert_eq!(
            decide_liveness(&hb, at, LivenessGate::DeadlinesOnly),
            LivenessAction::Idle
        );
    }

    #[test]
    fn test_zero_interval_never_acts() {
        let t0 = Instant::now();
        let hb = HeartbeatManager::new(Duration::ZERO, t0);
        let later = t0 + Duration::from_secs(3600);
        assert_eq!(
            decide_liveness(&hb, later, probe(false, false)),
            LivenessAction::Idle
        );
    }

    #[test]
    fn test_logout_timeout_runs_from_sent_at() {
        let t0 = Instant::now();
        let timeout = Duration::from_secs(10);
        let session = Session::new("S")
            .connect()
            .send_logon(t0)
            .on_logon_ack()
            .initiate_logout(t0);
        assert!(!logout_timed_out(
            &session,
            t0 + Duration::from_secs(9),
            timeout
        ));
        assert!(logout_timed_out(&session, t0 + timeout, timeout));
        assert!(logout_timed_out(
            &session,
            t0 + Duration::from_secs(11),
            timeout
        ));
    }

    #[test]
    fn test_logout_timeout_treats_an_earlier_now_as_no_time_elapsed() {
        let t0 = Instant::now();
        let sent = t0 + Duration::from_secs(5);
        let session = Session::new("S")
            .connect()
            .send_logon(t0)
            .on_logon_ack()
            .initiate_logout(sent);
        assert!(!logout_timed_out(&session, t0, Duration::from_secs(1)));
        assert!(logout_timed_out(&session, t0, Duration::ZERO));
    }

    #[test]
    fn test_test_request_reply_echoes_a_non_empty_id() {
        assert_eq!(test_request_reply_id(Some("ABC")), Some("ABC"));
        assert_eq!(test_request_reply_id(Some("")), None);
        assert_eq!(test_request_reply_id(None), None);
    }
}
