/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! Heartbeat and TestRequest management.
//!
//! This module handles FIX session heartbeat logic including:
//! - Sending heartbeats at configured intervals
//! - Sending TestRequest when no messages received
//! - Detecting heartbeat timeouts
//!
//! # `HeartBtInt` (108) = 0
//!
//! Zero is a legal `HeartBtInt` and means *do not heartbeat*: neither side
//! emits Heartbeats, neither side probes with a TestRequest, and there is
//! therefore no heartbeat-driven liveness check at all. A
//! [`HeartbeatManager`] built with [`Duration::ZERO`] reports `false` from
//! [`HeartbeatManager::should_send_heartbeat`],
//! [`HeartbeatManager::should_send_test_request`] and
//! [`HeartbeatManager::is_timed_out`] for the life of the session.
//!
//! # Liveness after a TestRequest
//!
//! `doc/fix_operations.md` ("Test Request") says only "if no response,
//! consider session disconnected" and does not define what counts as a
//! response. IronFix defines it here: **any inbound message the session
//! accepts stops the countdown**, and a Heartbeat echoing the outstanding
//! `TestReqID` (112) is the positive confirmation, reported as
//! [`TestRequestOutcome::Confirmed`]. Traffic that is not that Heartbeat
//! clears the pending request as [`TestRequestOutcome::SupersededByTraffic`].
//! A peer that is sending us messages is alive whether or not it echoed our
//! `TestReqID`, and several real venues answer a TestRequest with a Heartbeat
//! that omits tag 112 or let it be reordered behind application traffic.
//! This matches the QuickFIX family, which resets its test-request counter on
//! any successfully verified inbound message.

use std::time::{Duration, Instant};

/// Largest counterparty-confirmed `HeartBtInt` (108) this engine will honour,
/// in seconds (one hour).
///
/// `HeartBtInt` is counterparty-controlled, and it drives every liveness timer
/// in the session. An unbounded value disables dead-peer detection outright,
/// so a confirmed interval above this ceiling is refused rather than adopted.
/// See [`negotiate_interval`].
pub const MAX_HEARTBEAT_INTERVAL_SECS: u64 = 3600;

/// Fraction of the heartbeat interval allowed as transmission grace before a
/// TestRequest is due: the grace is `interval / TEST_REQUEST_GRACE_DIVISOR`.
///
/// Five gives the 20% allowance the QuickFIX family uses (`1.2 * HeartBtInt`
/// of inbound silence before probing).
const TEST_REQUEST_GRACE_DIVISOR: u32 = 5;

/// Floor for the TestRequest grace period.
///
/// The proportional allowance collapses to almost nothing for sub-second
/// intervals, where ordinary scheduling jitter is already comparable to the
/// interval itself. 250 ms is long enough to absorb a scheduler hiccup and
/// short enough that it never dominates a realistic `HeartBtInt`.
const MIN_TEST_REQUEST_GRACE: Duration = Duration::from_millis(250);

/// A counterparty-confirmed `HeartBtInt` (108) this engine refuses to adopt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("counterparty HeartBtInt (108) of {secs}s exceeds the maximum supported {max}s")]
pub struct HeartbeatIntervalError {
    /// The interval the counterparty confirmed, in seconds.
    pub secs: u64,
    /// The largest interval this engine honours, in seconds.
    pub max: u64,
}

/// Effect an inbound message had on an outstanding TestRequest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestRequestOutcome {
    /// No TestRequest was outstanding.
    NonePending,
    /// A Heartbeat echoed the outstanding `TestReqID` (112): the counterparty
    /// answered the probe exactly as asked.
    Confirmed,
    /// Other inbound traffic arrived while a TestRequest was outstanding. The
    /// countdown stops — the peer is demonstrably alive — but this is not the
    /// Heartbeat the TestRequest asked for.
    SupersededByTraffic,
}

/// Resolves the heartbeat interval for a session from the interval this side
/// requested and the `HeartBtInt` (108) the counterparty confirmed.
///
/// FIX expects the acceptor to echo the requested value; when it does not, the
/// confirmed value wins (`doc/fix_operations.md`, "Logon"). Because that value
/// is counterparty-controlled it is bounded: anything above
/// [`MAX_HEARTBEAT_INTERVAL_SECS`] is refused, since adopting it would disable
/// dead-peer detection for as long as the peer chose. A confirmed value that is
/// exactly what this side requested is always accepted — a peer echoing our own
/// configuration back is not the counterparty pushing us anywhere.
///
/// `0` is accepted at any time and means "do not heartbeat"; see the module
/// documentation.
///
/// # Arguments
/// * `requested` - The interval this side asked for in its Logon
/// * `confirmed_secs` - The `HeartBtInt` (108) on the counterparty's Logon
///
/// # Errors
/// Returns [`HeartbeatIntervalError`] when `confirmed_secs` exceeds
/// [`MAX_HEARTBEAT_INTERVAL_SECS`] and is not the requested interval.
pub fn negotiate_interval(
    requested: Duration,
    confirmed_secs: u64,
) -> Result<Duration, HeartbeatIntervalError> {
    let confirmed = Duration::from_secs(confirmed_secs);
    if confirmed == requested {
        return Ok(confirmed);
    }
    if confirmed_secs > MAX_HEARTBEAT_INTERVAL_SECS {
        return Err(HeartbeatIntervalError {
            secs: confirmed_secs,
            max: MAX_HEARTBEAT_INTERVAL_SECS,
        });
    }
    Ok(confirmed)
}

/// Transmission grace allowed on top of the interval before a TestRequest is
/// due.
///
/// Proportional to the interval, floored at [`MIN_TEST_REQUEST_GRACE`]. A
/// disabled interval has no grace because it has no TestRequest.
fn grace_for(interval: Duration) -> Duration {
    if interval.is_zero() {
        return Duration::ZERO;
    }
    (interval / TEST_REQUEST_GRACE_DIVISOR).max(MIN_TEST_REQUEST_GRACE)
}

/// Manages heartbeat timing for a FIX session.
#[derive(Debug)]
pub struct HeartbeatManager {
    /// Heartbeat interval. [`Duration::ZERO`] disables heartbeating entirely.
    interval: Duration,
    /// Transmission grace added to the interval before a TestRequest is due.
    grace: Duration,
    /// Time of last message sent.
    last_sent: Instant,
    /// Time of last message received.
    last_received: Instant,
    /// Pending TestRequest ID, if any.
    test_request_pending: Option<String>,
    /// Time when TestRequest was sent.
    test_request_sent_at: Option<Instant>,
}

impl HeartbeatManager {
    /// Creates a new heartbeat manager with the specified interval.
    ///
    /// [`Duration::ZERO`] is the legal `HeartBtInt` = 0 case and disables
    /// heartbeats, TestRequests and the heartbeat timeout; see the module
    /// documentation.
    ///
    /// # Arguments
    /// * `interval` - The heartbeat interval
    #[must_use]
    pub fn new(interval: Duration) -> Self {
        let now = Instant::now();
        Self {
            interval,
            grace: grace_for(interval),
            last_sent: now,
            last_received: now,
            test_request_pending: None,
            test_request_sent_at: None,
        }
    }

    /// Returns whether heartbeating is enabled, i.e. `HeartBtInt` is not 0.
    ///
    /// When this is `false` every timing predicate on this manager is `false`.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        !self.interval.is_zero()
    }

    /// Records that a message was sent.
    #[inline]
    pub fn on_message_sent(&mut self) {
        self.last_sent = Instant::now();
    }

    /// Records that a message was received.
    ///
    /// Any inbound message clears an outstanding TestRequest: the counterparty
    /// is demonstrably alive, so the timeout countdown stops. The returned
    /// [`TestRequestOutcome`] distinguishes the Heartbeat that actually echoed
    /// the `TestReqID` from other traffic that merely superseded it. See the
    /// module documentation for why the rule is this broad.
    ///
    /// # Arguments
    /// * `is_heartbeat` - Whether the received message is a Heartbeat
    /// * `test_req_id` - The `TestReqID` (112) on the message, if present
    pub fn on_message_received(
        &mut self,
        is_heartbeat: bool,
        test_req_id: Option<&str>,
    ) -> TestRequestOutcome {
        self.last_received = Instant::now();

        let Some(pending) = self.test_request_pending.take() else {
            return TestRequestOutcome::NonePending;
        };
        self.test_request_sent_at = None;

        if is_heartbeat && test_req_id == Some(pending.as_str()) {
            TestRequestOutcome::Confirmed
        } else {
            TestRequestOutcome::SupersededByTraffic
        }
    }

    /// Checks if a heartbeat should be sent.
    ///
    /// A heartbeat should be sent if no message has been sent within the
    /// interval. Always `false` when `HeartBtInt` is 0.
    #[must_use]
    pub fn should_send_heartbeat(&self) -> bool {
        self.is_enabled() && self.last_sent.elapsed() >= self.interval
    }

    /// Checks if a TestRequest should be sent.
    ///
    /// A TestRequest should be sent if no message has been received within the
    /// interval plus [`HeartbeatManager::test_request_grace`], and no
    /// TestRequest is already pending. Always `false` when `HeartBtInt` is 0.
    #[must_use]
    pub fn should_send_test_request(&self) -> bool {
        if !self.is_enabled() || self.test_request_pending.is_some() {
            return false;
        }
        // An interval so large that adding the grace overflows can never come
        // due; report that rather than panicking on the addition.
        match self.interval.checked_add(self.grace) {
            Some(due_after) => self.last_received.elapsed() >= due_after,
            None => false,
        }
    }

    /// Checks if the session has timed out.
    ///
    /// A timeout occurs only if a TestRequest was sent and **nothing at all**
    /// has been received since, for one full interval — any inbound message
    /// clears the pending request (see
    /// [`HeartbeatManager::on_message_received`]). Always `false` when
    /// `HeartBtInt` is 0.
    #[must_use]
    pub fn is_timed_out(&self) -> bool {
        if !self.is_enabled() {
            return false;
        }
        match self.test_request_sent_at {
            Some(sent_at) => sent_at.elapsed() >= self.interval,
            None => false,
        }
    }

    /// Records that a TestRequest was sent.
    ///
    /// # Arguments
    /// * `test_req_id` - The `TestReqID` that was sent
    pub fn on_test_request_sent(&mut self, test_req_id: String) {
        self.test_request_pending = Some(test_req_id);
        self.test_request_sent_at = Some(Instant::now());
        self.last_sent = Instant::now();
    }

    /// Returns the pending TestRequest ID, if any.
    #[must_use]
    pub fn pending_test_request(&self) -> Option<&str> {
        self.test_request_pending.as_deref()
    }

    /// Returns the time since the last message was received.
    #[must_use]
    pub fn time_since_last_received(&self) -> Duration {
        self.last_received.elapsed()
    }

    /// Returns the time since the last message was sent.
    #[must_use]
    pub fn time_since_last_sent(&self) -> Duration {
        self.last_sent.elapsed()
    }

    /// Returns the heartbeat interval.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }

    /// Returns the transmission grace added to the interval before a
    /// TestRequest becomes due.
    ///
    /// Derived from the interval, not configured: 20% of it, floored at
    /// 250 ms. Zero when `HeartBtInt` is 0.
    #[must_use]
    pub const fn test_request_grace(&self) -> Duration {
        self.grace
    }

    /// Resets the manager state.
    ///
    /// The interval and its derived grace are session configuration and are
    /// kept; only the timers and the pending TestRequest are cleared.
    pub fn reset(&mut self) {
        let now = Instant::now();
        self.last_sent = now;
        self.last_received = now;
        self.test_request_pending = None;
        self.test_request_sent_at = None;
    }
}

/// Generates a unique TestReqID.
///
/// Uses the current timestamp in nanoseconds.
#[must_use]
pub fn generate_test_req_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    format!("TEST{}", nanos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_heartbeat_manager_new() {
        let mgr = HeartbeatManager::new(Duration::from_secs(30));
        assert_eq!(mgr.interval(), Duration::from_secs(30));
        assert!(mgr.pending_test_request().is_none());
        assert!(mgr.is_enabled());
    }

    #[test]
    fn test_should_send_heartbeat() {
        let mgr = HeartbeatManager::new(Duration::from_millis(10));
        assert!(!mgr.should_send_heartbeat());

        sleep(Duration::from_millis(15));
        assert!(mgr.should_send_heartbeat());
    }

    #[test]
    fn test_on_message_sent() {
        let mut mgr = HeartbeatManager::new(Duration::from_millis(10));
        sleep(Duration::from_millis(15));
        assert!(mgr.should_send_heartbeat());

        mgr.on_message_sent();
        assert!(!mgr.should_send_heartbeat());
    }

    #[test]
    fn test_test_request_pending() {
        let mut mgr = HeartbeatManager::new(Duration::from_secs(30));

        mgr.on_test_request_sent("TEST123".to_string());
        assert_eq!(mgr.pending_test_request(), Some("TEST123"));

        let outcome = mgr.on_message_received(true, Some("TEST123"));
        assert_eq!(outcome, TestRequestOutcome::Confirmed);
        assert!(mgr.pending_test_request().is_none());
    }

    #[test]
    fn test_generate_test_req_id() {
        let id1 = generate_test_req_id();
        std::thread::sleep(std::time::Duration::from_nanos(1));
        let id2 = generate_test_req_id();

        assert!(id1.starts_with("TEST"));
        assert!(id2.starts_with("TEST"));
        // IDs may be equal if generated within the same nanosecond on fast systems
        // The important thing is that they have the correct format
        assert!(id1.len() > 4);
        assert!(id2.len() > 4);
    }

    // --- HeartBtInt = 0: heartbeating disabled -------------------------------

    #[test]
    fn test_zero_interval_reports_disabled() {
        let mgr = HeartbeatManager::new(Duration::ZERO);
        assert!(!mgr.is_enabled());
        assert_eq!(mgr.test_request_grace(), Duration::ZERO);
    }

    #[test]
    fn test_zero_interval_never_sends_heartbeat_or_test_request() {
        let mgr = HeartbeatManager::new(Duration::ZERO);
        assert!(!mgr.should_send_heartbeat());
        assert!(!mgr.should_send_test_request());

        sleep(Duration::from_millis(20));
        assert!(!mgr.should_send_heartbeat());
        assert!(!mgr.should_send_test_request());
    }

    #[test]
    fn test_zero_interval_never_times_out() {
        let mut mgr = HeartbeatManager::new(Duration::ZERO);
        assert!(!mgr.is_timed_out());

        // Even with a TestRequest artificially outstanding, a disabled
        // interval has no timeout to expire.
        mgr.on_test_request_sent("TEST-ZERO".to_string());
        sleep(Duration::from_millis(20));
        assert!(!mgr.is_timed_out());
    }

    // --- Grace period --------------------------------------------------------

    #[test]
    fn test_test_request_grace_is_one_fifth_of_a_long_interval() {
        let mgr = HeartbeatManager::new(Duration::from_secs(30));
        assert_eq!(mgr.test_request_grace(), Duration::from_secs(6));
    }

    #[test]
    fn test_test_request_grace_uses_floor_for_short_intervals() {
        let mgr = HeartbeatManager::new(Duration::from_millis(100));
        assert_eq!(mgr.test_request_grace(), MIN_TEST_REQUEST_GRACE);
    }

    #[test]
    fn test_should_send_test_request_waits_for_interval_plus_grace() {
        // 2s interval -> 400ms grace, so the probe is due at 2.4s. Scaled down
        // by using an interval whose fifth is above the floor.
        let interval = Duration::from_millis(2000);
        let mgr = HeartbeatManager::new(interval);
        assert_eq!(mgr.test_request_grace(), Duration::from_millis(400));

        // Before interval + grace: not due.
        sleep(Duration::from_millis(50));
        assert!(!mgr.should_send_test_request());
    }

    #[test]
    fn test_should_send_test_request_boundary() {
        // 1s interval -> grace floored at 250ms, so the probe is due at 1250ms
        // of inbound silence.
        let mgr = HeartbeatManager::new(Duration::from_secs(1));
        assert_eq!(mgr.test_request_grace(), Duration::from_millis(250));

        sleep(Duration::from_millis(700));
        assert!(
            !mgr.should_send_test_request(),
            "neither interval nor grace has elapsed"
        );

        sleep(Duration::from_millis(700));
        assert!(
            mgr.should_send_test_request(),
            "interval plus grace has elapsed"
        );
    }

    #[test]
    fn test_should_send_test_request_suppressed_while_pending() {
        let mut mgr = HeartbeatManager::new(Duration::from_millis(50));
        sleep(Duration::from_millis(320));
        assert!(mgr.should_send_test_request());

        mgr.on_test_request_sent("TEST-PENDING".to_string());
        assert!(!mgr.should_send_test_request());
    }

    #[test]
    fn test_should_send_test_request_unreachable_interval_is_never_due() {
        let mgr = HeartbeatManager::new(Duration::MAX);
        assert!(!mgr.should_send_test_request());
    }

    // --- Timeout branches ----------------------------------------------------

    #[test]
    fn test_is_timed_out_false_without_pending_test_request() {
        let mgr = HeartbeatManager::new(Duration::from_millis(10));
        sleep(Duration::from_millis(50));
        assert!(!mgr.is_timed_out());
    }

    #[test]
    fn test_is_timed_out_false_before_the_interval_elapses() {
        let mut mgr = HeartbeatManager::new(Duration::from_millis(200));
        mgr.on_test_request_sent("TEST-EARLY".to_string());
        sleep(Duration::from_millis(20));
        assert!(!mgr.is_timed_out());
    }

    #[test]
    fn test_is_timed_out_true_after_silence_since_the_test_request() {
        let mut mgr = HeartbeatManager::new(Duration::from_millis(50));
        mgr.on_test_request_sent("TEST-SILENT".to_string());
        sleep(Duration::from_millis(80));
        assert!(mgr.is_timed_out());
    }

    // --- Clearing a pending TestRequest -------------------------------------

    #[test]
    fn test_application_traffic_clears_pending_test_request() {
        let mut mgr = HeartbeatManager::new(Duration::from_millis(50));
        mgr.on_test_request_sent("TEST-TRAFFIC".to_string());

        // An ExecutionReport, not a Heartbeat, and carrying no TestReqID.
        let outcome = mgr.on_message_received(false, None);
        assert_eq!(outcome, TestRequestOutcome::SupersededByTraffic);
        assert!(mgr.pending_test_request().is_none());

        sleep(Duration::from_millis(80));
        assert!(
            !mgr.is_timed_out(),
            "traffic after the TestRequest proves the peer is alive"
        );
    }

    #[test]
    fn test_heartbeat_without_test_req_id_clears_pending_test_request() {
        let mut mgr = HeartbeatManager::new(Duration::from_millis(50));
        mgr.on_test_request_sent("TEST-NO-112".to_string());

        let outcome = mgr.on_message_received(true, None);
        assert_eq!(outcome, TestRequestOutcome::SupersededByTraffic);
        assert!(mgr.pending_test_request().is_none());
        assert!(!mgr.is_timed_out());
    }

    #[test]
    fn test_heartbeat_with_wrong_test_req_id_clears_pending_test_request() {
        let mut mgr = HeartbeatManager::new(Duration::from_millis(50));
        mgr.on_test_request_sent("TEST-WANTED".to_string());

        let outcome = mgr.on_message_received(true, Some("TEST-OTHER"));
        assert_eq!(outcome, TestRequestOutcome::SupersededByTraffic);
        assert!(mgr.pending_test_request().is_none());
        assert!(!mgr.is_timed_out());
    }

    #[test]
    fn test_non_heartbeat_with_matching_id_is_not_confirmation() {
        let mut mgr = HeartbeatManager::new(Duration::from_millis(50));
        mgr.on_test_request_sent("TEST-ECHO".to_string());

        // A TestRequest of the counterparty's own carrying the same ID is not
        // the Heartbeat we asked for, though it still proves liveness.
        let outcome = mgr.on_message_received(false, Some("TEST-ECHO"));
        assert_eq!(outcome, TestRequestOutcome::SupersededByTraffic);
        assert!(mgr.pending_test_request().is_none());
    }

    #[test]
    fn test_on_message_received_without_pending_reports_none_pending() {
        let mut mgr = HeartbeatManager::new(Duration::from_secs(30));
        let outcome = mgr.on_message_received(true, Some("TEST-UNSOLICITED"));
        assert_eq!(outcome, TestRequestOutcome::NonePending);
    }

    #[test]
    fn test_reset_clears_pending_test_request_and_timers() {
        let mut mgr = HeartbeatManager::new(Duration::from_millis(50));
        mgr.on_test_request_sent("TEST-RESET".to_string());
        sleep(Duration::from_millis(80));
        assert!(mgr.is_timed_out());

        mgr.reset();
        assert!(mgr.pending_test_request().is_none());
        assert!(!mgr.is_timed_out());
        assert!(!mgr.should_send_test_request());
        assert_eq!(mgr.interval(), Duration::from_millis(50));
        assert_eq!(mgr.test_request_grace(), MIN_TEST_REQUEST_GRACE);
    }

    // --- Interval negotiation ------------------------------------------------

    #[test]
    fn test_negotiate_interval_accepts_the_echoed_value() {
        let requested = Duration::from_secs(30);
        assert_eq!(negotiate_interval(requested, 30), Ok(requested));
    }

    #[test]
    fn test_negotiate_interval_accepts_zero() {
        assert_eq!(
            negotiate_interval(Duration::from_secs(30), 0),
            Ok(Duration::ZERO)
        );
    }

    #[test]
    fn test_negotiate_interval_accepts_a_differing_value_within_bounds() {
        assert_eq!(
            negotiate_interval(Duration::from_secs(30), 60),
            Ok(Duration::from_secs(60))
        );
    }

    #[test]
    fn test_negotiate_interval_accepts_the_maximum() {
        assert_eq!(
            negotiate_interval(Duration::from_secs(30), MAX_HEARTBEAT_INTERVAL_SECS),
            Ok(Duration::from_secs(MAX_HEARTBEAT_INTERVAL_SECS))
        );
    }

    #[test]
    fn test_negotiate_interval_refuses_above_the_maximum() {
        let err = negotiate_interval(Duration::from_secs(30), MAX_HEARTBEAT_INTERVAL_SECS + 1);
        assert_eq!(
            err,
            Err(HeartbeatIntervalError {
                secs: MAX_HEARTBEAT_INTERVAL_SECS + 1,
                max: MAX_HEARTBEAT_INTERVAL_SECS,
            })
        );
    }

    #[test]
    fn test_negotiate_interval_refuses_an_absurd_value() {
        assert!(negotiate_interval(Duration::from_secs(30), u64::MAX).is_err());
    }

    #[test]
    fn test_negotiate_interval_accepts_an_out_of_bounds_echo_of_our_own_request() {
        // A deliberately configured long interval echoed back is our own
        // choice, not the counterparty pushing us past the ceiling.
        let requested = Duration::from_secs(MAX_HEARTBEAT_INTERVAL_SECS + 100);
        assert_eq!(
            negotiate_interval(requested, MAX_HEARTBEAT_INTERVAL_SECS + 100),
            Ok(requested)
        );
    }
}
