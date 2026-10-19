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
//!
//! # Time is an input
//!
//! This module never reads a clock (ADR-0002, "Time source contract"). Every
//! method whose result or effect depends on time takes `now: Instant`, a
//! monotonic instant supplied by the driver; [`generate_test_req_id`] takes
//! the wall-clock time it encodes. The same manager therefore runs under the
//! Tokio reactor, under a consumer's own event loop, or in a test driven by
//! synthetic instants. Callers must pass instants that do not go backwards for
//! a given manager; an instant earlier than a recorded one is read as zero
//! elapsed time (and trips a `debug_assert!` in debug builds).

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

/// Time elapsed from `earlier` to `now`, both supplied by the caller.
///
/// A `now` before `earlier` breaks the monotonic-input contract; it is
/// reported in debug builds and read as zero elapsed time in release builds,
/// which can only delay a timer, never fire one early.
fn elapsed_between(earlier: Instant, now: Instant) -> Duration {
    debug_assert!(
        now >= earlier,
        "HeartbeatManager was given an instant earlier than one it recorded"
    );
    match now.checked_duration_since(earlier) {
        Some(elapsed) => elapsed,
        None => Duration::ZERO,
    }
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
    /// * `now` - The current monotonic instant; both timers start from it
    #[must_use]
    pub fn new(interval: Duration, now: Instant) -> Self {
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

    /// Records that a message was sent at `now`.
    #[inline]
    pub fn on_message_sent(&mut self, now: Instant) {
        self.last_sent = now;
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
    /// * `now` - When the message was received
    pub fn on_message_received(
        &mut self,
        is_heartbeat: bool,
        test_req_id: Option<&str>,
        now: Instant,
    ) -> TestRequestOutcome {
        self.last_received = now;

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
    pub fn should_send_heartbeat(&self, now: Instant) -> bool {
        self.is_enabled() && elapsed_between(self.last_sent, now) >= self.interval
    }

    /// Checks if a TestRequest should be sent.
    ///
    /// A TestRequest should be sent if no message has been received within the
    /// interval plus [`HeartbeatManager::test_request_grace`], and no
    /// TestRequest is already pending. Always `false` when `HeartBtInt` is 0.
    #[must_use]
    pub fn should_send_test_request(&self, now: Instant) -> bool {
        if !self.is_enabled() || self.test_request_pending.is_some() {
            return false;
        }
        // An interval so large that adding the grace overflows can never come
        // due; report that rather than panicking on the addition.
        match self.interval.checked_add(self.grace) {
            Some(due_after) => elapsed_between(self.last_received, now) >= due_after,
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
    pub fn is_timed_out(&self, now: Instant) -> bool {
        if !self.is_enabled() {
            return false;
        }
        match self.test_request_sent_at {
            Some(sent_at) => elapsed_between(sent_at, now) >= self.interval,
            None => false,
        }
    }

    /// Records that a TestRequest was sent.
    ///
    /// # Arguments
    /// * `test_req_id` - The `TestReqID` that was sent
    /// * `now` - When it was sent; the timeout countdown runs from here
    pub fn on_test_request_sent(&mut self, test_req_id: String, now: Instant) {
        self.test_request_pending = Some(test_req_id);
        self.test_request_sent_at = Some(now);
        self.last_sent = now;
    }

    /// Returns the pending TestRequest ID, if any.
    #[must_use]
    pub fn pending_test_request(&self) -> Option<&str> {
        self.test_request_pending.as_deref()
    }

    /// Returns the time from the last message received to `now`.
    #[must_use]
    pub fn time_since_last_received(&self, now: Instant) -> Duration {
        elapsed_between(self.last_received, now)
    }

    /// Returns the time from the last message sent to `now`.
    #[must_use]
    pub fn time_since_last_sent(&self, now: Instant) -> Duration {
        elapsed_between(self.last_sent, now)
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
    /// kept; only the timers and the pending TestRequest are cleared, and
    /// both timers restart from `now`.
    pub fn reset(&mut self, now: Instant) {
        self.last_sent = now;
        self.last_received = now;
        self.test_request_pending = None;
        self.test_request_sent_at = None;
    }
}

/// Generates a TestReqID (112) from a wall-clock time the caller supplies.
///
/// The ID is `TEST` followed by `wall_clock` in nanoseconds since the Unix
/// epoch, so distinct times yield distinct IDs. The session layer reads no
/// clock: the driver passes the current time (or any other monotonically
/// distinct value expressed as a `SystemTime`). A time before the epoch
/// encodes as `TEST0`.
///
/// # Arguments
/// * `wall_clock` - The entropy for the ID, normally the current time
#[must_use]
pub fn generate_test_req_id(wall_clock: SystemTime) -> String {
    let nanos = match wall_clock.duration_since(UNIX_EPOCH) {
        Ok(since_epoch) => since_epoch.as_nanos(),
        Err(_) => 0,
    };

    format!("TEST{}", nanos)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every timing test is driven by synthetic instants: one base instant is
    // taken, and every later moment is `base + offset`. No test sleeps, so the
    // boundaries are asserted exactly rather than with scheduler slack.

    fn base() -> Instant {
        Instant::now()
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn test_heartbeat_manager_new() {
        let mgr = HeartbeatManager::new(Duration::from_secs(30), base());
        assert_eq!(mgr.interval(), Duration::from_secs(30));
        assert!(mgr.pending_test_request().is_none());
        assert!(mgr.is_enabled());
    }

    #[test]
    fn test_should_send_heartbeat_exact_boundary() {
        let t0 = base();
        let mgr = HeartbeatManager::new(ms(10), t0);
        assert!(!mgr.should_send_heartbeat(t0));
        assert!(!mgr.should_send_heartbeat(t0 + ms(9)));
        assert!(mgr.should_send_heartbeat(t0 + ms(10)));
        assert!(mgr.should_send_heartbeat(t0 + ms(15)));
    }

    #[test]
    fn test_on_message_sent_restarts_the_heartbeat_timer() {
        let t0 = base();
        let mut mgr = HeartbeatManager::new(ms(10), t0);
        assert!(mgr.should_send_heartbeat(t0 + ms(15)));

        mgr.on_message_sent(t0 + ms(15));
        assert!(!mgr.should_send_heartbeat(t0 + ms(15)));
        assert!(!mgr.should_send_heartbeat(t0 + ms(24)));
        assert!(mgr.should_send_heartbeat(t0 + ms(25)));
        assert_eq!(mgr.time_since_last_sent(t0 + ms(20)), ms(5));
    }

    #[test]
    fn test_inbound_traffic_does_not_restart_the_heartbeat_timer() {
        let t0 = base();
        let mut mgr = HeartbeatManager::new(ms(10), t0);
        let _ = mgr.on_message_received(false, None, t0 + ms(8));
        assert!(mgr.should_send_heartbeat(t0 + ms(10)));
        assert_eq!(mgr.time_since_last_received(t0 + ms(10)), ms(2));
    }

    #[test]
    fn test_test_request_pending() {
        let t0 = base();
        let mut mgr = HeartbeatManager::new(Duration::from_secs(30), t0);

        mgr.on_test_request_sent("TEST123".to_string(), t0);
        assert_eq!(mgr.pending_test_request(), Some("TEST123"));

        let outcome = mgr.on_message_received(true, Some("TEST123"), t0 + ms(5));
        assert_eq!(outcome, TestRequestOutcome::Confirmed);
        assert!(mgr.pending_test_request().is_none());
    }

    #[test]
    fn test_on_test_request_sent_counts_as_sending() {
        let t0 = base();
        let mut mgr = HeartbeatManager::new(ms(100), t0);
        mgr.on_test_request_sent("TEST-SENDS".to_string(), t0 + ms(90));
        assert!(!mgr.should_send_heartbeat(t0 + ms(100)));
        assert!(mgr.should_send_heartbeat(t0 + ms(190)));
    }

    #[test]
    fn test_generate_test_req_id_encodes_the_supplied_time() {
        let at = UNIX_EPOCH + Duration::from_nanos(1_234_567_890);
        assert_eq!(generate_test_req_id(at), "TEST1234567890");
    }

    #[test]
    fn test_generate_test_req_id_distinct_times_give_distinct_ids() {
        let at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let later = at + Duration::from_nanos(1);
        assert_ne!(generate_test_req_id(at), generate_test_req_id(later));
    }

    #[test]
    fn test_generate_test_req_id_before_the_epoch_is_zero() {
        let before = UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(generate_test_req_id(before), "TEST0");
    }

    // --- HeartBtInt = 0: heartbeating disabled -------------------------------

    #[test]
    fn test_zero_interval_reports_disabled() {
        let mgr = HeartbeatManager::new(Duration::ZERO, base());
        assert!(!mgr.is_enabled());
        assert_eq!(mgr.test_request_grace(), Duration::ZERO);
    }

    #[test]
    fn test_zero_interval_never_sends_heartbeat_or_test_request() {
        let t0 = base();
        let mgr = HeartbeatManager::new(Duration::ZERO, t0);
        for later in [t0, t0 + ms(20), t0 + Duration::from_secs(3600)] {
            assert!(!mgr.should_send_heartbeat(later));
            assert!(!mgr.should_send_test_request(later));
        }
    }

    #[test]
    fn test_zero_interval_never_times_out() {
        let t0 = base();
        let mut mgr = HeartbeatManager::new(Duration::ZERO, t0);
        assert!(!mgr.is_timed_out(t0));

        // Even with a TestRequest artificially outstanding, a disabled
        // interval has no timeout to expire.
        mgr.on_test_request_sent("TEST-ZERO".to_string(), t0);
        assert!(!mgr.is_timed_out(t0 + Duration::from_secs(3600)));
    }

    // --- Grace period --------------------------------------------------------

    #[test]
    fn test_test_request_grace_is_one_fifth_of_a_long_interval() {
        let mgr = HeartbeatManager::new(Duration::from_secs(30), base());
        assert_eq!(mgr.test_request_grace(), Duration::from_secs(6));
    }

    #[test]
    fn test_test_request_grace_uses_floor_for_short_intervals() {
        let mgr = HeartbeatManager::new(ms(100), base());
        assert_eq!(mgr.test_request_grace(), MIN_TEST_REQUEST_GRACE);
    }

    #[test]
    fn test_should_send_test_request_waits_for_interval_plus_grace() {
        // 2s interval -> 400ms grace, so the probe is due at exactly 2.4s.
        let t0 = base();
        let mgr = HeartbeatManager::new(ms(2000), t0);
        assert_eq!(mgr.test_request_grace(), ms(400));

        assert!(!mgr.should_send_test_request(t0 + ms(2000)));
        assert!(!mgr.should_send_test_request(t0 + ms(2399)));
        assert!(mgr.should_send_test_request(t0 + ms(2400)));
    }

    #[test]
    fn test_should_send_test_request_boundary() {
        // 1s interval -> grace floored at 250ms, so the probe is due at 1250ms
        // of inbound silence.
        let t0 = base();
        let mgr = HeartbeatManager::new(Duration::from_secs(1), t0);
        assert_eq!(mgr.test_request_grace(), ms(250));

        assert!(!mgr.should_send_test_request(t0 + ms(1249)));
        assert!(mgr.should_send_test_request(t0 + ms(1250)));
    }

    #[test]
    fn test_inbound_traffic_restarts_the_test_request_timer() {
        let t0 = base();
        let mut mgr = HeartbeatManager::new(Duration::from_secs(1), t0);
        let _ = mgr.on_message_received(false, None, t0 + ms(1000));
        assert!(!mgr.should_send_test_request(t0 + ms(1250)));
        assert!(!mgr.should_send_test_request(t0 + ms(2249)));
        assert!(mgr.should_send_test_request(t0 + ms(2250)));
    }

    #[test]
    fn test_should_send_test_request_suppressed_while_pending() {
        let t0 = base();
        let mut mgr = HeartbeatManager::new(ms(50), t0);
        assert!(mgr.should_send_test_request(t0 + ms(320)));

        mgr.on_test_request_sent("TEST-PENDING".to_string(), t0 + ms(320));
        assert!(!mgr.should_send_test_request(t0 + ms(320)));
        assert!(!mgr.should_send_test_request(t0 + ms(10_000)));
    }

    #[test]
    fn test_should_send_test_request_unreachable_interval_is_never_due() {
        let t0 = base();
        let mgr = HeartbeatManager::new(Duration::MAX, t0);
        assert!(!mgr.should_send_test_request(t0 + Duration::from_secs(86_400)));
    }

    #[test]
    fn test_predicates_near_duration_max_do_not_panic() {
        // Backstop for the remote-DoS root cause: a manager built with a huge
        // interval (e.g. from a counterparty HeartBtInt of u64::MAX that slipped
        // past the handshake bound) must not overflow the `interval + grace`
        // arithmetic. Under `panic = "abort"` an overflow here is a process
        // kill, so every timing predicate has to return, not panic. An
        // unreachable interval means "effectively never": nothing is ever due
        // and the session never times out.
        let t0 = base();
        let later = t0 + Duration::from_secs(86_400);
        let mut mgr = HeartbeatManager::new(Duration::MAX, t0);
        assert!(!mgr.should_send_heartbeat(later));
        assert!(!mgr.should_send_test_request(later));
        assert!(!mgr.is_timed_out(later));

        // Reach the `is_timed_out` comparison against the near-MAX interval by
        // leaving a TestRequest outstanding; it must compare, not overflow.
        mgr.on_test_request_sent("TEST-NEAR-MAX".to_string(), t0);
        assert!(!mgr.is_timed_out(later));
        assert!(!mgr.should_send_test_request(later));
    }

    // --- Timeout branches ----------------------------------------------------

    #[test]
    fn test_is_timed_out_false_without_pending_test_request() {
        let t0 = base();
        let mgr = HeartbeatManager::new(ms(10), t0);
        assert!(!mgr.is_timed_out(t0 + ms(50)));
    }

    #[test]
    fn test_is_timed_out_exact_boundary() {
        let t0 = base();
        let mut mgr = HeartbeatManager::new(ms(200), t0);
        mgr.on_test_request_sent("TEST-EARLY".to_string(), t0 + ms(100));
        assert!(!mgr.is_timed_out(t0 + ms(120)));
        assert!(!mgr.is_timed_out(t0 + ms(299)));
        assert!(mgr.is_timed_out(t0 + ms(300)));
    }

    #[test]
    fn test_is_timed_out_true_after_silence_since_the_test_request() {
        let t0 = base();
        let mut mgr = HeartbeatManager::new(ms(50), t0);
        mgr.on_test_request_sent("TEST-SILENT".to_string(), t0);
        assert!(mgr.is_timed_out(t0 + ms(80)));
    }

    // --- Clearing a pending TestRequest -------------------------------------

    #[test]
    fn test_application_traffic_clears_pending_test_request() {
        let t0 = base();
        let mut mgr = HeartbeatManager::new(ms(50), t0);
        mgr.on_test_request_sent("TEST-TRAFFIC".to_string(), t0);

        // An ExecutionReport, not a Heartbeat, and carrying no TestReqID.
        let outcome = mgr.on_message_received(false, None, t0 + ms(10));
        assert_eq!(outcome, TestRequestOutcome::SupersededByTraffic);
        assert!(mgr.pending_test_request().is_none());
        assert!(
            !mgr.is_timed_out(t0 + ms(80)),
            "traffic after the TestRequest proves the peer is alive"
        );
    }

    #[test]
    fn test_heartbeat_without_test_req_id_clears_pending_test_request() {
        let t0 = base();
        let mut mgr = HeartbeatManager::new(ms(50), t0);
        mgr.on_test_request_sent("TEST-NO-112".to_string(), t0);

        let outcome = mgr.on_message_received(true, None, t0 + ms(10));
        assert_eq!(outcome, TestRequestOutcome::SupersededByTraffic);
        assert!(mgr.pending_test_request().is_none());
        assert!(!mgr.is_timed_out(t0 + ms(80)));
    }

    #[test]
    fn test_heartbeat_with_wrong_test_req_id_clears_pending_test_request() {
        let t0 = base();
        let mut mgr = HeartbeatManager::new(ms(50), t0);
        mgr.on_test_request_sent("TEST-WANTED".to_string(), t0);

        let outcome = mgr.on_message_received(true, Some("TEST-OTHER"), t0 + ms(10));
        assert_eq!(outcome, TestRequestOutcome::SupersededByTraffic);
        assert!(mgr.pending_test_request().is_none());
        assert!(!mgr.is_timed_out(t0 + ms(80)));
    }

    #[test]
    fn test_non_heartbeat_with_matching_id_is_not_confirmation() {
        let t0 = base();
        let mut mgr = HeartbeatManager::new(ms(50), t0);
        mgr.on_test_request_sent("TEST-ECHO".to_string(), t0);

        // A TestRequest of the counterparty's own carrying the same ID is not
        // the Heartbeat we asked for, though it still proves liveness.
        let outcome = mgr.on_message_received(false, Some("TEST-ECHO"), t0 + ms(10));
        assert_eq!(outcome, TestRequestOutcome::SupersededByTraffic);
        assert!(mgr.pending_test_request().is_none());
    }

    #[test]
    fn test_on_message_received_without_pending_reports_none_pending() {
        let t0 = base();
        let mut mgr = HeartbeatManager::new(Duration::from_secs(30), t0);
        let outcome = mgr.on_message_received(true, Some("TEST-UNSOLICITED"), t0);
        assert_eq!(outcome, TestRequestOutcome::NonePending);
    }

    #[test]
    fn test_full_probe_cycle_on_synthetic_time() {
        // Silence, TestRequest due, sent, silence, timeout: all on synthetic
        // instants, at the exact boundaries.
        let t0 = base();
        let mut mgr = HeartbeatManager::new(Duration::from_secs(30), t0);
        let due = t0 + Duration::from_secs(36);
        assert!(!mgr.should_send_test_request(due - ms(1)));
        assert!(mgr.should_send_test_request(due));

        mgr.on_test_request_sent("TEST-CYCLE".to_string(), due);
        assert!(!mgr.is_timed_out(due + Duration::from_secs(29)));
        assert!(mgr.is_timed_out(due + Duration::from_secs(30)));
    }

    #[test]
    fn test_reset_clears_pending_test_request_and_timers() {
        let t0 = base();
        let mut mgr = HeartbeatManager::new(ms(50), t0);
        mgr.on_test_request_sent("TEST-RESET".to_string(), t0);
        assert!(mgr.is_timed_out(t0 + ms(80)));

        mgr.reset(t0 + ms(80));
        assert!(mgr.pending_test_request().is_none());
        assert!(!mgr.is_timed_out(t0 + ms(80)));
        assert!(!mgr.should_send_test_request(t0 + ms(80)));
        assert!(!mgr.should_send_heartbeat(t0 + ms(129)));
        assert!(mgr.should_send_heartbeat(t0 + ms(130)));
        assert_eq!(mgr.interval(), ms(50));
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
