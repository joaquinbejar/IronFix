/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Session configuration: keepalive, accepted counterparty keepalive range,
//! retransmission limits and policy, gap bounds and handshake timeout.
//!
//! The same [`FixpConfig`] serves both roles. Every knob has a default, a
//! documented unit and range, and is validated by
//! [`FixpConfigBuilder::build`]. Every duration is bounded by
//! [`MAX_TIMER`], the range of FIXP's `DeltaMillisecs` wire type, so no
//! deadline the session computes from it can overflow and silently never
//! fire.

use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::time::Duration;
use thiserror::Error;

/// Default keepalive interval this side announces: 5 seconds.
pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);

/// Default smallest counterparty keepalive interval accepted: 100 ms.
pub const DEFAULT_MIN_PEER_KEEPALIVE: Duration = Duration::from_millis(100);

/// Default largest counterparty keepalive interval accepted: one hour, the
/// ceiling `ironfix-session` applies to a FIX `HeartBtInt`.
pub const DEFAULT_MAX_PEER_KEEPALIVE: Duration = Duration::from_secs(3_600);

/// Default largest RetransmitRequest `Count` answered, and the largest this
/// side asks for in one request: 1 000 messages.
pub const DEFAULT_MAX_RETRANSMIT_COUNT: NonZeroU32 = match NonZeroU32::new(1_000) {
    Some(count) => count,
    None => NonZeroU32::MIN,
};

/// Default bound on separate unrecovered gaps tracked at once: 256.
pub const DEFAULT_MAX_PENDING_GAPS: NonZeroUsize = match NonZeroUsize::new(256) {
    Some(gaps) => gaps,
    None => NonZeroUsize::MIN,
};

/// Default largest single sequence gap accepted: 1 000 000 messages.
pub const DEFAULT_MAX_GAP_LEN: NonZeroU64 = match NonZeroU64::new(1_000_000) {
    Some(len) => len,
    None => NonZeroU64::MIN,
};

/// Default time a RetransmitRequest may go without a retransmitted message
/// before it counts as stalled: 10 seconds.
pub const DEFAULT_RETRANSMIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default time allowed for each handshake step: 10 seconds.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The longest duration any setting takes: `u32::MAX` milliseconds (about
/// 49.7 days), the range of the `DeltaMillisecs` wire type.
pub const MAX_TIMER: Duration = Duration::from_millis(u32::MAX as u64);

/// What a requester does when its RetransmitRequest stalls: no retransmitted
/// message for [`FixpConfig::retransmit_timeout`].
///
/// FIXP gives the requester two duties that can pull apart. It must not send
/// a second RetransmitRequest while a retransmission is in progress (sections
/// 4.6.1, 4.6.4 and 6.3: a strict provider terminates with
/// `ReRequestInProgress`), yet it is "the requester's responsibility" to ask
/// again when a batch did not fill the gap (section 4.6.2.2). The requester
/// cannot see whether a quiet provider has finished or is pacing its batches,
/// so the policy is the operator's call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum RetransmitStallPolicy {
    /// Report [`Event::RetransmitTimedOut`](crate::Event::RetransmitTimedOut)
    /// and keep waiting. The request stays outstanding; the application may
    /// terminate and re-establish, which requests the gap again.
    EventOnly,
    /// Report the stall and terminate the binding with `UnspecifiedError`.
    /// Unrecovered gaps survive and are requested again after the next
    /// establishment, when no retransmission can still be in progress.
    Terminate,
    /// The default. Ask again for what is still missing only when the
    /// provider has visibly stopped serving: a Sequence or Context arrived
    /// while a batch was still short of its `Count` (a context switch ends
    /// the batch, section 3.5.4) and `retransmit_timeout` has passed since
    /// that cut. Otherwise report the stall and keep waiting, as `EventOnly`
    /// does; a cut that comes after the stall was reported starts the timer
    /// again from the cut.
    ///
    /// Residual risk: a provider that cut a batch short but still considers
    /// the request in progress (IronFix's own provider does, if its driver
    /// writes fewer messages than a batch announced and does not call
    /// `end_retransmission`) sees the new request as premature, and a strict
    /// one terminates with `ReRequestInProgress`. Conversely, a provider that
    /// answers with one short but complete batch and expects a new request
    /// (one reading of section 4.6.2.2) is never asked again under this
    /// policy; use `Terminate` or `ReRequestAfterBatch` with such a
    /// counterparty.
    #[default]
    ReRequestAfterContextSwitch,
    /// Everything `ReRequestAfterContextSwitch` does, and also ask again for
    /// what is still missing when the last batch arrived in full, the
    /// request is still short of its `Count`, and `retransmit_timeout` has
    /// passed since that batch's last message: the provider answered with
    /// one complete batch and waits for a new request (one reading of
    /// section 4.6.2.2).
    ///
    /// Use it with a provider that serves one batch per request. Against a
    /// provider that paces several batches for one request more slowly than
    /// `retransmit_timeout` (IronFix's own may, as its driver decides), the
    /// new request is premature, and a strict provider terminates with
    /// `ReRequestInProgress` (sections 4.6.1, 4.6.4, 6.3).
    ReRequestAfterBatch,
}

/// Configuration of a FIXP session, either role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixpConfig {
    keepalive_interval: Duration,
    /// `keepalive_interval` in whole milliseconds, as it goes on the wire.
    keepalive_millis: u32,
    min_peer_keepalive: Duration,
    max_peer_keepalive: Duration,
    peer_silence_grace: Option<Duration>,
    max_retransmit_count: NonZeroU32,
    max_pending_gaps: NonZeroUsize,
    max_gap_len: NonZeroU64,
    retransmit_timeout: Duration,
    retransmit_stall_policy: RetransmitStallPolicy,
    handshake_timeout: Duration,
}

impl Default for FixpConfig {
    fn default() -> Self {
        Self {
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            keepalive_millis: 5_000,
            min_peer_keepalive: DEFAULT_MIN_PEER_KEEPALIVE,
            max_peer_keepalive: DEFAULT_MAX_PEER_KEEPALIVE,
            peer_silence_grace: None,
            max_retransmit_count: DEFAULT_MAX_RETRANSMIT_COUNT,
            max_pending_gaps: DEFAULT_MAX_PENDING_GAPS,
            max_gap_len: DEFAULT_MAX_GAP_LEN,
            retransmit_timeout: DEFAULT_RETRANSMIT_TIMEOUT,
            retransmit_stall_policy: RetransmitStallPolicy::ReRequestAfterContextSwitch,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }
}

impl FixpConfig {
    /// Returns a builder seeded with the defaults.
    pub fn builder() -> FixpConfigBuilder {
        FixpConfigBuilder {
            config: Self::default(),
        }
    }

    /// The keepalive interval this side announces (in Establish as a client,
    /// in EstablishmentAck as a server) and keeps to: it sends a heartbeat
    /// whenever this long passes without an application message.
    #[must_use]
    pub const fn keepalive_interval(&self) -> Duration {
        self.keepalive_interval
    }

    /// The keepalive interval in whole milliseconds, as it goes on the wire.
    pub(crate) const fn keepalive_millis(&self) -> u32 {
        self.keepalive_millis
    }

    /// The smallest counterparty keepalive interval accepted.
    #[must_use]
    pub const fn min_peer_keepalive(&self) -> Duration {
        self.min_peer_keepalive
    }

    /// The largest counterparty keepalive interval accepted.
    #[must_use]
    pub const fn max_peer_keepalive(&self) -> Duration {
        self.max_peer_keepalive
    }

    /// Returns `true` if `millis` is within the accepted counterparty range.
    pub(crate) fn accepts_peer_keepalive(&self, millis: u32) -> bool {
        let interval = Duration::from_millis(u64::from(millis));
        interval >= self.min_peer_keepalive && interval <= self.max_peer_keepalive
    }

    /// The leniency added to the counterparty's keepalive interval before its
    /// silence terminates the session. `None` means "equal to the
    /// counterparty's interval".
    #[must_use]
    pub const fn peer_silence_grace(&self) -> Option<Duration> {
        self.peer_silence_grace
    }

    /// The largest RetransmitRequest `Count` this side answers, and the
    /// largest it asks for in one request.
    #[must_use]
    pub const fn max_retransmit_count(&self) -> NonZeroU32 {
        self.max_retransmit_count
    }

    /// The most separate unrecovered gaps tracked at once.
    #[must_use]
    pub const fn max_pending_gaps(&self) -> NonZeroUsize {
        self.max_pending_gaps
    }

    /// The largest single gap, in messages, the session accepts in the
    /// counterparty's numbering; a larger jump terminates.
    #[must_use]
    pub const fn max_gap_len(&self) -> NonZeroU64 {
        self.max_gap_len
    }

    /// How long a RetransmitRequest may go without a retransmitted message
    /// before it counts as stalled.
    #[must_use]
    pub const fn retransmit_timeout(&self) -> Duration {
        self.retransmit_timeout
    }

    /// What the session does when a RetransmitRequest stalls.
    #[must_use]
    pub const fn retransmit_stall_policy(&self) -> RetransmitStallPolicy {
        self.retransmit_stall_policy
    }

    /// How long each handshake step may wait: a client for
    /// NegotiationResponse or EstablishmentAck; a server for Negotiate, for
    /// an Establish on a transport, and for the application's answer to
    /// either.
    #[must_use]
    pub const fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }
}

/// Builder for [`FixpConfig`].
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless .build() is called"]
pub struct FixpConfigBuilder {
    config: FixpConfig,
}

impl FixpConfigBuilder {
    /// Sets the keepalive interval this side announces and keeps to.
    ///
    /// Whole milliseconds, from 1 ms to [`MAX_TIMER`]. Default 5 s.
    pub const fn keepalive_interval(mut self, interval: Duration) -> Self {
        self.config.keepalive_interval = interval;
        self
    }

    /// Sets the range of counterparty keepalive intervals accepted, both ends
    /// inclusive, each in whole milliseconds from 1 ms to [`MAX_TIMER`]. A
    /// server refuses an Establish outside it with EstablishmentReject
    /// `KeepaliveInterval`; a client terminates on an EstablishmentAck
    /// outside it. Default 100 ms to 1 hour.
    ///
    /// The upper bound matters: the counterparty's interval drives this
    /// side's dead-peer detection, so an unbounded one would let the
    /// counterparty disable it.
    pub const fn peer_keepalive_range(mut self, min: Duration, max: Duration) -> Self {
        self.config.min_peer_keepalive = min;
        self.config.max_peer_keepalive = max;
        self
    }

    /// Sets the leniency added to the counterparty's keepalive interval
    /// before its silence terminates the session (FIXP v1.1 section 4.4
    /// recommends some), at most [`MAX_TIMER`].
    ///
    /// Default: equal to the counterparty's interval, so the session ends
    /// after two intervals without a message. FIXP asks for a heartbeat in
    /// each interval without application messages; a peer that schedules
    /// heartbeats on fixed interval boundaries can stay silent for almost two
    /// intervals without breaking that rule.
    pub const fn peer_silence_grace(mut self, grace: Duration) -> Self {
        self.config.peer_silence_grace = Some(grace);
        self
    }

    /// Sets the largest RetransmitRequest `Count` answered (a larger request
    /// is refused with RetransmitReject `RequestLimitExceeded`), which is also
    /// the largest this side asks for in one request. Default 1 000.
    pub const fn max_retransmit_count(mut self, count: NonZeroU32) -> Self {
        self.config.max_retransmit_count = count;
        self
    }

    /// Sets how many separate unrecovered gaps are tracked at once; one more
    /// terminates the session. Default 256.
    pub const fn max_pending_gaps(mut self, gaps: NonZeroUsize) -> Self {
        self.config.max_pending_gaps = gaps;
        self
    }

    /// Sets the largest single jump in the counterparty's numbering the
    /// session accepts as a gap, in messages; a larger one terminates.
    /// Default 1 000 000.
    ///
    /// It bounds the work a counterparty can cause with one `NextSeqNo`:
    /// the requests a Recoverable gap leads to, and the size a NotApplied
    /// reports.
    pub const fn max_gap_len(mut self, len: NonZeroU64) -> Self {
        self.config.max_gap_len = len;
        self
    }

    /// Sets how long a RetransmitRequest may go without a retransmitted
    /// message before it counts as stalled. From 1 ns to [`MAX_TIMER`].
    /// Default 10 s.
    pub const fn retransmit_timeout(mut self, timeout: Duration) -> Self {
        self.config.retransmit_timeout = timeout;
        self
    }

    /// Sets what the session does when a RetransmitRequest stalls. Default
    /// [`RetransmitStallPolicy::ReRequestAfterContextSwitch`].
    pub const fn retransmit_stall_policy(mut self, policy: RetransmitStallPolicy) -> Self {
        self.config.retransmit_stall_policy = policy;
        self
    }

    /// Sets how long each handshake step may wait. From 1 ns to
    /// [`MAX_TIMER`]. Default 10 s.
    pub const fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.config.handshake_timeout = timeout;
        self
    }

    /// Validates and returns the configuration.
    ///
    /// # Errors
    /// Returns a [`FixpConfigError`] naming the first invalid setting.
    pub fn build(self) -> Result<FixpConfig, FixpConfigError> {
        let mut config = self.config;
        config.keepalive_millis =
            validate_keepalive("keepalive_interval", config.keepalive_interval)?;
        validate_keepalive("min_peer_keepalive", config.min_peer_keepalive)?;
        validate_keepalive("max_peer_keepalive", config.max_peer_keepalive)?;
        if config.min_peer_keepalive > config.max_peer_keepalive {
            return Err(FixpConfigError::EmptyPeerKeepaliveRange {
                min: config.min_peer_keepalive,
                max: config.max_peer_keepalive,
            });
        }
        if let Some(grace) = config.peer_silence_grace {
            validate_upper_bound("peer_silence_grace", grace)?;
        }
        validate_timeout("retransmit_timeout", config.retransmit_timeout)?;
        validate_timeout("handshake_timeout", config.handshake_timeout)?;
        Ok(config)
    }
}

/// Checks a keepalive interval is whole milliseconds within the wire range
/// and returns it in milliseconds.
fn validate_keepalive(setting: &'static str, interval: Duration) -> Result<u32, FixpConfigError> {
    let invalid = FixpConfigError::InvalidKeepalive { setting, interval };
    if interval < Duration::from_millis(1)
        || interval > MAX_TIMER
        || !interval.subsec_nanos().is_multiple_of(1_000_000)
    {
        return Err(invalid);
    }
    u32::try_from(interval.as_millis()).map_err(|_| invalid)
}

/// Checks a timeout is neither zero nor above [`MAX_TIMER`].
fn validate_timeout(setting: &'static str, timeout: Duration) -> Result<(), FixpConfigError> {
    if timeout.is_zero() {
        return Err(FixpConfigError::ZeroTimeout { setting });
    }
    validate_upper_bound(setting, timeout)
}

/// Checks a duration is at most [`MAX_TIMER`].
fn validate_upper_bound(setting: &'static str, duration: Duration) -> Result<(), FixpConfigError> {
    if duration > MAX_TIMER {
        return Err(FixpConfigError::TimerTooLong {
            setting,
            duration,
            max: MAX_TIMER,
        });
    }
    Ok(())
}

/// An invalid [`FixpConfig`] setting.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum FixpConfigError {
    /// A keepalive interval that is not a whole number of milliseconds from
    /// 1 ms to [`MAX_TIMER`].
    #[error("{setting} of {interval:?} is not whole milliseconds from 1 ms to u32::MAX ms")]
    InvalidKeepalive {
        /// The setting name.
        setting: &'static str,
        /// The value given.
        interval: Duration,
    },
    /// A peer keepalive range whose minimum exceeds its maximum.
    #[error("peer keepalive range is empty: minimum {min:?} exceeds maximum {max:?}")]
    EmptyPeerKeepaliveRange {
        /// The minimum given.
        min: Duration,
        /// The maximum given.
        max: Duration,
    },
    /// A timeout of zero.
    #[error("{setting} must be greater than zero")]
    ZeroTimeout {
        /// The setting name.
        setting: &'static str,
    },
    /// A duration above [`MAX_TIMER`].
    #[error("{setting} of {duration:?} exceeds the maximum of {max:?}")]
    TimerTooLong {
        /// The setting name.
        setting: &'static str,
        /// The value given.
        duration: Duration,
        /// The largest accepted, [`MAX_TIMER`].
        max: Duration,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_is_valid() {
        let built = FixpConfig::builder().build();
        assert_eq!(built, Ok(FixpConfig::default()));
        let config = FixpConfig::default();
        assert_eq!(config.keepalive_interval(), Duration::from_secs(5));
        assert_eq!(config.keepalive_millis(), 5_000);
        assert_eq!(config.max_retransmit_count().get(), 1_000);
        assert_eq!(config.max_pending_gaps().get(), 256);
        assert_eq!(config.max_gap_len().get(), 1_000_000);
        assert_eq!(config.peer_silence_grace(), None);
        assert_eq!(config.retransmit_timeout(), Duration::from_secs(10));
        assert_eq!(
            config.retransmit_stall_policy(),
            RetransmitStallPolicy::ReRequestAfterContextSwitch
        );
        assert_eq!(
            RetransmitStallPolicy::default(),
            config.retransmit_stall_policy()
        );
        assert_eq!(config.handshake_timeout(), Duration::from_secs(10));
        assert_eq!(config.min_peer_keepalive(), Duration::from_millis(100));
        assert_eq!(config.max_peer_keepalive(), Duration::from_secs(3_600));
    }

    #[test]
    fn test_builder_sets_every_knob() {
        let built = FixpConfig::builder()
            .keepalive_interval(Duration::from_millis(250))
            .peer_keepalive_range(Duration::from_millis(10), Duration::from_secs(60))
            .peer_silence_grace(Duration::from_millis(50))
            .max_retransmit_count(NonZeroU32::MIN)
            .max_pending_gaps(NonZeroUsize::MIN)
            .max_gap_len(NonZeroU64::MIN)
            .retransmit_timeout(Duration::from_secs(1))
            .retransmit_stall_policy(RetransmitStallPolicy::Terminate)
            .handshake_timeout(Duration::from_secs(2))
            .build();
        assert!(built.is_ok());
        if let Ok(config) = built {
            assert_eq!(config.keepalive_millis(), 250);
            assert!(config.accepts_peer_keepalive(10));
            assert!(config.accepts_peer_keepalive(60_000));
            assert!(!config.accepts_peer_keepalive(9));
            assert!(!config.accepts_peer_keepalive(60_001));
            assert_eq!(config.peer_silence_grace(), Some(Duration::from_millis(50)));
            assert_eq!(config.max_retransmit_count().get(), 1);
            assert_eq!(config.max_pending_gaps().get(), 1);
            assert_eq!(config.max_gap_len().get(), 1);
            assert_eq!(
                config.retransmit_stall_policy(),
                RetransmitStallPolicy::Terminate
            );
        }
    }

    #[test]
    fn test_builder_rejects_invalid_keepalive_intervals() {
        for interval in [
            Duration::ZERO,
            Duration::from_micros(500),
            Duration::from_micros(1_500),
            Duration::from_millis(u64::from(u32::MAX) + 1),
        ] {
            assert_eq!(
                FixpConfig::builder().keepalive_interval(interval).build(),
                Err(FixpConfigError::InvalidKeepalive {
                    setting: "keepalive_interval",
                    interval,
                })
            );
        }
        assert!(matches!(
            FixpConfig::builder()
                .peer_keepalive_range(Duration::ZERO, Duration::from_secs(1))
                .build(),
            Err(FixpConfigError::InvalidKeepalive {
                setting: "min_peer_keepalive",
                ..
            })
        ));
    }

    #[test]
    fn test_builder_rejects_an_empty_peer_range_and_zero_timeouts() {
        assert_eq!(
            FixpConfig::builder()
                .peer_keepalive_range(Duration::from_secs(2), Duration::from_secs(1))
                .build(),
            Err(FixpConfigError::EmptyPeerKeepaliveRange {
                min: Duration::from_secs(2),
                max: Duration::from_secs(1),
            })
        );
        assert_eq!(
            FixpConfig::builder()
                .retransmit_timeout(Duration::ZERO)
                .build(),
            Err(FixpConfigError::ZeroTimeout {
                setting: "retransmit_timeout"
            })
        );
        assert_eq!(
            FixpConfig::builder()
                .handshake_timeout(Duration::ZERO)
                .build(),
            Err(FixpConfigError::ZeroTimeout {
                setting: "handshake_timeout"
            })
        );
    }

    #[test]
    fn test_builder_rejects_timers_above_the_wire_range() {
        // An unbounded timer would overflow `Instant` arithmetic and never
        // fire: a grace of Duration::MAX would disable dead-peer detection.
        let too_long = MAX_TIMER + Duration::from_millis(1);
        assert_eq!(
            FixpConfig::builder()
                .peer_silence_grace(Duration::MAX)
                .build(),
            Err(FixpConfigError::TimerTooLong {
                setting: "peer_silence_grace",
                duration: Duration::MAX,
                max: MAX_TIMER,
            })
        );
        assert_eq!(
            FixpConfig::builder().retransmit_timeout(too_long).build(),
            Err(FixpConfigError::TimerTooLong {
                setting: "retransmit_timeout",
                duration: too_long,
                max: MAX_TIMER,
            })
        );
        assert_eq!(
            FixpConfig::builder().handshake_timeout(too_long).build(),
            Err(FixpConfigError::TimerTooLong {
                setting: "handshake_timeout",
                duration: too_long,
                max: MAX_TIMER,
            })
        );
        // The bound itself is accepted.
        assert!(
            FixpConfig::builder()
                .peer_silence_grace(MAX_TIMER)
                .retransmit_timeout(MAX_TIMER)
                .handshake_timeout(MAX_TIMER)
                .build()
                .is_ok()
        );
        assert!(
            FixpConfigError::TimerTooLong {
                setting: "handshake_timeout",
                duration: too_long,
                max: MAX_TIMER,
            }
            .to_string()
            .contains("handshake_timeout")
        );
    }
}
