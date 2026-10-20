/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 19/10/26
******************************************************************************/

//! An optional per-session rate limit on outbound application messages
//! (issue #82).
//!
//! Venues publish per-session message limits and reject, or disconnect, a
//! session that exceeds them. A [`ThrottleConfig`] attached with
//! `with_throttle` on the [`Initiator`](crate::Initiator), the
//! [`Acceptor`](crate::Acceptor) or the [`EngineBuilder`](crate::EngineBuilder)
//! holds every new outbound application message of a session to one or more
//! **budgets**, each a token bucket:
//!
//! - a budget starts with [`ThrottleBudget::burst`] tokens, and earns one
//!   back every [`ThrottleBudget::per`] / [`ThrottleBudget::rate`] (rounded
//!   up to whole nanoseconds), up to `burst`;
//! - a message takes one token when it is about to be framed. Over any
//!   half-open interval `[t, t + per)` a budget lets at most `burst + rate - 1`
//!   messages through, so `burst = 1` (the default) keeps a session within a
//!   venue limit of `rate` messages per `per`, measured over any window;
//! - a message that finds no token is handled by the budget's
//!   [`ThrottlePolicy`]: [`ThrottlePolicy::Queue`] holds it, in order, until
//!   a token is earned, up to `max_depth` messages, and refuses one beyond
//!   that; [`ThrottlePolicy::Refuse`] refuses it at once. A refusal reports
//!   [`NotSentReason::Throttled`](crate::NotSentReason::Throttled) through
//!   [`Connection::send_tracked`](crate::Connection::send_tracked). With a
//!   throttle attached, prefer `send_tracked`: a plain
//!   [`Connection::send`](crate::Connection::send) the throttle refuses is
//!   only logged (a warning, counted per budget).
//!
//! An optional classifier ([`ThrottleConfigBuilder::classifier`]) puts each
//! message in one budget, so separate budgets can keep, for example, order
//! cancels from waiting behind new orders.
//!
//! # What is never throttled
//!
//! Administrative messages (Logon, Logout, Heartbeat, TestRequest,
//! ResendRequest, SequenceReset and every gap fill, Reject, XmlMessage) are
//! never throttled: they are what keeps the session legal, and a Heartbeat
//! held behind a budget would let the counterparty time the session out. A
//! replay, the answer to a `ResendRequest` (2) or the resend a counterparty's
//! `NextExpectedMsgSeqNum` (789) asks for, is never throttled either: it
//! resends frames that already went through the throttle when they were
//! first sent, under their original numbers. Neither takes a token.
//!
//! # Order
//!
//! Within one budget, messages leave in the order they were handed in: a
//! message never overtakes one held before it in the same budget, even when
//! a token is free. Across budgets a message whose budget has a token goes
//! ahead of one held in another budget: that is what separate budgets are
//! for. A consequence to plan for: a cancel in a budget of its own can
//! overtake the very order it cancels while that order is still held in the
//! order budget, and the venue then rejects the cancel for an unknown order.
//! With a single budget (no classifier) the order is the order of
//! [`Connection::send`](crate::Connection::send) calls. Messages released at
//! the same moment from several budgets leave in the order they were handed
//! in. The `MsgSeqNum` (34) is assigned when a message is framed, so the
//! numbers on the wire stay unique and in order whatever the budgets do.
//!
//! The throttle sits between the outbound queue and the outbound gate: a held
//! message goes through
//! [`Application::to_app_checked`](crate::Application::to_app_checked) when it
//! is released, not when it is queued, so a gate closed meanwhile still stops
//! it, and it spends no `MsgSeqNum` and touches no store until then. A message
//! the gate vetoes, or whose body the engine refuses, gives its token back.
//!
//! # Timer resolution
//!
//! A held message waits on a timer, and Tokio's timer has a resolution of one
//! millisecond: the session wakes at most once a millisecond to release held
//! messages, and each wake-up releases every held message whose token has
//! been earned, up to the budget's burst. A budget whose tokens come faster
//! than one per millisecond therefore keeps its rate while messages are held
//! only with a burst of at least `rate * 1 ms / per`, rounded up (10 for
//! 10 000 messages per second). With a smaller burst it releases at most
//! `burst` messages per millisecond: slower than its rate, never faster. The
//! session logs a warning when it starts with such a budget. A message that
//! finds a token when it is sent does not wait on the timer.
//!
//! # Time
//!
//! The decision is synchronous and takes the time as an argument, per
//! ADR-0002 (`doc/adr/0002-session-driver.md`): the reactor supplies the
//! monotonic time it reads from Tokio's clock, so a test that pauses the
//! clock (`tokio::time::pause`) drives the throttle deterministically, and
//! the bucket is unit-tested with synthetic instants. The token buckets and
//! the messages they hold are run by the sans-IO session core
//! (`ironfix_session::Throttle`, owned by `ironfix_session::SessionCore`,
//! issue #91); this module keeps the configuration, its validation and the
//! classifier, and hands the core one `TokenBucketSpec` per budget. The tokens start full
//! when the session becomes Active, and a new session (a reconnect) starts
//! with full budgets again.

use crate::outbound::OutboundMessage;
use ironfix_session::TokenBucketSpec;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

/// Most budgets one [`ThrottleConfig`] holds, the default one included.
pub const MAX_THROTTLE_BUDGETS: usize = 16;

/// Largest `max_depth` a [`ThrottlePolicy::Queue`] accepts, in messages.
///
/// A held message is kept whole in memory until it is released, so the bound
/// is also what one budget can hold: `max_depth` times the size of the
/// largest message the application sends. A budget's queue keeps the
/// capacity its deepest fill gave it for the rest of the session: `max_depth`
/// bounds the messages held, and the allocation may round up past it (128
/// slots for a depth of 65), so filling and draining it again allocates
/// nothing; that capacity is given back when the session ends.
pub const MAX_THROTTLE_QUEUE_DEPTH: usize = 65_536;

/// Longest window a [`ThrottleBudget`] accepts: one day.
pub const MAX_THROTTLE_WINDOW: Duration = Duration::from_secs(86_400);

/// The `max_depth` of the [`ThrottlePolicy::Queue`] a [`ThrottleBudget`]
/// starts with, in messages: the default capacity of the outbound queue.
pub const DEFAULT_THROTTLE_QUEUE_DEPTH: usize = 1_024;

/// The resolution of the timer a held message waits on: Tokio's.
const TIMER_RESOLUTION: Duration = Duration::from_millis(1);

/// Identifies one budget of a [`ThrottleConfig`]: its position in the order
/// the budgets were added, the default budget being 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct BudgetId(u8);

impl BudgetId {
    /// The default budget: the one passed to [`ThrottleConfig::builder`],
    /// which every message goes to when there is no classifier.
    pub const DEFAULT: Self = Self(0);

    /// The budget at `index`: 0 is the default budget, 1 the first one added
    /// with [`ThrottleConfigBuilder::budget`], and so on.
    #[must_use]
    pub const fn new(index: u8) -> Self {
        Self(index)
    }

    /// The budget's index.
    #[must_use]
    pub const fn index(self) -> u8 {
        self.0
    }

    /// The budget's position in the configuration's list.
    #[must_use]
    const fn slot(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for BudgetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// What a budget does with a message that finds no token.
///
/// `#[non_exhaustive]`: match it with a wildcard arm, so that a policy added
/// later is not a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ThrottlePolicy {
    /// Hold the message, in order behind the ones already held in this
    /// budget, until a token is earned; refuse it, as
    /// [`NotSentReason::Throttled`](crate::NotSentReason::Throttled), when
    /// `max_depth` messages are held already.
    Queue {
        /// Most messages the budget holds, from 1 to
        /// [`MAX_THROTTLE_QUEUE_DEPTH`].
        max_depth: usize,
    },
    /// Refuse the message at once, as
    /// [`NotSentReason::Throttled`](crate::NotSentReason::Throttled).
    Refuse,
}

/// One budget of a [`ThrottleConfig`]: a token bucket and the policy for a
/// message that finds it empty.
///
/// It starts with `burst` tokens and earns one every `per / rate`, rounded
/// up to whole nanoseconds, up to `burst`. Over any half-open interval
/// `[t, t + per)` at most `burst + rate - 1` messages go through it; with the default
/// `burst` of 1 that is `rate`, which keeps a session within a venue limit of
/// `rate` messages per `per`, however the venue places its window.
///
/// The values are checked by [`ThrottleConfigBuilder::build`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ThrottleBudget {
    /// Messages earned per `per`.
    rate: u32,
    /// The window `rate` is counted over.
    per: Duration,
    /// Most tokens the budget holds.
    burst: u32,
    /// What a message that finds no token gets.
    policy: ThrottlePolicy,
}

impl ThrottleBudget {
    /// A budget of `rate` messages per `per`, with a burst of 1 and the
    /// policy [`ThrottlePolicy::Queue`] with a `max_depth` of
    /// [`DEFAULT_THROTTLE_QUEUE_DEPTH`].
    ///
    /// # Arguments
    /// * `rate` - Messages per window, at least 1
    /// * `per` - The window, above zero and at most [`MAX_THROTTLE_WINDOW`]
    #[must_use]
    pub const fn new(rate: u32, per: Duration) -> Self {
        Self {
            rate,
            per,
            burst: 1,
            policy: ThrottlePolicy::Queue {
                max_depth: DEFAULT_THROTTLE_QUEUE_DEPTH,
            },
        }
    }

    /// Sets the burst: how many tokens the budget holds, so how many
    /// messages can go out at once after a quiet period (default 1).
    ///
    /// A budget whose tokens come faster than one per millisecond needs a
    /// burst of at least `rate * 1 ms / per` to keep its rate while messages
    /// are held: see "Timer resolution" in the [module documentation](self).
    ///
    /// # Arguments
    /// * `burst` - Most tokens, in messages, at least 1
    #[must_use]
    pub const fn with_burst(mut self, burst: u32) -> Self {
        self.burst = burst;
        self
    }

    /// Sets what a message that finds no token gets (default
    /// [`ThrottlePolicy::Queue`] with a `max_depth` of
    /// [`DEFAULT_THROTTLE_QUEUE_DEPTH`]).
    #[must_use]
    pub const fn with_policy(mut self, policy: ThrottlePolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Messages earned per window.
    #[must_use]
    pub const fn rate(&self) -> u32 {
        self.rate
    }

    /// The window the rate is counted over.
    #[must_use]
    pub const fn per(&self) -> Duration {
        self.per
    }

    /// Most tokens the budget holds, in messages.
    #[must_use]
    pub const fn burst(&self) -> u32 {
        self.burst
    }

    /// What a message that finds no token gets.
    #[must_use]
    pub const fn policy(&self) -> ThrottlePolicy {
        self.policy
    }

    /// The time it takes to earn one token: `per / rate`, rounded **up** to
    /// whole nanoseconds, so that `rate` tokens never take less than `per`,
    /// and never below one nanosecond.
    #[must_use]
    fn spacing(&self) -> Duration {
        let nanos = self
            .per
            .as_nanos()
            .div_ceil(u128::from(self.rate.max(1)))
            .max(1);
        // `per` is at most a day, about 8.6e13 ns, so this always fits.
        u64::try_from(nanos).map_or(self.per, Duration::from_nanos)
    }

    /// The smallest burst with which this budget keeps its rate while
    /// messages are held, given the release timer's resolution: the tokens
    /// earned in [`TIMER_RESOLUTION`], rounded up, and at least 1.
    #[must_use]
    fn burst_for_timer(&self) -> u32 {
        let per_tick = TIMER_RESOLUTION
            .as_nanos()
            .div_ceil(self.spacing().as_nanos().max(1))
            .max(1);
        u32::try_from(per_tick).unwrap_or(u32::MAX)
    }

    /// The token bucket the sans-IO core runs for this budget: its spacing,
    /// its burst (at least 1) and, under [`ThrottlePolicy::Queue`], its
    /// depth.
    fn bucket_spec(&self) -> TokenBucketSpec {
        let max_depth = match self.policy {
            ThrottlePolicy::Queue { max_depth } => Some(max_depth),
            ThrottlePolicy::Refuse => None,
        };
        TokenBucketSpec::new(self.spacing(), self.burst.max(1), max_depth)
    }

    /// Checks the values for the budget `budget`.
    fn validate(&self, budget: BudgetId) -> Result<(), ThrottleConfigError> {
        if self.rate == 0 {
            return Err(ThrottleConfigError::ZeroRate { budget });
        }
        if self.burst == 0 {
            return Err(ThrottleConfigError::ZeroBurst { budget });
        }
        if self.per.is_zero() || self.per > MAX_THROTTLE_WINDOW {
            return Err(ThrottleConfigError::WindowOutOfRange {
                budget,
                per: self.per,
            });
        }
        if let ThrottlePolicy::Queue { max_depth } = self.policy
            && !(1..=MAX_THROTTLE_QUEUE_DEPTH).contains(&max_depth)
        {
            return Err(ThrottleConfigError::QueueDepthOutOfRange { budget, max_depth });
        }
        Ok(())
    }
}

/// The classifier a [`ThrottleConfig`] puts each message in a budget with.
type Classifier = Arc<dyn Fn(&OutboundMessage) -> BudgetId + Send + Sync>;

/// Why a [`ThrottleConfigBuilder`] refused its configuration.
///
/// Every variant that concerns one budget names it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ThrottleConfigError {
    /// A budget's rate is zero: it would never earn a token.
    #[error("throttle budget {budget}: the rate must be at least 1 message per window, got 0")]
    ZeroRate {
        /// The budget at fault.
        budget: BudgetId,
    },
    /// A budget's burst is zero: it could never hold a token.
    #[error("throttle budget {budget}: the burst must be at least 1 message, got 0")]
    ZeroBurst {
        /// The budget at fault.
        budget: BudgetId,
    },
    /// A budget's window is zero or longer than [`MAX_THROTTLE_WINDOW`].
    #[error(
        "throttle budget {budget}: the window must be above zero and at most 86400 s, got {per:?}"
    )]
    WindowOutOfRange {
        /// The budget at fault.
        budget: BudgetId,
        /// The window configured.
        per: Duration,
    },
    /// A budget's [`ThrottlePolicy::Queue`] has a `max_depth` of zero or
    /// above [`MAX_THROTTLE_QUEUE_DEPTH`].
    #[error(
        "throttle budget {budget}: the queue depth must be between 1 and 65536 messages, got \
         {max_depth}"
    )]
    QueueDepthOutOfRange {
        /// The budget at fault.
        budget: BudgetId,
        /// The depth configured.
        max_depth: usize,
    },
    /// More than [`MAX_THROTTLE_BUDGETS`] budgets, the default one included.
    #[error("a throttle holds at most 16 budgets, got {count}")]
    TooManyBudgets {
        /// How many budgets were configured.
        count: usize,
    },
}

/// The outbound throttle of a session: its budgets and, optionally, the
/// classifier that puts each message in one.
///
/// Built with [`ThrottleConfig::builder`], which checks every value, and
/// attached with `with_throttle` on the [`Initiator`](crate::Initiator), the
/// [`Acceptor`](crate::Acceptor) or the [`EngineBuilder`](crate::EngineBuilder).
/// Each session of the engine gets its own budgets from it. Cloning is cheap.
/// See the [module documentation](self) for what is throttled and in what
/// order messages leave.
///
/// # Examples
///
/// New orders limited to 50 per second, held up to 500 deep; cancels in a
/// budget of their own, 100 per second, so they never wait behind new
/// orders:
///
/// ```
/// use ironfix_core::message::MsgType;
/// use ironfix_engine::throttle::{BudgetId, ThrottleBudget, ThrottleConfig, ThrottlePolicy};
/// use std::time::Duration;
///
/// # fn main() -> Result<(), ironfix_engine::throttle::ThrottleConfigError> {
/// const CANCELS: BudgetId = BudgetId::new(1);
/// let orders = ThrottleBudget::new(50, Duration::from_secs(1))
///     .with_policy(ThrottlePolicy::Queue { max_depth: 500 });
/// let cancels = ThrottleBudget::new(100, Duration::from_secs(1));
/// let throttle = ThrottleConfig::builder(orders)
///     .budget(cancels)
///     .classifier(|message| match message.msg_type() {
///         MsgType::OrderCancelRequest => CANCELS,
///         _ => BudgetId::DEFAULT,
///     })
///     .build()?;
/// assert_eq!(throttle.budgets().len(), 2);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct ThrottleConfig {
    /// The budgets, the default one first.
    budgets: Vec<ThrottleBudget>,
    /// Puts each message in a budget; every message goes to the default one
    /// without it.
    classifier: Option<Classifier>,
}

/// Written by hand: the classifier is a closure, which is not `Debug`.
impl fmt::Debug for ThrottleConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThrottleConfig")
            .field("budgets", &self.budgets)
            .field("classifier", &self.classifier.is_some())
            .finish()
    }
}

impl ThrottleConfig {
    /// Starts a configuration whose default budget ([`BudgetId::DEFAULT`]) is
    /// `default`.
    pub fn builder(default: ThrottleBudget) -> ThrottleConfigBuilder {
        ThrottleConfigBuilder {
            budgets: vec![default],
            classifier: None,
        }
    }

    /// The budgets, in [`BudgetId`] order: the default one first.
    #[must_use]
    pub fn budgets(&self) -> &[ThrottleBudget] {
        &self.budgets
    }

    /// The budget `id`, if this configuration defines it.
    #[must_use]
    pub fn budget(&self, id: BudgetId) -> Option<&ThrottleBudget> {
        self.budgets.get(id.slot())
    }

    /// The budget `message` is held to: the classifier's choice, or
    /// [`BudgetId::DEFAULT`] without a classifier, and also when the
    /// classifier names a budget this configuration does not define.
    #[must_use]
    pub fn classify(&self, message: &OutboundMessage) -> BudgetId {
        self.classify_checked(message).unwrap_or(BudgetId::DEFAULT)
    }

    /// The budgets whose burst is too small to keep their rate while
    /// messages are held, given the release timer's resolution (see "Timer
    /// resolution" in the [module documentation](self)), each with the
    /// smallest burst that would.
    pub(crate) fn timer_limited(&self) -> impl Iterator<Item = (BudgetId, &ThrottleBudget, u32)> {
        (0..=u8::MAX)
            .zip(&self.budgets)
            .filter_map(|(index, budget)| {
                let needed = budget.burst_for_timer();
                (budget.burst < needed).then_some((BudgetId::new(index), budget, needed))
            })
    }

    /// The token buckets the sans-IO core runs for this configuration, one
    /// per budget in [`BudgetId`] order (issue #91, stage 6c).
    pub(crate) fn bucket_specs(&self) -> impl ExactSizeIterator<Item = TokenBucketSpec> + '_ {
        self.budgets.iter().map(ThrottleBudget::bucket_spec)
    }

    /// [`ThrottleConfig::classify`], reporting as `Err` a budget the
    /// classifier named that this configuration does not define, so the
    /// reactor can say so once.
    pub(crate) fn classify_checked(&self, message: &OutboundMessage) -> Result<BudgetId, BudgetId> {
        let Some(classifier) = &self.classifier else {
            return Ok(BudgetId::DEFAULT);
        };
        let id = classifier(message);
        if id.slot() < self.budgets.len() {
            Ok(id)
        } else {
            Err(id)
        }
    }
}

/// Builds a [`ThrottleConfig`]; see [`ThrottleConfig::builder`].
#[must_use = "builders do nothing unless .build() is called"]
pub struct ThrottleConfigBuilder {
    /// The budgets, the default one first.
    budgets: Vec<ThrottleBudget>,
    /// The classifier, if one was set.
    classifier: Option<Classifier>,
}

/// Written by hand: the classifier is a closure, which is not `Debug`.
impl fmt::Debug for ThrottleConfigBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThrottleConfigBuilder")
            .field("budgets", &self.budgets)
            .field("classifier", &self.classifier.is_some())
            .finish()
    }
}

impl ThrottleConfigBuilder {
    /// Adds a budget. It is [`BudgetId`] 1 for the first one added, 2 for the
    /// next, and so on; a classifier names it by that id.
    pub fn budget(mut self, budget: ThrottleBudget) -> Self {
        self.budgets.push(budget);
        self
    }

    /// Sets the classifier: the budget each new outbound application message
    /// is held to, by its MsgType or by anything else in its body.
    ///
    /// It runs on the session's reactor, once per message, before the
    /// outbound gate, so it must be quick and must not block. A budget it
    /// names that the configuration does not define is taken as
    /// [`BudgetId::DEFAULT`], and the session logs that once.
    pub fn classifier<F>(mut self, classifier: F) -> Self
    where
        F: Fn(&OutboundMessage) -> BudgetId + Send + Sync + 'static,
    {
        self.classifier = Some(Arc::new(classifier));
        self
    }

    /// Checks every budget and builds the configuration.
    ///
    /// # Errors
    /// [`ThrottleConfigError::TooManyBudgets`] past [`MAX_THROTTLE_BUDGETS`]
    /// budgets; otherwise the first budget, in [`BudgetId`] order, with a zero
    /// rate ([`ThrottleConfigError::ZeroRate`]), a zero burst
    /// ([`ThrottleConfigError::ZeroBurst`]), a window that is zero or longer
    /// than [`MAX_THROTTLE_WINDOW`]
    /// ([`ThrottleConfigError::WindowOutOfRange`]), or a queue depth outside
    /// 1 to [`MAX_THROTTLE_QUEUE_DEPTH`]
    /// ([`ThrottleConfigError::QueueDepthOutOfRange`]).
    pub fn build(self) -> Result<ThrottleConfig, ThrottleConfigError> {
        let count = self.budgets.len();
        if count > MAX_THROTTLE_BUDGETS {
            return Err(ThrottleConfigError::TooManyBudgets { count });
        }
        for (index, budget) in (0..=u8::MAX).zip(&self.budgets) {
            budget.validate(BudgetId::new(index))?;
        }
        Ok(ThrottleConfig {
            budgets: self.budgets,
            classifier: self.classifier,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironfix_core::message::MsgType;

    const SECOND: Duration = Duration::from_secs(1);

    /// Builds `config`, failing the test with the error.
    #[track_caller]
    fn built(builder: ThrottleConfigBuilder) -> ThrottleConfig {
        match builder.build() {
            Ok(config) => config,
            Err(err) => panic!("the test configuration must build: {err}"),
        }
    }

    #[test]
    fn test_throttle_budget_defaults_are_burst_one_and_a_bounded_queue() {
        let budget = ThrottleBudget::new(10, SECOND);
        assert_eq!(budget.rate(), 10);
        assert_eq!(budget.per(), SECOND);
        assert_eq!(budget.burst(), 1);
        assert_eq!(
            budget.policy(),
            ThrottlePolicy::Queue {
                max_depth: DEFAULT_THROTTLE_QUEUE_DEPTH
            }
        );
        let budget = budget.with_burst(4).with_policy(ThrottlePolicy::Refuse);
        assert_eq!(
            (budget.burst(), budget.policy()),
            (4, ThrottlePolicy::Refuse)
        );
    }

    #[test]
    fn test_throttle_budget_spacing_rounds_up_to_whole_nanoseconds() {
        assert_eq!(
            ThrottleBudget::new(3, SECOND).spacing(),
            Duration::from_nanos(333_333_334),
            "three tokens must never take less than the window"
        );
        assert_eq!(
            ThrottleBudget::new(4, SECOND).spacing(),
            Duration::from_millis(250)
        );
        assert_eq!(
            ThrottleBudget::new(u32::MAX, Duration::from_nanos(1)).spacing(),
            Duration::from_nanos(1),
            "never below one nanosecond"
        );
    }

    #[test]
    fn test_throttle_budget_burst_for_timer_is_a_millisecond_of_tokens() {
        assert_eq!(ThrottleBudget::new(1_000, SECOND).burst_for_timer(), 1);
        assert_eq!(ThrottleBudget::new(10_000, SECOND).burst_for_timer(), 10);
        assert_eq!(
            ThrottleBudget::new(4_096, SECOND).burst_for_timer(),
            5,
            "4.1 tokens a millisecond, rounded up"
        );
        assert_eq!(ThrottleBudget::new(50, SECOND).burst_for_timer(), 1);

        let config = built(
            ThrottleConfig::builder(ThrottleBudget::new(10_000, SECOND))
                .budget(ThrottleBudget::new(10_000, SECOND).with_burst(10))
                .budget(ThrottleBudget::new(100, SECOND)),
        );
        let limited: Vec<_> = config
            .timer_limited()
            .map(|(id, _, needed)| (id, needed))
            .collect();
        assert_eq!(limited, [(BudgetId::DEFAULT, 10)]);
    }

    #[test]
    fn test_throttle_config_build_refuses_a_zero_rate() {
        let err = ThrottleConfig::builder(ThrottleBudget::new(1, SECOND))
            .budget(ThrottleBudget::new(0, SECOND))
            .build()
            .err();
        assert_eq!(
            err,
            Some(ThrottleConfigError::ZeroRate {
                budget: BudgetId::new(1)
            }),
            "the error names the budget at fault"
        );
    }

    #[test]
    fn test_throttle_config_build_refuses_a_zero_burst() {
        let err = ThrottleConfig::builder(ThrottleBudget::new(1, SECOND).with_burst(0))
            .build()
            .err();
        assert_eq!(
            err,
            Some(ThrottleConfigError::ZeroBurst {
                budget: BudgetId::DEFAULT
            })
        );
    }

    #[test]
    fn test_throttle_config_build_refuses_a_window_out_of_range() {
        for per in [
            Duration::ZERO,
            MAX_THROTTLE_WINDOW + Duration::from_nanos(1),
        ] {
            let err = ThrottleConfig::builder(ThrottleBudget::new(1, per))
                .build()
                .err();
            assert_eq!(
                err,
                Some(ThrottleConfigError::WindowOutOfRange {
                    budget: BudgetId::DEFAULT,
                    per
                })
            );
        }
        let longest = ThrottleConfig::builder(ThrottleBudget::new(1, MAX_THROTTLE_WINDOW)).build();
        assert!(longest.is_ok(), "a window of exactly one day is accepted");
        let shortest =
            ThrottleConfig::builder(ThrottleBudget::new(1, Duration::from_nanos(1))).build();
        assert!(shortest.is_ok(), "a window of one nanosecond is accepted");
    }

    #[test]
    fn test_throttle_config_build_refuses_a_queue_depth_out_of_range() {
        for max_depth in [0, MAX_THROTTLE_QUEUE_DEPTH + 1] {
            let budget =
                ThrottleBudget::new(1, SECOND).with_policy(ThrottlePolicy::Queue { max_depth });
            let err = ThrottleConfig::builder(budget).build().err();
            assert_eq!(
                err,
                Some(ThrottleConfigError::QueueDepthOutOfRange {
                    budget: BudgetId::DEFAULT,
                    max_depth
                })
            );
        }
        let deepest = ThrottleBudget::new(1, SECOND).with_policy(ThrottlePolicy::Queue {
            max_depth: MAX_THROTTLE_QUEUE_DEPTH,
        });
        assert!(ThrottleConfig::builder(deepest).build().is_ok());
    }

    #[test]
    fn test_throttle_config_build_refuses_too_many_budgets() {
        let budget = ThrottleBudget::new(1, SECOND);
        let mut builder = ThrottleConfig::builder(budget);
        for _ in 1..MAX_THROTTLE_BUDGETS {
            builder = builder.budget(budget);
        }
        let config = built(builder);
        assert_eq!(config.budgets().len(), MAX_THROTTLE_BUDGETS);

        let mut builder = ThrottleConfig::builder(budget);
        for _ in 0..MAX_THROTTLE_BUDGETS {
            builder = builder.budget(budget);
        }
        assert_eq!(
            builder.build().err(),
            Some(ThrottleConfigError::TooManyBudgets {
                count: MAX_THROTTLE_BUDGETS + 1
            })
        );
    }

    #[test]
    fn test_throttle_config_error_messages_name_the_budget_and_the_value() {
        let err = ThrottleConfigError::QueueDepthOutOfRange {
            budget: BudgetId::new(2),
            max_depth: 0,
        };
        assert_eq!(
            err.to_string(),
            "throttle budget 2: the queue depth must be between 1 and 65536 messages, got 0"
        );
        let err = ThrottleConfigError::WindowOutOfRange {
            budget: BudgetId::new(1),
            per: Duration::ZERO,
        };
        assert!(err.to_string().contains("got 0ns"), "{err}");
    }

    #[test]
    fn test_throttle_config_classify_falls_back_to_the_default_budget() {
        let config = built(
            ThrottleConfig::builder(ThrottleBudget::new(1, SECOND))
                .budget(ThrottleBudget::new(1, SECOND))
                .classifier(|message| match message.msg_type() {
                    MsgType::OrderCancelRequest => BudgetId::new(1),
                    MsgType::Quote => BudgetId::new(9),
                    _ => BudgetId::DEFAULT,
                }),
        );
        let cancel = OutboundMessage::new(MsgType::OrderCancelRequest);
        let order = OutboundMessage::new(MsgType::NewOrderSingle);
        let quote = OutboundMessage::new(MsgType::Quote);
        assert_eq!(config.classify(&cancel), BudgetId::new(1));
        assert_eq!(config.classify(&order), BudgetId::DEFAULT);
        assert_eq!(
            config.classify(&quote),
            BudgetId::DEFAULT,
            "a budget the configuration does not define"
        );
        assert_eq!(config.classify_checked(&quote), Err(BudgetId::new(9)));
        assert!(config.budget(BudgetId::new(1)).is_some());
        assert!(config.budget(BudgetId::new(2)).is_none());

        let unclassified = built(ThrottleConfig::builder(ThrottleBudget::new(1, SECOND)));
        assert_eq!(unclassified.classify(&cancel), BudgetId::DEFAULT);
        assert!(format!("{unclassified:?}").contains("classifier: false"));
        assert!(format!("{config:?}").contains("classifier: true"));
    }
}
