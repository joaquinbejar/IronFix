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
//! the bucket is unit-tested with synthetic instants. The tokens start full
//! when the session becomes Active, and a new session (a reconnect) starts
//! with full budgets again.

use crate::outbound::OutboundMessage;
use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

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

/// What [`Throttle::admit`] decided for a message.
#[derive(Debug)]
pub(crate) enum Admission<T> {
    /// A token was taken: frame the message now.
    Now(T),
    /// The message is held in its budget's queue until a token is earned.
    Held,
    /// The budget refuses it: no token and no room to hold it, or a
    /// [`ThrottlePolicy::Refuse`] budget with no token.
    Refused(T),
}

/// One budget at run time: its tokens, and the messages held for them.
#[derive(Debug)]
struct Bucket<T> {
    /// Time to earn one token.
    spacing: Duration,
    /// Most tokens.
    burst: u32,
    /// Tokens held now (as of `refilled_at`), the reserved ones included.
    tokens: u32,
    /// Tokens reserved by messages that may go but whose frame is not fed
    /// yet: still in the bucket, so the clock runs as if they had not been
    /// taken, and taken only at the feed ([`Throttle::charge_at`]).
    reserved: u32,
    /// When the tokens were last brought up to date: the instant the last
    /// earned token was earned, or the last time the bucket was found full.
    refilled_at: Instant,
    /// Most messages held, or `None` under [`ThrottlePolicy::Refuse`].
    max_depth: Option<usize>,
    /// The messages held, oldest first, each with its arrival ticket.
    queue: VecDeque<(u64, T)>,
}

impl<T> Bucket<T> {
    /// A full bucket for `budget` at `now`. The queue grows on first use and
    /// keeps its capacity, so a session that throttles in steady state does
    /// not allocate per message.
    fn new(budget: &ThrottleBudget, now: Instant) -> Self {
        Self {
            spacing: budget.spacing(),
            burst: budget.burst.max(1),
            tokens: budget.burst.max(1),
            reserved: 0,
            refilled_at: now,
            max_depth: match budget.policy {
                ThrottlePolicy::Queue { max_depth } => Some(max_depth),
                ThrottlePolicy::Refuse => None,
            },
            queue: VecDeque::new(),
        }
    }

    /// Brings the tokens up to date at `now`: one per whole `spacing` since
    /// `refilled_at`, up to `burst`. A full bucket earns nothing and moves
    /// `refilled_at` to `now`, so time spent full is not banked. An instant
    /// earlier than `refilled_at` earns nothing.
    fn refill(&mut self, now: Instant) {
        if self.tokens >= self.burst {
            if now > self.refilled_at {
                self.refilled_at = now;
            }
            return;
        }
        let Some(elapsed) = now.checked_duration_since(self.refilled_at) else {
            return;
        };
        // `spacing` is at least one nanosecond, so the division is defined.
        let earned = elapsed.as_nanos() / self.spacing.as_nanos().max(1);
        if earned == 0 {
            return;
        }
        // The bucket is not full here, so `room` is at least one token.
        let Some(room) = self.burst.checked_sub(self.tokens) else {
            return;
        };
        match u32::try_from(earned) {
            Ok(earned) if earned < room => {
                // `earned < burst - tokens`, so the sum stays below `burst`.
                self.tokens = self.tokens.checked_add(earned).unwrap_or(self.burst);
                // The token earned last was earned at `refilled_at + earned *
                // spacing`; the time since then counts toward the next one.
                // Out of range only for absurd instants, and then the
                // progress toward the next token is dropped, never granted.
                self.refilled_at = self
                    .spacing
                    .checked_mul(earned)
                    .and_then(|span| self.refilled_at.checked_add(span))
                    .unwrap_or(now);
            }
            _ => {
                self.tokens = self.burst;
                self.refilled_at = now;
            }
        }
    }

    /// Tokens free to reserve: held and not reserved.
    fn available(&self) -> u32 {
        self.tokens.saturating_sub(self.reserved)
    }

    /// Reserves a token at `now`, if one is free. The token stays in the
    /// bucket until the frame is fed, so the clock is not moved.
    fn reserve(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.available() == 0 {
            return false;
        }
        match self.reserved.checked_add(1) {
            Some(reserved) => {
                self.reserved = reserved;
                true
            }
            None => false,
        }
    }

    /// When the message at the head of the queue can take a token, as of
    /// `now`: `now` if a token is there already, otherwise when the next one
    /// is earned. `None` when nothing is held.
    fn ready_at(&mut self, now: Instant) -> Option<Instant> {
        self.queue.front()?;
        self.refill(now);
        if self.available() > 0 {
            return Some(now);
        }
        // `refilled_at` is never after `now` and `spacing` is at most a day,
        // so this is in range on every platform Tokio supports.
        self.refilled_at.checked_add(self.spacing)
    }
}

/// The run-time state of a session's throttle: one bucket per budget, and
/// the messages held, of type `T`.
///
/// Every decision takes `now`, the driver's monotonic time, and reads no
/// clock (ADR-0002).
#[derive(Debug)]
pub(crate) struct Throttle<T> {
    /// One bucket per budget, in [`BudgetId`] order.
    buckets: Vec<Bucket<T>>,
    /// The ticket the next held message gets: arrival order across budgets.
    next_ticket: u64,
    /// Messages held, across every budget.
    held: usize,
}

impl<T> Throttle<T> {
    /// Full budgets for `config`, at `now`.
    #[must_use]
    pub(crate) fn new(config: &ThrottleConfig, now: Instant) -> Self {
        Self {
            buckets: config
                .budgets
                .iter()
                .map(|budget| Bucket::new(budget, now))
                .collect(),
            next_ticket: 0,
            held: 0,
        }
    }

    /// The bucket for `budget`, falling back to the default one.
    fn bucket_mut(&mut self, budget: BudgetId) -> Option<&mut Bucket<T>> {
        let slot = if budget.slot() < self.buckets.len() {
            budget.slot()
        } else {
            BudgetId::DEFAULT.slot()
        };
        self.buckets.get_mut(slot)
    }

    /// Decides what becomes of `item`, a new message of `budget`, at `now`.
    ///
    /// It reserves a token (taken at the feed, [`Throttle::charge_at`]) and
    /// goes now only when its budget holds nothing
    /// already, so it never overtakes a message of its own budget. Otherwise
    /// it is held, under [`ThrottlePolicy::Queue`] with room left, or refused.
    pub(crate) fn admit(&mut self, budget: BudgetId, item: T, now: Instant) -> Admission<T> {
        let ticket = self.next_ticket;
        let Some(bucket) = self.bucket_mut(budget) else {
            // A configuration always holds the default budget.
            return Admission::Now(item);
        };
        if bucket.queue.is_empty() && bucket.reserve(now) {
            return Admission::Now(item);
        }
        match bucket.max_depth {
            Some(max_depth) if bucket.queue.len() < max_depth => {
                bucket.queue.push_back((ticket, item));
                // A ticket per held message, reset whenever nothing is held:
                // a u64 cannot run out within one busy period.
                self.next_ticket = ticket.checked_add(1).unwrap_or(ticket);
                self.held = self.held.checked_add(1).unwrap_or(self.held);
                Admission::Held
            }
            _ => Admission::Refused(item),
        }
    }

    /// Releases, at `now`, the held message that may go: of the budgets
    /// whose head can take a token, the head that was handed in first. Its
    /// token is reserved, and taken by [`Throttle::charge_at`] at the feed. `None` when no held message may go yet.
    pub(crate) fn release(&mut self, now: Instant) -> Option<(BudgetId, T)> {
        let mut first: Option<(usize, u64)> = None;
        for (slot, bucket) in self.buckets.iter_mut().enumerate() {
            let Some(&(ticket, _)) = bucket.queue.front() else {
                continue;
            };
            bucket.refill(now);
            if bucket.available() == 0 {
                continue;
            }
            if first.is_none_or(|(_, earliest)| ticket < earliest) {
                first = Some((slot, ticket));
            }
        }
        let (slot, _) = first?;
        let bucket = self.buckets.get_mut(slot)?;
        if !bucket.reserve(now) {
            return None;
        }
        let (_, item) = bucket.queue.pop_front()?;
        // The message just taken out was counted, so `held` is at least 1.
        debug_assert!(self.held > 0, "a held message was counted");
        if let Some(held) = self.held.checked_sub(1) {
            self.held = held;
        }
        if self.held == 0 {
            self.next_ticket = 0;
        }
        let id = u8::try_from(slot).map_or(BudgetId::DEFAULT, BudgetId::new);
        Some((id, item))
    }

    /// When the next held message may go, as of `now`: `now` when one may go
    /// already, otherwise when the first budget with a message held earns a
    /// token. `None` when nothing is held.
    ///
    /// [`Throttle::release`] at that instant or later releases a message: it
    /// brings the tokens up to date by the same rule.
    pub(crate) fn next_release(&mut self, now: Instant) -> Option<Instant> {
        if self.held == 0 {
            return None;
        }
        self.buckets
            .iter_mut()
            .filter_map(|bucket| bucket.ready_at(now))
            .min()
    }

    /// Takes, at `now`, the token a message of `budget` reserved when it was
    /// admitted or released, now that its frame is fed. The bucket is brought
    /// up to date at `now` first, with the reserved token still in it, so the
    /// result is exactly what taking the token at `now` gives, whatever the
    /// time spent in between (the outbound gate, the store): a full bucket
    /// earned nothing meanwhile and its clock restarts at `now`.
    pub(crate) fn charge_at(&mut self, budget: BudgetId, now: Instant) {
        if let Some(bucket) = self.bucket_mut(budget)
            && let Some(reserved) = bucket.reserved.checked_sub(1)
        {
            bucket.refill(now);
            bucket.reserved = reserved;
            if let Some(left) = bucket.tokens.checked_sub(1) {
                bucket.tokens = left;
            }
        }
    }

    /// Releases the token a message of `budget` reserved and did not use:
    /// the outbound gate vetoed it, or its body could not be framed. The
    /// token was never taken, so the bucket is as if the message had not
    /// been sent.
    pub(crate) fn refund(&mut self, budget: BudgetId) {
        if let Some(bucket) = self.bucket_mut(budget)
            && let Some(reserved) = bucket.reserved.checked_sub(1)
        {
            bucket.reserved = reserved;
        }
    }

    /// How many messages are held, across every budget.
    #[must_use]
    pub(crate) const fn held(&self) -> usize {
        self.held
    }

    /// Removes every held message, budget by budget, each with its budget.
    pub(crate) fn drain(&mut self) -> impl Iterator<Item = (BudgetId, T)> + '_ {
        self.held = 0;
        self.next_ticket = 0;
        self.buckets
            .iter_mut()
            .enumerate()
            .flat_map(|(slot, bucket)| {
                let id = u8::try_from(slot).map_or(BudgetId::DEFAULT, BudgetId::new);
                bucket.queue.drain(..).map(move |(_, item)| (id, item))
            })
    }
}

#[cfg(test)]
impl<T> Throttle<T> {
    /// [`Throttle::admit`] for a message fed at once: a reserved token is
    /// charged at `now`.
    fn admit_sent(&mut self, budget: BudgetId, item: T, now: Instant) -> Admission<T> {
        let admission = self.admit(budget, item, now);
        if matches!(admission, Admission::Now(_)) {
            self.charge_at(budget, now);
        }
        admission
    }

    /// [`Throttle::release`] for a message fed at once.
    fn release_sent(&mut self, now: Instant) -> Option<(BudgetId, T)> {
        let released = self.release(now);
        if let Some((budget, _)) = &released {
            self.charge_at(*budget, now);
        }
        released
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

    /// A one-budget throttle at `t0`.
    fn single(budget: ThrottleBudget, t0: Instant) -> Throttle<u32> {
        Throttle::new(&built(ThrottleConfig::builder(budget)), t0)
    }

    #[track_caller]
    fn assert_now(admission: Admission<u32>, expected: u32) {
        match admission {
            Admission::Now(item) => assert_eq!(item, expected),
            other => panic!("expected Now({expected}), got {other:?}"),
        }
    }

    #[track_caller]
    fn assert_held(admission: Admission<u32>) {
        assert!(
            matches!(admission, Admission::Held),
            "expected Held, got {admission:?}"
        );
    }

    #[track_caller]
    fn assert_refused(admission: Admission<u32>, expected: u32) {
        match admission {
            Admission::Refused(item) => assert_eq!(item, expected),
            other => panic!("expected Refused({expected}), got {other:?}"),
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

    #[test]
    fn test_throttle_burst_goes_at_once_then_one_per_spacing() {
        let t0 = Instant::now();
        let mut throttle = single(ThrottleBudget::new(4, SECOND).with_burst(3), t0);
        for item in 0..3 {
            assert_now(throttle.admit_sent(BudgetId::DEFAULT, item, t0), item);
        }
        assert_held(throttle.admit_sent(BudgetId::DEFAULT, 3, t0));
        assert_held(throttle.admit_sent(BudgetId::DEFAULT, 4, t0));
        assert_eq!(throttle.held(), 2);

        let spacing = Duration::from_millis(250);
        assert_eq!(throttle.next_release(t0), Some(t0 + spacing));
        let just_before = t0 + spacing - Duration::from_nanos(1);
        assert!(
            throttle.release_sent(just_before).is_none(),
            "not earned yet"
        );
        assert_eq!(
            throttle.release_sent(t0 + spacing),
            Some((BudgetId::DEFAULT, 3)),
            "the head goes first"
        );
        assert_eq!(throttle.next_release(t0 + spacing), Some(t0 + 2 * spacing));
        assert_eq!(
            throttle.release_sent(t0 + 2 * spacing),
            Some((BudgetId::DEFAULT, 4))
        );
        assert_eq!(throttle.held(), 0);
        assert_eq!(throttle.next_release(t0 + 2 * spacing), None);
    }

    #[test]
    fn test_throttle_next_release_is_now_when_a_token_is_waiting() {
        let t0 = Instant::now();
        let mut throttle = single(ThrottleBudget::new(1, SECOND), t0);
        assert_now(throttle.admit_sent(BudgetId::DEFAULT, 1, t0), 1);
        assert_held(throttle.admit_sent(BudgetId::DEFAULT, 2, t0));
        let later = t0 + 5 * SECOND;
        assert_eq!(
            throttle.next_release(later),
            Some(later),
            "a token was earned while the release waited"
        );
        assert_eq!(throttle.release_sent(later), Some((BudgetId::DEFAULT, 2)));
    }

    #[test]
    fn test_throttle_refuse_policy_never_holds() {
        let t0 = Instant::now();
        let mut throttle = single(
            ThrottleBudget::new(2, SECOND)
                .with_burst(2)
                .with_policy(ThrottlePolicy::Refuse),
            t0,
        );
        assert_now(throttle.admit_sent(BudgetId::DEFAULT, 1, t0), 1);
        assert_now(throttle.admit_sent(BudgetId::DEFAULT, 2, t0), 2);
        assert_refused(throttle.admit_sent(BudgetId::DEFAULT, 3, t0), 3);
        assert_eq!(throttle.held(), 0);
        assert_eq!(throttle.next_release(t0), None);
        let half = t0 + Duration::from_millis(500);
        assert_now(throttle.admit_sent(BudgetId::DEFAULT, 4, half), 4);
        assert_refused(throttle.admit_sent(BudgetId::DEFAULT, 5, half), 5);
    }

    #[test]
    fn test_throttle_queue_refuses_past_its_depth() {
        let t0 = Instant::now();
        let mut throttle = single(
            ThrottleBudget::new(1, SECOND).with_policy(ThrottlePolicy::Queue { max_depth: 2 }),
            t0,
        );
        assert_now(throttle.admit_sent(BudgetId::DEFAULT, 1, t0), 1);
        assert_held(throttle.admit_sent(BudgetId::DEFAULT, 2, t0));
        assert_held(throttle.admit_sent(BudgetId::DEFAULT, 3, t0));
        assert_refused(throttle.admit_sent(BudgetId::DEFAULT, 4, t0), 4);
        assert_eq!(throttle.held(), 2);
    }

    #[test]
    fn test_throttle_budgets_are_independent() {
        let t0 = Instant::now();
        let config = built(
            ThrottleConfig::builder(ThrottleBudget::new(1, Duration::from_secs(3_600)))
                .budget(ThrottleBudget::new(10, SECOND).with_burst(10)),
        );
        let mut throttle: Throttle<u32> = Throttle::new(&config, t0);
        let orders = BudgetId::DEFAULT;
        let cancels = BudgetId::new(1);
        assert_now(throttle.admit_sent(orders, 1, t0), 1);
        assert_held(throttle.admit_sent(orders, 2, t0));
        assert_now(throttle.admit_sent(cancels, 100, t0), 100);
        assert_now(throttle.admit_sent(cancels, 101, t0), 101);
        assert_eq!(throttle.held(), 1, "only the order waits");
        assert_eq!(
            throttle.next_release(t0),
            Some(t0 + Duration::from_secs(3_600))
        );
    }

    #[test]
    fn test_throttle_release_across_budgets_follows_arrival_order() {
        let t0 = Instant::now();
        let config = built(
            ThrottleConfig::builder(ThrottleBudget::new(1, SECOND))
                .budget(ThrottleBudget::new(1, SECOND)),
        );
        let mut throttle: Throttle<u32> = Throttle::new(&config, t0);
        let (a, b) = (BudgetId::DEFAULT, BudgetId::new(1));
        assert_now(throttle.admit_sent(a, 1, t0), 1);
        assert_now(throttle.admit_sent(b, 2, t0), 2);
        assert_held(throttle.admit_sent(b, 3, t0));
        assert_held(throttle.admit_sent(a, 4, t0));
        assert_held(throttle.admit_sent(b, 5, t0));
        // Both budgets earn their token at the same moment: the message
        // handed in first goes first, whatever its budget.
        let t1 = t0 + SECOND;
        assert_eq!(throttle.release_sent(t1), Some((b, 3)));
        assert_eq!(throttle.release_sent(t1), Some((a, 4)));
        assert!(throttle.release_sent(t1).is_none());
        assert_eq!(throttle.release_sent(t0 + 2 * SECOND), Some((b, 5)));
    }

    #[test]
    fn test_throttle_queue_cycles_without_reallocating() {
        let t0 = Instant::now();
        let mut throttle = single(
            ThrottleBudget::new(1, Duration::from_nanos(1))
                .with_policy(ThrottlePolicy::Queue { max_depth: 65 }),
            t0,
        );
        assert_now(throttle.admit_sent(BudgetId::DEFAULT, 99, t0), 99);
        let mut capacity = None;
        let mut at = t0;
        for _ in 0..10 {
            for item in 0..65 {
                assert_held(throttle.admit_sent(BudgetId::DEFAULT, item, t0));
            }
            for _ in 0..65 {
                at += Duration::from_nanos(1);
                assert!(throttle.release_sent(at).is_some());
            }
            let now = throttle
                .buckets
                .first()
                .map(|bucket| bucket.queue.capacity());
            assert!(
                capacity.is_none() || capacity == now,
                "the queue was reallocated"
            );
            capacity = now;
        }
    }

    #[test]
    fn test_throttle_new_message_never_overtakes_one_held_in_its_budget() {
        let t0 = Instant::now();
        let mut throttle = single(ThrottleBudget::new(1, SECOND).with_burst(2), t0);
        assert_now(throttle.admit_sent(BudgetId::DEFAULT, 1, t0), 1);
        assert_now(throttle.admit_sent(BudgetId::DEFAULT, 2, t0), 2);
        assert_held(throttle.admit_sent(BudgetId::DEFAULT, 3, t0));
        // A token is earned: the next message still queues behind the one
        // held, and the held one takes the token.
        let t1 = t0 + SECOND;
        assert_held(throttle.admit_sent(BudgetId::DEFAULT, 4, t1));
        assert_eq!(throttle.release_sent(t1), Some((BudgetId::DEFAULT, 3)));
        assert!(
            throttle.release_sent(t1).is_none(),
            "one token, one release"
        );
        assert_eq!(
            throttle.release_sent(t1 + SECOND),
            Some((BudgetId::DEFAULT, 4))
        );
    }

    /// A message admitted at `t0` whose frame is fed `delay` later: the next
    /// token is due one spacing after the feed, whatever the delay.
    #[track_caller]
    fn assert_feed_after(delay: Duration) {
        let t0 = Instant::now();
        let mut throttle = single(ThrottleBudget::new(1, SECOND), t0);
        assert_now(throttle.admit(BudgetId::DEFAULT, 1, t0), 1);
        let fed = t0 + delay;
        throttle.charge_at(BudgetId::DEFAULT, fed);
        assert_held(throttle.admit_sent(BudgetId::DEFAULT, 2, fed));
        assert_eq!(
            throttle.next_release(fed),
            Some(fed + SECOND),
            "fed {delay:?} after admission"
        );
        assert!(
            throttle
                .release_sent(fed + SECOND - Duration::from_nanos(1))
                .is_none()
        );
        assert_eq!(
            throttle.release_sent(fed + SECOND),
            Some((BudgetId::DEFAULT, 2))
        );
    }

    #[test]
    fn test_throttle_token_is_taken_at_the_feed_for_any_delay() {
        for delay in [
            Duration::ZERO,
            SECOND / 4,
            SECOND / 2,
            SECOND * 3 / 4,
            SECOND,
            2 * SECOND,
        ] {
            assert_feed_after(delay);
        }
    }

    #[test]
    fn test_throttle_reserved_token_is_not_free_to_another_message() {
        let t0 = Instant::now();
        let mut throttle = single(ThrottleBudget::new(1, SECOND), t0);
        assert_now(throttle.admit(BudgetId::DEFAULT, 1, t0), 1);
        // Before the feed, a second message finds the token reserved.
        assert_held(throttle.admit(BudgetId::DEFAULT, 2, t0 + 2 * SECOND));
    }

    #[test]
    fn test_throttle_refund_releases_the_reservation_and_keeps_the_progress() {
        let t0 = Instant::now();
        let mut throttle = single(ThrottleBudget::new(1, SECOND).with_burst(2), t0);
        assert_now(throttle.admit_sent(BudgetId::DEFAULT, 1, t0), 1);
        // Half a token earned, then a message reserves the last token and is
        // vetoed: the token is free again, and the half still counts.
        let half = t0 + Duration::from_millis(500);
        assert_now(throttle.admit(BudgetId::DEFAULT, 2, half), 2);
        throttle.refund(BudgetId::DEFAULT);
        assert_now(throttle.admit_sent(BudgetId::DEFAULT, 3, half), 3);
        assert_held(throttle.admit_sent(BudgetId::DEFAULT, 4, half));
        assert_eq!(throttle.next_release(half), Some(t0 + SECOND));
    }

    #[test]
    fn test_throttle_refund_at_a_full_bucket_grants_nothing() {
        let t0 = Instant::now();
        let mut throttle = single(ThrottleBudget::new(1, SECOND), t0);
        throttle.refund(BudgetId::DEFAULT);
        assert_now(throttle.admit_sent(BudgetId::DEFAULT, 1, t0), 1);
        assert_held(throttle.admit_sent(BudgetId::DEFAULT, 2, t0));
    }

    #[test]
    fn test_throttle_refund_is_capped_at_the_burst() {
        let t0 = Instant::now();
        let mut throttle = single(ThrottleBudget::new(1, SECOND).with_burst(2), t0);
        throttle.refund(BudgetId::DEFAULT);
        throttle.refund(BudgetId::new(7));
        assert_now(throttle.admit_sent(BudgetId::DEFAULT, 1, t0), 1);
        assert_now(throttle.admit_sent(BudgetId::DEFAULT, 2, t0), 2);
        assert_held(throttle.admit_sent(BudgetId::DEFAULT, 3, t0));
    }

    #[test]
    fn test_throttle_time_spent_full_is_not_banked() {
        let t0 = Instant::now();
        let mut throttle = single(ThrottleBudget::new(1, SECOND).with_burst(2), t0);
        // An hour idle: the bucket is full (2), not 3600 tokens deep.
        let later = t0 + Duration::from_secs(3_600);
        assert_now(throttle.admit_sent(BudgetId::DEFAULT, 1, later), 1);
        assert_now(throttle.admit_sent(BudgetId::DEFAULT, 2, later), 2);
        assert_held(throttle.admit_sent(BudgetId::DEFAULT, 3, later));
        assert_eq!(throttle.next_release(later), Some(later + SECOND));
    }

    #[test]
    fn test_throttle_an_earlier_instant_earns_nothing() {
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(10);
        let mut throttle = single(ThrottleBudget::new(1, SECOND), t1);
        assert_now(throttle.admit_sent(BudgetId::DEFAULT, 1, t1), 1);
        assert_held(throttle.admit_sent(BudgetId::DEFAULT, 2, t0));
        assert!(throttle.release_sent(t0).is_none());
        assert_eq!(throttle.next_release(t0), Some(t1 + SECOND));
    }

    #[test]
    fn test_throttle_drain_returns_every_held_message() {
        let t0 = Instant::now();
        let config = built(
            ThrottleConfig::builder(ThrottleBudget::new(1, SECOND))
                .budget(ThrottleBudget::new(1, SECOND)),
        );
        let mut throttle: Throttle<u32> = Throttle::new(&config, t0);
        let (a, b) = (BudgetId::DEFAULT, BudgetId::new(1));
        assert_now(throttle.admit_sent(a, 1, t0), 1);
        assert_now(throttle.admit_sent(b, 2, t0), 2);
        assert_held(throttle.admit_sent(a, 3, t0));
        assert_held(throttle.admit_sent(b, 4, t0));
        let drained: Vec<_> = throttle.drain().collect();
        assert_eq!(drained, [(a, 3), (b, 4)]);
        assert_eq!(throttle.held(), 0);
        assert_eq!(throttle.next_release(t0 + SECOND), None);
    }

    /// The bound the documentation states: over any half-open interval of
    /// length `per`, a budget lets at most `burst + rate - 1` messages
    /// through, for a sender that sends whenever it may.
    #[test]
    fn test_throttle_never_exceeds_burst_plus_rate_minus_one_per_window() {
        for (rate, burst) in [(3, 1), (5, 1), (5, 3), (7, 2), (1, 4)] {
            let t0 = Instant::now();
            let per = SECOND;
            let mut throttle = single(ThrottleBudget::new(rate, per).with_burst(burst), t0);
            let mut sent = Vec::new();
            // A greedy sender, polled every millisecond for ten windows, plus
            // a release at every instant the throttle names.
            let mut item = 0;
            let mut at = t0;
            while at < t0 + 10 * per {
                match throttle.admit_sent(BudgetId::DEFAULT, item, at) {
                    Admission::Now(_) => sent.push(at),
                    Admission::Held => {
                        let Some(next) = throttle.next_release(at) else {
                            panic!("a held message has a release time");
                        };
                        let Some(_) = throttle.release_sent(next) else {
                            panic!("a release at the named instant releases");
                        };
                        sent.push(next);
                        at = next;
                    }
                    Admission::Refused(_) => panic!("the default queue has room"),
                }
                item += 1;
                at += Duration::from_millis(1);
            }
            let bound = usize::try_from(burst + rate - 1).unwrap_or(usize::MAX);
            for (index, start) in sent.iter().enumerate() {
                let within = sent
                    .iter()
                    .skip(index)
                    .take_while(|&&sent_at| sent_at < *start + per)
                    .count();
                assert!(
                    within <= bound,
                    "rate {rate}, burst {burst}: {within} messages within one window from \
                     message {index}, above {bound}"
                );
            }
            assert!(
                sent.len() >= usize::try_from(rate * 9).unwrap_or(0),
                "rate {rate}: the throttle let the rate through ({} messages)",
                sent.len()
            );
        }
    }
}
