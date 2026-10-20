/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! Sans-IO core, stage 6c: the outbound throttle's token buckets.
//!
//! A venue limits how many messages a session may send per window (issue
//! #82, ADR-0024). The token buckets that enforce those limits, and the
//! messages they hold, are run-time state of one session, so they live in
//! the core: [`Throttle`] holds them and [`SessionCore`](crate::SessionCore)
//! owns one per session. Each bucket is described by a [`TokenBucketSpec`]
//! (the time to earn one token, the burst and the queue depth); budgets are
//! named by their index in the order they were given, 0 being the default.
//!
//! The configuration a user writes stays with the driver: in
//! `ironfix-engine` that is `ThrottleConfig` with its budgets
//! (`ThrottleBudget`, `BudgetId`, `ThrottlePolicy`), its validation and its
//! classifier, which reads the engine's `OutboundMessage`. The engine turns
//! each budget into a [`TokenBucketSpec`] when a session starts.
//!
//! The bucket rule: a bucket starts with `burst` tokens and earns one back
//! every `spacing`, up to `burst`; time spent full is not banked. With a
//! spacing of `per / rate` rounded up, over any half-open interval
//! `[t, t + per)` it lets at most `burst + rate - 1` messages through.
//! Within one budget messages leave in the order they were handed in; across
//! budgets, a message whose budget has a token goes ahead of one held in
//! another budget, and messages released at the same moment leave in arrival
//! order.
//!
//! Like the rest of the core it performs no I/O and reads no clock: every
//! decision takes `now`, the driver's monotonic time (ADR-0002).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// The default budget's index: the one every message goes to when the
/// driver does not classify.
pub const DEFAULT_BUDGET: u8 = 0;

/// One budget's token bucket, as the core runs it.
///
/// The driver derives it from its own budget configuration; the core only
/// needs the time to earn a token, the most tokens held, and how many
/// messages may wait for one. A zero `spacing` is read as one nanosecond
/// and a zero `burst` as 1, so a bucket always earns and always holds a
/// token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenBucketSpec {
    spacing: Duration,
    burst: u32,
    max_depth: Option<usize>,
}

impl TokenBucketSpec {
    /// A bucket that earns one token every `spacing`, holds at most `burst`,
    /// and holds up to `max_depth` messages waiting for a token (`None`:
    /// refuse a message that finds no token, hold nothing).
    ///
    /// # Arguments
    /// * `spacing` - Time to earn one token
    /// * `burst` - Most tokens held, in messages
    /// * `max_depth` - Most messages held waiting, or `None` to refuse them
    #[must_use]
    pub const fn new(spacing: Duration, burst: u32, max_depth: Option<usize>) -> Self {
        Self {
            spacing,
            burst,
            max_depth,
        }
    }

    /// Time to earn one token.
    #[must_use]
    pub const fn spacing(&self) -> Duration {
        self.spacing
    }

    /// Most tokens held, in messages.
    #[must_use]
    pub const fn burst(&self) -> u32 {
        self.burst
    }

    /// Most messages held waiting for a token, or `None` when a message that
    /// finds no token is refused.
    #[must_use]
    pub const fn max_depth(&self) -> Option<usize> {
        self.max_depth
    }
}

/// When a session's outbound throttle may release the next message it holds
/// ([`SessionCore::throttle_release_at`](crate::SessionCore::throttle_release_at)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ThrottleRelease {
    /// Nothing to release: no throttle, or nothing held.
    Idle,
    /// A held message has its token already.
    Now,
    /// The next held message's token is earned at this instant.
    At(Instant),
}

/// What [`Throttle::admit`] decided for a message.
#[derive(Debug)]
#[must_use]
#[repr(u8)]
pub enum ThrottleAdmission<T> {
    /// A token was taken: frame the message now.
    Now(T),
    /// The message is held in its budget's queue until a token is earned.
    Held,
    /// The budget refuses it: no token and no room to hold it, or a
    /// [``max_depth` of `None``] budget with no token.
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
    /// Most messages held, or `None` under [``max_depth` of `None``].
    max_depth: Option<usize>,
    /// The messages held, oldest first, each with its arrival ticket.
    queue: VecDeque<(u64, T)>,
}

impl<T> Bucket<T> {
    /// A full bucket for `budget` at `now`. The queue grows on first use and
    /// keeps its capacity, so a session that throttles in steady state does
    /// not allocate per message.
    fn new(spec: &TokenBucketSpec, now: Instant) -> Self {
        Self {
            spacing: spec.spacing.max(Duration::from_nanos(1)),
            burst: spec.burst.max(1),
            tokens: spec.burst.max(1),
            reserved: 0,
            refilled_at: now,
            max_depth: spec.max_depth,
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
        // A token is reserved only while it is in the bucket, and the bucket
        // never loses a token it holds until the reservation is charged, so
        // `tokens >= reserved` always. Were it broken, no token would be free:
        // the safe side, which can only delay a message, never send one early.
        match self.tokens.checked_sub(self.reserved) {
            Some(free) => free,
            None => {
                debug_assert!(false, "a reserved token is always held");
                0
            }
        }
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

/// The run-time state of a session's outbound throttle: one bucket per budget, and
/// the messages held, of type `T`.
///
/// Every decision takes `now`, the driver's monotonic time, and reads no
/// clock (ADR-0002).
#[derive(Debug)]
pub struct Throttle<T> {
    /// One bucket per budget, in budget index order.
    buckets: Vec<Bucket<T>>,
    /// The ticket the next held message gets: arrival order across budgets.
    next_ticket: u64,
    /// Messages held, across every budget.
    held: usize,
}

impl<T> Throttle<T> {
    /// Full buckets, one per spec in budget index order (the default budget,
    /// [`DEFAULT_BUDGET`], first), at `now`.
    #[must_use]
    pub fn new(specs: impl IntoIterator<Item = TokenBucketSpec>, now: Instant) -> Self {
        Self {
            buckets: specs
                .into_iter()
                .map(|spec| Bucket::new(&spec, now))
                .collect(),
            next_ticket: 0,
            held: 0,
        }
    }

    /// The bucket for `budget`, falling back to the default one.
    fn bucket_mut(&mut self, budget: u8) -> Option<&mut Bucket<T>> {
        let slot = usize::from(budget);
        let slot = if slot < self.buckets.len() {
            slot
        } else {
            usize::from(DEFAULT_BUDGET)
        };
        self.buckets.get_mut(slot)
    }

    /// Decides what becomes of `item`, a new message of `budget`, at `now`.
    ///
    /// It reserves a token (taken at the feed, [`Throttle::charge_at`]) and
    /// goes now only when its budget holds nothing
    /// already, so it never overtakes a message of its own budget. Otherwise
    /// it is held, under a `max_depth` with room left, or refused.
    pub fn admit(&mut self, budget: u8, item: T, now: Instant) -> ThrottleAdmission<T> {
        let ticket = self.next_ticket;
        let Some(bucket) = self.bucket_mut(budget) else {
            // A configuration always holds the default budget.
            return ThrottleAdmission::Now(item);
        };
        if bucket.queue.is_empty() && bucket.reserve(now) {
            return ThrottleAdmission::Now(item);
        }
        match bucket.max_depth {
            Some(max_depth) if bucket.queue.len() < max_depth => {
                bucket.queue.push_back((ticket, item));
                // A ticket per held message, reset whenever nothing is held:
                // a u64 cannot run out within one busy period.
                self.next_ticket = ticket.checked_add(1).unwrap_or(ticket);
                self.held = self.held.checked_add(1).unwrap_or(self.held);
                ThrottleAdmission::Held
            }
            _ => ThrottleAdmission::Refused(item),
        }
    }

    /// Releases, at `now`, the held message that may go: of the budgets
    /// whose head can take a token, the head that was handed in first. Its
    /// token is reserved, and taken by [`Throttle::charge_at`] at the feed. `None` when no held message may go yet.
    pub fn release(&mut self, now: Instant) -> Option<(u8, T)> {
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
        let id = u8::try_from(slot).unwrap_or(DEFAULT_BUDGET);
        Some((id, item))
    }

    /// When the next held message may go, as of `now`: `now` when one may go
    /// already, otherwise when the first budget with a message held earns a
    /// token. `None` when nothing is held.
    ///
    /// [`Throttle::release`] at that instant or later releases a message: it
    /// brings the tokens up to date by the same rule.
    pub fn next_release(&mut self, now: Instant) -> Option<Instant> {
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
    pub fn charge_at(&mut self, budget: u8, now: Instant) {
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
    pub fn refund(&mut self, budget: u8) {
        if let Some(bucket) = self.bucket_mut(budget)
            && let Some(reserved) = bucket.reserved.checked_sub(1)
        {
            bucket.reserved = reserved;
        }
    }

    /// How many messages are held, across every budget.
    #[must_use]
    pub const fn held(&self) -> usize {
        self.held
    }

    /// Removes every held message, budget by budget, each with its budget.
    ///
    /// The throttle is empty once the returned iterator is dropped, whether
    /// or not it was consumed: what was not taken is dropped with it, so the
    /// count of held messages never disagrees with the queues.
    pub fn drain(&mut self) -> ThrottleDrain<'_, T> {
        self.held = 0;
        self.next_ticket = 0;
        ThrottleDrain {
            buckets: &mut self.buckets,
            slot: 0,
        }
    }
}

/// The held messages of a [`Throttle`], each with its budget, from
/// [`Throttle::drain`]. Dropping it drops whatever was not taken.
#[derive(Debug)]
pub struct ThrottleDrain<'a, T> {
    /// The throttle's buckets.
    buckets: &'a mut [Bucket<T>],
    /// The bucket being emptied.
    slot: usize,
}

impl<T> Iterator for ThrottleDrain<'_, T> {
    type Item = (u8, T);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(bucket) = self.buckets.get_mut(self.slot) {
            if let Some((_, item)) = bucket.queue.pop_front() {
                let id = u8::try_from(self.slot).unwrap_or(DEFAULT_BUDGET);
                return Some((id, item));
            }
            match self.slot.checked_add(1) {
                Some(slot) => self.slot = slot,
                None => {
                    debug_assert!(false, "a bucket index never reaches usize::MAX");
                    return None;
                }
            }
        }
        None
    }
}

impl<T> Drop for ThrottleDrain<'_, T> {
    fn drop(&mut self) {
        for bucket in self.buckets.iter_mut() {
            bucket.queue.clear();
        }
    }
}

#[cfg(test)]
impl<T> Throttle<T> {
    /// [`Throttle::admit`] for a message fed at once: a reserved token is
    /// charged at `now`.
    fn admit_sent(&mut self, budget: u8, item: T, now: Instant) -> ThrottleAdmission<T> {
        let admission = self.admit(budget, item, now);
        if matches!(admission, ThrottleAdmission::Now(_)) {
            self.charge_at(budget, now);
        }
        admission
    }

    /// [`Throttle::release`] for a message fed at once.
    fn release_sent(&mut self, now: Instant) -> Option<(u8, T)> {
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

    const SECOND: Duration = Duration::from_secs(1);

    /// What a budget does with a message that finds no token, as the
    /// engine's `ThrottlePolicy` says it.
    #[derive(Debug, Clone, Copy)]
    enum TestPolicy {
        Queue { max_depth: usize },
        Refuse,
    }

    /// A test stand-in for the engine's `ThrottleBudget`: `rate` messages
    /// per `per`, a burst, and a policy, turned into the core's spec with
    /// the engine's rule (spacing `per / rate`, rounded up).
    #[derive(Debug, Clone, Copy)]
    struct TestBudget {
        rate: u32,
        per: Duration,
        burst: u32,
        policy: TestPolicy,
    }

    impl TestBudget {
        const fn new(rate: u32, per: Duration) -> Self {
            Self {
                rate,
                per,
                burst: 1,
                policy: TestPolicy::Queue { max_depth: 1_024 },
            }
        }

        const fn with_burst(mut self, burst: u32) -> Self {
            self.burst = burst;
            self
        }

        const fn with_policy(mut self, policy: TestPolicy) -> Self {
            self.policy = policy;
            self
        }

        fn spec(self) -> TokenBucketSpec {
            let nanos = self
                .per
                .as_nanos()
                .div_ceil(u128::from(self.rate.max(1)))
                .max(1);
            let spacing = u64::try_from(nanos).map_or(self.per, Duration::from_nanos);
            let max_depth = match self.policy {
                TestPolicy::Queue { max_depth } => Some(max_depth),
                TestPolicy::Refuse => None,
            };
            TokenBucketSpec::new(spacing, self.burst, max_depth)
        }
    }

    /// A one-budget throttle at `t0`.
    fn single(budget: TestBudget, t0: Instant) -> Throttle<u32> {
        Throttle::new([budget.spec()], t0)
    }

    #[track_caller]
    fn assert_now(admission: ThrottleAdmission<u32>, expected: u32) {
        match admission {
            ThrottleAdmission::Now(item) => assert_eq!(item, expected),
            other => panic!("expected Now({expected}), got {other:?}"),
        }
    }

    #[track_caller]
    fn assert_held(admission: ThrottleAdmission<u32>) {
        assert!(
            matches!(admission, ThrottleAdmission::Held),
            "expected Held, got {admission:?}"
        );
    }

    #[track_caller]
    fn assert_refused(admission: ThrottleAdmission<u32>, expected: u32) {
        match admission {
            ThrottleAdmission::Refused(item) => assert_eq!(item, expected),
            other => panic!("expected Refused({expected}), got {other:?}"),
        }
    }

    #[test]
    fn test_throttle_burst_goes_at_once_then_one_per_spacing() {
        let t0 = Instant::now();
        let mut throttle = single(TestBudget::new(4, SECOND).with_burst(3), t0);
        for item in 0..3 {
            assert_now(throttle.admit_sent(DEFAULT_BUDGET, item, t0), item);
        }
        assert_held(throttle.admit_sent(DEFAULT_BUDGET, 3, t0));
        assert_held(throttle.admit_sent(DEFAULT_BUDGET, 4, t0));
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
            Some((DEFAULT_BUDGET, 3)),
            "the head goes first"
        );
        assert_eq!(throttle.next_release(t0 + spacing), Some(t0 + 2 * spacing));
        assert_eq!(
            throttle.release_sent(t0 + 2 * spacing),
            Some((DEFAULT_BUDGET, 4))
        );
        assert_eq!(throttle.held(), 0);
        assert_eq!(throttle.next_release(t0 + 2 * spacing), None);
    }

    #[test]
    fn test_throttle_next_release_is_now_when_a_token_is_waiting() {
        let t0 = Instant::now();
        let mut throttle = single(TestBudget::new(1, SECOND), t0);
        assert_now(throttle.admit_sent(DEFAULT_BUDGET, 1, t0), 1);
        assert_held(throttle.admit_sent(DEFAULT_BUDGET, 2, t0));
        let later = t0 + 5 * SECOND;
        assert_eq!(
            throttle.next_release(later),
            Some(later),
            "a token was earned while the release waited"
        );
        assert_eq!(throttle.release_sent(later), Some((DEFAULT_BUDGET, 2)));
    }

    #[test]
    fn test_throttle_refuse_policy_never_holds() {
        let t0 = Instant::now();
        let mut throttle = single(
            TestBudget::new(2, SECOND)
                .with_burst(2)
                .with_policy(TestPolicy::Refuse),
            t0,
        );
        assert_now(throttle.admit_sent(DEFAULT_BUDGET, 1, t0), 1);
        assert_now(throttle.admit_sent(DEFAULT_BUDGET, 2, t0), 2);
        assert_refused(throttle.admit_sent(DEFAULT_BUDGET, 3, t0), 3);
        assert_eq!(throttle.held(), 0);
        assert_eq!(throttle.next_release(t0), None);
        let half = t0 + Duration::from_millis(500);
        assert_now(throttle.admit_sent(DEFAULT_BUDGET, 4, half), 4);
        assert_refused(throttle.admit_sent(DEFAULT_BUDGET, 5, half), 5);
    }

    #[test]
    fn test_throttle_queue_refuses_past_its_depth() {
        let t0 = Instant::now();
        let mut throttle = single(
            TestBudget::new(1, SECOND).with_policy(TestPolicy::Queue { max_depth: 2 }),
            t0,
        );
        assert_now(throttle.admit_sent(DEFAULT_BUDGET, 1, t0), 1);
        assert_held(throttle.admit_sent(DEFAULT_BUDGET, 2, t0));
        assert_held(throttle.admit_sent(DEFAULT_BUDGET, 3, t0));
        assert_refused(throttle.admit_sent(DEFAULT_BUDGET, 4, t0), 4);
        assert_eq!(throttle.held(), 2);
    }

    #[test]
    fn test_throttle_budgets_are_independent() {
        let t0 = Instant::now();
        let budgets = [
            TestBudget::new(1, Duration::from_secs(3_600)),
            TestBudget::new(10, SECOND).with_burst(10),
        ];
        let specs = budgets.map(|budget| budget.spec());
        let mut throttle: Throttle<u32> = Throttle::new(specs, t0);
        let orders = DEFAULT_BUDGET;
        let cancels = 1;
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
        let budgets = [TestBudget::new(1, SECOND), TestBudget::new(1, SECOND)];
        let specs = budgets.map(|budget| budget.spec());
        let mut throttle: Throttle<u32> = Throttle::new(specs, t0);
        let (a, b) = (DEFAULT_BUDGET, 1);
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
            TestBudget::new(1, Duration::from_nanos(1))
                .with_policy(TestPolicy::Queue { max_depth: 65 }),
            t0,
        );
        assert_now(throttle.admit_sent(DEFAULT_BUDGET, 99, t0), 99);
        let mut capacity = None;
        let mut at = t0;
        for _ in 0..10 {
            for item in 0..65 {
                assert_held(throttle.admit_sent(DEFAULT_BUDGET, item, t0));
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
        let mut throttle = single(TestBudget::new(1, SECOND).with_burst(2), t0);
        assert_now(throttle.admit_sent(DEFAULT_BUDGET, 1, t0), 1);
        assert_now(throttle.admit_sent(DEFAULT_BUDGET, 2, t0), 2);
        assert_held(throttle.admit_sent(DEFAULT_BUDGET, 3, t0));
        // A token is earned: the next message still queues behind the one
        // held, and the held one takes the token.
        let t1 = t0 + SECOND;
        assert_held(throttle.admit_sent(DEFAULT_BUDGET, 4, t1));
        assert_eq!(throttle.release_sent(t1), Some((DEFAULT_BUDGET, 3)));
        assert!(
            throttle.release_sent(t1).is_none(),
            "one token, one release"
        );
        assert_eq!(
            throttle.release_sent(t1 + SECOND),
            Some((DEFAULT_BUDGET, 4))
        );
    }

    /// A message admitted at `t0` whose frame is fed `delay` later: the next
    /// token is due one spacing after the feed, whatever the delay.
    #[track_caller]
    fn assert_feed_after(delay: Duration) {
        let t0 = Instant::now();
        let mut throttle = single(TestBudget::new(1, SECOND), t0);
        assert_now(throttle.admit(DEFAULT_BUDGET, 1, t0), 1);
        let fed = t0 + delay;
        throttle.charge_at(DEFAULT_BUDGET, fed);
        assert_held(throttle.admit_sent(DEFAULT_BUDGET, 2, fed));
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
            Some((DEFAULT_BUDGET, 2))
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
        let mut throttle = single(TestBudget::new(1, SECOND), t0);
        assert_now(throttle.admit(DEFAULT_BUDGET, 1, t0), 1);
        // Before the feed, a second message finds the token reserved.
        assert_held(throttle.admit(DEFAULT_BUDGET, 2, t0 + 2 * SECOND));
    }

    #[test]
    fn test_throttle_refund_releases_the_reservation_and_keeps_the_progress() {
        let t0 = Instant::now();
        let mut throttle = single(TestBudget::new(1, SECOND).with_burst(2), t0);
        assert_now(throttle.admit_sent(DEFAULT_BUDGET, 1, t0), 1);
        // Half a token earned, then a message reserves the last token and is
        // vetoed: the token is free again, and the half still counts.
        let half = t0 + Duration::from_millis(500);
        assert_now(throttle.admit(DEFAULT_BUDGET, 2, half), 2);
        throttle.refund(DEFAULT_BUDGET);
        assert_now(throttle.admit_sent(DEFAULT_BUDGET, 3, half), 3);
        assert_held(throttle.admit_sent(DEFAULT_BUDGET, 4, half));
        assert_eq!(throttle.next_release(half), Some(t0 + SECOND));
    }

    #[test]
    fn test_throttle_refund_at_a_full_bucket_grants_nothing() {
        let t0 = Instant::now();
        let mut throttle = single(TestBudget::new(1, SECOND), t0);
        throttle.refund(DEFAULT_BUDGET);
        assert_now(throttle.admit_sent(DEFAULT_BUDGET, 1, t0), 1);
        assert_held(throttle.admit_sent(DEFAULT_BUDGET, 2, t0));
    }

    #[test]
    fn test_throttle_refund_is_capped_at_the_burst() {
        let t0 = Instant::now();
        let mut throttle = single(TestBudget::new(1, SECOND).with_burst(2), t0);
        throttle.refund(DEFAULT_BUDGET);
        throttle.refund(7);
        assert_now(throttle.admit_sent(DEFAULT_BUDGET, 1, t0), 1);
        assert_now(throttle.admit_sent(DEFAULT_BUDGET, 2, t0), 2);
        assert_held(throttle.admit_sent(DEFAULT_BUDGET, 3, t0));
    }

    #[test]
    fn test_throttle_time_spent_full_is_not_banked() {
        let t0 = Instant::now();
        let mut throttle = single(TestBudget::new(1, SECOND).with_burst(2), t0);
        // An hour idle: the bucket is full (2), not 3600 tokens deep.
        let later = t0 + Duration::from_secs(3_600);
        assert_now(throttle.admit_sent(DEFAULT_BUDGET, 1, later), 1);
        assert_now(throttle.admit_sent(DEFAULT_BUDGET, 2, later), 2);
        assert_held(throttle.admit_sent(DEFAULT_BUDGET, 3, later));
        assert_eq!(throttle.next_release(later), Some(later + SECOND));
    }

    #[test]
    fn test_throttle_an_earlier_instant_earns_nothing() {
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(10);
        let mut throttle = single(TestBudget::new(1, SECOND), t1);
        assert_now(throttle.admit_sent(DEFAULT_BUDGET, 1, t1), 1);
        assert_held(throttle.admit_sent(DEFAULT_BUDGET, 2, t0));
        assert!(throttle.release_sent(t0).is_none());
        assert_eq!(throttle.next_release(t0), Some(t1 + SECOND));
    }

    #[test]
    fn test_throttle_drain_returns_every_held_message() {
        let t0 = Instant::now();
        let budgets = [TestBudget::new(1, SECOND), TestBudget::new(1, SECOND)];
        let specs = budgets.map(|budget| budget.spec());
        let mut throttle: Throttle<u32> = Throttle::new(specs, t0);
        let (a, b) = (DEFAULT_BUDGET, 1);
        assert_now(throttle.admit_sent(a, 1, t0), 1);
        assert_now(throttle.admit_sent(b, 2, t0), 2);
        assert_held(throttle.admit_sent(a, 3, t0));
        assert_held(throttle.admit_sent(b, 4, t0));
        let drained: Vec<_> = throttle.drain().collect();
        assert_eq!(drained, [(a, 3), (b, 4)]);
        assert_eq!(throttle.held(), 0);
        assert_eq!(throttle.next_release(t0 + SECOND), None);
    }

    /// Dropping the drain unconsumed, or after taking part of it, still
    /// leaves the throttle empty, so a later admit and release keep their
    /// accounting (#179 review).
    #[test]
    fn test_throttle_drain_dropped_early_still_empties_the_throttle() {
        let t0 = Instant::now();
        let budgets = [TestBudget::new(1, SECOND), TestBudget::new(1, SECOND)];
        let specs = budgets.map(|budget| budget.spec());
        for take in 0..3 {
            let mut throttle: Throttle<u32> = Throttle::new(specs, t0);
            let (a, b) = (DEFAULT_BUDGET, 1);
            assert_now(throttle.admit_sent(a, 1, t0), 1);
            assert_now(throttle.admit_sent(b, 2, t0), 2);
            assert_held(throttle.admit_sent(a, 3, t0));
            assert_held(throttle.admit_sent(b, 4, t0));
            assert_eq!(throttle.drain().take(take).count(), take.min(2));
            assert_eq!(throttle.held(), 0);
            assert_eq!(throttle.next_release(t0 + SECOND), None);
            assert!(throttle.release_sent(t0 + SECOND).is_none());
            assert_held(throttle.admit_sent(a, 5, t0));
            assert_eq!(throttle.held(), 1);
            assert_eq!(throttle.release_sent(t0 + SECOND), Some((a, 5)));
            assert_eq!(throttle.held(), 0);
        }
    }

    /// The bound the documentation states: over any half-open interval of
    /// length `per`, a budget lets at most `burst + rate - 1` messages
    /// through, for a sender that sends whenever it may.
    #[test]
    fn test_throttle_never_exceeds_burst_plus_rate_minus_one_per_window() {
        for (rate, burst) in [(3, 1), (5, 1), (5, 3), (7, 2), (1, 4)] {
            let t0 = Instant::now();
            let per = SECOND;
            let mut throttle = single(TestBudget::new(rate, per).with_burst(burst), t0);
            let mut sent = Vec::new();
            // A greedy sender, polled every millisecond for ten windows, plus
            // a release at every instant the throttle names.
            let mut item = 0;
            let mut at = t0;
            while at < t0 + 10 * per {
                match throttle.admit_sent(DEFAULT_BUDGET, item, at) {
                    ThrottleAdmission::Now(_) => sent.push(at),
                    ThrottleAdmission::Held => {
                        let Some(next) = throttle.next_release(at) else {
                            panic!("a held message has a release time");
                        };
                        let Some(_) = throttle.release_sent(next) else {
                            panic!("a release at the named instant releases");
                        };
                        sent.push(next);
                        at = next;
                    }
                    ThrottleAdmission::Refused(_) => panic!("the default queue has room"),
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

    #[test]
    fn test_token_bucket_spec_reads_back_and_a_zero_spec_still_earns() {
        let spec = TokenBucketSpec::new(SECOND, 3, Some(5));
        assert_eq!(
            (spec.spacing(), spec.burst(), spec.max_depth()),
            (SECOND, 3, Some(5))
        );
        // A zero spacing and burst are read as one nanosecond and one token:
        // the bucket still holds a token and still earns.
        let t0 = Instant::now();
        let mut throttle: Throttle<u32> =
            Throttle::new([TokenBucketSpec::new(Duration::ZERO, 0, None)], t0);
        assert_now(throttle.admit_sent(DEFAULT_BUDGET, 1, t0), 1);
        assert_refused(throttle.admit_sent(DEFAULT_BUDGET, 2, t0), 2);
        let t1 = t0 + Duration::from_nanos(1);
        assert_now(throttle.admit_sent(DEFAULT_BUDGET, 3, t1), 3);
    }

    #[test]
    fn test_an_unknown_budget_falls_back_to_the_default_one() {
        let t0 = Instant::now();
        let mut throttle = single(TestBudget::new(1, SECOND), t0);
        assert_now(throttle.admit_sent(9, 1, t0), 1);
        assert_held(throttle.admit_sent(DEFAULT_BUDGET, 2, t0));
        assert_eq!(
            throttle.release_sent(t0 + SECOND),
            Some((DEFAULT_BUDGET, 2))
        );
    }
}
