/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/11/26
******************************************************************************/

//! Sans-IO core: the fail-closed persistence policy (issue #224).
//!
//! A session with a store writes to it in a fixed order (ADR-0005): an
//! outbound frame is filed with the next sender number before it is written,
//! and the next target number is persisted before the inbound message that
//! advanced it is acted on. Every write can fail, and [`StoreFailurePolicy`]
//! decides what a failure means.
//!
//! The core performs no I/O, so it cannot make the write. It owns the rule
//! instead, as an input and an output:
//!
//! - **Input.** The driver names the write it made ([`StoreWrite`]) and feeds
//!   its result ([`StoreResult`]).
//! - **Output.** The core decides ([`StoreFailurePolicy::decide`]): proceed,
//!   proceed with the write not durable, or close the session
//!   ([`StoreVerdict`]).
//!
//! [`StoreGate`] makes the ordering structural: the action a write guards (a
//! frame to write, a message to deliver) is held inside the gate, and the
//! only way to get it back is to resolve the gate with the write's result.
//! A driver therefore cannot deliver before the counter write has a result,
//! and under [`StoreFailurePolicy::CloseSession`] it gets the action back
//! only as [`StoreRelease::Close`]. [`PersistedCounters`] keeps a counter from
//! being written again when it did not change.
//!
//! What stays with the driver: making the store call, bounding it by a
//! timeout (an overrun is a failed write), the owed-reset marker, and the log
//! lines. `ironfix-engine` is the first driver: it re-exports
//! [`StoreFailurePolicy`] and applies [`StoreFailurePolicy::decide`] to every
//! failed store call.

/// What the driver does when a write to its store fails.
///
/// Applies to every write made during a session: filing an outbound frame,
/// persisting the next sender sequence number, the next target sequence
/// number and the inbound application watermark. A call that does not
/// finish within the driver's store timeout counts as a failed write.
/// Without a store there is nothing to fail and the policy has no effect.
///
/// The resets and the refresh fail closed whatever the policy
/// ([`StoreWrite::fails_closed_whatever_the_policy`]), because carrying on
/// past any of them would run one sequence stream over another.
///
/// # Example
///
/// ```
/// use ironfix_session::{StoreFailurePolicy, StoreResult, StoreVerdict, StoreWrite};
///
/// let policy = StoreFailurePolicy::CloseSession;
/// let write = StoreWrite::NextTarget { next: 8 };
/// assert_eq!(policy.decide(write, StoreResult::Failed), StoreVerdict::Close);
/// assert_eq!(
///     StoreFailurePolicy::Continue.decide(write, StoreResult::Failed),
///     StoreVerdict::ProceedUnpersisted
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum StoreFailurePolicy {
    /// Log a warning and carry on: the frame is written anyway, the message
    /// is acted on anyway, and a counter that could not be persisted is simply
    /// not durable.
    ///
    /// A frame whose filing failed is not confirmed as filed; a later
    /// `ResendRequest` (2) covering it replays it if the store saved it
    /// despite the error, and gets a `SequenceReset`-GapFill otherwise. This
    /// is the default. It gives **no** crash guarantee: after a failed write,
    /// a crash can leave the store behind what the counterparty has seen.
    #[default]
    Continue,
    /// Fail closed: a frame whose filing or sender-counter write fails is not
    /// written at all (the counterparty reads no bytes for it), an inbound
    /// message whose target-counter write fails is not acted on, and the
    /// session closes, not gracefully. During the Logon handshake the failure
    /// refuses the session, also when it happens while a Logon is being
    /// refused.
    ///
    /// No Logout (5) is sent on the way out: it would have to be filed like
    /// any other frame, through the store that just failed.
    CloseSession,
}

impl StoreFailurePolicy {
    /// Returns whether a failed store write ends the session under this
    /// policy.
    #[must_use]
    pub const fn closes_session(self) -> bool {
        matches!(self, Self::CloseSession)
    }

    /// Decides what the driver does once `write` has `result`.
    ///
    /// A write that landed always proceeds. A failed one proceeds unpersisted
    /// under [`Continue`](Self::Continue) and closes the session under
    /// [`CloseSession`](Self::CloseSession), except a reset or a refresh,
    /// which closes it under every policy.
    #[must_use]
    pub const fn decide(self, write: StoreWrite, result: StoreResult) -> StoreVerdict {
        match result {
            StoreResult::Written => StoreVerdict::Proceed,
            StoreResult::Failed => {
                if self.closes_session() || write.fails_closed_whatever_the_policy() {
                    StoreVerdict::Close
                } else {
                    StoreVerdict::ProceedUnpersisted
                }
            }
        }
    }
}

/// One store write the driver makes, named for the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreWrite {
    /// Filing an outbound frame together with the next sender number, before
    /// the frame is written.
    OutboundFrame {
        /// The frame's `MsgSeqNum` (34).
        seq: u64,
        /// The next sender number persisted with it.
        next_sender: u64,
    },
    /// Persisting the next sender sequence number on its own.
    NextSender {
        /// The value written.
        next: u64,
    },
    /// Persisting the next target sequence number, before the inbound
    /// message that advanced it is acted on.
    NextTarget {
        /// The value written.
        next: u64,
    },
    /// Persisting the inbound application watermark (ADR-0030).
    AppWatermark {
        /// The value written.
        watermark: u64,
    },
    /// Resetting the store and setting both counters, for a sequence reset.
    Reset {
        /// The next sender number after the reset.
        next_sender: u64,
        /// The next target number after the reset.
        next_target: u64,
    },
    /// Re-reading the counters from the store before the session is seeded.
    Refresh,
}

impl StoreWrite {
    /// Returns whether a failure of this write closes the session under every
    /// policy: a reset, or the refresh that recovers the counters. Carrying
    /// on past either would run one sequence stream over another.
    #[must_use]
    pub const fn fails_closed_whatever_the_policy(self) -> bool {
        matches!(self, Self::Reset { .. } | Self::Refresh)
    }

    /// Returns whether a failure of this write leaves the store in an unknown
    /// state, so the driver owes a reset to its next session (ADR-0029). Every
    /// mutation does: part of a failed write can land. The refresh is a read
    /// and does not.
    #[must_use]
    pub const fn failure_owes_reset(self) -> bool {
        !matches!(self, Self::Refresh)
    }
}

/// The result of one store write, fed by the driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StoreResult {
    /// The store reported success.
    Written,
    /// The store reported an error, or the call overran the driver's timeout.
    Failed,
}

impl StoreResult {
    /// Maps a store call's `Result` to the core's input, dropping the error
    /// (the driver keeps it for its log line and its close reason).
    #[must_use]
    pub const fn of<T, E>(result: &Result<T, E>) -> Self {
        match result {
            Ok(_) => Self::Written,
            Err(_) => Self::Failed,
        }
    }
}

/// What the driver does after a store write, from
/// [`StoreFailurePolicy::decide`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StoreVerdict {
    /// The write landed: act on what it guards.
    Proceed,
    /// The write failed and the policy carries on: act on what it guards,
    /// knowing the write is not durable (a frame is not confirmed as filed).
    ProceedUnpersisted,
    /// The write failed and the session closes: do not act on what it
    /// guards, write nothing more for it, and close without a Logout.
    Close,
}

/// An action held until the store write that guards it has a result.
///
/// The driver builds the gate when it starts the write
/// ([`StoreGate::hold`]), makes the write, and resolves the gate with the
/// result ([`StoreGate::resolve`]); the action comes back only then, as a
/// [`StoreRelease`]. The gate is the "hold" output of the core: while it
/// exists, the action is neither delivered nor dropped.
#[derive(Debug)]
#[must_use = "the guarded action is only released by resolving the gate"]
pub struct StoreGate<T> {
    /// The write the action waits for.
    write: StoreWrite,
    /// The held action.
    action: T,
}

impl<T> StoreGate<T> {
    /// Holds `action` until `write` has a result.
    pub const fn hold(write: StoreWrite, action: T) -> Self {
        Self { write, action }
    }

    /// The write the action waits for.
    #[must_use]
    pub const fn write(&self) -> StoreWrite {
        self.write
    }

    /// Resolves the gate with the write's `result` under `policy`, releasing
    /// the action for delivery or for the close.
    pub fn resolve(self, policy: StoreFailurePolicy, result: StoreResult) -> StoreRelease<T> {
        match policy.decide(self.write, result) {
            StoreVerdict::Proceed => StoreRelease::Deliver(self.action),
            StoreVerdict::ProceedUnpersisted => StoreRelease::DeliverUnpersisted(self.action),
            StoreVerdict::Close => StoreRelease::Close {
                write: self.write,
                action: self.action,
            },
        }
    }
}

/// A held action released by [`StoreGate::resolve`].
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a released action must be delivered or dropped with the close"]
pub enum StoreRelease<T> {
    /// The write landed: deliver the action.
    Deliver(T),
    /// The write failed under [`StoreFailurePolicy::Continue`]: deliver the
    /// action; the write is not durable.
    DeliverUnpersisted(T),
    /// The session closes: the action must not be acted on. It is handed
    /// back so the driver can account for it (report it, free it).
    Close {
        /// The write that failed.
        write: StoreWrite,
        /// The action that must not be acted on.
        action: T,
    },
}

/// The counter values last written to the store, so that a counter is
/// written only when it changed.
///
/// A driver that checks its counters after every event, a periodic tick
/// included, would otherwise pay two store writes per tick. A value is
/// recorded once its write was attempted: under
/// [`StoreFailurePolicy::Continue`] a failed write is not retried every
/// check, only when the counter moves again.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PersistedCounters {
    /// Last next-sender value written, if any.
    sender: Option<u64>,
    /// Last next-target value written, if any.
    target: Option<u64>,
}

impl PersistedCounters {
    /// No counter written yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sender: None,
            target: None,
        }
    }

    /// Returns `current` if it differs from the last next-sender value
    /// written.
    #[must_use]
    pub fn sender_to_write(self, current: u64) -> Option<u64> {
        (self.sender != Some(current)).then_some(current)
    }

    /// Returns `current` if it differs from the last next-target value
    /// written.
    #[must_use]
    pub fn target_to_write(self, current: u64) -> Option<u64> {
        (self.target != Some(current)).then_some(current)
    }

    /// Records that `value` was written as the next sender sequence number.
    pub const fn record_sender(&mut self, value: u64) {
        self.sender = Some(value);
    }

    /// Records that `value` was written as the next target sequence number.
    pub const fn record_target(&mut self, value: u64) {
        self.target = Some(value);
    }

    /// Plans the target write that must come before an inbound message that
    /// moved the next target number to `next` is acted on: `Some` when the
    /// value changed, `None` when nothing needs writing.
    ///
    /// Planning records nothing: a planned write that the driver defers or
    /// drops is planned again next time. The driver calls
    /// [`record_attempt`](Self::record_attempt) when it starts the call.
    #[must_use]
    pub fn plan_target(self, next: u64) -> Option<StoreWrite> {
        self.target_to_write(next)?;
        Some(StoreWrite::NextTarget { next })
    }

    /// Records that the driver started `write`, so the counters it carries
    /// are not written again until they move. Call it when the store call
    /// starts (under [`StoreFailurePolicy::Continue`] a failed attempt is not
    /// retried until the counter moves), never when the write is only
    /// planned. A write that carries no counter records nothing.
    pub const fn record_attempt(&mut self, write: StoreWrite) {
        match write {
            StoreWrite::OutboundFrame { next_sender, .. } => self.record_sender(next_sender),
            StoreWrite::NextSender { next } => self.record_sender(next),
            StoreWrite::NextTarget { next } => self.record_target(next),
            StoreWrite::Reset {
                next_sender,
                next_target,
            } => {
                self.record_sender(next_sender);
                self.record_target(next_target);
            }
            StoreWrite::AppWatermark { .. } | StoreWrite::Refresh => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MUTATIONS: [StoreWrite; 4] = [
        StoreWrite::OutboundFrame {
            seq: 4,
            next_sender: 5,
        },
        StoreWrite::NextSender { next: 5 },
        StoreWrite::NextTarget { next: 9 },
        StoreWrite::AppWatermark { watermark: 8 },
    ];

    const ALWAYS_CLOSED: [StoreWrite; 2] = [
        StoreWrite::Reset {
            next_sender: 1,
            next_target: 1,
        },
        StoreWrite::Refresh,
    ];

    #[test]
    fn test_policy_defaults_to_continue() {
        assert_eq!(StoreFailurePolicy::default(), StoreFailurePolicy::Continue);
        assert!(!StoreFailurePolicy::Continue.closes_session());
        assert!(StoreFailurePolicy::CloseSession.closes_session());
    }

    #[test]
    fn test_a_written_store_call_always_proceeds() {
        for policy in [
            StoreFailurePolicy::Continue,
            StoreFailurePolicy::CloseSession,
        ] {
            for write in MUTATIONS.into_iter().chain(ALWAYS_CLOSED) {
                assert_eq!(
                    policy.decide(write, StoreResult::Written),
                    StoreVerdict::Proceed
                );
            }
        }
    }

    #[test]
    fn test_a_failed_mutation_follows_the_policy() {
        for write in MUTATIONS {
            assert_eq!(
                StoreFailurePolicy::Continue.decide(write, StoreResult::Failed),
                StoreVerdict::ProceedUnpersisted
            );
            assert_eq!(
                StoreFailurePolicy::CloseSession.decide(write, StoreResult::Failed),
                StoreVerdict::Close
            );
            assert!(write.failure_owes_reset());
        }
    }

    #[test]
    fn test_a_failed_reset_or_refresh_closes_under_every_policy() {
        for write in ALWAYS_CLOSED {
            for policy in [
                StoreFailurePolicy::Continue,
                StoreFailurePolicy::CloseSession,
            ] {
                assert_eq!(
                    policy.decide(write, StoreResult::Failed),
                    StoreVerdict::Close
                );
            }
        }
        assert!(!StoreWrite::Refresh.failure_owes_reset());
    }

    #[test]
    fn test_store_result_of_maps_a_call_result() {
        assert_eq!(StoreResult::of(&Ok::<(), ()>(())), StoreResult::Written);
        assert_eq!(StoreResult::of(&Err::<(), _>("disk")), StoreResult::Failed);
    }

    #[test]
    fn test_gate_releases_the_action_only_once_resolved() {
        let write = StoreWrite::NextTarget { next: 9 };
        let gate = StoreGate::hold(write, "msg 8");
        assert_eq!(gate.write(), write);
        assert_eq!(
            gate.resolve(StoreFailurePolicy::CloseSession, StoreResult::Written),
            StoreRelease::Deliver("msg 8")
        );
    }

    #[test]
    fn test_gate_under_continue_delivers_an_unpersisted_action() {
        let gate = StoreGate::hold(StoreWrite::NextTarget { next: 9 }, 8_u64);
        assert_eq!(
            gate.resolve(StoreFailurePolicy::Continue, StoreResult::Failed),
            StoreRelease::DeliverUnpersisted(8)
        );
    }

    #[test]
    fn test_gate_under_close_session_hands_the_action_back_with_the_close() {
        let write = StoreWrite::OutboundFrame {
            seq: 4,
            next_sender: 5,
        };
        let gate = StoreGate::hold(write, "frame 4");
        assert_eq!(
            gate.resolve(StoreFailurePolicy::CloseSession, StoreResult::Failed),
            StoreRelease::Close {
                write,
                action: "frame 4"
            }
        );
    }

    #[test]
    fn test_gate_closes_on_a_failed_reset_even_under_continue() {
        let write = StoreWrite::Reset {
            next_sender: 2,
            next_target: 2,
        };
        let gate = StoreGate::hold(write, ());
        assert_eq!(
            gate.resolve(StoreFailurePolicy::Continue, StoreResult::Failed),
            StoreRelease::Close { write, action: () }
        );
    }

    #[test]
    fn test_persisted_counters_write_only_changed_values() {
        let mut persisted = PersistedCounters::new();
        assert_eq!(persisted, PersistedCounters::default());
        assert_eq!(persisted.sender_to_write(1), Some(1));
        assert_eq!(persisted.target_to_write(1), Some(1));
        persisted.record_sender(1);
        persisted.record_target(1);
        assert_eq!(persisted.sender_to_write(1), None);
        assert_eq!(persisted.target_to_write(1), None);
        assert_eq!(persisted.sender_to_write(2), Some(2));
    }

    #[test]
    fn test_plan_target_writes_a_changed_value_once() {
        let mut persisted = PersistedCounters::new();
        assert_eq!(
            persisted.plan_target(5),
            Some(StoreWrite::NextTarget { next: 5 })
        );
        persisted.record_attempt(StoreWrite::NextTarget { next: 5 });
        assert_eq!(persisted.plan_target(5), None);
        assert_eq!(
            persisted.plan_target(6),
            Some(StoreWrite::NextTarget { next: 6 })
        );
    }

    #[test]
    fn test_a_planned_but_unattempted_write_is_planned_again() {
        // A poll driver that plans, then defers the call, must not be told
        // later that nothing needs writing.
        let persisted = PersistedCounters::new();
        let first = persisted.plan_target(7);
        assert_eq!(first, Some(StoreWrite::NextTarget { next: 7 }));
        assert_eq!(persisted.plan_target(7), first);
    }

    #[test]
    fn test_record_attempt_covers_every_counter_a_write_carries() {
        let mut persisted = PersistedCounters::new();
        persisted.record_attempt(StoreWrite::OutboundFrame {
            seq: 4,
            next_sender: 5,
        });
        assert_eq!(persisted.sender_to_write(5), None);
        persisted.record_attempt(StoreWrite::Reset {
            next_sender: 2,
            next_target: 3,
        });
        assert_eq!(persisted.sender_to_write(2), None);
        assert_eq!(persisted.target_to_write(3), None);
        persisted.record_attempt(StoreWrite::Refresh);
        persisted.record_attempt(StoreWrite::AppWatermark { watermark: 9 });
        assert_eq!(persisted.target_to_write(3), None);
    }

    #[test]
    fn test_fail_closed_driver_never_delivers_after_a_failed_target_write() {
        // A sans-IO driver loop: plan the write, hold the message, feed the
        // store's result, act on the release.
        let mut persisted = PersistedCounters::new();
        let mut delivered = Vec::new();
        let mut closed = None;
        let results = [
            StoreResult::Written,
            StoreResult::Failed,
            StoreResult::Written,
        ];
        for (seq, result) in (1_u64..).zip(results) {
            let Some(write) = persisted.plan_target(seq + 1) else {
                continue;
            };
            let gate = StoreGate::hold(write, seq);
            persisted.record_attempt(gate.write());
            match gate.resolve(StoreFailurePolicy::CloseSession, result) {
                StoreRelease::Deliver(msg) | StoreRelease::DeliverUnpersisted(msg) => {
                    delivered.push(msg);
                }
                StoreRelease::Close { write, action } => {
                    closed = Some((write, action));
                    break;
                }
            }
        }
        assert_eq!(delivered, vec![1]);
        assert_eq!(closed, Some((StoreWrite::NextTarget { next: 3 }, 2)));
    }
}
