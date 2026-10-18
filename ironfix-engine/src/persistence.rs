/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Store write policy and the persistence steps the engine performs on it.
//!
//! When a [`MessageStore`] is attached, the engine writes to it in a fixed
//! order (see `doc/adr/0005-fallible-store-writes.md`):
//!
//! 1. An outbound frame is filed and the next sender sequence number persisted,
//!    in one [`MessageStore::file_outbound`] call, before the number is spent
//!    in memory and before the frame's bytes are written to the socket. The
//!    Logon handshakes and the live session share this step.
//! 2. The next target sequence number is persisted before the inbound message
//!    that advanced it is acted on, and before the in-memory expectation
//!    moves: before an administrative message is processed, before an
//!    in-sequence `SequenceReset`-GapFill reaches `from_admin`, and before an
//!    application message is handed to the application. Two messages are
//!    exceptions, listed below.
//! 3. A counter is written only when its value changed.
//!
//! Every store call is bounded by the store timeout
//! ([`Initiator::with_store_timeout`](crate::Initiator::with_store_timeout));
//! an overrun is a failed call, reported as [`StoreError::Timeout`].
//!
//! Every one of those writes can fail. [`StoreFailurePolicy`] decides what a
//! failure means: carry on with a warning (the default, and the behaviour
//! before writes were fallible), or close the session without writing the
//! frame, or acting on the message, that the failure concerns.
//!
//! # Exceptions to the inbound order
//!
//! - The initiator's Logon acknowledgement reaches `from_admin` before its
//!   number is persisted: `from_admin` may refuse the Logon, and the ack's
//!   `ResetSeqNumFlag` (141) has to be applied before its number can be
//!   validated. The number is persisted before the session goes Active and
//!   before `on_logon` runs.
//! - A `SequenceReset` in Reset mode (`GapFillFlag` (123) absent or N) has no
//!   place in the sequence, so it reaches `from_admin` first; its `NewSeqNo`
//!   (36) is persisted once `from_admin` has accepted it, before the
//!   expectation moves.
//!
//! # Crash guarantees depend on the policy
//!
//! Only [`StoreFailurePolicy::CloseSession`] turns the order above into a
//! guarantee. Under [`StoreFailurePolicy::Continue`] a failed write is logged
//! and the session carries on as if it had succeeded: the frame is still
//! written and the message still acted on. A crash after such a failure can
//! leave the store behind what the counterparty has seen, so Continue gives
//! **no** crash guarantee. It keeps a session running through a store outage,
//! and nothing more.
//!
//! # Inbound delivery is at most once
//!
//! Because the target counter is persisted before an application message is
//! handed over, a crash after that write and before `from_app` has finished
//! with the message loses it to the application: on restart the engine expects
//! the next number, and the counterparty is never asked for this one again.
//! The window is every message waiting in the application queue, up to its
//! capacity (1024 by default, see
//! [`Initiator::with_app_queue_capacity`](crate::Initiator::with_app_queue_capacity)),
//! plus the one `from_app` is handling.
//!
//! The same messages can be lost while the process runs, without a crash: when
//! the session closes, the dispatcher gets a bounded time to finish its queue
//! and is then aborted. The engine logs, at error level, the range of
//! `MsgSeqNum`s it had handed over and `from_app` had not finished.
//!
//! Under [`StoreFailurePolicy::CloseSession`] a message whose counter write
//! failed is never handed over; under [`StoreFailurePolicy::Continue`] it is.
//!
//! What this does **not** provide: the engine does not detect or report, after
//! a restart, the inbound messages lost across a crash, so the "lost message
//! is reported" requirement of issue #89 is not met for inbound traffic.
//! Reporting needs a completion signal from the dispatcher back to the
//! reactor, a durable application watermark (a new defaulted
//! [`MessageStore`] method), and a typed report at restart of the numbers
//! between that watermark and the persisted target. At-least-once delivery
//! additionally needs an inbound journal, or redelivery through a
//! `ResendRequest`. Both are tracked in issue #105.
//!
//! # A reset that could not be made
//!
//! Two resets can fail after the decision to reset has been taken:
//!
//! - `reset_on_logout` and `reset_on_disconnect` reset the store as the
//!   session closes. If that reset fails, no counter is written: the reset
//!   values written over a store still holding the previous stream would
//!   describe neither.
//! - A Logon acknowledgement carrying `ResetSeqNumFlag` (141) = Y, when the
//!   Logon did not ask for a reset, makes the engine reset the store and set
//!   both counters to 2 (one [`MessageStore::reset_to`] call) before
//!   `on_logon`. If that fails, the connect fails with [`EngineError::Store`],
//!   whatever the policy: under any policy, carrying on would let a resend in
//!   the new stream replay frames of the previous one.
//!
//! Either way the [`Initiator`](crate::Initiator) records that a reset is
//! owed. Its next `connect` resets the store before anything else, refusing
//! the session with [`EngineError::Store`] if it still cannot, whatever the
//! policy, and its Logon then declares `ResetSeqNumFlag` (141) = Y and starts
//! at 1, so both sides restart the sequence together rather than the retry
//! being refused as too low. The record is cleared once that Logon is
//! acknowledged. It lives in the `Initiator`, not in the store: a process
//! restart forgets it, and the next session starts from the counters the
//! store still holds.
//!
//! The default [`MessageStore::reset_to`] is three calls, not one atomic
//! write: a crash between them leaves the store cleared with its initial
//! counters, and the next session's Logon goes out at 1 without a reset. A
//! durable store should override it.
//!
//! A store failure never logs frame bytes: an outbound Logon carries
//! `Password` (554).

use crate::application::SessionId;
use crate::error::EngineError;
use ironfix_core::error::StoreError;
use ironfix_core::message::MsgType;
use ironfix_session::SequenceManager;
use ironfix_session::sequence::{SequenceCounter, SequenceExhausted};
use ironfix_store::MessageStore;
use std::time::Duration;

/// What the engine does when a write to the attached [`MessageStore`] fails.
///
/// Applies to every write the engine makes during a session: filing an
/// outbound frame, persisting the next sender sequence number, and persisting
/// the next target sequence number. A call that does not finish within the
/// store timeout counts as a failed write. Without a store attached there is
/// nothing to fail and the policy has no effect.
///
/// The resets and the refresh fail closed whatever the policy, because
/// carrying on past any of them would run one sequence stream over another:
/// the reset for a `ResetSeqNumFlag` (141) Logon, the reset when the
/// counterparty declares `ResetSeqNumFlag` on its Logon acknowledgement, a
/// reset owed by the previous session, and the refresh that recovers the
/// counters (see the [module documentation](self)).
///
/// # Example
///
/// ```
/// use ironfix_core::types::CompId;
/// use ironfix_engine::application::NoOpApplication;
/// use ironfix_engine::{Initiator, StoreFailurePolicy};
/// use ironfix_session::SessionConfig;
/// use ironfix_store::{MemoryStore, MessageStore};
/// use std::sync::Arc;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = SessionConfig::new(CompId::new("CLIENT")?, CompId::new("VENUE")?, "FIX.4.4");
/// let store: Arc<dyn MessageStore> = Arc::new(MemoryStore::new());
/// let initiator = Initiator::new(config, Arc::new(NoOpApplication))
///     .with_store(store)
///     .with_store_failure_policy(StoreFailurePolicy::CloseSession);
/// # let _ = initiator;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum StoreFailurePolicy {
    /// Log a warning and carry on: the frame is written anyway, the message
    /// is acted on anyway, and a counter that could not be persisted is simply
    /// not durable.
    ///
    /// A frame that could not be filed cannot be replayed; a later
    /// `ResendRequest` covering it gets a `SequenceReset`-GapFill instead. This
    /// is the default, and what the engine always did before store writes were
    /// fallible. It gives **no** crash guarantee: after a failed write, a crash
    /// can leave the store behind what the counterparty has seen.
    #[default]
    Continue,
    /// Fail closed: a frame whose filing or sender-counter write fails is not
    /// written at all (the counterparty reads no bytes for it), an inbound
    /// message whose target-counter write fails is not acted on, and the
    /// session closes, not gracefully. During the Logon handshake the failure
    /// is returned as [`EngineError::Store`], also when it happens while a
    /// Logon is being refused.
    ///
    /// No Logout is sent on the way out: it would have to be filed like any
    /// other frame, through the store that just failed. The failure is logged
    /// at error level.
    CloseSession,
}

impl StoreFailurePolicy {
    /// Returns whether a failed store write ends the session under this
    /// policy.
    #[must_use]
    pub const fn closes_session(self) -> bool {
        matches!(self, Self::CloseSession)
    }
}

/// Which store call failed, for the log line.
#[derive(Debug, Clone, Copy)]
enum StoreWrite<'m> {
    /// Filing an outbound frame together with the next sender number.
    Frame {
        /// Its `MsgSeqNum` (34).
        seq: u64,
        /// Its `MsgType` (35).
        msg_type: &'m MsgType,
    },
    /// Persisting the next sender sequence number.
    NextSender(u64),
    /// Persisting the next target sequence number.
    NextTarget(u64),
}

/// Runs one store call bounded by `timeout`, reporting an overrun as
/// [`StoreError::Timeout`].
///
/// Every store call the engine makes goes through this: the session awaits
/// the call, so an unbounded one would stall its reactor for as long as the
/// store takes.
///
/// # Errors
/// The call's own error, or [`StoreError::Timeout`] if it did not finish in
/// time.
pub(crate) async fn timed<T>(
    timeout: Duration,
    call: impl Future<Output = Result<T, StoreError>>,
) -> Result<T, StoreError> {
    match tokio::time::timeout(timeout, call).await {
        Ok(result) => result,
        Err(_) => Err(StoreError::Timeout { timeout }),
    }
}

/// A store attached to a session, together with the policy for its write
/// failures and the bound on each call.
///
/// Built wherever the engine writes: the handshakes and the reactor share it,
/// so the ordering and the policy cannot drift between them.
#[derive(Clone, Copy)]
pub(crate) struct SessionStore<'s> {
    /// The attached store.
    store: &'s dyn MessageStore,
    /// What a failed write means.
    policy: StoreFailurePolicy,
    /// Bound on each store call; an overrun is a failed write.
    timeout: Duration,
}

impl<'s> SessionStore<'s> {
    /// Binds `store` to `policy`, bounding each call by `timeout`.
    #[must_use]
    pub(crate) const fn new(
        store: &'s dyn MessageStore,
        policy: StoreFailurePolicy,
        timeout: Duration,
    ) -> Self {
        Self {
            store,
            policy,
            timeout,
        }
    }

    /// Files an outbound frame under `seq` and persists `next_sender`,
    /// through one [`MessageStore::file_outbound`] call. The caller writes the
    /// frame only after this returns `Ok`.
    ///
    /// The store files before it persists the counter, which makes "counter
    /// persisted, frame not filed" impossible: a crash between the two leaves
    /// a filed frame and the old counter, so the number is reused for a
    /// message the peer never saw and the filed frame is replaced.
    ///
    /// # Errors
    /// Under [`StoreFailurePolicy::CloseSession`], the store's error; the frame
    /// must then not be written. Under [`StoreFailurePolicy::Continue`] the
    /// failure is logged, the counter is written on its own as a best effort
    /// (the combined call may have failed on the frame alone), and `Ok` is
    /// returned.
    pub(crate) async fn file_outbound(
        self,
        session_id: &SessionId,
        seq: u64,
        msg_type: &MsgType,
        frame: &[u8],
        next_sender: u64,
    ) -> Result<(), StoreError> {
        let filed = timed(
            self.timeout,
            self.store.file_outbound(seq, msg_type, frame, next_sender),
        )
        .await;
        match filed {
            Ok(()) => Ok(()),
            Err(err) => {
                self.on_failure(session_id, StoreWrite::Frame { seq, msg_type }, err)?;
                self.persist_sender(session_id, next_sender).await
            }
        }
    }

    /// Persists the next sender sequence number.
    ///
    /// # Errors
    /// The store's error under [`StoreFailurePolicy::CloseSession`].
    pub(crate) async fn persist_sender(
        self,
        session_id: &SessionId,
        next: u64,
    ) -> Result<(), StoreError> {
        match timed(self.timeout, self.store.set_next_sender_seq(next)).await {
            Ok(()) => Ok(()),
            Err(err) => self.on_failure(session_id, StoreWrite::NextSender(next), err),
        }
    }

    /// Persists the next target sequence number.
    ///
    /// # Errors
    /// The store's error under [`StoreFailurePolicy::CloseSession`].
    pub(crate) async fn persist_target(
        self,
        session_id: &SessionId,
        next: u64,
    ) -> Result<(), StoreError> {
        match timed(self.timeout, self.store.set_next_target_seq(next)).await {
            Ok(()) => Ok(()),
            Err(err) => self.on_failure(session_id, StoreWrite::NextTarget(next), err),
        }
    }

    /// Resets the store and sets both counters through one
    /// [`MessageStore::reset_to`] call, for a sequence reset the counterparty
    /// declared on its Logon acknowledgement.
    ///
    /// This one fails closed **whatever the policy**: carrying on with the
    /// previous stream still filed lets a resend in the new stream replay its
    /// frames under numbers the new stream also uses.
    ///
    /// # Errors
    /// The store's error, or [`StoreError::Timeout`], under every policy.
    pub(crate) async fn reset_to(
        self,
        session_id: &SessionId,
        next_sender: u64,
        next_target: u64,
    ) -> Result<(), StoreError> {
        let reset = self.store.reset_to(next_sender, next_target);
        timed(self.timeout, reset).await.inspect_err(|err| {
            tracing::error!(
                session = %session_id,
                error = %err,
                "cannot reset the store for the counterparty's sequence reset: refusing the \
                 session rather than running the new stream over the previous one"
            );
        })
    }

    /// Applies the policy to one failed call: a warning and `Ok` to carry on,
    /// or an error-level line and the error to close. The log line names the
    /// call, never the frame bytes.
    #[cold]
    fn on_failure(
        self,
        session_id: &SessionId,
        write: StoreWrite<'_>,
        err: StoreError,
    ) -> Result<(), StoreError> {
        if self.policy.closes_session() {
            tracing::error!(
                session = %session_id,
                write = ?write,
                error = %err,
                "store write failed under the fail-closed policy: nothing more is written \
                 for it and the session is refused or closed"
            );
            return Err(err);
        }
        match write {
            StoreWrite::Frame { seq, msg_type } => tracing::warn!(
                session = %session_id,
                seq,
                msg_type = msg_type.as_str(),
                error = %err,
                "cannot file outbound message: sending it anyway; a resend of it will be gap-filled"
            ),
            StoreWrite::NextSender(next) => tracing::warn!(
                session = %session_id,
                next,
                error = %err,
                "cannot persist the next sender sequence number: continuing"
            ),
            StoreWrite::NextTarget(next) => tracing::warn!(
                session = %session_id,
                next,
                error = %err,
                "cannot persist the next target sequence number: continuing"
            ),
        }
        Ok(())
    }
}

/// The store binding a Logon handshake writes through, with the counter values
/// it wrote.
///
/// The record is handed to the reactor (see `SessionParams`), so the first
/// pass of the live session does not write those values a second time.
pub(crate) struct HandshakeStore<'s> {
    /// The binding.
    pub(crate) store: SessionStore<'s>,
    /// The counter values written so far.
    pub(crate) persisted: PersistedCounters,
}

/// Files an outbound frame and spends its sequence number, in the one order
/// the Logon handshakes and the live session share.
///
/// `seq` is the number the frame was encoded under, read from `sequences`
/// before encoding. The steps are: work out `seq + 1` with checked arithmetic;
/// when a store is attached, file the frame under `seq` and persist `seq + 1`
/// as the next sender number (recording that value in the counters); spend
/// `seq` in memory and check that it was the number spent. The caller writes
/// the frame only after this returns `Ok`, so the store and the in-memory
/// counter agree before any byte reaches the socket, and a write that fails
/// afterwards cannot lead to `seq` being reused.
///
/// # Errors
/// [`EngineError::SequenceExhausted`] when `seq` is `u64::MAX`;
/// [`EngineError::Store`] when the store write fails under
/// [`StoreFailurePolicy::CloseSession`], in which case nothing is spent; and
/// [`EngineError::Sequence`] if the number spent is not `seq`, which cannot
/// happen while only the reactor and the handshake allocate sender numbers.
pub(crate) async fn file_and_spend(
    store: Option<(SessionStore<'_>, &mut PersistedCounters)>,
    sequences: &SequenceManager,
    session_id: &SessionId,
    seq: u64,
    msg_type: &MsgType,
    frame: &[u8],
) -> Result<(), EngineError> {
    let next = seq.checked_add(1).ok_or(SequenceExhausted {
        counter: SequenceCounter::Sender,
    })?;
    if let Some((store, persisted)) = store {
        persisted.record_sender(next);
        store
            .file_outbound(session_id, seq, msg_type, frame, next)
            .await?;
    }
    let allocated = sequences.try_allocate_sender_seq()?.value();
    if allocated != seq {
        return Err(EngineError::Sequence(format!(
            "sender sequence moved from {seq} to {allocated} while a frame was being built"
        )));
    }
    Ok(())
}

/// The counter values last written to the store, so that a counter is written
/// only when it changed.
///
/// The reactor checks after every event, the 100 ms tick included; without
/// this every tick would cost two store writes. A value is recorded once its
/// write was attempted: under [`StoreFailurePolicy::Continue`] a failed write
/// is not retried every tick, only when the counter moves again.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PersistedCounters {
    /// Last next-sender value written, if any.
    sender: Option<u64>,
    /// Last next-target value written, if any.
    target: Option<u64>,
}

impl PersistedCounters {
    /// Returns `current` if it differs from the last next-sender value
    /// written.
    #[must_use]
    pub(crate) fn sender_to_write(self, current: u64) -> Option<u64> {
        (self.sender != Some(current)).then_some(current)
    }

    /// Returns `current` if it differs from the last next-target value
    /// written.
    #[must_use]
    pub(crate) fn target_to_write(self, current: u64) -> Option<u64> {
        (self.target != Some(current)).then_some(current)
    }

    /// Records that `value` was written as the next sender sequence number.
    pub(crate) const fn record_sender(&mut self, value: u64) {
        self.sender = Some(value);
    }

    /// Records that `value` was written as the next target sequence number.
    pub(crate) const fn record_target(&mut self, value: u64) {
        self.target = Some(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_failure_policy_defaults_to_continue() {
        assert_eq!(StoreFailurePolicy::default(), StoreFailurePolicy::Continue);
        assert!(!StoreFailurePolicy::Continue.closes_session());
        assert!(StoreFailurePolicy::CloseSession.closes_session());
    }

    #[test]
    fn test_persisted_counters_write_only_changed_values() {
        let mut counters = PersistedCounters::default();
        // Nothing written yet: every value is new.
        assert_eq!(counters.sender_to_write(1), Some(1));
        assert_eq!(counters.target_to_write(1), Some(1));

        counters.record_sender(2);
        counters.record_target(5);
        assert_eq!(counters.sender_to_write(2), None);
        assert_eq!(counters.target_to_write(5), None);
        assert_eq!(counters.sender_to_write(3), Some(3));
        // A reset moves a counter down; that is a change too.
        assert_eq!(counters.target_to_write(1), Some(1));
    }
}
