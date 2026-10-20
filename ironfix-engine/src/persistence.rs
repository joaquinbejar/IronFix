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
//! and is then aborted.
//!
//! Under [`StoreFailurePolicy::CloseSession`] a message whose counter write
//! failed is never handed over; under [`StoreFailurePolicy::Continue`] it is.
//!
//! # A lost inbound message is reported, not redelivered
//!
//! The loss is reported (issue #105, `doc/adr/0030-inbound-loss-report.md`):
//!
//! - **The watermark.** The dispatcher persists the inbound application
//!   watermark ([`MessageStore::set_app_watermark`]) after `from_app` returns
//!   for each message, and after the reactor has processed the
//!   administrative messages accepted since, so the stored watermark is the
//!   highest number up to which every accepted message was acted on. A
//!   failed write follows the policy: under
//!   [`StoreFailurePolicy::CloseSession`] the dispatcher stops delivering
//!   and the session closes.
//! - **At start.** Before the store is seeded, a session with a store
//!   reports the span between the stored watermark and the stored next
//!   target through [`Application::on_inbound_lost`], then writes the
//!   watermark up to it.
//! - **At close.** A dispatcher aborted after its drain timeout, or stopped
//!   by a failed watermark write, has its unfinished span reported the same
//!   way before `on_session_closed`, and the watermark is written up to it,
//!   so the next start does not report it again.
//! - **A reset clears it.** A store reset sets the watermark to 0 (none):
//!   the span it described belongs to the stream the reset replaced.
//!
//! The engine keeps no inbound journal and does not ask the counterparty to
//! resend numbers it has accepted, so delivery stays at most once.
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
//! being refused as too low. That reset is paid once that Logon is
//! acknowledged.
//!
//! The [`Acceptor`](crate::Acceptor) keeps the same record: a failed
//! close-time reset, or a failed reset for a session that resets, is owed to
//! its next accepted Logon, whose acknowledgement then declares the reset at
//! 1; that reset is paid once that acknowledgement is sent. The acceptor
//! resets its store only for a Logon that passes every check, so a refused
//! Logon cannot clear it, whatever it declares.
//!
//! # The owed reset is durable
//!
//! The record lives in the engine, and is mirrored by a durable marker in the
//! store ([`MessageStore::set_reset_owed`], issue #111,
//! `doc/adr/0029-durable-owed-reset.md`):
//!
//! - **Set before acting.** Before any reset is made (a Logon or Logon
//!   acknowledgement that declares one, the initiator's reset for a resetting
//!   acknowledgement, the close-time reset), the engine records the
//!   obligation and writes the marker. For a reset made in a handshake, a
//!   marker write that fails refuses the session whatever the policy: the
//!   reset must not be acted on unless its intent survives a crash. The
//!   close-time reset is made even if the marker cannot be written, since
//!   leaving the previous stream in place is worse; the failure is logged.
//! - **Set after a failed mutation**, as a best effort: the store just failed
//!   and may fail this too, which is logged.
//! - **Read at the start of every session.** A store whose marker is set
//!   makes the session reset the store and declare `ResetSeqNumFlag` (141) =
//!   Y at 1, in either role, exactly like a reset this engine owes.
//! - **Cleared only once paid**: after the Logon declaring the reset is
//!   acknowledged (initiator) or the acknowledgement declaring it is sent
//!   (acceptor), before `on_logon`; after a close-time reset has succeeded.
//!   It is cleared only if nothing else is owed by then. A clear that fails
//!   leaves the reset owed, so the next session resets again: the safe
//!   direction. In a handshake it follows the policy, closing the session
//!   under [`StoreFailurePolicy::CloseSession`].
//!
//! A crash at any point from the marker write on therefore restarts with a
//! reset. One window is left: between a resetting Logon acknowledgement
//! arriving and the marker being durable, a crash restarts from the previous
//! stream's counters, as if the acknowledgement had never arrived.
//!
//! A store that does not override the marker methods keeps no marker, and the
//! record is then in memory only, as before #111. A store must belong to
//! exactly one engine instance.
//!
//! The default [`MessageStore::reset_to`] is three calls, not one atomic
//! write: a crash between them leaves the store cleared with its initial
//! counters, and the next session's Logon goes out at 1 without a reset. A
//! durable store should override it.
//!
//! # Cancellation and timeouts
//!
//! A reset is recorded as owed **before** the engine awaits it, and it is
//! paid only once it has succeeded (for a reset declared on a Logon, once that
//! Logon is acknowledged). A caller that drops a connect while a reset is
//! pending, or a runtime that drops a closing session, runs no error branch;
//! the record still says the reset is owed, and the next session makes it and
//! declares it.
//!
//! The record is kept by generation: every obligation is numbered when it is
//! recorded, and paying a reset settles the obligation it was started for and
//! every earlier one, never a later one. The reset erased whatever an earlier
//! failed write left, but not what a write made after it started, so a store
//! write that fails during the handshake paying an owed reset, before or
//! after the acknowledgement, stays owed once that reset is paid, and the
//! next session resets again.
//!
//! A timeout drops the store call's future, not necessarily the work the store
//! has already submitted: a disk or replication write can still land later.
//! After any mutation overruns the store timeout, the engine therefore treats
//! the store as possibly holding an outstanding write and records a reset as
//! owed: the next session starts a new stream, with a reset and
//! `ResetSeqNumFlag` (141) = Y, rather than building on counters a late write
//! may still move. That is safe only for a store that applies its mutations in
//! call order even when a call's future is dropped, as the [`MessageStore`]
//! contract requires: the late write then lands before the next session's
//! reset, which erases it. A store that does not can apply the late write after
//! the next session's own writes, erasing a filed frame or moving a counter of
//! the new stream; such a store must not be reused after a timed-out mutation.
//!
//! A mutation that fails with any other error is treated the same way, under
//! both policies: the [`MessageStore`] contract gives a store no way to say
//! that a failed write changed nothing (a disk write can fail after part of it
//! reached the file, a flush can fail after the write it covers), so the
//! store's state after it is unknown, and a reset is owed. Under
//! [`StoreFailurePolicy::Continue`] that means the session carries on and the
//! next one starts with a reset and `ResetSeqNumFlag` (141) = Y.
//!
//! A store failure never logs frame bytes: an outbound Logon carries
//! `Password` (554).

use crate::application::{Application, SessionId};
use crate::error::EngineError;
use crate::loss::{InboundLoss, InboundLossCause};
use ironfix_core::error::StoreError;
use ironfix_core::message::MsgType;
use ironfix_session::sequence::{SequenceCounter, SequenceExhausted};
use ironfix_session::{
    SeedSource, SequenceManager, StoreSeed, decide_seed_source, initial_below_store,
    seed_from_initial, seed_from_store,
};
use ironfix_store::MessageStore;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// A frame whose filing failed is not confirmed as filed; a later
    /// `ResendRequest` covering it replays it if the store saved it despite
    /// the error, and gets a `SequenceReset`-GapFill otherwise. This
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
    /// Persisting the inbound application watermark (ADR-0030).
    AppWatermark(u64),
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
/// failures, the bound on each call, and the engine's owed-reset record.
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
    /// The engine's record of resets owed to the next session; a mutation
    /// that fails or overruns the timeout adds one.
    owed: &'s OwedReset,
}

impl<'s> SessionStore<'s> {
    /// Binds `store` to `policy`, bounding each call by `timeout`; a mutation
    /// that fails or overruns it leaves a reset owed in `owed`.
    #[must_use]
    pub(crate) const fn new(
        store: &'s dyn MessageStore,
        policy: StoreFailurePolicy,
        timeout: Duration,
        owed: &'s OwedReset,
    ) -> Self {
        Self {
            store,
            policy,
            timeout,
            owed,
        }
    }

    /// Runs one mutation bounded by the timeout.
    ///
    /// A timeout drops the call's future, not necessarily the work the store
    /// has already submitted: a disk or replication write can still land
    /// later. After an overrun the store is therefore treated as possibly
    /// holding an outstanding write, and a reset is owed, so the next session
    /// starts a new stream (a reset, and `ResetSeqNumFlag` (141) = Y) instead
    /// of building on counters a late write may still move. That is safe only
    /// for a store that applies its mutations in call order even when a call's
    /// future is dropped (see [`MessageStore`]): the late write then lands
    /// before the reset, which erases it.
    ///
    /// A mutation that fails with any other error owes a reset too, under
    /// every policy: the store cannot say that a failed write changed nothing
    /// (part of a disk write can reach the file before it fails, and a failed
    /// flush can drop what earlier writes left), so its state is unknown.
    ///
    /// # Errors
    /// The store's error, or [`StoreError::Timeout`].
    async fn mutate(
        self,
        call: impl Future<Output = Result<(), StoreError>>,
    ) -> Result<(), StoreError> {
        let result = timed(self.timeout, call).await;
        if result.is_err() {
            let _ = self.owed.owe();
            // Best effort: the store just failed, and may fail this too. The
            // reset stays owed in memory either way, and the next session
            // makes it.
            if let Err(err) = sync_marker(self.owed, self.store, self.timeout).await {
                tracing::warn!(
                    error = %err,
                    "cannot record the owed sequence reset in the store after a failed write: \
                     it is owed in memory only, and a restart before the next session forgets it"
                );
            }
        }
        result
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
    /// Returns whether the frame was filed: true only when the store's
    /// `file_outbound` returned `Ok`.
    ///
    /// # Errors
    /// Under [`StoreFailurePolicy::CloseSession`], the store's error; the frame
    /// must then not be written. Under [`StoreFailurePolicy::Continue`] the
    /// failure is logged, the counter is written on its own as a best effort
    /// (the combined call may have failed on the frame alone), and `Ok(false)`
    /// is returned: the frame goes out unfiled.
    pub(crate) async fn file_outbound(
        self,
        session_id: &SessionId,
        seq: u64,
        msg_type: &MsgType,
        frame: &[u8],
        next_sender: u64,
    ) -> Result<bool, StoreError> {
        let filed = self
            .mutate(self.store.file_outbound(seq, msg_type, frame, next_sender))
            .await;
        match filed {
            Ok(()) => Ok(true),
            Err(err) => {
                self.on_failure(session_id, StoreWrite::Frame { seq, msg_type }, err)?;
                self.persist_sender(session_id, next_sender)
                    .await
                    .map(|()| false)
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
        match self.mutate(self.store.set_next_sender_seq(next)).await {
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
        match self.mutate(self.store.set_next_target_seq(next)).await {
            Ok(()) => Ok(()),
            Err(err) => self.on_failure(session_id, StoreWrite::NextTarget(next), err),
        }
    }

    /// Persists the inbound application watermark (ADR-0030).
    ///
    /// A failure is handled like any other mutation's: it owes a reset (the
    /// store cannot say the failed write changed nothing), and the policy
    /// decides whether it closes the session. A watermark that did not land
    /// leaves the stored one lower, so the next start reports more as
    /// possibly lost, never less.
    ///
    /// # Errors
    /// The store's error under [`StoreFailurePolicy::CloseSession`].
    pub(crate) async fn persist_app_watermark(
        self,
        session_id: &SessionId,
        watermark: u64,
    ) -> Result<(), StoreError> {
        match self.mutate(self.store.set_app_watermark(watermark)).await {
            Ok(()) => Ok(()),
            Err(err) => self.on_failure(session_id, StoreWrite::AppWatermark(watermark), err),
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
        self.mutate(reset).await.inspect_err(|err| {
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
            StoreWrite::AppWatermark(watermark) => tracing::warn!(
                session = %session_id,
                watermark,
                error = %err,
                "cannot persist the inbound application watermark: continuing; the next \
                 session start may report messages from_app has seen as possibly lost"
            ),
        }
        Ok(())
    }
}

/// The record of the resets an engine owes its next session, kept by
/// generation.
///
/// Every obligation gets a number, in the order it is recorded: a reset the
/// engine is about to make (recorded before it is awaited, so a dropped call
/// still leaves it owed), a reset that could not be made, and a store mutation
/// that failed or overran the store timeout. Paying a reset settles the
/// obligation it was started for and every earlier one, and no later one: the
/// reset erased what the store held before it, including whatever an earlier
/// failed write left (a store applies its mutations in call order), but not
/// what a write made after it started. A store write that fails during the
/// Logon handshake that pays an owed reset, before or after the
/// acknowledgement, therefore stays owed once that reset is paid.
///
/// The generations live in memory; what survives a restart is the store's
/// durable marker ([`MessageStore::reset_owed`]), which [`sync_marker`] keeps
/// in line with [`OwedReset::is_owed`] and
/// [`StoreAttachment::reset_is_owed`] reads back (#111, ADR-0029).
#[derive(Debug, Default)]
pub(crate) struct OwedReset {
    /// Number of the last obligation recorded.
    recorded: AtomicU64,
    /// Number of the last obligation settled.
    settled: AtomicU64,
    /// Serialises the marker writes, so that a clear computed before an
    /// obligation was recorded can never land after the write recording it.
    /// A `tokio` mutex: it is held across the store call.
    marker: tokio::sync::Mutex<()>,
}

/// The number of the obligation a reset was started for. Paying it settles
/// that obligation and every earlier one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a reset ticket is how the reset is later paid"]
pub(crate) struct ResetTicket(u64);

impl OwedReset {
    /// Records an obligation and returns its number.
    pub(crate) fn owe(&self) -> ResetTicket {
        let mut current = self.recorded.load(Ordering::Acquire);
        loop {
            // Exhausting u64 obligations is not reachable; if it were, the
            // record would stay at its maximum, which still reads as owed
            // until a reset started at that number is paid.
            let Some(next) = current.checked_add(1) else {
                return ResetTicket(current);
            };
            match self.recorded.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return ResetTicket(next),
                Err(actual) => current = actual,
            }
        }
    }

    /// Whether an obligation is still unsettled.
    #[must_use]
    pub(crate) fn is_owed(&self) -> bool {
        self.recorded.load(Ordering::Acquire) > self.settled.load(Ordering::Acquire)
    }

    /// Settles the obligation `ticket` names and every earlier one.
    pub(crate) fn pay(&self, ticket: ResetTicket) {
        self.settled.fetch_max(ticket.0, Ordering::AcqRel);
    }

    /// Records an obligation unless one is already unsettled: a reset the
    /// store's durable marker says an earlier process owed.
    fn recover(&self) {
        if !self.is_owed() {
            let _ = self.owe();
        }
    }
}

/// Brings the store's durable owed-reset marker in line with `owed`: sets it
/// while a reset is owed, clears it once every obligation is settled, and
/// writes nothing when the store already says so.
///
/// Called before every reset the engine makes (the marker must be durable
/// before the reset is acted on), after a reset is paid, and after a store
/// mutation fails. The writes are serialised, and each one writes the state
/// of the record when it runs, so the last one to land always reflects the
/// latest obligation. A failed clear records an obligation again: the marker
/// may still be set, and the record must never say less than the store.
///
/// # Errors
/// The store's error, or [`StoreError::Timeout`].
pub(crate) async fn sync_marker(
    owed: &OwedReset,
    store: &dyn MessageStore,
    timeout: Duration,
) -> Result<(), StoreError> {
    let _serial = owed.marker.lock().await;
    let desired = owed.is_owed();
    if store.reset_owed() == desired {
        return Ok(());
    }
    let result = timed(timeout, store.set_reset_owed(desired)).await;
    if result.is_err() && !desired {
        let _ = owed.owe();
    }
    result
}

/// A store attached to an engine, with its failure policy, the bound on each
/// call and the owed-reset record.
///
/// Both engines hold one, so the store settings and the inputs to
/// [`seed_session`] cannot drift between the roles. The owed-reset record is
/// mirrored by the store's durable marker, so a restart over the same store
/// still finds it (see the module documentation).
#[derive(Default)]
pub(crate) struct StoreAttachment {
    /// The attached store, if any.
    store: Option<Arc<dyn MessageStore>>,
    /// What a failed write to `store` means.
    policy: StoreFailurePolicy,
    /// Bound on each store call, or `None` for the engine's write timeout.
    timeout: Option<Duration>,
    /// The resets owed to the next session, by generation.
    reset_owed: Arc<OwedReset>,
}

/// Written by hand rather than derived: `dyn MessageStore` is not `Debug`.
impl std::fmt::Debug for StoreAttachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreAttachment")
            .field("store", &self.store.is_some())
            .field("policy", &self.policy)
            .field("timeout", &self.timeout)
            .field("reset_owed", &self.reset_is_owed())
            .finish()
    }
}

impl StoreAttachment {
    /// Attaches `store`.
    pub(crate) fn attach(&mut self, store: Arc<dyn MessageStore>) {
        self.store = Some(store);
    }

    /// Sets the store failure policy.
    pub(crate) const fn set_policy(&mut self, policy: StoreFailurePolicy) {
        self.policy = policy;
    }

    /// Sets the bound on each store call.
    pub(crate) const fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = Some(timeout);
    }

    /// The attached store, if any.
    #[must_use]
    pub(crate) const fn store(&self) -> Option<&Arc<dyn MessageStore>> {
        self.store.as_ref()
    }

    /// The store failure policy.
    #[must_use]
    pub(crate) const fn policy(&self) -> StoreFailurePolicy {
        self.policy
    }

    /// The bound on one store call: the configured one, or `write_timeout`
    /// when none was set.
    #[must_use]
    pub(crate) fn timeout(&self, write_timeout: Duration) -> Duration {
        self.timeout.unwrap_or(write_timeout)
    }

    /// Whether a store is attached and a reset is owed: by this engine, or
    /// by an earlier one whose intent the store's durable marker carries. A
    /// marker found set is taken into the in-memory record, so it is cleared
    /// only once a reset made after it is paid.
    #[must_use]
    pub(crate) fn reset_is_owed(&self) -> bool {
        let Some(store) = self.store.as_deref() else {
            return false;
        };
        if store.reset_owed() {
            self.reset_owed.recover();
        }
        self.reset_owed.is_owed()
    }

    /// Makes the store's durable marker match the owed-reset record (see
    /// [`sync_marker`]); nothing to do without a store.
    ///
    /// # Errors
    /// The store's error, or [`StoreError::Timeout`].
    pub(crate) async fn sync_marker(&self, write_timeout: Duration) -> Result<(), StoreError> {
        match self.store.as_deref() {
            Some(store) => sync_marker(&self.reset_owed, store, self.timeout(write_timeout)).await,
            None => Ok(()),
        }
    }

    /// Records the reset `ticket` was taken for as made and declared, then
    /// clears the store's durable marker if nothing else is owed.
    ///
    /// A clear that fails leaves the reset owed (the marker may still be
    /// set), so the next session resets again: the safe direction. Under
    /// [`StoreFailurePolicy::CloseSession`] the failure is returned, as for
    /// every failed write; under [`StoreFailurePolicy::Continue`] it is
    /// logged.
    ///
    /// # Errors
    /// The store's error under [`StoreFailurePolicy::CloseSession`].
    pub(crate) async fn settle(
        &self,
        session_id: &SessionId,
        ticket: Option<ResetTicket>,
        write_timeout: Duration,
    ) -> Result<(), StoreError> {
        if let Some(ticket) = ticket {
            self.reset_paid(ticket);
        }
        match self.sync_marker(write_timeout).await {
            Ok(()) => Ok(()),
            Err(err) if self.policy.closes_session() => {
                tracing::error!(
                    session = %session_id,
                    error = %err,
                    "cannot clear the owed-reset marker under the fail-closed policy: the \
                     session is refused, and the next one resets again"
                );
                Err(err)
            }
            Err(err) => {
                tracing::warn!(
                    session = %session_id,
                    error = %err,
                    "cannot clear the owed-reset marker: the next session resets again"
                );
                Ok(())
            }
        }
    }

    /// Records that a reset is owed and makes the store's durable marker say
    /// so, before the reset is attempted. Returns the ticket that pays it.
    ///
    /// # Errors
    /// The store's error, or [`StoreError::Timeout`], whatever the policy:
    /// the reset must not be acted on unless its intent survives a crash.
    /// The reset stays owed in memory.
    pub(crate) async fn owe_durably(
        &self,
        session_id: &SessionId,
        write_timeout: Duration,
    ) -> Result<ResetTicket, StoreError> {
        let ticket = self.owe_reset();
        self.sync_marker(write_timeout).await.inspect_err(|err| {
            tracing::error!(
                session = %session_id,
                error = %err,
                "cannot record the owed sequence reset in the store: refusing the session \
                 rather than resetting with an intent a crash could lose"
            );
        })?;
        Ok(ticket)
    }

    /// Records that a reset is owed, before it is attempted, and returns the
    /// ticket that pays it.
    pub(crate) fn owe_reset(&self) -> ResetTicket {
        self.reset_owed.owe()
    }

    /// Records that the reset `ticket` was taken for has been made and
    /// declared to the counterparty. Anything owed since the ticket was taken
    /// stays owed.
    pub(crate) fn reset_paid(&self, ticket: ResetTicket) {
        self.reset_owed.pay(ticket);
    }

    /// Reports to `application` the inbound span the previous session
    /// accepted above the store's application watermark, then records it as
    /// reported by writing the watermark up to the stored next target
    /// (issue #105, ADR-0030). Nothing happens without a store, or when the
    /// store's watermark covers everything it accepted.
    ///
    /// Called by both roles before the store is seeded (a reset would erase
    /// the numbers), with the values the store holds when the session
    /// starts. The callback runs before the write, so a crash in between
    /// reports the span again, never not at all. Nothing is redelivered.
    ///
    /// # Errors
    /// The store's error, under [`StoreFailurePolicy::CloseSession`] only:
    /// the session is then refused, and the span is reported again by the
    /// next one.
    pub(crate) async fn report_inbound_loss<A: Application + ?Sized>(
        &self,
        application: &A,
        session_id: &SessionId,
        write_timeout: Duration,
    ) -> Result<(), StoreError> {
        let Some(store) = self.store.as_deref() else {
            return Ok(());
        };
        let Some(loss) = InboundLoss::between(
            store.app_watermark(),
            store.next_target_seq(),
            InboundLossCause::FoundAtStart,
        ) else {
            return Ok(());
        };
        tracing::warn!(
            session = %session_id,
            first = loss.first(),
            last = loss.last(),
            "inbound messages accepted by the previous session may not have reached from_app: \
             reporting the span to the application; they are not redelivered"
        );
        application.on_inbound_lost(session_id, &loss).await;
        SessionStore::new(
            store,
            self.policy,
            self.timeout(write_timeout),
            &self.reset_owed,
        )
        .persist_app_watermark(session_id, loss.last())
        .await
    }

    /// The owed-reset record, shared with a session's reactor so its
    /// close-time reset and its failed writes can owe one.
    #[must_use]
    pub(crate) fn owed_record(&self) -> Arc<OwedReset> {
        Arc::clone(&self.reset_owed)
    }

    /// The inputs to [`seed_session`] for a session of this engine.
    #[must_use]
    pub(crate) fn seed_plan<'a>(
        &'a self,
        session_id: &'a SessionId,
        reset: bool,
        initial: Option<(u64, u64)>,
        write_timeout: Duration,
    ) -> SeedPlan<'a> {
        SeedPlan {
            session_id,
            store: self.store.as_deref(),
            policy: self.policy,
            timeout: self.timeout(write_timeout),
            reset,
            initial,
        }
    }

    /// The binding a Logon handshake writes through, starting from the
    /// counter values `persisted` records, or `None` without a store.
    #[must_use]
    pub(crate) fn handshake(
        &self,
        persisted: PersistedCounters,
        write_timeout: Duration,
    ) -> Option<HandshakeStore<'_>> {
        self.store.as_deref().map(|store| HandshakeStore {
            store: SessionStore::new(
                store,
                self.policy,
                self.timeout(write_timeout),
                &self.reset_owed,
            ),
            persisted,
        })
    }
}

/// The counters an explicit initial seed starts a session from.
///
/// # Errors
/// [`EngineError::InvalidInitialSequence`] for a zero seed: FIX numbers
/// messages from 1, and a `MsgSeqNum` (34) of 0 is rejected by every
/// conforming counterparty. Refused rather than raised to 1, in both roles.
pub(crate) fn seeded_counters(
    (sender, target): (u64, u64),
) -> Result<SequenceManager, EngineError> {
    seed_from_initial((sender, target))
        .map_err(|counter| EngineError::InvalidInitialSequence { counter })
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

impl HandshakeStore<'_> {
    /// Persists `next` as the next target sequence number, unless that is the
    /// value already recorded as written.
    ///
    /// # Errors
    /// The store's error under [`StoreFailurePolicy::CloseSession`].
    pub(crate) async fn persist_target(
        &mut self,
        session_id: &SessionId,
        next: u64,
    ) -> Result<(), StoreError> {
        if self.persisted.target_to_write(next).is_none() {
            return Ok(());
        }
        self.persisted.record_target(next);
        self.store.persist_target(session_id, next).await
    }

    /// Resets the store and sets both counters through one
    /// [`SessionStore::reset_to`] call, which fails closed whatever the
    /// policy, and records both values as written.
    ///
    /// # Errors
    /// The store's error, under every policy.
    pub(crate) async fn reset_to(
        &mut self,
        session_id: &SessionId,
        next_sender: u64,
        next_target: u64,
    ) -> Result<(), StoreError> {
        self.store
            .reset_to(session_id, next_sender, next_target)
            .await?;
        // The reset replaced whatever was recorded as written.
        self.persisted = PersistedCounters::default();
        self.persisted.record_sender(next_sender);
        self.persisted.record_target(next_target);
        Ok(())
    }
}

/// What a session starts from: its sequence counters, and which of their
/// values the store already holds.
pub(crate) struct Seeded {
    /// The sequence counters.
    pub(crate) sequences: SequenceManager,
    /// The counter values the store holds, so they are not written back
    /// unchanged.
    pub(crate) persisted: PersistedCounters,
    /// The (next sender, next target) the attached store held before any
    /// seed or reset was applied, for the mismatch report (ADR-0015); `None`
    /// without a store.
    pub(crate) stored: Option<(u64, u64)>,
}

/// The inputs [`seed_session`] decides a session's counters from.
pub(crate) struct SeedPlan<'a> {
    /// The session, for the log lines.
    pub(crate) session_id: &'a SessionId,
    /// The attached store, if any.
    pub(crate) store: Option<&'a dyn MessageStore>,
    /// The store failure policy.
    pub(crate) policy: StoreFailurePolicy,
    /// Bound on each store call.
    pub(crate) timeout: Duration,
    /// Whether the session starts a new sequence stream at 1, clearing the
    /// store: a `ResetSeqNumFlag` (141) Logon in either direction, the local
    /// `reset_on_logon`, or a reset an earlier session owes.
    pub(crate) reset: bool,
    /// Explicit initial (sender, target) numbers, if configured.
    pub(crate) initial: Option<(u64, u64)>,
}

/// Decides the sequence numbers a session starts from, for either role.
///
/// By priority, highest first:
///
/// 1. `reset` — both counters start at 1, and the store is reset to 1/1 in one
///    [`MessageStore::reset_to`] call. Keeping the old messages would leave two
///    different streams filed under the same numbers, and a later
///    `ResendRequest` could not tell them apart.
/// 2. An explicit initial seed outranks whatever the store remembers. Under
///    [`StoreFailurePolicy::CloseSession`] the store is refreshed first and a
///    sender seed below its next sender number is refused.
/// 3. The store's own counters, refreshed from its backing medium first.
///    Those are values the store already holds, so they are recorded as
///    written and the session does not write them back unchanged.
/// 4. A fresh session at 1/1.
///
/// Every store call is bounded by the plan's timeout, and fails closed
/// whatever the policy.
///
/// # Errors
/// [`EngineError::Store`] if the store cannot be reset (case 1) or refreshed
/// (case 3, and case 2 under [`StoreFailurePolicy::CloseSession`]): starting at
/// 1 with the previous stream still filed would let a later `ResendRequest`
/// replay it, and starting against un-refreshed counters would reuse a
/// `MsgSeqNum` the counterparty has already seen.
/// [`EngineError::InitialSequenceBelowStore`] for a sender seed below the
/// store's next sender number under [`StoreFailurePolicy::CloseSession`].
/// [`EngineError::InvalidInitialSequence`] for a zero seed (case 2).
pub(crate) async fn seed_session(plan: SeedPlan<'_>) -> Result<Seeded, EngineError> {
    let SeedPlan {
        session_id,
        store,
        policy,
        timeout,
        reset,
        initial,
    } = plan;
    let mut persisted = PersistedCounters::default();

    // Where the counters come from is the sans-IO core's decision (issue
    // #91, stage 5); the store calls stay here.
    let source = decide_seed_source(
        reset,
        initial.is_some(),
        store.is_some(),
        policy.closes_session(),
    );
    match (source, initial, store) {
        (SeedSource::Reset, _, store) => {
            let stored = store.map(|store| (store.next_sender_seq(), store.next_target_seq()));
            if let Some(store) = store {
                if let Err(err) = timed(timeout, store.reset_to(1, 1)).await {
                    tracing::error!(
                        session = %session_id,
                        error = %err,
                        "cannot reset the store for a session that starts a new sequence \
                         stream: refusing the session rather than starting at 1 with the \
                         previous stream still filed"
                    );
                    return Err(EngineError::Store(err));
                }
                persisted.record_sender(1);
                persisted.record_target(1);
            }
            Ok(Seeded {
                sequences: SequenceManager::new(),
                persisted,
                stored,
            })
        }
        (SeedSource::Initial { check_store }, Some(initial), store) => {
            let sequences = seeded_counters(initial)?;
            let (sender, _) = initial;
            if check_store && let Some(store) = store {
                refresh(session_id, store, timeout).await?;
                let stored = store.next_sender_seq();
                if initial_below_store(sender, stored) {
                    tracing::error!(
                        session = %session_id,
                        seeded = sender,
                        stored,
                        "initial sender sequence number is below the store's next sender \
                         number: refusing the session rather than reusing a MsgSeqNum already \
                         sent"
                    );
                    return Err(EngineError::InitialSequenceBelowStore {
                        seeded: sender,
                        stored,
                    });
                }
            }
            let stored = store.map(|store| (store.next_sender_seq(), store.next_target_seq()));
            Ok(Seeded {
                sequences,
                persisted,
                stored,
            })
        }
        (SeedSource::Store, _, Some(store)) => {
            refresh(session_id, store, timeout).await?;
            let sender = store.next_sender_seq();
            let target = store.next_target_seq();
            // A store reporting 0 is floored at 1 by the core, and a floored
            // value is not one the store holds, so it is not recorded.
            let StoreSeed {
                sequences,
                sender_held,
                target_held,
            } = seed_from_store(sender, target);
            if sender_held {
                persisted.record_sender(sender);
            }
            if target_held {
                persisted.record_target(target);
            }
            Ok(Seeded {
                stored: Some((sender, target)),
                sequences,
                persisted,
            })
        }
        (SeedSource::Fresh, _, _)
        | (SeedSource::Initial { .. }, None, _)
        | (SeedSource::Store, _, None) => {
            debug_assert!(
                matches!(source, SeedSource::Fresh),
                "the seed source follows the plan's seed and store"
            );
            Ok(Seeded {
                sequences: SequenceManager::new(),
                persisted,
                stored: None,
            })
        }
    }
}

/// Refreshes `store` from its backing medium, bounded by `timeout`.
///
/// # Errors
/// [`EngineError::Store`] if the refresh fails or overruns, whatever the
/// policy: the counters it would have recovered are what the session is about
/// to number its messages from.
async fn refresh(
    session_id: &SessionId,
    store: &dyn MessageStore,
    timeout: Duration,
) -> Result<(), EngineError> {
    timed(timeout, store.refresh()).await.map_err(|err| {
        tracing::error!(
            session = %session_id,
            error = %err,
            "cannot refresh the store: refusing the session rather than starting against \
             unknown counters and risking a reused MsgSeqNum"
        );
        EngineError::Store(err)
    })
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
/// Returns whether the store confirmed it filed the frame: false without a
/// store, and false under [`StoreFailurePolicy::Continue`] when the filing
/// failed or timed out (the store may still hold the frame).
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
) -> Result<bool, EngineError> {
    let next = seq.checked_add(1).ok_or(SequenceExhausted {
        counter: SequenceCounter::Sender,
    })?;
    let filed = match store {
        Some((store, persisted)) => {
            persisted.record_sender(next);
            store
                .file_outbound(session_id, seq, msg_type, frame, next)
                .await?
        }
        None => false,
    };
    let allocated = sequences.try_allocate_sender_seq()?.value();
    if allocated != seq {
        return Err(EngineError::Sequence(format!(
            "sender sequence moved from {seq} to {allocated} while a frame was being built"
        )));
    }
    Ok(filed)
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

    #[test]
    fn test_owed_reset_starts_clear_and_is_settled_by_its_ticket() {
        let owed = OwedReset::default();
        assert!(!owed.is_owed());
        let ticket = owed.owe();
        assert!(owed.is_owed());
        owed.pay(ticket);
        assert!(!owed.is_owed());
    }

    #[test]
    fn test_owed_reset_paying_a_reset_settles_what_was_owed_before_it() {
        let owed = OwedReset::default();
        // A failed write, then the reset that erases its effect.
        let _ = owed.owe();
        let reset = owed.owe();
        owed.pay(reset);
        assert!(!owed.is_owed());
    }

    #[test]
    fn test_owed_reset_a_failure_after_the_ticket_stays_owed_once_it_is_paid() {
        let owed = OwedReset::default();
        let reset = owed.owe();
        // A store write fails during the handshake that pays the reset.
        let failure = owed.owe();
        owed.pay(reset);
        assert!(owed.is_owed(), "the failure was recorded after the reset");
        // The next reset settles it.
        owed.pay(failure);
        assert!(!owed.is_owed());
    }

    #[test]
    fn test_owed_reset_paying_an_older_ticket_never_reopens_a_settled_one() {
        let owed = OwedReset::default();
        let first = owed.owe();
        let second = owed.owe();
        owed.pay(second);
        owed.pay(first);
        assert!(!owed.is_owed());
    }
}
