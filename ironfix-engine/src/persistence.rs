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
//! 1. An outbound frame is filed, then the next sender sequence number is
//!    persisted, and only then are the frame's bytes written to the socket.
//! 2. The next target sequence number is persisted before the inbound message
//!    that advanced it is acted on: before an administrative message is
//!    processed, and before an application message is handed to the
//!    application. Any other change to a counter (a `SequenceReset`, a gap
//!    fill) is persisted at the end of the event that made it, before the next
//!    event.
//! 3. A counter is written only when its value changed.
//!
//! Every one of those writes can fail. [`StoreFailurePolicy`] decides what a
//! failure means: carry on with a warning (the default, and the behaviour
//! before writes were fallible), or close the session without writing the
//! frame the failure concerns.
//!
//! # Inbound delivery is at most once
//!
//! Because the target counter is persisted before an application message is
//! handed over, a crash after that write and before `from_app` has finished
//! with the message loses it to the application: on restart the engine expects
//! the next number, and the counterparty is never asked for this one again.
//! The window covers the messages waiting in the application queue and the one
//! `from_app` is handling. The engine does not detect or report such a loss
//! after a restart. A message that never had its counter persisted is never
//! handed over, so it is never lost silently while the process runs.
//!
//! A store failure never logs frame bytes: an outbound Logon carries
//! `Password` (554).

use crate::application::SessionId;
use ironfix_core::error::StoreError;
use ironfix_core::message::MsgType;
use ironfix_store::MessageStore;
use std::sync::Arc;

/// What the engine does when a write to the attached [`MessageStore`] fails.
///
/// Applies to every write the engine makes during a session: filing an
/// outbound frame, persisting the next sender sequence number, and persisting
/// the next target sequence number. Without a store attached there is nothing
/// to fail and the policy has no effect.
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
    /// Log a warning and carry on: the frame is written anyway, and a counter
    /// that could not be persisted is simply not durable.
    ///
    /// A frame that could not be filed cannot be replayed; a later
    /// `ResendRequest` covering it gets a `SequenceReset`-GapFill instead. This
    /// is the default, and what the engine always did before store writes were
    /// fallible.
    #[default]
    Continue,
    /// Fail closed: a frame whose filing or sender-counter write fails is not
    /// written at all (the counterparty reads no bytes for it), an inbound
    /// message whose target-counter write fails is not acted on, and the
    /// session closes. During the Logon handshake the failure is returned as
    /// [`EngineError::Store`](crate::EngineError::Store).
    ///
    /// No Logout is sent on the way out: it would have to be filed like any
    /// other frame, through the store that just failed.
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

/// Which write failed, for the log line.
#[derive(Debug, Clone, Copy)]
enum StoreWrite<'m> {
    /// Filing an outbound frame.
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

/// A store attached to a session, together with the policy for its write
/// failures.
///
/// Built from an [`Arc<dyn MessageStore>`] and a [`StoreFailurePolicy`]
/// wherever the engine writes: the handshakes and the reactor share it, so
/// the ordering and the policy cannot drift between them.
#[derive(Clone, Copy)]
pub(crate) struct SessionStore<'s> {
    /// The attached store.
    store: &'s Arc<dyn MessageStore>,
    /// What a failed write means.
    policy: StoreFailurePolicy,
}

impl<'s> SessionStore<'s> {
    /// Binds `store` to `policy`.
    #[must_use]
    pub(crate) const fn new(store: &'s Arc<dyn MessageStore>, policy: StoreFailurePolicy) -> Self {
        Self { store, policy }
    }

    /// Files an outbound frame under `seq`, then persists `next_sender`, in
    /// that order. The caller writes the frame only after this returns `Ok`.
    ///
    /// Filing before the counter makes "counter persisted, frame not filed"
    /// impossible: a crash between the two leaves a filed frame and the old
    /// counter, so the number is reused for a message the peer never saw and
    /// the filed frame is overwritten.
    ///
    /// # Errors
    /// Under [`StoreFailurePolicy::CloseSession`], the first failed write; the
    /// counter is then not attempted and the frame must not be written. Under
    /// [`StoreFailurePolicy::Continue`] failures are logged and `Ok` returned.
    pub(crate) async fn file_outbound(
        self,
        session_id: &SessionId,
        seq: u64,
        msg_type: &MsgType,
        frame: &[u8],
        next_sender: u64,
    ) -> Result<(), StoreError> {
        if let Err(err) = self.store.store(seq, msg_type, frame).await {
            self.on_failure(session_id, StoreWrite::Frame { seq, msg_type }, err)?;
        }
        self.persist_sender(session_id, next_sender).await
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
        match self.store.set_next_sender_seq(next).await {
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
        match self.store.set_next_target_seq(next).await {
            Ok(()) => Ok(()),
            Err(err) => self.on_failure(session_id, StoreWrite::NextTarget(next), err),
        }
    }

    /// Applies the policy to one failed write: a warning and `Ok` to carry on,
    /// or the error to close. The log line names the write, never the frame
    /// bytes.
    #[cold]
    fn on_failure(
        self,
        session_id: &SessionId,
        write: StoreWrite<'_>,
        err: StoreError,
    ) -> Result<(), StoreError> {
        if self.policy.closes_session() {
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
