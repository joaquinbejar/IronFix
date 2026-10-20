/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! The synchronous message store, for the sans-IO path.
//!
//! [`SyncMessageStore`] is [`MessageStore`] with every method synchronous:
//! the same method set, the same defaults, and the same contract, the
//! persistence order and the call-order rule for mutations included (see the
//! [`traits`](crate::traits) module docs). A driver that runs sessions on its
//! own event loop, with no async runtime (ADR-0002, issue #92), calls it
//! directly; each call allocates no future.
//!
//! [`SyncStoreAdapter`] makes a synchronous store usable where a
//! [`MessageStore`] is expected, such as under the Tokio driver. Each async
//! method runs the synchronous one inline and is ready on its first poll, so
//! a call that blocks blocks the runtime thread for as long as it takes: the
//! adapter is sound for a store whose calls finish at once (an in-memory
//! store, or one that hands its writes to its own thread), and not for one
//! that waits on a disk or a network inside the call. Such a store should
//! implement [`MessageStore`] itself, or be called through
//! `tokio::task::spawn_blocking` by its owner. Because each adapted call
//! completes within one poll, a dropped future has either applied its
//! mutation in full or not started it, so the call-order rule holds.

use crate::stored::StoredMessage;
use crate::traits::MessageStore;
use async_trait::async_trait;
use ironfix_core::error::StoreError;
use ironfix_core::message::MsgType;

/// [`MessageStore`] with synchronous methods, for a driver without an async
/// runtime.
///
/// Every method has the meaning, the errors and the defaults of the
/// [`MessageStore`] method of the same name; the engine's ordering
/// guarantees and the rule that mutations take effect in call order apply
/// unchanged.
pub trait SyncMessageStore: Send + Sync {
    /// See [`MessageStore::store`].
    ///
    /// # Errors
    /// Returns `StoreError` if the message cannot be stored.
    fn store(&self, seq_num: u64, msg_type: &MsgType, message: &[u8]) -> Result<(), StoreError>;

    /// See [`MessageStore::get_range`].
    ///
    /// # Errors
    /// [`StoreError::InvalidRange`] for `begin` 0 or above `end` (0 meaning
    /// infinity), [`StoreError::RangeNotAvailable`] for a legal range holding
    /// nothing, or another `StoreError` if retrieval fails.
    fn get_range(&self, begin: u64, end: u64) -> Result<Vec<StoredMessage>, StoreError>;

    /// See [`MessageStore::get_page`]. The default materialises the range
    /// through [`SyncMessageStore::get_range`] and truncates it.
    ///
    /// # Errors
    /// [`StoreError::InvalidRange`] for `begin` 0 or above `end`, or another
    /// `StoreError` if retrieval fails. An empty page is `Ok`.
    fn get_page(
        &self,
        begin: u64,
        end: u64,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        match self.get_range(begin, end) {
            Ok(mut messages) => {
                messages.truncate(limit);
                Ok(messages)
            }
            Err(StoreError::RangeNotAvailable { .. }) => Ok(Vec::new()),
            Err(other) => Err(other),
        }
    }

    /// See [`MessageStore::file_outbound`]. The default runs
    /// [`SyncMessageStore::store`] then
    /// [`SyncMessageStore::set_next_sender_seq`], stopping at the first error.
    ///
    /// # Errors
    /// Returns `StoreError` if either write fails.
    fn file_outbound(
        &self,
        seq_num: u64,
        msg_type: &MsgType,
        message: &[u8],
        next_sender: u64,
    ) -> Result<(), StoreError> {
        self.store(seq_num, msg_type, message)?;
        self.set_next_sender_seq(next_sender)
    }

    /// See [`MessageStore::next_sender_seq`].
    fn next_sender_seq(&self) -> u64;

    /// See [`MessageStore::next_target_seq`].
    fn next_target_seq(&self) -> u64;

    /// See [`MessageStore::set_next_sender_seq`].
    ///
    /// # Errors
    /// Returns `StoreError` if the number cannot be persisted.
    fn set_next_sender_seq(&self, seq: u64) -> Result<(), StoreError>;

    /// See [`MessageStore::set_next_target_seq`].
    ///
    /// # Errors
    /// Returns `StoreError` if the number cannot be persisted.
    fn set_next_target_seq(&self, seq: u64) -> Result<(), StoreError>;

    /// See [`MessageStore::reset`].
    ///
    /// # Errors
    /// Returns `StoreError` if the reset fails.
    fn reset(&self) -> Result<(), StoreError>;

    /// See [`MessageStore::reset_to`]. The default runs the three changes in
    /// order, stopping at the first error, and is not atomic.
    ///
    /// # Errors
    /// Returns `StoreError` if any of the changes fails.
    fn reset_to(&self, next_sender: u64, next_target: u64) -> Result<(), StoreError> {
        self.reset()?;
        self.set_next_sender_seq(next_sender)?;
        self.set_next_target_seq(next_target)
    }

    /// See [`MessageStore::reset_owed`]. The default reports `false`.
    fn reset_owed(&self) -> bool {
        false
    }

    /// See [`MessageStore::set_reset_owed`]. The default keeps no marker.
    ///
    /// # Errors
    /// Returns `StoreError` if the marker cannot be made durable.
    fn set_reset_owed(&self, owed: bool) -> Result<(), StoreError> {
        let _ = owed;
        Ok(())
    }

    /// See [`MessageStore::app_watermark`]. The default reports 0.
    fn app_watermark(&self) -> u64 {
        0
    }

    /// See [`MessageStore::set_app_watermark`]. The default keeps no
    /// watermark.
    ///
    /// # Errors
    /// Returns `StoreError` if the watermark cannot be persisted.
    fn set_app_watermark(&self, watermark: u64) -> Result<(), StoreError> {
        let _ = watermark;
        Ok(())
    }

    /// See [`MessageStore::creation_time`].
    fn creation_time(&self) -> std::time::SystemTime;

    /// See [`MessageStore::refresh`]. The default does nothing.
    ///
    /// # Errors
    /// Returns `StoreError` if the refresh fails.
    fn refresh(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

/// A [`SyncMessageStore`] used as a [`MessageStore`].
///
/// Every async method runs the synchronous method of the same name inline;
/// see the [module docs](self) for when that is sound.
#[derive(Debug, Clone, Default)]
pub struct SyncStoreAdapter<S> {
    /// The synchronous store.
    inner: S,
}

impl<S> SyncStoreAdapter<S> {
    /// Wraps `inner`.
    #[must_use]
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }

    /// The synchronous store.
    #[must_use]
    pub const fn inner(&self) -> &S {
        &self.inner
    }

    /// Unwraps the synchronous store.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

#[async_trait]
impl<S: SyncMessageStore> MessageStore for SyncStoreAdapter<S> {
    async fn store(
        &self,
        seq_num: u64,
        msg_type: &MsgType,
        message: &[u8],
    ) -> Result<(), StoreError> {
        self.inner.store(seq_num, msg_type, message)
    }

    async fn get_range(&self, begin: u64, end: u64) -> Result<Vec<StoredMessage>, StoreError> {
        self.inner.get_range(begin, end)
    }

    async fn get_page(
        &self,
        begin: u64,
        end: u64,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        self.inner.get_page(begin, end, limit)
    }

    async fn file_outbound(
        &self,
        seq_num: u64,
        msg_type: &MsgType,
        message: &[u8],
        next_sender: u64,
    ) -> Result<(), StoreError> {
        self.inner
            .file_outbound(seq_num, msg_type, message, next_sender)
    }

    fn next_sender_seq(&self) -> u64 {
        self.inner.next_sender_seq()
    }

    fn next_target_seq(&self) -> u64 {
        self.inner.next_target_seq()
    }

    async fn set_next_sender_seq(&self, seq: u64) -> Result<(), StoreError> {
        self.inner.set_next_sender_seq(seq)
    }

    async fn set_next_target_seq(&self, seq: u64) -> Result<(), StoreError> {
        self.inner.set_next_target_seq(seq)
    }

    async fn reset(&self) -> Result<(), StoreError> {
        self.inner.reset()
    }

    async fn reset_to(&self, next_sender: u64, next_target: u64) -> Result<(), StoreError> {
        self.inner.reset_to(next_sender, next_target)
    }

    fn reset_owed(&self) -> bool {
        self.inner.reset_owed()
    }

    async fn set_reset_owed(&self, owed: bool) -> Result<(), StoreError> {
        self.inner.set_reset_owed(owed)
    }

    fn app_watermark(&self) -> u64 {
        self.inner.app_watermark()
    }

    async fn set_app_watermark(&self, watermark: u64) -> Result<(), StoreError> {
        self.inner.set_app_watermark(watermark)
    }

    fn creation_time(&self) -> std::time::SystemTime {
        self.inner.creation_time()
    }

    async fn refresh(&self) -> Result<(), StoreError> {
        self.inner.refresh()
    }
}
