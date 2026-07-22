/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! Message store trait definition.
//!
//! This module defines the abstract interface for message storage implementations.

use crate::stored::StoredMessage;
use async_trait::async_trait;
use ironfix_core::error::StoreError;
use ironfix_core::message::MsgType;

/// Abstract interface for FIX message storage.
///
/// Implementations of this trait provide persistence for outgoing messages
/// to support resend requests and session recovery.
#[async_trait]
pub trait MessageStore: Send + Sync {
    /// Stores an outgoing message for potential resend.
    ///
    /// `msg_type` is passed in rather than parsed out of `message`: this crate
    /// depends on `ironfix-core` only and owns no decoder, and a store that
    /// guessed the type would hand back a message that is not the one that was
    /// filed. The caller has already encoded the frame and knows its type.
    ///
    /// `message` must be the **complete frame**, from `BeginString` (8) through
    /// `CheckSum` (10), because a resend rebuilds from it verbatim.
    ///
    /// # Arguments
    /// * `seq_num` - The `MsgSeqNum` (34) the message was sent under
    /// * `msg_type` - The `MsgType` (35) the message was sent as
    /// * `message` - The complete raw frame bytes
    ///
    /// # Errors
    /// Returns `StoreError` if the message cannot be stored.
    async fn store(
        &self,
        seq_num: u64,
        msg_type: &MsgType,
        message: &[u8],
    ) -> Result<(), StoreError>;

    /// Retrieves messages for a resend request.
    ///
    /// The result is ordered by sequence number and may be **sparse**: a range
    /// covering sequence numbers that were never stored, or have been evicted,
    /// yields only what is present. Each [`StoredMessage`] carries the sequence
    /// number it was filed under, so a caller can tell exactly which numbers it
    /// received and gap-fill the holes.
    ///
    /// # Arguments
    /// * `begin` - Begin sequence number (inclusive)
    /// * `end` - End sequence number (inclusive, or 0 for infinity)
    ///
    /// # Returns
    /// The stored messages inside the requested range, in ascending sequence
    /// order.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidRange`] if `begin` is above `end` (with
    /// `end` = 0 meaning infinity, which is never below `begin`), or `begin`
    /// is 0, which is not a legal `MsgSeqNum`;
    /// [`StoreError::RangeNotAvailable`] if the range is legal but holds no
    /// stored message at all; or another `StoreError` if retrieval fails.
    ///
    /// An entirely empty range is an error rather than an empty vector so a
    /// caller cannot mistake "nothing was stored" for "nothing was asked for".
    async fn get_range(&self, begin: u64, end: u64) -> Result<Vec<StoredMessage>, StoreError>;

    /// Reads at most `limit` stored messages inside `begin..=end`, in ascending
    /// sequence order, starting at or after `begin`.
    ///
    /// This is the paging primitive a resend replays over: answering a
    /// `ResendRequest` (35=2) whose `EndSeqNo` (16) = 0 means "replay the whole
    /// session", and materialising an entire long history in one
    /// [`get_range`](MessageStore::get_range) call would allocate it all at once
    /// and, for a lock-based store, hold the lock across the whole build. A
    /// caller pages instead: it reads one bounded batch, replays it, yields, and
    /// asks for the next batch starting past the last sequence number it saw.
    ///
    /// Unlike [`get_range`](MessageStore::get_range), an **empty page is not an
    /// error**: paging over a sparse history naturally lands on stretches that
    /// hold nothing, and the caller tells "this page is empty" from "the range
    /// is exhausted" by advancing its own cursor. `end` here is an absolute
    /// bound — `0` does **not** mean infinity, because the caller has already
    /// resolved that to the last sequence number it actually sent.
    ///
    /// # Arguments
    /// * `begin` - First sequence number to read from, inclusive
    /// * `end` - Last sequence number to read, inclusive
    /// * `limit` - Maximum number of messages to return; `0` yields an empty page
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidRange`] if `begin` is 0 or above `end`, or
    /// another `StoreError` if retrieval fails. An empty result is `Ok`, not an
    /// error.
    ///
    /// The default implementation materialises the whole range through
    /// [`get_range`](MessageStore::get_range) and truncates it; a store whose
    /// history can be large should override this with a natively bounded read so
    /// one resend cannot allocate the entire history.
    async fn get_page(
        &self,
        begin: u64,
        end: u64,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        match self.get_range(begin, end).await {
            Ok(mut messages) => {
                messages.truncate(limit);
                Ok(messages)
            }
            // An empty range is `get_range`'s error; for a page it is a normal,
            // non-terminal outcome the caller resolves by advancing its cursor.
            Err(StoreError::RangeNotAvailable { .. }) => Ok(Vec::new()),
            Err(other) => Err(other),
        }
    }

    /// Returns the next sender sequence number.
    fn next_sender_seq(&self) -> u64;

    /// Returns the next expected target sequence number.
    fn next_target_seq(&self) -> u64;

    /// Sets the next sender sequence number.
    ///
    /// # Arguments
    /// * `seq` - The new sequence number
    fn set_next_sender_seq(&self, seq: u64);

    /// Sets the next expected target sequence number.
    ///
    /// # Arguments
    /// * `seq` - The new sequence number
    fn set_next_target_seq(&self, seq: u64);

    /// Resets the store, clearing all messages and resetting sequence numbers.
    ///
    /// # Errors
    /// Returns `StoreError` if the reset fails.
    async fn reset(&self) -> Result<(), StoreError>;

    /// Returns the creation time of the store/session.
    fn creation_time(&self) -> std::time::SystemTime;

    /// Refreshes the store from persistent storage.
    ///
    /// # Errors
    /// Returns `StoreError` if the refresh fails.
    async fn refresh(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockStore;

    #[async_trait]
    impl MessageStore for MockStore {
        async fn store(
            &self,
            _seq_num: u64,
            _msg_type: &MsgType,
            _message: &[u8],
        ) -> Result<(), StoreError> {
            Ok(())
        }

        async fn get_range(
            &self,
            _begin: u64,
            _end: u64,
        ) -> Result<Vec<StoredMessage>, StoreError> {
            Ok(vec![])
        }

        fn next_sender_seq(&self) -> u64 {
            1
        }

        fn next_target_seq(&self) -> u64 {
            1
        }

        fn set_next_sender_seq(&self, _seq: u64) {}

        fn set_next_target_seq(&self, _seq: u64) {}

        async fn reset(&self) -> Result<(), StoreError> {
            Ok(())
        }

        fn creation_time(&self) -> std::time::SystemTime {
            std::time::SystemTime::now()
        }
    }

    #[tokio::test]
    async fn test_mock_store() {
        let store = MockStore;
        assert_eq!(store.next_sender_seq(), 1);
        assert_eq!(store.next_target_seq(), 1);
        assert!(store.store(1, &MsgType::Heartbeat, b"test").await.is_ok());
        assert!(store.reset().await.is_ok());
    }
}
