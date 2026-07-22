/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! In-memory message store implementation.
//!
//! This module provides a simple in-memory message store suitable for
//! testing and applications that don't require persistence.

use crate::stored::StoredMessage;
use crate::traits::MessageStore;
use async_trait::async_trait;
use bytes::Bytes;
use ironfix_core::error::StoreError;
use ironfix_core::message::MsgType;
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

/// In-memory message store.
///
/// Stores messages in a `BTreeMap` for efficient range queries.
/// Not persistent - all data is lost when the process exits, so it cannot
/// carry a session across a restart. It is the only implementation in this
/// crate today.
#[derive(Debug)]
pub struct MemoryStore {
    /// Stored frames and their recorded `MsgType`, indexed by sequence number.
    messages: RwLock<BTreeMap<u64, (MsgType, Bytes)>>,
    /// Next sender sequence number.
    next_sender_seq: AtomicU64,
    /// Next expected target sequence number.
    next_target_seq: AtomicU64,
    /// Store creation time.
    creation_time: SystemTime,
}

impl MemoryStore {
    /// Creates a new empty memory store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            messages: RwLock::new(BTreeMap::new()),
            next_sender_seq: AtomicU64::new(1),
            next_target_seq: AtomicU64::new(1),
            creation_time: SystemTime::now(),
        }
    }

    /// Creates a new memory store with initial sequence numbers.
    ///
    /// # Arguments
    /// * `sender_seq` - Initial sender sequence number
    /// * `target_seq` - Initial target sequence number
    #[must_use]
    pub fn with_initial_seqs(sender_seq: u64, target_seq: u64) -> Self {
        Self {
            messages: RwLock::new(BTreeMap::new()),
            next_sender_seq: AtomicU64::new(sender_seq),
            next_target_seq: AtomicU64::new(target_seq),
            creation_time: SystemTime::now(),
        }
    }

    /// Returns the number of stored messages.
    #[must_use]
    pub fn message_count(&self) -> usize {
        self.messages.read().len()
    }

    /// Checks if a message with the given sequence number exists.
    #[must_use]
    pub fn contains(&self, seq_num: u64) -> bool {
        self.messages.read().contains_key(&seq_num)
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MessageStore for MemoryStore {
    async fn store(
        &self,
        seq_num: u64,
        msg_type: &MsgType,
        message: &[u8],
    ) -> Result<(), StoreError> {
        let entry = (msg_type.clone(), Bytes::copy_from_slice(message));
        // The guard is scoped to this statement: it is a `parking_lot` lock,
        // which does not yield, and must never be live across an await.
        self.messages.write().insert(seq_num, entry);
        Ok(())
    }

    async fn get_range(&self, begin: u64, end: u64) -> Result<Vec<StoredMessage>, StoreError> {
        // `EndSeqNo` (16) = 0 is the FIX spelling of "to infinity". It is
        // normalised here, before any comparison, so the inverted-range check
        // below cannot mistake it for a bound below `begin`.
        let end = if end == 0 { u64::MAX } else { end };

        // Both guards run before `BTreeMap::range`, which *panics* on an
        // inverted range — and this is reachable from a plain trait call, so
        // the panic would abort the process under `panic = "abort"`.
        if begin == 0 || begin > end {
            return Err(StoreError::InvalidRange { begin, end });
        }

        let result: Vec<StoredMessage> = {
            let messages = self.messages.read();
            messages
                .range(begin..=end)
                .map(|(seq_num, (msg_type, payload))| {
                    StoredMessage::new(*seq_num, msg_type.clone(), payload.clone())
                })
                .collect()
        };

        if result.is_empty() {
            // Inclusive bounds, carried as two numbers: `end` may be
            // `u64::MAX` here, and an `end + 1` to build a half-open range
            // would overflow — the original defect this replaces.
            return Err(StoreError::RangeNotAvailable { begin, end });
        }

        Ok(result)
    }

    async fn get_page(
        &self,
        begin: u64,
        end: u64,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        // `BTreeMap::range` panics on an inverted range, and this is reachable
        // from a plain trait call, so it is guarded before the map is touched.
        // `end` is an absolute bound here — 0 is a legitimately empty page, not
        // "to infinity" — so no normalisation happens.
        if begin == 0 || begin > end {
            return Err(StoreError::InvalidRange { begin, end });
        }

        // A natively bounded read: `range` seeks to the first key at or after
        // `begin` in O(log n) and `take` stops after `limit`, so the guard is
        // held only for the page — never the whole history — and the allocation
        // is capped at `limit`. Cloning a payload is a `Bytes` refcount bump.
        let page: Vec<StoredMessage> = {
            let messages = self.messages.read();
            messages
                .range(begin..=end)
                .take(limit)
                .map(|(seq_num, (msg_type, payload))| {
                    StoredMessage::new(*seq_num, msg_type.clone(), payload.clone())
                })
                .collect()
        };

        // An empty page is a normal outcome for a sparse history: unlike
        // `get_range`, the caller resolves it by advancing its cursor.
        Ok(page)
    }

    fn next_sender_seq(&self) -> u64 {
        self.next_sender_seq.load(Ordering::SeqCst)
    }

    fn next_target_seq(&self) -> u64 {
        self.next_target_seq.load(Ordering::SeqCst)
    }

    fn set_next_sender_seq(&self, seq: u64) {
        self.next_sender_seq.store(seq, Ordering::SeqCst);
    }

    fn set_next_target_seq(&self, seq: u64) {
        self.next_target_seq.store(seq, Ordering::SeqCst);
    }

    async fn reset(&self) -> Result<(), StoreError> {
        let mut messages = self.messages.write();
        messages.clear();
        self.next_sender_seq.store(1, Ordering::SeqCst);
        self.next_target_seq.store(1, Ordering::SeqCst);
        Ok(())
    }

    fn creation_time(&self) -> SystemTime {
        self.creation_time
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fails the test with context instead of `.unwrap()` / `.expect()`.
    #[track_caller]
    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("{what}: {err:?}"),
        }
    }

    /// Files a message, failing the test if the store rejects it.
    async fn put(store: &MemoryStore, seq: u64, msg_type: MsgType, payload: &[u8]) {
        ok(
            store.store(seq, &msg_type, payload).await,
            "store must accept the message",
        );
    }

    #[tokio::test]
    async fn test_memory_store_new_starts_at_sequence_one() {
        let store = MemoryStore::new();
        assert_eq!(store.next_sender_seq(), 1);
        assert_eq!(store.next_target_seq(), 1);
        assert_eq!(store.message_count(), 0);
    }

    #[tokio::test]
    async fn test_memory_store_store_and_retrieve_tracks_every_sequence() {
        let store = MemoryStore::new();

        put(&store, 1, MsgType::Logon, b"message1").await;
        put(&store, 2, MsgType::NewOrderSingle, b"message2").await;
        put(&store, 3, MsgType::Heartbeat, b"message3").await;

        assert_eq!(store.message_count(), 3);
        assert!(store.contains(1));
        assert!(store.contains(2));
        assert!(store.contains(3));
        assert!(!store.contains(4));
    }

    #[tokio::test]
    async fn test_memory_store_get_range_returns_only_stored_sequences() {
        let store = MemoryStore::new();

        put(&store, 1, MsgType::Logon, b"msg1").await;
        put(&store, 2, MsgType::NewOrderSingle, b"msg2").await;
        put(&store, 3, MsgType::NewOrderSingle, b"msg3").await;
        put(&store, 5, MsgType::NewOrderSingle, b"msg5").await;

        let range = ok(store.get_range(1, 3).await, "range 1..=3 must resolve");
        assert_eq!(
            range.iter().map(StoredMessage::seq_num).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );

        // 4 was never stored: the hole is simply absent, and the caller can
        // see that from the sequence numbers it got back.
        let range = ok(store.get_range(2, 5).await, "range 2..=5 must resolve");
        assert_eq!(
            range.iter().map(StoredMessage::seq_num).collect::<Vec<_>>(),
            vec![2, 3, 5]
        );
    }

    #[tokio::test]
    async fn test_memory_store_get_range_preserves_msg_type_and_payload() {
        let store = MemoryStore::new();
        put(&store, 4, MsgType::NewOrderSingle, b"8=FIX.4.4\x0135=D\x01").await;

        let range = ok(store.get_range(4, 4).await, "range 4..=4 must resolve");
        let [message] = range.as_slice() else {
            panic!("exactly one message must come back, got {}", range.len());
        };

        // The old implementation rebuilt every result with `MsgType::default()`
        // (Heartbeat) and dropped the sequence key, so what came out was never
        // what went in.
        assert_eq!(message.seq_num(), 4);
        assert_eq!(message.msg_type(), &MsgType::NewOrderSingle);
        assert_eq!(&message.payload()[..], b"8=FIX.4.4\x0135=D\x01");
    }

    #[tokio::test]
    async fn test_memory_store_get_range_inverted_is_invalid_range_not_a_panic() {
        let store = MemoryStore::new();
        put(&store, 1, MsgType::Logon, b"msg1").await;

        // `BTreeMap::range(5..=3)` panics; under `panic = "abort"` that kills
        // the process from a plain trait call.
        assert_eq!(
            store.get_range(5, 3).await,
            Err(StoreError::InvalidRange { begin: 5, end: 3 })
        );
    }

    #[tokio::test]
    async fn test_memory_store_get_range_zero_begin_is_invalid_range() {
        let store = MemoryStore::new();
        put(&store, 1, MsgType::Logon, b"msg1").await;

        // MsgSeqNum starts at 1, so 0 names no message.
        assert_eq!(
            store.get_range(0, 5).await,
            Err(StoreError::InvalidRange { begin: 0, end: 5 })
        );
    }

    #[tokio::test]
    async fn test_memory_store_get_range_to_infinity_on_empty_store_is_range_not_available() {
        let store = MemoryStore::new();

        // `end` = 0 normalises to `u64::MAX`; the old code then computed
        // `end + 1` for the error payload and overflowed.
        assert_eq!(
            store.get_range(5, 0).await,
            Err(StoreError::RangeNotAvailable {
                begin: 5,
                end: u64::MAX,
            })
        );
    }

    #[tokio::test]
    async fn test_memory_store_get_range_to_infinity_returns_everything_from_begin() {
        let store = MemoryStore::new();
        put(&store, 1, MsgType::Logon, b"msg1").await;
        put(&store, 2, MsgType::NewOrderSingle, b"msg2").await;
        put(&store, u64::MAX, MsgType::NewOrderSingle, b"last").await;

        let range = ok(store.get_range(2, 0).await, "range 2..=inf must resolve");
        assert_eq!(
            range.iter().map(StoredMessage::seq_num).collect::<Vec<_>>(),
            vec![2, u64::MAX]
        );
    }

    #[tokio::test]
    async fn test_memory_store_get_range_with_no_match_is_range_not_available() {
        let store = MemoryStore::new();
        put(&store, 1, MsgType::Logon, b"msg1").await;

        assert_eq!(
            store.get_range(10, 20).await,
            Err(StoreError::RangeNotAvailable { begin: 10, end: 20 })
        );
    }

    #[tokio::test]
    async fn test_memory_store_get_page_caps_at_limit() {
        let store = MemoryStore::new();
        for seq in 1..=10 {
            put(&store, seq, MsgType::NewOrderSingle, b"msg").await;
        }

        // Only `limit` messages come back, starting at `begin`, even though the
        // range holds more — the whole history is never materialised.
        let page = ok(store.get_page(1, 10, 3).await, "first page must resolve");
        assert_eq!(
            page.iter().map(StoredMessage::seq_num).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[tokio::test]
    async fn test_memory_store_get_page_advances_across_pages() {
        let store = MemoryStore::new();
        for seq in 1..=7 {
            put(&store, seq, MsgType::NewOrderSingle, b"msg").await;
        }

        // Walk the range in bounded pages the way the resend replay does: read a
        // batch, then ask for the next one starting past the last seq seen, and
        // stop once the cursor passes the upper bound.
        const END: u64 = 7;
        let mut seen = Vec::new();
        let mut cursor = 1;
        while cursor <= END {
            let page = ok(store.get_page(cursor, END, 3).await, "page must resolve");
            let Some(last) = page.last().map(StoredMessage::seq_num) else {
                break;
            };
            seen.extend(page.iter().map(StoredMessage::seq_num));
            let Some(next) = last.checked_add(1) else {
                break;
            };
            cursor = next;
        }
        assert_eq!(seen, vec![1, 2, 3, 4, 5, 6, 7]);
    }

    #[tokio::test]
    async fn test_memory_store_get_page_empty_range_is_ok_not_error() {
        let store = MemoryStore::new();
        put(&store, 1, MsgType::Logon, b"msg1").await;

        // A hole in a sparse history: paging over it is normal, so an empty page
        // is `Ok`, unlike `get_range` which treats an empty range as an error.
        let page = ok(store.get_page(5, 9, 4).await, "empty page must resolve");
        assert!(page.is_empty());
    }

    #[tokio::test]
    async fn test_memory_store_get_page_zero_limit_is_empty_page() {
        let store = MemoryStore::new();
        put(&store, 1, MsgType::Logon, b"msg1").await;

        let page = ok(
            store.get_page(1, 5, 0).await,
            "zero-limit page must resolve",
        );
        assert!(page.is_empty());
    }

    #[tokio::test]
    async fn test_memory_store_get_page_inverted_is_invalid_range_not_a_panic() {
        let store = MemoryStore::new();
        put(&store, 1, MsgType::Logon, b"msg1").await;

        // `BTreeMap::range(5..=3)` panics; the guard must fire before the map is
        // touched, exactly as `get_range` does.
        assert_eq!(
            store.get_page(5, 3, 4).await,
            Err(StoreError::InvalidRange { begin: 5, end: 3 })
        );
    }

    #[tokio::test]
    async fn test_memory_store_get_page_preserves_msg_type_and_payload() {
        let store = MemoryStore::new();
        put(&store, 4, MsgType::NewOrderSingle, b"8=FIX.4.4\x0135=D\x01").await;

        let page = ok(store.get_page(4, 4, 8).await, "page must resolve");
        let [message] = page.as_slice() else {
            panic!("exactly one message must come back, got {}", page.len());
        };
        assert_eq!(message.seq_num(), 4);
        assert_eq!(message.msg_type(), &MsgType::NewOrderSingle);
        assert_eq!(&message.payload()[..], b"8=FIX.4.4\x0135=D\x01");
    }

    #[tokio::test]
    async fn test_memory_store_sequence_numbers_round_trip() {
        let store = MemoryStore::new();

        store.set_next_sender_seq(10);
        store.set_next_target_seq(20);

        assert_eq!(store.next_sender_seq(), 10);
        assert_eq!(store.next_target_seq(), 20);
    }

    #[tokio::test]
    async fn test_memory_store_reset_clears_messages_and_sequences() {
        let store = MemoryStore::new();

        put(&store, 1, MsgType::Logon, b"msg1").await;
        store.set_next_sender_seq(10);
        store.set_next_target_seq(20);

        ok(store.reset().await, "reset must succeed");

        assert_eq!(store.message_count(), 0);
        assert_eq!(store.next_sender_seq(), 1);
        assert_eq!(store.next_target_seq(), 1);
    }
}
