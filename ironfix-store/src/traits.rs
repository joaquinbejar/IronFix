/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! Message store trait definition.
//!
//! This module defines the abstract interface for message storage implementations.
//!
//! # The persistence contract
//!
//! Every write is fallible and asynchronous: [`MessageStore::store`],
//! [`MessageStore::file_outbound`], [`MessageStore::set_next_sender_seq`] and
//! [`MessageStore::set_next_target_seq`] return a `Result`, so a store backed by
//! a disk or a replica can report a write it could not make. Being `async`, a
//! call does not block the runtime thread, but the session awaits it: a slow
//! store delays that session's reactor for as long as the call takes.
//! `ironfix-engine` bounds every call with a store timeout and treats an
//! overrun as a failed write. `Ok` means the value is as durable as the
//! implementation promises; [`MemoryStore`](crate::MemoryStore) promises
//! nothing beyond the process.
//!
//! Each call through this `async_trait` interface allocates one boxed future.
//! [`MessageStore::file_outbound`] exists so the per-message outbound write is
//! one call (and, for a durable store, can be one atomic write) rather than
//! two, and [`MessageStore::reset_to`] does the same for a reset that sets
//! both counters.
//!
//! `ironfix-engine` relies on the following ordering, which a durable store
//! makes meaningful (see `doc/adr/0005-fallible-store-writes.md`):
//!
//! - An outbound frame is filed, and then the next sender sequence number is
//!   persisted, **before** the frame's bytes reach the socket (both through
//!   [`MessageStore::file_outbound`]). A crash can therefore leave a filed
//!   frame the peer never saw, or a spent number, but never a frame on the wire
//!   the store cannot replay.
//! - The next target sequence number is persisted **before** the inbound
//!   message that advanced it is acted on: before an administrative message is
//!   processed, and before an application message is handed to the
//!   application. The initiator's Logon acknowledgement and a `SequenceReset`
//!   in Reset mode are the exceptions: they reach `from_admin` first.
//! - A counter is written only when its value changed.
//!
//! These are guarantees only under the engine's fail-closed store policy. Its
//! default policy logs a failed write and carries on as if it had succeeded,
//! so after a failure a crash can leave the store behind what the
//! counterparty has seen.
//!
//! # Mutations take effect in call order, even when a call is dropped
//!
//! `ironfix-engine` bounds every call with a timeout, and a timeout drops the
//! call's future; so does a caller that abandons a connect. A store whose call
//! has already submitted work (a disk write, a replication round trip) may
//! still complete it afterwards. Every implementation must therefore apply
//! its **mutations** ([`MessageStore::store`],
//! [`MessageStore::file_outbound`], the two counter setters,
//! [`MessageStore::set_reset_owed`], [`MessageStore::reset`],
//! [`MessageStore::reset_to`]) **in call order, even
//! when a call's future is dropped before it completes**: a mutation takes
//! effect before any mutation called after it, or not at all. Serialising
//! mutations through an internal queue that later calls wait behind, or
//! completing or aborting the submitted work synchronously when the future is
//! dropped, both satisfy this.
//!
//! [`MemoryStore`](crate::MemoryStore) satisfies it: each of its mutations
//! runs to completion within a single poll of its future, under its lock and
//! without awaiting anything, so a dropped future has either applied its
//! change in full or not started it. (The defaulted composite methods,
//! [`MessageStore::file_outbound`] and [`MessageStore::reset_to`], run their
//! steps in order; a composite dropped between steps leaves the earlier steps
//! applied, still in order.)
//!
//! The engine relies on this after a mutation times out: it treats the store
//! as possibly holding an outstanding write, records that a reset is owed, and
//! starts the next session with a reset. With a conforming store the late
//! write lands before that reset, which erases it. A store that does not
//! conform can apply the late write after the next session's reset and
//! writes, overwriting a frame or moving a counter of the new stream:
//! reusing such a store after a timed-out mutation is not safe.
//!
//! Error values must never contain frame bytes: an outbound Logon carries
//! `Password` (554), and the engine logs store errors.

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
    /// Filing under a `seq_num` that is already filed **replaces** the frame
    /// there. The engine relies on this: a crash after a frame is filed but
    /// before its number is persisted makes the next session reuse that number
    /// for a message the peer never saw, and the new frame must be the one a
    /// resend replays.
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

    /// Files an outbound frame under `seq_num` and persists `next_sender` as
    /// the next sender sequence number, in that order.
    ///
    /// This is the one call the engine makes per outbound sequenced message,
    /// before the frame's bytes are written. The default runs
    /// [`store`](MessageStore::store) and then
    /// [`set_next_sender_seq`](MessageStore::set_next_sender_seq), stopping at
    /// the first error. A durable store should override it to make both
    /// changes in one atomic write: then a crash leaves either both or
    /// neither, and the engine pays one call instead of two.
    ///
    /// # Arguments
    /// * `seq_num` - The `MsgSeqNum` (34) the message is sent under
    /// * `msg_type` - The `MsgType` (35) the message is sent as
    /// * `message` - The complete raw frame bytes
    /// * `next_sender` - The next `MsgSeqNum` to send, `seq_num + 1`
    ///
    /// # Errors
    /// Returns `StoreError` if either write fails. The error must not contain
    /// frame bytes.
    async fn file_outbound(
        &self,
        seq_num: u64,
        msg_type: &MsgType,
        message: &[u8],
        next_sender: u64,
    ) -> Result<(), StoreError> {
        self.store(seq_num, msg_type, message).await?;
        self.set_next_sender_seq(next_sender).await
    }

    /// Returns the next sender sequence number.
    fn next_sender_seq(&self) -> u64;

    /// Returns the next expected target sequence number.
    fn next_target_seq(&self) -> u64;

    /// Persists the next sender sequence number.
    ///
    /// The engine calls this through
    /// [`file_outbound`](MessageStore::file_outbound) before a frame is
    /// written, with the number the next outbound message will carry, and on
    /// its own after other counter changes, only when the value changed.
    ///
    /// The value is **not** monotonic, and a store must not reject a lower
    /// one:
    ///
    /// - A sequence reset brings it back down: a Logon or Logon ack with
    ///   `ResetSeqNumFlag` (141) = Y, the `reset_on_logout` /
    ///   `reset_on_disconnect` close, and a reset the previous session owed.
    ///   The engine resets the store first in each case.
    /// - After a failed [`file_outbound`](MessageStore::file_outbound) the
    ///   number was not spent, and the engine writes the unspent number when
    ///   the session closes. That can be one below what the failed call left
    ///   behind, if it took effect and still reported a failure (a call that
    ///   overran the engine's store timeout, for instance).
    /// - An explicit `with_initial_sequences` seed on the initiator can start
    ///   a session below the stored value (the fail-closed policy refuses
    ///   that; the default does not).
    ///
    /// # Arguments
    /// * `seq` - The next `MsgSeqNum` (34) to send
    ///
    /// # Errors
    /// Returns `StoreError` if the number cannot be persisted. The error must
    /// not contain frame bytes.
    async fn set_next_sender_seq(&self, seq: u64) -> Result<(), StoreError>;

    /// Persists the next expected target sequence number.
    ///
    /// The engine calls this when an inbound message has been accepted in
    /// sequence, before the message is acted on (processed, if administrative;
    /// handed to the application, if not), and before any other change to the
    /// expectation (a `SequenceReset`, a gap fill) takes effect, only when the
    /// value changed. Two messages reach the application's `from_admin`
    /// before the write: the initiator's Logon acknowledgement and a
    /// `SequenceReset` in Reset mode (see `doc/adr/0005-fallible-store-writes.md`).
    ///
    /// # Arguments
    /// * `seq` - The next inbound `MsgSeqNum` (34) expected
    ///
    /// # Errors
    /// Returns `StoreError` if the number cannot be persisted. The error must
    /// not contain frame bytes.
    async fn set_next_target_seq(&self, seq: u64) -> Result<(), StoreError>;

    /// Resets the store, clearing all messages and resetting sequence numbers.
    ///
    /// # Errors
    /// Returns `StoreError` if the reset fails.
    async fn reset(&self) -> Result<(), StoreError>;

    /// Resets the store and then sets both sequence counters, as one change.
    ///
    /// The engine calls this when the counterparty resets the sequence on its
    /// Logon acknowledgement (`ResetSeqNumFlag` (141) = Y) although the Logon
    /// did not ask for it: the previous stream is cleared, and the counters
    /// are set for the new one, whose message 1 in each direction (the Logon
    /// and its acknowledgement) has already been exchanged.
    ///
    /// The default runs [`reset`](MessageStore::reset), then
    /// [`set_next_sender_seq`](MessageStore::set_next_sender_seq), then
    /// [`set_next_target_seq`](MessageStore::set_next_target_seq), stopping at
    /// the first error. It is **not** atomic: a crash between the calls leaves
    /// the store cleared with its initial counters, and the next session's
    /// Logon then goes out at `MsgSeqNum` 1 without a reset, which the
    /// counterparty reads as too low. A durable store should override it to
    /// make the three changes in one atomic write.
    ///
    /// # Arguments
    /// * `next_sender` - The next `MsgSeqNum` (34) to send after the reset
    /// * `next_target` - The next inbound `MsgSeqNum` (34) expected after it
    ///
    /// # Errors
    /// Returns `StoreError` if any of the changes fails. The error must not
    /// contain frame bytes.
    async fn reset_to(&self, next_sender: u64, next_target: u64) -> Result<(), StoreError> {
        self.reset().await?;
        self.set_next_sender_seq(next_sender).await?;
        self.set_next_target_seq(next_target).await
    }

    /// Returns whether the store holds the durable owed-reset marker.
    ///
    /// The marker is the engine's intent to reset the sequence, recorded
    /// before the engine acts on it, so that a crash or a restart cannot lose
    /// it: a session that starts on a store reporting `true` resets the store
    /// and logs on with `ResetSeqNumFlag` (141) = Y at `MsgSeqNum` 1 (see
    /// `doc/adr/0029-durable-owed-reset.md`).
    ///
    /// The default reports `false`: a store that does not override
    /// [`set_reset_owed`](MessageStore::set_reset_owed) keeps no marker, and
    /// the intent lives only in the engine's memory, as before the marker
    /// existed.
    fn reset_owed(&self) -> bool {
        false
    }

    /// Records (`true`) or clears (`false`) the durable owed-reset marker.
    ///
    /// The engine sets the marker before it resets the store for a reset it
    /// has decided (a Logon or Logon acknowledgement with `ResetSeqNumFlag`
    /// (141) = Y, a `reset_on_logout` / `reset_on_disconnect` close, a reset
    /// an earlier session owed), and after a store mutation that failed; it
    /// clears it only once the reset has been made and the Logon or
    /// acknowledgement declaring it has been exchanged, or right after a
    /// successful close-time reset when nothing else is owed. `Ok` must mean the
    /// marker is as durable as the store's counters can be made: a durable
    /// store flushes it before it returns, whatever its own sync policy.
    ///
    /// [`reset`](MessageStore::reset) and [`reset_to`](MessageStore::reset_to)
    /// must **keep** the marker: a reset made under it is not yet declared to
    /// the counterparty, and a crash before that must still find it.
    ///
    /// This is a mutation, and takes effect in call order like the others.
    ///
    /// The default does nothing and returns `Ok`: the store keeps no marker
    /// (see [`reset_owed`](MessageStore::reset_owed)).
    ///
    /// # Errors
    /// Returns `StoreError` if the marker cannot be made durable. The error
    /// must not contain frame bytes.
    async fn set_reset_owed(&self, owed: bool) -> Result<(), StoreError> {
        let _ = owed;
        Ok(())
    }

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

        async fn set_next_sender_seq(&self, _seq: u64) -> Result<(), StoreError> {
            Ok(())
        }

        async fn set_next_target_seq(&self, _seq: u64) -> Result<(), StoreError> {
            Ok(())
        }

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
        assert!(store.set_next_sender_seq(2).await.is_ok());
        assert!(store.set_next_target_seq(2).await.is_ok());
        // The default `file_outbound` composes the two writes.
        assert!(
            store
                .file_outbound(2, &MsgType::Heartbeat, b"test", 3)
                .await
                .is_ok()
        );
        assert!(store.reset().await.is_ok());
        // The default `reset_to` composes the reset and the two setters.
        assert!(store.reset_to(2, 2).await.is_ok());
        // Without an override the store keeps no owed-reset marker.
        assert!(store.set_reset_owed(true).await.is_ok());
        assert!(!store.reset_owed());
    }
}
