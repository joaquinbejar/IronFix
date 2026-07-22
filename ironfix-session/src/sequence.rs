/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! Sequence number management.
//!
//! This module provides atomic sequence number management for FIX sessions.

use ironfix_core::types::SeqNum;
use std::sync::atomic::{AtomicU64, Ordering};

/// Error returned when a sequence counter has reached its maximum value.
///
/// FIX sequence numbers are unbounded in the specification, but this
/// implementation stores them as `u64`. Once a counter reaches `u64::MAX`
/// no further numbers can be allocated: the session must perform a
/// sequence reset (Logon with `ResetSeqNumFlag(141)=Y`, or an out-of-band
/// reset agreed with the counterparty) and then call
/// [`SequenceManager::reset`] before continuing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "sequence counter exhausted: {counter} reached u64::MAX, session requires a sequence reset"
)]
pub struct SequenceExhausted {
    /// Which counter was exhausted.
    pub counter: SequenceCounter,
}

/// Identifies one of the two sequence counters of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceCounter {
    /// Outgoing (sender) sequence counter.
    Sender,
    /// Incoming (target) sequence counter.
    Target,
}

impl std::fmt::Display for SequenceCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sender => write!(f, "sender"),
            Self::Target => write!(f, "target"),
        }
    }
}

/// Manages sequence numbers for a FIX session.
///
/// Uses atomic operations for thread-safe access without locks.
#[derive(Debug)]
pub struct SequenceManager {
    /// Next outgoing sequence number.
    next_sender_seq: AtomicU64,
    /// Next expected incoming sequence number.
    next_target_seq: AtomicU64,
}

impl SequenceManager {
    /// Creates a new sequence manager with sequence numbers starting at 1.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_sender_seq: AtomicU64::new(1),
            next_target_seq: AtomicU64::new(1),
        }
    }

    /// Creates a new sequence manager with specified starting values.
    ///
    /// # Arguments
    /// * `sender_seq` - Initial sender sequence number
    /// * `target_seq` - Initial target sequence number
    #[must_use]
    pub fn with_initial(sender_seq: u64, target_seq: u64) -> Self {
        Self {
            next_sender_seq: AtomicU64::new(sender_seq),
            next_target_seq: AtomicU64::new(target_seq),
        }
    }

    /// Returns the next sender sequence number without incrementing.
    #[inline]
    #[must_use]
    pub fn next_sender_seq(&self) -> SeqNum {
        SeqNum::new(self.next_sender_seq.load(Ordering::SeqCst))
    }

    /// Returns the next target sequence number without incrementing.
    #[inline]
    #[must_use]
    pub fn next_target_seq(&self) -> SeqNum {
        SeqNum::new(self.next_target_seq.load(Ordering::SeqCst))
    }

    /// Allocates and returns the next sender sequence number.
    ///
    /// This atomically increments the sequence number and returns the
    /// value before the increment.
    ///
    /// Note: wraps silently on `u64` overflow. Prefer
    /// [`try_allocate_sender_seq`](Self::try_allocate_sender_seq) for
    /// venue-grade sessions where exhaustion must be an explicit error.
    #[inline]
    #[deprecated(
        since = "0.4.0",
        note = "wraps silently on overflow, which corrupts a live session; use try_allocate_sender_seq. Removed in the next breaking release."
    )]
    pub fn allocate_sender_seq(&self) -> SeqNum {
        SeqNum::new(self.next_sender_seq.fetch_add(1, Ordering::SeqCst))
    }

    /// Allocates and returns the next sender sequence number, failing
    /// instead of wrapping when the counter is exhausted.
    ///
    /// On success this atomically increments the counter and returns the
    /// value before the increment. On exhaustion the counter is left
    /// untouched; the session must perform a sequence reset (see
    /// [`SequenceExhausted`]) before more numbers can be allocated.
    ///
    /// # Errors
    /// Returns [`SequenceExhausted`] if the counter has reached `u64::MAX`.
    #[inline]
    pub fn try_allocate_sender_seq(&self) -> Result<SeqNum, SequenceExhausted> {
        self.next_sender_seq
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_add(1)
            })
            .map(SeqNum::new)
            .map_err(|_| SequenceExhausted {
                counter: SequenceCounter::Sender,
            })
    }

    /// Increments the target sequence number.
    ///
    /// Call this after successfully processing an incoming message.
    ///
    /// Note: wraps silently on `u64` overflow. Prefer
    /// [`try_increment_target_seq`](Self::try_increment_target_seq) for
    /// venue-grade sessions where exhaustion must be an explicit error.
    #[inline]
    #[deprecated(
        since = "0.4.0",
        note = "wraps silently on overflow, which corrupts a live session; use try_increment_target_seq. Removed in the next breaking release."
    )]
    pub fn increment_target_seq(&self) {
        self.next_target_seq.fetch_add(1, Ordering::SeqCst);
    }

    /// Increments the target sequence number, failing instead of wrapping
    /// when the counter is exhausted.
    ///
    /// On success returns the new next expected target sequence number.
    /// On exhaustion the counter is left untouched; the session must
    /// perform a sequence reset (see [`SequenceExhausted`]) before more
    /// messages can be accepted.
    ///
    /// # Errors
    /// Returns [`SequenceExhausted`] if the counter has reached `u64::MAX`.
    #[inline]
    pub fn try_increment_target_seq(&self) -> Result<SeqNum, SequenceExhausted> {
        self.next_target_seq
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                current.checked_add(1)
            })
            .map(|previous| SeqNum::new(previous + 1))
            .map_err(|_| SequenceExhausted {
                counter: SequenceCounter::Target,
            })
    }

    /// Sets the next sender sequence number.
    ///
    /// # Arguments
    /// * `seq` - The new sequence number
    #[inline]
    pub fn set_sender_seq(&self, seq: u64) {
        self.next_sender_seq.store(seq, Ordering::SeqCst);
    }

    /// Sets the next target sequence number.
    ///
    /// # Arguments
    /// * `seq` - The new sequence number
    #[inline]
    pub fn set_target_seq(&self, seq: u64) {
        self.next_target_seq.store(seq, Ordering::SeqCst);
    }

    /// Resets both sequence numbers to 1.
    #[inline]
    pub fn reset(&self) {
        self.next_sender_seq.store(1, Ordering::SeqCst);
        self.next_target_seq.store(1, Ordering::SeqCst);
    }

    /// Validates an incoming sequence number.
    ///
    /// # Arguments
    /// * `received` - The received sequence number
    ///
    /// # Returns
    /// - `Ok(())` if the sequence number matches expected
    /// - `Err(SequenceResult::TooLow)` if it's a possible duplicate
    /// - `Err(SequenceResult::Gap)` if there's a gap
    #[must_use]
    pub fn validate_incoming(&self, received: u64) -> SequenceResult {
        let expected = self.next_target_seq.load(Ordering::SeqCst);

        if received == expected {
            SequenceResult::Ok
        } else if received < expected {
            SequenceResult::TooLow { expected, received }
        } else {
            SequenceResult::Gap { expected, received }
        }
    }
}

impl Default for SequenceManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of sequence number validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceResult {
    /// Sequence number is as expected.
    Ok,
    /// Sequence number is lower than expected (possible duplicate).
    TooLow {
        /// Expected sequence number.
        expected: u64,
        /// Received sequence number.
        received: u64,
    },
    /// Sequence number is higher than expected (gap detected).
    Gap {
        /// Expected sequence number.
        expected: u64,
        /// Received sequence number.
        received: u64,
    },
}

impl SequenceResult {
    /// Returns true if the sequence is valid.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }

    /// Returns true if there's a gap.
    #[must_use]
    pub const fn is_gap(&self) -> bool {
        matches!(self, Self::Gap { .. })
    }

    /// Returns true if the sequence is too low.
    #[must_use]
    pub const fn is_too_low(&self) -> bool {
        matches!(self, Self::TooLow { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequence_manager_new() {
        let mgr = SequenceManager::new();
        assert_eq!(mgr.next_sender_seq().value(), 1);
        assert_eq!(mgr.next_target_seq().value(), 1);
    }

    #[test]
    #[allow(deprecated)]
    fn test_allocate_sender_seq() {
        let mgr = SequenceManager::new();

        let seq1 = mgr.allocate_sender_seq();
        assert_eq!(seq1.value(), 1);
        assert_eq!(mgr.next_sender_seq().value(), 2);

        let seq2 = mgr.allocate_sender_seq();
        assert_eq!(seq2.value(), 2);
        assert_eq!(mgr.next_sender_seq().value(), 3);
    }

    #[test]
    #[allow(deprecated)]
    fn test_increment_target_seq() {
        let mgr = SequenceManager::new();

        mgr.increment_target_seq();
        assert_eq!(mgr.next_target_seq().value(), 2);

        mgr.increment_target_seq();
        assert_eq!(mgr.next_target_seq().value(), 3);
    }

    #[test]
    fn test_validate_incoming() {
        let mgr = SequenceManager::new();

        assert!(mgr.validate_incoming(1).is_ok());

        mgr.set_target_seq(5);
        assert!(mgr.validate_incoming(4).is_too_low());
        assert!(mgr.validate_incoming(5).is_ok());
        assert!(mgr.validate_incoming(10).is_gap());
    }

    #[test]
    fn test_try_allocate_sender_seq() {
        let mgr = SequenceManager::new();

        assert_eq!(mgr.try_allocate_sender_seq().map(SeqNum::value), Ok(1));
        assert_eq!(mgr.try_allocate_sender_seq().map(SeqNum::value), Ok(2));
        assert_eq!(mgr.next_sender_seq().value(), 3);
    }

    #[test]
    fn test_try_allocate_sender_seq_exhausted() {
        let mgr = SequenceManager::with_initial(u64::MAX, 1);

        assert_eq!(
            mgr.try_allocate_sender_seq(),
            Err(SequenceExhausted {
                counter: SequenceCounter::Sender
            })
        );
        // Counter untouched: still exhausted, no wraparound.
        assert_eq!(mgr.next_sender_seq().value(), u64::MAX);
        assert!(mgr.try_allocate_sender_seq().is_err());

        // Reset restores a usable session.
        mgr.reset();
        assert_eq!(mgr.try_allocate_sender_seq().map(SeqNum::value), Ok(1));
    }

    #[test]
    fn test_try_increment_target_seq() {
        let mgr = SequenceManager::new();

        assert_eq!(mgr.try_increment_target_seq().map(SeqNum::value), Ok(2));
        assert_eq!(mgr.try_increment_target_seq().map(SeqNum::value), Ok(3));
        assert_eq!(mgr.next_target_seq().value(), 3);
    }

    #[test]
    fn test_try_increment_target_seq_exhausted() {
        let mgr = SequenceManager::with_initial(1, u64::MAX);

        assert_eq!(
            mgr.try_increment_target_seq(),
            Err(SequenceExhausted {
                counter: SequenceCounter::Target
            })
        );
        assert_eq!(mgr.next_target_seq().value(), u64::MAX);
        assert!(mgr.try_increment_target_seq().is_err());
    }

    #[test]
    fn test_reset() {
        let mgr = SequenceManager::with_initial(100, 200);
        assert_eq!(mgr.next_sender_seq().value(), 100);
        assert_eq!(mgr.next_target_seq().value(), 200);

        mgr.reset();
        assert_eq!(mgr.next_sender_seq().value(), 1);
        assert_eq!(mgr.next_target_seq().value(), 1);
    }
}
