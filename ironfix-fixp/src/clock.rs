/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! The session's notion of wall-clock time, derived without reading a clock.
//!
//! FIXP requests carry a `Timestamp` of type `nanotime` that identifies the
//! request and that the response echoes (Negotiate, Establish and
//! RetransmitRequest; FIXP v1.1 sections 4.2.1, 4.3.1 and 4.6.1). Per
//! ADR-0002 the session core never reads a clock, so the driver supplies a
//! [`ClockAnchor`]: one monotonic [`Instant`] paired with the wall-clock time
//! it was taken at. Every later request timestamp is the anchor's wall time
//! plus the monotonic time elapsed since the anchor, computed with checked
//! arithmetic.
//!
//! Two requests are never given the same timestamp: if the derived time has
//! not advanced past the last one issued (two requests in the same
//! nanosecond, or an `Instant` earlier than the previous one), the last
//! timestamp plus one nanosecond is used instead.

use crate::error::FixpError;
use crate::types::Nanotime;
use ironfix_core::Timestamp;
use std::time::Instant;

/// A monotonic instant paired with the wall-clock time it corresponds to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockAnchor {
    instant: Instant,
    wall: u64,
}

impl ClockAnchor {
    /// Pairs `instant` with the wall-clock time `wall` it was taken at.
    ///
    /// A driver typically builds it once, from `Instant::now()` and
    /// `ironfix_core::Timestamp::try_now()` read back to back.
    #[must_use]
    pub const fn new(instant: Instant, wall: Timestamp) -> Self {
        Self {
            instant,
            wall: wall.as_nanos(),
        }
    }

    /// Returns the wall-clock time corresponding to `now`.
    ///
    /// # Errors
    /// Returns [`FixpError::ClockOutOfRange`] if the result does not fit a
    /// 64-bit nanosecond count.
    pub fn nanotime_at(&self, now: Instant) -> Result<Nanotime, FixpError> {
        let nanos = match now.checked_duration_since(self.instant) {
            Some(elapsed) => u64::try_from(elapsed.as_nanos())
                .ok()
                .and_then(|elapsed| self.wall.checked_add(elapsed)),
            None => u64::try_from(self.instant.duration_since(now).as_nanos())
                .ok()
                .and_then(|before| self.wall.checked_sub(before)),
        };
        nanos
            .map(Nanotime::from_nanos)
            .ok_or(FixpError::ClockOutOfRange)
    }
}

/// Issues strictly increasing request timestamps from a [`ClockAnchor`].
#[derive(Debug, Clone)]
pub(crate) struct RequestClock {
    anchor: ClockAnchor,
    last: Option<u64>,
}

impl RequestClock {
    pub(crate) const fn new(anchor: ClockAnchor) -> Self {
        Self { anchor, last: None }
    }

    /// Returns a request timestamp for `now`, greater than every one issued
    /// before.
    pub(crate) fn next(&mut self, now: Instant) -> Result<Nanotime, FixpError> {
        let derived = self.anchor.nanotime_at(now)?.as_nanos();
        let issued = match self.last {
            Some(last) if derived <= last => {
                last.checked_add(1).ok_or(FixpError::ClockOutOfRange)?
            }
            Some(_) | None => derived,
        };
        self.last = Some(issued);
        Ok(Nanotime::from_nanos(issued))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn anchor(wall: u64) -> (Instant, ClockAnchor) {
        let base = Instant::now();
        let timestamp = Timestamp::from_nanos(wall).unwrap_or(Timestamp::EPOCH);
        (base, ClockAnchor::new(base, timestamp))
    }

    #[test]
    fn test_nanotime_at_adds_the_elapsed_monotonic_time() {
        let (base, anchor) = anchor(1_000_000_000);
        assert_eq!(
            anchor.nanotime_at(base + Duration::from_millis(3)),
            Ok(Nanotime::from_nanos(1_003_000_000))
        );
        assert_eq!(
            anchor.nanotime_at(base),
            Ok(Nanotime::from_nanos(1_000_000_000))
        );
    }

    #[test]
    fn test_nanotime_at_handles_an_instant_before_the_anchor() {
        let base = Instant::now() + Duration::from_secs(10);
        let anchor = ClockAnchor::new(
            base,
            Timestamp::from_nanos(5_000_000_000).unwrap_or(Timestamp::EPOCH),
        );
        assert_eq!(
            anchor.nanotime_at(base - Duration::from_secs(2)),
            Ok(Nanotime::from_nanos(3_000_000_000))
        );
        assert_eq!(
            anchor.nanotime_at(base - Duration::from_secs(6)),
            Err(FixpError::ClockOutOfRange)
        );
    }

    #[test]
    fn test_request_clock_never_repeats_a_timestamp() {
        let (base, anchor) = anchor(100);
        let mut clock = RequestClock::new(anchor);
        assert_eq!(clock.next(base), Ok(Nanotime::from_nanos(100)));
        assert_eq!(clock.next(base), Ok(Nanotime::from_nanos(101)));
        assert_eq!(clock.next(base), Ok(Nanotime::from_nanos(102)));
        assert_eq!(
            clock.next(base + Duration::from_nanos(1_000)),
            Ok(Nanotime::from_nanos(1_100))
        );
    }
}
