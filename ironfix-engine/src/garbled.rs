/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 17/10/26
******************************************************************************/

//! Garbled-frame accounting: the decision behind
//! [`SessionConfig::garbled_frame_limit`](ironfix_session::SessionConfig::garbled_frame_limit).
//!
//! The codec skips a garbled frame and counts it
//! ([`ironfix_transport::FixCodec::take_garbled_count`]); the reactor hands each
//! count to [`GarbledFrameWindow::record`] together with the time it observed
//! it, and closes the session when the verdict says so. Nothing else about a
//! garbled frame reaches the session: its `MsgSeqNum` (34) cannot be trusted,
//! so it consumes none, and garbled bytes are not proof that the peer is alive,
//! so the heartbeat clock is not refreshed.
//!
//! The decision is synchronous and takes the time as an argument rather than
//! reading a clock, per ADR-0002 (`doc/adr/0002-session-driver.md`): the
//! driver supplies `now`, so the window is exact under a paused clock and is
//! unit-tested with synthetic instants.

use ironfix_session::GarbledFrameLimit;
use std::collections::VecDeque;
use std::time::Instant;

/// What the reactor must do after recording garbled frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GarbledVerdict {
    /// Fewer than the limit fall inside the window: keep the session.
    Tolerated,
    /// The limit is reached inside the window: close the session.
    LimitReached,
}

/// Sliding-window count of garbled inbound frames against a
/// [`GarbledFrameLimit`].
///
/// It remembers when each garbled frame still inside the window arrived, and
/// never more than [`GarbledFrameLimit::max`] of them, so its memory is bounded
/// by the configuration (at most
/// [`MAX_GARBLED_FRAME_LIMIT`](ironfix_session::config::MAX_GARBLED_FRAME_LIMIT)
/// timestamps), never by the input.
#[derive(Debug)]
pub(crate) struct GarbledFrameWindow {
    /// The configured bound.
    limit: GarbledFrameLimit,
    /// Arrival times of the garbled frames inside the window, oldest first.
    seen: VecDeque<Instant>,
}

impl GarbledFrameWindow {
    /// Creates an empty window for `limit`, with room for every timestamp it
    /// can ever hold, so recording never reallocates.
    ///
    /// The capacity is a hint: on a target where the count does not fit in
    /// `usize` (none that Tokio supports) the deque starts empty and grows,
    /// still never past `max` entries.
    #[must_use]
    pub(crate) fn new(limit: GarbledFrameLimit) -> Self {
        let seen = usize::try_from(limit.max().get())
            .map_or_else(|_| VecDeque::new(), VecDeque::with_capacity);
        Self { limit, seen }
    }

    /// Returns the bound this window enforces.
    #[must_use]
    pub(crate) const fn limit(&self) -> GarbledFrameLimit {
        self.limit
    }

    /// Records `frames` garbled frames observed at `now` and decides whether
    /// the session may continue.
    ///
    /// A frame stays inside the window while its age is strictly less than the
    /// window: one exactly `window` old has aged out. The verdict is
    /// [`GarbledVerdict::LimitReached`] as soon as the frames inside the window
    /// number [`GarbledFrameLimit::max`]. Recording stops there, so even an
    /// enormous `frames` costs at most `max` steps.
    ///
    /// `now` is the driver's monotonic time. An instant earlier than one
    /// already recorded cannot age that frame out, so a clock that steps back
    /// never shrinks the count.
    #[must_use = "a reached limit must close the session"]
    pub(crate) fn record(&mut self, now: Instant, frames: u64) -> GarbledVerdict {
        let window = self.limit.window();
        while self.seen.front().is_some_and(|&arrived| {
            now.checked_duration_since(arrived)
                .is_some_and(|age| age >= window)
        }) {
            self.seen.pop_front();
        }

        let max = u64::from(self.limit.max().get());
        for _ in 0..frames {
            if self.is_full(max) {
                break;
            }
            self.seen.push_back(now);
        }

        if self.is_full(max) {
            GarbledVerdict::LimitReached
        } else {
            GarbledVerdict::Tolerated
        }
    }

    /// Whether the window holds `max` frames.
    ///
    /// A length that does not fit in `u64` is treated as full; it is
    /// unreachable, since the window never holds more than `max <= u32::MAX`.
    fn is_full(&self, max: u64) -> bool {
        u64::try_from(self.seen.len()).map_or(true, |len| len >= max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A window for `max` frames within `window_secs` seconds.
    #[track_caller]
    fn window(max: u32, window_secs: u64) -> GarbledFrameWindow {
        let Some(max) = std::num::NonZeroU32::new(max) else {
            panic!("test frame count must be non-zero");
        };
        match GarbledFrameLimit::try_new(max, Duration::from_secs(window_secs)) {
            Ok(limit) => GarbledFrameWindow::new(limit),
            Err(err) => panic!("test limit must be valid: {err}"),
        }
    }

    /// `secs` seconds after `base`.
    fn at(base: Instant, secs: u64) -> Instant {
        match base.checked_add(Duration::from_secs(secs)) {
            Some(instant) => instant,
            None => panic!("test instant must be representable"),
        }
    }

    #[test]
    fn test_record_below_the_limit_is_tolerated() {
        let base = Instant::now();
        let mut garbled = window(3, 10);
        assert_eq!(garbled.record(at(base, 0), 1), GarbledVerdict::Tolerated);
        assert_eq!(garbled.record(at(base, 1), 1), GarbledVerdict::Tolerated);
    }

    #[test]
    fn test_record_reaching_the_limit_within_the_window_closes() {
        let base = Instant::now();
        let mut garbled = window(3, 10);
        assert_eq!(garbled.record(at(base, 0), 1), GarbledVerdict::Tolerated);
        assert_eq!(garbled.record(at(base, 4), 1), GarbledVerdict::Tolerated);
        assert_eq!(garbled.record(at(base, 9), 1), GarbledVerdict::LimitReached);
    }

    #[test]
    fn test_record_frames_that_aged_out_do_not_count() {
        let base = Instant::now();
        let mut garbled = window(3, 10);
        assert_eq!(garbled.record(at(base, 0), 1), GarbledVerdict::Tolerated);
        assert_eq!(garbled.record(at(base, 1), 1), GarbledVerdict::Tolerated);
        // At t=11 both earlier frames are at least 10 s old: only this one is
        // inside the window.
        assert_eq!(garbled.record(at(base, 11), 1), GarbledVerdict::Tolerated);
        assert_eq!(garbled.record(at(base, 12), 1), GarbledVerdict::Tolerated);
        assert_eq!(
            garbled.record(at(base, 13), 1),
            GarbledVerdict::LimitReached
        );
    }

    #[test]
    fn test_record_a_frame_exactly_one_window_old_has_aged_out() {
        let base = Instant::now();
        let mut garbled = window(2, 10);
        assert_eq!(garbled.record(at(base, 0), 1), GarbledVerdict::Tolerated);
        assert_eq!(garbled.record(at(base, 10), 1), GarbledVerdict::Tolerated);
    }

    #[test]
    fn test_record_a_frame_just_inside_the_window_still_counts() {
        let base = Instant::now();
        let mut garbled = window(2, 10);
        assert_eq!(garbled.record(base, 1), GarbledVerdict::Tolerated);
        let Some(just_inside) = at(base, 10).checked_sub(Duration::from_nanos(1)) else {
            panic!("test instant must be representable");
        };
        assert_eq!(garbled.record(just_inside, 1), GarbledVerdict::LimitReached);
    }

    #[test]
    fn test_record_a_batch_at_one_instant_counts_every_frame() {
        let base = Instant::now();
        let mut garbled = window(3, 10);
        assert_eq!(garbled.record(base, 2), GarbledVerdict::Tolerated);
        assert_eq!(garbled.record(base, 1), GarbledVerdict::LimitReached);

        let mut garbled = window(3, 10);
        assert_eq!(garbled.record(base, 3), GarbledVerdict::LimitReached);
    }

    #[test]
    fn test_record_a_huge_batch_is_bounded_by_the_limit() {
        let base = Instant::now();
        let mut garbled = window(4, 10);
        assert_eq!(garbled.record(base, u64::MAX), GarbledVerdict::LimitReached);
        assert_eq!(garbled.seen.len(), 4, "never more than `max` timestamps");
    }

    #[test]
    fn test_record_zero_frames_changes_nothing() {
        let base = Instant::now();
        let mut garbled = window(1, 10);
        assert_eq!(garbled.record(base, 0), GarbledVerdict::Tolerated);
        assert!(garbled.seen.is_empty());
    }

    #[test]
    fn test_record_a_limit_of_one_closes_on_the_first_garbled_frame() {
        let mut garbled = window(1, 10);
        assert_eq!(
            garbled.record(Instant::now(), 1),
            GarbledVerdict::LimitReached
        );
    }

    #[test]
    fn test_record_a_clock_stepping_back_never_shrinks_the_count() {
        let base = Instant::now();
        let mut garbled = window(2, 10);
        assert_eq!(garbled.record(at(base, 5), 1), GarbledVerdict::Tolerated);
        assert_eq!(garbled.record(base, 1), GarbledVerdict::LimitReached);
    }

    #[test]
    fn test_limit_reports_the_configured_bound() {
        let garbled = window(7, 30);
        assert_eq!(garbled.limit().max().get(), 7);
        assert_eq!(garbled.limit().window(), Duration::from_secs(30));
    }

    #[test]
    fn test_new_reserves_room_for_every_timestamp_up_front() {
        let mut garbled = window(16, 30);
        assert!(garbled.seen.capacity() >= 16);
        let before = garbled.seen.capacity();
        assert_eq!(
            garbled.record(Instant::now(), 16),
            GarbledVerdict::LimitReached
        );
        assert_eq!(
            garbled.seen.capacity(),
            before,
            "recording never reallocates"
        );
    }
}
