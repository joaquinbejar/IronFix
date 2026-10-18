/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Proves that formatting a [`Timestamp`] allocates nothing.
//!
//! `MessageFactory::encode` in `ironfix-engine` stamps `SendingTime` (52) with
//! `Timestamp::now().format_millis()` on every outbound frame, or with
//! `Timestamp::now().format_seconds()` on a FIX 4.0 or FIX 4.1 session, so a
//! heap block here is a heap block per message sent.
//!
//! `dhat` is installed as this binary's global allocator and counts every
//! heap block, a reallocation included. The timestamps are built first, and
//! every variant is called once before the measured windows. Each window then
//! makes [`CALLS`] calls of one of:
//!
//! - [`Timestamp::format_seconds`];
//! - [`Timestamp::format_millis`];
//! - [`Timestamp::format_micros`];
//! - the [`Display`](std::fmt::Display) impl, written into a fixed-capacity
//!   buffer;
//! - `Timestamp::now().format_millis()` and `Timestamp::now().format_seconds()`,
//!   the calls the engine makes.
//!
//! The number of blocks allocated in every window must be zero.
//!
//! It runs without the libtest harness (`harness = false` in `Cargo.toml`), so
//! no other test and no harness thread allocates while it measures. It
//! asserts counts, never timings, and holds in debug and release builds.

use arrayvec::ArrayString;
use ironfix_core::Timestamp;
use std::fmt::Write as _;
use std::hint::black_box;

#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;

/// Calls in each measured window.
const CALLS: usize = 1_000;

/// Fails the test with context instead of `.unwrap()` / `.expect()`.
#[track_caller]
fn ok<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{what}: {err:?}"),
    }
}

/// Heap blocks allocated so far, reallocations included.
fn blocks() -> u64 {
    dhat::HeapStats::get().total_blocks
}

/// Counts the blocks `call` allocates over [`CALLS`] calls, cycling through
/// `stamps`.
fn window(stamps: &[Timestamp], mut call: impl FnMut(Timestamp)) -> u64 {
    let before = blocks();
    for stamp in stamps.iter().cycle().take(CALLS) {
        call(black_box(*stamp));
    }
    blocks() - before
}

fn main() {
    // The epoch, the last representable nanosecond, a leap day with every
    // fractional digit set, and single-digit calendar fields.
    let stamps = [
        Timestamp::EPOCH,
        ok(Timestamp::from_nanos(Timestamp::MAX_NANOS), "MAX_NANOS"),
        ok(
            Timestamp::from_nanos(1_709_210_096_789_012_345),
            "2024-02-29T12:34:56.789012345Z",
        ),
        ok(
            Timestamp::from_nanos(981_173_106_007_008_009),
            "2001-02-03T04:05:06.007008009Z",
        ),
    ];
    let _profiler = dhat::Profiler::builder().testing().build();

    let mut display = ArrayString::<32>::new();
    let mut display_call = |stamp: Timestamp| {
        display.clear();
        ok(write!(display, "{stamp}"), "a timestamp fits 32 bytes");
        black_box(display.len());
    };

    // Each variant once, so nothing set up lazily lands in a window.
    for stamp in stamps {
        black_box(stamp.format_seconds());
        black_box(stamp.format_millis());
        black_box(stamp.format_micros());
        display_call(stamp);
    }
    black_box(Timestamp::now().format_millis());
    black_box(Timestamp::now().format_seconds());

    let seconds = window(&stamps, |stamp| {
        black_box(stamp.format_seconds());
    });
    let millis = window(&stamps, |stamp| {
        black_box(stamp.format_millis());
    });
    let micros = window(&stamps, |stamp| {
        black_box(stamp.format_micros());
    });
    let shown = window(&stamps, &mut display_call);
    let now = window(&stamps, |_| {
        black_box(Timestamp::now().format_millis());
    });
    let now_seconds = window(&stamps, |_| {
        black_box(Timestamp::now().format_seconds());
    });

    let counts = [
        ("format_seconds", seconds),
        ("format_millis", millis),
        ("format_micros", micros),
        ("Display", shown),
        ("now().format_millis", now),
        ("now().format_seconds", now_seconds),
    ];
    let allocating: Vec<(&str, u64)> = counts
        .into_iter()
        .filter(|(_, blocks)| *blocks != 0)
        .collect();
    assert!(
        allocating.is_empty(),
        "heap blocks allocated in {CALLS} calls, by variant: {allocating:?}; formatting a \
         Timestamp must allocate none"
    );
}
