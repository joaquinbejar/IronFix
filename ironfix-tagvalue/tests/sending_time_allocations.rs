/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Proves that stamping `SendingTime` (52) on a reused [`Encoder`] allocates
//! nothing per frame.
//!
//! This is the shape of `MessageFactory::encode` in `ironfix-engine`, which
//! clears one long-lived [`Encoder`], writes the standard header with
//! `Timestamp::now().format_millis()` as tag 52 (and as `OrigSendingTime`
//! (122) on a possible duplicate), appends the body, and calls
//! [`Encoder::finish`]. That type is private to the engine, so this test
//! rebuilds the same sequence of calls from the public `Encoder` and
//! `Timestamp`.
//!
//! `dhat` is installed as this binary's global allocator and counts every
//! heap block, a reallocation included. The encoder is built and one frame
//! encoded before the measured window, so its buffer already has its final
//! capacity. Inside the window the test encodes [`FRAMES`] Heartbeats, every
//! other one flagged as a possible duplicate, and the number of blocks
//! allocated must be zero.
//!
//! It runs without the libtest harness (`harness = false` in `Cargo.toml`), so
//! no other test and no harness thread allocates while it measures. It
//! asserts counts, never timings, and holds in debug and release builds.

use ironfix_core::Timestamp;
use ironfix_tagvalue::Encoder;
use std::hint::black_box;

#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;

/// Frames encoded in the measured window.
const FRAMES: u64 = 1_000;

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

/// Encodes a Heartbeat (35=0) answering a TestRequest, header first, the way
/// the engine stamps it, and returns the frame's length in bytes.
fn encode_heartbeat(encoder: &mut Encoder, seq: u64) -> usize {
    let poss_dup = seq.is_multiple_of(2);
    encoder.clear();
    encoder.put_str(35, "0");
    encoder.put_str(49, "INITIATOR");
    encoder.put_str(56, "ACCEPTOR");
    encoder.put_uint(34, seq);
    if poss_dup {
        encoder.put_bool(43, true);
    }
    let sending_time = Timestamp::now().format_millis();
    encoder.put_str(52, sending_time.as_str());
    if poss_dup {
        encoder.put_str(122, sending_time.as_str());
    }
    encoder.put_str(112, "TEST-REQ-0001");
    ok(encoder.finish(), "a Heartbeat encodes").len()
}

fn main() {
    let mut encoder = Encoder::new("FIX.4.4");
    let _profiler = dhat::Profiler::builder().testing().build();

    // Both header shapes once, so the buffer has grown to its final size.
    black_box(encode_heartbeat(&mut encoder, 1));
    black_box(encode_heartbeat(&mut encoder, 2));

    let before = blocks();
    for seq in 3..3 + FRAMES {
        black_box(encode_heartbeat(&mut encoder, black_box(seq)));
    }
    let allocated = blocks() - before;

    assert_eq!(
        allocated, 0,
        "encoding {FRAMES} frames on a reused Encoder with SendingTime stamped allocated \
         {allocated} heap blocks; it must allocate none"
    );
}
