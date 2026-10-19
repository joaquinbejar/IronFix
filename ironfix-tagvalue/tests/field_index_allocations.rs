/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 19/10/26
******************************************************************************/

//! Proves that decoding into a reused [`FieldIndex`] allocates nothing per
//! message, for a message well above the 32 fields `RawMessage` keeps inline.
//!
//! `dhat` is installed as this binary's global allocator and counts every
//! heap block, a reallocation included. The frame and the index are built
//! before the measured window. Inside the window the test decodes a
//! 100-field message [`FRAMES`] times into the same index, reads every field
//! back, and the number of blocks allocated must be zero.
//!
//! A clone of an empty index must also decode without allocating.
//!
//! As a control, the same message through [`Decoder::decode`] must allocate:
//! its `SmallVec<[FieldRef; 32]>` spills above 32 fields, which is the
//! allocation the index exists to remove.
//!
//! It runs without the libtest harness (`harness = false` in `Cargo.toml`), so
//! no other test and no harness thread allocates while it measures. It
//! asserts counts, never timings, and holds in debug and release builds.

use ironfix_tagvalue::{Decoder, Encoder, FieldIndex};
use std::hint::black_box;

#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;

/// Messages decoded in the measured window.
const FRAMES: u64 = 1_000;

/// Fields in the decoded message, CheckSum (10) excluded.
const FIELDS: usize = 100;

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

/// Encodes a message with exactly [`FIELDS`] fields: 8, 9, 35 and 97 body
/// fields after it.
fn hundred_field_frame() -> Vec<u8> {
    let mut encoder = Encoder::new("FIX.4.4");
    encoder.put_str(35, "8");
    for tag in 0..FIELDS - 3 {
        let tag = ok(u32::try_from(tag), "tag fits u32") + 5000;
        encoder.put_uint(tag, u64::from(tag));
    }
    ok(encoder.finish(), "the message encodes").to_vec()
}

/// Decodes `frame` into `index` and folds every field into a checksum, so no
/// read is optimised away.
fn decode_indexed(frame: &[u8], index: &mut FieldIndex) -> usize {
    let message = ok(
        Decoder::new(frame).decode_into(index),
        "the message decodes into the index",
    );
    assert_eq!(message.field_count(), FIELDS);
    message
        .fields()
        .map(|field| field.value.len() + field.tag as usize)
        .sum()
}

fn main() {
    let frame = hundred_field_frame();
    let mut index = FieldIndex::with_capacity(FIELDS);
    let _profiler = dhat::Profiler::builder().testing().build();

    // One decode before the window, as a warm-up.
    black_box(decode_indexed(&frame, &mut index));

    let before = blocks();
    for _ in 0..FRAMES {
        black_box(decode_indexed(black_box(&frame), &mut index));
    }
    let allocated = blocks() - before;
    assert_eq!(
        allocated, 0,
        "decoding a {FIELDS}-field message {FRAMES} times into a reused FieldIndex allocated \
         {allocated} heap blocks; it must allocate none"
    );

    // A clone of an empty index keeps its reserved storage: decoding into it
    // allocates nothing either (a derived `Clone` reallocated here).
    let mut cloned = FieldIndex::with_capacity(FIELDS).clone();
    let before = blocks();
    black_box(decode_indexed(&frame, &mut cloned));
    let cloned_blocks = blocks() - before;
    assert_eq!(
        cloned_blocks, 0,
        "decoding into a cloned FieldIndex allocated {cloned_blocks} heap blocks; it must allocate none"
    );

    // Control: the SmallVec path spills above 32 fields.
    let before = blocks();
    let raw = ok(Decoder::new(&frame).decode(), "the message decodes");
    black_box(raw.field_count());
    let spilled = blocks() - before;
    assert!(
        spilled > 0,
        "decode() of a {FIELDS}-field message is expected to spill its SmallVec"
    );
}
