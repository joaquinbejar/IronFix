/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Counts the heap allocations of a `FileStore` call in steady state.
//!
//! `dhat` is installed as this binary's global allocator and counts every
//! heap block, on every thread: the caller's and the store's writer thread.
//! The store is opened and warmed up first: its record buffer and reply cell
//! pools filled, the index chunk allocated, and both ways a call can block
//! taken once, so that whatever they set up lazily is set up before the
//! windows: the writer thread blocks in its empty queue (a pause), and the
//! caller parks while the writer is busy (a flush). Contention between the two
//! threads on a call's locks then allocates nothing (see the store's `writer`
//! module). Inside the measured windows the test makes [`CALLS`] calls of
//! `set_next_target_seq` and of `file_outbound`, and asserts that each call
//! allocates exactly one block: the boxed future of the `async_trait`
//! method, which the `MessageStore` trait shape costs every implementation
//! (ADR-0005). The store itself allocates nothing per call: the command
//! travels by value through a bounded queue whose slots exist already, the
//! answer comes back through a pooled reply cell, and the record is encoded
//! into a pooled buffer.
//!
//! It runs without the libtest harness (`harness = false` in `Cargo.toml`), so
//! no other test and no harness thread allocates while it measures. It
//! asserts counts, never timings, and holds in debug and release builds. The
//! journal uses `SyncPolicy::Never`, which changes when the store flushes,
//! not what it allocates.

use ironfix_core::message::MsgType;
use ironfix_store::{FileStore, FileStoreConfig, MessageStore, SyncPolicy};
use std::path::PathBuf;
use std::time::Duration;

#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;

/// Calls in each measured window.
const CALLS: u64 = 1_000;

/// Calls of each kind made before measuring.
const WARM_UP: u64 = 200;

/// Fails the test with context instead of `.unwrap()` / `.expect()`.
#[track_caller]
fn ok<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{what}: {err:?}"),
    }
}

/// A NewOrderSingle-shaped frame of about 200 bytes, the same length for
/// every number in the test.
fn frame(seq: u64) -> Vec<u8> {
    format!(
        "8=FIX.4.4\x019=170\x0135=D\x0149=CLIENT\x0156=VENUE\x0134={seq:06}\x01\
         52=20261018-10:15:30.123\x0111=CLORD-{seq:010}\x0121=1\x0155=AAPL\x0154=1\x01\
         60=20261018-10:15:30.120\x0138=10000\x0140=2\x0144=150.50\x0159=0\x0110=000\x01"
    )
    .into_bytes()
}

/// Heap blocks allocated so far, on every thread.
fn blocks() -> u64 {
    dhat::HeapStats::get().total_blocks
}

/// Takes both ways a call can block: the writer thread runs out of work and
/// blocks in its queue while this thread sleeps, and this thread parks while
/// the writer flushes the journal.
async fn block_both_ways(store: &FileStore) {
    std::thread::sleep(Duration::from_millis(20));
    ok(store.sync().await, "flush");
}

fn main() {
    let directory: PathBuf =
        std::env::temp_dir().join(format!("ironfix-store-allocations-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    let runtime = ok(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build(),
        "runtime",
    );
    let config = ok(
        FileStoreConfig::try_new(&directory, "ALLOCATIONS"),
        "store config",
    )
    .with_create_if_missing(true)
    .with_sync_policy(SyncPolicy::Never);
    let store = ok(runtime.block_on(FileStore::open(config)), "open the store");

    // Frames are built before the windows; the numbers stay inside the index's
    // first chunk, so no chunk is allocated while measuring.
    let frames: Vec<Vec<u8>> = (0..=WARM_UP + CALLS).map(frame).collect();
    let _profiler = dhat::Profiler::builder().testing().build();

    let (targets, outbound) = runtime.block_on(async {
        for target in 1..=WARM_UP {
            ok(store.set_next_target_seq(target).await, "warm up targets");
        }
        block_both_ways(&store).await;
        let before = blocks();
        for target in WARM_UP + 1..=WARM_UP + CALLS {
            ok(
                store.set_next_target_seq(target).await,
                "set_next_target_seq",
            );
        }
        let targets = blocks() - before;

        for seq in 1..=WARM_UP {
            let Some(payload) = frames.get(seq as usize) else {
                panic!("frame {seq} was built");
            };
            ok(
                store
                    .file_outbound(seq, &MsgType::NewOrderSingle, payload, seq + 1)
                    .await,
                "warm up frames",
            );
        }
        block_both_ways(&store).await;
        let before = blocks();
        for seq in WARM_UP + 1..=WARM_UP + CALLS {
            let Some(payload) = frames.get(seq as usize) else {
                panic!("frame {seq} was built");
            };
            ok(
                store
                    .file_outbound(seq, &MsgType::NewOrderSingle, payload, seq + 1)
                    .await,
                "file_outbound",
            );
        }
        (targets, blocks() - before)
    });

    drop(store);
    let _ = std::fs::remove_dir_all(&directory);

    assert_eq!(
        targets, CALLS,
        "set_next_target_seq allocated {targets} blocks in {CALLS} calls; it must allocate \
         exactly one per call (the async_trait future)"
    );
    assert_eq!(
        outbound, CALLS,
        "file_outbound allocated {outbound} blocks in {CALLS} calls; it must allocate exactly \
         one per call (the async_trait future)"
    );
}
