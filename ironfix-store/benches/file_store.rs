/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Criterion benchmarks for `FileStore`.
//!
//! The engine calls the store once per outbound message (`file_outbound`) and
//! once per inbound message (`set_next_target_seq`), and reads it in pages when
//! it answers a `ResendRequest`. The shapes covered:
//!
//! - `file_outbound` and `set_next_target_seq` under each `SyncPolicy`, so the
//!   cost of a flush can be told from the cost of the write;
//! - a 256-frame `get_page`, the engine's resend page;
//! - opening (and closing) a store whose journal holds 10 000 frames, which
//!   reads and checks the whole journal.
//!
//! The journals live in the system temporary directory, so what a flush costs
//! depends on the file system and device behind it. This harness only makes
//! measurement possible. It records no baseline and asserts no latency or
//! throughput figure: run `make bench` to obtain numbers on your own hardware.

use std::hint::black_box;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use criterion::{Criterion, criterion_group, criterion_main};
use ironfix_core::message::MsgType;
use ironfix_store::{FileStore, FileStoreConfig, MessageStore, SyncPolicy};
use tokio::runtime::Runtime;

/// Frames in the journal the open and page benchmarks read.
const JOURNAL_FRAMES: u64 = 10_000;

/// Frames in one resend page, the engine's page size.
const PAGE: usize = 256;

/// Fails the benchmark setup with context.
#[track_caller]
fn ok<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("{what}: {err:?}"),
    }
}

/// A directory for one benchmark, removed when it ends.
struct BenchDir(PathBuf);

impl BenchDir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("ironfix-store-bench-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        Self(path)
    }

    fn config(&self, policy: SyncPolicy) -> FileStoreConfig {
        ok(
            FileStoreConfig::try_new(&self.0, "FIX.4.4-CLIENT-VENUE"),
            "bench config",
        )
        .with_sync_policy(policy)
        .with_create_if_missing(true)
    }
}

impl Drop for BenchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A NewOrderSingle-shaped frame of about 200 bytes.
fn frame(seq: u64) -> Vec<u8> {
    format!(
        "8=FIX.4.4\x019=170\x0135=D\x0149=CLIENT\x0156=VENUE\x0134={seq}\x01\
         52=20261018-10:15:30.123\x0111=CLORD-{seq:010}\x0121=1\x0155=AAPL\x0154=1\x01\
         60=20261018-10:15:30.120\x0138=10000\x0140=2\x0144=150.50\x0159=0\x0110=000\x01"
    )
    .into_bytes()
}

fn runtime() -> Runtime {
    ok(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build(),
        "runtime",
    )
}

fn policies() -> [(&'static str, SyncPolicy); 3] {
    let every_64 = NonZeroU32::new(64).map_or(SyncPolicy::EveryWrite, SyncPolicy::EveryN);
    [
        ("every_write", SyncPolicy::EveryWrite),
        ("every_n_64", every_64),
        ("never", SyncPolicy::Never),
    ]
}

fn bench_writes(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("file_store_write");
    for (name, policy) in policies() {
        let dir = BenchDir::new(&format!("write-{name}"));
        let store = ok(rt.block_on(FileStore::open(dir.config(policy))), "open");
        let seq = AtomicU64::new(1);
        let payload = frame(1);
        group.bench_function(format!("file_outbound/{name}"), |b| {
            b.iter(|| {
                let at = seq.fetch_add(1, Ordering::Relaxed);
                let filed = rt.block_on(store.file_outbound(
                    at,
                    &MsgType::NewOrderSingle,
                    black_box(&payload),
                    at + 1,
                ));
                ok(filed, "file_outbound");
            });
        });
        group.bench_function(format!("set_next_target_seq/{name}"), |b| {
            b.iter(|| {
                let at = seq.fetch_add(1, Ordering::Relaxed);
                ok(
                    rt.block_on(store.set_next_target_seq(black_box(at))),
                    "set_next_target_seq",
                );
            });
        });
        ok(rt.block_on(store.close()), "close");
    }
    group.finish();
}

/// Builds a journal of [`JOURNAL_FRAMES`] frames, unflushed, and closes it.
fn build_journal(rt: &Runtime, dir: &BenchDir) {
    let store = ok(
        rt.block_on(FileStore::open(dir.config(SyncPolicy::Never))),
        "open",
    );
    for seq in 1..=JOURNAL_FRAMES {
        ok(
            rt.block_on(store.file_outbound(seq, &MsgType::NewOrderSingle, &frame(seq), seq + 1)),
            "file_outbound",
        );
    }
    ok(rt.block_on(store.close()), "close");
}

fn bench_reads(c: &mut Criterion) {
    let rt = runtime();
    let dir = BenchDir::new("reads");
    build_journal(&rt, &dir);
    let mut group = c.benchmark_group("file_store_read");

    let store = ok(
        rt.block_on(FileStore::open(dir.config(SyncPolicy::Never))),
        "open",
    );
    group.bench_function("get_page/256", |b| {
        b.iter(|| {
            let page = ok(
                rt.block_on(store.get_page(black_box(5_000), JOURNAL_FRAMES, PAGE)),
                "get_page",
            );
            black_box(page);
        });
    });
    ok(rt.block_on(store.close()), "close");

    group.sample_size(20);
    group.bench_function("open_and_close/10000_frames", |b| {
        b.iter(|| {
            let store = ok(
                rt.block_on(FileStore::open(dir.config(SyncPolicy::Never))),
                "open",
            );
            ok(rt.block_on(store.close()), "close");
        });
    });
    group.finish();
}

criterion_group!(benches, bench_writes, bench_reads);
criterion_main!(benches);
