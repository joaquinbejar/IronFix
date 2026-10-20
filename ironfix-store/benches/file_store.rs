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
//!   reads and checks the whole journal;
//! - `file_outbound` and `set_next_target_seq` under `SyncPolicy::Never` from
//!   a task spawned on a multi-thread runtime, as the engine's reactor calls
//!   them, timed inside the task (`iter_custom`) so the cost of the call and
//!   of the hand-off to the store's writer thread is measured without the
//!   runtime's `block_on` around each call;
//! - `FileStore::compact` over journals of 1 000 and 10 000 frames, which
//!   copies every live record and flushes the new journal and its directory,
//!   and over 10 000 frames under `SyncPolicy::EveryWrite`;
//! - `get_range` over 1, 256 and 10 000 frames of a 10 000-frame journal, and
//!   a cold `get_range` on a store reopened before each call;
//! - `set_next_sender_seq` under each `SyncPolicy`, and the in-memory reads
//!   `next_sender_seq` and `next_target_seq`;
//! - `file_outbound` re-filing the same 64 sequence numbers on a store with an
//!   automatic compaction threshold, so the superseded frame records
//!   periodically trigger a compaction on the writer thread; an untimed check
//!   first asserts that a compaction does happen;
//! - `file_outbound` and `set_next_target_seq` under `SyncPolicy::EveryWrite`
//!   on a fresh directory per iteration (`*_fresh`), so the cost of a flush is
//!   not skewed by a journal that grows across the whole run;
//! - the multi-thread cases also under `SyncPolicy::EveryWrite`.
//!
//! The journals live in the directory named by the `IRONFIX_BENCH_DIR`
//! environment variable, or in the system temporary directory when it is not
//! set. What a flush costs
//! depends on the file system and device behind it. This harness only makes
//! measurement possible. It records no baseline and asserts no latency or
//! throughput figure: run `make bench` to obtain numbers on your own hardware.

use std::hint::black_box;
use std::num::{NonZeroU32, NonZeroU64};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ironfix_core::message::MsgType;
use ironfix_store::{FileStore, FileStoreConfig, MessageStore, SyncPolicy};
use tokio::runtime::Runtime;

/// Frames in the journal the open and page benchmarks read.
const JOURNAL_FRAMES: u64 = 10_000;

/// Frames in one resend page, the engine's page size.
const PAGE: usize = 256;

/// Superseded bytes that trigger an automatic compaction in the
/// auto-compaction benchmark.
const AUTO_COMPACT_BYTES: u64 = 64 * 1024;

/// Sequence numbers the auto-compaction benchmark re-files in turn.
const OVERWRITE_SEQS: u64 = 64;

/// Writes the auto-compaction benchmark may make, untimed, before the check
/// that an automatic compaction happened gives up.
const AUTO_COMPACT_PROBE_WRITES: u64 = 10_000;

/// Environment variable naming the directory the journals live in.
const BENCH_DIR_VAR: &str = "IRONFIX_BENCH_DIR";

/// The root directory for every benchmark journal, chosen once.
fn bench_root() -> &'static PathBuf {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        std::env::var_os(BENCH_DIR_VAR).map_or_else(std::env::temp_dir, PathBuf::from)
    })
}

/// Checks, outside the timed region, that `write` makes the store compact
/// its journal on its own: a compaction writes a new journal and renames it
/// into place, so the journal's inode changes or its size drops.
fn assert_auto_compacts(journal: &std::path::Path, mut write: impl FnMut(u64), next: &AtomicU64) {
    let identity = |path: &std::path::Path| {
        let meta = ok(std::fs::metadata(path), "journal metadata");
        #[cfg(unix)]
        let inode = std::os::unix::fs::MetadataExt::ino(&meta);
        #[cfg(not(unix))]
        let inode = 0_u64;
        (inode, meta.len())
    };
    write(next.fetch_add(1, Ordering::Relaxed));
    let (inode, mut size) = identity(journal);
    for _ in 0..AUTO_COMPACT_PROBE_WRITES {
        write(next.fetch_add(1, Ordering::Relaxed));
        let (now_inode, now_size) = identity(journal);
        if now_inode != inode || now_size < size {
            return;
        }
        size = now_size;
    }
    panic!("no automatic compaction after {AUTO_COMPACT_PROBE_WRITES} overwriting writes");
}

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
        let path = bench_root().join(format!("ironfix-store-bench-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        Self(path)
    }

    fn config(&self, policy: SyncPolicy) -> FileStoreConfig {
        self.config_with_compaction(policy, None)
    }

    /// The bench config with an automatic compaction threshold, in bytes.
    fn config_with_compaction(
        &self,
        policy: SyncPolicy,
        threshold: Option<u64>,
    ) -> FileStoreConfig {
        ok(
            FileStoreConfig::try_new(&self.0, "FIX.4.4-CLIENT-VENUE"),
            "bench config",
        )
        .with_sync_policy(policy)
        .with_create_if_missing(true)
        .with_compaction_threshold(threshold.and_then(NonZeroU64::new))
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
        group.bench_function(format!("set_next_sender_seq/{name}"), |b| {
            b.iter(|| {
                let at = seq.fetch_add(1, Ordering::Relaxed);
                ok(
                    rt.block_on(store.set_next_sender_seq(black_box(at))),
                    "set_next_sender_seq",
                );
            });
        });
        if matches!(policy, SyncPolicy::Never) {
            group.bench_function("next_sender_seq/never", |b| {
                b.iter(|| black_box(store.next_sender_seq()));
            });
            group.bench_function("next_target_seq/never", |b| {
                b.iter(|| black_box(store.next_target_seq()));
            });
        }
        ok(rt.block_on(store.close()), "close");
    }

    // Re-filing the same few sequence numbers supersedes the earlier frame
    // records, so this store crosses its compaction threshold periodically
    // and compacts on its writer thread. Counter writes would not: they
    // overwrite the checkpoint slots in place and leave no superseded bytes.
    let dir = BenchDir::new("write-auto-compact");
    let config = dir.config_with_compaction(SyncPolicy::Never, Some(AUTO_COMPACT_BYTES));
    let journal = config.journal_path();
    let store = ok(rt.block_on(FileStore::open(config)), "open");
    let payload = frame(1);
    let next = AtomicU64::new(0);
    let overwrite = |store: &FileStore, i: u64| {
        let at = i % OVERWRITE_SEQS + 1;
        let filed = rt.block_on(store.file_outbound(
            at,
            &MsgType::NewOrderSingle,
            black_box(&payload),
            OVERWRITE_SEQS + 1,
        ));
        ok(filed, "file_outbound");
    };
    assert_auto_compacts(&journal, |i| overwrite(&store, i), &next);
    group.bench_function("file_outbound_overwrite_auto_compact/never", |b| {
        b.iter(|| overwrite(&store, next.fetch_add(1, Ordering::Relaxed)));
    });
    ok(rt.block_on(store.close()), "close");
    group.finish();
}

/// Writes under `SyncPolicy::EveryWrite`, each on a store opened in a fresh
/// directory, so the journal does not grow across the run. Only the call is
/// timed; opening and closing the store are not.
fn bench_fresh_writes(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("file_store_write");
    let payload = frame(1);
    let batch = AtomicU64::new(0);
    // The store comes first so it is dropped (and its writer thread stopped)
    // before its directory is removed, outside the timed section.
    let fresh = |rt: &Runtime| {
        let n = batch.fetch_add(1, Ordering::Relaxed);
        let dir = BenchDir::new(&format!("write-fresh-{n}"));
        let store = ok(
            rt.block_on(FileStore::open(dir.config(SyncPolicy::EveryWrite))),
            "open",
        );
        (store, dir)
    };
    group.bench_function("file_outbound_fresh/every_write", |b| {
        b.iter_batched(
            || fresh(&rt),
            |(store, dir)| {
                let filed = rt.block_on(store.file_outbound(
                    1,
                    &MsgType::NewOrderSingle,
                    black_box(&payload),
                    2,
                ));
                ok(filed, "file_outbound");
                (store, dir)
            },
            BatchSize::PerIteration,
        );
    });
    group.bench_function("set_next_target_seq_fresh/every_write", |b| {
        b.iter_batched(
            || fresh(&rt),
            |(store, dir)| {
                ok(
                    rt.block_on(store.set_next_target_seq(black_box(2))),
                    "set_next_target_seq",
                );
                (store, dir)
            },
            BatchSize::PerIteration,
        );
    });
    group.bench_function("set_next_sender_seq_fresh/every_write", |b| {
        b.iter_batched(
            || fresh(&rt),
            |(store, dir)| {
                ok(
                    rt.block_on(store.set_next_sender_seq(black_box(2))),
                    "set_next_sender_seq",
                );
                (store, dir)
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

/// Builds a journal of [`JOURNAL_FRAMES`] frames, unflushed, and closes it.
fn build_journal(rt: &Runtime, dir: &BenchDir) {
    build_journal_of(rt, dir, JOURNAL_FRAMES);
}

/// Builds a journal of `frames` frames, unflushed, and closes it.
fn build_journal_of(rt: &Runtime, dir: &BenchDir, frames: u64) {
    let store = ok(
        rt.block_on(FileStore::open(dir.config(SyncPolicy::Never))),
        "open",
    );
    for seq in 1..=frames {
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
    // Ranges ending at the journal's last frame: 1, a resend page, and all.
    for len in [1u64, PAGE as u64, JOURNAL_FRAMES] {
        let begin = JOURNAL_FRAMES - len + 1;
        group.bench_function(format!("get_range/{len}"), |b| {
            b.iter(|| {
                let range = ok(
                    rt.block_on(store.get_range(black_box(begin), JOURNAL_FRAMES)),
                    "get_range",
                );
                black_box(range);
            });
        });
    }
    ok(rt.block_on(store.close()), "close");

    // A resend page from a store reopened before each call; only `get_range`
    // is timed, not the open or the close.
    group.bench_function("get_range/cold", |b| {
        b.iter_batched(
            || {
                ok(
                    rt.block_on(FileStore::open(dir.config(SyncPolicy::Never))),
                    "open",
                )
            },
            |store| {
                let range = ok(
                    rt.block_on(store.get_range(black_box(5_000), 5_000 + PAGE as u64 - 1)),
                    "get_range",
                );
                black_box(range);
                store
            },
            BatchSize::PerIteration,
        );
    });

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

/// A multi-thread runtime, as an engine runs on.
fn multi_thread_runtime() -> Runtime {
    ok(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build(),
        "multi-thread runtime",
    )
}

/// Runs `iters` calls of `call` in one task spawned on `rt`, and returns the
/// time they took, measured inside the task.
fn timed_in_task<F, Fut>(rt: &Runtime, store: &Arc<FileStore>, iters: u64, call: F) -> Duration
where
    F: Fn(Arc<FileStore>, u64) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let store = Arc::clone(store);
    let task = rt.spawn(async move {
        let start = Instant::now();
        for iteration in 0..iters {
            call(Arc::clone(&store), iteration).await;
        }
        start.elapsed()
    });
    ok(rt.block_on(task), "benchmark task")
}

fn bench_multi_thread(c: &mut Criterion) {
    let rt = multi_thread_runtime();
    let mut group = c.benchmark_group("file_store_multi_thread");
    for (name, policy) in [
        ("never", SyncPolicy::Never),
        ("every_write", SyncPolicy::EveryWrite),
    ] {
        let dir = BenchDir::new(&format!("multi-thread-{name}"));
        let store = Arc::new(ok(rt.block_on(FileStore::open(dir.config(policy))), "open"));
        let next = Arc::new(AtomicU64::new(1));
        let payload = Arc::new(frame(1));

        group.bench_function(format!("file_outbound/{name}"), |b| {
            b.iter_custom(|iters| {
                let next = Arc::clone(&next);
                let payload = Arc::clone(&payload);
                timed_in_task(&rt, &store, iters, move |store, _| {
                    let at = next.fetch_add(1, Ordering::Relaxed);
                    let payload = Arc::clone(&payload);
                    async move {
                        let filed = store
                            .file_outbound(
                                at,
                                &MsgType::NewOrderSingle,
                                black_box(&payload),
                                at + 1,
                            )
                            .await;
                        ok(filed, "file_outbound");
                    }
                })
            });
        });
        group.bench_function(format!("set_next_target_seq/{name}"), |b| {
            b.iter_custom(|iters| {
                let next = Arc::clone(&next);
                timed_in_task(&rt, &store, iters, move |store, _| {
                    let at = next.fetch_add(1, Ordering::Relaxed);
                    async move {
                        ok(
                            store.set_next_target_seq(black_box(at)).await,
                            "set_next_target_seq",
                        );
                    }
                })
            });
        });
        drop(store);
    }
    group.finish();
}

fn bench_compaction(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("file_store_compact");
    group.sample_size(10);
    for frames in [1_000u64, 10_000] {
        let dir = BenchDir::new(&format!("compact-{frames}"));
        build_journal_of(&rt, &dir, frames);
        let store = ok(
            rt.block_on(FileStore::open(dir.config(SyncPolicy::Never))),
            "open",
        );
        // Every iteration rewrites all `frames` live records and flushes the
        // new journal and its directory.
        group.bench_function(format!("compact/{frames}_frames"), |b| {
            b.iter(|| black_box(ok(rt.block_on(store.compact()), "compact")));
        });
        ok(rt.block_on(store.close()), "close");
    }

    // The same 10 000-frame compaction on a store that flushes every write.
    let dir = BenchDir::new("compact-every-write");
    build_journal_of(&rt, &dir, JOURNAL_FRAMES);
    let store = ok(
        rt.block_on(FileStore::open(dir.config(SyncPolicy::EveryWrite))),
        "open",
    );
    group.bench_function(
        format!("compact/{JOURNAL_FRAMES}_frames_every_write"),
        |b| {
            b.iter(|| black_box(ok(rt.block_on(store.compact()), "compact")));
        },
    );
    ok(rt.block_on(store.close()), "close");
    group.finish();
}

criterion_group!(
    benches,
    bench_writes,
    bench_fresh_writes,
    bench_reads,
    bench_multi_thread,
    bench_compaction
);
criterion_main!(benches);
