/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! A persistent, file-backed message store.
//!
//! [`FileStore`] keeps a session's outbound journal and both sequence counters
//! in one file, so they survive a process restart: a session started on a
//! reopened store resumes from its counters, and a `ResendRequest` (35=2)
//! after a restart is answered with the original frames. The design is
//! recorded in `doc/adr/0006-file-store.md` and, for the writer thread, the
//! index, the counter slots and compaction, in
//! `doc/adr/0022-file-store-writer-thread-and-compaction.md`.
//!
//! # Layout
//!
//! One journal file, `<directory>/<name>.journal` (see [`FileStoreConfig`]),
//! in format version 4: a header recording the creation time, two **counter
//! slots** holding both sequence counters, then a sequence of
//! length-prefixed, CRC-checked records, each a filed frame, or a filed frame
//! together with the next sender number (one
//! [`MessageStore::file_outbound`] call). Frames are appended; the counters
//! are written in place, into the slot that does not hold the last durable
//! checkpoint, so **the file grows with outbound frames only**, never with
//! inbound traffic. Loading
//! replays the records in order, so a later frame filed under a number
//! replaces the earlier one. The byte layout is documented in the `format`
//! module source and in ADR-0022.
//!
//! Each counter slot also carries the **owed-reset marker**
//! ([`MessageStore::set_reset_owed`], ADR-0029): the engine's durable intent
//! to reset the sequence. Setting or clearing it writes both slots, each
//! flushed whatever the [`SyncPolicy`]; a reset and a compaction carry it into
//! the new journal.
//!
//! The slots also carry the **inbound application watermark**
//! ([`MessageStore::set_app_watermark`], ADR-0030): the highest inbound
//! `MsgSeqNum` up to which the engine acted on every message it accepted.
//! It is written like a counter, into one slot under the [`SyncPolicy`]; a
//! reset clears it and a compaction carries it.
//!
//! A journal in any other format version is refused with
//! [`StoreError::Corrupted`] naming the version. That includes version 1, a
//! development format (counters as appended records), version 2, the slots
//! without the marker, and version 3, the slots without the watermark; none
//! was ever released, and none is migrated.
//!
//! # Memory
//!
//! In memory the store keeps an index from sequence number to the record's
//! position, plus the two counters; frames are read back from the file when a
//! resend asks for them, and checked again on the way. The index is dense: 12
//! bytes per sequence number from the lowest filed to the highest, in fixed
//! 48 KiB chunks (at most two of them partly used), with a bounded number of
//! holes; a jump past that bound switches it to a sparse map (about 40 to 50
//! bytes per filed frame, by estimate) until the next reset, compaction or
//! reload. Memory therefore never depends on how far the numbers jump.
//!
//! # Atomicity
//!
//! - [`MessageStore::file_outbound`] writes the frame and the next sender
//!   number as **one record**: after a crash both are in the journal or
//!   neither is.
//! - [`MessageStore::set_next_sender_seq`] and
//!   [`MessageStore::set_next_target_seq`] overwrite the counter slot that
//!   does not hold the last checkpoint known to be on stable storage, with
//!   the next generation; until the next flush every counter write goes to
//!   that same slot. A write torn or lost by a crash damages only that slot,
//!   and the store reopens from the other one: at least the last flushed
//!   counters. Each slot also records the offset up to which the records were
//!   durable when it was written (its durable boundary).
//! - [`MessageStore::reset`] and [`MessageStore::reset_to`] write a complete
//!   new journal (no records, carrying the new counters) to
//!   `<name>.journal.tmp`, flush it, rename it over the journal and flush the
//!   directory, whatever the [`SyncPolicy`]: after a crash the store is
//!   entirely the old stream or entirely the new one. [`FileStore::compact`]
//!   commits the same way.
//! - [`MessageStore::store`] is one record.
//!
//! # Call order
//!
//! Every call runs on the store's own **writer thread**, one at a time, in the
//! order the calls were made: the async caller queues it and awaits the
//! answer, holding no lock while it waits. The queue holds at most 1 024
//! calls; a call made while it is full fails with [`StoreError::Io`] without
//! having been queued. A caller may drop a call's future (the engine bounds
//! every store call with a timeout): a call dropped before the writer thread
//! takes it does nothing (it stays in the queue until the thread skips it),
//! and once the thread has taken it the call runs to the end before the
//! thread takes the next one, even if its future is dropped. A dropped call
//! can therefore take effect without reporting it, but never after, or
//! interleaved with, a later call: the [`MessageStore`] call-order contract.
//!
//! # Durability
//!
//! Every write reaches the operating system before its call returns, so
//! anything that returned `Ok` survives the process crashing. What survives
//! the operating system crashing or a power loss depends on the
//! [`SyncPolicy`]; only [`SyncPolicy::EveryWrite`] makes every `Ok` survive
//! it, and only under the engine's `StoreFailurePolicy::CloseSession` does a
//! failed write keep its frame off the wire (under `Continue` the frame is
//! sent anyway and the engine owes the next session a sequence reset). These
//! guarantees are stated for Unix: elsewhere the directory is not flushed
//! and the store is untested.
//!
//! # Recovery
//!
//! [`FileStore::open`] and [`MessageStore::refresh`] read the whole journal.
//! Recovery cuts only what an interrupted write can leave, and refuses the
//! rest:
//!
//! - **Cut**: a record the file ends inside; a record whose body fails its
//!   CRC and is the last one in the file; a damaged record header within one
//!   maximum-size record of the end; damage followed only by zero bytes.
//!   Under [`SyncPolicy::EveryN`]`(n)` the window is `n` maximum-size
//!   records; under [`SyncPolicy::Never`] damage is cut wherever it is. A cut
//!   removes the record and everything after it, so the record is never
//!   returned, and [`FileStore::last_truncation`] reports it.
//! - **Fall back**: one counter slot failing its check (a torn counter write)
//!   is not a cut: the counters come from the other slot.
//! - **Refuse** with [`StoreError::Corrupted`], cutting nothing: damage
//!   outside that window (data already written, and acknowledged, is damaged);
//!   under [`SyncPolicy::EveryWrite`] and [`SyncPolicy::EveryN`], any damage
//!   to a record below the durable boundary of the newest counter slot, or a
//!   journal that ends before it (the slot vouches for those records, so
//!   their damage is never a torn tail); a well-formed record header
//!   declaring a body larger than the configured limit; a record that passes
//!   its CRC but does not decode; both counter slots failing their check; a
//!   header that is not a version-4 journal header. Under
//!   [`SyncPolicy::Never`] and in a repair, a cut below the boundary writes
//!   one new counter slot with the new end as its boundary, beside the newest
//!   one, which is left as it is.
//!   [`FileStore::repair`] cuts such a journal at its first unreadable record,
//!   on an operator's decision, after which the session must reset its
//!   sequence (`ResetSeqNumFlag` (141) = Y).
//!
//! A failed write is undone. A failed flush, including the one a refresh makes
//! of writes left unflushed, cuts the journal back to the end of its last
//! successful flush and puts the counter slots back as that flush left them,
//! because after a failed flush the operating system may have dropped writes
//! it had accepted, and leaves the store refusing every call except a reset
//! until [`MessageStore::refresh`] has made that undo durable and reloaded the
//! journal: an error from a write means it was not filed, and a refresh never
//! adopts bytes a failed flush left behind.
//!
//! A record that a read finds damaged or no longer whole (the file was cut
//! under the open store) is reported as [`StoreError::Corrupted`], never as
//! an I/O error, so the engine closes the session rather than gap-filling the
//! resend.
//!
//! # Compaction
//!
//! A frame filed again under a number already filed leaves the earlier
//! record behind. [`FileStore::compact`] rewrites the journal with only the
//! live records, through the temporary file and rename. The store compacts on
//! its own only when [`FileStoreConfig::with_compaction_threshold`] is set
//! (it is off by default). A compaction copies every live record, and the
//! calls queued behind it wait: see that method for what that means under the
//! engine's store timeout.
//!
//! # Permissions
//!
//! A journal holds complete outbound frames, an outbound Logon's `Password`
//! (554) included. On Unix every file the store creates (the journal, the
//! replacement a reset or a compaction writes, the lock file) is created
//! readable and writable by its owner only (`0600`), and every directory it
//! creates is the owner's only (`0700`). A replacement is a new file with
//! those permissions, so it never loosens the journal's, whatever a leftover
//! file had. Files and directories that already exist keep their permissions.
//! Off Unix the platform's defaults apply.
//!
//! # One store, one owner
//!
//! While a store is open it holds an advisory lock on `<name>.lock`
//! ([`std::fs::File::try_lock`], which needs Rust 1.89 or later), so a second
//! store opened on the same files, in this process or another, fails with
//! [`StoreError::Io`] instead of interleaving two sequence streams in one
//! journal. The operating system releases the lock when the process dies. It
//! is advisory, and network file systems may not honour it; where the platform
//! cannot lock at all, opening fails rather than proceeding unlocked.
//! Dropping a store closes its files, releases the lock and stops its writer
//! thread at once if neither a call nor an automatic compaction is running;
//! if one is, the drop does not wait, and the thread does all three once it
//! finishes. [`FileStore::close`] waits for it.
//!
//! # Limits
//!
//! - The journal grows with every outbound frame until it is reset; a
//!   compaction reclaims only frames filed again under the same number.
//! - Opening and refreshing read the whole journal.
//! - A frame above [`FileStoreConfig::max_frame_size`] is refused.
//! - Inbound frames are not filed; only the target counter is kept.

mod config;
mod crc32;
mod format;
mod index;
mod writer;

pub use config::{
    DEFAULT_MAX_FRAME_SIZE, FileStoreConfig, FileStoreConfigError, MAX_FRAME_SIZE_LIMIT,
    MAX_STORE_NAME_LEN, SyncPolicy,
};
pub use format::{Truncation, TruncationCause};

use crate::file::format::{
    DATA_START, DamageRule, Header, IndexEntry, MAX_BODY_OVERHEAD, SLOT_OFFSETS, Slot, SlotImages,
    io_error,
};
use crate::file::index::Index;
use crate::file::writer::{Served, Writer};
use crate::stored::StoredMessage;
use crate::traits::MessageStore;
use async_trait::async_trait;
use ironfix_core::error::StoreError;
use ironfix_core::message::MsgType;
use parking_lot::{Mutex as SyncMutex, RwLock};
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{BufReader, BufWriter, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::SystemTime;
use tokio::runtime::Handle;

/// Most frames a page read reserves room for up front.
const PAGE_CAPACITY_HINT: usize = 256;

/// Size of the buffer a replacement journal is written through, in bytes.
const REPLACEMENT_BUFFER: usize = 64 * 1024;

/// Size of the buffer a journal is read through when it is opened or
/// refreshed, in bytes (256 KiB).
const SCAN_BUFFER: usize = 256 * 1024;

/// Name of every store's writer thread.
const WRITER_THREAD_NAME: &str = "ironfix-store";

/// Most calls a store's queue holds, 1 024. A call made while it is full
/// fails without being queued; a timed-out call stays in it until the writer
/// thread skips it.
const CALL_QUEUE_CAPACITY: usize = 1024;

/// Most idle record buffers a store keeps for reuse.
const RECORD_BUFFERS: usize = 8;

/// Largest record buffer a store keeps for reuse, in bytes (64 KiB); a
/// larger one (a frame near the configured maximum) is freed after use.
const RECORD_BUFFER_CAP: usize = 64 * 1024;

/// Permission bits of every file a `FileStore` creates, on Unix: read and
/// write for the owner only. A journal holds complete outbound frames, an
/// outbound Logon's `Password` (554) included.
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

/// Permission bits of every directory a `FileStore` creates, on Unix: the
/// owner only.
#[cfg(unix)]
const DIRECTORY_MODE: u32 = 0o700;

/// Options that create a file readable and writable by its owner only, on
/// Unix; elsewhere the platform's default applies.
fn owner_only_file() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, FILE_MODE);
    options
}

/// A persistent [`MessageStore`] backed by one journal file.
///
/// See the [module documentation](self) for the layout, the atomicity of each
/// call, the durability of each [`SyncPolicy`], recovery, compaction and the
/// lock.
///
/// # Example
///
/// ```no_run
/// use ironfix_store::{FileStore, FileStoreConfig, MessageStore};
/// use std::sync::Arc;
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let config = FileStoreConfig::try_new("/var/lib/ironfix", "FIX.4.4-CLIENT-VENUE")?
///     .with_create_if_missing(true);
/// let store: Arc<dyn MessageStore> = Arc::new(FileStore::open(config).await?);
/// // Attach it with `Initiator::with_store` or `Acceptor::with_store`.
/// # let _ = store;
/// # Ok(())
/// # }
/// ```
pub struct FileStore {
    /// The writer thread that owns the journal and runs every call.
    writer: Writer<Journal>,
    /// The values the synchronous getters read.
    shared: Arc<Shared>,
    /// Record buffers, reused across calls.
    buffers: Arc<BufferPool>,
    /// The configuration the store was opened with.
    config: FileStoreConfig,
}

/// Values the synchronous trait getters read without going through the
/// writer thread.
///
/// Only the journal writes them, after the change they describe is in the
/// file.
#[derive(Debug)]
struct Shared {
    /// Next sender sequence number.
    next_sender: AtomicU64,
    /// Next target sequence number.
    next_target: AtomicU64,
    /// The owed-reset marker (ADR-0029).
    reset_owed: AtomicBool,
    /// The inbound application watermark (ADR-0030).
    app_watermark: AtomicU64,
    /// Creation time of the journal.
    creation_time: RwLock<SystemTime>,
    /// The last cut made since the store was opened, if any.
    truncation: SyncMutex<Option<Truncation>>,
}

impl Shared {
    /// A blank state, filled in when the journal is loaded.
    fn new() -> Self {
        Self {
            next_sender: AtomicU64::new(1),
            next_target: AtomicU64::new(1),
            reset_owed: AtomicBool::new(false),
            app_watermark: AtomicU64::new(0),
            creation_time: RwLock::new(SystemTime::UNIX_EPOCH),
            truncation: SyncMutex::new(None),
        }
    }

    /// Publishes the state of a freshly loaded or replaced journal.
    fn publish(&self, creation_time: SystemTime, next_sender: u64, next_target: u64) {
        self.next_sender.store(next_sender, Ordering::SeqCst);
        self.next_target.store(next_target, Ordering::SeqCst);
        *self.creation_time.write() = creation_time;
    }

    /// Publishes the state of a journal loaded from disk, and records the cut
    /// its recovery made. A clean load keeps the last cut on record.
    fn install(&self, scan: &format::Scan) {
        self.reset_owed.store(scan.reset_owed, Ordering::SeqCst);
        self.app_watermark
            .store(scan.app_watermark, Ordering::SeqCst);
        self.publish(
            scan.header.creation_time,
            scan.next_sender,
            scan.next_target,
        );
        if let Some(truncation) = scan.truncation {
            *self.truncation.lock() = Some(truncation);
        }
    }
}

/// Record buffers, reused so filing a frame allocates none once the store
/// has warmed up: a caller takes one to encode its record into, and the
/// writer thread gives it back once the record is written.
///
/// The lock is a `std::sync` mutex, as the writer's reply cells are: the
/// caller and the writer thread share it on every frame, and contention on it
/// must not allocate (see the `writer` module).
#[derive(Debug)]
struct BufferPool {
    /// The idle buffers, at most [`RECORD_BUFFERS`].
    buffers: std::sync::Mutex<Vec<Vec<u8>>>,
}

impl BufferPool {
    /// An empty pool.
    fn new() -> Self {
        Self {
            buffers: std::sync::Mutex::new(Vec::with_capacity(RECORD_BUFFERS)),
        }
    }

    /// An idle buffer, or a new empty one.
    fn take(&self) -> Vec<u8> {
        self.lock().pop().unwrap_or_default()
    }

    /// Keeps `buffer` for reuse, unless it is above [`RECORD_BUFFER_CAP`] or
    /// the pool is full.
    fn give(&self, mut buffer: Vec<u8>) {
        if buffer.capacity() > RECORD_BUFFER_CAP {
            return;
        }
        buffer.clear();
        let mut buffers = self.lock();
        if buffers.len() < buffers.capacity() {
            buffers.push(buffer);
        }
    }

    /// Locks the idle buffers, taking the lock over from a thread that
    /// panicked while holding it: the list stays a list of empty buffers at
    /// every point a panic could leave it.
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Vec<u8>>> {
        self.buffers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// What has to happen before a journal that failed mid-write can be used
/// again. While anything is pending the store refuses every call except a
/// reset and a refresh.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Pending {
    /// Cut the journal back to this offset and flush the cut.
    cut_back_to: Option<u64>,
    /// Write these images back into the counter slots and flush them.
    restore_slots: Option<SlotImages>,
    /// Flush the directory, to make a rename durable.
    directory_flush: bool,
    /// Reopen the journal from its path.
    reopen: bool,
}

impl Pending {
    /// Whether nothing is pending.
    const fn is_clear(&self) -> bool {
        self.cut_back_to.is_none()
            && self.restore_slots.is_none()
            && !self.directory_flush
            && !self.reopen
    }

    /// Records that the journal must be cut back to `offset`, keeping the
    /// earliest such offset.
    fn cut_back(&mut self, offset: u64) {
        self.cut_back_to = Some(self.cut_back_to.map_or(offset, |at| at.min(offset)));
    }
}

/// The steps of a compaction a test can stop it after, as a crash would.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompactionStep {
    /// The replacement is written, not flushed.
    Written,
    /// The replacement is flushed, not renamed.
    Flushed,
    /// The replacement is renamed into place; the directory is not flushed.
    Renamed,
}

/// A call, sent by value to the writer thread.
enum Command {
    /// `store`: append a frame record (from the record buffer pool).
    Store {
        /// The number the frame is filed under.
        seq: u64,
        /// The encoded, unsealed record.
        record: Vec<u8>,
    },
    /// `file_outbound`: append a frame and next sender record.
    FileOutbound {
        /// The number the frame is filed under.
        seq: u64,
        /// The encoded, unsealed record.
        record: Vec<u8>,
        /// The next sender number it carries.
        next_sender: u64,
    },
    /// `set_next_sender_seq`.
    SetNextSender(u64),
    /// `set_next_target_seq`.
    SetNextTarget(u64),
    /// `set_reset_owed`.
    SetResetOwed(bool),
    /// `set_app_watermark`.
    SetAppWatermark(u64),
    /// `reset_to` (and `reset`).
    ResetTo {
        /// The next sender number after the reset.
        next_sender: u64,
        /// The next target number after the reset.
        next_target: u64,
    },
    /// `get_page` and `get_range`: read at most `limit` frames in
    /// `begin..=end`.
    Read {
        /// The first number, inclusive.
        begin: u64,
        /// The last number, inclusive.
        end: u64,
        /// The most frames to read.
        limit: usize,
    },
    /// `refresh`.
    Refresh,
    /// `FileStore::sync`.
    Sync,
    /// `FileStore::compact`.
    Compact,
    /// `FileStore::close`: flush what is pending, then close.
    Close,
    /// Test-only: run a closure on the journal, without a stall.
    #[cfg(test)]
    Probe(ProbeOp),
}

/// Test-only: a closure a probe runs on the journal, and what it returns.
#[cfg(test)]
type ProbeOp = Box<dyn FnOnce(&mut Journal) -> Box<dyn std::any::Any + Send> + Send>;

/// What a call answers.
enum Answer {
    /// The call is done.
    Done,
    /// The frames a read found.
    Page(Vec<StoredMessage>),
    /// The bytes a compaction reclaimed.
    Reclaimed(u64),
    /// Test-only: what a probe returned.
    #[cfg(test)]
    Probe(Box<dyn std::any::Any + Send>),
}

/// The error for an answer of the wrong kind, which the writer never sends.
#[cold]
#[inline(never)]
fn unexpected_answer() -> StoreError {
    StoreError::Io("the file store's writer answered a call with the wrong kind".to_string())
}

/// The open journal: its file, the index of filed frames, the counters and
/// their slots, and the bookkeeping for the sync policy. Owned by the writer
/// thread.
#[derive(Debug)]
struct Journal {
    /// The configuration.
    config: FileStoreConfig,
    /// The journal file, open for reading and writing.
    file: File,
    /// The lock file, locked for as long as the journal is open.
    _lock: File,
    /// Every filed frame's record, by sequence number.
    index: Index,
    /// File offset just past the last record: where the next one goes.
    end: u64,
    /// File offset up to which the journal is known to be on stable storage:
    /// where it stood after its last successful flush (or when it was
    /// loaded).
    durable_end: u64,
    /// Writes made since the journal was last flushed, under
    /// [`SyncPolicy::EveryN`].
    unsynced: u32,
    /// What a failed write left to do before the journal is usable again.
    pending: Pending,
    /// The values the synchronous getters read.
    shared: Arc<Shared>,
    /// Record buffers, given back once their record is written.
    buffers: Arc<BufferPool>,
    /// Test-only fault injection and flush counting; empty outside tests.
    probe: Probe,
    /// When the journal was created; kept by a compaction.
    creation_time: SystemTime,
    /// Next sender sequence number.
    next_sender: u64,
    /// Next target sequence number.
    next_target: u64,
    /// The owed-reset marker every slot written carries (ADR-0029).
    reset_owed: bool,
    /// The inbound application watermark every slot written carries
    /// (ADR-0030).
    app_watermark: u64,
    /// The generation the next counter write takes.
    next_generation: u64,
    /// Both counter slots, as written.
    slots: SlotImages,
    /// The position of the slot holding the newest counters.
    active_slot: usize,
    /// The position of the slot holding the last checkpoint known to be on
    /// stable storage. Counter writes go to the other slot until the next
    /// successful flush, so it is never overwritten before its replacement
    /// is durable.
    durable_slot: usize,
    /// Both counter slots as the last successful flush left them.
    durable_slots: SlotImages,
    /// Bytes taken by records a later record for the same number replaced.
    dead_bytes: u64,
    /// The superseded bytes when an automatic compaction last failed: it is
    /// not tried again until another threshold's worth is superseded.
    failed_compaction_at: Option<u64>,
}

/// Test-only fault injection and flush counting. Outside tests it has no
/// fields and its methods do nothing.
#[derive(Debug, Default)]
struct Probe {
    /// Holds the next call on the writer thread for this long, before it does
    /// anything.
    #[cfg(test)]
    stall: Option<std::time::Duration>,
    /// Makes the next journal flush fail.
    #[cfg(test)]
    fail_next_flush: bool,
    /// Makes the next directory flush after a rename fail.
    #[cfg(test)]
    fail_next_dir_flush: bool,
    /// Makes the next load of the journal from disk fail.
    #[cfg(test)]
    fail_next_load: bool,
    /// Stops the next compaction after this step, leaving the files as a
    /// crash there would.
    #[cfg(test)]
    crash_compaction_after: Option<CompactionStep>,
    /// Journal and replacement-file flushes made.
    #[cfg(test)]
    file_flushes: u64,
    /// Directory flushes made.
    #[cfg(test)]
    dir_flushes: u64,
    /// Writes made to each counter slot, by position.
    #[cfg(test)]
    slot_writes: [u64; 2],
}

impl Probe {
    /// Holds the writer thread if a test asked for it.
    #[allow(clippy::unused_self)]
    fn stall(&mut self) {
        #[cfg(test)]
        if let Some(stall) = self.stall.take() {
            std::thread::sleep(stall);
        }
    }

    /// Counts a journal flush, and reports whether a test injected its
    /// failure.
    #[allow(clippy::unused_self)]
    fn journal_flush(&mut self) -> bool {
        self.file_flush();
        #[cfg(test)]
        {
            std::mem::take(&mut self.fail_next_flush)
        }
        #[cfg(not(test))]
        false
    }

    /// Counts a file flush.
    #[allow(clippy::unused_self)]
    fn file_flush(&mut self) {
        #[cfg(test)]
        {
            self.file_flushes += 1;
        }
    }

    /// Reports whether a test injected the failure of the next directory
    /// flush after a rename.
    #[allow(clippy::unused_self)]
    fn dir_flush_fails(&mut self) -> bool {
        #[cfg(test)]
        {
            std::mem::take(&mut self.fail_next_dir_flush)
        }
        #[cfg(not(test))]
        false
    }

    /// Reports whether a test injected the failure of the next load.
    #[allow(clippy::unused_self)]
    fn load_fails(&mut self) -> bool {
        #[cfg(test)]
        {
            std::mem::take(&mut self.fail_next_load)
        }
        #[cfg(not(test))]
        false
    }

    /// Counts a write to the counter slot at `position`.
    #[allow(clippy::unused_self)]
    fn slot_write(&mut self, position: usize) {
        #[cfg(test)]
        if let Some(count) = self.slot_writes.get_mut(position) {
            *count += 1;
        }
        let _ = position;
    }

    /// Counts a directory flush.
    #[allow(clippy::unused_self)]
    fn dir_flush(&mut self) {
        #[cfg(test)]
        {
            self.dir_flushes += 1;
        }
    }

    /// Reports whether a test asked the compaction to stop after `step`.
    #[allow(clippy::unused_self)]
    fn crashes_after(&mut self, step: CompactionStep) -> bool {
        #[cfg(test)]
        if self.crash_compaction_after == Some(step) {
            self.crash_compaction_after = None;
            return true;
        }
        let _ = step;
        false
    }
}

/// The error a compaction stopped by a test returns.
#[cold]
#[inline(never)]
fn compaction_stopped() -> StoreError {
    StoreError::Io("compaction stopped as a crash would stop it".to_string())
}

/// The error for a generation sequence that cannot go on.
#[cold]
#[inline(never)]
fn generations_exhausted() -> StoreError {
    StoreError::Io("the journal's generation sequence is exhausted; reset the store".to_string())
}

/// The file offset of the counter slot at `position` (0 or 1).
fn slot_offset(position: usize) -> Result<u64, StoreError> {
    SLOT_OFFSETS
        .get(position)
        .copied()
        .ok_or_else(|| StoreError::Io(format!("there is no counter slot {position}")))
}

impl Journal {
    /// A journal over a loaded file. `flushed` says whether the file was
    /// flushed once loaded: if it was, all of it is durable; if not (under
    /// [`SyncPolicy::Never`]), only what its newest slot vouches for.
    fn new(
        config: FileStoreConfig,
        lock: File,
        loaded: Loaded,
        flushed: bool,
        shared: Arc<Shared>,
        buffers: Arc<BufferPool>,
        probe: Probe,
    ) -> Self {
        let Loaded { file, scan } = loaded;
        shared.install(&scan);
        let durable_end = if flushed { scan.end } else { scan.boundary };
        Self {
            config,
            file,
            _lock: lock,
            index: scan.index,
            end: scan.end,
            durable_end,
            unsynced: 0,
            pending: Pending::default(),
            shared,
            buffers,
            probe,
            creation_time: scan.header.creation_time,
            next_sender: scan.next_sender,
            next_target: scan.next_target,
            reset_owed: scan.reset_owed,
            app_watermark: scan.app_watermark,
            next_generation: scan.next_generation,
            slots: scan.slots,
            active_slot: scan.active,
            durable_slot: scan.active,
            durable_slots: scan.slots,
            dead_bytes: scan.dead_bytes,
            failed_compaction_at: None,
        }
    }

    /// Fails if a failed write left something pending.
    fn usable(&self) -> Result<(), StoreError> {
        if self.pending.is_clear() {
            return Ok(());
        }
        Err(StoreError::Io(
            "the journal is not usable after a failed write; refresh the store (or reset it) \
             before using it again"
                .to_string(),
        ))
    }

    /// Takes the next generation.
    fn take_generation(&mut self) -> Result<u64, StoreError> {
        let generation = self.next_generation;
        self.next_generation = generation
            .checked_add(1)
            .ok_or_else(generations_exhausted)?;
        Ok(generation)
    }

    /// Appends one encoded record and flushes it as the policy requires.
    /// Returns the record's offset.
    ///
    /// A failed write is undone by cutting the file back to where the record
    /// started; if that fails, the cut is left pending. A failed flush cuts
    /// the journal back to its last successful flush (see [`Journal::flush`]).
    fn append(&mut self, record: &[u8]) -> Result<u64, StoreError> {
        let offset = self.end;
        let new_end = u64::try_from(record.len())
            .ok()
            .and_then(|len| offset.checked_add(len))
            .ok_or_else(|| StoreError::Io("journal offset overflows".to_string()))?;
        if let Err(err) = write_at(&mut self.file, record, offset) {
            if self.file.set_len(offset).is_err() {
                self.pending.cut_back(offset);
            }
            return Err(io_error("cannot append to the journal", &err));
        }
        self.end = new_end;
        self.after_write()?;
        Ok(offset)
    }

    /// Seals and appends a frame record from
    /// [`format::encode_frame_record_into`], indexes it under `seq`, and
    /// publishes `next_sender` if it carries one. The record buffer goes back
    /// to the pool whatever happens.
    fn append_frame(
        &mut self,
        seq: u64,
        mut record: Vec<u8>,
        next_sender: Option<u64>,
    ) -> Result<(), StoreError> {
        let appended = self.seal_and_append(&mut record);
        let body_len = format::record_body_len(&record);
        self.buffers.give(record);
        let offset = appended?;
        if let Some(replaced) = self.index.insert(seq, IndexEntry { offset, body_len })
            && let Some(dead) = self.dead_bytes.checked_add(replaced.record_len())
        {
            self.dead_bytes = dead;
        }
        if let Some(next_sender) = next_sender {
            self.next_sender = next_sender;
            self.shared.next_sender.store(next_sender, Ordering::SeqCst);
        }
        Ok(())
    }

    /// Takes a generation for a record that carries a counter, seals the
    /// record, and appends it. Returns its offset.
    fn seal_and_append(&mut self, record: &mut [u8]) -> Result<u64, StoreError> {
        let generation = if format::takes_generation(record) {
            self.take_generation()?
        } else {
            0
        };
        format::seal_frame_record(record, generation);
        self.append(record)
    }

    /// Writes both counters into the slot that does not hold the last
    /// durable checkpoint, with the next generation and the current durable
    /// boundary, flushes as the policy requires, and publishes them.
    ///
    /// Until a flush succeeds every counter write goes to that same slot, so
    /// the durable checkpoint is never overwritten before its replacement is
    /// durable (see the `format` module, "Slot rotation"). The boundary is the
    /// offset up to which the records are known to be on stable storage: what
    /// the slot vouches for once it is itself durable.
    ///
    /// A failed write puts the slot back as it was; if that fails too, the
    /// restore is left pending. A failed flush is handled by
    /// [`Journal::flush`].
    fn write_counters(&mut self, next_sender: u64, next_target: u64) -> Result<(), StoreError> {
        let generation = self.take_generation()?;
        let target = usize::from(self.durable_slot == 0);
        let offset = slot_offset(target)?;
        let image = format::encode_slot(&Slot {
            generation,
            next_sender,
            next_target,
            durable_end: self.durable_end,
            app_watermark: self.app_watermark,
            reset_owed: self.reset_owed,
        });
        if let Err(err) = write_at(&mut self.file, &image, offset) {
            let restored = self
                .slots
                .get(target)
                .is_some_and(|previous| write_at(&mut self.file, previous, offset).is_ok());
            if !restored {
                self.pending.restore_slots = Some(self.slots);
            }
            return Err(io_error("cannot write a counter slot", &err));
        }
        self.probe.slot_write(target);
        if let Some(slot) = self.slots.get_mut(target) {
            *slot = image;
        }
        self.active_slot = target;
        self.after_write()?;
        self.next_sender = next_sender;
        self.next_target = next_target;
        self.shared.next_sender.store(next_sender, Ordering::SeqCst);
        self.shared.next_target.store(next_target, Ordering::SeqCst);
        Ok(())
    }

    /// Sets or clears the owed-reset marker (ADR-0029): writes it into
    /// **both** counter slots, with the current counters, each write flushed
    /// before the next whatever the sync policy, and publishes it.
    ///
    /// Two slots, so that once the marker is set a slot torn or damaged
    /// afterwards still leaves the other one carrying it; both failing their
    /// check refuses the journal. A journal left unusable by a failed write
    /// is refreshed first (see [`Journal::reload`]), since the marker is
    /// typically set right after such a failure. Nothing is written when both
    /// slots already carry `owed`.
    ///
    /// A failure leaves the marker set in memory if it was set before or was
    /// being set: after a failure the slots may carry either value, and
    /// reporting a reset owed that is not is the safe direction.
    fn set_reset_owed(&mut self, owed: bool) -> Result<(), StoreError> {
        if !self.pending.is_clear() {
            self.reload()?;
        }
        let carried = self
            .slots
            .iter()
            .all(|image| format::decode_slot(image).is_some_and(|slot| slot.reset_owed == owed));
        if carried && self.reset_owed == owed {
            self.shared.reset_owed.store(owed, Ordering::SeqCst);
            return Ok(());
        }
        let previous = self.reset_owed;
        self.reset_owed = owed;
        for _ in 0..2 {
            let written = self
                .write_counters(self.next_sender, self.next_target)
                .and_then(|()| {
                    // `write_counters` flushed already if the policy flushes
                    // every write; otherwise the slot is flushed here.
                    if self.durable_slot == self.active_slot {
                        Ok(())
                    } else {
                        self.flush()
                    }
                });
            if let Err(err) = written {
                self.reset_owed = previous || owed;
                self.shared
                    .reset_owed
                    .store(self.reset_owed, Ordering::SeqCst);
                return Err(err);
            }
        }
        self.shared.reset_owed.store(owed, Ordering::SeqCst);
        Ok(())
    }

    /// Writes the inbound application watermark (ADR-0030) like a counter:
    /// into the slot the next counter write goes to, flushed as the sync
    /// policy requires, and publishes it. Nothing is written when the value
    /// is already the one carried.
    ///
    /// A failed write leaves the previous value in memory: the slots may
    /// carry either, and a lower watermark reports more as possibly lost,
    /// which is the safe direction.
    fn set_app_watermark(&mut self, watermark: u64) -> Result<(), StoreError> {
        self.usable()?;
        if self.app_watermark == watermark {
            return Ok(());
        }
        let previous = self.app_watermark;
        self.app_watermark = watermark;
        if let Err(err) = self.write_counters(self.next_sender, self.next_target) {
            self.app_watermark = previous;
            return Err(err);
        }
        self.shared.app_watermark.store(watermark, Ordering::SeqCst);
        Ok(())
    }

    /// Flushes as the sync policy requires after a write.
    fn after_write(&mut self) -> Result<(), StoreError> {
        match self.config.sync_policy() {
            SyncPolicy::EveryWrite => self.flush(),
            SyncPolicy::EveryN(every) => {
                self.unsynced = self
                    .unsynced
                    .checked_add(1)
                    .ok_or_else(|| StoreError::Io("unflushed write count overflows".to_string()))?;
                if self.unsynced >= every.get() {
                    self.flush()
                } else {
                    Ok(())
                }
            }
            SyncPolicy::Never => Ok(()),
        }
    }

    /// Flushes the journal file's data to stable storage.
    ///
    /// After a failed flush the operating system may have dropped data it had
    /// accepted from earlier writes, and a later flush can report success
    /// without bringing it back. The journal is therefore cut back to where
    /// its last successful flush left it, the counter slots are put back as
    /// that flush left them, and both are left pending until a refresh has
    /// made them durable: everything written since that flush is treated as
    /// not filed.
    fn flush(&mut self) -> Result<(), StoreError> {
        let flushed = if self.probe.journal_flush() {
            Err(std::io::Error::other("injected flush failure"))
        } else {
            self.file.sync_data()
        };
        match flushed {
            Ok(()) => {
                self.durable_end = self.end;
                self.durable_slots = self.slots;
                // The newest slot is now on stable storage: the next counter
                // writes go to the other one.
                self.durable_slot = self.active_slot;
                self.unsynced = 0;
                Ok(())
            }
            Err(err) => {
                let _ = self.file.set_len(self.durable_end);
                self.pending.cut_back(self.durable_end);
                if self.slots != self.durable_slots {
                    // Only the slot written since the last flush differs; the
                    // one holding the durable checkpoint is never written.
                    for (position, ((current, durable), offset)) in self
                        .slots
                        .iter()
                        .zip(&self.durable_slots)
                        .zip(SLOT_OFFSETS)
                        .enumerate()
                    {
                        if current != durable {
                            self.probe.slot_write(position);
                            let _ = write_at(&mut self.file, durable, offset);
                        }
                    }
                    self.pending.restore_slots = Some(self.durable_slots);
                    self.slots = self.durable_slots;
                    if let Ok((active, _)) = format::newest_slot(&self.slots) {
                        self.active_slot = active;
                        self.durable_slot = active;
                    }
                }
                Err(io_error(
                    "cannot flush the journal; the writes since its last flush are cut",
                    &err,
                ))
            }
        }
    }

    /// Reads at most `limit` filed frames in `begin..=end`, in ascending
    /// order.
    fn read(
        &mut self,
        begin: u64,
        end: u64,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        let mut messages = Vec::with_capacity(limit.min(PAGE_CAPACITY_HINT));
        for (seq, entry) in self.index.range(begin, end).take(limit) {
            messages.push(format::read_frame(&mut self.file, seq, entry)?);
        }
        Ok(messages)
    }

    /// Replaces the journal with an empty one starting from the given
    /// counters: a new file, flushed, renamed into place, and the directory
    /// flushed. Runs on a journal left unusable by a failed write too, and a
    /// success clears what was pending: the replaced journal no longer
    /// matters.
    fn replace(&mut self, next_sender: u64, next_target: u64) -> Result<(), StoreError> {
        let header = Header {
            creation_time: SystemTime::now(),
            next_sender,
            next_target,
        };
        let (slots, next_generation) =
            format::fresh_slots(0, next_sender, next_target, DATA_START, 0, self.reset_owed)?;
        write_replacement(&self.config, &header, &slots, &mut self.probe)?;
        // The rename is the commit point: past it, the journal on disk is the
        // new one whether or not what follows works.
        self.pending = Pending::default();
        self.index = Index::new();
        self.end = DATA_START;
        self.durable_end = DATA_START;
        self.unsynced = 0;
        self.creation_time = header.creation_time;
        self.next_sender = next_sender;
        self.next_target = next_target;
        self.next_generation = next_generation;
        // A reset clears the inbound application watermark (ADR-0030): it
        // described the replaced stream.
        self.app_watermark = 0;
        self.install_slots(slots);
        self.dead_bytes = 0;
        self.failed_compaction_at = None;
        self.shared.app_watermark.store(0, Ordering::SeqCst);
        self.shared
            .publish(header.creation_time, next_sender, next_target);
        self.after_rename()
    }

    /// Takes freshly written and flushed counter slots, the second one the
    /// newest, as both the current and the durable ones.
    const fn install_slots(&mut self, slots: SlotImages) {
        self.slots = slots;
        self.durable_slots = slots;
        self.active_slot = 1;
        self.durable_slot = 1;
    }

    /// Completes a rename that replaced the journal: flushes the directory
    /// and reopens the journal file. A failure leaves the step pending.
    fn after_rename(&mut self) -> Result<(), StoreError> {
        let dir_flushed = if self.probe.dir_flush_fails() {
            Err(StoreError::Io(
                "injected directory flush failure".to_string(),
            ))
        } else {
            flush_directory(self.config.directory())
        };
        match open_journal_file(&self.config) {
            Ok(file) => self.file = file,
            Err(err) => {
                self.pending.reopen = true;
                self.pending.directory_flush = dir_flushed.is_err();
                return Err(err);
            }
        }
        match dir_flushed {
            Ok(()) => {
                self.probe.dir_flush();
                Ok(())
            }
            Err(err) => {
                self.pending.directory_flush = true;
                Err(err)
            }
        }
    }

    /// Rewrites the journal with only its live records, through a temporary
    /// file and a rename, and returns how many bytes it shrank by.
    ///
    /// Each live record is read back into one reused buffer, checked, and
    /// copied as it is, in ascending sequence order; the counters go into two
    /// fresh slots with generations above every record's. The creation time
    /// is kept. A failure before the rename changes nothing (the temporary
    /// file is removed); after it, the journal is the compacted one, and what
    /// is left to do (the directory flush, reopening the file) is left
    /// pending.
    fn compact(&mut self) -> Result<u64, StoreError> {
        self.usable()?;
        let before = self.end;
        let header = Header {
            creation_time: self.creation_time,
            next_sender: self.next_sender,
            next_target: self.next_target,
        };
        // The compacted journal's end, known before it is written: its slots
        // vouch for every record in it, all flushed before the rename.
        let live = self
            .index
            .iter()
            .try_fold(0u64, |total, (_, entry)| {
                total.checked_add(entry.record_len())
            })
            .and_then(|live| live.checked_add(DATA_START))
            .ok_or_else(|| StoreError::Io("compacted journal length overflows".to_string()))?;
        let (slots, next_generation) = format::fresh_slots(
            self.next_generation,
            self.next_sender,
            self.next_target,
            live,
            self.app_watermark,
            self.reset_owed,
        )?;
        let mut replacement = Replacement::create(&self.config, &header, &slots)?;
        let mut index = Index::new();
        let mut record = Vec::new();
        for (seq, entry) in self.index.iter() {
            format::read_record_into(&mut self.file, seq, entry, &mut record)?;
            let offset = replacement.append(&record)?;
            index.insert(
                seq,
                IndexEntry {
                    offset,
                    body_len: entry.body_len,
                },
            );
        }
        if self.probe.crashes_after(CompactionStep::Written) {
            replacement.abandon();
            self.pending.reopen = true;
            return Err(compaction_stopped());
        }
        replacement.finish(&mut self.probe)?;
        if self.probe.crashes_after(CompactionStep::Flushed) {
            replacement.abandon();
            self.pending.reopen = true;
            return Err(compaction_stopped());
        }
        if replacement.end != live {
            return Err(StoreError::Io(format!(
                "compaction wrote {} bytes where its counter slots vouch for {live}; the journal \
                 is unchanged",
                replacement.end
            )));
        }
        let end = replacement.rename_into_place(&self.config)?;
        if self.probe.crashes_after(CompactionStep::Renamed) {
            self.pending.reopen = true;
            return Err(compaction_stopped());
        }
        // Committed: the journal on disk is the compacted one, all of it
        // flushed.
        self.index = index;
        self.end = end;
        self.durable_end = end;
        self.unsynced = 0;
        self.next_generation = next_generation;
        self.install_slots(slots);
        self.dead_bytes = 0;
        self.failed_compaction_at = None;
        self.after_rename()?;
        // A size, not a sequence number: a compaction never grows the
        // journal, and a report of 0 is the right answer if it did.
        Ok(before.saturating_sub(end))
    }

    /// Whether the superseded records call for an automatic compaction: one
    /// is configured, and they take at least its threshold and at least as
    /// many bytes as the live records.
    fn compaction_due(&self) -> bool {
        let Some(threshold) = self.config.compaction_threshold() else {
            return false;
        };
        if !self.pending.is_clear() || self.dead_bytes < threshold.get() {
            return false;
        }
        if let Some(failed_at) = self.failed_compaction_at
            && !self
                .dead_bytes
                .checked_sub(failed_at)
                .is_some_and(|grown| grown >= threshold.get())
        {
            return false;
        }
        let live = self
            .end
            .checked_sub(DATA_START)
            .and_then(|records| records.checked_sub(self.dead_bytes))
            .unwrap_or_default();
        self.dead_bytes >= live
    }

    /// Completes what a failed write left pending, then rereads the journal
    /// from disk, cutting what recovery allows, and flushes it unless the
    /// policy is [`SyncPolicy::Never`].
    ///
    /// The undo of a failed write (the cut back, the slots put back) stays
    /// pending until the reload succeeds: if reading the journal fails after
    /// the undo, the in-memory state still describes the file before it, so
    /// the store keeps refusing calls rather than append past the real end of
    /// the file.
    ///
    /// The flush goes through [`Journal::flush`]: if it fails, the journal is
    /// cut back to its last successful flush and the cut left pending, as for
    /// any failed flush, so writes left unflushed under
    /// [`SyncPolicy::EveryN`] are never adopted by a later refresh. A failure
    /// to read or scan the journal while nothing was pending leaves the store
    /// as it was.
    fn reload(&mut self) -> Result<(), StoreError> {
        if self.pending.directory_flush {
            flush_directory(self.config.directory())?;
            self.probe.dir_flush();
            self.pending.directory_flush = false;
        }
        if self.pending.cut_back_to.is_some() || self.pending.restore_slots.is_some() {
            undo_on_disk(
                &self.config,
                self.pending.cut_back_to,
                self.pending.restore_slots.as_ref(),
                &mut self.probe,
            )?;
            self.probe.file_flush();
            if let Some(offset) = self.pending.cut_back_to {
                self.durable_end = self.durable_end.min(offset);
            }
            if let Some(slots) = self.pending.restore_slots {
                self.durable_slots = slots;
            }
        }
        let rule = self.config.sync_policy().damage_rule();
        let Loaded { file, scan } = load(&self.config, rule, &mut self.probe)?;
        let (durable_end, durable_slots) = (self.durable_end, self.durable_slots);
        self.shared.install(&scan);
        self.file = file;
        self.index = scan.index;
        self.end = scan.end;
        self.unsynced = 0;
        self.pending = Pending::default();
        self.creation_time = scan.header.creation_time;
        self.next_sender = scan.next_sender;
        self.next_target = scan.next_target;
        self.reset_owed = scan.reset_owed;
        self.app_watermark = scan.app_watermark;
        self.next_generation = self.next_generation.max(scan.next_generation);
        self.slots = scan.slots;
        self.active_slot = scan.active;
        self.durable_slot = scan.active;
        self.dead_bytes = scan.dead_bytes;
        self.failed_compaction_at = None;
        if !self.config.sync_policy().flushes() {
            // A policy that never flushes knows the journal durable only as
            // far as its newest slot vouches for: what this reload read past
            // that may still be only in the page cache, and a counter slot
            // written next must not vouch for it.
            self.durable_end = scan.boundary;
            self.durable_slots = scan.slots;
            return Ok(());
        }
        // Only what was flushed before stays known durable until this flush
        // succeeds.
        self.durable_end = durable_end.min(scan.end);
        self.durable_slots = durable_slots;
        self.flush()
    }

    /// Runs a call (see [`Served::execute`]).
    fn run(&mut self, command: Command) -> Result<Answer, StoreError> {
        let stalls = !command.is_probe();
        if stalls {
            self.probe.stall();
        }
        match command {
            Command::Store { seq, record } => {
                if let Err(err) = self.usable() {
                    self.buffers.give(record);
                    return Err(err);
                }
                self.append_frame(seq, record, None)?;
                Ok(Answer::Done)
            }
            Command::FileOutbound {
                seq,
                record,
                next_sender,
            } => {
                if let Err(err) = self.usable() {
                    self.buffers.give(record);
                    return Err(err);
                }
                self.append_frame(seq, record, Some(next_sender))?;
                Ok(Answer::Done)
            }
            Command::SetNextSender(next_sender) => {
                self.usable()?;
                self.write_counters(next_sender, self.next_target)?;
                Ok(Answer::Done)
            }
            Command::SetNextTarget(next_target) => {
                self.usable()?;
                self.write_counters(self.next_sender, next_target)?;
                Ok(Answer::Done)
            }
            Command::SetResetOwed(owed) => {
                self.set_reset_owed(owed)?;
                Ok(Answer::Done)
            }
            Command::SetAppWatermark(watermark) => {
                self.set_app_watermark(watermark)?;
                Ok(Answer::Done)
            }
            Command::ResetTo {
                next_sender,
                next_target,
            } => {
                self.replace(next_sender, next_target)?;
                Ok(Answer::Done)
            }
            Command::Read { begin, end, limit } => {
                self.usable()?;
                self.read(begin, end, limit).map(Answer::Page)
            }
            Command::Refresh => {
                self.reload()?;
                Ok(Answer::Done)
            }
            Command::Sync => {
                self.usable()?;
                self.flush()?;
                Ok(Answer::Done)
            }
            Command::Compact => self.compact().map(Answer::Reclaimed),
            Command::Close => {
                if self.unsynced > 0 && self.pending.is_clear() {
                    self.flush()?;
                }
                Ok(Answer::Done)
            }
            #[cfg(test)]
            Command::Probe(op) => Ok(Answer::Probe(op(self))),
        }
    }
}

impl Command {
    /// Whether this is a test probe, which a stall set by a test skips.
    #[allow(clippy::unused_self)]
    const fn is_probe(&self) -> bool {
        #[cfg(test)]
        if matches!(self, Self::Probe(_)) {
            return true;
        }
        false
    }
}

impl Served for Journal {
    type Command = Command;
    type Answer = Answer;
    type Recycler = BufferPool;

    fn execute(&mut self, command: Command) -> Result<Answer, StoreError> {
        self.run(command)
    }

    fn closes(command: &Command) -> bool {
        matches!(command, Command::Close)
    }

    /// Gives a record buffer back to the pool: a `store` or `file_outbound`
    /// that was skipped, refused by a full queue, or reached a closed store.
    fn discard(buffers: &BufferPool, command: Command) {
        match command {
            Command::Store { record, .. } | Command::FileOutbound { record, .. } => {
                buffers.give(record);
            }
            _ => {}
        }
    }

    fn after_call_due(&self) -> bool {
        self.compaction_due()
    }

    /// Compacts the journal. A failure before the commit point changes
    /// nothing and reaches no caller (the crate cannot log); it is not
    /// retried until another threshold's worth of records is superseded. One
    /// after it leaves the store refusing calls until a refresh, like a
    /// failed reset.
    fn after_call(&mut self) {
        if self.compact().is_err() {
            self.failed_compaction_at = Some(self.dead_bytes);
        }
    }
}

/// Writes all of `record` at `offset`.
#[cfg(unix)]
fn write_at(file: &mut File, record: &[u8], offset: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(file, record, offset)
}

/// Writes all of `record` at `offset`.
#[cfg(not(unix))]
fn write_at(file: &mut File, record: &[u8], offset: u64) -> std::io::Result<()> {
    use std::io::SeekFrom;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(record)
}

/// The largest record body `config` allows, in bytes.
fn max_body(config: &FileStoreConfig) -> u64 {
    u64::from(config.max_frame_size().get()) + MAX_BODY_OVERHEAD
}

/// A journal file read from disk, with what it holds.
struct Loaded {
    /// The journal file, open for reading and writing.
    file: File,
    /// What it holds.
    scan: format::Scan,
}

/// Opens the journal file for reading and writing.
fn open_journal_file(config: &FileStoreConfig) -> Result<File, StoreError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(config.journal_path())
        .map_err(|err| {
            io_error(
                &format!("cannot open {}", config.journal_path().display()),
                &err,
            )
        })
}

/// Reads the journal from disk, through a [`SCAN_BUFFER`] buffer, and cuts
/// what `rule` allows. Does not flush: the caller does, opening a store
/// directly and refreshing one through [`Journal::flush`].
fn load(
    config: &FileStoreConfig,
    rule: DamageRule,
    probe: &mut Probe,
) -> Result<Loaded, StoreError> {
    if probe.load_fails() {
        return Err(StoreError::Io("injected load failure".to_string()));
    }
    let mut file = open_journal_file(config)?;
    let len = file
        .metadata()
        .map_err(|err| io_error("cannot read the journal's length", &err))?
        .len();
    file.rewind()
        .map_err(|err| io_error("cannot read the journal", &err))?;
    let scan = format::scan(
        BufReader::with_capacity(SCAN_BUFFER, &mut file),
        len,
        max_body(config),
        rule,
    )?;
    let mut scan = scan;
    if let Some(truncation) = scan.truncation {
        file.set_len(truncation.offset())
            .map_err(|err| io_error("cannot cut the journal", &err))?;
    }
    if scan.slots_stale {
        restamp_slots(&mut file, &mut scan, probe)?;
    }
    Ok(Loaded { file, scan })
}

/// Writes a new counter slot, for a journal a `Never` or repair scan cut
/// below the durable boundary of its newest slot: the same counters, a
/// generation above every one in the journal, and the cut journal's end as
/// its boundary. Without it the slots would claim records the journal no
/// longer holds, and a later open would refuse it.
///
/// One slot is enough, and only one is written: loading reads the boundary of
/// the newest valid slot only. It goes into the position that does **not**
/// hold the newest slot, which is left as it is, so the rewrite is
/// crash-safe: a write torn by a crash leaves the newest slot, and the
/// journal as the scan found it, for the next repair or `Never` open to cut
/// and restamp again (a tail rule refuses it meanwhile). The next counter
/// write goes over the old newest slot, by the rotation rule. The new
/// boundary is the truth: everything below the cut was below the old
/// boundary, which vouched for it. The caller flushes (a repair always does;
/// `Never` does not).
fn restamp_slots(
    file: &mut File,
    scan: &mut format::Scan,
    probe: &mut Probe,
) -> Result<(), StoreError> {
    let position = usize::from(scan.active == 0);
    let generation = scan.next_generation;
    let image = format::encode_slot(&Slot {
        generation,
        next_sender: scan.next_sender,
        next_target: scan.next_target,
        durable_end: scan.end,
        app_watermark: scan.app_watermark,
        reset_owed: scan.reset_owed,
    });
    write_at(file, &image, slot_offset(position)?)
        .map_err(|err| io_error("cannot write the journal's counter slot", &err))?;
    probe.slot_write(position);
    if let Some(slot) = scan.slots.get_mut(position) {
        *slot = image;
    }
    scan.active = position;
    scan.next_generation = generation
        .checked_add(1)
        .ok_or_else(generations_exhausted)?;
    scan.boundary = scan.end;
    scan.slots_stale = false;
    Ok(())
}

/// Completes the undo a failed write or flush left pending: cuts the journal
/// back to `offset`, if it is longer, puts back each counter slot whose bytes
/// on disk differ from `slots`, and flushes. The slot holding the durable
/// checkpoint already matches, and is not written.
fn undo_on_disk(
    config: &FileStoreConfig,
    offset: Option<u64>,
    slots: Option<&SlotImages>,
    probe: &mut Probe,
) -> Result<(), StoreError> {
    let mut file = open_journal_file(config)?;
    if let Some(offset) = offset {
        let len = file
            .metadata()
            .map_err(|err| io_error("cannot read the journal's length", &err))?
            .len();
        if len > offset {
            file.set_len(offset)
                .map_err(|err| io_error("cannot cut the journal back", &err))?;
        }
    }
    if let Some(slots) = slots {
        for (position, (image, at)) in slots.iter().zip(SLOT_OFFSETS).enumerate() {
            let mut on_disk = [0u8; format::SLOT_LEN];
            let matches = format::ReadAt::read_record_at(&mut file, &mut on_disk, at).is_ok()
                && on_disk == *image;
            if !matches {
                probe.slot_write(position);
                write_at(&mut file, image, at)
                    .map_err(|err| io_error("cannot put a counter slot back", &err))?;
            }
        }
    }
    file.sync_data()
        .map_err(|err| io_error("cannot flush the journal's undo", &err))
}

/// A replacement journal being written to the temporary path. Dropped before
/// it is renamed into place, it removes the temporary file.
struct Replacement {
    /// The temporary file, buffered; `None` once closed.
    out: Option<BufWriter<File>>,
    /// The temporary path.
    temp: PathBuf,
    /// Bytes written so far: the offset of the next record.
    end: u64,
    /// Whether dropping the replacement removes the temporary file.
    remove_on_drop: bool,
}

impl Replacement {
    /// Creates the temporary file (a new one, owner-only, whatever a leftover
    /// had) and writes the prefix: `header` and `slots`.
    fn create(
        config: &FileStoreConfig,
        header: &Header,
        slots: &SlotImages,
    ) -> Result<Self, StoreError> {
        let temp = config.temp_path();
        // Always a new file, so it takes the owner-only mode rather than
        // whatever a leftover one had; renamed into place, it becomes the
        // journal, so a replacement never loosens the journal's permissions.
        match std::fs::remove_file(&temp) {
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
                return Err(io_error("cannot write the new journal", &err));
            }
            _ => {}
        }
        let file = owner_only_file()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|err| io_error("cannot write the new journal", &err))?;
        let mut replacement = Self {
            out: Some(BufWriter::with_capacity(REPLACEMENT_BUFFER, file)),
            temp,
            end: 0,
            remove_on_drop: true,
        };
        replacement.append(&format::encode_prefix(header, slots))?;
        Ok(replacement)
    }

    /// Appends `bytes`, returning the offset they start at.
    fn append(&mut self, bytes: &[u8]) -> Result<u64, StoreError> {
        let offset = self.end;
        self.end = u64::try_from(bytes.len())
            .ok()
            .and_then(|len| offset.checked_add(len))
            .ok_or_else(|| StoreError::Io("new journal offset overflows".to_string()))?;
        self.out
            .as_mut()
            .ok_or_else(|| StoreError::Io("the new journal is already closed".to_string()))?
            .write_all(bytes)
            .map_err(|err| io_error("cannot write the new journal", &err))?;
        Ok(offset)
    }

    /// Writes out the buffer and flushes the temporary file to stable
    /// storage, then closes it.
    fn finish(&mut self, probe: &mut Probe) -> Result<(), StoreError> {
        let mut out = self
            .out
            .take()
            .ok_or_else(|| StoreError::Io("the new journal is already closed".to_string()))?;
        out.flush()
            .and_then(|()| out.get_ref().sync_all())
            .map_err(|err| io_error("cannot write the new journal", &err))?;
        probe.file_flush();
        Ok(())
    }

    /// Renames the finished temporary file over the journal: the commit
    /// point. Returns the new journal's length. The caller flushes the
    /// directory.
    fn rename_into_place(mut self, config: &FileStoreConfig) -> Result<u64, StoreError> {
        drop(self.out.take());
        std::fs::rename(&self.temp, config.journal_path())
            .map_err(|err| io_error("cannot rename the new journal into place", &err))?;
        self.remove_on_drop = false;
        Ok(self.end)
    }

    /// Leaves the temporary file as it is, as a crash would: written out but
    /// not removed.
    fn abandon(mut self) {
        if let Some(mut out) = self.out.take() {
            let _ = out.flush();
        }
        self.remove_on_drop = false;
    }
}

impl Drop for Replacement {
    fn drop(&mut self) {
        drop(self.out.take());
        if self.remove_on_drop {
            let _ = std::fs::remove_file(&self.temp);
        }
    }
}

/// Writes a journal holding only `header` and `slots` to the temporary path,
/// flushes it, and renames it over the journal. The caller flushes the
/// directory.
///
/// # Errors
/// [`StoreError::Io`] if any step fails; nothing has then changed on disk.
fn write_replacement(
    config: &FileStoreConfig,
    header: &Header,
    slots: &SlotImages,
    probe: &mut Probe,
) -> Result<(), StoreError> {
    let mut replacement = Replacement::create(config, header, slots)?;
    replacement.finish(probe)?;
    replacement.rename_into_place(config).map(|_| ())
}

/// Flushes a directory, so a rename or a creation in it is durable.
#[cfg(unix)]
fn flush_directory(directory: &Path) -> Result<(), StoreError> {
    // A relative path with one component has an empty parent: the current
    // directory.
    let directory = if directory.as_os_str().is_empty() {
        Path::new(".")
    } else {
        directory
    };
    File::open(directory)
        .and_then(|dir| dir.sync_all())
        .map_err(|err| {
            io_error(
                &format!("cannot flush the directory {}", directory.display()),
                &err,
            )
        })
}

/// Flushes a directory, so a rename or a creation in it is durable. Not done
/// off Unix, where a directory cannot be opened as a file.
#[cfg(not(unix))]
fn flush_directory(_directory: &Path) -> Result<(), StoreError> {
    Ok(())
}

/// Creates `directory` and any missing parent, flushing each new directory
/// into its parent so the creation is durable.
fn create_directory(directory: &Path, probe: &mut Probe) -> Result<(), StoreError> {
    // The directories that do not exist yet, deepest first.
    let mut missing: Vec<PathBuf> = Vec::new();
    let mut at = Some(directory);
    while let Some(path) = at {
        if path.as_os_str().is_empty()
            || path
                .try_exists()
                .map_err(|err| io_error("cannot look for the store directory", &err))?
        {
            break;
        }
        missing.push(path.to_path_buf());
        at = path.parent();
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, DIRECTORY_MODE);
    builder
        .create(directory)
        .map_err(|err| io_error(&format!("cannot create {}", directory.display()), &err))?;
    for created in missing.iter().rev() {
        if let Some(parent) = created.parent() {
            flush_directory(parent)?;
            probe.dir_flush();
        }
    }
    Ok(())
}

/// The error for a store that does not exist and is not to be created.
#[cold]
#[inline(never)]
fn missing_store(config: &FileStoreConfig) -> StoreError {
    StoreError::Io(format!(
        "store {} has no journal in {}; set create_if_missing to create a new store",
        config.name(),
        config.directory().display()
    ))
}

/// Opens the journal in `config`'s directory: creates it if missing and
/// `create` is set, takes the lock, removes a replacement a crash left behind,
/// and loads the journal, cutting what `rule` allows. Runs on the writer
/// thread.
fn open_journal(
    config: FileStoreConfig,
    shared: Arc<Shared>,
    buffers: Arc<BufferPool>,
    rule: DamageRule,
    create: bool,
) -> Result<Journal, StoreError> {
    let mut probe = Probe::default();
    let journal_exists = |config: &FileStoreConfig| {
        config
            .journal_path()
            .try_exists()
            .map_err(|err| io_error("cannot look for the journal", &err))
    };
    let directory_exists = config
        .directory()
        .try_exists()
        .map_err(|err| io_error("cannot look for the store directory", &err))?;
    if !directory_exists {
        if !create {
            return Err(missing_store(&config));
        }
        create_directory(config.directory(), &mut probe)?;
    } else if !create && !journal_exists(&config)? {
        return Err(missing_store(&config));
    }

    let lock = owner_only_file()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(config.lock_path())
        .map_err(|err| {
            io_error(
                &format!("cannot open {}", config.lock_path().display()),
                &err,
            )
        })?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => {
            return Err(StoreError::Io(format!(
                "store {} in {} is already open in another FileStore",
                config.name(),
                config.directory().display()
            )));
        }
        // Includes a platform or file system that cannot lock: the store is
        // not opened unlocked.
        Err(TryLockError::Error(err)) => {
            return Err(io_error(
                &format!("cannot lock {}", config.lock_path().display()),
                &err,
            ));
        }
    }

    // A replacement that was never renamed into place is a reset or a
    // compaction that did not happen.
    match std::fs::remove_file(config.temp_path()) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(io_error("cannot remove an unfinished reset", &err)),
    }

    if !journal_exists(&config)? {
        if !create {
            return Err(missing_store(&config));
        }
        let header = Header {
            creation_time: SystemTime::now(),
            next_sender: 1,
            next_target: 1,
        };
        let (slots, _) = format::fresh_slots(0, 1, 1, DATA_START, 0, false)?;
        write_replacement(&config, &header, &slots, &mut probe)?;
        flush_directory(config.directory())?;
        probe.dir_flush();
    }

    let loaded = load(&config, rule, &mut probe)?;
    // Flushing at open makes what was loaded the durable starting point,
    // whatever the previous owner left unflushed. A salvage is always
    // flushed. A failure refuses the open: there is no store to poison yet.
    // Under `Never` nothing is flushed, so the journal is durable only as far
    // as its newest slot vouches for.
    let flushed = config.sync_policy().flushes() || rule == DamageRule::Salvage;
    if flushed {
        probe.file_flush();
        loaded
            .file
            .sync_data()
            .map_err(|err| io_error("cannot flush the journal", &err))?;
    }
    Ok(Journal::new(
        config, lock, loaded, flushed, shared, buffers, probe,
    ))
}

/// The Tokio runtime check every call makes.
///
/// # Errors
/// [`StoreError::Io`] outside a Tokio runtime: a `FileStore` is used from
/// inside one, as the #78 store documents and tests. The check costs a
/// thread-local read and no allocation.
fn runtime() -> Result<Handle, StoreError> {
    Handle::try_current().map_err(|_| {
        StoreError::Io("a FileStore must be used from inside a Tokio runtime".to_string())
    })
}

impl FileStore {
    /// Opens the store `config` describes and recovers its journal, on a
    /// writer thread the store starts and keeps until it is dropped or
    /// closed.
    ///
    /// With [`FileStoreConfig::with_create_if_missing`] set, a missing
    /// directory and journal are created (an empty journal, both counters at
    /// 1, flushed with its directory); otherwise a missing journal is an
    /// error. The journal is flushed once loaded, unless the policy is
    /// [`SyncPolicy::Never`].
    ///
    /// # Errors
    /// [`StoreError::Io`] if the files are missing (and not to be created) or
    /// cannot be created, opened, read, flushed or locked, including when
    /// another `FileStore` already has them open or the platform cannot lock
    /// them, if the writer thread cannot be started, and outside a Tokio
    /// runtime; [`StoreError::Corrupted`] if recovery refuses the journal
    /// (see the [module documentation](self), "Recovery"), including a
    /// journal in a format version other than 2.
    pub async fn open(config: FileStoreConfig) -> Result<Self, StoreError> {
        let rule = config.sync_policy().damage_rule();
        let create = config.create_if_missing();
        Self::open_with(config, rule, create).await
    }

    /// Cuts the journal `config` describes at its first record that cannot
    /// be read, wherever it is and for whatever reason, flushes the cut, and
    /// closes the store again. Returns the cut, or `None` if the journal was
    /// intact.
    ///
    /// This is the operator's decision to salvage a journal that
    /// [`FileStore::open`] refuses. The records cut away can include ones that
    /// were acknowledged and whose bytes the counterparty received, so the
    /// journal can be behind the session: **the next session must reset its
    /// sequence** (`ResetSeqNumFlag` (141) = Y), for example with
    /// `reset_on_logon`, or by calling [`MessageStore::reset`] before
    /// attaching the store. Resuming from the repaired counters can reuse a
    /// `MsgSeqNum` (34) with different content.
    ///
    /// # Errors
    /// [`StoreError::Io`] if the journal is missing or cannot be opened, cut,
    /// flushed or locked, and outside a Tokio runtime;
    /// [`StoreError::Corrupted`] if its header is not a version-4 journal
    /// header, or both of its counter slots are unreadable.
    pub async fn repair(config: FileStoreConfig) -> Result<Option<Truncation>, StoreError> {
        let store = Self::open_with(config, DamageRule::Salvage, false).await?;
        let truncation = store.last_truncation();
        store.close().await?;
        Ok(truncation)
    }

    /// Opens the store with an explicit damage rule and creation choice.
    async fn open_with(
        config: FileStoreConfig,
        rule: DamageRule,
        create: bool,
    ) -> Result<Self, StoreError> {
        runtime()?;
        let shared = Arc::new(Shared::new());
        let buffers = Arc::new(BufferPool::new());
        let (writer, opened) = {
            let config = config.clone();
            let shared = Arc::clone(&shared);
            let buffers = Arc::clone(&buffers);
            let recycler = Arc::clone(&buffers);
            Writer::spawn(
                WRITER_THREAD_NAME,
                CALL_QUEUE_CAPACITY,
                recycler,
                move || open_journal(config, shared, buffers, rule, create),
            )?
        };
        opened.await.map_err(|_| {
            StoreError::Io("the file store's writer thread stopped while opening".to_string())
        })??;
        Ok(Self {
            writer,
            shared,
            buffers,
            config,
        })
    }

    /// Returns the configuration the store was opened with.
    #[must_use]
    pub const fn config(&self) -> &FileStoreConfig {
        &self.config
    }

    /// Returns the last cut a recovery made to the journal since the store
    /// was opened, or `None` if none was made. A later clean refresh does not
    /// clear it.
    ///
    /// `ironfix-store` does not log, so this is how a cut is reported: an
    /// application may log it.
    #[must_use]
    pub fn last_truncation(&self) -> Option<Truncation> {
        *self.shared.truncation.lock()
    }

    /// Flushes every write made so far to stable storage, whatever the
    /// [`SyncPolicy`].
    ///
    /// Under [`SyncPolicy::EveryN`] and [`SyncPolicy::Never`] this is how to
    /// make the writes so far survive an operating-system crash, for example
    /// when a session closes. The engine never calls it: keep a clone of the
    /// `Arc<FileStore>` to call it yourself.
    ///
    /// # Errors
    /// [`StoreError::Io`] if the flush fails (the writes since the last
    /// successful flush are then cut, and the store refuses every call but a
    /// reset until a refresh succeeds), if the store is already unusable after
    /// a failed write, if its call queue is full, or outside a Tokio runtime.
    pub async fn sync(&self) -> Result<(), StoreError> {
        self.done(Command::Sync).await
    }

    /// Compacts the journal now: rewrites it with only its live records (a
    /// frame filed again under the same number leaves the earlier record
    /// behind) and the current counters, through a temporary file and a
    /// rename, flushed with the directory whatever the [`SyncPolicy`].
    /// Returns how many bytes the journal shrank by.
    ///
    /// The rename is the commit point, as for a reset: after a crash the
    /// journal is entirely the old one or entirely the compacted one, and both
    /// hold the same frames and counters.
    ///
    /// **A compaction blocks the store.** It copies every live record, so it
    /// takes time in proportion to the journal, and every call queued behind
    /// it waits. Under `ironfix-engine` a call that waits past the store
    /// timeout (`with_store_timeout`, default the 10-second write timeout)
    /// counts as a failed write: the next session owes a sequence reset, and
    /// under `StoreFailurePolicy::CloseSession` the session closes. Compact
    /// when no session is running on the store, or keep journals small
    /// enough that a compaction fits well inside the store timeout.
    ///
    /// # Errors
    /// [`StoreError::Io`] if the new journal cannot be written, flushed or
    /// renamed (the journal is then unchanged), if the directory cannot be
    /// flushed or the journal reopened after the rename (the store then
    /// refuses every call but a reset until a refresh succeeds), if the store
    /// is unusable after a failed write, if its call queue is full, or outside
    /// a Tokio runtime; [`StoreError::Corrupted`] if a live record fails its
    /// checks as it is read back (the journal is unchanged).
    pub async fn compact(&self) -> Result<u64, StoreError> {
        match self.command(Command::Compact).await? {
            Answer::Reclaimed(bytes) => Ok(bytes),
            _ => Err(unexpected_answer()),
        }
    }

    /// Closes the store: waits for any call still running, flushes writes
    /// left unflushed under [`SyncPolicy::EveryN`], closes the files,
    /// releases the lock, and stops the writer thread.
    ///
    /// Dropping a store does the same without the flush, at once if neither a
    /// call nor an automatic compaction is running; if one is, its writer
    /// thread does it once that is done. A store shared as
    /// `Arc<dyn MessageStore>` cannot be closed this way; it is dropped with
    /// its last reference.
    ///
    /// # Errors
    /// [`StoreError::Io`] if the flush fails; the lock is released anyway.
    pub async fn close(self) -> Result<(), StoreError> {
        self.done(Command::Close).await
    }

    /// Runs `command` on the writer thread, after every call made before it.
    ///
    /// The command is queued at the first poll, before anything awaits.
    /// Dropping the future before the writer thread takes the call cancels
    /// it; once the thread has taken it, it runs to the end and no later call
    /// runs before or beside it.
    async fn command(&self, command: Command) -> Result<Answer, StoreError> {
        runtime()?;
        self.writer.call(command)?.await
    }

    /// Runs a command that answers [`Answer::Done`].
    async fn done(&self, command: Command) -> Result<(), StoreError> {
        match self.command(command).await? {
            Answer::Done => Ok(()),
            _ => Err(unexpected_answer()),
        }
    }

    /// Encodes a frame record into a pooled buffer and files it: with the
    /// next sender number (`file_outbound`) or without (`store`). The buffer
    /// goes back to the pool if the frame is refused.
    async fn file_frame(
        &self,
        seq: u64,
        next_sender: Option<u64>,
        msg_type: &MsgType,
        frame: &[u8],
    ) -> Result<(), StoreError> {
        let mut record = self.buffers.take();
        if let Err(err) = format::encode_frame_record_into(
            &mut record,
            seq,
            next_sender,
            msg_type,
            frame,
            self.config.max_frame_size().get(),
        ) {
            self.buffers.give(record);
            return Err(err);
        }
        let command = match next_sender {
            Some(next_sender) => Command::FileOutbound {
                seq,
                record,
                next_sender,
            },
            None => Command::Store { seq, record },
        };
        self.done(command).await
    }

    /// Validates a range and runs a bounded read over it.
    async fn read(
        &self,
        begin: u64,
        end: u64,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        // An inverted range holds nothing and is a caller error; it is
        // refused before the index is touched.
        if begin == 0 || begin > end {
            return Err(StoreError::InvalidRange { begin, end });
        }
        match self.command(Command::Read { begin, end, limit }).await? {
            Answer::Page(messages) => Ok(messages),
            _ => Err(unexpected_answer()),
        }
    }

    /// Test-only: runs `op` on the journal, without taking a stalled call.
    #[cfg(test)]
    async fn probe<T, F>(&self, op: F) -> T
    where
        T: Send + 'static,
        F: FnOnce(&mut Journal) -> T + Send + 'static,
    {
        let command = Command::Probe(Box::new(move |journal: &mut Journal| {
            let value: Box<dyn std::any::Any + Send> = Box::new(op(journal));
            value
        }));
        let answer = match self.writer.call(command) {
            Ok(reply) => reply.await,
            Err(err) => Err(err),
        };
        match answer {
            Ok(Answer::Probe(value)) => match value.downcast::<T>() {
                Ok(value) => *value,
                Err(_) => panic!("the test probe answered the wrong type"),
            },
            Ok(_) => panic!("the test probe got the wrong kind of answer"),
            Err(err) => panic!("the test probe could not reach the journal: {err:?}"),
        }
    }

    /// Test-only: holds the next call on the writer thread for `stall`.
    #[cfg(test)]
    async fn stall_next_call(&self, stall: std::time::Duration) {
        self.probe(move |journal| journal.probe.stall = Some(stall))
            .await;
    }

    /// Test-only: makes the next journal flush fail.
    #[cfg(test)]
    async fn fail_next_flush(&self) {
        self.probe(|journal| journal.probe.fail_next_flush = true)
            .await;
    }

    /// Test-only: makes the next directory flush after a rename fail.
    #[cfg(test)]
    async fn fail_next_dir_flush(&self) {
        self.probe(|journal| journal.probe.fail_next_dir_flush = true)
            .await;
    }

    /// Test-only: the (file, directory) flushes made so far, since open.
    #[cfg(test)]
    async fn flushes(&self) -> (u64, u64) {
        self.probe(|journal| (journal.probe.file_flushes, journal.probe.dir_flushes))
            .await
    }
}

/// Written by hand: the journal lives on the writer thread.
impl std::fmt::Debug for FileStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileStore")
            .field("config", &self.config)
            .field("next_sender", &self.next_sender_seq())
            .field("next_target", &self.next_target_seq())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl MessageStore for FileStore {
    /// Appends one frame record. A frame above the configured maximum is
    /// refused with [`StoreError::StoreFailed`] and nothing is written.
    async fn store(
        &self,
        seq_num: u64,
        msg_type: &MsgType,
        message: &[u8],
    ) -> Result<(), StoreError> {
        self.file_frame(seq_num, None, msg_type, message).await
    }

    async fn get_range(&self, begin: u64, end: u64) -> Result<Vec<StoredMessage>, StoreError> {
        // `EndSeqNo` (16) = 0 is "to infinity"; normalised before any
        // comparison so it is not mistaken for a bound below `begin`.
        let end = if end == 0 { u64::MAX } else { end };
        let messages = self.read(begin, end, usize::MAX).await?;
        if messages.is_empty() {
            return Err(StoreError::RangeNotAvailable { begin, end });
        }
        Ok(messages)
    }

    /// A natively bounded read: only the at most `limit` frames of the page
    /// are read from the file, one positional read each. A record that fails
    /// its checks fails the whole page with [`StoreError::Corrupted`]; it is
    /// never skipped, and no frame after it in the page is returned.
    async fn get_page(
        &self,
        begin: u64,
        end: u64,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        self.read(begin, end, limit).await
    }

    /// Appends one record carrying both the frame and the next sender number,
    /// so a crash leaves both in the journal or neither.
    async fn file_outbound(
        &self,
        seq_num: u64,
        msg_type: &MsgType,
        message: &[u8],
        next_sender: u64,
    ) -> Result<(), StoreError> {
        self.file_frame(seq_num, Some(next_sender), msg_type, message)
            .await
    }

    fn next_sender_seq(&self) -> u64 {
        self.shared.next_sender.load(Ordering::SeqCst)
    }

    fn next_target_seq(&self) -> u64 {
        self.shared.next_target.load(Ordering::SeqCst)
    }

    /// The marker as the newest valid counter slot carries it, as loaded at
    /// open or by the last refresh, and as last set since.
    fn reset_owed(&self) -> bool {
        self.shared.reset_owed.load(Ordering::SeqCst)
    }

    /// Writes the marker into both counter slots, flushing each, whatever the
    /// [`SyncPolicy`]; a store left unusable by a failed write is refreshed
    /// first. A reset and a compaction carry the marker into the new journal.
    async fn set_reset_owed(&self, owed: bool) -> Result<(), StoreError> {
        self.done(Command::SetResetOwed(owed)).await
    }

    /// The watermark as the newest valid counter slot carries it, as loaded
    /// at open or by the last refresh, and as last set since.
    fn app_watermark(&self) -> u64 {
        self.shared.app_watermark.load(Ordering::SeqCst)
    }

    /// Overwrites the counter slot that does not hold the last durable
    /// checkpoint, like a counter write, flushed as the [`SyncPolicy`] says;
    /// the file does not grow. A reset writes 0; a compaction carries it.
    async fn set_app_watermark(&self, watermark: u64) -> Result<(), StoreError> {
        self.done(Command::SetAppWatermark(watermark)).await
    }

    /// Overwrites the counter slot that does not hold the last durable
    /// checkpoint; the file does not grow.
    async fn set_next_sender_seq(&self, seq: u64) -> Result<(), StoreError> {
        self.done(Command::SetNextSender(seq)).await
    }

    /// Overwrites the counter slot that does not hold the last durable
    /// checkpoint; the file does not grow.
    async fn set_next_target_seq(&self, seq: u64) -> Result<(), StoreError> {
        self.done(Command::SetNextTarget(seq)).await
    }

    /// Replaces the journal with an empty one at 1/1 and a new creation time,
    /// atomically (see [`MessageStore::reset_to`]).
    async fn reset(&self) -> Result<(), StoreError> {
        self.reset_to(1, 1).await
    }

    /// Replaces the journal with an empty one starting from the given
    /// counters and a new creation time, in one atomic change: the new
    /// journal is written to a temporary file, flushed, renamed over the old
    /// one, and the directory flushed, whatever the [`SyncPolicy`], so a crash
    /// leaves one or the other, never a mix.
    ///
    /// Runs even on a store left unusable by a failed write, and a success
    /// makes it usable again: the replaced journal no longer matters. A
    /// failure to flush the directory after the rename leaves the store
    /// unusable until a refresh has flushed it.
    async fn reset_to(&self, next_sender: u64, next_target: u64) -> Result<(), StoreError> {
        self.done(Command::ResetTo {
            next_sender,
            next_target,
        })
        .await
    }

    fn creation_time(&self) -> SystemTime {
        *self.shared.creation_time.read()
    }

    /// Completes what a failed write left pending (a directory flush, the cut
    /// back to the last successful flush and the counter slots as it left
    /// them, made durable), then rereads the journal from disk: the counters,
    /// the index and the creation time are replaced by what the file holds,
    /// recovery cuts what it allows (see [`FileStore::last_truncation`]), and
    /// the journal is flushed unless the policy is [`SyncPolicy::Never`].
    async fn refresh(&self) -> Result<(), StoreError> {
        self.done(Command::Refresh).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU32;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    /// Fails the test with context instead of `.unwrap()` / `.expect()`.
    #[track_caller]
    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("{what}: {err:?}"),
        }
    }

    /// A directory unique to one test, removed when the test ends.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(test: &str) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let unique = NEXT.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!(
                "ironfix-store-{}-{test}-{unique}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            Self(path)
        }

        /// A configuration that creates the store on first open.
        fn config(&self) -> FileStoreConfig {
            self.existing().with_create_if_missing(true)
        }

        /// A configuration that only opens a store that already exists.
        fn existing(&self) -> FileStoreConfig {
            ok(
                FileStoreConfig::try_new(&self.0, "FIX.4.4-CLIENT-VENUE"),
                "test config",
            )
        }

        fn config_with(&self, policy: SyncPolicy) -> FileStoreConfig {
            self.config().with_sync_policy(policy)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn open(config: FileStoreConfig) -> FileStore {
        ok(FileStore::open(config).await, "the store must open")
    }

    fn journal_len(config: &FileStoreConfig) -> u64 {
        ok(std::fs::metadata(config.journal_path()), "journal metadata").len()
    }

    fn journal_bytes(config: &FileStoreConfig) -> Vec<u8> {
        ok(std::fs::read(config.journal_path()), "read the journal")
    }

    fn write_journal(config: &FileStoreConfig, bytes: &[u8]) {
        ok(
            std::fs::write(config.journal_path(), bytes),
            "rewrite the journal",
        );
    }

    fn cut_journal(config: &FileStoreConfig, len: u64) {
        let file = ok(
            OpenOptions::new().write(true).open(config.journal_path()),
            "open the journal to cut it",
        );
        ok(file.set_len(len), "cut the journal");
    }

    /// A frame that looks like a FIX message, distinct per sequence number.
    fn frame(seq: u64) -> Vec<u8> {
        format!("8=FIX.4.4\x019=40\x0135=D\x0134={seq}\x0111=ORDER-{seq}\x0110=000\x01")
            .into_bytes()
    }

    async fn file(store: &FileStore, seq: u64) {
        ok(
            store
                .file_outbound(seq, &MsgType::NewOrderSingle, &frame(seq), seq + 1)
                .await,
            "file_outbound",
        );
    }

    async fn seqs(store: &FileStore, begin: u64, end: u64, limit: usize) -> Vec<u64> {
        ok(store.get_page(begin, end, limit).await, "get_page")
            .iter()
            .map(StoredMessage::seq_num)
            .collect()
    }

    #[tokio::test]
    async fn test_file_store_open_creates_an_empty_store_at_one() {
        let dir = TempDir::new("create");
        let store = open(dir.config()).await;
        assert_eq!(store.next_sender_seq(), 1);
        assert_eq!(store.next_target_seq(), 1);
        assert_eq!(store.last_truncation(), None);
        assert!(dir.config().journal_path().exists());
        assert!(dir.config().lock_path().exists());
        assert!(seqs(&store, 1, u64::MAX, 10).await.is_empty());
        assert_eq!(
            store.get_range(1, 0).await,
            Err(StoreError::RangeNotAvailable {
                begin: 1,
                end: u64::MAX
            })
        );
    }

    #[tokio::test]
    async fn test_file_store_missing_store_is_an_error_without_create_if_missing() {
        let dir = TempDir::new("missing");
        let opened = FileStore::open(dir.existing()).await;
        assert!(
            matches!(opened, Err(StoreError::Io(ref reason)) if reason.contains("create_if_missing")),
            "{opened:?}"
        );
        assert!(!dir.0.exists(), "nothing is created");

        // An existing directory without a journal is no different.
        ok(std::fs::create_dir_all(&dir.0), "create the directory");
        assert!(FileStore::open(dir.existing()).await.is_err());
        assert!(!dir.existing().journal_path().exists());
    }

    #[tokio::test]
    async fn test_file_store_create_if_missing_creates_nested_directories() {
        let dir = TempDir::new("nested");
        ok(std::fs::create_dir_all(&dir.0), "the test directory");
        let Ok(config) = FileStoreConfig::try_new(dir.0.join("a").join("b"), "session") else {
            panic!("valid name");
        };
        let store = open(config.clone().with_create_if_missing(true)).await;
        // Two directories created, each flushed into its parent, then the
        // journal's own rename flushed.
        assert_eq!(store.flushes().await.1, 3);
        drop(store);
        // Once created, the store opens without create_if_missing.
        let store = open(config).await;
        assert_eq!(store.next_sender_seq(), 1);
    }

    #[tokio::test]
    async fn test_file_store_reopen_returns_byte_identical_frames_and_counters() {
        let dir = TempDir::new("round-trip");
        let config = dir.config();
        let creation;
        {
            let store = open(config.clone()).await;
            creation = store.creation_time();
            ok(
                store.store(1, &MsgType::Logon, &frame(1)).await,
                "store the Logon",
            );
            ok(store.set_next_sender_seq(2).await, "sender counter");
            for seq in 2..=20 {
                file(&store, seq).await;
            }
            ok(store.set_next_target_seq(14).await, "target counter");
        }

        let store = open(config).await;
        assert_eq!(store.next_sender_seq(), 21);
        assert_eq!(store.next_target_seq(), 14);
        assert_eq!(store.creation_time(), creation);
        assert_eq!(store.last_truncation(), None);

        let all = ok(store.get_range(1, 0).await, "get_range to infinity");
        assert_eq!(all.len(), 20);
        for (message, seq) in all.iter().zip(1u64..) {
            assert_eq!(message.seq_num(), seq);
            assert_eq!(&message.payload()[..], &frame(seq)[..], "frame {seq}");
            let expected = if seq == 1 {
                MsgType::Logon
            } else {
                MsgType::NewOrderSingle
            };
            assert_eq!(message.msg_type(), &expected);
        }

        let page = ok(store.get_page(5, 20, 3).await, "bounded page");
        assert_eq!(
            page.iter()
                .map(|message| (message.seq_num(), message.payload().to_vec()))
                .collect::<Vec<_>>(),
            vec![(5, frame(5)), (6, frame(6)), (7, frame(7))]
        );
    }

    #[tokio::test]
    async fn test_file_store_get_page_over_a_sparse_range_returns_only_stored_numbers() {
        let dir = TempDir::new("sparse");
        let store = open(dir.config()).await;
        for seq in [2, 3, 7, 11] {
            file(&store, seq).await;
        }

        assert_eq!(seqs(&store, 1, 20, 10).await, vec![2, 3, 7, 11]);
        assert_eq!(seqs(&store, 3, 11, 2).await, vec![3, 7]);
        // A hole is an empty page, not an error.
        assert!(seqs(&store, 4, 6, 10).await.is_empty());
        assert!(seqs(&store, 1, 20, 0).await.is_empty());
        // get_range treats an empty range as an error, and keeps the bounds.
        assert_eq!(
            store.get_range(4, 6).await,
            Err(StoreError::RangeNotAvailable { begin: 4, end: 6 })
        );
        assert_eq!(
            ok(store.get_range(5, 9).await, "range 5..=9")
                .iter()
                .map(StoredMessage::seq_num)
                .collect::<Vec<_>>(),
            vec![7]
        );
    }

    #[tokio::test]
    async fn test_file_store_invalid_ranges_are_refused_not_a_panic() {
        let dir = TempDir::new("ranges");
        let store = open(dir.config()).await;
        file(&store, 1).await;
        assert_eq!(
            store.get_page(5, 3, 4).await,
            Err(StoreError::InvalidRange { begin: 5, end: 3 })
        );
        assert_eq!(
            store.get_page(0, 3, 4).await,
            Err(StoreError::InvalidRange { begin: 0, end: 3 })
        );
        assert_eq!(
            store.get_range(5, 3).await,
            Err(StoreError::InvalidRange { begin: 5, end: 3 })
        );
        assert_eq!(
            store.get_range(0, 0).await,
            Err(StoreError::InvalidRange {
                begin: 0,
                end: u64::MAX
            })
        );
    }

    #[tokio::test]
    async fn test_file_store_store_at_an_existing_seq_replaces_the_frame_across_reopen() {
        let dir = TempDir::new("replace");
        let config = dir.config();
        {
            let store = open(config.clone()).await;
            ok(
                store.store(7, &MsgType::NewOrderSingle, b"first").await,
                "first",
            );
            ok(
                store
                    .file_outbound(7, &MsgType::OrderCancelRequest, b"second", 8)
                    .await,
                "second",
            );
            let now = ok(store.get_range(7, 7).await, "range 7");
            assert_eq!(now.len(), 1);
        }
        let store = open(config).await;
        let range = ok(store.get_range(7, 7).await, "range 7 after reopen");
        let [message] = range.as_slice() else {
            panic!("exactly one message must remain, got {}", range.len());
        };
        assert_eq!(message.msg_type(), &MsgType::OrderCancelRequest);
        assert_eq!(&message.payload()[..], b"second");
        assert_eq!(store.next_sender_seq(), 8);
    }

    #[tokio::test]
    async fn test_file_store_truncated_mid_record_reopens_with_the_last_complete_record() {
        let dir = TempDir::new("torn");
        let config = dir.config();
        let (after_two, after_three);
        {
            let store = open(config.clone()).await;
            file(&store, 1).await;
            file(&store, 2).await;
            after_two = journal_len(&config);
            file(&store, 3).await;
            after_three = journal_len(&config);
        }
        // A crash halfway through the third append.
        let cut = after_two + (after_three - after_two) / 2;
        cut_journal(&config, cut);

        {
            let store = open(config.clone()).await;
            assert_eq!(seqs(&store, 1, 10, 10).await, vec![1, 2]);
            assert_eq!(store.next_sender_seq(), 3, "the counter filed with 2");
            let Some(truncation) = store.last_truncation() else {
                panic!("the cut must be reported");
            };
            assert_eq!(truncation.cause(), TruncationCause::Incomplete);
            assert_eq!(truncation.offset(), after_two);
            assert_eq!(truncation.dropped_bytes(), cut - after_two);
            // The torn bytes are gone from the file, so the next append is
            // read back after it.
            assert_eq!(journal_len(&config), after_two);
            file(&store, 3).await;
        }
        let store = open(config).await;
        assert_eq!(store.last_truncation(), None);
        assert_eq!(seqs(&store, 1, 10, 10).await, vec![1, 2, 3]);
        assert_eq!(store.next_sender_seq(), 4);
    }

    /// Files records 1 to 3 and returns the offset each one starts at and the
    /// journal's length after them.
    async fn three_records(config: &FileStoreConfig) -> ([u64; 3], u64) {
        let store = open(config.clone()).await;
        let mut starts = [0u64; 3];
        for (seq, start) in (1u64..).zip(starts.iter_mut()) {
            *start = journal_len(config);
            file(&store, seq).await;
        }
        (starts, journal_len(config))
    }

    /// Flips one bit of the journal at `at`.
    fn flip(config: &FileStoreConfig, at: u64) {
        let mut bytes = journal_bytes(config);
        let Some(byte) = usize::try_from(at).ok().and_then(|at| bytes.get_mut(at)) else {
            panic!("offset {at} must be inside the journal");
        };
        *byte ^= 0x01;
        write_journal(config, &bytes);
    }

    #[tokio::test]
    async fn test_file_store_damage_before_the_last_record_refuses_to_open() {
        let dir = TempDir::new("damage-middle");
        let config = dir.config();
        let ([_, second, _], len) = three_records(&config).await;
        // A frame byte inside record 2, with record 3 written after it: damage
        // to data already written, not an interrupted write.
        flip(&config, second + 40);
        let damaged = journal_bytes(&config);

        let opened = FileStore::open(config.clone()).await;
        assert!(
            matches!(
                opened,
                Err(StoreError::Corrupted { ref reason }) if reason.contains("repair")
            ),
            "{opened:?}"
        );
        // Refused, not cut: the journal is untouched.
        assert_eq!(journal_len(&config), len);
        assert_eq!(journal_bytes(&config), damaged);
    }

    #[tokio::test]
    async fn test_file_store_damaged_last_record_is_cut_and_never_returned() {
        let dir = TempDir::new("damage-last");
        let config = dir.config();
        let ([_, _, third], _) = three_records(&config).await;
        flip(&config, third + 40);

        let store = open(config.clone()).await;
        assert_eq!(seqs(&store, 1, 10, 10).await, vec![1, 2]);
        assert_eq!(store.next_sender_seq(), 3);
        assert_eq!(
            store.get_range(3, 3).await,
            Err(StoreError::RangeNotAvailable { begin: 3, end: 3 })
        );
        let Some(truncation) = store.last_truncation() else {
            panic!("the cut must be reported");
        };
        assert_eq!(truncation.cause(), TruncationCause::Damaged);
        assert_eq!(truncation.offset(), third);
        assert_eq!(journal_len(&config), third);
    }

    #[tokio::test]
    async fn test_file_store_never_policy_cuts_damage_anywhere() {
        let dir = TempDir::new("damage-never");
        let config = dir.config_with(SyncPolicy::Never);
        let ([_, second, _], _) = three_records(&config).await;
        flip(&config, second + 40);

        // A policy that flushes nothing promises nothing after an OS crash, so
        // damage anywhere may be what one left: it is cut, and reported.
        let store = open(config).await;
        assert_eq!(seqs(&store, 1, 10, 10).await, vec![1]);
        assert_eq!(
            store
                .last_truncation()
                .map(|cut| (cut.offset(), cut.cause())),
            Some((second, TruncationCause::Damaged))
        );
    }

    #[tokio::test]
    async fn test_file_store_every_n_cuts_damage_within_its_unflushed_window() {
        let dir = TempDir::new("damage-every-n");
        let Some(four) = NonZeroU32::new(4) else {
            panic!("non-zero");
        };
        let config = dir.config_with(SyncPolicy::EveryN(four));
        let ([_, second, _], _) = three_records(&config).await;
        flip(&config, second + 40);
        // Two records from the end, inside a four-write window: cut.
        let store = open(config).await;
        assert_eq!(seqs(&store, 1, 10, 10).await, vec![1]);
    }

    #[tokio::test]
    async fn test_file_store_repair_cuts_a_refused_journal_at_its_first_bad_record() {
        let dir = TempDir::new("repair");
        let config = dir.config();
        let ([_, second, _], _) = three_records(&config).await;
        flip(&config, second + 40);
        assert!(FileStore::open(config.clone()).await.is_err());

        let repaired = ok(FileStore::repair(config.clone()).await, "repair");
        assert_eq!(
            repaired.map(|cut| (cut.offset(), cut.cause())),
            Some((second, TruncationCause::Damaged))
        );
        // The repair closed the store, so it opens again at once.
        let store = open(config.clone()).await;
        assert_eq!(seqs(&store, 1, 10, 10).await, vec![1]);
        assert_eq!(store.next_sender_seq(), 2);
        drop(store);
        // An intact journal needs no repair.
        assert_eq!(ok(FileStore::repair(config).await, "second repair"), None);
    }

    #[tokio::test]
    async fn test_file_store_repair_of_a_missing_store_is_an_error() {
        let dir = TempDir::new("repair-missing");
        assert!(matches!(
            FileStore::repair(dir.config()).await,
            Err(StoreError::Io(_))
        ));
        assert!(!dir.0.exists(), "a repair never creates a store");
    }

    #[tokio::test]
    async fn test_file_store_huge_length_prefix_is_corrupted_not_an_allocation() {
        let dir = TempDir::new("huge-length");
        let config = dir.config();
        drop(open(config.clone()).await);

        let mut bytes = journal_bytes(&config);
        // A well-formed record header declaring a 4 GiB body.
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.extend_from_slice(&(!u32::MAX).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(b"short");
        write_journal(&config, &bytes);

        let opened = FileStore::open(config.clone()).await;
        assert!(
            matches!(
                opened,
                Err(StoreError::Corrupted { ref reason }) if reason.contains("4294967295")
            ),
            "{opened:?}"
        );
        // Refused, not cut: the bytes are still there for an operator.
        assert_eq!(journal_len(&config), bytes.len() as u64);
    }

    #[tokio::test]
    async fn test_file_store_record_damaged_after_open_fails_the_page_not_just_the_record() {
        let dir = TempDir::new("damaged-on-read");
        let config = dir.config();
        let store = open(config.clone()).await;
        let mut starts = Vec::new();
        for seq in 1..=3 {
            starts.push(journal_len(&config));
            file(&store, seq).await;
        }
        let Some(second) = starts.get(1).copied() else {
            panic!("three records were filed");
        };
        // The disk changes under the open store.
        flip(&config, second + 40);
        assert!(matches!(
            store.get_page(1, 3, 10).await,
            Err(StoreError::Corrupted { reason }) if reason.contains("MsgSeqNum 2")
        ));
        // A page that does not reach the damaged record is still served.
        assert_eq!(seqs(&store, 1, 1, 10).await, vec![1]);
        assert_eq!(seqs(&store, 3, 3, 10).await, vec![3]);
    }

    #[tokio::test]
    async fn test_file_store_lowered_frame_limit_refuses_a_journal_with_larger_frames() {
        let dir = TempDir::new("lowered-limit");
        let config = dir.config();
        {
            let store = open(config.clone()).await;
            ok(
                store.store(1, &MsgType::NewOrderSingle, &[b'x'; 200]).await,
                "store a 200-byte frame",
            );
        }
        let Some(small) = NonZeroU32::new(100) else {
            panic!("non-zero");
        };
        let lowered = ok(config.clone().with_max_frame_size(small), "lowered limit");
        assert!(matches!(
            FileStore::open(lowered).await,
            Err(StoreError::Corrupted { .. })
        ));
        // Raised back, the journal is readable again.
        let store = open(config).await;
        assert_eq!(seqs(&store, 1, 1, 1).await, vec![1]);
    }

    #[tokio::test]
    async fn test_file_store_frame_above_the_limit_is_refused_and_nothing_is_written() {
        let dir = TempDir::new("big-frame");
        let Some(limit) = NonZeroU32::new(64) else {
            panic!("non-zero");
        };
        let config = ok(dir.config().with_max_frame_size(limit), "limit");
        let store = open(config.clone()).await;
        let before = journal_len(&config);
        let result = store
            .file_outbound(1, &MsgType::NewOrderSingle, &[b'x'; 65], 2)
            .await;
        assert!(matches!(
            result,
            Err(StoreError::StoreFailed { seq_num: 1, .. })
        ));
        assert_eq!(journal_len(&config), before);
        assert_eq!(store.next_sender_seq(), 1);
        file(&store, 1).await;
    }

    #[tokio::test]
    async fn test_file_store_file_outbound_leaves_both_or_neither_at_every_crash_point() {
        let dir = TempDir::new("both-or-neither");
        let config = dir.config();
        let (before, after);
        {
            let store = open(config.clone()).await;
            file(&store, 1).await;
            ok(store.set_next_target_seq(4).await, "target counter");
            before = journal_len(&config);
            file(&store, 2).await;
            after = journal_len(&config);
        }
        let intact = journal_bytes(&config);

        // A crash at every byte of the second file_outbound's write.
        for cut in before..=after {
            write_journal(&config, &intact);
            cut_journal(&config, cut);
            let store = open(config.clone()).await;
            let filed = seqs(&store, 1, 10, 10).await;
            if cut == after {
                assert_eq!(filed, vec![1, 2], "complete record, cut at {cut}");
                assert_eq!(store.next_sender_seq(), 3, "cut at {cut}");
            } else {
                assert_eq!(filed, vec![1], "torn record, cut at {cut}");
                assert_eq!(store.next_sender_seq(), 2, "cut at {cut}");
            }
            assert_eq!(store.next_target_seq(), 4, "cut at {cut}");
        }

        // Damage anywhere in the record also leaves neither.
        let record_len = usize::try_from(after - before).unwrap_or(usize::MAX);
        let start = usize::try_from(before).unwrap_or(usize::MAX);
        for at in start..start + record_len {
            let mut damaged = intact.clone();
            if let Some(byte) = damaged.get_mut(at) {
                *byte ^= 0x80;
            }
            write_journal(&config, &damaged);
            let store = open(config.clone()).await;
            assert_eq!(seqs(&store, 1, 10, 10).await, vec![1], "damage at {at}");
            assert_eq!(store.next_sender_seq(), 2, "damage at {at}");
        }
    }

    #[tokio::test]
    async fn test_file_store_reset_survives_reopen_as_an_empty_store_at_one() {
        let dir = TempDir::new("reset");
        let config = dir.config();
        let reset_at;
        {
            let store = open(config.clone()).await;
            for seq in 1..=5 {
                file(&store, seq).await;
            }
            ok(store.set_next_target_seq(9).await, "target counter");
            let created = store.creation_time();
            ok(store.reset().await, "reset");
            reset_at = store.creation_time();
            assert!(reset_at >= created);
            assert_eq!(store.next_sender_seq(), 1);
            assert_eq!(store.next_target_seq(), 1);
            assert!(seqs(&store, 1, 10, 10).await.is_empty());
        }
        assert!(!config.temp_path().exists());
        let store = open(config).await;
        assert_eq!(store.next_sender_seq(), 1);
        assert_eq!(store.next_target_seq(), 1);
        assert_eq!(store.creation_time(), reset_at);
        assert!(seqs(&store, 1, 10, 10).await.is_empty());
        // The journal is usable after the reset.
        file(&store, 1).await;
        assert_eq!(seqs(&store, 1, 10, 10).await, vec![1]);
    }

    #[tokio::test]
    async fn test_file_store_reset_to_survives_reopen_with_the_counters_as_set() {
        let dir = TempDir::new("reset-to");
        let config = dir.config();
        {
            let store = open(config.clone()).await;
            for seq in 41..=42 {
                file(&store, seq).await;
            }
            ok(store.set_next_target_seq(17).await, "target counter");
            ok(store.reset_to(2, 2).await, "reset_to");
            assert_eq!(store.next_sender_seq(), 2);
            assert_eq!(store.next_target_seq(), 2);
        }
        {
            let store = open(config.clone()).await;
            assert!(
                seqs(&store, 1, 100, 10).await.is_empty(),
                "the previous stream is gone"
            );
            assert_eq!(store.next_sender_seq(), 2);
            assert_eq!(store.next_target_seq(), 2);
            file(&store, 2).await;
        }
        let store = open(config).await;
        assert_eq!(seqs(&store, 1, 100, 10).await, vec![2]);
        assert_eq!(store.next_sender_seq(), 3);
        assert_eq!(store.next_target_seq(), 2);
    }

    #[tokio::test]
    async fn test_file_store_unfinished_reset_is_discarded_at_open() {
        let dir = TempDir::new("unfinished-reset");
        let config = dir.config();
        {
            let store = open(config.clone()).await;
            file(&store, 1).await;
        }
        // A crash before the rename leaves the replacement beside the journal.
        ok(
            std::fs::write(config.temp_path(), b"half-written replacement"),
            "leave a temporary file",
        );
        let store = open(config.clone()).await;
        assert!(!config.temp_path().exists());
        assert_eq!(seqs(&store, 1, 10, 10).await, vec![1]);
        assert_eq!(store.next_sender_seq(), 2);
    }

    #[tokio::test]
    async fn test_file_store_not_a_journal_is_corrupted() {
        let dir = TempDir::new("not-a-journal");
        let config = dir.config();
        ok(std::fs::create_dir_all(config.directory()), "directory");
        write_journal(
            &config,
            b"definitely not a journal, but long enough for a header",
        );
        assert!(matches!(
            FileStore::open(config.clone()).await,
            Err(StoreError::Corrupted { .. })
        ));
        // An empty journal (a rename made durable before its data) is refused
        // too, never treated as a fresh store.
        write_journal(&config, b"");
        assert!(matches!(
            FileStore::open(config).await,
            Err(StoreError::Corrupted { .. })
        ));
    }

    #[tokio::test]
    async fn test_file_store_second_open_on_the_same_files_is_refused() {
        let dir = TempDir::new("lock");
        let config = dir.config();
        let store = open(config.clone()).await;
        assert!(matches!(
            FileStore::open(config.clone()).await,
            Err(StoreError::Io(ref reason)) if reason.contains("already open")
        ));
        drop(store);
        let reopened = FileStore::open(config).await;
        assert!(reopened.is_ok(), "{reopened:?}");
    }

    #[tokio::test]
    async fn test_file_store_refresh_reloads_and_cuts_a_torn_tail() {
        let dir = TempDir::new("refresh");
        let config = dir.config();
        let store = open(config.clone()).await;
        file(&store, 1).await;
        ok(store.set_next_target_seq(5).await, "target counter");
        let good = journal_len(&config);

        // Bytes appended behind the store's back, as a torn write would.
        let mut bytes = journal_bytes(&config);
        bytes.extend_from_slice(&[0x55; 7]);
        write_journal(&config, &bytes);

        ok(store.refresh().await, "refresh");
        assert_eq!(store.next_sender_seq(), 2);
        assert_eq!(store.next_target_seq(), 5);
        assert_eq!(seqs(&store, 1, 10, 10).await, vec![1]);
        assert_eq!(
            store
                .last_truncation()
                .map(|cut| (cut.offset(), cut.dropped_bytes())),
            Some((good, 7))
        );
        assert_eq!(journal_len(&config), good);

        // A clean refresh keeps the report.
        ok(store.refresh().await, "second refresh");
        assert_eq!(store.last_truncation().map(|cut| cut.offset()), Some(good));
    }

    #[tokio::test]
    async fn test_file_store_open_creates_and_flushes_the_journal() {
        let dir = TempDir::new("open-flushes");
        let store = open(dir.config_with(SyncPolicy::EveryWrite)).await;
        // The new journal file, then the loaded journal; the store directory
        // (into its parent) and the new journal's rename.
        let expected_dirs = if cfg!(unix) { 2 } else { 0 };
        assert_eq!(store.flushes().await, (2, expected_dirs));
    }

    #[tokio::test]
    async fn test_file_store_sync_policy_every_write_flushes_each_append() {
        let dir = TempDir::new("every-write");
        let store = open(dir.config_with(SyncPolicy::EveryWrite)).await;
        let (base, _) = store.flushes().await;
        for seq in 1..=3 {
            file(&store, seq).await;
        }
        ok(store.set_next_target_seq(2).await, "target counter");
        assert_eq!(store.flushes().await.0 - base, 4);
    }

    #[tokio::test]
    async fn test_file_store_sync_policy_every_n_flushes_every_nth_append() {
        let dir = TempDir::new("every-n");
        let Some(three) = NonZeroU32::new(3) else {
            panic!("non-zero");
        };
        let store = open(dir.config_with(SyncPolicy::EveryN(three))).await;
        let (base, _) = store.flushes().await;
        for seq in 1..=7 {
            file(&store, seq).await;
        }
        // Flushed after the 3rd and the 6th append; the 7th is pending.
        assert_eq!(store.flushes().await.0 - base, 2);
        ok(store.sync().await, "explicit sync");
        assert_eq!(store.flushes().await.0 - base, 3);
        // The explicit sync restarted the count.
        file(&store, 8).await;
        file(&store, 9).await;
        assert_eq!(store.flushes().await.0 - base, 3);
        file(&store, 10).await;
        assert_eq!(store.flushes().await.0 - base, 4);
    }

    #[tokio::test]
    async fn test_file_store_every_n_refresh_flushes_what_is_pending() {
        let dir = TempDir::new("every-n-refresh");
        let Some(three) = NonZeroU32::new(3) else {
            panic!("non-zero");
        };
        let store = open(dir.config_with(SyncPolicy::EveryN(three))).await;
        let (base, _) = store.flushes().await;
        file(&store, 1).await;
        file(&store, 2).await;
        assert_eq!(store.flushes().await.0 - base, 0, "two writes are pending");
        // The refresh restarts the count, so it flushes what was pending:
        // otherwise up to 2 + 2 writes could be unflushed after it.
        ok(store.refresh().await, "refresh");
        assert_eq!(store.flushes().await.0 - base, 1);
        file(&store, 3).await;
        file(&store, 4).await;
        assert_eq!(store.flushes().await.0 - base, 1);
        file(&store, 5).await;
        assert_eq!(store.flushes().await.0 - base, 2);
    }

    #[tokio::test]
    async fn test_file_store_sync_policy_never_flushes_only_resets_and_requests() {
        let dir = TempDir::new("never");
        let config = dir.config_with(SyncPolicy::Never);
        let dirs = |count: u64| if cfg!(unix) { count } else { 0 };
        {
            let store = open(config.clone()).await;
            // Creating a journal is a replacement, flushed whatever the
            // policy; the loaded journal is not flushed.
            assert_eq!(store.flushes().await, (1, dirs(2)));
            for seq in 1..=5 {
                file(&store, seq).await;
            }
            assert_eq!(
                store.flushes().await,
                (1, dirs(2)),
                "appends are not flushed"
            );
            // A reset is flushed whatever the policy: file and directory.
            ok(store.reset_to(3, 3).await, "reset_to");
            assert_eq!(store.flushes().await, (2, dirs(3)));
            file(&store, 3).await;
            ok(store.sync().await, "explicit sync");
            assert_eq!(store.flushes().await, (3, dirs(3)));
        }
        // Unflushed writes still reached the operating system: they survive
        // the store (and the process) going away.
        let store = open(config).await;
        assert_eq!(seqs(&store, 1, 10, 10).await, vec![3]);
        assert_eq!(store.next_sender_seq(), 4);
        assert_eq!(store.next_target_seq(), 3);
    }

    #[tokio::test]
    async fn test_file_store_reset_flushes_the_new_file_and_its_directory() {
        let dir = TempDir::new("reset-flush");
        let Some(hundred) = NonZeroU32::new(100) else {
            panic!("non-zero");
        };
        let store = open(dir.config_with(SyncPolicy::EveryN(hundred))).await;
        let (files, dirs) = store.flushes().await;
        ok(store.reset_to(5, 6).await, "reset_to");
        let (files_after, dirs_after) = store.flushes().await;
        assert_eq!(files_after - files, 1, "the replacement file");
        if cfg!(unix) {
            assert_eq!(dirs_after - dirs, 1, "the directory holding the rename");
        }
    }

    #[tokio::test]
    async fn test_file_store_failed_flush_cuts_back_and_err_means_not_filed() {
        let dir = TempDir::new("poison");
        let config = dir.config();
        let store = open(config.clone()).await;
        file(&store, 1).await;
        let durable = journal_len(&config);
        store.fail_next_flush().await;
        assert!(matches!(
            store
                .file_outbound(2, &MsgType::NewOrderSingle, &frame(2), 3)
                .await,
            Err(StoreError::Io(_))
        ));
        // The write since the last flush is cut at once, and the counter it
        // carried was never published.
        assert_eq!(journal_len(&config), durable);
        assert_eq!(store.next_sender_seq(), 2);
        // Every call but a reset or a refresh fails until the cut is durable.
        assert!(matches!(
            store.set_next_target_seq(2).await,
            Err(StoreError::Io(_))
        ));
        assert!(matches!(
            store.get_page(1, 10, 10).await,
            Err(StoreError::Io(_))
        ));
        assert!(matches!(store.sync().await, Err(StoreError::Io(_))));
        ok(store.refresh().await, "refresh");
        // An error meant "not filed": the reload does not bring 2 back.
        assert_eq!(seqs(&store, 1, 10, 10).await, vec![1]);
        assert_eq!(store.next_sender_seq(), 2);
        file(&store, 2).await;
        drop(store);
        let store = open(config).await;
        assert_eq!(seqs(&store, 1, 10, 10).await, vec![1, 2]);
    }

    #[tokio::test]
    async fn test_file_store_failed_flush_under_every_n_cuts_every_unflushed_write() {
        let dir = TempDir::new("poison-every-n");
        let Some(three) = NonZeroU32::new(3) else {
            panic!("non-zero");
        };
        let config = dir.config_with(SyncPolicy::EveryN(three));
        let store = open(config.clone()).await;
        for seq in 1..=3 {
            file(&store, seq).await;
        }
        file(&store, 4).await;
        file(&store, 5).await;
        store.fail_next_flush().await;
        assert!(matches!(store.sync().await, Err(StoreError::Io(_))));
        ok(store.refresh().await, "refresh");
        // 4 and 5 were never flushed: after a failed flush they cannot be
        // vouched for, so they are gone, and so is the counter they carried.
        assert_eq!(seqs(&store, 1, 10, 10).await, vec![1, 2, 3]);
        assert_eq!(store.next_sender_seq(), 4);
    }

    #[tokio::test]
    async fn test_file_store_reset_runs_on_a_poisoned_store_and_clears_it() {
        let dir = TempDir::new("poison-reset");
        let config = dir.config();
        let store = open(config.clone()).await;
        file(&store, 1).await;
        store.fail_next_flush().await;
        assert!(store.set_next_target_seq(5).await.is_err());
        ok(
            store.reset_to(1, 1).await,
            "a reset runs on a poisoned store",
        );
        file(&store, 1).await;
        drop(store);
        let store = open(config).await;
        assert_eq!(seqs(&store, 1, 10, 10).await, vec![1]);
        assert_eq!(store.next_sender_seq(), 2);
        assert_eq!(store.next_target_seq(), 1);
    }

    #[tokio::test]
    async fn test_file_store_failed_directory_flush_poisons_until_refresh_flushes_it() {
        let dir = TempDir::new("dir-flush");
        let config = dir.config();
        let store = open(config.clone()).await;
        file(&store, 1).await;
        store.fail_next_dir_flush().await;
        assert!(matches!(
            store.reset_to(4, 5).await,
            Err(StoreError::Io(reason)) if reason.contains("directory")
        ));
        // The rename happened: the store reports the new stream...
        assert_eq!(store.next_sender_seq(), 4);
        // ...but is unusable until the rename is known to be durable.
        assert!(store.set_next_target_seq(6).await.is_err());
        ok(store.refresh().await, "refresh flushes the directory");
        ok(store.set_next_target_seq(6).await, "usable again");
        drop(store);
        let store = open(config).await;
        assert!(seqs(&store, 1, 10, 10).await.is_empty());
        assert_eq!(store.next_sender_seq(), 4);
        assert_eq!(store.next_target_seq(), 6);
    }

    #[tokio::test]
    async fn test_file_store_close_releases_the_lock_and_keeps_the_writes() {
        let dir = TempDir::new("close");
        let Some(ten) = NonZeroU32::new(10) else {
            panic!("non-zero");
        };
        let config = dir.config_with(SyncPolicy::EveryN(ten));
        let store = open(config.clone()).await;
        file(&store, 1).await;
        ok(store.close().await, "close");
        // Released at once: no call can still be holding it.
        let store = open(config).await;
        assert_eq!(seqs(&store, 1, 10, 10).await, vec![1]);
    }

    /// Polls `future` to completion on this thread, outside any Tokio
    /// runtime.
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        struct ThreadWaker(std::thread::Thread);
        impl std::task::Wake for ThreadWaker {
            fn wake(self: Arc<Self>) {
                self.0.unpark();
            }
        }
        let waker = std::task::Waker::from(Arc::new(ThreadWaker(std::thread::current())));
        let mut context = std::task::Context::from_waker(&waker);
        let mut future = std::pin::pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                std::task::Poll::Ready(output) => return output,
                std::task::Poll::Pending => std::thread::park(),
            }
        }
    }

    #[test]
    fn test_file_store_outside_a_tokio_runtime_is_an_error_not_a_panic() {
        let dir = TempDir::new("no-runtime");
        let runtime = ok(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build(),
            "runtime",
        );
        let store = runtime.block_on(open(dir.config()));
        // Polled by an executor that is not Tokio.
        assert!(matches!(
            block_on(store.set_next_target_seq(3)),
            Err(StoreError::Io(reason)) if reason.contains("Tokio runtime")
        ));
        assert!(matches!(
            block_on(FileStore::open(dir.config())),
            Err(StoreError::Io(reason)) if reason.contains("Tokio runtime")
        ));
        drop(store);
    }

    #[tokio::test]
    async fn test_file_store_dropped_file_outbound_lands_before_the_next_call() {
        let dir = TempDir::new("dropped-file-outbound");
        let config = dir.config();
        {
            let store = open(config.clone()).await;
            file(&store, 4).await;
            // The next call is held on its blocking thread with the lock, the
            // way a slow disk would hold it, and the caller gives up on it.
            store.stall_next_call(Duration::from_millis(300)).await;
            let abandoned = tokio::time::timeout(
                Duration::from_millis(50),
                store.file_outbound(5, &MsgType::NewOrderSingle, &frame(5), 6),
            )
            .await;
            assert!(
                abandoned.is_err(),
                "the call must have been dropped mid-flight"
            );
            // The engine then writes back the number it did not spend.
            ok(
                store.set_next_sender_seq(5).await,
                "write back the unspent number",
            );
            assert_eq!(store.next_sender_seq(), 5);
        }
        // On disk the dropped call came first: frame 5 is filed, and the later
        // write-back is the counter that survives.
        let store = open(config).await;
        assert_eq!(seqs(&store, 1, 10, 10).await, vec![4, 5]);
        assert_eq!(store.next_sender_seq(), 5);
    }

    #[tokio::test]
    async fn test_file_store_dropped_reset_to_lands_before_the_next_call() {
        let dir = TempDir::new("dropped-reset-to");
        let config = dir.config();
        {
            let store = open(config.clone()).await;
            for seq in 1..=3 {
                file(&store, seq).await;
            }
            store.stall_next_call(Duration::from_millis(300)).await;
            let abandoned =
                tokio::time::timeout(Duration::from_millis(50), store.reset_to(1, 2)).await;
            assert!(
                abandoned.is_err(),
                "the reset must have been dropped mid-flight"
            );
            file(&store, 1).await;
        }
        // Reset first, then the new stream's message 1: had the order been
        // reversed, the reset would have erased it.
        let store = open(config).await;
        let filed = ok(store.get_range(1, 0).await, "the new stream");
        assert_eq!(
            filed.iter().map(StoredMessage::seq_num).collect::<Vec<_>>(),
            vec![1]
        );
        assert_eq!(store.next_sender_seq(), 2);
        assert_eq!(store.next_target_seq(), 2);
    }

    #[tokio::test]
    async fn test_file_store_call_dropped_before_it_runs_writes_nothing() {
        let dir = TempDir::new("dropped-waiting");
        let config = dir.config();
        let store = Arc::new(open(config.clone()).await);
        store.stall_next_call(Duration::from_millis(300)).await;
        // The first call holds the lock on its blocking thread...
        let first = {
            let store = Arc::clone(&store);
            tokio::spawn(async move { store.set_next_target_seq(7).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        // ...so this one is still waiting for it when it is dropped.
        let waiting =
            tokio::time::timeout(Duration::from_millis(50), store.set_next_sender_seq(99)).await;
        assert!(waiting.is_err());
        ok(ok(first.await, "first call task"), "first call");
        drop(store);

        let store = open(config).await;
        assert_eq!(store.next_target_seq(), 7);
        assert_eq!(store.next_sender_seq(), 1, "the dropped call wrote nothing");
    }

    /// The permission bits of `path`.
    #[cfg(unix)]
    fn mode(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        ok(std::fs::metadata(path), "metadata").permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_file_store_creates_owner_only_files_and_directories() {
        let dir = TempDir::new("permissions");
        let Ok(config) = FileStoreConfig::try_new(dir.0.join("nested"), "session") else {
            panic!("valid name");
        };
        let store = open(config.clone().with_create_if_missing(true)).await;
        // A journal holds complete outbound frames, a Logon's Password
        // included: nobody but the owner reads it.
        assert_eq!(mode(&config.journal_path()), 0o600);
        assert_eq!(mode(&config.lock_path()), 0o600);
        assert_eq!(mode(&dir.0), 0o700);
        assert_eq!(mode(config.directory()), 0o700);
        file(&store, 1).await;
        assert_eq!(mode(&config.journal_path()), 0o600);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_file_store_reset_keeps_the_journal_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("permissions-reset");
        let config = dir.config();
        let store = open(config.clone()).await;
        file(&store, 1).await;
        ok(store.reset_to(2, 2).await, "reset_to");
        assert_eq!(mode(&config.journal_path()), 0o600);

        // A reset writes a new file: a leftover or loosened one never passes
        // its permissions on.
        ok(
            std::fs::set_permissions(
                config.journal_path(),
                std::fs::Permissions::from_mode(0o644),
            ),
            "loosen the journal",
        );
        ok(
            std::fs::write(config.temp_path(), b"leftover"),
            "a leftover temporary file",
        );
        ok(
            std::fs::set_permissions(config.temp_path(), std::fs::Permissions::from_mode(0o666)),
            "loosen the leftover",
        );
        ok(store.reset().await, "reset");
        assert_eq!(mode(&config.journal_path()), 0o600);
    }

    #[tokio::test]
    async fn test_file_store_record_cut_after_it_was_indexed_is_corrupted_not_io() {
        let dir = TempDir::new("cut-after-index");
        let config = dir.config();
        let store = open(config.clone()).await;
        for seq in 1..=3 {
            file(&store, seq).await;
        }
        // The journal is cut under the open store, inside record 3.
        cut_journal(&config, journal_len(&config) - 10);
        assert!(matches!(
            store.get_page(1, 3, 10).await,
            Err(StoreError::Corrupted { reason }) if reason.contains("MsgSeqNum 3")
        ));
        // Records before the cut are still served.
        assert_eq!(seqs(&store, 1, 2, 10).await, vec![1, 2]);
    }

    #[tokio::test]
    async fn test_file_store_failed_flush_during_refresh_cuts_back_and_poisons() {
        let dir = TempDir::new("refresh-flush");
        let Some(ten) = NonZeroU32::new(10) else {
            panic!("non-zero");
        };
        let config = dir.config_with(SyncPolicy::EveryN(ten));
        let store = open(config.clone()).await;
        let durable = journal_len(&config);
        file(&store, 1).await;
        file(&store, 2).await;
        store.fail_next_flush().await;
        // The refresh flushes the two pending writes and that flush fails.
        assert!(matches!(store.refresh().await, Err(StoreError::Io(_))));
        // Cut back to the last successful flush, and unusable until a refresh
        // has made the cut durable.
        assert_eq!(journal_len(&config), durable);
        assert!(matches!(
            store.set_next_target_seq(2).await,
            Err(StoreError::Io(_))
        ));
        assert!(matches!(
            store.get_page(1, 10, 10).await,
            Err(StoreError::Io(_))
        ));
        ok(
            store.refresh().await,
            "the second refresh completes the cut",
        );
        // The unflushed writes are never adopted again.
        assert!(seqs(&store, 1, 10, 10).await.is_empty());
        assert_eq!(store.next_sender_seq(), 1);
        file(&store, 1).await;
        drop(store);
        let store = open(config).await;
        assert_eq!(seqs(&store, 1, 10, 10).await, vec![1]);
    }

    #[tokio::test]
    async fn test_file_store_debug_names_the_store_without_frames() {
        let dir = TempDir::new("debug");
        let store = open(dir.config()).await;
        file(&store, 1).await;
        let rendered = format!("{store:?}");
        assert!(rendered.contains("FIX.4.4-CLIENT-VENUE"));
        assert!(rendered.contains("next_sender: 2"));
        assert!(!rendered.contains("ORDER-1"));
    }
}

/// Tests for the writer thread, the dense index, the counter slots,
/// compaction and the refusal of other format versions (#112, ADR-0022). The
/// #78 tests above run unchanged against the same store.
#[cfg(test)]
mod v2_tests {
    use super::*;
    use crate::file::format::HEADER_LEN;
    use std::num::NonZeroU64;
    use std::sync::atomic::AtomicUsize;
    use std::time::{Duration, Instant};

    #[track_caller]
    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("{what}: {err:?}"),
        }
    }

    /// A directory unique to one test, removed when the test ends.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(test: &str) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let unique = NEXT.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!(
                "ironfix-store-v2-{}-{test}-{unique}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            Self(path)
        }

        /// A configuration that creates the store on first open.
        fn config(&self) -> FileStoreConfig {
            self.existing().with_create_if_missing(true)
        }

        /// A configuration that only opens a store that already exists.
        fn existing(&self) -> FileStoreConfig {
            ok(
                FileStoreConfig::try_new(&self.0, "FIX.4.4-CLIENT-VENUE"),
                "test config",
            )
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn open(config: FileStoreConfig) -> FileStore {
        ok(FileStore::open(config).await, "the store must open")
    }

    fn journal_len(config: &FileStoreConfig) -> u64 {
        ok(std::fs::metadata(config.journal_path()), "journal metadata").len()
    }

    fn journal_bytes(config: &FileStoreConfig) -> Vec<u8> {
        ok(std::fs::read(config.journal_path()), "read the journal")
    }

    fn write_journal(config: &FileStoreConfig, bytes: &[u8]) {
        ok(
            std::fs::write(config.journal_path(), bytes),
            "rewrite the journal",
        );
    }

    fn frame(seq: u64) -> Vec<u8> {
        format!("8=FIX.4.4\x019=40\x0135=D\x0134={seq}\x0111=ORDER-{seq}\x0110=000\x01")
            .into_bytes()
    }

    async fn file(store: &FileStore, seq: u64) {
        ok(
            store
                .file_outbound(seq, &MsgType::NewOrderSingle, &frame(seq), seq + 1)
                .await,
            "file_outbound",
        );
    }

    async fn page(store: &FileStore) -> Vec<(u64, Vec<u8>)> {
        ok(store.get_page(1, u64::MAX, usize::MAX).await, "get_page")
            .iter()
            .map(|message| (message.seq_num(), message.payload().to_vec()))
            .collect()
    }

    /// The length of the record `file_outbound` writes for `frame(seq)`.
    fn record_len(seq: u64) -> u64 {
        let Ok(record) = format::encode_frame_record(
            seq,
            Some(seq + 1),
            &MsgType::NewOrderSingle,
            &frame(seq),
            u32::MAX,
        ) else {
            panic!("the record must encode");
        };
        record.len() as u64
    }

    /// The two counter slots as the journal holds them.
    fn slots_on_disk(config: &FileStoreConfig) -> [Option<Slot>; 2] {
        let bytes = journal_bytes(config);
        SLOT_OFFSETS.map(|offset| {
            let at = offset as usize;
            bytes
                .get(at..at + format::SLOT_LEN)
                .and_then(|slot| slot.first_chunk::<{ format::SLOT_LEN }>())
                .and_then(format::decode_slot)
        })
    }

    /// The position of the newest valid counter slot on disk.
    fn newest_on_disk(config: &FileStoreConfig) -> usize {
        let [first, second] = slots_on_disk(config);
        match (first, second) {
            (Some(first), Some(second)) if second.generation > first.generation => 1,
            (None, Some(_)) => 1,
            _ => 0,
        }
    }

    #[tokio::test]
    async fn test_file_store_inbound_counter_writes_do_not_grow_the_journal() {
        let dir = TempDir::new("no-growth");
        // The file's size is the point here, not its flushes: under
        // `EveryWrite` each of these writes would wait for one.
        let config = dir.config().with_sync_policy(SyncPolicy::Never);
        {
            let store = open(config.clone()).await;
            for seq in 1..=3 {
                file(&store, seq).await;
            }
            let after_frames = journal_len(&config);
            // A long run of inbound traffic: one target write per message, and
            // a few sender write-backs.
            for target in 2..=2_000 {
                ok(store.set_next_target_seq(target).await, "target counter");
            }
            ok(store.set_next_sender_seq(4).await, "sender counter");
            assert_eq!(
                journal_len(&config),
                after_frames,
                "counters live in fixed slots: the file does not grow"
            );
            assert_eq!(
                after_frames,
                DATA_START + (1..=3).map(record_len).sum::<u64>()
            );
        }
        let store = open(config).await;
        assert_eq!(store.next_target_seq(), 2_000);
        assert_eq!(store.next_sender_seq(), 4);
        assert_eq!(
            page(&store)
                .await
                .iter()
                .map(|(seq, _)| *seq)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[tokio::test]
    async fn test_file_store_torn_counter_slot_write_recovers_to_the_other_slot() {
        let dir = TempDir::new("torn-slot");
        let config = dir.config();
        let (before, after);
        {
            let store = open(config.clone()).await;
            file(&store, 1).await;
            ok(store.set_next_target_seq(5).await, "target 5");
            before = journal_bytes(&config);
            ok(store.set_next_target_seq(6).await, "target 6");
            after = journal_bytes(&config);
        }
        // The second write went to the slot that did not hold target 5.
        let written = newest_on_disk(&config);
        let start = SLOT_OFFSETS[written] as usize;
        let slot = start..start + format::SLOT_LEN;
        assert_ne!(before[slot.clone()], after[slot.clone()]);
        assert_eq!(before[..start], after[..start]);
        assert_eq!(before[slot.end..], after[slot.end..]);

        // A crash at every byte of that slot write: the new bytes up to the
        // cut, the old ones after it.
        for cut in 0..=format::SLOT_LEN {
            let mut torn = before.clone();
            torn[start..start + cut].copy_from_slice(&after[start..start + cut]);
            write_journal(&config, &torn);
            let store = open(config.clone()).await;
            let expected = if cut == format::SLOT_LEN { 6 } else { 5 };
            assert_eq!(store.next_target_seq(), expected, "torn at byte {cut}");
            assert_eq!(store.next_sender_seq(), 2, "torn at byte {cut}");
            assert_eq!(store.last_truncation(), None, "a torn slot is not a cut");
        }

        // A store opened over a torn slot writes its next counters there,
        // over the damage, and never over the slot it recovered from.
        let mut torn = after.clone();
        torn[start + 3] ^= 0xFF;
        write_journal(&config, &torn);
        {
            let store = open(config.clone()).await;
            assert_eq!(store.next_target_seq(), 5);
            ok(store.set_next_target_seq(7).await, "target 7");
            assert_eq!(newest_on_disk(&config), written);
            assert!(slots_on_disk(&config).iter().all(Option::is_some));
        }
        let store = open(config).await;
        assert_eq!(store.next_target_seq(), 7);
    }

    #[tokio::test]
    async fn test_file_store_both_counter_slots_damaged_is_refused_even_by_repair() {
        let dir = TempDir::new("both-slots");
        let config = dir.config();
        {
            let store = open(config.clone()).await;
            file(&store, 1).await;
        }
        let mut bytes = journal_bytes(&config);
        for offset in SLOT_OFFSETS {
            bytes[offset as usize + 1] ^= 0xFF;
        }
        write_journal(&config, &bytes);
        assert!(matches!(
            FileStore::open(config.clone()).await,
            Err(StoreError::Corrupted { reason }) if reason.contains("both counter slots")
        ));
        assert!(matches!(
            FileStore::repair(config.clone()).await,
            Err(StoreError::Corrupted { .. })
        ));
        assert_eq!(journal_bytes(&config), bytes, "refused, not changed");
    }

    #[tokio::test]
    async fn test_file_store_counter_slot_and_frame_record_are_ordered_by_generation() {
        let dir = TempDir::new("generation-order");
        let config = dir.config();
        {
            let store = open(config.clone()).await;
            file(&store, 5).await;
            // The unspent number written back after the frame record: the
            // slot is newer, so it wins.
            ok(store.set_next_sender_seq(5).await, "write back 5");
        }
        {
            let store = open(config.clone()).await;
            assert_eq!(store.next_sender_seq(), 5);
            ok(store.set_next_sender_seq(10).await, "seed 10");
            // Now the frame record is newer than the slot.
            file(&store, 10).await;
        }
        let store = open(config).await;
        assert_eq!(store.next_sender_seq(), 11);
        assert_eq!(
            page(&store)
                .await
                .iter()
                .map(|(seq, _)| *seq)
                .collect::<Vec<_>>(),
            vec![5, 10]
        );
    }

    #[tokio::test]
    async fn test_file_store_failed_flush_after_a_counter_write_puts_the_slots_back() {
        let dir = TempDir::new("slot-flush");
        let config = dir.config();
        let store = open(config.clone()).await;
        ok(store.set_next_target_seq(5).await, "target 5");
        let durable = journal_bytes(&config);
        store.fail_next_flush().await;
        assert!(store.set_next_target_seq(6).await.is_err());
        // Put back at once, and never published.
        assert_eq!(journal_bytes(&config), durable);
        assert_eq!(store.next_target_seq(), 5);
        assert!(store.set_next_target_seq(7).await.is_err(), "poisoned");
        ok(store.refresh().await, "refresh");
        assert_eq!(store.next_target_seq(), 5);
        ok(store.set_next_target_seq(8).await, "usable again");
        drop(store);
        let store = open(config).await;
        assert_eq!(store.next_target_seq(), 8);
    }

    #[tokio::test]
    async fn test_file_store_dense_index_for_consecutive_numbers() {
        let dir = TempDir::new("dense");
        let store = open(dir.config()).await;
        for seq in 1..=100 {
            file(&store, seq).await;
        }
        let (dense, chunks) = store
            .probe(|journal| (journal.index.is_dense(), journal.index.dense_chunks()))
            .await;
        assert!(dense);
        assert_eq!(chunks, 1, "one 4 096-slot chunk holds 100 numbers");
    }

    #[tokio::test]
    async fn test_file_store_huge_sequence_jump_falls_back_without_allocating_the_gap() {
        let dir = TempDir::new("jump");
        let config = dir.config();
        let far = 1_000_000_000_000_000;
        {
            let store = open(config.clone()).await;
            file(&store, 1).await;
            file(&store, 2).await;
            // 10^15 numbers skipped: 12 PB of slots, were they allocated.
            file(&store, far).await;
            let (dense, chunks) = store
                .probe(|journal| (journal.index.is_dense(), journal.index.dense_chunks()))
                .await;
            assert!(!dense);
            assert_eq!(chunks, 0);
            assert_eq!(
                page(&store).await,
                vec![(1, frame(1)), (2, frame(2)), (far, frame(far))]
            );
            assert_eq!(store.next_sender_seq(), far + 1);
        }
        // A journal holding the jump loads into the sparse index too.
        let store = open(config).await;
        assert!(!store.probe(|journal| journal.index.is_dense()).await);
        assert_eq!(
            page(&store)
                .await
                .iter()
                .map(|(seq, _)| *seq)
                .collect::<Vec<_>>(),
            vec![1, 2, far]
        );
        // The sparse index keeps the replace semantics.
        ok(
            store.store(2, &MsgType::Heartbeat, b"replaced").await,
            "replace 2",
        );
        assert_eq!(
            ok(store.get_range(2, 2).await, "range 2")
                .first()
                .map(|message| message.payload().to_vec()),
            Some(b"replaced".to_vec())
        );
    }

    /// Files 1 to 5, files 3 again three times, and sets the target counter.
    /// Returns what the store holds.
    async fn store_with_superseded_records(store: &FileStore) -> Vec<(u64, Vec<u8>)> {
        for seq in 1..=5 {
            file(store, seq).await;
        }
        for round in 0..3u8 {
            ok(
                store
                    .store(3, &MsgType::NewOrderSingle, &[b'0' + round; 30])
                    .await,
                "refile 3",
            );
        }
        ok(store.set_next_target_seq(9).await, "target counter");
        page(store).await
    }

    #[tokio::test]
    async fn test_file_store_compact_drops_only_superseded_records() {
        let dir = TempDir::new("compact");
        let config = dir.config();
        let (held, creation, compacted_len);
        {
            let store = open(config.clone()).await;
            creation = store.creation_time();
            held = store_with_superseded_records(&store).await;
            let before = journal_len(&config);
            let reclaimed = ok(store.compact().await, "compact");
            compacted_len = journal_len(&config);
            assert_eq!(reclaimed, before - compacted_len);
            // The four records filed under 3 before the last one.
            assert_eq!(reclaimed, record_len(3) + 2 * (12 + 1 + 8 + 1 + 1 + 30));
            assert!(!config.temp_path().exists());
            assert_eq!(page(&store).await, held);
            assert_eq!(store.next_sender_seq(), 6);
            assert_eq!(store.next_target_seq(), 9);
            // The compacted store takes writes as before.
            file(&store, 6).await;
            ok(store.set_next_target_seq(10).await, "target counter");
        }
        let store = open(config.clone()).await;
        assert_eq!(store.creation_time(), creation, "a compaction keeps it");
        assert_eq!(store.next_sender_seq(), 7);
        assert_eq!(store.next_target_seq(), 10);
        let mut expected = held;
        expected.push((6, frame(6)));
        assert_eq!(page(&store).await, expected);
        assert_eq!(journal_len(&config), compacted_len + record_len(6));
        // Nothing left to reclaim.
        assert_eq!(ok(store.compact().await, "second compaction"), 0);
    }

    #[tokio::test]
    async fn test_file_store_compaction_crash_at_each_step_recovers() {
        for step in [
            CompactionStep::Written,
            CompactionStep::Flushed,
            CompactionStep::Renamed,
        ] {
            let dir = TempDir::new("compact-crash");
            let config = dir.config();
            let (held, before);
            {
                let store = open(config.clone()).await;
                held = store_with_superseded_records(&store).await;
                before = journal_len(&config);
                store
                    .probe(move |journal| journal.probe.crash_compaction_after = Some(step))
                    .await;
                assert!(store.compact().await.is_err(), "{step:?}");
                // The crash: the process goes away here.
            }
            let renamed = step == CompactionStep::Renamed;
            assert_eq!(config.temp_path().exists(), !renamed, "{step:?}");
            let store = open(config.clone()).await;
            assert!(!config.temp_path().exists(), "{step:?}: removed at open");
            assert_eq!(
                journal_len(&config) < before,
                renamed,
                "{step:?}: the old journal before the rename, the new one after"
            );
            assert_eq!(page(&store).await, held, "{step:?}");
            assert_eq!(store.next_sender_seq(), 6, "{step:?}");
            assert_eq!(store.next_target_seq(), 9, "{step:?}");
            assert_eq!(store.last_truncation(), None, "{step:?}");
        }
    }

    #[tokio::test]
    async fn test_file_store_compacts_on_its_own_past_the_threshold() {
        let dir = TempDir::new("auto-compact");
        let config = dir.config().with_compaction_threshold(NonZeroU64::new(1));
        let store = open(config.clone()).await;
        for seq in 1..=3 {
            file(&store, seq).await;
        }
        let live = journal_len(&config);
        // Superseded bytes below the live ones: no compaction yet.
        file(&store, 2).await;
        file(&store, 2).await;
        assert_eq!(journal_len(&config), live + 2 * record_len(2));
        // The third refile makes them outweigh the live records; the
        // compaction runs after that call is answered, before the next one.
        file(&store, 2).await;
        let _ = store.flushes().await;
        assert_eq!(journal_len(&config), live);
        assert_eq!(
            page(&store).await,
            vec![(1, frame(1)), (2, frame(2)), (3, frame(3))]
        );
        assert_eq!(store.next_sender_seq(), 3);

        // Off: the same traffic is never compacted on its own.
        let dir = TempDir::new("no-auto-compact");
        let config = dir.config();
        let store = open(config.clone()).await;
        for seq in [1, 2, 3, 2, 2, 2] {
            file(&store, seq).await;
        }
        let _ = store.flushes().await;
        assert_eq!(journal_len(&config), live + 3 * record_len(2));
    }

    #[tokio::test]
    async fn test_file_store_drop_with_a_call_in_flight_does_not_wait_for_it() {
        let dir = TempDir::new("drop-busy");
        let config = dir.config();
        let store = open(config.clone()).await;
        store.stall_next_call(Duration::from_millis(400)).await;
        let abandoned = tokio::time::timeout(Duration::from_millis(50), file(&store, 1)).await;
        assert!(abandoned.is_err());
        let before = Instant::now();
        drop(store);
        assert!(
            before.elapsed() < Duration::from_millis(250),
            "the drop returned while the call still ran"
        );
        // The writer thread finishes the call, then closes the files and
        // releases the lock on its own.
        let deadline = Instant::now() + Duration::from_secs(10);
        let store = loop {
            match FileStore::open(config.clone()).await {
                Ok(store) => break store,
                Err(err) => {
                    assert!(Instant::now() < deadline, "never released: {err:?}");
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        };
        assert_eq!(page(&store).await, vec![(1, frame(1))]);
    }

    #[tokio::test]
    async fn test_file_store_unsupported_format_version_is_corrupted() {
        // Versions 2 (#112, no owed-reset flag) and 3 (#111, no inbound
        // watermark) were never released and are not migrated; version 5
        // does not exist yet.
        for version in [2u16, 3, 5] {
            let dir = TempDir::new(&format!("version-{version}"));
            let config = dir.config();
            drop(open(config.clone()).await);
            let mut bytes = journal_bytes(&config);
            bytes[8..10].copy_from_slice(&version.to_le_bytes());
            let crc = crc32::crc32(&bytes[..HEADER_LEN - 4]);
            bytes[HEADER_LEN - 4..HEADER_LEN].copy_from_slice(&crc.to_le_bytes());
            write_journal(&config, &bytes);
            assert!(matches!(
                FileStore::open(config.clone()).await,
                Err(StoreError::Corrupted { reason })
                    if reason.contains(&format!("version {version} is not supported"))
                        && reason.contains("never")
            ));
            assert_eq!(journal_bytes(&config), bytes, "refused, not changed");
        }
    }

    /// Rewrites the format version in the header of `config`'s journal, and
    /// seals the header again so the version is what the open checks.
    fn set_format_version(config: &FileStoreConfig, version: u16) -> Vec<u8> {
        let mut bytes = journal_bytes(config);
        bytes[8..10].copy_from_slice(&version.to_le_bytes());
        let crc = crc32::crc32(&bytes[..HEADER_LEN - 4]);
        bytes[HEADER_LEN - 4..HEADER_LEN].copy_from_slice(&crc.to_le_bytes());
        write_journal(config, &bytes);
        bytes
    }

    #[tokio::test]
    async fn test_file_store_version_one_journal_is_refused_not_migrated() {
        let dir = TempDir::new("version-1");
        let config = dir.config();
        {
            let store = open(config.clone()).await;
            file(&store, 1).await;
        }
        // The header of the never-released version-1 format, over whatever
        // follows it.
        let bytes = set_format_version(&config, 1);
        assert!(matches!(
            FileStore::open(config.clone()).await,
            Err(StoreError::Corrupted { reason }) if reason.contains("version 1 is not supported")
        ));
        assert!(matches!(
            FileStore::repair(config.clone()).await,
            Err(StoreError::Corrupted { reason }) if reason.contains("version 1")
        ));
        assert_eq!(journal_bytes(&config), bytes, "refused, not changed");
        assert!(!config.temp_path().exists(), "nothing was rewritten");
    }

    #[tokio::test]
    async fn test_file_store_failed_reload_after_an_undo_keeps_the_store_refusing_writes() {
        let dir = TempDir::new("reload-after-undo");
        let config = dir.config();
        let store = open(config.clone()).await;
        file(&store, 1).await;
        let durable = journal_len(&config);
        store.fail_next_flush().await;
        assert!(
            store
                .file_outbound(2, &MsgType::NewOrderSingle, &frame(2), 3)
                .await
                .is_err()
        );
        // The refresh makes the cut durable, then fails to reread the
        // journal: the in-memory end still points past the cut record.
        store
            .probe(|journal| journal.probe.fail_next_load = true)
            .await;
        assert!(matches!(
            store.refresh().await,
            Err(StoreError::Io(reason)) if reason.contains("injected load failure")
        ));
        assert_eq!(journal_len(&config), durable);
        // Still refused: an append now would land past the real end of the
        // file and leave a gap of zeros.
        assert!(store.set_next_target_seq(2).await.is_err());
        assert!(
            store
                .file_outbound(2, &MsgType::NewOrderSingle, &frame(2), 3)
                .await
                .is_err()
        );
        assert_eq!(journal_len(&config), durable);
        // A refresh that succeeds makes the store usable again.
        ok(store.refresh().await, "refresh");
        file(&store, 2).await;
        assert_eq!(journal_len(&config), durable + record_len(2));
        drop(store);
        let store = open(config.clone()).await;
        assert_eq!(page(&store).await, vec![(1, frame(1)), (2, frame(2))]);
        assert_eq!(store.last_truncation(), None, "no gap to cut");
    }

    /// Where the counter slot at `position` is in a journal image.
    fn slot_bytes(position: usize) -> std::ops::Range<usize> {
        let start = SLOT_OFFSETS[position] as usize;
        start..start + format::SLOT_LEN
    }

    /// Review thread 4307678227: under `EveryN`, counter writes made after a
    /// flush must never overwrite the slot holding the flushed checkpoint, so
    /// a power loss that discards, keeps or tears any of them recovers at
    /// least that checkpoint, and never refuses the journal.
    #[tokio::test]
    async fn test_file_store_unflushed_counter_writes_never_overwrite_the_flushed_slot() {
        let dir = TempDir::new("slot-rotation");
        let Some(three) = std::num::NonZeroU32::new(3) else {
            panic!("non-zero");
        };
        let config = dir.config().with_sync_policy(SyncPolicy::EveryN(three));
        let (durable, after_five, dirty);
        {
            let store = open(config.clone()).await;
            file(&store, 1).await;
            ok(store.set_next_target_seq(3).await, "target 3");
            ok(store.set_next_target_seq(4).await, "target 4");
            ok(
                store.sync().await,
                "flush: target 4 is the durable checkpoint",
            );
            durable = journal_bytes(&config);
            // Two acknowledged counter writes the policy leaves unflushed.
            ok(store.set_next_target_seq(5).await, "target 5");
            after_five = journal_bytes(&config);
            ok(store.set_next_target_seq(6).await, "target 6");
            dirty = journal_bytes(&config);
        }
        assert_eq!(durable.len(), dirty.len(), "counter writes append nothing");
        // Between flushes only one slot block is written, again and again:
        // the one that does not hold the flushed checkpoint. So no power loss
        // can tear both, or discard one write and tear the other.
        let changed: Vec<usize> = (0..2)
            .filter(|&position| durable[slot_bytes(position)] != dirty[slot_bytes(position)])
            .collect();
        assert_eq!(changed.len(), 1, "exactly one slot block is dirty");
        for position in 0..2 {
            if !changed.contains(&position) {
                assert_eq!(
                    durable[slot_bytes(position)],
                    after_five[slot_bytes(position)],
                    "the flushed checkpoint is never overwritten"
                );
            }
        }

        // Every way a power loss can leave each slot block: as flushed, after
        // the first unflushed write, after the second, or torn between any
        // two of those.
        let outcomes = |position: usize| -> Vec<Vec<u8>> {
            let range = slot_bytes(position);
            let states = [
                durable[range.clone()].to_vec(),
                after_five[range.clone()].to_vec(),
                dirty[range].to_vec(),
            ];
            let half = format::SLOT_LEN / 2;
            let mut all: Vec<Vec<u8>> = states.to_vec();
            for newer in &states {
                for older in &states {
                    let mut torn = newer[..half].to_vec();
                    torn.extend_from_slice(&older[half..]);
                    all.push(torn);
                }
            }
            all.sort();
            all.dedup();
            all
        };
        let mut images = 0;
        for first in outcomes(0) {
            for second in outcomes(1) {
                let mut image = durable.clone();
                image[slot_bytes(0)].copy_from_slice(&first);
                image[slot_bytes(1)].copy_from_slice(&second);
                write_journal(&config, &image);
                let opened = FileStore::open(config.clone()).await;
                let Ok(store) = opened else {
                    panic!("image {images}: the journal must open: {opened:?}");
                };
                assert!(
                    [4, 5, 6].contains(&store.next_target_seq()),
                    "image {images}: target {} is behind the flushed checkpoint 4",
                    store.next_target_seq()
                );
                assert_eq!(store.next_sender_seq(), 2, "image {images}");
                drop(store);
                images += 1;
            }
        }
        assert!(images >= 5, "the unflushed writes changed a slot");

        // After the next flush the writes move to the other slot.
        let store = open(config.clone()).await;
        let before = journal_bytes(&config);
        ok(store.set_next_target_seq(7).await, "target 7");
        ok(store.sync().await, "flush");
        ok(store.set_next_target_seq(8).await, "target 8");
        let now = journal_bytes(&config);
        drop(store);
        let moved: Vec<usize> = (0..2)
            .filter(|&position| before[slot_bytes(position)] != now[slot_bytes(position)])
            .collect();
        assert_eq!(moved, vec![0, 1], "one slot per flush interval");
    }

    /// Review thread 4307678262: a frame record damaged after a later
    /// counter write made it durable is damage to acknowledged data, not a
    /// torn tail: the journal is refused, as #78 refused it, rather than
    /// cut back behind counters that say the frame was filed. A repair
    /// salvages it, and leaves slots that no longer vouch for the cut frame.
    #[tokio::test]
    async fn test_file_store_damaged_frame_below_the_slots_durable_boundary_is_refused() {
        let dir = TempDir::new("durable-boundary");
        let config = dir.config();
        {
            let store = open(config.clone()).await;
            file(&store, 1).await;
            ok(store.set_next_target_seq(2).await, "target 2");
        }
        let mut bytes = journal_bytes(&config);
        // A payload byte of frame 1, the only record.
        let at = DATA_START as usize + 40;
        bytes[at] ^= 0x01;
        write_journal(&config, &bytes);
        let opened = FileStore::open(config.clone()).await;
        assert!(
            matches!(opened, Err(StoreError::Corrupted { ref reason }) if reason.contains("repair")),
            "{opened:?}"
        );
        assert_eq!(journal_bytes(&config), bytes, "refused, not cut");

        // The operator's repair cuts it and writes a new counter slot, so
        // the journal opens afterwards under the default policy.
        let repaired = ok(FileStore::repair(config.clone()).await, "repair");
        assert_eq!(repaired.map(|cut| cut.offset()), Some(DATA_START));
        let store = open(config).await;
        assert!(page(&store).await.is_empty());
        assert_eq!(store.next_target_seq(), 2);
    }

    #[tokio::test]
    async fn test_file_store_journal_cut_below_the_durable_boundary_is_refused() {
        let dir = TempDir::new("boundary-cut");
        let config = dir.config();
        {
            let store = open(config.clone()).await;
            file(&store, 1).await;
            file(&store, 2).await;
            ok(store.set_next_target_seq(2).await, "target 2");
        }
        // The file loses its last record whole, at a record boundary: nothing
        // looks torn, but the slots vouch for it.
        let cut = DATA_START + record_len(1);
        ok(
            OpenOptions::new()
                .write(true)
                .open(config.journal_path())
                .and_then(|file| file.set_len(cut)),
            "cut the journal",
        );
        assert!(matches!(
            FileStore::open(config.clone()).await,
            Err(StoreError::Corrupted { reason }) if reason.contains("journal ends")
        ));
    }

    #[tokio::test]
    async fn test_file_store_durable_boundary_follows_cut_backs_compactions_and_resets() {
        // After a failed flush cut the journal back, the boundary is no
        // higher than what is left: the journal reopens.
        let dir = TempDir::new("boundary-cut-back");
        let config = dir.config();
        {
            let store = open(config.clone()).await;
            file(&store, 1).await;
            ok(store.set_next_target_seq(2).await, "target 2");
            store.fail_next_flush().await;
            assert!(
                store
                    .file_outbound(2, &MsgType::NewOrderSingle, &frame(2), 3)
                    .await
                    .is_err()
            );
            ok(
                store.refresh().await,
                "refresh after the frame's failed flush",
            );
            store.fail_next_flush().await;
            assert!(store.set_next_target_seq(3).await.is_err());
            ok(
                store.refresh().await,
                "refresh after the counter's failed flush",
            );
        }
        let store = open(config.clone()).await;
        assert_eq!(page(&store).await, vec![(1, frame(1))]);
        assert_eq!(store.next_target_seq(), 2);
        drop(store);

        // A compaction's slots vouch for every record it copied: damage to
        // its last record is refused, not cut as a torn tail.
        let dir = TempDir::new("boundary-compaction");
        let config = dir.config();
        {
            let store = open(config.clone()).await;
            for seq in 1..=3 {
                file(&store, seq).await;
            }
            ok(store.compact().await, "compact");
        }
        let mut bytes = journal_bytes(&config);
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        write_journal(&config, &bytes);
        assert!(matches!(
            FileStore::open(config.clone()).await,
            Err(StoreError::Corrupted { reason }) if reason.contains("repair")
        ));

        // A reset starts a new boundary: the previous stream's does not
        // carry over, so the new stream's last record is a tail again.
        let dir = TempDir::new("boundary-reset");
        let config = dir.config();
        {
            let store = open(config.clone()).await;
            for seq in 1..=3 {
                file(&store, seq).await;
            }
            ok(store.set_next_target_seq(9).await, "target 9");
            ok(store.reset_to(5, 5).await, "reset");
            file(&store, 5).await;
        }
        let mut bytes = journal_bytes(&config);
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        write_journal(&config, &bytes);
        let store = open(config).await;
        assert!(page(&store).await.is_empty(), "the torn tail is cut");
        assert_eq!(
            store.last_truncation().map(|cut| cut.offset()),
            Some(DATA_START)
        );
    }

    #[tokio::test]
    async fn test_file_store_never_policy_cut_below_the_boundary_rewrites_the_slots() {
        let dir = TempDir::new("boundary-never");
        let config = dir.config();
        {
            let store = open(config.clone()).await;
            file(&store, 1).await;
            ok(store.set_next_target_seq(2).await, "target 2");
        }
        let mut bytes = journal_bytes(&config);
        bytes[DATA_START as usize + 40] ^= 0x01;
        write_journal(&config, &bytes);
        // `Never` cuts damage wherever it is, and then writes the slots
        // again, so the journal is consistent for any policy afterwards.
        {
            let store = open(config.clone().with_sync_policy(SyncPolicy::Never)).await;
            assert!(page(&store).await.is_empty());
            assert_eq!(store.next_target_seq(), 2);
        }
        let store = open(config).await;
        assert!(page(&store).await.is_empty());
        assert_eq!(store.next_target_seq(), 2);
    }

    /// Under `Never`, what was loaded at open was never flushed, so a counter
    /// slot written afterwards must not vouch for it: after a power loss that
    /// keeps the slot and loses the unflushed frames, a later open under a
    /// flushing policy cuts the torn tail instead of refusing the journal.
    #[tokio::test]
    async fn test_file_store_never_slot_does_not_vouch_for_records_it_never_flushed() {
        for cut_inside in [true, false] {
            let dir = TempDir::new("never-boundary");
            let never = dir.config().with_sync_policy(SyncPolicy::Never);
            // Run 1 files two frames and closes without a flush.
            {
                let store = open(never.clone()).await;
                file(&store, 1).await;
                file(&store, 2).await;
            }
            // Run 2 reopens under Never and writes a counter slot.
            {
                let store = open(never.clone()).await;
                ok(store.set_next_target_seq(5).await, "target 5");
            }
            // A power loss keeps the slot block and loses the frames written
            // without a flush: the file ends before what run 2 loaded.
            let cut = if cut_inside {
                DATA_START + record_len(1) + 5
            } else {
                DATA_START
            };
            ok(
                OpenOptions::new()
                    .write(true)
                    .open(never.journal_path())
                    .and_then(|file| file.set_len(cut)),
                "power loss",
            );
            // Run 3 opens under the default policy.
            let opened = FileStore::open(dir.config()).await;
            let Ok(store) = opened else {
                panic!("cut inside {cut_inside}: the journal must open: {opened:?}");
            };
            assert_eq!(store.next_target_seq(), 5, "the slot survived");
            let expected: Vec<(u64, Vec<u8>)> = if cut_inside {
                vec![(1, frame(1))]
            } else {
                Vec::new()
            };
            assert_eq!(page(&store).await, expected, "cut inside {cut_inside}");
        }
    }

    /// A failed flush puts back only the slot written since the last flush,
    /// and the refresh completing that undo writes no slot that already
    /// matches: the slot holding the durable checkpoint is never written.
    #[tokio::test]
    async fn test_file_store_failed_flush_never_writes_the_durable_checkpoint_slot() {
        let dir = TempDir::new("failed-flush-slots");
        let config = dir.config();
        let store = open(config.clone()).await;
        file(&store, 1).await;
        ok(store.set_next_target_seq(5).await, "target 5, flushed");
        let durable = newest_on_disk(&config);
        let before = store.probe(|journal| journal.probe.slot_writes).await;
        store.fail_next_flush().await;
        assert!(store.set_next_target_seq(6).await.is_err());
        ok(store.refresh().await, "refresh");
        let after = store.probe(|journal| journal.probe.slot_writes).await;
        assert_eq!(
            after[durable], before[durable],
            "the durable checkpoint slot was never written"
        );
        let dirty = 1 - durable;
        assert_eq!(
            after[dirty] - before[dirty],
            2,
            "the dirty slot: the counter write, then putting it back"
        );
        assert_eq!(store.next_target_seq(), 5);
        drop(store);
        let store = open(config).await;
        assert_eq!(store.next_target_seq(), 5);
    }

    /// A `Never` cut below the boundary writes one new slot, into the
    /// position that does not hold the newest slot, which stays as it was.
    #[tokio::test]
    async fn test_file_store_restamp_writes_one_slot_and_never_the_newest() {
        let dir = TempDir::new("restamp-one-slot");
        let config = dir.config();
        {
            let store = open(config.clone()).await;
            file(&store, 1).await;
            ok(store.set_next_target_seq(2).await, "target 2");
        }
        let mut bytes = journal_bytes(&config);
        bytes[DATA_START as usize + 40] ^= 0x01;
        write_journal(&config, &bytes);
        let newest = newest_on_disk(&config);
        let store = open(config.clone().with_sync_policy(SyncPolicy::Never)).await;
        let after = journal_bytes(&config);
        assert_eq!(
            after[slot_bytes(newest)],
            bytes[slot_bytes(newest)],
            "the newest slot is left as it was"
        );
        assert_ne!(after[slot_bytes(1 - newest)], bytes[slot_bytes(1 - newest)]);
        assert_eq!(newest_on_disk(&config), 1 - newest);
        assert_eq!(
            store.probe(|journal| journal.probe.slot_writes).await,
            {
                let mut writes = [0, 0];
                writes[1 - newest] = 1;
                writes
            },
            "one slot write, at open"
        );
        assert_eq!(store.next_target_seq(), 2);
    }

    // ---- Owed-reset marker (issue #111, ADR-0029) ----

    /// Whether both slots on disk decode and carry the marker as `owed`.
    fn marker_on_disk(config: &FileStoreConfig) -> [Option<bool>; 2] {
        slots_on_disk(config).map(|slot| slot.map(|slot| slot.reset_owed))
    }

    #[tokio::test]
    async fn test_file_store_reset_owed_marker_survives_reopen_reset_and_compaction() {
        let dir = TempDir::new("marker-durable");
        let config = dir.config();
        {
            let store = open(config.clone()).await;
            assert!(!store.reset_owed(), "a new journal owes nothing");
            file(&store, 1).await;
            ok(store.set_reset_owed(true).await, "set the marker");
            assert!(store.reset_owed());
            assert_eq!(marker_on_disk(&config), [Some(true), Some(true)]);
        }
        {
            let store = open(config.clone()).await;
            assert!(store.reset_owed(), "the marker survives a reopen");
            assert_eq!(store.next_sender_seq(), 2, "the counters are untouched");
            // A reset made under the marker keeps it: the reset is not yet
            // declared to the counterparty.
            ok(store.reset_to(2, 2).await, "reset");
            assert!(store.reset_owed());
            file(&store, 2).await;
            ok(store.compact().await, "compact");
            assert!(store.reset_owed(), "a compaction keeps the marker");
            ok(store.set_next_target_seq(3).await, "counter write");
        }
        {
            let store = open(config.clone()).await;
            assert!(store.reset_owed());
            assert_eq!(store.next_target_seq(), 3);
            ok(store.set_reset_owed(false).await, "clear the marker");
            assert_eq!(marker_on_disk(&config), [Some(false), Some(false)]);
        }
        let store = open(config).await;
        assert!(!store.reset_owed(), "the clear survives a reopen");
    }

    #[tokio::test]
    async fn test_file_store_app_watermark_survives_reopen_and_compaction_and_a_reset_clears_it() {
        let dir = TempDir::new("app-watermark");
        let config = dir.config();
        {
            let store = open(config.clone()).await;
            assert_eq!(store.app_watermark(), 0, "a new journal has no watermark");
            file(&store, 1).await;
            ok(store.set_next_target_seq(8).await, "counter write");
            ok(store.set_app_watermark(6).await, "set the watermark");
            assert_eq!(store.app_watermark(), 6);
            ok(
                store.set_next_target_seq(9).await,
                "a counter write carries it",
            );
        }
        {
            let store = open(config.clone()).await;
            assert_eq!(store.app_watermark(), 6, "the watermark survives a reopen");
            assert_eq!(store.next_target_seq(), 9, "the counters are untouched");
            file(&store, 2).await;
            ok(store.compact().await, "compact");
            assert_eq!(store.app_watermark(), 6, "a compaction keeps it");
        }
        {
            let store = open(config.clone()).await;
            assert_eq!(store.app_watermark(), 6, "kept across the compaction");
            ok(store.reset_to(2, 2).await, "reset");
            assert_eq!(store.app_watermark(), 0, "a reset clears it");
        }
        let store = open(config).await;
        assert_eq!(store.app_watermark(), 0, "the clear survives a reopen");
    }

    #[tokio::test]
    async fn test_file_store_app_watermark_costs_one_slot_write_under_the_sync_policy() {
        for (policy, flushes) in [(SyncPolicy::Never, 0), (SyncPolicy::EveryWrite, 1)] {
            let dir = TempDir::new("app-watermark-cost");
            let config = dir.config().with_sync_policy(policy);
            let store = open(config.clone()).await;
            let (journal, _) = store.flushes().await;
            ok(store.set_app_watermark(3).await, "set the watermark");
            let (after, _) = store.flushes().await;
            assert_eq!(after - journal, flushes, "{policy:?}: the policy decides");
            // The same value again writes nothing.
            ok(store.set_app_watermark(3).await, "set it again");
            assert_eq!(store.flushes().await.0, after, "{policy:?}: unchanged");
            drop(store);
            let store = open(config).await;
            assert_eq!(store.app_watermark(), 3, "{policy:?}: on disk once closed");
        }
    }

    #[tokio::test]
    async fn test_file_store_reset_owed_marker_is_flushed_under_every_policy() {
        for policy in [SyncPolicy::Never, SyncPolicy::EveryWrite] {
            let dir = TempDir::new("marker-flush");
            let config = dir.config().with_sync_policy(policy);
            let store = open(config.clone()).await;
            let (journal, _) = store.flushes().await;
            ok(store.set_reset_owed(true).await, "set the marker");
            let (after, _) = store.flushes().await;
            assert_eq!(after - journal, 2, "{policy:?}: one flush per slot");
            // Setting it again writes nothing.
            ok(store.set_reset_owed(true).await, "set it again");
            assert_eq!(store.flushes().await.0, after, "{policy:?}: no write");
        }
    }

    #[tokio::test]
    async fn test_file_store_reset_owed_marker_crash_between_the_two_slot_writes() {
        let dir = TempDir::new("marker-torn");
        let config = dir.config();
        let (before, after);
        {
            let store = open(config.clone()).await;
            file(&store, 1).await;
            before = journal_bytes(&config);
            ok(store.set_reset_owed(true).await, "set the marker");
            after = journal_bytes(&config);
        }
        // The first write goes to the slot that does not hold the newest
        // checkpoint; the second to the other one.
        let first = usize::from(newest_on_disk_of(&before) == 0);
        let second = 1 - first;
        let first_range = slot_bytes(first);

        // A crash at every byte of the first slot write: until it is whole the
        // previous checkpoint is the newest valid slot and nothing is owed;
        // the call had not returned, so the engine has not acted on it.
        for cut in 0..=format::SLOT_LEN {
            let mut torn = before.clone();
            torn[first_range.start..first_range.start + cut]
                .copy_from_slice(&after[first_range.start..first_range.start + cut]);
            write_journal(&config, &torn);
            let store = open(config.clone()).await;
            assert_eq!(
                store.reset_owed(),
                cut == format::SLOT_LEN,
                "torn at byte {cut}"
            );
            assert_eq!(store.next_sender_seq(), 2, "torn at byte {cut}");
        }

        // A crash during the second slot write: the first one already carries
        // the marker, so it is owed whatever the second holds.
        let second_range = slot_bytes(second);
        for cut in 0..=format::SLOT_LEN {
            let mut torn = before.clone();
            torn[first_range.clone()].copy_from_slice(&after[first_range.clone()]);
            torn[second_range.start..second_range.start + cut]
                .copy_from_slice(&after[second_range.start..second_range.start + cut]);
            write_journal(&config, &torn);
            let store = open(config.clone()).await;
            assert!(store.reset_owed(), "torn at byte {cut} of the second slot");
        }
    }

    /// The position of the newest valid slot in a journal image.
    fn newest_on_disk_of(bytes: &[u8]) -> usize {
        let mut images = [[0u8; format::SLOT_LEN]; 2];
        for (position, image) in images.iter_mut().enumerate() {
            image.copy_from_slice(&bytes[slot_bytes(position)]);
        }
        match format::newest_slot(&images) {
            Ok((position, _)) => position,
            Err(err) => panic!("no valid slot: {err:?}"),
        }
    }

    #[tokio::test]
    async fn test_file_store_reset_owed_marker_damaged_slot_fails_closed() {
        let dir = TempDir::new("marker-damage");
        let config = dir.config();
        {
            let store = open(config.clone()).await;
            file(&store, 1).await;
            ok(store.set_reset_owed(true).await, "set the marker");
        }
        let marked = journal_bytes(&config);

        // Either slot damaged after the marker was set: the other one still
        // carries it, so the reset stays owed.
        for position in 0..2 {
            let mut damaged = marked.clone();
            damaged[SLOT_OFFSETS[position] as usize + 33] ^= 0xFF;
            write_journal(&config, &damaged);
            let store = open(config.clone()).await;
            assert!(store.reset_owed(), "slot {position} damaged");
        }

        // A flag bit this version does not define makes the slot invalid,
        // even with a valid CRC: it is not read as "nothing owed".
        let mut unknown = marked.clone();
        let newest = newest_on_disk_of(&marked);
        let range = slot_bytes(newest);
        unknown[range.start + 40] = 0x03;
        let crc = crc32::crc32(&unknown[range.start..range.start + 48]);
        unknown[range.start + 48..range.end].copy_from_slice(&crc.to_le_bytes());
        write_journal(&config, &unknown);
        {
            let store = open(config.clone()).await;
            assert!(store.reset_owed(), "the other slot carries the marker");
        }

        // Both slots damaged: the journal is refused, never opened as owing
        // nothing.
        let mut both = marked.clone();
        for offset in SLOT_OFFSETS {
            both[offset as usize + 33] ^= 0xFF;
        }
        write_journal(&config, &both);
        assert!(matches!(
            FileStore::open(config.clone()).await,
            Err(StoreError::Corrupted { reason }) if reason.contains("both counter slots")
        ));
    }

    #[tokio::test]
    async fn test_file_store_reset_owed_marker_on_a_journal_left_unusable_refreshes_it() {
        let dir = TempDir::new("marker-unusable");
        let config = dir.config();
        let store = open(config.clone()).await;
        ok(store.set_next_target_seq(5).await, "target 5");
        store.fail_next_flush().await;
        assert!(store.set_next_target_seq(6).await.is_err());
        assert!(store.set_next_target_seq(7).await.is_err(), "unusable");
        // Setting the marker refreshes the journal first, then writes it.
        ok(store.set_reset_owed(true).await, "set the marker");
        assert!(store.reset_owed());
        assert_eq!(store.next_target_seq(), 5, "the failed write is undone");
        drop(store);
        let store = open(config).await;
        assert!(store.reset_owed());
    }

    #[tokio::test]
    async fn test_file_store_reset_owed_marker_failed_flush_reports_it_owed() {
        let dir = TempDir::new("marker-flush-fails");
        let config = dir.config();
        let store = open(config.clone()).await;
        store.fail_next_flush().await;
        assert!(store.set_reset_owed(true).await.is_err());
        // The slots may carry either value after the failure: the marker is
        // reported set, the safe direction.
        assert!(store.reset_owed());
        // A clear that fails leaves it set too.
        ok(store.refresh().await, "refresh");
        ok(store.set_reset_owed(true).await, "set the marker");
        store.fail_next_flush().await;
        assert!(store.set_reset_owed(false).await.is_err());
        assert!(store.reset_owed());
    }
}
