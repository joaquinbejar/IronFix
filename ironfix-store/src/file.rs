/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! A persistent, file-backed message store.
//!
//! [`FileStore`] keeps a session's outbound journal and both sequence counters
//! in one append-only file, so they survive a process restart: a session
//! started on a reopened store resumes from its counters, and a
//! `ResendRequest` (35=2) after a restart is answered with the original
//! frames. The design is recorded in `doc/adr/0006-file-store.md`.
//!
//! # Layout
//!
//! One journal file, `<directory>/<name>.journal` (see [`FileStoreConfig`]):
//! a header recording the creation time and the counters the journal starts
//! from, then a sequence of length-prefixed, CRC-checked records. A record is
//! a filed frame, a filed frame together with the next sender number (one
//! [`MessageStore::file_outbound`] call), or one counter. Loading replays the
//! records in order, so a later frame filed under a number replaces the
//! earlier one and a later counter value replaces the earlier one. The byte
//! layout is documented in the `format` module source and in ADR-0006.
//!
//! In memory the store keeps only an index from sequence number to the
//! record's position, plus the two counters; frames are read back from the
//! file when a resend asks for them, and checked again on the way.
//!
//! # Atomicity
//!
//! - [`MessageStore::file_outbound`] writes the frame and the next sender
//!   number as **one record**: after a crash both are in the journal or
//!   neither is.
//! - [`MessageStore::reset`] and [`MessageStore::reset_to`] write a complete
//!   new journal (header only, carrying the new counters) to
//!   `<name>.journal.tmp` and rename it over the journal: after a crash the
//!   store is entirely the old stream or entirely the new one.
//! - Every other write is one record.
//!
//! # Call order
//!
//! Calls run one at a time, in the order they were first polled, through an
//! internal first-in, first-out lock, and the file I/O of each call runs on a
//! blocking thread that holds that lock until the I/O is finished. A caller
//! may drop a call's future (the engine bounds every store call with a
//! timeout): a call dropped while it waits for the lock writes nothing, and a
//! call dropped once its I/O has started still completes it before any later
//! call starts. A dropped call can therefore take effect after reporting
//! nothing, but never after, or interleaved with, a later call.
//!
//! # Durability
//!
//! Every write reaches the operating system before its call returns, so
//! anything that returned `Ok` survives the process crashing. What survives
//! the operating system crashing or a power loss depends on the
//! [`SyncPolicy`]; only [`SyncPolicy::EveryWrite`] makes every `Ok` survive
//! it.
//!
//! # Recovery
//!
//! [`FileStore::open`] and [`MessageStore::refresh`] read the whole journal.
//! A record the file ends inside (a write a crash interrupted), or one whose
//! header or CRC check fails, is cut from the file together with everything
//! after it and is never returned; [`FileStore::last_truncation`] reports the
//! cut. A record whose header is well formed but declares a body larger than
//! the configured limit, a record that passes its CRC but does not decode,
//! and a header that is not a version-1 journal header are refused with
//! [`StoreError::Corrupted`]: the store does not open, and nothing is cut.
//!
//! # One store, one owner
//!
//! While a store is open it holds an advisory lock on `<name>.lock`
//! ([`std::fs::File::try_lock`]), so a second store opened on the same files,
//! in this process or another, fails with [`StoreError::Io`] instead of
//! interleaving two sequence streams in one journal.
//!
//! # Limits
//!
//! - The journal grows until it is reset: every counter write adds a 21-byte
//!   record, and a frame filed again under the same number leaves the earlier
//!   one in the file. There is no compaction.
//! - Opening and refreshing read the whole journal.
//! - A frame above [`FileStoreConfig::max_frame_size`] is refused.
//! - Inbound frames are not filed; only the target counter is kept.
//! - The directory is flushed after a rename on Unix only.

mod config;
mod crc32;
mod format;

pub use config::{
    DEFAULT_MAX_FRAME_SIZE, FileStoreConfig, FileStoreConfigError, MAX_FRAME_SIZE_LIMIT,
    MAX_STORE_NAME_LEN, SyncPolicy,
};
pub use format::{Truncation, TruncationCause};

use crate::file::format::{HEADER_LEN_U64, Header, IndexEntry, MAX_BODY_OVERHEAD, io_error};
use crate::stored::StoredMessage;
use crate::traits::MessageStore;
use async_trait::async_trait;
use ironfix_core::error::StoreError;
use ironfix_core::message::MsgType;
use parking_lot::{Mutex as SyncMutex, RwLock};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{BufReader, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;
use tokio::sync::{Mutex, OwnedMutexGuard};

/// A persistent [`MessageStore`] backed by one append-only journal file.
///
/// See the [module documentation](self) for the layout, the atomicity of each
/// call, the durability of each [`SyncPolicy`], and recovery.
///
/// # Example
///
/// ```no_run
/// use ironfix_store::{FileStore, FileStoreConfig, MessageStore};
/// use std::sync::Arc;
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let config = FileStoreConfig::try_new("/var/lib/ironfix", "FIX.4.4-CLIENT-VENUE")?;
/// let store: Arc<dyn MessageStore> = Arc::new(FileStore::open(config).await?);
/// // Attach it with `Initiator::with_store` or `Acceptor::with_store`.
/// # let _ = store;
/// # Ok(())
/// # }
/// ```
pub struct FileStore {
    /// The journal, behind the lock that orders every call.
    journal: Arc<Mutex<Journal>>,
    /// The values the synchronous getters read.
    shared: Arc<Shared>,
    /// The configuration the store was opened with.
    config: FileStoreConfig,
}

/// Values the synchronous trait getters read without taking the journal lock.
///
/// Only the journal writes them, after the change they describe is in the
/// file.
#[derive(Debug)]
struct Shared {
    /// Next sender sequence number.
    next_sender: AtomicU64,
    /// Next target sequence number.
    next_target: AtomicU64,
    /// Creation time of the journal.
    creation_time: RwLock<SystemTime>,
    /// The cut the last open or refresh made, if any.
    truncation: SyncMutex<Option<Truncation>>,
}

impl Shared {
    /// Publishes the state of a freshly loaded or replaced journal.
    fn publish(&self, header: &Header, next_sender: u64, next_target: u64) {
        self.next_sender.store(next_sender, Ordering::SeqCst);
        self.next_target.store(next_target, Ordering::SeqCst);
        *self.creation_time.write() = header.creation_time;
    }

    /// Publishes the state of a journal loaded from disk, and the cut its
    /// recovery made.
    fn install(&self, scan: &format::Scan) {
        self.publish(&scan.header, scan.next_sender, scan.next_target);
        *self.truncation.lock() = scan.truncation;
    }
}

/// The open journal: its file, the index of filed frames, and the bookkeeping
/// for the sync policy. Only ever touched on a blocking thread, behind the
/// journal lock.
#[derive(Debug)]
struct Journal {
    /// The configuration.
    config: FileStoreConfig,
    /// The journal file, open for reading and writing.
    file: File,
    /// The lock file, locked for as long as the journal is open.
    _lock: File,
    /// Every filed frame's record, by sequence number.
    index: BTreeMap<u64, IndexEntry>,
    /// File offset just past the last record: where the next one goes.
    end: u64,
    /// Records appended since the journal was last flushed, under
    /// [`SyncPolicy::EveryN`].
    unsynced: u32,
    /// Set when the file may no longer match the in-memory state (a failed
    /// flush, or a failed undo of a failed write). Every call but
    /// [`MessageStore::refresh`] then fails until a refresh reloads the file.
    poisoned: bool,
    /// The values the synchronous getters read.
    shared: Arc<Shared>,
    /// Test-only fault injection and flush counting; empty outside tests.
    probe: Probe,
}

/// Test-only fault injection and flush counting. Outside tests it has no
/// fields and its methods do nothing.
#[derive(Debug, Default)]
struct Probe {
    /// Holds the next call on its blocking thread for this long, with the
    /// journal lock held, before it does anything.
    #[cfg(test)]
    stall: Option<std::time::Duration>,
    /// Makes the next journal flush fail.
    #[cfg(test)]
    fail_next_flush: bool,
    /// Journal and replacement-file flushes made.
    #[cfg(test)]
    file_flushes: u64,
    /// Directory flushes made.
    #[cfg(test)]
    dir_flushes: u64,
}

impl Probe {
    /// Holds the calling blocking thread if a test asked for it.
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

    /// Counts a directory flush.
    #[allow(clippy::unused_self)]
    fn dir_flush(&mut self) {
        #[cfg(test)]
        {
            self.dir_flushes += 1;
        }
    }
}

impl Journal {
    /// Fails if a failed flush or undo left the journal unusable.
    fn usable(&self) -> Result<(), StoreError> {
        if self.poisoned {
            return Err(StoreError::Io(
                "the journal may not match the store after a failed write; refresh or reopen \
                 the store"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Appends one encoded record and flushes it as the policy requires.
    /// Returns the record's offset.
    ///
    /// A failed write is undone by cutting the file back to where the record
    /// started; if that fails too, or the flush fails, the journal is
    /// poisoned.
    fn append(&mut self, record: &[u8]) -> Result<u64, StoreError> {
        let offset = self.end;
        let new_end = u64::try_from(record.len())
            .ok()
            .and_then(|len| offset.checked_add(len))
            .ok_or_else(|| StoreError::Io("journal offset overflows".to_string()))?;
        let written = self
            .file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| self.file.write_all(record));
        if let Err(err) = written {
            if self.file.set_len(offset).is_err() {
                self.poisoned = true;
            }
            return Err(io_error("cannot append to the journal", &err));
        }
        self.end = new_end;
        match self.config.sync_policy() {
            SyncPolicy::EveryWrite => self.flush()?,
            SyncPolicy::EveryN(every) => {
                self.unsynced = self
                    .unsynced
                    .checked_add(1)
                    .ok_or_else(|| StoreError::Io("unflushed write count overflows".to_string()))?;
                if self.unsynced >= every.get() {
                    self.flush()?;
                }
            }
            SyncPolicy::Never => {}
        }
        Ok(offset)
    }

    /// Flushes the journal file's data to stable storage. A failure poisons
    /// the journal: after a failed flush the operating system may have
    /// dropped data that earlier writes reported as written.
    fn flush(&mut self) -> Result<(), StoreError> {
        if self.probe.journal_flush() {
            self.poisoned = true;
            return Err(StoreError::Io("injected flush failure".to_string()));
        }
        if let Err(err) = self.file.sync_data() {
            self.poisoned = true;
            return Err(io_error("cannot flush the journal", &err));
        }
        self.unsynced = 0;
        Ok(())
    }

    /// Indexes a frame record appended at `offset`.
    fn index_frame(&mut self, seq: u64, offset: u64, record: &[u8]) {
        self.index.insert(
            seq,
            IndexEntry {
                offset,
                body_len: format::record_body_len(record),
            },
        );
    }

    /// Reads at most `limit` filed frames in `begin..=end`, in ascending
    /// order.
    fn read(
        &mut self,
        begin: u64,
        end: u64,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        let mut messages = Vec::new();
        for (seq, entry) in self.index.range(begin..=end).take(limit) {
            messages.push(format::read_frame(&mut self.file, *seq, *entry)?);
        }
        Ok(messages)
    }

    /// Replaces the journal with an empty one starting from the given
    /// counters, through a new file renamed into place.
    fn replace(&mut self, next_sender: u64, next_target: u64) -> Result<(), StoreError> {
        let header = Header {
            creation_time: SystemTime::now(),
            next_sender,
            next_target,
        };
        let replaced = write_replacement(&self.config, &header, &mut self.probe);
        // The rename is the commit point. Past it, the journal on disk is the
        // new one whether or not the directory flush worked, so the store
        // switches to it before reporting a flush failure.
        let flushed = match replaced {
            Replacement::NotCommitted(err) => return Err(err),
            Replacement::Committed(flushed) => flushed,
        };
        match open_journal_file(&self.config) {
            Ok(file) => self.file = file,
            Err(err) => {
                self.poisoned = true;
                return Err(err);
            }
        }
        self.index.clear();
        self.end = HEADER_LEN_U64;
        self.unsynced = 0;
        self.poisoned = false;
        self.shared.publish(&header, next_sender, next_target);
        flushed
    }

    /// Reloads the journal from disk, cutting a damaged or incomplete tail.
    fn reload(&mut self) -> Result<(), StoreError> {
        let Loaded { file, scan } = load(&self.config, &mut self.probe)?;
        self.shared.install(&scan);
        self.file = file;
        self.index = scan.index;
        self.end = scan.end;
        self.unsynced = 0;
        self.poisoned = false;
        Ok(())
    }
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

/// Reads the journal from disk and cuts a damaged or incomplete tail.
fn load(config: &FileStoreConfig, probe: &mut Probe) -> Result<Loaded, StoreError> {
    let mut file = open_journal_file(config)?;
    let file_len = file
        .metadata()
        .map_err(|err| io_error("cannot read the journal's length", &err))?
        .len();
    let scan = format::scan(BufReader::new(&mut file), file_len, max_body(config))?;
    if let Some(truncation) = scan.truncation {
        file.set_len(truncation.offset())
            .map_err(|err| io_error("cannot cut the journal's damaged tail", &err))?;
        if config.sync_policy().flushes_replacements() {
            probe.file_flush();
            file.sync_data()
                .map_err(|err| io_error("cannot flush the journal's cut", &err))?;
        }
    }
    Ok(Loaded { file, scan })
}

/// How writing a replacement journal ended.
enum Replacement {
    /// Nothing changed on disk (but a leftover temporary file, removed at the
    /// next open).
    NotCommitted(StoreError),
    /// The replacement was renamed into place; the result is the directory
    /// flush that followed.
    Committed(Result<(), StoreError>),
}

/// Writes a journal holding only `header` to the temporary path, flushes it as
/// the policy requires, renames it over the journal, and flushes the
/// directory.
fn write_replacement(config: &FileStoreConfig, header: &Header, probe: &mut Probe) -> Replacement {
    let temp = config.temp_path();
    let flush = config.sync_policy().flushes_replacements();
    let written = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp)?;
        file.write_all(&format::encode_header(header))?;
        if flush {
            file.sync_all()?;
        }
        Ok::<(), std::io::Error>(())
    })();
    if let Err(err) = written {
        let _ = std::fs::remove_file(&temp);
        return Replacement::NotCommitted(io_error("cannot write the new journal", &err));
    }
    if flush {
        probe.file_flush();
    }
    if let Err(err) = std::fs::rename(&temp, config.journal_path()) {
        let _ = std::fs::remove_file(&temp);
        return Replacement::NotCommitted(io_error(
            "cannot rename the new journal into place",
            &err,
        ));
    }
    if !flush {
        return Replacement::Committed(Ok(()));
    }
    let flushed = flush_directory(config.directory());
    if cfg!(unix) && flushed.is_ok() {
        probe.dir_flush();
    }
    Replacement::Committed(flushed)
}

/// Flushes a directory, so a rename in it is durable.
#[cfg(unix)]
fn flush_directory(directory: &Path) -> Result<(), StoreError> {
    File::open(directory)
        .and_then(|dir| dir.sync_all())
        .map_err(|err| io_error("cannot flush the store directory", &err))
}

/// Flushes a directory, so a rename in it is durable. Not supported off Unix,
/// where a directory cannot be opened as a file.
#[cfg(not(unix))]
fn flush_directory(_directory: &Path) -> Result<(), StoreError> {
    Ok(())
}

/// Opens or creates the journal in `config`'s directory: takes the lock,
/// removes a replacement a crash left behind, creates an empty journal if
/// there is none, and loads it.
fn open_journal(config: FileStoreConfig, shared: Arc<Shared>) -> Result<Journal, StoreError> {
    std::fs::create_dir_all(config.directory()).map_err(|err| {
        io_error(
            &format!("cannot create {}", config.directory().display()),
            &err,
        )
    })?;

    let lock = OpenOptions::new()
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
        Err(TryLockError::Error(err)) => {
            return Err(io_error(
                &format!("cannot lock {}", config.lock_path().display()),
                &err,
            ));
        }
    }

    // A replacement that was never renamed into place is a reset that did not
    // happen.
    match std::fs::remove_file(config.temp_path()) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(io_error("cannot remove an unfinished reset", &err)),
    }

    let mut probe = Probe::default();

    let exists = config
        .journal_path()
        .try_exists()
        .map_err(|err| io_error("cannot look for the journal", &err))?;
    if !exists {
        let header = Header {
            creation_time: SystemTime::now(),
            next_sender: 1,
            next_target: 1,
        };
        match write_replacement(&config, &header, &mut probe) {
            Replacement::NotCommitted(err) | Replacement::Committed(Err(err)) => return Err(err),
            Replacement::Committed(Ok(())) => {}
        }
    }

    let Loaded { file, scan } = load(&config, &mut probe)?;
    shared.install(&scan);
    Ok(Journal {
        config,
        file,
        _lock: lock,
        index: scan.index,
        end: scan.end,
        unsynced: 0,
        poisoned: false,
        shared,
        probe,
    })
}

/// Reports a blocking task that did not run to completion.
#[cold]
#[inline(never)]
fn task_failed(err: &tokio::task::JoinError) -> StoreError {
    StoreError::Io(format!("file store task did not complete: {err}"))
}

impl FileStore {
    /// Opens the store `config` describes, creating its directory and an empty
    /// journal (both counters at 1) if they do not exist, and recovering the
    /// journal if they do.
    ///
    /// # Errors
    /// [`StoreError::Io`] if the files cannot be created, opened, read or
    /// locked, including when another `FileStore` already has them open;
    /// [`StoreError::Corrupted`] if the journal is not a readable version-1
    /// journal (see the [module documentation](self), "Recovery").
    pub async fn open(config: FileStoreConfig) -> Result<Self, StoreError> {
        let shared = Arc::new(Shared {
            next_sender: AtomicU64::new(1),
            next_target: AtomicU64::new(1),
            creation_time: RwLock::new(SystemTime::UNIX_EPOCH),
            truncation: SyncMutex::new(None),
        });
        let journal = {
            let config = config.clone();
            let shared = Arc::clone(&shared);
            tokio::task::spawn_blocking(move || open_journal(config, shared))
                .await
                .map_err(|err| task_failed(&err))??
        };
        Ok(Self {
            journal: Arc::new(Mutex::new(journal)),
            shared,
            config,
        })
    }

    /// Returns the configuration the store was opened with.
    #[must_use]
    pub const fn config(&self) -> &FileStoreConfig {
        &self.config
    }

    /// Returns the cut the last open or refresh made to the journal, or
    /// `None` if the journal was intact.
    ///
    /// `ironfix-store` does not log, so this is how a cut is reported: an
    /// application may log it, or refuse to start a session over a
    /// [`TruncationCause::Damaged`] one, which can have dropped records that
    /// were acknowledged.
    #[must_use]
    pub fn last_truncation(&self) -> Option<Truncation> {
        *self.shared.truncation.lock()
    }

    /// Flushes every write made so far to stable storage, whatever the
    /// [`SyncPolicy`].
    ///
    /// Under [`SyncPolicy::EveryN`] and [`SyncPolicy::Never`] this is how to
    /// make the writes so far survive an operating-system crash, for example
    /// when a session closes.
    ///
    /// # Errors
    /// [`StoreError::Io`] if the flush fails; the store then fails every call
    /// until [`MessageStore::refresh`] succeeds.
    pub async fn sync(&self) -> Result<(), StoreError> {
        self.run(|journal| {
            journal.usable()?;
            journal.flush()
        })
        .await
    }

    /// Runs `op` on the journal on a blocking thread, holding the journal lock
    /// from before the thread is started until `op` returns.
    ///
    /// The lock is first-in, first-out, so calls run in the order they were
    /// first polled. Dropping the returned future while it waits for the lock
    /// cancels the call; dropping it later does not stop `op`, which keeps the
    /// lock until it is done, so no later call can run before or beside it.
    async fn run<T, F>(&self, op: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Journal) -> Result<T, StoreError> + Send + 'static,
    {
        let guard: OwnedMutexGuard<Journal> = Arc::clone(&self.journal).lock_owned().await;
        tokio::task::spawn_blocking(move || {
            let mut journal = guard;
            journal.probe.stall();
            op(&mut journal)
        })
        .await
        .map_err(|err| task_failed(&err))?
    }

    /// Validates a range and runs a bounded read over it.
    async fn read(
        &self,
        begin: u64,
        end: u64,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        // `BTreeMap::range` panics on an inverted range, so it is refused
        // before the index is touched.
        if begin == 0 || begin > end {
            return Err(StoreError::InvalidRange { begin, end });
        }
        self.run(move |journal| {
            journal.usable()?;
            journal.read(begin, end, limit)
        })
        .await
    }

    /// Test-only: holds the next call on its blocking thread for `stall`,
    /// with the journal lock held.
    #[cfg(test)]
    async fn stall_next_call(&self, stall: std::time::Duration) {
        self.journal.lock().await.probe.stall = Some(stall);
    }

    /// Test-only: makes the next journal flush fail.
    #[cfg(test)]
    async fn fail_next_flush(&self) {
        self.journal.lock().await.probe.fail_next_flush = true;
    }

    /// Test-only: the (file, directory) flushes made so far.
    #[cfg(test)]
    async fn flushes(&self) -> (u64, u64) {
        let journal = self.journal.lock().await;
        (journal.probe.file_flushes, journal.probe.dir_flushes)
    }
}

/// Written by hand: the journal sits behind an async lock.
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
        let record = format::encode_frame_record(
            seq_num,
            None,
            msg_type,
            message,
            self.config.max_frame_size().get(),
        )?;
        self.run(move |journal| {
            journal.usable()?;
            let offset = journal.append(&record)?;
            journal.index_frame(seq_num, offset, &record);
            Ok(())
        })
        .await
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
    /// are read from the file.
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
        let record = format::encode_frame_record(
            seq_num,
            Some(next_sender),
            msg_type,
            message,
            self.config.max_frame_size().get(),
        )?;
        self.run(move |journal| {
            journal.usable()?;
            let offset = journal.append(&record)?;
            journal.index_frame(seq_num, offset, &record);
            journal
                .shared
                .next_sender
                .store(next_sender, Ordering::SeqCst);
            Ok(())
        })
        .await
    }

    fn next_sender_seq(&self) -> u64 {
        self.shared.next_sender.load(Ordering::SeqCst)
    }

    fn next_target_seq(&self) -> u64 {
        self.shared.next_target.load(Ordering::SeqCst)
    }

    async fn set_next_sender_seq(&self, seq: u64) -> Result<(), StoreError> {
        let record = format::encode_next_sender_record(seq);
        self.run(move |journal| {
            journal.usable()?;
            journal.append(&record)?;
            journal.shared.next_sender.store(seq, Ordering::SeqCst);
            Ok(())
        })
        .await
    }

    async fn set_next_target_seq(&self, seq: u64) -> Result<(), StoreError> {
        let record = format::encode_next_target_record(seq);
        self.run(move |journal| {
            journal.usable()?;
            journal.append(&record)?;
            journal.shared.next_target.store(seq, Ordering::SeqCst);
            Ok(())
        })
        .await
    }

    /// Replaces the journal with an empty one at 1/1 and a new creation time,
    /// atomically (see [`MessageStore::reset_to`]).
    async fn reset(&self) -> Result<(), StoreError> {
        self.reset_to(1, 1).await
    }

    /// Replaces the journal with an empty one starting from the given
    /// counters and a new creation time, in one atomic change: the new
    /// journal is written to a temporary file and renamed over the old one,
    /// so a crash leaves one or the other, never a mix.
    async fn reset_to(&self, next_sender: u64, next_target: u64) -> Result<(), StoreError> {
        self.run(move |journal| {
            journal.usable()?;
            journal.replace(next_sender, next_target)
        })
        .await
    }

    fn creation_time(&self) -> SystemTime {
        *self.shared.creation_time.read()
    }

    /// Rereads the journal from disk: the counters, the index and the creation
    /// time are replaced by what the file holds, and a damaged or incomplete
    /// tail is cut (see [`FileStore::last_truncation`]). This also clears the
    /// state a failed flush leaves behind.
    async fn refresh(&self) -> Result<(), StoreError> {
        self.run(Journal::reload).await
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

        fn config(&self) -> FileStoreConfig {
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

    #[tokio::test]
    async fn test_file_store_flipped_byte_fails_the_crc_and_is_never_returned() {
        let dir = TempDir::new("flipped");
        let config = dir.config();
        let after_one;
        {
            let store = open(config.clone()).await;
            file(&store, 1).await;
            after_one = journal_len(&config);
            file(&store, 2).await;
            file(&store, 3).await;
        }
        // Damage a frame byte inside record 2: it and everything after it go.
        let mut bytes = journal_bytes(&config);
        let at = usize::try_from(after_one).unwrap_or(usize::MAX) + 40;
        let Some(byte) = bytes.get_mut(at) else {
            panic!("record 2 must be longer than 40 bytes");
        };
        *byte ^= 0x01;
        write_journal(&config, &bytes);

        let store = open(config.clone()).await;
        assert_eq!(seqs(&store, 1, 10, 10).await, vec![1]);
        assert_eq!(store.next_sender_seq(), 2);
        assert_eq!(
            store.get_range(2, 3).await,
            Err(StoreError::RangeNotAvailable { begin: 2, end: 3 })
        );
        let Some(truncation) = store.last_truncation() else {
            panic!("the cut must be reported");
        };
        assert_eq!(truncation.cause(), TruncationCause::Damaged);
        assert_eq!(truncation.offset(), after_one);
        assert_eq!(journal_len(&config), after_one);
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

        // A clean refresh clears the report.
        ok(store.refresh().await, "second refresh");
        assert_eq!(store.last_truncation(), None);
    }

    #[tokio::test]
    async fn test_file_store_sync_policy_every_write_flushes_each_append() {
        let dir = TempDir::new("every-write");
        let store = open(dir.config_with(SyncPolicy::EveryWrite)).await;
        // Creating the journal flushed the new file (and, on Unix, its
        // directory).
        assert_eq!(store.flushes().await.0, 1);
        for seq in 1..=3 {
            file(&store, seq).await;
        }
        ok(store.set_next_target_seq(2).await, "target counter");
        assert_eq!(store.flushes().await.0, 5);
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
    async fn test_file_store_sync_policy_never_flushes_only_on_request() {
        let dir = TempDir::new("never");
        let config = dir.config_with(SyncPolicy::Never);
        {
            let store = open(config.clone()).await;
            assert_eq!(store.flushes().await, (0, 0), "not even at creation");
            for seq in 1..=5 {
                file(&store, seq).await;
            }
            ok(store.reset_to(3, 3).await, "reset_to");
            file(&store, 3).await;
            assert_eq!(store.flushes().await, (0, 0));
            ok(store.sync().await, "explicit sync");
            assert_eq!(store.flushes().await, (1, 0));
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
    async fn test_file_store_failed_flush_poisons_until_refresh() {
        let dir = TempDir::new("poison");
        let store = open(dir.config()).await;
        file(&store, 1).await;
        store.fail_next_flush().await;
        assert!(matches!(
            store
                .file_outbound(2, &MsgType::NewOrderSingle, &frame(2), 3)
                .await,
            Err(StoreError::Io(_))
        ));
        // The failed call did not advance the counter it reported failing.
        assert_eq!(store.next_sender_seq(), 2);
        // Every call fails until a refresh rereads the file.
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
        // The write reached the file before its flush failed, so the reload
        // finds it: the call took effect although it reported a failure.
        assert_eq!(seqs(&store, 1, 10, 10).await, vec![1, 2]);
        assert_eq!(store.next_sender_seq(), 3);
        file(&store, 3).await;
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
