/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/11/26
******************************************************************************/

//! A bounded submit/poll form of a [`SyncMessageStore`] (issue #222).
//!
//! [`SyncMessageStore::file_outbound`] completes or fails in one call, so a
//! busy-polled duty cycle that calls it waits for every write, a slow fsync
//! included. [`PendingStore`] moves the writes onto one worker thread of its
//! own and gives the caller two non-blocking calls instead:
//!
//! - [`PendingStore::submit`] queues one outbound frame under its sequence
//!   number and returns a [`Ticket`] at once, or
//!   [`PendingError::Full`] when the configured bound of in-flight writes
//!   is reached (or the retryable [`PendingError::Busy`] if the worker held
//!   the queue lock at that instant);
//! - [`PendingStore::poll_durable`] collects the writes the worker finished
//!   and reports the highest sequence number now durable. It never waits on
//!   the worker: if the worker is publishing an outcome at that instant, the
//!   poll collects nothing and the next one does.
//!
//! The session holds a frame off the wire until its sequence number is
//! durable, which keeps the engine's write order (file, persist, then
//! write) without blocking the duty cycle. [`PendingStore::drain`] blocks
//! until nothing is in flight, for shutdown.
//!
//! ## Guarantees
//!
//! [`PendingStore::new`] takes the store **by value**, so the wrapper is
//! its single outbound writer: no other handle can file a frame, move the
//! sender counter or reset it while the wrapper lives.
//!
//! - Sequence numbers are submitted contiguously from the store's next
//!   sender number at construction ([`PendingError::NotNext`] otherwise),
//!   so every number below the durable watermark was confirmed or is
//!   history the store held at construction.
//! - Writes run in submit order, one at a time, through
//!   [`SyncMessageStore::file_outbound`], which files the frame and then
//!   persists `seq + 1` as the next sender sequence number.
//! - "Durable" means what the inner store's `file_outbound` returning `Ok`
//!   means; for a store that does not sync to disk, that is nothing more
//!   than "applied".
//! - The store fails closed: the worker publishes a failed write at once,
//!   so every submit after it is refused with [`PendingError::Failed`]; any
//!   write already queued behind it is skipped (not applied); the error is
//!   returned once by [`PendingStore::poll_durable`] or
//!   [`PendingStore::drain`].
//! - Reads see confirmed frames only. [`PendingStore::get_range`] and
//!   [`PendingStore::get_page`] cap the range at the last confirmed
//!   sequence number that is both durable and **sent**: the driver reports
//!   each frame it wrote to the socket with [`PendingStore::mark_sent`],
//!   which refuses a number not yet durable. Before any, the cap is the
//!   history the store held at construction (every number below its next
//!   sender number then). A frame in flight, failed, or durable but not
//!   yet written is never returned, so a resend never replays a frame that
//!   may still go out under the same number.
//!   [`PendingStore::next_sender_seq`] is the confirmed (durable) counter.
//! - The target (inbound) counter goes through the same queue:
//!   [`PendingStore::submit_target`] queues it behind every write submitted
//!   before it, so it cannot persist ahead of an earlier outbound frame
//!   (the call-order rule of the [`traits`](crate::traits) module), with
//!   the same bound, `Busy` and fail-closed behaviour.
//!   It returns a [`TargetTicket`], checked with
//!   [`PendingStore::is_target_applied`];
//!   [`PendingStore::durable_target`] reports the last number applied.
//! - Sent reports are contiguous ([`PendingStore::mark_sent`] refuses a
//!   number that skips an unreported frame), so every readable frame was
//!   reported sent.
//! - Dropping a [`PendingStore`] finishes the writes already queued and
//!   joins the worker, so it blocks for up to the bound times one write.
//!
//! Each submit copies the frame into one owned buffer for the worker; the
//! queues themselves are reserved up front. Error values never contain frame
//! bytes or backend text: an outbound Logon carries `Password` (554), and a
//! custom store may quote the frame, so a failed write is reported with its
//! sequence number and the kind of error only.

use crate::stored::StoredMessage;
use crate::sync_traits::SyncMessageStore;
use ironfix_core::error::StoreError;
use ironfix_core::message::MsgType;
use parking_lot::{Condvar, Mutex};
use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

/// Why [`PendingStore::submit`] refused a write.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PendingError {
    /// `bound` writes are in flight; poll for durability before submitting
    /// again.
    #[error("pending store is full: {bound} writes in flight")]
    Full {
        /// The configured bound on in-flight writes.
        bound: usize,
    },
    /// A write failed earlier; the store refuses every later write.
    #[error("pending store refused the write: an earlier write failed")]
    Failed,
    /// The worker held the queue lock at that instant (it holds it only to
    /// take one job); nothing was queued. Retry on the next duty cycle.
    #[error("pending store queue is busy; retry")]
    Busy,
    /// The worker thread is gone.
    #[error("pending store worker has stopped")]
    Closed,
    /// `seq` is not the next contiguous sequence number. Submissions run
    /// from the store's next sender number at construction without a gap,
    /// so no frame left unconfirmed below a later one can be read back.
    #[error("sequence {seq} is not the next contiguous {expected}")]
    NotNext {
        /// The only sequence number `submit` accepts now.
        expected: u64,
        /// The sequence number refused.
        seq: u64,
    },
    /// [`PendingStore::mark_sent`] named a number that is not durable yet.
    #[error("sequence {seq} is not durable, so it cannot have been sent")]
    NotDurable {
        /// The sequence number refused.
        seq: u64,
    },
    /// `seq` is below the inner store's next sender sequence number at
    /// construction: that number is resend history.
    #[error("sequence {seq} is below the store's next sender sequence {next}")]
    BelowNextSender {
        /// The inner store's next sender sequence number at construction.
        next: u64,
        /// The sequence number refused.
        seq: u64,
    },
    /// `seq` is `u64::MAX`, so the next sender sequence number cannot be
    /// persisted.
    #[error("sequence {seq} leaves no next sender sequence number")]
    SequenceExhausted {
        /// The sequence number refused.
        seq: u64,
    },
}

/// Receipt for one submitted write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a ticket names the sequence number to wait on"]
pub struct Ticket {
    /// The sequence number the frame was submitted under.
    seq: u64,
}

impl Ticket {
    /// The sequence number the frame was submitted under; it is durable once
    /// [`PendingStore::durable`] reaches it.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }
}

/// Receipt for one target (inbound) counter write; see
/// [`PendingStore::is_target_applied`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a target ticket names the write to wait on"]
pub struct TargetTicket {
    /// The target sequence number submitted.
    seq: u64,
    /// The write's position among the target writes submitted.
    index: u64,
    /// The [`PendingStore`] instance that issued it.
    instance: u64,
}

impl TargetTicket {
    /// The target sequence number submitted.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }
}

/// One write handed to the worker.
enum Job {
    /// File an outbound frame and persist the next sender number.
    Outbound {
        seq: u64,
        msg_type: MsgType,
        message: Vec<u8>,
        next_sender: u64,
    },
    /// Persist the next target (inbound) number.
    Target { seq: u64 },
}

/// One write's outcome, sent back by the worker.
enum Done {
    /// `file_outbound` returned `Ok` for this sequence number.
    Filed(u64),
    /// `set_next_target_seq` returned `Ok` for this number.
    TargetSet(u64),
    /// `file_outbound` failed; the error is already sanitised.
    Failed(StoreError),
    /// Not applied: an earlier write failed.
    Skipped,
}

/// The worker's input.
struct Jobs {
    queue: VecDeque<Job>,
    /// Set by the caller's drop: finish the queue, then exit.
    closed: bool,
}

/// What the caller and the worker share. Every critical section is one push
/// or one pop; no guard is held across a store call.
struct Shared {
    jobs: Mutex<Jobs>,
    /// Signalled when a job is queued or the queue is closed.
    job_ready: Condvar,
    outcomes: Mutex<VecDeque<Done>>,
    /// Signalled when an outcome is pushed or the worker exits.
    outcome_ready: Condvar,
    /// Set by the worker the moment a write fails, before its outcome is
    /// collected, so a submit after it is refused at once.
    failed: AtomicBool,
    /// Set when the worker exits, however it exits, after its last push.
    stopped: AtomicBool,
}

/// Marks the worker stopped when it returns or unwinds.
struct Stopped<'a>(&'a Shared);

impl Drop for Stopped<'_> {
    fn drop(&mut self) {
        {
            // Under the job lock too, so an enqueue either lands before the
            // worker is gone or is refused with `Closed`.
            let _jobs = self.0.jobs.lock();
            self.0.stopped.store(true, Ordering::Release);
        }
        {
            // Under the lock, so a drain that saw the queue empty and the
            // flag clear is already waiting when it is notified.
            let _outcomes = self.0.outcomes.lock();
            self.0.stopped.store(true, Ordering::Release);
        }
        self.0.outcome_ready.notify_all();
    }
}

/// How long [`PendingStore::drain`] waits before re-checking the worker.
const DRAIN_RECHECK: Duration = Duration::from_millis(50);

/// A [`SyncMessageStore`] whose outbound writes are submitted and polled
/// rather than called; see the [module docs](self).
pub struct PendingStore<S: SyncMessageStore + 'static> {
    store: Arc<S>,
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
    bound: NonZeroUsize,
    in_flight: usize,
    /// The only sequence number `submit` accepts now.
    next_to_submit: u64,
    /// A failure collected by a poll that also reported progress; the next
    /// poll returns it.
    deferred: Option<StoreError>,
    /// The inner store's next sender number when this wrapper was built.
    floor: u64,
    durable: Option<u64>,
    /// The last frame the driver reported written to the socket.
    sent: Option<u64>,
    /// The last target number the worker applied.
    durable_target: Option<u64>,
    /// Target writes submitted, and applied, so far.
    targets_submitted: u64,
    targets_applied: u64,
    /// This instance's identity, stamped on its target tickets.
    instance: u64,
}

impl<S: SyncMessageStore + 'static> PendingStore<S> {
    /// Starts the worker thread for `store`, with at most `bound` writes in
    /// flight. The caller must make this the store's only outbound writer
    /// for as long as it lives (see the [module docs](self)).
    ///
    /// # Errors
    /// [`StoreError::InvalidRange`] if the store's next sender number is 0;
    /// [`StoreError::Io`] if the queues for `bound` writes cannot be
    /// reserved or the worker thread cannot be spawned.
    pub fn new(store: S, bound: NonZeroUsize) -> Result<Self, StoreError> {
        let jobs = reserve::<Job>(bound)?;
        let outcomes = reserve::<Done>(bound)?;
        // A frame already filed below the store's next sender number is
        // resend history; refilling it would replace the frame and move the
        // counter back. The number itself may be refilled (a crash between
        // filing and persisting the counter).
        let instance = next_instance()?;
        let floor = store.next_sender_seq();
        if floor == 0 {
            // Sequence 0 is never valid in FIX, and no resend read can
            // return it: refuse rather than confirm an unreplayable frame.
            return Err(StoreError::InvalidRange { begin: 0, end: 0 });
        }
        let store = Arc::new(store);
        let shared = Arc::new(Shared {
            jobs: Mutex::new(Jobs {
                queue: jobs,
                closed: false,
            }),
            job_ready: Condvar::new(),
            outcomes: Mutex::new(outcomes),
            outcome_ready: Condvar::new(),
            failed: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
        });
        let worker_store = Arc::clone(&store);
        let worker_shared = Arc::clone(&shared);
        let worker = std::thread::Builder::new()
            .name("ironfix-store-pending".to_owned())
            .spawn(move || run_worker(&*worker_store, &worker_shared))
            .map_err(|err| StoreError::Io(format!("spawn pending store worker: {err}")))?;
        Ok(Self {
            store,
            shared,
            worker: Some(worker),
            bound,
            in_flight: 0,
            next_to_submit: floor,
            deferred: None,
            sent: None,
            durable_target: None,
            targets_submitted: 0,
            targets_applied: 0,
            instance,
            floor,
            durable: None,
        })
    }

    /// Queues `message`, filed under `seq` as `msg_type`, and returns at
    /// once. `message` must be the complete frame, as for
    /// [`SyncMessageStore::store`].
    ///
    /// # Errors
    /// [`PendingError::Full`] when `bound` writes are in flight,
    /// [`PendingError::Failed`] after a failed write,
    /// [`PendingError::NotNext`] when `seq` is not the next contiguous
    /// number, [`PendingError::BelowNextSender`] when `seq` is below the
    /// store's next sender number at construction,
    /// [`PendingError::SequenceExhausted`] for `u64::MAX`,
    /// [`PendingError::Busy`] when the worker held the queue lock at that
    /// instant, and [`PendingError::Closed`] when the worker is gone.
    pub fn submit(
        &mut self,
        seq: u64,
        msg_type: &MsgType,
        message: &[u8],
    ) -> Result<Ticket, PendingError> {
        if self.is_failed() {
            return Err(PendingError::Failed);
        }
        if self.shared.stopped.load(Ordering::Acquire) {
            return Err(PendingError::Closed);
        }
        if self.in_flight >= self.bound.get() {
            return Err(PendingError::Full {
                bound: self.bound.get(),
            });
        }
        if seq < self.floor {
            return Err(PendingError::BelowNextSender {
                next: self.floor,
                seq,
            });
        }
        let Some(next_sender) = seq.checked_add(1) else {
            return Err(PendingError::SequenceExhausted { seq });
        };
        if seq != self.next_to_submit {
            return Err(PendingError::NotNext {
                expected: self.next_to_submit,
                seq,
            });
        }
        enqueue(&self.shared, || Job::Outbound {
            seq,
            msg_type: msg_type.clone(),
            message: message.to_vec(),
            next_sender,
        })?;
        // `in_flight < bound <= usize::MAX`, checked above.
        self.in_flight += 1;
        self.next_to_submit = next_sender;
        Ok(Ticket { seq })
    }

    /// Collects the writes the worker has finished, without blocking.
    ///
    /// Returns `Some(seq)` when the durable sequence number advanced to
    /// `seq`, `None` when it did not.
    ///
    /// # Errors
    /// The [`StoreError`] of a failed write, once; the store then refuses
    /// every later submit. When the same poll also confirmed earlier writes,
    /// it returns that progress and the next poll returns the error. [`StoreError::Io`] if the worker stopped with
    /// writes in flight.
    pub fn poll_durable(&mut self) -> Result<Option<u64>, StoreError> {
        if let Some(err) = self.deferred.take() {
            return Err(err);
        }
        let before = self.durable;
        while self.in_flight > 0 {
            // `try_lock`: the worker holds the lock only to push, and a poll
            // must not wait for it.
            let (next, stopped) = match self.shared.outcomes.try_lock() {
                Some(mut outcomes) => (
                    outcomes.pop_front(),
                    self.shared.stopped.load(Ordering::Acquire),
                ),
                None => break,
            };
            let failure = match next {
                Some(done) => self.apply(done).err(),
                // Read under the lock, after the worker's last push: final.
                None if stopped => Some(self.worker_lost()),
                None => break,
            };
            if let Some(err) = failure {
                if self.durable == before {
                    return Err(err);
                }
                // Report this poll's progress first; the error comes next.
                self.deferred = Some(err);
                break;
            }
        }
        Ok(if self.durable == before {
            None
        } else {
            self.durable
        })
    }

    /// Blocks until no write is in flight, and returns the highest durable
    /// sequence number.
    ///
    /// # Errors
    /// As [`PendingStore::poll_durable`]; on a failed write it still waits
    /// for the skipped writes queued behind it before returning the error.
    pub fn drain(&mut self) -> Result<Option<u64>, StoreError> {
        let mut first_error = self.deferred.take();
        while self.in_flight > 0 {
            let next = {
                let mut outcomes = self.shared.outcomes.lock();
                loop {
                    if let Some(done) = outcomes.pop_front() {
                        break Some(done);
                    }
                    if self.shared.stopped.load(Ordering::Acquire) {
                        break None;
                    }
                    let _ = self
                        .shared
                        .outcome_ready
                        .wait_for(&mut outcomes, DRAIN_RECHECK);
                }
            };
            match next {
                Some(done) => {
                    if let Err(err) = self.apply(done) {
                        first_error.get_or_insert(err);
                    }
                }
                None => {
                    let err = self.worker_lost();
                    first_error.get_or_insert(err);
                }
            }
        }
        match first_error {
            Some(err) => Err(err),
            None => Ok(self.durable),
        }
    }

    /// The highest sequence number whose write is durable, if any.
    #[must_use]
    pub const fn durable(&self) -> Option<u64> {
        self.durable
    }

    /// Writes submitted and not yet collected by a poll.
    #[must_use]
    pub const fn in_flight(&self) -> usize {
        self.in_flight
    }

    /// The configured bound on in-flight writes.
    #[must_use]
    pub const fn bound(&self) -> NonZeroUsize {
        self.bound
    }

    /// Whether a write failed; every later submit is refused.
    #[must_use]
    pub fn is_failed(&self) -> bool {
        self.shared.failed.load(Ordering::Acquire)
    }

    /// The last readable outbound sequence number: the sent watermark
    /// (never above the durable one), or the history held at construction.
    fn confirmed(&self) -> Option<u64> {
        let history = self.floor.checked_sub(1).filter(|&seq| seq > 0);
        match (self.sent, history) {
            (Some(sent), Some(history)) => Some(sent.max(history)),
            (sent, history) => sent.or(history),
        }
    }

    /// Records that the frame under `seq` was written to the socket, so a
    /// resend may read it. Reports are contiguous: `seq` must be the number
    /// right after the last readable one, so no frame is made readable
    /// without its own report. Reporting a number already readable is a
    /// no-op.
    ///
    /// # Errors
    /// [`PendingError::NotNext`] when `seq` skips an unreported frame;
    /// [`PendingError::NotDurable`] when `seq` is above the durable
    /// watermark: a frame must be durable before it is sent.
    pub fn mark_sent(&mut self, seq: u64) -> Result<(), PendingError> {
        let expected = match self.confirmed() {
            Some(readable) => match readable.checked_add(1) {
                Some(next) => next,
                None => return Ok(()),
            },
            None => 1,
        };
        if seq < expected {
            return Ok(());
        }
        if seq != expected {
            return Err(PendingError::NotNext { expected, seq });
        }
        if self.durable.is_none_or(|durable| seq > durable) {
            return Err(PendingError::NotDurable { seq });
        }
        self.sent = Some(seq);
        Ok(())
    }

    /// The last frame reported with [`PendingStore::mark_sent`].
    #[must_use]
    pub const fn sent(&self) -> Option<u64> {
        self.sent
    }

    /// Queues the next target (inbound) sequence number behind every write
    /// submitted before it, and returns at once. Its durability is
    /// collected by [`PendingStore::poll_durable`]; check the returned
    /// [`TargetTicket`] with [`PendingStore::is_target_applied`].
    ///
    /// # Errors
    /// As [`PendingStore::submit`]: [`PendingError::Full`],
    /// [`PendingError::Busy`], [`PendingError::Failed`] and
    /// [`PendingError::Closed`].
    pub fn submit_target(&mut self, seq: u64) -> Result<TargetTicket, PendingError> {
        if self.is_failed() {
            return Err(PendingError::Failed);
        }
        if self.shared.stopped.load(Ordering::Acquire) {
            return Err(PendingError::Closed);
        }
        if self.in_flight >= self.bound.get() {
            return Err(PendingError::Full {
                bound: self.bound.get(),
            });
        }
        let Some(index) = self.targets_submitted.checked_add(1) else {
            return Err(PendingError::SequenceExhausted { seq });
        };
        enqueue(&self.shared, || Job::Target { seq })?;
        // `in_flight < bound <= usize::MAX`, checked above.
        self.in_flight += 1;
        self.targets_submitted = index;
        Ok(TargetTicket {
            seq,
            index,
            instance: self.instance,
        })
    }

    /// Whether the target write behind `ticket` has been applied, as of
    /// the last poll. Target writes run in submit order, so a later one
    /// being applied implies this one was. A ticket issued by another
    /// [`PendingStore`] is never reported applied.
    #[must_use]
    pub const fn is_target_applied(&self, ticket: &TargetTicket) -> bool {
        ticket.instance == self.instance && self.targets_applied >= ticket.index
    }

    /// The last target number the worker applied, as of the last poll.
    #[must_use]
    pub const fn durable_target(&self) -> Option<u64> {
        self.durable_target
    }

    /// The end of `begin..=end` (`end` 0 meaning infinity) capped at the
    /// last confirmed number, or `None` when nothing in it is confirmed.
    fn capped(&self, begin: u64, end: u64) -> Result<Option<u64>, StoreError> {
        if begin == 0 || (end != 0 && begin > end) {
            return Err(StoreError::InvalidRange { begin, end });
        }
        let Some(confirmed) = self.confirmed() else {
            return Ok(None);
        };
        let capped = if end == 0 || end > confirmed {
            confirmed
        } else {
            end
        };
        Ok((begin <= capped).then_some(capped))
    }

    /// Confirmed frames in `begin..=end` (`end` 0 meaning infinity), as
    /// [`SyncMessageStore::get_range`]; frames submitted but not confirmed
    /// are never returned (see the [module docs](self)).
    ///
    /// # Errors
    /// [`StoreError::InvalidRange`] for `begin` 0 or above `end`,
    /// [`StoreError::RangeNotAvailable`] when nothing confirmed is in the
    /// range, or the inner store's error.
    pub fn get_range(&self, begin: u64, end: u64) -> Result<Vec<StoredMessage>, StoreError> {
        match self.capped(begin, end)? {
            Some(capped) => self
                .store
                .get_range(begin, capped)
                .map_err(|err| sanitise_read(begin, err)),
            None => Err(StoreError::RangeNotAvailable { begin, end }),
        }
    }

    /// Up to `limit` confirmed frames in `begin..=end` (`end` absolute,
    /// never infinity), as
    /// [`SyncMessageStore::get_page`]; an empty page when nothing
    /// confirmed is in the range.
    ///
    /// # Errors
    /// [`StoreError::InvalidRange`] for `begin` 0 or above `end`, or the
    /// inner store's error.
    pub fn get_page(
        &self,
        begin: u64,
        end: u64,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        // `end` is absolute here: 0 is not infinity (see the trait).
        if begin == 0 || begin > end {
            return Err(StoreError::InvalidRange { begin, end });
        }
        match self.capped(begin, end)? {
            Some(capped) => self
                .store
                .get_page(begin, capped, limit)
                .map_err(|err| sanitise_read(begin, err)),
            None => Ok(Vec::new()),
        }
    }

    /// The confirmed next sender sequence number: one above the durable
    /// watermark, or the store's next sender number at construction.
    #[must_use]
    pub fn next_sender_seq(&self) -> u64 {
        match self.durable {
            // `submit` refuses `u64::MAX`, so a durable number has a next.
            Some(seq) => match seq.checked_add(1) {
                Some(next) => next,
                None => {
                    debug_assert!(false, "durable u64::MAX");
                    self.floor
                }
            },
            None => self.floor,
        }
    }

    /// The inner store's next target (inbound) sequence number, as last
    /// applied by the worker.
    #[must_use]
    pub fn next_target_seq(&self) -> u64 {
        self.store.next_target_seq()
    }

    /// The inner store's creation time.
    #[must_use]
    pub fn creation_time(&self) -> std::time::SystemTime {
        self.store.creation_time()
    }

    fn apply(&mut self, done: Done) -> Result<(), StoreError> {
        // `in_flight > 0` whenever an outcome arrives: one per submit.
        match self.in_flight.checked_sub(1) {
            Some(n) => self.in_flight = n,
            None => debug_assert!(false, "outcome with nothing in flight"),
        }
        match done {
            Done::Filed(seq) => {
                self.durable = Some(seq);
                Ok(())
            }
            Done::TargetSet(seq) => {
                self.durable_target = Some(seq);
                // One per submitted target, at most `targets_submitted`.
                match self.targets_applied.checked_add(1) {
                    Some(applied) => self.targets_applied = applied,
                    None => debug_assert!(false, "more targets applied than submitted"),
                }
                Ok(())
            }
            Done::Failed(err) => {
                self.shared.failed.store(true, Ordering::Release);
                Err(err)
            }
            Done::Skipped => Ok(()),
        }
    }

    fn worker_lost(&mut self) -> StoreError {
        self.shared.failed.store(true, Ordering::Release);
        self.in_flight = 0;
        StoreError::Io("pending store worker stopped with writes in flight".to_owned())
    }
}

impl<S: SyncMessageStore + 'static> Drop for PendingStore<S> {
    fn drop(&mut self) {
        // The worker finishes what is queued, then exits.
        self.shared.jobs.lock().closed = true;
        self.shared.job_ready.notify_all();
        if let Some(worker) = self.worker.take() {
            // A worker that panicked has nothing left to finish.
            let _ = worker.join();
        }
    }
}

impl<S: SyncMessageStore + 'static> std::fmt::Debug for PendingStore<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingStore")
            .field("bound", &self.bound)
            .field("in_flight", &self.in_flight)
            .field("durable", &self.durable)
            .field("failed", &self.is_failed())
            .finish_non_exhaustive()
    }
}

/// An empty queue with room for `bound` entries, or an error instead of
/// the allocation panic `with_capacity` would raise.
fn reserve<T>(bound: NonZeroUsize) -> Result<VecDeque<T>, StoreError> {
    let mut queue = VecDeque::new();
    queue.try_reserve_exact(bound.get()).map_err(|err| {
        StoreError::Io(format!(
            "reserve pending store queue for {bound} writes: {err}"
        ))
    })?;
    Ok(queue)
}

/// Queues the job built by `job`, or refuses it. `try_lock`: the worker
/// holds the lock only to pop or to publish a failure, and a submit must
/// not wait for it. The worker publishes a failure under this lock, so
/// under it the flag is exact: a job is either queued before the failure
/// was published or refused with [`PendingError::Failed`].
fn enqueue(shared: &Shared, job: impl FnOnce() -> Job) -> Result<(), PendingError> {
    let Some(mut jobs) = shared.jobs.try_lock() else {
        return Err(PendingError::Busy);
    };
    if shared.failed.load(Ordering::Acquire) {
        return Err(PendingError::Failed);
    }
    if shared.stopped.load(Ordering::Acquire) {
        return Err(PendingError::Closed);
    }
    // One push into reserved capacity (the caller checked the bound).
    jobs.queue.push_back(job());
    drop(jobs);
    shared.job_ready.notify_one();
    Ok(())
}

/// Source of [`PendingStore`] instance identities.
static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);

/// A fresh instance identity, never reused in this process.
fn next_instance() -> Result<u64, StoreError> {
    NEXT_INSTANCE
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .map_err(|_| StoreError::Io("pending store instance ids exhausted".to_owned()))
}

/// A read error without backend text: the structured range and lookup
/// errors pass through; anything else keeps only its kind.
fn sanitise_read(begin: u64, err: StoreError) -> StoreError {
    let kind = match err {
        StoreError::InvalidRange { .. }
        | StoreError::RangeNotAvailable { .. }
        | StoreError::NotFound { .. }
        | StoreError::Timeout { .. } => return err,
        StoreError::RetrieveFailed { .. } => "retrieve failed",
        StoreError::Corrupted { .. } => "store corrupted",
        StoreError::Io(_) => "i/o error",
        _ => "store error",
    };
    StoreError::RetrieveFailed {
        seq_num: begin,
        reason: format!("inner store read failed ({kind})"),
    }
}

/// Replaces a backend error with one that carries no backend text; only
/// the kind of error and the sequence number survive.
fn sanitise(seq_num: u64, err: &StoreError) -> StoreError {
    let kind = match err {
        StoreError::Timeout { timeout } => return StoreError::Timeout { timeout: *timeout },
        StoreError::StoreFailed { .. } => "store failed",
        StoreError::Corrupted { .. } => "store corrupted",
        StoreError::Io(_) => "i/o error",
        _ => "store error",
    };
    StoreError::StoreFailed {
        seq_num,
        reason: format!("inner store write failed ({kind})"),
    }
}

/// Applies the queued writes in order; after a failure, skips the rest.
/// Returns once the caller closed the queue and it is empty.
fn run_worker<S: SyncMessageStore>(store: &S, shared: &Shared) {
    let _stopped = Stopped(shared);
    let mut failed = false;
    loop {
        let job = {
            let mut jobs = shared.jobs.lock();
            loop {
                if let Some(job) = jobs.queue.pop_front() {
                    break job;
                }
                if jobs.closed {
                    return;
                }
                shared.job_ready.wait(&mut jobs);
            }
        };
        let done = if failed {
            Done::Skipped
        } else {
            let (seq, result, ok) = match job {
                Job::Outbound {
                    seq,
                    msg_type,
                    message,
                    next_sender,
                } => (
                    seq,
                    store.file_outbound(seq, &msg_type, &message, next_sender),
                    Done::Filed(seq),
                ),
                Job::Target { seq } => (seq, store.set_next_target_seq(seq), Done::TargetSet(seq)),
            };
            match result {
                Ok(()) => ok,
                Err(err) => {
                    failed = true;
                    // Published under the job lock, before the outcome, so
                    // every submit is either queued before it or refused.
                    {
                        let _jobs = shared.jobs.lock();
                        shared.failed.store(true, Ordering::Release);
                    }
                    Done::Failed(sanitise(seq, &err))
                }
            }
        };
        shared.outcomes.lock().push_back(done);
        shared.outcome_ready.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStore;
    use std::sync::mpsc;
    use std::time::{Instant, SystemTime};

    /// A store whose writes wait for one token each on `gate`, and whose
    /// `fail_at` write fails with `fail_with`.
    struct GatedStore {
        inner: Arc<MemoryStore>,
        gate: Option<Mutex<mpsc::Receiver<()>>>,
        fail_at: Option<u64>,
        fail_with: StoreError,
        /// Panics in the `panic_at` write, to stop the worker.
        panic_at: Option<u64>,
        /// Signalled when a write starts (before the gate), and again once
        /// the `fail_at` write has decided to fail.
        failing: Option<Mutex<mpsc::Sender<()>>>,
    }

    impl SyncMessageStore for GatedStore {
        fn store(&self, seq: u64, msg_type: &MsgType, message: &[u8]) -> Result<(), StoreError> {
            if let Some(failing) = &self.failing {
                let _ = failing.lock().send(());
            }
            if let Some(gate) = &self.gate
                && gate.lock().recv_timeout(Duration::from_secs(5)).is_err()
            {
                return Err(StoreError::Io("gate timed out".to_owned()));
            }
            if self.panic_at == Some(seq) {
                panic!("injected backend panic");
            }
            if self.fail_at == Some(seq) {
                if let Some(failing) = &self.failing {
                    let _ = failing.lock().send(());
                }
                return Err(self.fail_with.clone());
            }
            self.inner.store(seq, msg_type, message)
        }
        fn get_range(&self, begin: u64, end: u64) -> Result<Vec<StoredMessage>, StoreError> {
            self.inner.get_range(begin, end)
        }
        fn next_sender_seq(&self) -> u64 {
            self.inner.next_sender_seq()
        }
        fn next_target_seq(&self) -> u64 {
            self.inner.next_target_seq()
        }
        fn set_next_sender_seq(&self, seq: u64) -> Result<(), StoreError> {
            self.inner.set_next_sender_seq(seq)
        }
        fn set_next_target_seq(&self, seq: u64) -> Result<(), StoreError> {
            self.inner.set_next_target_seq(seq)
        }
        fn reset(&self) -> Result<(), StoreError> {
            self.inner.reset()
        }
        fn creation_time(&self) -> SystemTime {
            self.inner.creation_time()
        }
    }

    fn bound(n: usize) -> NonZeroUsize {
        match NonZeroUsize::new(n) {
            Some(n) => n,
            None => panic!("bound must be non-zero"),
        }
    }

    fn injected(seq: u64) -> StoreError {
        StoreError::StoreFailed {
            seq_num: seq,
            reason: "injected".to_owned(),
        }
    }

    fn pending_with(
        n: usize,
        fail_at: Option<u64>,
        fail_with: StoreError,
    ) -> (PendingStore<GatedStore>, mpsc::Sender<()>) {
        let (open, gate) = mpsc::channel();
        let store = GatedStore {
            inner: Arc::new(MemoryStore::new()),
            gate: Some(Mutex::new(gate)),
            fail_at,
            fail_with,
            failing: None,
            panic_at: None,
        };
        match PendingStore::new(store, bound(n)) {
            Ok(p) => (p, open),
            Err(err) => panic!("new: {err:?}"),
        }
    }

    fn pending(n: usize, fail_at: Option<u64>) -> (PendingStore<GatedStore>, mpsc::Sender<()>) {
        pending_with(n, fail_at, injected(fail_at.unwrap_or(0)))
    }

    /// Submits, retrying while the queue is busy.
    fn submit<S: SyncMessageStore>(
        p: &mut PendingStore<S>,
        seq: u64,
    ) -> Result<Ticket, PendingError> {
        loop {
            match p.submit(seq, &MsgType::Heartbeat, b"8=FIX.4.4\x0135=0\x0110=000\x01") {
                Err(PendingError::Busy) => std::thread::yield_now(),
                other => return other,
            }
        }
    }

    /// Polls until the durable sequence number reaches `seq` or 5 s pass.
    fn poll_until(p: &mut PendingStore<GatedStore>, seq: u64) -> Result<(), StoreError> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while p.durable() < Some(seq) && Instant::now() < deadline {
            p.poll_durable()?;
            std::thread::yield_now();
        }
        Ok(())
    }

    #[test]
    fn test_pending_store_full_at_the_bound_then_accepts_after_drain() {
        let (mut p, open) = pending(2, None);
        assert!(submit(&mut p, 1).is_ok());
        assert!(submit(&mut p, 2).is_ok());
        assert_eq!(submit(&mut p, 3), Err(PendingError::Full { bound: 2 }));
        assert_eq!(p.in_flight(), 2);
        // Nothing is durable while the writes are held.
        assert_eq!(p.poll_durable(), Ok(None));

        assert!(open.send(()).is_ok());
        assert!(open.send(()).is_ok());
        assert_eq!(p.drain(), Ok(Some(2)));
        assert_eq!(p.in_flight(), 0);
        assert_eq!(p.next_sender_seq(), 3);
        assert!(submit(&mut p, 3).is_ok());
        assert!(open.send(()).is_ok());
        assert_eq!(p.drain(), Ok(Some(3)));
    }

    #[test]
    fn test_pending_store_poll_reports_each_advance_in_order() {
        let (mut p, open) = pending(4, None);
        for seq in 1..=3 {
            assert!(submit(&mut p, seq).is_ok());
        }
        assert!(open.send(()).is_ok());
        assert_eq!(poll_until(&mut p, 1), Ok(()));
        assert_eq!(p.durable(), Some(1));
        assert_eq!(p.poll_durable(), Ok(None));
        assert!(open.send(()).is_ok());
        assert!(open.send(()).is_ok());
        assert_eq!(poll_until(&mut p, 3), Ok(()));
        assert_eq!(p.durable(), Some(3));
        assert_eq!(p.in_flight(), 0);
        // Durable but not sent: not readable yet.
        assert_eq!(
            p.get_range(1, 3),
            Err(StoreError::RangeNotAvailable { begin: 1, end: 3 })
        );
        for seq in 1..=3 {
            assert_eq!(p.mark_sent(seq), Ok(()));
        }
        match p.get_range(1, 3) {
            Ok(messages) => assert_eq!(messages.len(), 3),
            Err(err) => panic!("range: {err:?}"),
        }
    }

    #[test]
    fn test_pending_store_fails_closed_after_a_failed_write() {
        let (mut p, open) = pending(4, Some(2));
        for seq in 1..=3 {
            assert!(submit(&mut p, seq).is_ok());
        }
        for _ in 0..3 {
            assert!(open.send(()).is_ok());
        }
        assert!(matches!(
            p.drain(),
            Err(StoreError::StoreFailed { seq_num: 2, .. })
        ));
        assert!(p.is_failed());
        assert_eq!(p.durable(), Some(1));
        assert_eq!(p.in_flight(), 0);
        // The write queued behind the failure was skipped, not applied.
        assert!(!p.store.inner.contains(3));
        assert_eq!(submit(&mut p, 4), Err(PendingError::Failed));
    }

    #[test]
    fn test_pending_store_refuses_a_submit_once_the_worker_failed_before_any_poll() {
        let (mut p, open) = pending(4, Some(1));
        assert!(submit(&mut p, 1).is_ok());
        assert!(open.send(()).is_ok());
        let deadline = Instant::now() + Duration::from_secs(5);
        while !p.is_failed() && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(p.is_failed());
        // No poll has collected the failure, and the queue has room.
        assert_eq!(submit(&mut p, 2), Err(PendingError::Failed));
        // The outcome may still be on its way: wait for it.
        assert!(matches!(
            p.drain(),
            Err(StoreError::StoreFailed { seq_num: 1, .. })
        ));
    }

    /// The failure is published under the job lock: while a submit holds
    /// it, the flag cannot change, so the check under the lock is exact.
    #[test]
    fn test_pending_store_publishes_a_failure_only_under_the_job_lock() {
        let (open, gate) = mpsc::channel();
        let (failing, failed_write) = mpsc::channel();
        let store = GatedStore {
            inner: Arc::new(MemoryStore::new()),
            gate: Some(Mutex::new(gate)),
            fail_at: Some(1),
            fail_with: injected(1),
            failing: Some(Mutex::new(failing)),
            panic_at: None,
        };
        let mut p = match PendingStore::new(store, bound(4)) {
            Ok(p) => p,
            Err(err) => panic!("new: {err:?}"),
        };
        assert!(submit(&mut p, 1).is_ok());
        // The worker has popped write 1 and waits at the gate.
        assert!(failed_write.recv_timeout(Duration::from_secs(5)).is_ok());
        {
            // Stand where a submit stands between its lock and its push.
            let jobs = p.shared.jobs.lock();
            assert!(open.send(()).is_ok());
            // The worker has decided to fail and now needs this lock.
            assert!(failed_write.recv_timeout(Duration::from_secs(5)).is_ok());
            assert!(!p.shared.failed.load(Ordering::Acquire));
            drop(jobs);
        }
        // Once the lock is free the worker publishes the flag.
        while !p.shared.failed.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        // An enqueue that passed the unlocked fast check before the failure
        // is refused under the lock: no job is built, no ticket issued.
        loop {
            match enqueue(&p.shared, || panic!("a job built after the failure")) {
                Err(PendingError::Failed) => break,
                Err(PendingError::Busy) => std::thread::yield_now(),
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(submit(&mut p, 2), Err(PendingError::Failed));
        assert!(matches!(
            p.drain(),
            Err(StoreError::StoreFailed { seq_num: 1, .. })
        ));
    }

    /// A worker that dies is published under the job lock: an enqueue that
    /// passed the unlocked check is refused with `Closed`, not ticketed.
    #[test]
    fn test_pending_store_refuses_an_enqueue_once_the_worker_stopped() {
        let store = GatedStore {
            inner: Arc::new(MemoryStore::new()),
            gate: None,
            fail_at: None,
            fail_with: injected(0),
            failing: None,
            panic_at: Some(1),
        };
        let mut p = match PendingStore::new(store, bound(4)) {
            Ok(p) => p,
            Err(err) => panic!("new: {err:?}"),
        };
        assert!(submit(&mut p, 1).is_ok());
        while !p.shared.stopped.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        loop {
            match enqueue(&p.shared, || panic!("a job built after the worker stopped")) {
                Err(PendingError::Closed) => break,
                Err(PendingError::Busy) => std::thread::yield_now(),
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(submit(&mut p, 2), Err(PendingError::Closed));
        assert!(matches!(p.drain(), Err(StoreError::Io(_))));
    }

    #[test]
    fn test_pending_store_refuses_a_sequence_below_the_store_next_sender() {
        let store = GatedStore {
            inner: Arc::new(MemoryStore::new()),
            gate: None,
            fail_at: None,
            fail_with: injected(0),
            failing: None,
            panic_at: None,
        };
        assert!(
            store
                .inner
                .store(4, &MsgType::Heartbeat, b"history")
                .is_ok()
        );
        assert!(store.inner.set_next_sender_seq(5).is_ok());
        let mut p = match PendingStore::new(store, bound(2)) {
            Ok(p) => p,
            Err(err) => panic!("new: {err:?}"),
        };
        assert_eq!(
            submit(&mut p, 4),
            Err(PendingError::BelowNextSender { next: 5, seq: 4 })
        );
        assert!(submit(&mut p, 5).is_ok());
        assert_eq!(p.drain(), Ok(Some(5)));
        assert_eq!(p.next_sender_seq(), 6);
    }

    /// Seq 1 is filed in the inner store but its counter write blocks; a
    /// resend read must not see it until the write is confirmed.
    struct SetterGated {
        inner: Arc<MemoryStore>,
        /// Signalled once the frame is filed and the setter is about to run.
        filed: Mutex<mpsc::Sender<()>>,
        /// One token per setter call; `Err` from the token fails it.
        setter: Mutex<mpsc::Receiver<Result<(), StoreError>>>,
    }

    impl SyncMessageStore for SetterGated {
        fn store(&self, seq: u64, msg_type: &MsgType, message: &[u8]) -> Result<(), StoreError> {
            self.inner.store(seq, msg_type, message)
        }
        fn get_range(&self, begin: u64, end: u64) -> Result<Vec<StoredMessage>, StoreError> {
            self.inner.get_range(begin, end)
        }
        fn next_sender_seq(&self) -> u64 {
            self.inner.next_sender_seq()
        }
        fn next_target_seq(&self) -> u64 {
            self.inner.next_target_seq()
        }
        fn set_next_sender_seq(&self, seq: u64) -> Result<(), StoreError> {
            let _ = self.filed.lock().send(());
            match self.setter.lock().recv_timeout(Duration::from_secs(5)) {
                Ok(Ok(())) => self.inner.set_next_sender_seq(seq),
                Ok(Err(err)) => Err(err),
                Err(_) => Err(StoreError::Io("setter gate timed out".to_owned())),
            }
        }
        fn set_next_target_seq(&self, seq: u64) -> Result<(), StoreError> {
            self.inner.set_next_target_seq(seq)
        }
        fn reset(&self) -> Result<(), StoreError> {
            self.inner.reset()
        }
        fn creation_time(&self) -> SystemTime {
            self.inner.creation_time()
        }
    }

    /// A store holding seqs 1..=2 as history, whose next setter is gated.
    /// The wrapper, the inner store, the filed signal and the setter gate.
    type SetterFixture = (
        PendingStore<SetterGated>,
        Arc<MemoryStore>,
        mpsc::Receiver<()>,
        mpsc::Sender<Result<(), StoreError>>,
    );

    fn setter_gated() -> SetterFixture {
        let inner = Arc::new(MemoryStore::new());
        for seq in 1..=2 {
            assert!(inner.store(seq, &MsgType::Heartbeat, b"history").is_ok());
        }
        assert!(inner.set_next_sender_seq(3).is_ok());
        let (filed_tx, filed) = mpsc::channel();
        let (setter, setter_rx) = mpsc::channel();
        let store = SetterGated {
            inner: Arc::clone(&inner),
            filed: Mutex::new(filed_tx),
            setter: Mutex::new(setter_rx),
        };
        match PendingStore::new(store, bound(4)) {
            Ok(p) => (p, inner, filed, setter),
            Err(err) => panic!("new: {err:?}"),
        }
    }

    fn seqs(result: Result<Vec<StoredMessage>, StoreError>) -> Vec<u64> {
        match result {
            Ok(messages) => messages.iter().map(StoredMessage::seq_num).collect(),
            Err(err) => panic!("range: {err:?}"),
        }
    }

    #[test]
    fn test_pending_store_resend_read_excludes_a_write_in_flight() {
        let (mut p, inner, filed, setter) = setter_gated();
        assert!(submit(&mut p, 3).is_ok());
        // The frame is in the inner store; its counter write is held.
        assert!(filed.recv_timeout(Duration::from_secs(5)).is_ok());
        assert!(inner.contains(3));
        assert_eq!(seqs(p.get_range(1, 0)), vec![1, 2]);
        assert_eq!(seqs(p.get_page(1, 10, 10)), vec![1, 2]);
        assert_eq!(
            p.get_range(3, 3),
            Err(StoreError::RangeNotAvailable { begin: 3, end: 3 })
        );
        assert_eq!(p.next_sender_seq(), 3);
        assert!(setter.send(Ok(())).is_ok());
        assert_eq!(p.drain(), Ok(Some(3)));
        assert_eq!(seqs(p.get_range(1, 0)), vec![1, 2]);
        assert_eq!(p.mark_sent(3), Ok(()));
        assert_eq!(seqs(p.get_range(1, 0)), vec![1, 2, 3]);
        assert_eq!(p.next_sender_seq(), 4);
    }

    #[test]
    fn test_pending_store_resend_read_excludes_a_write_whose_setter_failed() {
        let (mut p, inner, filed, setter) = setter_gated();
        assert!(submit(&mut p, 3).is_ok());
        assert!(filed.recv_timeout(Duration::from_secs(5)).is_ok());
        assert!(setter.send(Err(StoreError::Io("disk".to_owned()))).is_ok());
        assert!(p.drain().is_err());
        // Filed in the inner store, never confirmed: never read back.
        assert!(inner.contains(3));
        assert_eq!(seqs(p.get_range(1, 0)), vec![1, 2]);
        assert!(p.get_page(3, 10, 10).is_ok_and(|page| page.is_empty()));
        assert_eq!(p.next_sender_seq(), 3);
    }

    /// Frame 3 filed by an earlier run whose counter write failed: hidden at
    /// construction, and no gap can later put it under a confirmed number.
    #[test]
    fn test_pending_store_never_exposes_an_unconfirmed_frame_across_a_gap() {
        let (mut p, inner, filed, setter) = setter_gated();
        assert!(inner.store(3, &MsgType::Heartbeat, b"stale").is_ok());
        assert_eq!(
            submit(&mut p, 5),
            Err(PendingError::NotNext {
                expected: 3,
                seq: 5
            })
        );
        assert_eq!(seqs(p.get_range(1, 0)), vec![1, 2]);
        // Refiling 3 replaces the stale frame before it can be confirmed.
        assert!(submit(&mut p, 3).is_ok());
        assert!(filed.recv_timeout(Duration::from_secs(5)).is_ok());
        assert!(setter.send(Ok(())).is_ok());
        assert_eq!(p.drain(), Ok(Some(3)));
        assert_eq!(p.mark_sent(3), Ok(()));
        match p.get_range(3, 3) {
            Ok(messages) => assert_eq!(
                messages.first().map(|m| m.payload().as_ref()),
                Some(&b"8=FIX.4.4\x0135=0\x0110=000\x01"[..])
            ),
            Err(err) => panic!("range: {err:?}"),
        }
    }

    #[test]
    fn test_pending_store_reads_pre_existing_history_and_pass_through_target() {
        let (mut p, _inner, _filed, _setter) = setter_gated();
        assert_eq!(seqs(p.get_range(2, 2)), vec![2]);
        assert_eq!(
            p.get_range(0, 2),
            Err(StoreError::InvalidRange { begin: 0, end: 2 })
        );
        assert_eq!(p.mark_sent(2), Ok(()));
        assert_eq!(p.sent(), None);
        assert_eq!(p.next_sender_seq(), 3);
    }

    #[test]
    fn test_pending_store_get_page_zero_end_is_invalid_not_infinity() {
        let (p, _inner, _filed, _setter) = setter_gated();
        assert_eq!(
            p.get_page(1, 0, 10),
            Err(StoreError::InvalidRange { begin: 1, end: 0 })
        );
    }

    #[test]
    fn test_pending_store_refuses_a_store_whose_next_sender_is_zero() {
        let store = MemoryStore::new();
        assert!(store.set_next_sender_seq(0).is_ok());
        assert!(matches!(
            PendingStore::new(store, bound(1)),
            Err(StoreError::InvalidRange { .. })
        ));
    }

    #[test]
    fn test_pending_store_poll_reports_progress_before_a_later_failure() {
        let (mut p, open) = pending(4, Some(2));
        assert!(submit(&mut p, 1).is_ok());
        assert!(submit(&mut p, 2).is_ok());
        assert!(open.send(()).is_ok());
        assert!(open.send(()).is_ok());
        // Wait until both outcomes are queued, without collecting them.
        let deadline = Instant::now() + Duration::from_secs(5);
        while p.shared.outcomes.lock().len() < 2 && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert_eq!(p.poll_durable(), Ok(Some(1)));
        assert!(matches!(
            p.poll_durable(),
            Err(StoreError::StoreFailed { seq_num: 2, .. })
        ));
        assert_eq!(p.poll_durable(), Ok(None));
        assert_eq!(submit(&mut p, 3), Err(PendingError::Failed));
    }

    #[test]
    fn test_pending_store_target_write_cannot_overtake_a_queued_outbound_frame() {
        let (mut p, open) = pending(4, None);
        assert!(submit(&mut p, 1).is_ok());
        let target = loop {
            match p.submit_target(9) {
                Err(PendingError::Busy) => std::thread::yield_now(),
                other => break other,
            }
        };
        let ticket = match target {
            Ok(ticket) => ticket,
            Err(err) => panic!("target: {err:?}"),
        };
        assert_eq!(ticket.seq(), 9);
        assert_eq!(p.in_flight(), 2);
        // Frame 1 is held at the gate, so the target write behind it in
        // the one worker queue cannot have run.
        assert_eq!(p.store.inner.next_target_seq(), 1);
        assert_eq!(p.durable_target(), None);
        assert!(!p.is_target_applied(&ticket));
        assert!(open.send(()).is_ok());
        assert_eq!(p.drain(), Ok(Some(1)));
        assert_eq!(p.durable_target(), Some(9));
        assert!(p.is_target_applied(&ticket));
        assert_eq!(p.next_target_seq(), 9);
    }

    #[test]
    fn test_pending_store_target_submit_is_bounded_and_fails_closed() {
        let (mut p, open) = pending(1, Some(1));
        assert!(submit(&mut p, 1).is_ok());
        assert_eq!(p.submit_target(5), Err(PendingError::Full { bound: 1 }));
        assert!(open.send(()).is_ok());
        assert!(p.drain().is_err());
        assert_eq!(p.submit_target(5), Err(PendingError::Failed));
        assert_eq!(p.store.inner.next_target_seq(), 1);
    }

    #[test]
    fn test_pending_store_resend_reads_cap_at_the_sent_watermark() {
        let (mut p, inner, filed, setter) = setter_gated();
        for seq in 3..=4 {
            assert!(submit(&mut p, seq).is_ok());
            assert!(filed.recv_timeout(Duration::from_secs(5)).is_ok());
            assert!(setter.send(Ok(())).is_ok());
        }
        assert_eq!(p.drain(), Ok(Some(4)));
        assert!(inner.contains(4));
        // Durable, not sent: only history is readable.
        assert_eq!(seqs(p.get_range(1, 0)), vec![1, 2]);
        // Frame 3 is unreported: reporting 4 would make it readable.
        assert_eq!(
            p.mark_sent(4),
            Err(PendingError::NotNext {
                expected: 3,
                seq: 4
            })
        );
        assert_eq!(p.mark_sent(3), Ok(()));
        assert_eq!(seqs(p.get_range(1, 0)), vec![1, 2, 3]);
        assert_eq!(seqs(p.get_page(1, 10, 10)), vec![1, 2, 3]);
        // A lower report does not move the watermark back.
        assert_eq!(p.mark_sent(1), Ok(()));
        assert_eq!(p.sent(), Some(3));
        assert_eq!(p.mark_sent(4), Ok(()));
        assert_eq!(seqs(p.get_range(1, 0)), vec![1, 2, 3, 4]);
        assert_eq!(p.mark_sent(5), Err(PendingError::NotDurable { seq: 5 }));
    }

    #[test]
    fn test_pending_store_target_ticket_is_bound_to_its_store() {
        let (mut a, open_a) = pending(4, None);
        let (b, _open_b) = pending(4, None);
        let ticket = loop {
            match a.submit_target(3) {
                Err(PendingError::Busy) => std::thread::yield_now(),
                Ok(ticket) => break ticket,
                Err(err) => panic!("target: {err:?}"),
            }
        };
        assert!(open_a.send(()).is_ok());
        assert_eq!(a.drain(), Ok(None));
        assert!(a.is_target_applied(&ticket));
        assert!(!b.is_target_applied(&ticket));
    }

    /// A backend whose reads fail quoting a Logon.
    struct LeakyReads(MemoryStore);

    impl SyncMessageStore for LeakyReads {
        fn store(&self, seq: u64, msg_type: &MsgType, message: &[u8]) -> Result<(), StoreError> {
            self.0.store(seq, msg_type, message)
        }
        fn get_range(&self, _begin: u64, _end: u64) -> Result<Vec<StoredMessage>, StoreError> {
            Err(StoreError::Io("35=A\x01554=hunter2\x01".to_owned()))
        }
        fn next_sender_seq(&self) -> u64 {
            self.0.next_sender_seq()
        }
        fn next_target_seq(&self) -> u64 {
            self.0.next_target_seq()
        }
        fn set_next_sender_seq(&self, seq: u64) -> Result<(), StoreError> {
            self.0.set_next_sender_seq(seq)
        }
        fn set_next_target_seq(&self, seq: u64) -> Result<(), StoreError> {
            self.0.set_next_target_seq(seq)
        }
        fn reset(&self) -> Result<(), StoreError> {
            self.0.reset()
        }
        fn creation_time(&self) -> SystemTime {
            self.0.creation_time()
        }
    }

    #[test]
    fn test_pending_store_read_errors_carry_no_backend_text() {
        let inner = MemoryStore::new();
        assert!(inner.set_next_sender_seq(3).is_ok());
        let p = match PendingStore::new(LeakyReads(inner), bound(1)) {
            Ok(p) => p,
            Err(err) => panic!("new: {err:?}"),
        };
        for result in [p.get_range(1, 0), p.get_page(1, 2, 10)] {
            match result {
                Err(err @ StoreError::RetrieveFailed { seq_num: 1, .. }) => {
                    let text = format!("{err} {err:?}");
                    assert!(!text.contains("hunter2"), "leaked: {text}");
                }
                other => panic!("expected a sanitised RetrieveFailed, got {other:?}"),
            }
        }
        // Structured range errors pass through.
        assert_eq!(
            p.get_range(0, 1),
            Err(StoreError::InvalidRange { begin: 0, end: 1 })
        );
    }

    #[test]
    fn test_pending_store_oversized_bound_is_an_error_not_a_panic() {
        assert!(matches!(
            PendingStore::new(MemoryStore::new(), NonZeroUsize::MAX),
            Err(StoreError::Io(_))
        ));
    }

    #[test]
    fn test_pending_store_error_carries_no_backend_text() {
        let secret = "8=FIX.4.4\x0135=A\x01554=hunter2\x01";
        let (mut p, open) = pending_with(2, Some(1), StoreError::Io(secret.to_owned()));
        assert!(submit(&mut p, 1).is_ok());
        assert!(open.send(()).is_ok());
        match p.drain() {
            Err(err @ StoreError::StoreFailed { seq_num: 1, .. }) => {
                let text = format!("{err} {err:?}");
                assert!(!text.contains("hunter2"), "leaked: {text}");
                assert!(text.contains("i/o error"));
            }
            other => panic!("expected a sanitised StoreFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_pending_store_refuses_out_of_order_and_exhausted_sequences() {
        let (mut p, open) = pending(4, None);
        assert_eq!(
            submit(&mut p, 2),
            Err(PendingError::NotNext {
                expected: 1,
                seq: 2
            })
        );
        assert!(submit(&mut p, 1).is_ok());
        assert_eq!(
            submit(&mut p, 1),
            Err(PendingError::NotNext {
                expected: 2,
                seq: 1
            })
        );
        // A gap is refused: frame 2 would be skipped and 3 confirmed.
        assert_eq!(
            submit(&mut p, 3),
            Err(PendingError::NotNext {
                expected: 2,
                seq: 3
            })
        );
        assert_eq!(
            submit(&mut p, u64::MAX),
            Err(PendingError::SequenceExhausted { seq: u64::MAX })
        );
        assert!(open.send(()).is_ok());
        assert_eq!(p.drain(), Ok(Some(1)));
    }

    #[test]
    fn test_pending_store_drop_finishes_queued_writes() {
        let inner = Arc::new(MemoryStore::new());
        let store = GatedStore {
            inner: Arc::clone(&inner),
            gate: None,
            fail_at: None,
            fail_with: injected(0),
            failing: None,
            panic_at: None,
        };
        let mut p = match PendingStore::new(store, bound(8)) {
            Ok(p) => p,
            Err(err) => panic!("new: {err:?}"),
        };
        for seq in 1..=8 {
            loop {
                match p.submit(seq, &MsgType::Heartbeat, b"8=FIX.4.4\x01") {
                    Err(PendingError::Busy) => std::thread::yield_now(),
                    other => {
                        assert!(other.is_ok());
                        break;
                    }
                }
            }
        }
        drop(p);
        assert_eq!(inner.message_count(), 8);
        assert_eq!(inner.next_sender_seq(), 9);
    }
}
