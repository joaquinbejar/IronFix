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
//! - Dropping a [`PendingStore`] finishes the writes already queued and
//!   joins the worker, so it blocks for up to the bound times one write.
//!
//! Each submit copies the frame into one owned buffer for the worker; the
//! queues themselves are reserved up front. Error values never contain frame
//! bytes or backend text: an outbound Logon carries `Password` (554), and a
//! custom store may quote the frame, so a failed write is reported with its
//! sequence number and the kind of error only.

use crate::sync_traits::SyncMessageStore;
use ironfix_core::error::StoreError;
use ironfix_core::message::MsgType;
use parking_lot::{Condvar, Mutex};
use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// `seq` is not above the last sequence number submitted.
    #[error("sequence {seq} is not above the last submitted {last}")]
    OutOfOrder {
        /// The last sequence number submitted.
        last: u64,
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

/// One write handed to the worker.
struct Job {
    seq: u64,
    msg_type: MsgType,
    message: Vec<u8>,
    next_sender: u64,
}

/// One write's outcome, sent back by the worker.
enum Done {
    /// `file_outbound` returned `Ok` for this sequence number.
    Filed(u64),
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
    last_submitted: Option<u64>,
    durable: Option<u64>,
}

impl<S: SyncMessageStore + 'static> PendingStore<S> {
    /// Starts the worker thread for `store`, with at most `bound` writes in
    /// flight.
    ///
    /// # Errors
    /// [`StoreError::Io`] if the worker thread cannot be spawned.
    pub fn new(store: Arc<S>, bound: NonZeroUsize) -> Result<Self, StoreError> {
        let shared = Arc::new(Shared {
            jobs: Mutex::new(Jobs {
                queue: VecDeque::with_capacity(bound.get()),
                closed: false,
            }),
            job_ready: Condvar::new(),
            outcomes: Mutex::new(VecDeque::with_capacity(bound.get())),
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
            last_submitted: None,
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
    /// [`PendingError::OutOfOrder`] when `seq` is not above the last
    /// submitted, [`PendingError::SequenceExhausted`] for `u64::MAX`,
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
        if let Some(last) = self.last_submitted
            && seq <= last
        {
            return Err(PendingError::OutOfOrder { last, seq });
        }
        let Some(next_sender) = seq.checked_add(1) else {
            return Err(PendingError::SequenceExhausted { seq });
        };
        enqueue(&self.shared, || Job {
            seq,
            msg_type: msg_type.clone(),
            message: message.to_vec(),
            next_sender,
        })?;
        // `in_flight < bound <= usize::MAX`, checked above.
        self.in_flight += 1;
        self.last_submitted = Some(seq);
        Ok(Ticket { seq })
    }

    /// Collects the writes the worker has finished, without blocking.
    ///
    /// Returns `Some(seq)` when the durable sequence number advanced to
    /// `seq`, `None` when it did not.
    ///
    /// # Errors
    /// The [`StoreError`] of a failed write, once; the store then refuses
    /// every later submit. [`StoreError::Io`] if the worker stopped with
    /// writes in flight.
    pub fn poll_durable(&mut self) -> Result<Option<u64>, StoreError> {
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
            match next {
                Some(done) => self.apply(done)?,
                // Read under the lock, after the worker's last push: final.
                None if stopped => return Err(self.worker_lost()),
                None => break,
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
        let mut first_error = None;
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

    /// The inner store, for reads such as a resend's `get_range`. Writing
    /// through it bypasses the submit order.
    #[must_use]
    pub const fn store(&self) -> &Arc<S> {
        &self.store
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
            match store.file_outbound(job.seq, &job.msg_type, &job.message, job.next_sender) {
                Ok(()) => Done::Filed(job.seq),
                Err(err) => {
                    failed = true;
                    // Published under the job lock, before the outcome, so
                    // every submit is either queued before it or refused.
                    {
                        let _jobs = shared.jobs.lock();
                        shared.failed.store(true, Ordering::Release);
                    }
                    Done::Failed(sanitise(job.seq, &err))
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
    use crate::stored::StoredMessage;
    use std::sync::mpsc;
    use std::time::{Instant, SystemTime};

    /// A store whose writes wait for one token each on `gate`, and whose
    /// `fail_at` write fails with `fail_with`.
    struct GatedStore {
        inner: MemoryStore,
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
            inner: MemoryStore::new(),
            gate: Some(Mutex::new(gate)),
            fail_at,
            fail_with,
            failing: None,
            panic_at: None,
        };
        match PendingStore::new(Arc::new(store), bound(n)) {
            Ok(p) => (p, open),
            Err(err) => panic!("new: {err:?}"),
        }
    }

    fn pending(n: usize, fail_at: Option<u64>) -> (PendingStore<GatedStore>, mpsc::Sender<()>) {
        pending_with(n, fail_at, injected(fail_at.unwrap_or(0)))
    }

    /// Submits, retrying while the queue is busy.
    fn submit(p: &mut PendingStore<GatedStore>, seq: u64) -> Result<Ticket, PendingError> {
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
        assert_eq!(p.store().next_sender_seq(), 3);
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
        match p.store().get_range(1, 3) {
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
        assert!(!p.store().inner.contains(3));
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
            inner: MemoryStore::new(),
            gate: Some(Mutex::new(gate)),
            fail_at: Some(1),
            fail_with: injected(1),
            failing: Some(Mutex::new(failing)),
            panic_at: None,
        };
        let mut p = match PendingStore::new(Arc::new(store), bound(4)) {
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
            inner: MemoryStore::new(),
            gate: None,
            fail_at: None,
            fail_with: injected(0),
            failing: None,
            panic_at: Some(1),
        };
        let mut p = match PendingStore::new(Arc::new(store), bound(4)) {
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
        assert!(submit(&mut p, 5).is_ok());
        assert_eq!(
            submit(&mut p, 5),
            Err(PendingError::OutOfOrder { last: 5, seq: 5 })
        );
        assert_eq!(
            submit(&mut p, u64::MAX),
            Err(PendingError::SequenceExhausted { seq: u64::MAX })
        );
        assert!(open.send(()).is_ok());
        assert_eq!(p.drain(), Ok(Some(5)));
    }

    #[test]
    fn test_pending_store_drop_finishes_queued_writes() {
        let store = Arc::new(GatedStore {
            inner: MemoryStore::new(),
            gate: None,
            fail_at: None,
            fail_with: injected(0),
            failing: None,
            panic_at: None,
        });
        let mut p = match PendingStore::new(Arc::clone(&store), bound(8)) {
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
        assert_eq!(store.inner.message_count(), 8);
        assert_eq!(store.next_sender_seq(), 9);
    }
}
