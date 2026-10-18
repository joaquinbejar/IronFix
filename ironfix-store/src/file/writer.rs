/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! The writer thread of a [`FileStore`](super::FileStore): one dedicated
//! thread per store that owns the journal and runs every call on it, one at a
//! time, in the order the calls were made.
//!
//! An async caller sends its command **by value** through a bounded
//! `crossbeam-channel` queue, with `try_send`: it never blocks, and a full
//! queue fails the call with a typed [`StoreError`]. The answer comes back
//! through a **reply cell** taken from a pool and returned to it after use:
//! the queue's slots are allocated once, and in steady state a call allocates
//! nothing here. Nothing is held across the caller's await: the command is
//! queued synchronously, before the caller's future first yields.
//!
//! Each call still costs two cross-thread wakes: the caller's queueing wakes
//! the writer thread, and the answer wakes the caller's task.
//!
//! The locks the caller and the writer thread share on every call (a reply
//! cell's, and the cell pool's) are `std::sync` mutexes: contention on them
//! waits in the kernel and allocates nothing. A `parking_lot` lock allocates
//! its process-wide table of parked threads the first time a thread parks on
//! one, which would put a heap allocation on whichever call first meets
//! contention. The state lock stays `parking_lot`: only the writer thread
//! takes it, and the drop only tries it.
//!
//! # Call order and dropped calls
//!
//! The queue is first in, first out, and the thread takes one call at a time,
//! so calls run in the order they were queued. Before running a call the
//! thread checks whether its caller is still waiting (the reply future has
//! not been dropped):
//!
//! - a call whose future was dropped **before the thread took it** is skipped,
//!   and does nothing;
//! - a call the thread has started runs to the end, even if its future is
//!   dropped meanwhile, before the thread takes the next one.
//!
//! A call therefore takes effect before any call queued after it, or not at
//! all: the `MessageStore` call-order contract (ADR-0005), with the same
//! cancellation semantics as the first-in, first-out lock it replaces
//! (ADR-0006, ADR-0022). A call whose future was dropped stays in the queue,
//! taking a slot, until the thread reaches and skips it.
//!
//! # After-call work
//!
//! Whether the state has work to do after a call (an automatic compaction)
//! is checked under the same lock as the call. The work itself runs once the
//! call has been answered, so that call is not delayed; the next call waits
//! for it.
//!
//! # Shutdown
//!
//! Dropping the [`Writer`] closes the queue. If the thread is idle, the state
//! (the journal, with its files and lock) is dropped at once on the dropping
//! thread and the writer thread is joined, so the files are closed and the
//! lock released when the drop returns. If a call or after-call work is
//! running, the drop does not wait for it: the thread finishes it, skips what
//! is left in the queue (no caller can be waiting any more), drops the state
//! and exits on its own.

use crate::file::format::io_error;
use crossbeam_channel::{Receiver, Sender, TrySendError};
use ironfix_core::error::StoreError;
use parking_lot::Mutex;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex, MutexGuard as StdGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::thread::JoinHandle;
use tokio::sync::oneshot;

/// Stack size of a writer thread, in bytes (256 KiB). The thread runs the
/// journal's I/O and its recovery scan, which keep their buffers on the heap.
pub(crate) const WRITER_STACK_SIZE: usize = 256 * 1024;

/// Most idle reply cells a writer keeps for reuse.
const REPLY_CELL_POOL: usize = 64;

/// State the writer thread serves calls on.
pub(crate) trait Served: Send + 'static {
    /// A call.
    type Command: Send + 'static;
    /// What a call answers.
    type Answer: Send + 'static;

    /// Runs a call.
    ///
    /// # Errors
    /// Whatever the call fails with.
    fn execute(&mut self, command: Self::Command) -> Result<Self::Answer, StoreError>;

    /// Whether the state is closed once `command` has run.
    fn closes(command: &Self::Command) -> bool;

    /// Whether there is work to do after the call just run (checked under the
    /// same lock as the call).
    fn after_call_due(&self) -> bool;

    /// The work [`Served::after_call_due`] asked for. Its outcome reaches no
    /// caller.
    fn after_call(&mut self);
}

/// What the writer thread owns, behind the lock the thread holds while it
/// runs a call.
#[derive(Debug)]
enum State<S> {
    /// The thread has not built the state yet.
    Starting,
    /// The state, between and during calls.
    Open(S),
    /// Closed: by a call that closes, by a failed start, or by the drop.
    Closed,
}

/// The error for a call on a store whose writer has stopped.
#[cold]
#[inline(never)]
fn store_closed() -> StoreError {
    StoreError::Io("the file store is closed: its writer thread has stopped".to_string())
}

/// The error for a call refused because the queue is full.
#[cold]
#[inline(never)]
fn queue_full(capacity: usize) -> StoreError {
    StoreError::Io(format!(
        "the file store's call queue is full ({capacity} calls waiting): the call was not \
         queued and changed nothing"
    ))
}

/// Where the writer thread puts a call's answer and the caller's task finds
/// it. Reused across calls through a [`CellPool`].
#[derive(Debug)]
struct ReplyCell<A> {
    /// The cell's state.
    inner: StdMutex<CellState<A>>,
}

/// The state of a [`ReplyCell`].
#[derive(Debug)]
struct CellState<A> {
    /// The answer, once the writer has run the call.
    answer: Option<Result<A, StoreError>>,
    /// The waker of the task waiting for the answer.
    waker: Option<Waker>,
    /// Whether the caller dropped its future before the answer.
    abandoned: bool,
}

/// Locks a `std::sync` mutex, taking it over from a thread that panicked
/// while holding it: the data behind these locks stays consistent at every
/// point a panic could leave it (an answer, a waker, a flag, a list of idle
/// cells).
fn lock<T>(mutex: &StdMutex<T>) -> StdGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl<A> ReplyCell<A> {
    /// An empty cell.
    const fn new() -> Self {
        Self {
            inner: StdMutex::new(CellState {
                answer: None,
                waker: None,
                abandoned: false,
            }),
        }
    }
}

/// Idle reply cells, reused so a call allocates none. At most
/// [`REPLY_CELL_POOL`] are kept; one more is dropped.
#[derive(Debug)]
struct CellPool<A> {
    /// The idle cells.
    cells: StdMutex<Vec<Arc<ReplyCell<A>>>>,
}

impl<A> CellPool<A> {
    /// An empty pool, with room for [`REPLY_CELL_POOL`] cells.
    fn new() -> Self {
        Self {
            cells: StdMutex::new(Vec::with_capacity(REPLY_CELL_POOL)),
        }
    }

    /// An idle cell, or a new one if there is none.
    fn take(&self) -> Arc<ReplyCell<A>> {
        lock(&self.cells)
            .pop()
            .unwrap_or_else(|| Arc::new(ReplyCell::new()))
    }

    /// Empties `cell` and keeps it for reuse, if there is room.
    ///
    /// Only the party that is done with the cell last gives it back: the
    /// caller, once it has the answer or drops a future that already has one;
    /// the writer, once it has skipped or answered a call whose future was
    /// dropped. The cell's lock decides which.
    fn give(&self, cell: Arc<ReplyCell<A>>) {
        {
            let mut state = lock(&cell.inner);
            state.answer = None;
            state.waker = None;
            state.abandoned = false;
        }
        let mut cells = lock(&self.cells);
        if cells.len() < cells.capacity() {
            cells.push(cell);
        }
    }
}

/// A queued call: the command, and the cell its answer goes to.
struct Request<S: Served> {
    /// The command.
    command: S::Command,
    /// Where the answer goes.
    cell: Arc<ReplyCell<S::Answer>>,
}

/// The answer to a queued call, as a future.
///
/// Dropping it before the answer arrives marks the call abandoned: the
/// writer skips it if it has not started it.
pub(crate) struct Reply<'a, A> {
    /// The cell the answer arrives in; `None` once the answer is taken.
    cell: Option<Arc<ReplyCell<A>>>,
    /// Where the cell goes back.
    pool: &'a CellPool<A>,
}

impl<A> Future for Reply<'_, A> {
    type Output = Result<A, StoreError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let Some(cell) = this.cell.as_ref() else {
            return Poll::Ready(Err(store_closed()));
        };
        let mut state = lock(&cell.inner);
        if let Some(answer) = state.answer.take() {
            drop(state);
            if let Some(cell) = this.cell.take() {
                this.pool.give(cell);
            }
            return Poll::Ready(answer);
        }
        match &state.waker {
            Some(waker) if waker.will_wake(cx.waker()) => {}
            _ => state.waker = Some(cx.waker().clone()),
        }
        Poll::Pending
    }
}

impl<A> Drop for Reply<'_, A> {
    fn drop(&mut self) {
        let Some(cell) = self.cell.take() else {
            return;
        };
        let answered = {
            let mut state = lock(&cell.inner);
            if state.answer.is_some() {
                true
            } else {
                state.abandoned = true;
                state.waker = None;
                false
            }
        };
        // Answered: the writer is done with the cell. Not answered: the
        // writer gives it back once it has skipped or run the call.
        if answered {
            self.pool.give(cell);
        }
    }
}

/// The handle on a writer thread: queues calls, and shuts the thread down
/// when dropped (see the [module documentation](self)).
pub(crate) struct Writer<S: Served> {
    /// The queue; `None` once the writer is being dropped.
    calls: Option<Sender<Request<S>>>,
    /// The queue's capacity, in calls.
    capacity: usize,
    /// The state, shared with the thread.
    state: Arc<Mutex<State<S>>>,
    /// Idle reply cells, shared with the thread.
    cells: Arc<CellPool<S::Answer>>,
    /// The thread; taken when it is joined.
    thread: Option<JoinHandle<()>>,
}

impl<S: Served> Writer<S> {
    /// Starts a writer thread named `name`, with a queue of `capacity` calls,
    /// which builds its state with `init` and then serves calls. Returns the
    /// writer at once, with a receiver for the outcome of `init`.
    ///
    /// # Errors
    /// [`StoreError::Io`] if the thread cannot be started.
    pub(crate) fn spawn<I>(
        name: &str,
        capacity: usize,
        init: I,
    ) -> Result<(Self, oneshot::Receiver<Result<(), StoreError>>), StoreError>
    where
        I: FnOnce() -> Result<S, StoreError> + Send + 'static,
    {
        let (calls, queue) = crossbeam_channel::bounded::<Request<S>>(capacity);
        let state = Arc::new(Mutex::new(State::Starting));
        let cells = Arc::new(CellPool::new());
        let (started, outcome) = oneshot::channel();
        let thread_state = Arc::clone(&state);
        let thread_cells = Arc::clone(&cells);
        let thread = std::thread::Builder::new()
            .name(name.to_string())
            .stack_size(WRITER_STACK_SIZE)
            .spawn(move || {
                // After a failed start the thread still serves the queue,
                // answering every call that the store is closed, so no call
                // waits for an answer that never comes.
                start(&thread_state, init, started);
                serve(&queue, &thread_state, &thread_cells);
            })
            .map_err(|err| io_error("cannot start the file store's writer thread", &err))?;
        Ok((
            Self {
                calls: Some(calls),
                capacity,
                state,
                cells,
                thread: Some(thread),
            },
            outcome,
        ))
    }

    /// Queues `command` and returns the future of its answer.
    ///
    /// The command is queued now. Dropping the returned future before the
    /// thread takes the call cancels it; once the thread has taken it, it
    /// runs to the end.
    ///
    /// # Errors
    /// [`StoreError::Io`] if the queue is full or the writer has stopped; the
    /// command was then not queued.
    pub(crate) fn call(&self, command: S::Command) -> Result<Reply<'_, S::Answer>, StoreError> {
        let calls = self.calls.as_ref().ok_or_else(store_closed)?;
        let cell = self.cells.take();
        let request = Request {
            command,
            cell: Arc::clone(&cell),
        };
        match calls.try_send(request) {
            Ok(()) => Ok(Reply {
                cell: Some(cell),
                pool: &self.cells,
            }),
            Err(refused) => {
                let full = matches!(refused, TrySendError::Full(_));
                drop(refused);
                self.cells.give(cell);
                Err(if full {
                    queue_full(self.capacity)
                } else {
                    store_closed()
                })
            }
        }
    }
}

/// Builds the state on the writer thread, holding the state lock meanwhile,
/// and reports the outcome. A writer dropped before the thread started has
/// already closed the state, and nothing is built.
fn start<S, I>(state: &Mutex<State<S>>, init: I, started: oneshot::Sender<Result<(), StoreError>>)
where
    I: FnOnce() -> Result<S, StoreError>,
{
    let outcome = {
        let mut guard = state.lock();
        if !matches!(*guard, State::Starting) {
            return;
        }
        match init() {
            Ok(open) => {
                *guard = State::Open(open);
                Ok(())
            }
            Err(err) => {
                *guard = State::Closed;
                Err(err)
            }
        }
    };
    let _ = started.send(outcome);
}

/// The writer thread's loop: runs each queued call whose caller still waits,
/// and the after-call work it asks for, until the queue is closed; then drops
/// the state.
fn serve<S: Served>(
    queue: &Receiver<Request<S>>,
    state: &Mutex<State<S>>,
    cells: &CellPool<S::Answer>,
) {
    while let Ok(request) = queue.recv() {
        if run(request, state, cells)
            && let State::Open(open) = &mut *state.lock()
        {
            open.after_call();
        }
    }
    let closed = std::mem::replace(&mut *state.lock(), State::Closed);
    drop(closed);
}

/// Runs one call, unless it was abandoned, and answers it. Returns whether
/// after-call work is due.
fn run<S: Served>(
    request: Request<S>,
    state: &Mutex<State<S>>,
    cells: &CellPool<S::Answer>,
) -> bool {
    let Request { command, cell } = request;
    if lock(&cell.inner).abandoned {
        cells.give(cell);
        return false;
    }
    let (result, closed, due) = {
        let mut guard = state.lock();
        match &mut *guard {
            State::Open(open) => {
                let closes = S::closes(&command);
                let result = open.execute(command);
                let due = !closes && open.after_call_due();
                let closed = closes.then(|| std::mem::replace(&mut *guard, State::Closed));
                (result, closed, due)
            }
            State::Starting | State::Closed => (Err(store_closed()), None, false),
        }
    };
    // The state a closing call took out is dropped before the answer, so the
    // caller sees the files closed; the lock is released before the answer
    // too, so a caller that drops the writer next finds it idle.
    drop(closed);
    let mut cell_state = lock(&cell.inner);
    if cell_state.abandoned {
        drop(cell_state);
        cells.give(cell);
    } else {
        cell_state.answer = Some(result);
        let waker = cell_state.waker.take();
        drop(cell_state);
        drop(cell);
        if let Some(waker) = waker {
            waker.wake();
        }
    }
    due
}

impl<S: Served> Drop for Writer<S> {
    fn drop(&mut self) {
        // Idle: nothing holds the state lock. Close the state here, so its
        // files and lock are released before the drop returns. Busy: leave
        // the state to the thread, which drops it once its work is done.
        let closed = self
            .state
            .try_lock()
            .map(|mut guard| std::mem::replace(&mut *guard, State::Closed));
        let idle = closed.is_some();
        drop(closed);
        // Closing the queue ends the thread's loop once it is empty; every
        // call left in it was abandoned, since no caller outlives the writer.
        drop(self.calls.take());
        if let Some(thread) = self.thread.take()
            && idle
            && thread.thread().id() != std::thread::current().id()
        {
            let _ = thread.join();
        }
    }
}

impl<S: Served> std::fmt::Debug for Writer<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Writer")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    /// A state that records the calls it ran and when it is dropped.
    struct Log {
        ran: Arc<Mutex<Vec<u32>>>,
        dropped: Arc<AtomicBool>,
        after_calls: Arc<AtomicU32>,
        due: bool,
    }

    /// A test call.
    enum TestCall {
        /// Records the value, after holding the thread this long.
        Record(u32, Duration),
        /// Makes after-call work due after the next call.
        AfterNext,
        /// Closes the state.
        Close,
        /// Fails.
        Fail,
    }

    impl Served for Log {
        type Command = TestCall;
        type Answer = u32;

        fn execute(&mut self, command: TestCall) -> Result<u32, StoreError> {
            match command {
                TestCall::Record(value, hold) => {
                    std::thread::sleep(hold);
                    self.ran.lock().push(value);
                    Ok(value)
                }
                TestCall::AfterNext => {
                    self.due = true;
                    Ok(0)
                }
                TestCall::Close => Ok(0),
                TestCall::Fail => Err(StoreError::Io("failed".to_string())),
            }
        }

        fn closes(command: &TestCall) -> bool {
            matches!(command, TestCall::Close)
        }

        fn after_call_due(&self) -> bool {
            self.due
        }

        fn after_call(&mut self) {
            self.due = false;
            self.after_calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Drop for Log {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    #[track_caller]
    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("{what}: {err:?}"),
        }
    }

    struct Fixture {
        writer: Writer<Log>,
        ran: Arc<Mutex<Vec<u32>>>,
        dropped: Arc<AtomicBool>,
        after_calls: Arc<AtomicU32>,
    }

    async fn fixture(capacity: usize) -> Fixture {
        let ran = Arc::new(Mutex::new(Vec::new()));
        let dropped = Arc::new(AtomicBool::new(false));
        let after_calls = Arc::new(AtomicU32::new(0));
        let log = Log {
            ran: Arc::clone(&ran),
            dropped: Arc::clone(&dropped),
            after_calls: Arc::clone(&after_calls),
            due: false,
        };
        let spawned = Writer::spawn("ironfix-store-test", capacity, move || Ok(log));
        let (writer, started) = ok(spawned, "spawn");
        ok(ok(started.await, "started"), "init");
        Fixture {
            writer,
            ran,
            dropped,
            after_calls,
        }
    }

    async fn call(writer: &Writer<Log>, command: TestCall) -> Result<u32, StoreError> {
        writer.call(command)?.await
    }

    #[tokio::test]
    async fn test_writer_runs_calls_in_the_order_they_were_queued() {
        let fixture = fixture(64).await;
        let replies: Vec<_> = (0..50)
            .map(|value| {
                ok(
                    fixture.writer.call(TestCall::Record(value, Duration::ZERO)),
                    "queue",
                )
            })
            .collect();
        for (reply, value) in replies.into_iter().zip(0..) {
            assert_eq!(ok(reply.await, "call"), value);
        }
        assert_eq!(*fixture.ran.lock(), (0..50).collect::<Vec<_>>());
        assert!(matches!(
            call(&fixture.writer, TestCall::Fail).await,
            Err(StoreError::Io(reason)) if reason == "failed"
        ));
    }

    #[tokio::test]
    async fn test_writer_reuses_its_reply_cells() {
        let fixture = fixture(8).await;
        for value in 0..20 {
            ok(
                call(&fixture.writer, TestCall::Record(value, Duration::ZERO)).await,
                "call",
            );
        }
        // One call at a time: one cell, taken and given back each time.
        assert_eq!(lock(&fixture.writer.cells.cells).len(), 1);
    }

    #[tokio::test]
    async fn test_writer_finishes_a_started_call_whose_future_was_dropped() {
        let fixture = fixture(8).await;
        let dropped = tokio::time::timeout(
            Duration::from_millis(20),
            call(
                &fixture.writer,
                TestCall::Record(1, Duration::from_millis(200)),
            ),
        )
        .await;
        assert!(dropped.is_err(), "the caller gave up while it ran");
        ok(
            call(&fixture.writer, TestCall::Record(2, Duration::ZERO)).await,
            "next",
        );
        assert_eq!(*fixture.ran.lock(), vec![1, 2]);
        // The abandoned call's cell came back too.
        assert_eq!(lock(&fixture.writer.cells.cells).len(), 2);
    }

    #[tokio::test]
    async fn test_writer_skips_a_call_dropped_before_it_started() {
        let fixture = fixture(8).await;
        let slow = ok(
            fixture
                .writer
                .call(TestCall::Record(1, Duration::from_millis(200))),
            "queue",
        );
        let waiting = ok(
            fixture.writer.call(TestCall::Record(2, Duration::ZERO)),
            "queue",
        );
        // Both are queued; the second is dropped while the first still holds
        // the thread.
        drop(waiting);
        ok(slow.await, "slow call");
        ok(
            call(&fixture.writer, TestCall::Record(3, Duration::ZERO)).await,
            "next",
        );
        assert_eq!(*fixture.ran.lock(), vec![1, 3]);
    }

    #[tokio::test]
    async fn test_writer_full_queue_refuses_the_call_without_blocking() {
        let fixture = fixture(2).await;
        let running = ok(
            fixture
                .writer
                .call(TestCall::Record(1, Duration::from_millis(300))),
            "queue",
        );
        // Let the thread take the first call, so the two slots are free.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let second = ok(
            fixture.writer.call(TestCall::Record(2, Duration::ZERO)),
            "queue",
        );
        let third = ok(
            fixture.writer.call(TestCall::Record(3, Duration::ZERO)),
            "queue",
        );
        let before = Instant::now();
        assert!(matches!(
            fixture.writer.call(TestCall::Record(4, Duration::ZERO)),
            Err(StoreError::Io(reason)) if reason.contains("queue is full")
        ));
        assert!(
            before.elapsed() < Duration::from_millis(100),
            "never blocks"
        );
        for reply in [running, second, third] {
            ok(reply.await, "queued call");
        }
        assert_eq!(
            *fixture.ran.lock(),
            vec![1, 2, 3],
            "the refused call ran nowhere"
        );
    }

    #[tokio::test]
    async fn test_writer_runs_after_call_work_once_the_call_is_answered() {
        let fixture = fixture(8).await;
        ok(
            call(&fixture.writer, TestCall::Record(1, Duration::ZERO)).await,
            "call",
        );
        assert_eq!(fixture.after_calls.load(Ordering::SeqCst), 0, "not due");
        ok(
            call(&fixture.writer, TestCall::AfterNext).await,
            "make it due",
        );
        // The work runs before the thread takes the next call.
        ok(
            call(&fixture.writer, TestCall::Record(2, Duration::ZERO)).await,
            "call",
        );
        assert_eq!(fixture.after_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_writer_dropped_while_idle_closes_the_state_and_joins() {
        let fixture = fixture(8).await;
        ok(
            call(&fixture.writer, TestCall::Record(1, Duration::ZERO)).await,
            "call",
        );
        drop(fixture.writer);
        assert!(
            fixture.dropped.load(Ordering::SeqCst),
            "the state is closed when the drop returns"
        );
    }

    #[tokio::test]
    async fn test_writer_dropped_while_busy_returns_at_once_and_finishes_later() {
        let fixture = fixture(8).await;
        let busy = tokio::time::timeout(
            Duration::from_millis(20),
            call(
                &fixture.writer,
                TestCall::Record(1, Duration::from_millis(300)),
            ),
        )
        .await;
        assert!(busy.is_err());
        let before = Instant::now();
        drop(fixture.writer);
        assert!(
            before.elapsed() < Duration::from_millis(200),
            "the drop does not wait for the running call"
        );
        assert!(!fixture.dropped.load(Ordering::SeqCst));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !fixture.dropped.load(Ordering::SeqCst) {
            assert!(Instant::now() < deadline, "the thread must exit on its own");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(*fixture.ran.lock(), vec![1], "the running call finished");
    }

    #[tokio::test]
    async fn test_writer_closing_call_drops_the_state_before_answering() {
        let fixture = fixture(8).await;
        ok(call(&fixture.writer, TestCall::Close).await, "closing call");
        assert!(fixture.dropped.load(Ordering::SeqCst));
        assert!(matches!(
            call(&fixture.writer, TestCall::Record(2, Duration::ZERO)).await,
            Err(StoreError::Io(reason)) if reason.contains("closed")
        ));
    }

    #[tokio::test]
    async fn test_writer_failed_start_is_reported_and_the_thread_stops() {
        let spawned = Writer::<Log>::spawn("ironfix-store-test", 8, || {
            Err(StoreError::Io("cannot open".to_string()))
        });
        let (writer, started) = ok(spawned, "spawn");
        assert!(matches!(
            ok(started.await, "started"),
            Err(StoreError::Io(reason)) if reason == "cannot open"
        ));
        // The thread answers every call that the store is closed.
        assert!(matches!(
            call(&writer, TestCall::Record(1, Duration::ZERO)).await,
            Err(StoreError::Io(reason)) if reason.contains("closed")
        ));
    }
}
