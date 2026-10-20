/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! PRIVATE module: the bounded queue that carries a [`Connection`]'s commands
//! to the session reactor (issue #76).
//!
//! It replaces a `tokio::sync::mpsc` channel, which allocates a block of
//! slots as its tail advances (about one per 128 sends), with a ring the
//! size of the session's outbound capacity, allocated once when the session
//! starts and never grown. A send takes a slot from a [`Semaphore`] with as
//! many permits as the ring holds before it queues, so senders that find it
//! full are admitted in the order they began to wait, as on the channel, and
//! one that waits cannot be overtaken by later sends. The reactor waits for
//! a command through [`Notify`]. The ring is a `VecDeque` behind a
//! `std::sync::Mutex`, held only to push or pop one command and never across
//! an `.await`; the waiters of both live in the futures that wait, so waiting
//! allocates nothing either.
//!
//! The semantics are the channel's:
//!
//! - commands arrive in the order they were queued;
//! - [`CommandReceiver::recv`] returns `None` once every [`CommandSender`] is
//!   dropped and the ring is empty, so the reactor still reads "all handles
//!   dropped";
//! - once the receiver closes ([`CommandReceiver::close`]), a send fails at
//!   once and hands its command back, and the receiver can still drain what
//!   was queued ([`CommandReceiver::try_recv`]); once it is dropped, what was
//!   queued is dropped with it, so a surviving handle keeps no command (or
//!   pooled message) alive;
//! - both futures are cancel-safe: a send dropped before it queued its
//!   command queued nothing, and a receive dropped while waiting took
//!   nothing.
//!
//! [`Connection`]: crate::Connection

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use tokio::sync::{Notify, Semaphore};

/// What both ends share.
struct Shared<T> {
    /// The queued commands; its capacity is the bound, and it never grows.
    ring: Mutex<VecDeque<T>>,
    /// The bound.
    capacity: usize,
    /// Live senders.
    senders: AtomicUsize,
    /// Free slots of the ring, handed out in the order senders asked; closed
    /// once the receiver closes or is dropped.
    slots: Semaphore,
    /// Wakes the receiver: a command was queued, or the last sender left.
    queued: Notify,
}

impl<T> Shared<T> {
    /// The ring, taken over a poisoned lock: no code holding it panics, and
    /// a queue of commands stays valid whatever was interrupted.
    fn ring(&self) -> MutexGuard<'_, VecDeque<T>> {
        self.ring.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Creates a queue that holds at most `capacity` commands (at least one).
pub(crate) fn command_queue<T>(capacity: usize) -> (CommandSender<T>, CommandReceiver<T>) {
    let capacity = capacity.max(1);
    let shared = Arc::new(Shared {
        ring: Mutex::new(VecDeque::with_capacity(capacity)),
        capacity,
        senders: AtomicUsize::new(1),
        slots: Semaphore::new(capacity),
        queued: Notify::new(),
    });
    (
        CommandSender {
            shared: Arc::clone(&shared),
        },
        CommandReceiver { shared },
    )
}

/// The sending end; cloned with each [`Connection`](crate::Connection).
pub(crate) struct CommandSender<T> {
    shared: Arc<Shared<T>>,
}

impl<T> CommandSender<T> {
    /// Queues `command`, waiting for room while the queue is full.
    ///
    /// # Errors
    /// The receiver closed: `command` is handed back, unqueued.
    pub(crate) async fn send(&self, command: T) -> Result<(), T> {
        // A slot first, in waiting order; the permit is given back by the
        // receiver when it takes the command out.
        let Ok(slot) = self.shared.slots.acquire().await else {
            return Err(command);
        };
        slot.forget();
        // A slot guarantees room: the ring holds at most as many commands as
        // there are permits.
        self.shared.ring().push_back(command);
        self.shared.queued.notify_one();
        Ok(())
    }
}

impl<T> Clone for CommandSender<T> {
    fn clone(&self) -> Self {
        self.shared.senders.fetch_add(1, Ordering::AcqRel);
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<T> Drop for CommandSender<T> {
    fn drop(&mut self) {
        if self.shared.senders.fetch_sub(1, Ordering::AcqRel) == 1 {
            // The last sender: the receiver reads the end once the ring is
            // empty.
            self.shared.queued.notify_one();
        }
    }
}

impl<T> fmt::Debug for CommandSender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommandSender")
            .field("capacity", &self.shared.capacity)
            .field("closed", &self.shared.slots.is_closed())
            .finish()
    }
}

/// The receiving end, owned by the reactor.
pub(crate) struct CommandReceiver<T> {
    shared: Arc<Shared<T>>,
}

impl<T> CommandReceiver<T> {
    /// The next command, waiting for one; `None` once every sender is gone
    /// and nothing is left.
    pub(crate) async fn recv(&self) -> Option<T> {
        loop {
            let queued = self.shared.queued.notified();
            tokio::pin!(queued);
            queued.as_mut().enable();
            if let Some(command) = self.try_recv() {
                return Some(command);
            }
            if self.shared.senders.load(Ordering::Acquire) == 0 {
                // A send that completed before the last sender left is in
                // the ring already.
                return self.try_recv();
            }
            queued.await;
        }
    }

    /// The next command if one is queued, without waiting.
    pub(crate) fn try_recv(&self) -> Option<T> {
        let command = self.shared.ring().pop_front();
        if command.is_some() {
            // The slot is free again: the oldest waiting send takes it.
            self.shared.slots.add_permits(1);
        }
        command
    }

    /// Refuses further sends, waiting ones included; what is queued can still
    /// be taken with [`CommandReceiver::try_recv`].
    pub(crate) fn close(&self) {
        self.shared.slots.close();
    }
}

impl<T> Drop for CommandReceiver<T> {
    fn drop(&mut self) {
        self.close();
        // What is still queued is dropped now, not when the last sender
        // goes: a handle that outlives the session keeps nothing alive. One
        // command at a time, each dropped after the lock is released.
        loop {
            let command = self.shared.ring().pop_front();
            match command {
                Some(command) => drop(command),
                None => break,
            }
        }
    }
}

impl<T> fmt::Debug for CommandReceiver<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommandReceiver")
            .field("capacity", &self.shared.capacity)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    /// The send future holds no lock across its wait, so it is `Send`, as
    /// `Connection::send` must be.
    #[test]
    fn test_the_send_future_is_send() {
        fn is_send<F: std::future::Future + Send>(_: &F) {}
        let (tx, _rx) = command_queue::<u8>(1);
        let send = tx.send(1);
        is_send(&send);
    }

    /// A send already waiting for room takes the next free slot: later
    /// sends cannot overtake it however many slots are freed (#197 review).
    #[tokio::test]
    async fn test_a_waiting_send_is_admitted_before_later_ones() {
        let (tx, rx) = command_queue(1);
        assert!(tx.send(0).await.is_ok());
        let waiting = {
            let tx = tx.clone();
            tokio::spawn(async move { tx.send(1).await })
        };
        // Let it start waiting.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert_eq!(rx.try_recv(), Some(0));
        // A fresh send now waits behind the older one.
        let later = timeout(Duration::from_millis(20), tx.send(2)).await;
        assert!(later.is_err(), "the freed slot belongs to the waiting send");
        assert!(matches!(waiting.await, Ok(Ok(()))));
        assert_eq!(rx.try_recv(), Some(1));
    }

    /// Dropping the receiver drops what is queued, while a sender lives on
    /// (#197 review): a surviving handle keeps nothing alive.
    #[tokio::test]
    async fn test_dropping_the_receiver_drops_what_is_queued() {
        let marker = Arc::new(());
        let (tx, rx) = command_queue(4);
        assert!(tx.send(Arc::clone(&marker)).await.is_ok());
        assert!(tx.send(Arc::clone(&marker)).await.is_ok());
        assert_eq!(Arc::strong_count(&marker), 3);
        drop(rx);
        assert_eq!(
            Arc::strong_count(&marker),
            1,
            "the queued commands are gone"
        );
        assert!(tx.send(Arc::clone(&marker)).await.is_err());
        assert_eq!(Arc::strong_count(&marker), 1);
    }

    #[tokio::test]
    async fn test_commands_arrive_in_order() {
        let (tx, rx) = command_queue(4);
        for value in 0..4 {
            assert!(tx.send(value).await.is_ok());
        }
        for value in 0..4 {
            assert_eq!(rx.recv().await, Some(value));
        }
    }

    #[tokio::test]
    async fn test_a_full_queue_waits_for_room() {
        let (tx, rx) = command_queue(1);
        assert!(tx.send(1).await.is_ok());
        let blocked = timeout(Duration::from_millis(20), tx.send(2)).await;
        assert!(blocked.is_err(), "a full queue makes the send wait");
        let sender = tokio::spawn(async move { tx.send(3).await.is_ok() });
        tokio::task::yield_now().await;
        assert_eq!(rx.recv().await, Some(1));
        assert!(matches!(sender.await, Ok(true)), "room wakes the sender");
        assert_eq!(rx.recv().await, Some(3));
    }

    #[tokio::test]
    async fn test_recv_ends_once_every_sender_is_gone_and_the_ring_is_empty() {
        let (tx, rx) = command_queue(4);
        let other = tx.clone();
        assert!(tx.send(1).await.is_ok());
        drop(tx);
        assert!(other.send(2).await.is_ok());
        drop(other);
        assert_eq!(rx.recv().await, Some(1));
        assert_eq!(rx.recv().await, Some(2));
        assert_eq!(rx.recv().await, None);
    }

    #[tokio::test]
    async fn test_dropping_the_last_sender_wakes_a_waiting_receiver() {
        let (tx, rx) = command_queue::<u8>(4);
        let receiver = tokio::spawn(async move { rx.recv().await });
        tokio::task::yield_now().await;
        drop(tx);
        let ended = timeout(Duration::from_secs(1), receiver).await;
        assert!(matches!(ended, Ok(Ok(None))));
    }

    #[tokio::test]
    async fn test_a_closed_queue_refuses_sends_and_still_drains() {
        let (tx, rx) = command_queue(1);
        assert!(tx.send(1).await.is_ok());
        let waiting = {
            let tx = tx.clone();
            tokio::spawn(async move { tx.send(2).await })
        };
        tokio::task::yield_now().await;
        rx.close();
        let refused = timeout(Duration::from_secs(1), waiting).await;
        assert!(
            matches!(refused, Ok(Ok(Err(2)))),
            "a waiting send is refused"
        );
        assert_eq!(tx.send(3).await, Err(3));
        assert_eq!(rx.try_recv(), Some(1));
        assert_eq!(rx.try_recv(), None);
    }

    #[tokio::test]
    async fn test_dropping_the_receiver_refuses_sends() {
        let (tx, rx) = command_queue(4);
        drop(rx);
        assert_eq!(tx.send(1).await, Err(1));
    }

    #[tokio::test]
    async fn test_a_cancelled_send_queues_nothing() {
        let (tx, rx) = command_queue(1);
        assert!(tx.send(1).await.is_ok());
        // Cancelled while waiting for room: nothing is queued.
        let _ = timeout(Duration::from_millis(10), tx.send(2)).await;
        assert_eq!(rx.try_recv(), Some(1));
        assert_eq!(rx.try_recv(), None);
    }
}
