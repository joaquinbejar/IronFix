/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! # IronFix Store
//!
//! Message storage for the IronFix FIX protocol engine.
//!
//! A store exists to answer one question the FIX session layer cannot answer
//! on its own: *what did we send under sequence number N?* `ironfix-engine`
//! files every sequenced outbound frame here, and replays from here when a
//! counterparty sends a `ResendRequest` (35=2).
//!
//! This crate provides:
//! - **[`MessageStore`] trait**: the abstract interface for storing outbound
//!   messages so a `ResendRequest` can be answered, and for persisting sequence
//!   numbers across restarts. Every write, the counters included, is
//!   asynchronous and fallible, and the engine relies on a stated ordering (see
//!   the [`traits`] module docs)
//! - **[`SyncMessageStore`]**: the same contract with synchronous methods,
//!   for a driver without an async runtime (ADR-0002, issue #92), and
//!   [`SyncStoreAdapter`], which uses one where a [`MessageStore`] is
//!   expected (see the [`sync_traits`] module docs for when that is sound)
//! - **[`StoredMessage`]**: one message as it was filed — verbatim frame bytes,
//!   its sequence number, and its recorded `MsgType`
//! - **[`PendingStore`]**: a bounded submit/poll form of any
//!   [`SyncMessageStore`] (issue #222): [`PendingStore::submit`] queues an
//!   outbound frame for a worker thread and returns a [`Ticket`] at once, or
//!   [`PendingError::Full`] at the configured bound, and
//!   [`PendingStore::poll_durable`] reports the highest durable sequence
//!   number without blocking. Built with or without the `async` feature.
//! - **[`MemoryStore`]**: an in-memory implementation, backed by a
//!   `parking_lot::RwLock<BTreeMap<..>>` and two atomics. Nothing in it
//!   survives the process.
//! - **[`FileStore`]**: a persistent implementation, one journal file per
//!   store holding the filed frames (appended) and both sequence counters (in
//!   two fixed slots, so inbound traffic does not grow the file), written by
//!   one writer thread per store, so a session resumes from its counters
//!   after a restart and a `ResendRequest` is answered with the original
//!   frames. Configured by [`FileStoreConfig`].
//!
//! ## What survives what
//!
//! | Store | Process crash | OS crash or power loss |
//! |---|---|---|
//! | [`MemoryStore`] | nothing | nothing |
//! | [`FileStore`], [`SyncPolicy::EveryWrite`] (default) | every write that returned `Ok` | every write that returned `Ok` |
//! | [`FileStore`], [`SyncPolicy::EveryN`] | every write that returned `Ok` | all but at most the last `n - 1` |
//! | [`FileStore`], [`SyncPolicy::Never`] | every write that returned `Ok` | nothing is promised |
//!
//! Only [`SyncPolicy::EveryWrite`] makes the engine's write order a guarantee
//! against an OS crash or a power loss, and only under the engine's
//! `StoreFailurePolicy::CloseSession` does a failed write keep its frame off
//! the wire. These guarantees are stated for Unix. When a [`FileStore`]
//! opens, it cuts only what an interrupted write can leave at the end of its
//! journal; damage anywhere else makes it refuse to open
//! (`StoreError::Corrupted`) until an operator runs [`FileStore::repair`],
//! after which the session must reset its sequence. It never returns a record
//! it cannot vouch for (see the [`file`](mod@file) module and
//! `doc/adr/0006-file-store.md`). There is no memory-mapped store.
//!
//! ## Features
//!
//! - **`async`** (default): [`MessageStore`], [`SyncStoreAdapter`] and
//!   [`FileStore`], which depend on `tokio` and `async-trait`. With
//!   `default-features = false` the crate is [`SyncMessageStore`],
//!   [`MemoryStore`] and [`StoredMessage`], and neither `tokio` nor
//!   `async-trait` is in its normal dependency graph (issue #221). There is
//!   no synchronous file store yet: [`FileStore`] answers through its writer
//!   thread with `tokio` oneshot replies and needs the feature.

// The store contract (persistence order, call order, frame requirements) is
// in the `traits` module docs, built in every configuration. Method-level
// links from `SyncMessageStore` to `MessageStore`, and links to
// `FileStore`, target items the `async` feature compiles; without it they
// cannot resolve. The published docs build with default features.
#![cfg_attr(not(feature = "async"), allow(rustdoc::broken_intra_doc_links))]

#[cfg(feature = "async")]
pub mod file;
pub mod memory;
pub mod pending;
pub mod stored;
pub mod sync_traits;
pub mod traits;

#[cfg(feature = "async")]
pub use file::{
    FileStore, FileStoreConfig, FileStoreConfigError, SyncPolicy, Truncation, TruncationCause,
};
pub use memory::MemoryStore;
pub use pending::{PendingError, PendingStore, Ticket};
pub use stored::StoredMessage;
pub use sync_traits::SyncMessageStore;
#[cfg(feature = "async")]
pub use sync_traits::SyncStoreAdapter;
#[cfg(feature = "async")]
pub use traits::MessageStore;
