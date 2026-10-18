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
//! - **[`StoredMessage`]**: one message as it was filed — verbatim frame bytes,
//!   its sequence number, and its recorded `MsgType`
//! - **[`MemoryStore`]**: an in-memory implementation, backed by a
//!   `parking_lot::RwLock<BTreeMap<..>>` and two atomics. Nothing in it
//!   survives the process.
//! - **[`FileStore`]**: a persistent implementation, one append-only journal
//!   file per store holding the filed frames and both sequence counters, so a
//!   session resumes from its counters after a restart and a `ResendRequest`
//!   is answered with the original frames. Configured by [`FileStoreConfig`].
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
//! against an OS crash or a power loss. A [`FileStore`] cuts a torn or damaged
//! journal tail when it opens, and never returns a record it cannot vouch for
//! (see the [`file`](mod@file) module and `doc/adr/0006-file-store.md`). There
//! is no memory-mapped store.

pub mod file;
pub mod memory;
pub mod stored;
pub mod traits;

pub use file::{
    FileStore, FileStoreConfig, FileStoreConfigError, SyncPolicy, Truncation, TruncationCause,
};
pub use memory::MemoryStore;
pub use stored::StoredMessage;
pub use traits::MessageStore;
