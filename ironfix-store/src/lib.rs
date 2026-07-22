/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! # IronFix Store
//!
//! Message persistence and storage for the IronFix FIX protocol engine.
//!
//! This crate provides:
//! - **[`MessageStore`] trait**: the abstract interface for storing outbound
//!   messages so a `ResendRequest` can be answered, and for persisting sequence
//!   numbers across restarts
//! - **[`MemoryStore`]**: an in-memory implementation, backed by a
//!   `parking_lot::RwLock<BTreeMap<..>>` and two atomics
//!
//! ## Current limitations
//!
//! [`MemoryStore`] is the **only** implementation — there is no file-based or
//! memory-mapped store, so nothing here survives a process restart.
//!
//! Furthermore, `ironfix-engine` does not currently use this crate at all: no
//! outbound message is stored and no sequence number is persisted, so
//! resend-from-store is not implemented. An inbound `ResendRequest` is answered
//! with a `SequenceReset`/gap fill rather than with the original messages.

pub mod memory;
pub mod traits;

pub use memory::MemoryStore;
pub use traits::MessageStore;
