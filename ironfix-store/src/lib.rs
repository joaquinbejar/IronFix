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
//!   numbers across restarts
//! - **[`StoredMessage`]**: one message as it was filed — verbatim frame bytes,
//!   its sequence number, and its recorded `MsgType`
//! - **[`MemoryStore`]**: an in-memory implementation, backed by a
//!   `parking_lot::RwLock<BTreeMap<..>>` and two atomics
//!
//! ## Not persistent
//!
//! [`MemoryStore`] is the **only** implementation — there is no file-based or
//! memory-mapped store, so nothing here survives a process restart. A durable
//! implementation is separate, tracked work; until it lands, restart recovery
//! is a gap, not a feature.

pub mod memory;
pub mod stored;
pub mod traits;

pub use memory::MemoryStore;
pub use stored::StoredMessage;
pub use traits::MessageStore;
