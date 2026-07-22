/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! # IronFix Core
//!
//! Core types, traits, and error definitions for the IronFix FIX protocol engine.
//!
//! This crate provides the fundamental building blocks used across all IronFix crates:
//! - **Error types**: Unified error handling with `thiserror`
//! - **Field types**: `FieldTag`, `FieldValue`, and the `FixField` trait
//! - **Message types**: `RawMessage`, `OwnedMessage`, and the `FixMessage` trait
//! - **Core types**: `SeqNum`, `Timestamp`, `CompID`, `MsgType`
//! - **Protocol versions**: `FixVersion`, the single mapping from a FIX
//!   version to its `BeginString` (8) and `ApplVerID` (1128 / 1137)
//!
//! ## Zero-Copy Design
//!
//! The core abstractions support both zero-copy borrowed views (for hot-path processing)
//! and owned representations (for storage and cross-thread transfer).

pub mod error;
pub mod field;
pub mod message;
pub mod types;
pub mod version;

pub use error::{
    CompIdError, DecodeError, EncodeError, FixError, InvalidFieldTag, InvalidSide, MsgTypeError,
    Result, SessionError, StoreError, TimestampError, UnknownFixVersion,
};
pub use field::{FieldRef, FieldTag, FieldValue, FixField, USER_DEFINED_TAG_MIN};
pub use message::{CustomMsgType, FixMessage, MSG_TYPE_MAX_LEN, MsgType, OwnedMessage, RawMessage};
pub use types::{COMP_ID_MAX_LEN, CompId, SeqNum, Side, Timestamp};
pub use version::FixVersion;
