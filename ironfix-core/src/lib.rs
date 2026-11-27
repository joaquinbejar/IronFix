/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! # IronFix Core
//!
//! Core types, traits, and error definitions for the IronFix FIX protocol engine.
//!
//! This is the root of the workspace dependency graph: it depends on no other
//! IronFix crate, and every other crate speaks the vocabulary defined here.
//!
//! - **Error types**: [`FixError`] and its children [`DecodeError`],
//!   [`EncodeError`], [`SessionError`] and [`StoreError`], all built with
//!   `thiserror`
//! - **Field types**: [`FieldTag`], [`FieldRef`], [`FieldValue`], and the
//!   [`FixField`] trait
//! - **Message types**: [`RawMessage`], [`OwnedMessage`], [`MsgType`], and the
//!   [`FixMessage`] trait
//! - **Core types**: [`SeqNum`], [`Timestamp`], [`CompId`] (an inline
//!   `ArrayString`, not a `String`), and [`Side`]
//! - **Protocol versions**: [`FixVersion`], the single mapping from a FIX
//!   version to its `BeginString` (8) and `ApplVerID` (1128 / 1137)
//! - **Inbound validation seam**: [`InboundValidator`], [`InboundRejection`]
//!   and [`InboundDefect`], which `ironfix-dictionary` implements and
//!   `ironfix-engine` calls, so neither depends on the other (ADR-0031)
//!
//! ## Zero-Copy Design
//!
//! The core abstractions support both zero-copy borrowed views (for hot-path processing)
//! and owned representations (for storage and cross-thread transfer).
//!
//! # Features
//!
//! - **`chrono`** (off by default): `Timestamp::to_datetime` and
//!   `TryFrom<chrono::DateTime<Utc>> for Timestamp`, for interop only.
//!   Without it the crate has no `chrono` in its dependency graph (issue
//!   #225, RUSTSEC-2026-0543): [`Timestamp`] carries its own proleptic
//!   Gregorian calendar, with the civil accessors (`date`, `year`, `month`,
//!   `day`, `hour`, `minute`, `second`, `nanosecond`, `iso_weekday`), the
//!   checked civil constructor `from_utc_ymd_hms_nanos` (a `23:59:60` leap
//!   second folds onto the next day, as the chrono conversion did), Unix
//!   second conversions (`from_unix_seconds`, `from_unix_parts`,
//!   `as_unix_seconds`) and the zero-allocation UTCTimestamp formatters.

pub mod error;
pub mod field;
pub mod message;
pub mod types;
pub mod validation;
pub mod version;

pub use error::{
    CompIdError, DecodeError, EncodeError, FixError, InvalidFieldTag, InvalidSide, MsgTypeError,
    Result, SessionError, StoreError, TimestampError, UnknownFixVersion,
};
pub use field::{
    FieldRef, FieldTag, FieldValue, FixField, USER_DEFINED_EXT_TAG_MAX, USER_DEFINED_EXT_TAG_MIN,
    USER_DEFINED_TAG_MAX, USER_DEFINED_TAG_MIN,
};
pub use message::{CustomMsgType, FixMessage, MSG_TYPE_MAX_LEN, MsgType, OwnedMessage, RawMessage};
pub use types::{COMP_ID_MAX_LEN, CompId, SeqNum, Side, Timestamp};
pub use validation::{InboundDefect, InboundRejection, InboundValidator};
pub use version::FixVersion;
