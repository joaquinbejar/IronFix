/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! # IronFix FAST
//!
//! FAST (FIX Adapted for Streaming) protocol encoding and decoding for the IronFix engine.
//!
//! FAST is a binary encoding protocol used for high-performance market data feeds.
//! It uses techniques like stop-bit encoding, presence maps, and field operators
//! to achieve high compression ratios.
//!
//! ## What this crate provides
//!
//! These are encoding *primitives*, not a complete FAST implementation:
//!
//! - **Stop-bit encoding**: integer and string encode/decode
//! - **Presence maps**: [`PresenceMap`] / [`PresenceMapBuilder`], tracking which
//!   optional fields are present
//! - **Field operators**: [`operators::Operator`] — copy, delta, increment,
//!   tail and default — with per-template and global
//!   [`operators::DictionaryScope`] for previous-value state
//!
//! ## Not provided
//!
//! - **No template definitions and no template XML parser.** Templates are
//!   referred to only by numeric id, for scoping the previous-value dictionary;
//!   nothing here reads a FAST template file or describes a message structure.
//! - **No transport.** There is no UDP multicast receiver and no A/B feed
//!   arbitration.
//! - **Not wired into the engine.** This crate sits parallel to
//!   `ironfix-tagvalue`, depends only on `ironfix-core`, and is not used by the
//!   session or engine path. Driving it is the caller's job — see the `fast_*`
//!   examples in `ironfix-example`.
//!
//! ## Untrusted input
//!
//! Every decoding entry point is an untrusted-input parser. Malformed input
//! maps to a typed [`FastError`] and never to a panic: integer encodings are
//! capped at [`MAX_INT_ENCODED_LEN`] bytes and rejected with
//! [`FastError::IntegerOverflow`] when they would not fit their target type,
//! presence maps are capped at [`MAX_PMAP_BYTES`] bytes, and a declared byte
//! length is validated against the bytes actually available before it is ever
//! used to size an allocation.
//!
//! The encoders are the mirror image: they only ever emit encodings the
//! decoders accept. Values that have no legal FAST representation — a
//! non-ASCII string, a string that begins with a NUL and continues, or
//! `Some(u64::MAX)` in a nullable unsigned field — are refused with a typed
//! error rather than written to the wire in a corrupt form.

pub mod decoder;
pub mod encoder;
pub mod error;
pub mod operators;
pub mod pmap;

pub use decoder::{FastDecoder, MAX_INT_ENCODED_LEN};
pub use encoder::FastEncoder;
pub use error::FastError;
pub use pmap::{MAX_PMAP_BYTES, PresenceMap, PresenceMapBuilder};
