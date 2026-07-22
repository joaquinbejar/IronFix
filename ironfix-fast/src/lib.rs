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
//! ## Features
//!
//! - **Stop-bit encoding**: Efficient integer and string encoding
//! - **Presence maps**: Track which optional fields are present
//! - **Field operators**: Copy, Delta, Increment, Tail, etc.
//! - **Template support**: Message structure definitions
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
