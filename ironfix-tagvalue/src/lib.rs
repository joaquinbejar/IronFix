/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! # IronFix Tag-Value
//!
//! Zero-copy FIX tag=value encoding and decoding for the IronFix engine.
//!
//! This crate parses and serialises FIX messages in the standard tag=value
//! format with SOH (0x01) delimiters.
//!
//! ## Features
//!
//! - **Zero-copy decoding**: decoded fields are `FieldRef<'a>` slices that
//!   borrow the input buffer; the decoder allocates nothing per message.
//! - **Dictionary-free**: [`Decoder`] is a byte scanner and does not know what
//!   a tag means, so no schema lookup happens on the decode path. Validating a
//!   message against a schema is a separate, opt-in pass in
//!   `ironfix-dictionary`. Length/Data field pairs (for example 95/96) are the
//!   one exception and are framed by their declared byte count.
//! - **Delimiter search via `memchr`**, which is SIMD-accelerated on supported
//!   targets.
//! - **Checksum**: [`calculate_checksum`] plus formatting and parsing of the
//!   tag 10 trailer.
//!
//! ## Untrusted input
//!
//! Every entry point here is an untrusted-input parser. Truncated messages, a
//! bogus `BodyLength` (tag 9), a bad or malformed `CheckSum` (tag 10), a
//! non-numeric tag, and an out-of-range declared length each map to a typed
//! `DecodeError` — never a panic and never an attacker-controlled allocation.
//! A genuinely incomplete buffer is reported distinctly from malformed input,
//! so a caller framing a stream can tell "read more" from "reject this".
//!
//! No performance figure is quoted here, and none should be: this workspace has
//! no benchmark harness, so nothing in it has been measured.

pub mod checksum;
pub mod decoder;
pub mod encoder;

pub use checksum::calculate_checksum;
pub use decoder::Decoder;
pub use encoder::Encoder;
pub use ironfix_core::message::RawMessage;
