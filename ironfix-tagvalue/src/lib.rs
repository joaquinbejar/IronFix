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
//!   borrow the input buffer, so field values are never copied. The field index
//!   is a `SmallVec<[FieldRef; 32]>`: it stays inline for the first 32 fields
//!   and spills to the heap only for a message with more than 32 fields.
//! - **Dictionary-free**: [`Decoder`] is a byte scanner and does not know what
//!   a tag means, so no schema lookup happens on the decode path. Validating a
//!   message against a schema is a separate, opt-in pass in
//!   `ironfix-dictionary`. Length/Data field pairs (for example 95/96) are the
//!   one exception and are framed by their declared byte count.
//! - **Delimiter search via `memchr`**, which is SIMD-accelerated on supported
//!   targets.
//! - **Checksum**: [`calculate_checksum`] plus formatting and parsing of the
//!   tag 10 trailer.
//! - **Single-buffer encoding**: [`Encoder`] reserves room for the header and
//!   back-fills it, so a frame is assembled without an intermediate buffer or a
//!   copy of the body, and [`Encoder::clear`] retains the capacity for the next
//!   message.
//!
//! ## Both directions are hostile-input boundaries
//!
//! Every entry point here is an untrusted-input parser. [`Decoder`] treats
//! every byte as attacker-controlled: truncated messages, a `BodyLength` (tag
//! 9) that disagrees with the bytes, a bad or malformed `CheckSum` (tag 10), a
//! non-numeric tag, and a `DATA` field whose declared count reaches past the
//! body each map to a typed [`ironfix_core::error::DecodeError`] — never a
//! panic and never an attacker-controlled allocation. A genuinely incomplete
//! buffer is reported distinctly from malformed input, so a caller framing a
//! stream can tell "read more" from "reject this".
//!
//! [`Encoder`] holds the mirror invariant: **every frame it produces is one
//! this crate's [`Decoder`] accepts**. A value carrying the SOH delimiter, an
//! empty value, a framing tag written into the body, a `MsgType` (tag 35) that
//! is missing, not first, or unrepresentable, and half of a `LENGTH`/`DATA`
//! pair written alone are all refused with a typed
//! [`ironfix_core::error::EncodeError`] rather than stamped into a frame whose
//! `BodyLength` and `CheckSum` are correct for corrupted bytes.
//!
//! No performance figure is quoted here, and none should be: the criterion
//! harness under `benches/` records no baseline, so nothing here has been
//! measured — run `make bench` to obtain numbers on your own hardware.

pub mod checksum;
pub mod decoder;
pub mod encoder;

/// SOH (Start of Header), the byte that terminates every FIX field.
///
/// Defined once here and re-exported from [`decoder`] and [`encoder`], which
/// both need it: two independent definitions of one protocol byte are two
/// semver-governed paths that can drift.
pub const SOH: u8 = 0x01;

/// The `=` byte that separates a tag from its value.
pub const EQUALS: u8 = b'=';

pub use checksum::calculate_checksum;
pub use decoder::Decoder;
pub use encoder::Encoder;
pub use ironfix_core::message::RawMessage;
