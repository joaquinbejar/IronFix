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
//! ## What this crate implements
//!
//! - **Stop-bit encoding**: unsigned and signed integers, ASCII strings and
//!   byte vectors, each in a nullable and a non-nullable form, encoder and
//!   decoder paired so every encoding this crate emits is one it accepts back.
//! - **Presence maps**: [`PresenceMap`] decodes a map with a size ceiling and
//!   encodes it in the minimal form.
//! - **Field operators**: the [`Operator`] table, and the
//!   rule that decides — from the operator, the field's optionality and the
//!   presence map — whether a field's value is in the stream, comes from the
//!   template's initial value, comes from the operator dictionary, or is
//!   absent. That decision is
//!   [`Operator::transfer`](operators::Operator::transfer), and it is the piece
//!   that keeps a positional presence map aligned.
//!
//! ## What this crate does not implement yet
//!
//! There is **no template layer**: nothing here parses a FAST template XML
//! file, holds a field sequence, or applies an operator to produce a value.
//! Concretely, still missing are the template model (field identity, type,
//! optionality and initial value), operator *application* (delta arithmetic,
//! increment, tail combination), the decimal codec that pairs a mantissa with
//! an exponent, and sequence decoding with its length ceiling. Several
//! [`FastError`] variants exist for that work and are not constructed yet.
//!
//! Two consequences are worth stating plainly. This crate cannot decode a FAST
//! message end to end — it decodes the fields of one, given something else that
//! knows their order. And because a presence map's bits are only meaningful
//! against a known field count, the padding bits inside its last byte are
//! indistinguishable here from genuinely absent fields; closing that gap needs
//! the template layer.
//!
//! `ironfix-fast` is also not wired into the session path: it is parallel to
//! `ironfix-tagvalue`, not downstream of it.
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
//! non-ASCII string, or a string that begins with a NUL and continues — are
//! refused with a typed error rather than written to the wire in a corrupt
//! form. The nullable unsigned codec covers the full `0..=u64::MAX` domain:
//! `Some(u64::MAX)` biases to 2^64 and round-trips through a `u128` path
//! rather than being rejected.

pub mod decoder;
pub mod encoder;
pub mod error;
pub mod operators;
pub mod pmap;

pub use decoder::{FastDecoder, MAX_INT_ENCODED_LEN};
pub use encoder::FastEncoder;
pub use error::FastError;
pub use operators::{DictionaryScope, DictionaryValue, FieldTransfer, Operator};
pub use pmap::{MAX_PMAP_BYTES, PresenceMap, PresenceMapBuilder};
