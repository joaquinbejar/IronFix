/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! # IronFix SOFH
//!
//! Simple Open Framing Header (SOFH) framing for the IronFix protocol engine:
//! the binary counterpart of `ironfix_transport::FixCodec`.
//!
//! SOFH prefixes every message on a stream with six bytes: a `Message_Length`
//! that counts the whole frame, header included, and an `Encoding_Type` that
//! names the payload's encoding (Simple Binary Encoding, FIX tag=value, FAST,
//! and others). It is how SBE messages, and FIXP sessions, are framed on TCP.
//!
//! - [`SofhHeader`]: the header, with `const fn` encode and decode;
//! - [`EncodingType`]: the registered encoding types, with unregistered values
//!   preserved;
//! - [`SofhCodec`]: a `tokio_util` `Decoder` yielding [`SofhFrame`]s and an
//!   `Encoder` framing payloads, with a size ceiling;
//! - [`SofhError`]: every framing failure, typed.
//!
//! The codec frames, it does not interpret: it never decodes a payload and
//! depends on no SBE codec.
//!
//! ## Specification
//!
//! This crate implements the FIX Simple Open Framing Header Technical
//! Specification **v1.0**, the Draft Standard approved by the FIX Global
//! Technical Committee in December 2016
//! (<https://github.com/FIXTradingCommunity/fix-simple-open-framing-header>).
//! Every wire detail is cited to its section where it is implemented: the
//! layout on [`SofhHeader`] (module `header`), each encoding type on its
//! [`EncodingType`] variant (module `encoding`).
//!
//! The later v1.1 Release Candidate 1 (September 2019) is not the standard
//! and is not implemented. Its two changes are: a little-endian header by
//! bilateral agreement (this crate reads and writes the header big-endian
//! only), and SBE 2.0 encoding types `0x5BE1` / `0xEB51` (decoded here as
//! [`EncodingType::Unregistered`], with the value preserved).
//!
//! ## Untrusted input
//!
//! Every byte the decoder reads is chosen by the counterparty. A declared
//! length below the 7-byte minimum, a declared length above the configured
//! ceiling ([`SofhCodec::with_max_message_size`], 1 MiB by default), and a
//! frame cut short by the end of the stream are each a typed [`SofhError`],
//! never a panic. A truncated frame mid-stream is `Ok(None)`, and the codec
//! reserves at most the rest of the declared frame, which the ceiling bounds.
//! Nothing is ever allocated from a length above the ceiling.
//!
//! ## Decisions
//!
//! - **Unknown encoding types are preserved, not rejected.** The frame
//!   boundary depends on `Message_Length` alone, and SOFH exists so that a
//!   receiver can skip a message it has no codec for; it can only do that if
//!   the frame reaches it. See the `encoding` module.
//! - **Every error is fatal for the stream.** SOFH has no resynchronisation
//!   anchor like the `8=FIX` of tag=value, so after a length that cannot be
//!   trusted the next frame boundary is unknown. The decoder consumes nothing
//!   on error, and the caller must close the connection. See [`SofhError`].
//!
//! ## Example
//!
//! ```
//! use bytes::BytesMut;
//! use ironfix_sofh::{EncodingType, SofhCodec, SofhError};
//! use tokio_util::codec::{Decoder, Encoder};
//!
//! fn main() -> Result<(), SofhError> {
//!     let mut codec = SofhCodec::new().with_max_message_size(64 * 1024);
//!
//!     let mut wire = BytesMut::new();
//!     codec.encode((EncodingType::SbeV1LittleEndian, &b"an sbe message"[..]), &mut wire)?;
//!     // Message_Length 20 (6 + 14), then Encoding_Type 0xEB50, both big-endian.
//!     assert_eq!(wire.get(..6), Some(&[0, 0, 0, 20, 0xEB, 0x50][..]));
//!
//!     if let Some(frame) = codec.decode(&mut wire)? {
//!         assert_eq!(frame.encoding_type(), EncodingType::SbeV1LittleEndian);
//!         assert_eq!(frame.payload(), b"an sbe message");
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ## Not provided
//!
//! No FIXP session, no SBE codec, and no wiring into `ironfix-engine` yet:
//! those are ADR-0003's follow-ups (`ironfix-fixp`, and FIXP over SOFH in the
//! engine behind a `fixp` feature). Opening a socket is the caller's job, as
//! with `FixCodec`.

pub mod codec;
pub mod encoding;
pub mod error;
pub mod header;

pub use codec::{SofhCodec, SofhFrame};
pub use encoding::{EncodingType, UnregisteredEncoding};
pub use error::SofhError;
pub use header::SofhHeader;
