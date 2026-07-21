/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! # IronFix Transport
//!
//! FIX message framing for the IronFix protocol engine.
//!
//! This crate contains exactly one thing: [`FixCodec`], a `tokio_util` codec
//! that splits a byte stream into complete FIX messages using `BeginString`,
//! `BodyLength` and the `CheckSum` trailer, and encodes already-serialised
//! messages back onto the wire. Its read buffer is bounded and the trailer is
//! verified unconditionally; malformed framing surfaces as [`CodecError`].
//!
//! The codec frames, it does not interpret. It never inspects session state and
//! never applies business logic.
//!
//! ## Not provided
//!
//! Despite the crate name, there are **no TCP connector or acceptor helpers and
//! no TLS support** here — there is no `rustls` dependency, and the crate's only
//! IronFix dependencies are `ironfix-core` and `ironfix-tagvalue`. Opening a
//! socket is the caller's job; `ironfix_engine::Initiator` calls
//! `TcpStream::connect` directly and wraps the result in this codec.

pub mod codec;

pub use codec::{CodecError, FixCodec};
