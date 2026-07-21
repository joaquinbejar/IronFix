/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

#![allow(non_snake_case)]

//! # IronFix
//!
//! Umbrella facade over the IronFix FIX/FAST workspace: this crate re-exports
//! every other `ironfix-*` crate under a module of its own, plus a [`prelude`]
//! of the types most programs need. It adds no protocol logic of its own.
//!
//! IronFix implements FIX tag=value messaging and the FAST encoding primitives
//! directly — there is no upstream protocol library beneath it. Decoding is
//! zero-copy and dictionary-free; validating a message against a schema is a
//! separate, opt-in pass ([`dictionary::Validator`]).
//!
//! ## Features
//!
//! - **Zero-copy decoding**: decoded fields borrow the input buffer instead of
//!   allocating; delimiter search uses `memchr`, which is SIMD-accelerated on
//!   supported targets.
//! - **Typed error paths**: every malformed-input case in the decoders is a
//!   typed error, never a panic and never an attacker-sized allocation.
//! - **Type-safe session states**: the session FSM is a sealed typestate, so
//!   illegal transitions do not compile.
//! - **Async**: everything that touches a socket runs on Tokio. There is no
//!   synchronous or kernel-bypass transport mode.
//!
//! ## Current limitations
//!
//! Read these before designing around the crate:
//!
//! - `ironfix-engine` provides an [`engine::Initiator`] only — there is **no
//!   Acceptor**. The server-side examples hand-roll their accept loop.
//! - [`engine::EngineBuilder`] collects configuration but has **no terminal
//!   `build()` method**; the working entry point is
//!   `Initiator::new(config, app).connect(addr)`.
//! - The engine never reads or writes a [`store::MessageStore`], so
//!   resend-from-store is not implemented; an inbound `ResendRequest` is
//!   answered with a gap fill. [`store::MemoryStore`] is the only store.
//! - [`transport`] contains only a framing codec — no TCP connector or
//!   acceptor and no TLS.
//! - Only FIX 4.4 has an embedded dictionary; other versions need
//!   `Dictionary::from_quickfix_xml`. The validator is never invoked
//!   automatically.
//! - [`fast`] is standalone: no template XML parser, no UDP multicast, and no
//!   wiring into the session path.
//! - No benchmark harness exists in this workspace, so no latency or
//!   throughput figure here has been measured.
//!
//! ## Quick Start
//!
//! Connect as an initiator, send a `NewOrderSingle`, then log out. The engine
//! owns the socket and stamps the header, `MsgSeqNum` and trailer.
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! use ironfix_example::core::{CompId, MsgType};
//! use ironfix_example::engine::{Initiator, NoOpApplication, OutboundMessage, SessionConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = SessionConfig::new(
//!         CompId::new("SENDER")?,
//!         CompId::new("TARGET")?,
//!         "FIX.4.4",
//!     )
//!     .with_heartbeat_interval(Duration::from_secs(30));
//!
//!     // Substitute your own `Application` impl for NoOpApplication to receive
//!     // on_logon / from_app / from_admin callbacks.
//!     let initiator = Initiator::new(config, Arc::new(NoOpApplication))
//!         .with_connect_timeout(Duration::from_secs(5));
//!     let connection = initiator.connect("127.0.0.1:9876").await?;
//!
//!     let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
//!     order
//!         .push_str(11, "ORD001")
//!         .push_str(55, "AAPL")
//!         .push_char(54, '1')
//!         .push_uint(38, 100)
//!         .push_str(44, "150.50")
//!         .push_char(40, '2');
//!     connection.send(order).await?;
//!
//!     connection.logout().await?;
//!     connection.wait_closed().await;
//!     Ok(())
//! }
//! ```
//!
//! See `examples/fix44_engine_client.rs` for the same flow with a real
//! `Application` implementation.
//!
//! ## Crate Organization
//!
//! - [`core`]: Fundamental types, traits, and error definitions
//! - [`dictionary`]: FIX specification parsing and dictionary management
//! - [`tagvalue`]: Zero-copy tag=value encoding and decoding
//! - [`session`]: Session layer protocol logic (no I/O)
//! - [`store`]: The `MessageStore` trait and an in-memory implementation
//! - [`transport`]: The `FixCodec` framing codec
//! - [`fast`]: FAST protocol encoding and decoding primitives
//! - [`engine`]: The composition root — `Initiator`, `Connection`, `Application`

pub mod core {
    //! Core types, traits, and error definitions.
    pub use ironfix_core::*;
}

pub mod dictionary {
    //! FIX specification parsing and dictionary management.
    pub use ironfix_dictionary::*;
}

pub mod tagvalue {
    //! Zero-copy tag=value encoding and decoding.
    pub use ironfix_tagvalue::*;
}

pub mod session {
    //! Session layer protocol implementation.
    pub use ironfix_session::*;
}

pub mod store {
    //! The `MessageStore` trait and its in-memory implementation.
    //!
    //! Note that the engine does not currently read from or write to a store.
    pub use ironfix_store::*;
}

pub mod transport {
    //! FIX message framing: the `FixCodec` Tokio codec.
    //!
    //! This crate does not provide TCP connect/accept helpers or TLS.
    pub use ironfix_transport::*;
}

pub mod fast {
    //! FAST protocol encoding and decoding primitives.
    //!
    //! Standalone: not wired into the session or engine path.
    pub use ironfix_fast::*;
}

pub mod engine {
    //! The composition root: `Initiator`, `Connection`, and the `Application`
    //! callback trait. Client-side only — there is no acceptor.
    pub use ironfix_engine::*;
}

/// Prelude module for convenient imports.
pub mod prelude {
    // Core types
    pub use ironfix_core::{
        CompId, DecodeError, EncodeError, FieldRef, FieldTag, FieldValue, FixError, FixField,
        FixMessage, MsgType, OwnedMessage, RawMessage, Result, SeqNum, SessionError, Side,
        StoreError, Timestamp,
    };

    // Dictionary
    pub use ironfix_dictionary::{Dictionary, FieldDef, FieldType, MessageDef, Version};

    // Tag-value encoding
    pub use ironfix_tagvalue::{Decoder, Encoder, calculate_checksum};

    // Session
    pub use ironfix_session::{
        Active, Connecting, Disconnected, HeartbeatManager, LogonSent, LogoutPending, Resending,
        SequenceManager, SessionConfig, SessionState,
    };

    // Store
    pub use ironfix_store::{MemoryStore, MessageStore};

    // Transport
    pub use ironfix_transport::{CodecError, FixCodec};

    // FAST
    pub use ironfix_fast::{FastDecoder, FastEncoder, FastError, PresenceMap};

    // Engine
    pub use ironfix_engine::{Application, EngineBuilder};
}

#[cfg(test)]
mod tests {
    use super::prelude::*;

    #[test]
    fn test_prelude_imports() {
        // Verify that prelude imports work
        let _seq = SeqNum::new(1);
        let _ts = Timestamp::now();
        let _side = Side::Buy;
    }

    #[test]
    fn test_version() {
        let version = Version::Fix44;
        assert_eq!(version.begin_string(), "FIX.4.4");
    }
}
