/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/
//! FIX 5.0 client example.
//!
//! Dials the matching `fix50_server`, then runs one full session: Logon,
//! a limit `NewOrderSingle`, the `ExecutionReport` that acknowledges it, a
//! `TestRequest` / `Heartbeat` round trip, and Logout. Every outbound message
//! carries the next `MsgSeqNum` (34) from a real `SequenceManager`, and every
//! inbound one is checked against the expected sequence number.
//!
//! ## What the 5.0 family changes on the wire
//!
//! * `BeginString` (8) is `FIXT.1.1`, not `FIX 5.0`: 5.0 splits the session
//!   version from the application version. Putting `FIX 5.0` in tag 8 is
//!   rejected by a conforming counterparty.
//! * The application version travels in `DefaultApplVerID` (1137) on the Logon
//!   and `ApplVerID` (1128) on application messages; for FIX 5.0 it is `7`.
//!
//! **This pair demonstrates FIXT.1.1 transport only.** Its application messages
//! are the 4.4 ones re-stamped with 1128; IronFix has no coverage that is
//! specific to 5.0, SP1 or SP2, and this example is not evidence of any.
//!
//! The session itself lives in [`common::run_demo_client`] and the message
//! layouts in [`ironfix_example::demo`], because nine near-identical copies of
//! both had already drifted into protocol bugs. Framing is
//! `ironfix_transport::FixCodec` — the same codec the engine uses.
//!
//! ```text
//! FIX_HOST=127.0.0.1 FIX_PORT=9880 cargo run --example fix50_client
//! ```

mod common;
use common::{ExampleConfig, init_logging, run_demo_client};
use ironfix_core::FixVersion;

/// FIX version this example speaks.
const VERSION: FixVersion = FixVersion::Fix50;

/// Port dialled when `FIX_PORT` is unset.
const DEFAULT_PORT: u16 = 9880;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();
    run_demo_client(VERSION, &ExampleConfig::client(DEFAULT_PORT)).await
}
