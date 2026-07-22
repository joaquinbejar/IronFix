/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/
//! FIX 4.2 client example.
//!
//! Dials the matching `fix42_server`, then runs one full session: Logon,
//! a limit `NewOrderSingle`, the `ExecutionReport` that acknowledges it, a
//! `TestRequest` / `Heartbeat` round trip, and Logout. Every outbound message
//! carries the next `MsgSeqNum` (34) from a real `SequenceManager`, and every
//! inbound one is checked against the expected sequence number.
//!
//! ## What this version changes on the wire
//!
//! * `BeginString` (8) is `FIX.4.2`.
//! * The `ExecutionReport` carries both `ExecTransType` (20), still required
//!   through 4.2, and `ExecType` (150) / `LeavesQty` (151), introduced in 4.1.
//!
//! The session itself lives in [`common::run_demo_client`] and the message
//! layouts in [`ironfix_example::demo`], because nine near-identical copies of
//! both had already drifted into protocol bugs. Framing is
//! `ironfix_transport::FixCodec` — the same codec the engine uses.
//!
//! ```text
//! FIX_HOST=127.0.0.1 FIX_PORT=9872 cargo run --example fix42_client
//! ```

mod common;
use common::{ExampleConfig, init_logging, run_demo_client};
use ironfix_core::FixVersion;

/// FIX version this example speaks.
const VERSION: FixVersion = FixVersion::Fix42;

/// Port dialled when `FIX_PORT` is unset.
const DEFAULT_PORT: u16 = 9872;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();
    run_demo_client(VERSION, &ExampleConfig::client(DEFAULT_PORT)).await
}
