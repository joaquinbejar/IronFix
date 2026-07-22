/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/
//! FIX 4.0 client example.
//!
//! Dials the matching `fix40_server`, then runs one full session: Logon,
//! a limit `NewOrderSingle`, the `ExecutionReport` that acknowledges it, a
//! `TestRequest` / `Heartbeat` round trip, and Logout. Every outbound message
//! carries the next `MsgSeqNum` (34) from a real `SequenceManager`, and every
//! inbound one is checked against the expected sequence number.
//!
//! ## What FIX 4.0 changes on the wire
//!
//! * `BeginString` (8) is `FIX.4.0`.
//! * The `ExecutionReport` carries `ExecTransType` (20) and, because
//!   `ExecType` (150) and `LeavesQty` (151) do not exist until 4.1, reports the
//!   order with `OrderQty` (38), `LastShares` (32) and `LastPx` (31) instead.
//!
//! The session itself lives in [`common::run_demo_client`] and the message
//! layouts in [`ironfix_example::demo`], because nine near-identical copies of
//! both had already drifted into protocol bugs. Framing is
//! `ironfix_transport::FixCodec` — the same codec the engine uses.
//!
//! ```text
//! FIX_HOST=127.0.0.1 FIX_PORT=9870 cargo run --example fix40_client
//! ```

mod common;
use common::{ExampleConfig, init_logging, run_demo_client};
use ironfix_core::FixVersion;

/// FIX version this example speaks.
const VERSION: FixVersion = FixVersion::Fix40;

/// Port dialled when `FIX_PORT` is unset.
const DEFAULT_PORT: u16 = 9870;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();
    run_demo_client(VERSION, &ExampleConfig::client(DEFAULT_PORT)).await
}
