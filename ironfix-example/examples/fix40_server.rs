/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/
//! FIX 4.0 server example.
//!
//! Accepts connections from `fix40_client` and answers Logon with Logon,
//! `TestRequest` with `Heartbeat`, `NewOrderSingle` with an `ExecutionReport`
//! acknowledging the order as `New`, and Logout with Logout. Each connection
//! gets its own sequence counters, so `MsgSeqNum` (34) starts at 1 and advances
//! per message sent — a hard-coded 34 is a protocol violation any compliant
//! counterparty, including IronFix's own `Initiator`, flags as a gap.
//!
//! ## What FIX 4.0 changes on the wire
//!
//! * `BeginString` (8) is `FIX.4.0`.
//! * The `ExecutionReport` carries `ExecTransType` (20) and, because
//!   `ExecType` (150) and `LeavesQty` (151) do not exist until 4.1, reports the
//!   order with `OrderQty` (38), `LastShares` (32) and `LastPx` (31) instead.
//!
//! The accept loop lives in [`common::run_demo_server`] and the message layouts
//! in [`ironfix_example::demo`]. Note that `ironfix-engine` has no acceptor yet:
//! this is a demonstration server, not a session engine — it keeps no message
//! store and cannot answer a `ResendRequest`.
//!
//! ```text
//! FIX_HOST=0.0.0.0 FIX_PORT=9870 cargo run --example fix40_server
//! ```

mod common;
use common::{ExampleConfig, init_logging, run_demo_server};
use ironfix_core::FixVersion;

/// FIX version this example speaks.
const VERSION: FixVersion = FixVersion::Fix40;

/// Port bound when `FIX_PORT` is unset.
const DEFAULT_PORT: u16 = 9870;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();
    run_demo_server(VERSION, &ExampleConfig::server(DEFAULT_PORT)).await
}
