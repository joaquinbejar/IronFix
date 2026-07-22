/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/
//! FIX 4.3 server example.
//!
//! Accepts connections from `fix43_client` and answers Logon with Logon,
//! `TestRequest` with `Heartbeat`, `NewOrderSingle` with an `ExecutionReport`
//! acknowledging the order as `New`, and Logout with Logout. Each connection
//! gets its own sequence counters, so `MsgSeqNum` (34) starts at 1 and advances
//! per message sent — a hard-coded 34 is a protocol violation any compliant
//! counterparty, including IronFix's own `Initiator`, flags as a gap.
//!
//! ## What this version changes on the wire
//!
//! * `BeginString` (8) is `FIX.4.3`.
//! * `ExecType` (150) has replaced `ExecTransType` (20) in the
//!   `ExecutionReport`, which reports the open quantity as `LeavesQty` (151).
//!
//! The accept loop lives in [`common::run_demo_server`] and the message layouts
//! in [`ironfix_example::demo`]. Note that `ironfix-engine` has no acceptor yet:
//! this is a demonstration server, not a session engine — it keeps no message
//! store and cannot answer a `ResendRequest`.
//!
//! ```text
//! FIX_HOST=0.0.0.0 FIX_PORT=9873 cargo run --example fix43_server
//! ```

mod common;
use common::{ExampleConfig, init_logging, run_demo_server};
use ironfix_core::FixVersion;

/// FIX version this example speaks.
const VERSION: FixVersion = FixVersion::Fix43;

/// Port bound when `FIX_PORT` is unset.
const DEFAULT_PORT: u16 = 9873;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();
    run_demo_server(VERSION, &ExampleConfig::server(DEFAULT_PORT)).await
}
