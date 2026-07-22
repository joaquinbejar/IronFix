/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/
//! FIX 5.0 SP2 server example.
//!
//! Accepts connections from `fix50sp2_client` and answers Logon with Logon,
//! `TestRequest` with `Heartbeat`, `NewOrderSingle` with an `ExecutionReport`
//! acknowledging the order as `New`, and Logout with Logout. Each connection
//! gets its own sequence counters, so `MsgSeqNum` (34) starts at 1 and advances
//! per message sent — a hard-coded 34 is a protocol violation any compliant
//! counterparty, including IronFix's own `Initiator`, flags as a gap.
//!
//! ## What the 5.0 family changes on the wire
//!
//! * `BeginString` (8) is `FIXT.1.1`, not `FIX 5.0 SP2`: 5.0 splits the session
//!   version from the application version. Putting `FIX 5.0 SP2` in tag 8 is
//!   rejected by a conforming counterparty.
//! * The application version travels in `DefaultApplVerID` (1137) on the Logon
//!   and `ApplVerID` (1128) on application messages; for FIX 5.0 SP2 it is `9`.
//!
//! **This pair demonstrates FIXT.1.1 transport only.** Its application messages
//! are the 4.4 ones re-stamped with 1128; IronFix has no coverage that is
//! specific to 5.0, SP1 or SP2, and this example is not evidence of any.
//!
//! The accept loop lives in [`common::run_demo_server`] and the message layouts
//! in [`ironfix_example::demo`]. Note that `ironfix-engine` has no acceptor yet:
//! this is a demonstration server, not a session engine — it keeps no message
//! store and cannot answer a `ResendRequest`.
//!
//! ```text
//! FIX_HOST=0.0.0.0 FIX_PORT=9882 cargo run --example fix50sp2_server
//! ```

mod common;
use common::{ExampleConfig, init_logging, run_demo_server};
use ironfix_core::FixVersion;

/// FIX version this example speaks.
const VERSION: FixVersion = FixVersion::Fix50Sp2;

/// Port bound when `FIX_PORT` is unset.
const DEFAULT_PORT: u16 = 9882;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();
    run_demo_server(VERSION, &ExampleConfig::server(DEFAULT_PORT)).await
}
