/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/
//! FIX 4.4 client with no async runtime: one session driven by a plain,
//! single-threaded poll loop over a non-blocking `std::net` socket (issue
//! #93, ADR-0002).
//!
//! Counterpart to `fix44_server`, which runs on the Tokio `Acceptor`: run
//! that first, then this. The client logs on, sends a `NewOrderSingle`,
//! waits for the server's `ExecutionReport`, and logs out. Every protocol
//! decision (sequence numbers, gaps, resends, heartbeats, the Logout
//! exchange) comes from the sans-IO core in `ironfix_session::sans_io`; the
//! loop below only reads the clock, polls the session, and sleeps when
//! nothing moved. See `poll_driver/mod.rs`.
//!
//! ```text
//! cargo run --example fix44_server
//! cargo run --example fix44_poll_client
//! ```

use std::net::ToSocketAddrs;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use ironfix_core::message::{MsgType, RawMessage};
use ironfix_core::types::CompId;
use ironfix_engine::application::{RejectReason, SessionId};
use ironfix_engine::{OutboundMessage, SyncApplication};
use ironfix_session::SessionConfig;
use ironfix_store::MemoryStore;
use tracing::info;

mod common;
mod poll_driver;
use common::{ExampleConfig, init_logging};
use poll_driver::PollSession;

/// Port dialled when `FIX_PORT` is unset; matches `fix44_server`.
const DEFAULT_PORT: u16 = 9876;

/// How long the demo waits for each step.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// Records execution reports; everything else is the session's job.
#[derive(Debug, Default)]
struct ClientApp {
    reports: Mutex<Vec<String>>,
}

impl SyncApplication for ClientApp {
    fn on_create(&self, session_id: &SessionId) {
        info!("session created: {session_id}");
    }

    fn on_logon(&self, session_id: &SessionId) {
        info!("logged on: {session_id}");
    }

    fn on_logout(&self, session_id: &SessionId) {
        info!("logged out: {session_id}");
    }

    fn to_admin(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    fn from_admin(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }

    fn to_app(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    fn from_app(
        &self,
        message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        if *message.msg_type() == MsgType::ExecutionReport {
            let order = message.get_field_str(11).unwrap_or_default().to_string();
            info!("execution report for {order}");
            if let Ok(mut reports) = self.reports.lock() {
                reports.push(order);
            }
        }
        Ok(())
    }
}

/// Polls `session` until `done` holds or `STEP_TIMEOUT` passes, sleeping a
/// millisecond whenever a pass moved nothing.
fn poll_until(
    session: &mut PollSession<ClientApp, MemoryStore>,
    what: &str,
    done: impl Fn(&PollSession<ClientApp, MemoryStore>) -> bool,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + STEP_TIMEOUT;
    while !done(session) {
        if let Some(ended) = session.ended() {
            bail!("the session ended while waiting for {what}: {ended:?}");
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for {what}");
        }
        if !session.poll(Instant::now()) {
            thread::sleep(Duration::from_millis(1));
        }
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    init_logging();
    let cfg = ExampleConfig::client(DEFAULT_PORT);
    let addr = (cfg.host.as_str(), cfg.port)
        .to_socket_addrs()?
        .next()
        .context("the server address resolves to nothing")?;
    let config = SessionConfig::new(
        CompId::new(&cfg.sender_comp_id)?,
        CompId::new(&cfg.target_comp_id)?,
        "FIX.4.4",
    )
    .with_heartbeat_interval(Duration::from_secs(cfg.heartbeat_interval));

    let mut session = PollSession::connect(
        addr,
        config,
        ClientApp::default(),
        MemoryStore::new(),
        Instant::now(),
    )?;
    poll_until(&mut session, "the Logon", PollSession::is_active)?;

    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order
        .push_str(11, "POLL-1")
        .push_str(55, "AAPL")
        .push_char(54, '1')
        .push_str(60, &ironfix_core::types::Timestamp::now().format_millis())
        .push_str(38, "100")
        .push_char(40, '1');
    let seq = session
        .send_app(order, Instant::now())
        .map_err(anyhow::Error::msg)?;
    info!("order POLL-1 sent under MsgSeqNum {seq}");
    poll_until(&mut session, "the ExecutionReport", |session| {
        session
            .app()
            .reports
            .lock()
            .is_ok_and(|reports| !reports.is_empty())
    })?;

    session.logout(Instant::now());
    poll_until(&mut session, "the Logout", |session| {
        session.ended().is_some()
    })?;
    info!("session ended: {:?}", session.ended());
    Ok(())
}
