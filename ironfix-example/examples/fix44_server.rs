/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 22/7/26
******************************************************************************/
//! FIX 4.4 Server Example using the `ironfix-engine` Acceptor.
//!
//! Counterpart to `fix44_client`: run this server first, then the client.
//! Unlike the other `fixNN_server` examples (which hand-roll their accept loops
//! with a raw `Decoder`/`Encoder` and implement no real session behavior), this
//! example lets the engine own each connection: `FixCodec` framing, the
//! acceptor-side Logon handshake, heartbeats/TestRequests, sequence validation,
//! and the Logout handshake are all the `Acceptor`'s job.
//!
//! The application logic is small: on a `NewOrderSingle` it replies with an
//! `ExecutionReport`. The engine stamps every standard header (including
//! `MsgSeqNum`) and the trailer, so the reply only carries body fields.
//!
//! ```text
//! FIX_HOST=0.0.0.0 FIX_PORT=9876 cargo run --example fix44_server
//! ```

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::{error, info};

use ironfix_core::MsgType;
use ironfix_core::message::RawMessage;
use ironfix_core::types::CompId;
use ironfix_engine::application::{Application, RejectReason, SessionId};
use ironfix_engine::{Acceptor, Connection, OutboundMessage};
use ironfix_session::SessionConfig;
use tokio::net::TcpListener;
use tokio::sync::watch;

mod common;
use common::{ExampleConfig, init_logging};

/// FIX version this example speaks, as its `BeginString` (8).
const FIX_VERSION: &str = "FIX.4.4";

/// Port bound when `FIX_PORT` is unset.
const DEFAULT_PORT: u16 = 9876;

/// Per-connection application: logs session events and answers each
/// `NewOrderSingle` with an `ExecutionReport`.
///
/// The [`Connection`] is the outbound handle, and it only exists once
/// [`Acceptor::serve`] returns — but `serve` spawns the session reactor before
/// it returns, so a pipelined order can reach [`Application::from_app`] before
/// the handle is installed. The handle is therefore published on a
/// [`watch`] channel: `from_app` subscribes and waits for it, so an order that
/// races ahead of `set_connection` still finds its `Connection` rather than
/// dropping the reply.
#[derive(Debug)]
struct ServerApp {
    /// Outbound handle to this session, published once the session establishes.
    connection: watch::Sender<Option<Connection>>,
}

impl ServerApp {
    /// Creates the application with an as-yet-unset connection handle.
    fn new() -> Self {
        let (connection, _rx) = watch::channel(None);
        Self { connection }
    }

    /// Publishes the outbound handle for the established session.
    fn set_connection(&self, connection: Connection) {
        let _ = self.connection.send(Some(connection));
    }

    /// A receiver a spawned task can await the connection handle on.
    fn subscribe(&self) -> watch::Receiver<Option<Connection>> {
        self.connection.subscribe()
    }
}

#[async_trait]
impl Application for ServerApp {
    async fn on_create(&self, session_id: &SessionId) {
        info!("session created: {session_id}");
    }

    async fn on_logon(&self, session_id: &SessionId) {
        info!("logged on: {session_id}");
    }

    async fn on_logout(&self, session_id: &SessionId) {
        info!("logged out: {session_id}");
    }

    async fn to_admin(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_admin(
        &self,
        _message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        Ok(())
    }

    async fn to_app(&self, _message: &mut OutboundMessage, _session_id: &SessionId) {}

    async fn from_app(
        &self,
        message: &RawMessage<'_>,
        _session_id: &SessionId,
    ) -> Result<(), RejectReason> {
        if message.msg_type() != &MsgType::NewOrderSingle {
            info!("app message received: 35={}", message.msg_type());
            return Ok(());
        }

        let clid = message.get_field_str(11).unwrap_or("0");
        let symbol = message.get_field_str(55).unwrap_or("N/A");
        let side = message.get_field_str(54).unwrap_or("1");
        let qty = message.get_field_str(38).unwrap_or("0");
        info!("order {clid} {symbol} side={side} qty={qty}: acking with an ExecutionReport");

        // The reply is built here (copying every value out of the borrowed
        // message) but sent from a spawned task, not inline: `from_app` runs on
        // the reactor's application dispatcher, and awaiting `Connection::send`
        // on the bounded command queue the reactor itself drains could deadlock
        // if that queue were full. The spawned task also waits for the connection
        // handle, covering the case where this order arrived before
        // `set_connection`.
        let mut exec = OutboundMessage::new(MsgType::ExecutionReport);
        exec.push_str(37, &format!("ORD{clid}"))
            .push_str(11, clid)
            .push_str(17, &format!("EX{clid}"))
            .push_char(150, '0')
            .push_char(39, '0')
            .push_str(55, symbol)
            .push_str(54, side)
            .push_str(151, qty)
            .push_str(14, "0")
            .push_str(6, "0");

        let mut connection_rx = self.subscribe();
        tokio::spawn(async move {
            // Wait for the session's outbound handle to be published.
            let connection = loop {
                if let Some(connection) = connection_rx.borrow_and_update().clone() {
                    break connection;
                }
                if connection_rx.changed().await.is_err() {
                    error!("session ended before its connection handle was installed");
                    return;
                }
            };
            if let Err(err) = connection.send(exec).await {
                error!("failed to send ExecutionReport: {err}");
            }
        });
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();
    let cfg = ExampleConfig::server(DEFAULT_PORT);
    info!("{FIX_VERSION} engine server listening on {}", cfg.addr());

    let listener = TcpListener::bind(&cfg.addr()).await?;

    loop {
        let (stream, peer) = listener.accept().await?;
        info!("connection from {peer}");
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(err) = serve(stream, cfg).await {
                error!("session error: {err}");
            }
        });
    }
}

/// Establishes one acceptor session and runs it until it closes.
async fn serve(
    stream: tokio::net::TcpStream,
    cfg: ExampleConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Config from the acceptor's point of view: sender is this server, target
    // is the client it expects.
    let config = SessionConfig::new(
        CompId::new(&cfg.sender_comp_id)?,
        CompId::new(&cfg.target_comp_id)?,
        FIX_VERSION,
    )
    .with_heartbeat_interval(Duration::from_secs(cfg.heartbeat_interval));

    let app = Arc::new(ServerApp::new());
    let acceptor = Acceptor::new(config, Arc::clone(&app));

    let connection = acceptor.serve(stream).await?;
    app.set_connection(connection.clone());

    // The reactor owns the socket in the background; block until it closes.
    connection.wait_closed().await;
    Ok(())
}
