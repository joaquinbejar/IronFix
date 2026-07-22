/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/

//! Socket plumbing shared by the runnable examples.
//!
//! Two things live here and nowhere else:
//!
//! * [`ExampleConfig`] — where a demo binds or dials, read from the
//!   environment.
//! * [`run_demo_client`] / [`run_demo_server`] — one complete FIX session,
//!   parameterised by [`FixVersion`]. The nine `fixNN_client` / `fixNN_server`
//!   pairs are each a version constant, a default port and a call to one of
//!   these; everything protocol-shaped is in
//!   [`ironfix_example::demo`](../../src/demo.rs), which `cargo test` covers.
//!
//! # Framing
//!
//! Messages are framed by [`FixCodec`] from `ironfix-transport` — the same
//! codec the engine's `Initiator` uses — wrapped in a `tokio_util` [`Framed`].
//! These examples deliberately do **not** hand-roll a `BodyLength` scan: the
//! previous helper here repeated the unchecked-arithmetic and unbounded-buffer
//! bug class that `FixCodec` already fixes, and a second implementation is a
//! second thing to get wrong. `FixCodec` caps the frame at 1 MiB by default,
//! validates the checksum, and resynchronises after garbage.
//!
//! # What a demo session does
//!
//! Logon → NewOrderSingle → ExecutionReport → TestRequest → Heartbeat →
//! Logout. Every inbound message has its `MsgSeqNum` (34) checked against the
//! session's own expectation, and every outbound message carries the next
//! number from a real [`SequenceManager`](ironfix_session::SequenceManager).
//!
//! # What a demo session does not do
//!
//! It does not persist messages, answer a `ResendRequest`, or recover from a
//! sequence gap — a gap is logged and the session continues, where a real
//! acceptor would issue a `ResendRequest`. For a session with those behaviours,
//! use `ironfix_engine::Initiator`; `fix44_engine_client.rs` drives this same
//! server with it.

#![allow(dead_code)]

use std::env;
use std::time::Duration;

use anyhow::{Context, bail};
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ironfix_core::{FixVersion, MsgType, RawMessage};
use ironfix_example::demo::{DemoOrder, DemoSession, IncomingOrder};
use ironfix_session::sequence::SequenceResult;
use ironfix_tagvalue::Decoder;
use ironfix_transport::FixCodec;
use rust_decimal::Decimal;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;
use tracing::{error, info, warn};

/// Default server host when the environment names none.
pub const DEFAULT_HOST: &str = "127.0.0.1";

/// Default server port when neither the environment nor the example names one.
pub const DEFAULT_PORT: u16 = 9876;

/// How long a demo waits for a reply before giving up.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

/// A framed FIX connection: `FixCodec` over a TCP stream.
pub type FixConnection = Framed<TcpStream, FixCodec>;

/// Where an example binds or dials, and as whom.
#[derive(Debug, Clone)]
pub struct ExampleConfig {
    /// Server hostname.
    pub host: String,
    /// Server port.
    pub port: u16,
    /// `SenderCompID` (49) of this side.
    pub sender_comp_id: String,
    /// `TargetCompID` (56) of the counterparty.
    pub target_comp_id: String,
    /// `HeartBtInt` (108), in seconds.
    pub heartbeat_interval: u64,
}

/// Returns the first of `names` set in the environment, or `fallback`.
fn env_first(names: &[&str], fallback: &str) -> String {
    names
        .iter()
        .find_map(|name| env::var(name).ok())
        .unwrap_or_else(|| fallback.to_string())
}

/// Returns the first of `names` that parses as a port, or `fallback`.
fn env_port(names: &[&str], fallback: u16) -> u16 {
    names
        .iter()
        .find_map(|name| env::var(name).ok()?.parse().ok())
        .unwrap_or(fallback)
}

impl ExampleConfig {
    /// Configuration for a client dialling `default_port`.
    ///
    /// `FIX_HOST`, `FIX_PORT`, `FIX_SENDER` and `FIX_TARGET` override the
    /// defaults.
    ///
    /// # Arguments
    /// * `default_port` - Port to dial when `FIX_PORT` is unset
    #[must_use]
    pub fn client(default_port: u16) -> Self {
        Self {
            host: env_first(&["FIX_HOST"], DEFAULT_HOST),
            port: env_port(&["FIX_PORT"], default_port),
            sender_comp_id: env_first(&["FIX_SENDER"], "CLIENT"),
            target_comp_id: env_first(&["FIX_TARGET"], "SERVER"),
            heartbeat_interval: 30,
        }
    }

    /// Configuration for a server binding `default_port`.
    ///
    /// # Arguments
    /// * `default_port` - Port to bind when `FIX_PORT` is unset
    #[must_use]
    pub fn server(default_port: u16) -> Self {
        Self {
            host: env_first(&["FIX_HOST"], DEFAULT_HOST),
            port: env_port(&["FIX_PORT"], default_port),
            sender_comp_id: env_first(&["FIX_SENDER"], "SERVER"),
            target_comp_id: env_first(&["FIX_TARGET"], "CLIENT"),
            heartbeat_interval: 30,
        }
    }

    /// Configuration for a FAST client.
    ///
    /// `FAST_HOST` / `FAST_PORT` take precedence over `FIX_HOST` / `FIX_PORT`,
    /// so a container image may use either spelling.
    ///
    /// # Arguments
    /// * `default_port` - Port to dial when neither variable is set
    #[must_use]
    pub fn fast_client(default_port: u16) -> Self {
        Self {
            host: env_first(&["FAST_HOST", "FIX_HOST"], DEFAULT_HOST),
            port: env_port(&["FAST_PORT", "FIX_PORT"], default_port),
            ..Self::client(default_port)
        }
    }

    /// Configuration for a FAST server.
    ///
    /// # Arguments
    /// * `default_port` - Port to bind when neither variable is set
    #[must_use]
    pub fn fast_server(default_port: u16) -> Self {
        Self {
            host: env_first(&["FAST_HOST", "FIX_HOST"], DEFAULT_HOST),
            port: env_port(&["FAST_PORT", "FIX_PORT"], default_port),
            ..Self::server(default_port)
        }
    }

    /// Returns the socket address to bind or dial.
    #[must_use]
    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Installs the tracing subscriber. Examples log; libraries do not.
pub fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .try_init();
}

/// Writes one frame to the connection.
async fn send(connection: &mut FixConnection, frame: &[u8]) -> anyhow::Result<()> {
    connection
        .send(frame)
        .await
        .context("writing a frame to the peer")
}

/// Reads one frame, failing if none arrives within [`REPLY_TIMEOUT`].
async fn recv(connection: &mut FixConnection) -> anyhow::Result<BytesMut> {
    match tokio::time::timeout(REPLY_TIMEOUT, connection.next()).await {
        Ok(Some(frame)) => frame.context("framing an inbound message"),
        Ok(None) => bail!("the peer closed the connection"),
        Err(_) => bail!("no reply within {REPLY_TIMEOUT:?}"),
    }
}

/// The disposition of an inbound message once its `MsgSeqNum` (34) has been
/// checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Inbound {
    /// The sequence number is in order (or a tolerated gap): dispatch the
    /// message to business handling.
    Process,
    /// The message is a possible duplicate — `PossDupFlag` (43) is `Y` and the
    /// sequence number is below what the session expects — so it has already
    /// been processed once. The caller must drop it: re-dispatching a
    /// retransmitted `NewOrderSingle` would execute the order a second time.
    Duplicate,
}

/// Checks an inbound `MsgSeqNum` (34) against what the session expects and
/// advances the inbound counter.
///
/// Returns [`Inbound::Duplicate`] for a possible duplicate — `PossDupFlag` (43)
/// is `Y` and the number is too low — so the caller can drop it instead of
/// processing the same message twice; otherwise [`Inbound::Process`]. A
/// duplicate does not advance the counter, since the counter is already past
/// that number.
///
/// A gap is reported and tolerated: these demos have no message store, so they
/// cannot answer a `ResendRequest` and must not pretend otherwise.
fn accept_inbound(session: &DemoSession, raw: &RawMessage<'_>) -> anyhow::Result<Inbound> {
    let received: u64 = raw
        .get_field_str(34)
        .context("inbound message has no MsgSeqNum (34)")?
        .parse()
        .context("MsgSeqNum (34) is not a number")?;

    match session.sequences().validate_incoming(received) {
        SequenceResult::Ok => {}
        SequenceResult::Gap { expected, received } => {
            warn!(
                expected,
                received, "sequence gap: a real acceptor answers this with a ResendRequest"
            );
            session.sequences().set_target_seq(received);
        }
        SequenceResult::TooLow { expected, received } => {
            let poss_dup = raw.get_field_str(43) == Some("Y");
            if poss_dup {
                info!(
                    expected,
                    received, "possible duplicate (43=Y): dropping without reprocessing"
                );
                return Ok(Inbound::Duplicate);
            }
            bail!("MsgSeqNum too low: expected {expected}, received {received}");
        }
    }

    session
        .sequences()
        .try_increment_target_seq()
        .context("inbound sequence counter exhausted")?;
    Ok(Inbound::Process)
}

/// Reads one frame, decodes it, and checks its sequence number.
///
/// Returns the raw frame; the caller decodes it again to borrow from a buffer
/// it owns.
async fn recv_checked(
    connection: &mut FixConnection,
    session: &DemoSession,
) -> anyhow::Result<BytesMut> {
    let frame = recv(connection).await?;
    {
        let mut decoder = Decoder::new(&frame);
        let raw = decoder.decode().context("decoding an inbound message")?;
        accept_inbound(session, &raw)?;
    }
    Ok(frame)
}

/// Reads the next frame and requires it to be `expected`.
async fn expect_msg_type(
    connection: &mut FixConnection,
    session: &DemoSession,
    expected: &MsgType,
) -> anyhow::Result<BytesMut> {
    let frame = recv_checked(connection, session).await?;
    {
        let mut decoder = Decoder::new(&frame);
        let raw = decoder.decode().context("decoding an inbound message")?;
        if raw.msg_type() != expected {
            bail!(
                "expected 35={}, received 35={}",
                expected.as_str(),
                raw.msg_type().as_str()
            );
        }
    }
    Ok(frame)
}

/// Runs one complete demo client session against a demo server.
///
/// Logon, one limit order, a TestRequest round trip, then Logout.
///
/// # Arguments
/// * `version` - FIX version to speak
/// * `cfg` - Where to dial and as whom
///
/// # Errors
/// Any connection, framing, decoding, sequence or protocol failure. A reply of
/// the wrong `MsgType`, or none within ten seconds, ends the session.
pub async fn run_demo_client(version: FixVersion, cfg: &ExampleConfig) -> anyhow::Result<()> {
    info!(%version, addr = %cfg.addr(), "connecting");
    let stream = TcpStream::connect(cfg.addr())
        .await
        .with_context(|| format!("connecting to {}", cfg.addr()))?;
    let mut connection = Framed::new(stream, FixCodec::new());

    let mut session = DemoSession::new(
        version,
        &cfg.sender_comp_id,
        &cfg.target_comp_id,
        cfg.heartbeat_interval,
    );

    send(&mut connection, session.logon()?).await?;
    expect_msg_type(&mut connection, &session, &MsgType::Logon).await?;
    info!("logon accepted");

    let order = DemoOrder {
        cl_ord_id: "ORD001",
        symbol: "IBM",
        side: ironfix_core::Side::Buy,
        quantity: 100,
        price: Decimal::new(12550, 2),
    };
    send(&mut connection, session.new_order_single(&order)?).await?;
    let report = expect_msg_type(&mut connection, &session, &MsgType::ExecutionReport).await?;
    {
        let mut decoder = Decoder::new(&report);
        let raw = decoder.decode().context("decoding the ExecutionReport")?;
        info!(
            order_id = raw.get_field_str(37),
            ord_status = raw.get_field_str(39),
            "execution report"
        );
    }

    // A TestRequest exercises the heartbeat path immediately, instead of
    // idling for HeartBtInt seconds.
    let test_req_id = format!("TEST-{}", session.next_sender_seq());
    send(&mut connection, session.test_request(&test_req_id)?).await?;
    let heartbeat = expect_msg_type(&mut connection, &session, &MsgType::Heartbeat).await?;
    {
        let mut decoder = Decoder::new(&heartbeat);
        let raw = decoder.decode().context("decoding the Heartbeat")?;
        if raw.get_field_str(112) != Some(test_req_id.as_str()) {
            bail!("Heartbeat did not echo TestReqID {test_req_id}");
        }
    }
    info!("test request answered");

    send(&mut connection, session.logout(Some("done"))?).await?;
    expect_msg_type(&mut connection, &session, &MsgType::Logout).await?;
    info!("logged out");
    Ok(())
}

/// Runs a demo server until the process is stopped.
///
/// Each accepted connection gets its own [`DemoSession`], so its sequence
/// counters start at 1 and advance per message.
///
/// # Arguments
/// * `version` - FIX version to speak
/// * `cfg` - Where to bind and as whom
///
/// # Errors
/// A failure to bind the listener, or to accept a connection.
pub async fn run_demo_server(version: FixVersion, cfg: &ExampleConfig) -> anyhow::Result<()> {
    let listener = TcpListener::bind(cfg.addr())
        .await
        .with_context(|| format!("binding {}", cfg.addr()))?;
    info!(%version, addr = %cfg.addr(), "listening");

    loop {
        let (stream, peer) = listener.accept().await.context("accepting a connection")?;
        info!(%peer, "connection accepted");
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_connection(version, &cfg, stream).await {
                error!(%peer, %error, "session ended");
            } else {
                info!(%peer, "session closed");
            }
        });
    }
}

/// Answers a `NewOrderSingle` with an `ExecutionReport`, or with a session-level
/// `Reject` when the order cannot be acknowledged as written.
///
/// The `OrderID` and `ExecID` the acceptor assigns are built here; they are not
/// part of [`IncomingOrder`], which holds only what the client sent.
async fn answer_new_order(
    connection: &mut FixConnection,
    session: &mut DemoSession,
    message: &RawMessage<'_>,
    order_number: u64,
    ref_seq_num: u64,
) -> anyhow::Result<()> {
    let order_id = format!("ORD{order_number}");
    let exec_id = format!("EX{order_number}");

    let response = match IncomingOrder::from_new_order(message) {
        Some(order) => {
            info!(
                cl_ord_id = order.cl_ord_id,
                symbol = order.symbol,
                "order accepted"
            );
            session.execution_report(&order, &order_id, &exec_id)?
        }
        None => {
            warn!("NewOrderSingle is missing or malforms a required field");
            session.reject(
                ref_seq_num,
                None,
                "unusable ClOrdID, Symbol, Side or OrderQty",
            )?
        }
    };
    send(connection, response).await
}

/// Serves one accepted connection to completion.
async fn serve_connection(
    version: FixVersion,
    cfg: &ExampleConfig,
    stream: TcpStream,
) -> anyhow::Result<()> {
    let mut connection = Framed::new(stream, FixCodec::new());
    let mut session = DemoSession::new(
        version,
        &cfg.sender_comp_id,
        &cfg.target_comp_id,
        cfg.heartbeat_interval,
    );
    let mut orders: u64 = 0;

    while let Some(frame) = connection.next().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(error) => {
                // A framing error is the peer's, not ours: report it and drop
                // the connection rather than trying to resynchronise blind.
                warn!(%error, "malformed frame, closing");
                return Ok(());
            }
        };

        let mut decoder = Decoder::new(&frame);
        let raw = match decoder.decode() {
            Ok(raw) => raw,
            Err(error) => {
                warn!(%error, "undecodable message, ignoring");
                continue;
            }
        };

        match accept_inbound(&session, &raw) {
            Ok(Inbound::Process) => {}
            Ok(Inbound::Duplicate) => {
                // Already processed once. Dispatching a retransmitted
                // NewOrderSingle again would execute the order a second time.
                continue;
            }
            Err(error) => {
                warn!(%error, "rejecting inbound message");
                continue;
            }
        }

        let inbound_seq = raw.get_field_str(34).and_then(|s| s.parse().ok());
        info!(msg_type = %raw.msg_type().as_str(), "received");

        match raw.msg_type() {
            MsgType::Logon => {
                let response = session.logon()?;
                send(&mut connection, response).await?;
            }
            MsgType::TestRequest => {
                let test_req_id = raw.get_field_str(112);
                let response = session.heartbeat(test_req_id)?;
                send(&mut connection, response).await?;
            }
            MsgType::Heartbeat => {}
            MsgType::NewOrderSingle => {
                orders = orders.checked_add(1).context("order counter exhausted")?;
                answer_new_order(
                    &mut connection,
                    &mut session,
                    &raw,
                    orders,
                    inbound_seq.unwrap_or(0),
                )
                .await?;
            }
            MsgType::Logout => {
                let response = session.logout(None)?;
                send(&mut connection, response).await?;
                return Ok(());
            }
            other => {
                warn!(msg_type = %other.as_str(), "message type not handled by this demo");
            }
        }
    }

    Ok(())
}
