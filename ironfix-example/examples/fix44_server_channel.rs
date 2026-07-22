/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/

//! FIX 4.4 server with channel-based message processing.
//!
//! The same protocol behaviour as `fix44_server`, arranged differently: network
//! I/O runs in per-connection tasks, decoded messages go to a single processor
//! task over an mpsc channel, and responses come back over a per-connection
//! reply channel. This is the shape to copy when business logic must not sit on
//! the read path.
//!
//! ```text
//! ┌──────────────┐  IncomingMessage  ┌──────────────┐
//! │ reader task  │ ────────────────▶ │  processor   │
//! │ (per client) │                   │  (one task)  │
//! └──────────────┘ ◀──────────────── └──────────────┘
//!        │           encoded frame
//!        ▼
//!   writer task ──▶ socket
//! ```
//!
//! # What is shared with the other examples
//!
//! Framing is `ironfix_transport::FixCodec` and the messages come from
//! [`ironfix_example::demo`], so this server stamps the same real, incrementing
//! `MsgSeqNum` (34) as the rest. The sequence counter lives with the connection
//! rather than with the processor, because it belongs to the session.
//!
//! ```text
//! FIX_HOST=0.0.0.0 FIX_PORT=9876 cargo run --example fix44_server_channel
//! ```

mod common;

use std::collections::HashMap;

use anyhow::Context;
use bytes::BytesMut;
use common::{ExampleConfig, init_logging};
use futures_util::{SinkExt, StreamExt};
use ironfix_core::{FixVersion, MsgType};
use ironfix_example::demo::{DemoSession, IncomingOrder};
use ironfix_session::sequence::SequenceResult;
use ironfix_tagvalue::Decoder;
use ironfix_transport::FixCodec;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::Framed;
use tracing::{error, info, warn};

/// FIX version this example speaks.
const VERSION: FixVersion = FixVersion::Fix44;

/// Port bound when `FIX_PORT` is unset.
const DEFAULT_PORT: u16 = 9876;

/// Depth of the shared processor queue, in messages.
const PROCESSOR_QUEUE: usize = 1_000;

/// Tags the processor is given a copy of.
///
/// Copying a bounded set keeps the borrowed frame on the reader task, so the
/// processor holds no reference into a network buffer.
const FORWARDED_TAGS: [u32; 6] = [11, 34, 38, 54, 55, 112];

/// A decoded message handed to the processor.
#[derive(Debug)]
struct IncomingMessage {
    /// Which session it arrived on.
    session_id: String,
    /// Its `MsgType` (35).
    msg_type: MsgType,
    /// The subset of fields in [`FORWARDED_TAGS`] that were present.
    fields: HashMap<u32, String>,
    /// Where the decision goes back.
    reply: oneshot::Sender<Decision>,
}

/// What the processor decided to do about a message.
#[derive(Debug)]
enum Decision {
    /// Reply with a `Logon`.
    Logon,
    /// Reply with a `Heartbeat`, echoing this `TestReqID`.
    Heartbeat(Option<String>),
    /// Acknowledge an order as `New`.
    AcceptOrder {
        /// `ClOrdID` (11) of the order.
        cl_ord_id: String,
        /// `Symbol` (55) of the order.
        symbol: String,
        /// `Side` (54) of the order, as received.
        side: String,
        /// `OrderQty` (38) of the order, as received.
        order_qty: String,
        /// Sequence number this acknowledgement counts.
        order_number: u64,
    },
    /// Reject the message at the session level.
    Reject {
        /// `RefSeqNum` (45).
        ref_seq_num: u64,
        /// `Text` (58).
        text: String,
    },
    /// Reply with a `Logout` and close.
    Logout,
    /// Say nothing.
    Ignore,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();
    let cfg = ExampleConfig::server(DEFAULT_PORT);

    let (processor_tx, processor_rx) = mpsc::channel::<IncomingMessage>(PROCESSOR_QUEUE);
    tokio::spawn(process(processor_rx));

    let listener = TcpListener::bind(cfg.addr())
        .await
        .with_context(|| format!("binding {}", cfg.addr()))?;
    info!(version = %VERSION, addr = %cfg.addr(), "listening");

    loop {
        let (stream, peer) = listener.accept().await.context("accepting a connection")?;
        info!(%peer, "connection accepted");
        let cfg = cfg.clone();
        let processor_tx = processor_tx.clone();
        tokio::spawn(async move {
            if let Err(error) = serve(stream, cfg, processor_tx).await {
                error!(%peer, %error, "session ended");
            }
        });
    }
}

/// Reads a connection, forwards each message to the processor, and writes back
/// whatever it decides.
async fn serve(
    stream: TcpStream,
    cfg: ExampleConfig,
    processor_tx: mpsc::Sender<IncomingMessage>,
) -> anyhow::Result<()> {
    let session_id = format!("{}->{}", cfg.target_comp_id, cfg.sender_comp_id);
    let mut connection = Framed::new(stream, FixCodec::new());
    let mut session = DemoSession::new(
        VERSION,
        &cfg.sender_comp_id,
        &cfg.target_comp_id,
        cfg.heartbeat_interval,
    );

    while let Some(frame) = connection.next().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(error) => {
                warn!(%error, "malformed frame, closing");
                return Ok(());
            }
        };

        let Some(incoming) = extract(&frame, &session_id, &session) else {
            continue;
        };
        let (message, reply_rx) = incoming;

        if processor_tx.send(message).await.is_err() {
            warn!("the processor has stopped");
            return Ok(());
        }

        let Ok(decision) = reply_rx.await else {
            warn!("the processor dropped a message without deciding");
            continue;
        };

        if apply(&mut connection, &mut session, decision).await? {
            return Ok(());
        }
    }

    Ok(())
}

/// Decodes a frame, checks its sequence number, and packages it for the
/// processor.
///
/// Returns `None` when the message is undecodable or out of sequence; the
/// connection carries on.
fn extract(
    frame: &BytesMut,
    session_id: &str,
    session: &DemoSession,
) -> Option<(IncomingMessage, oneshot::Receiver<Decision>)> {
    let mut decoder = Decoder::new(frame);
    let raw = match decoder.decode() {
        Ok(raw) => raw,
        Err(error) => {
            warn!(%error, "undecodable message, ignoring");
            return None;
        }
    };

    let received: u64 = raw.get_field_str(34)?.parse().ok()?;
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
            warn!(expected, received, "MsgSeqNum too low, ignoring");
            return None;
        }
    }
    session.sequences().try_increment_target_seq().ok()?;

    let mut fields = HashMap::new();
    for tag in FORWARDED_TAGS {
        if let Some(value) = raw.get_field_str(tag) {
            fields.insert(tag, value.to_string());
        }
    }

    let (reply, reply_rx) = oneshot::channel();
    info!(msg_type = %raw.msg_type().as_str(), "received");

    Some((
        IncomingMessage {
            session_id: session_id.to_string(),
            msg_type: raw.msg_type().clone(),
            fields,
            reply,
        },
        reply_rx,
    ))
}

/// Encodes and writes the processor's decision.
///
/// Returns `true` when the session should close.
async fn apply(
    connection: &mut Framed<TcpStream, FixCodec>,
    session: &mut DemoSession,
    decision: Decision,
) -> anyhow::Result<bool> {
    let (frame, close) = match &decision {
        Decision::Logon => (session.logon()?, false),
        Decision::Heartbeat(test_req_id) => (session.heartbeat(test_req_id.as_deref())?, false),
        Decision::AcceptOrder {
            cl_ord_id,
            symbol,
            side,
            order_qty,
            order_number,
        } => {
            let order_id = format!("ORD{order_number}");
            let exec_id = format!("EX{order_number}");
            let Some(order) = IncomingOrder::from_parts(cl_ord_id, symbol, side, order_qty) else {
                warn!("NewOrderSingle is missing or malforms a required field");
                let frame = session.reject(0, None, "unusable Side or OrderQty")?;
                connection.send(frame).await?;
                return Ok(false);
            };
            let frame = session.execution_report(&order, &order_id, &exec_id)?;
            connection.send(frame).await?;
            return Ok(false);
        }
        Decision::Reject { ref_seq_num, text } => {
            (session.reject(*ref_seq_num, None, text)?, false)
        }
        Decision::Logout => (session.logout(None)?, true),
        Decision::Ignore => return Ok(false),
    };

    connection.send(frame).await?;
    Ok(close)
}

/// The business logic: one task, no network, no session state.
async fn process(mut rx: mpsc::Receiver<IncomingMessage>) {
    info!("processor started");
    let mut orders: u64 = 0;

    while let Some(message) = rx.recv().await {
        let decision = match message.msg_type {
            MsgType::Logon => {
                info!(session = %message.session_id, "logged in");
                Decision::Logon
            }
            MsgType::TestRequest => Decision::Heartbeat(message.fields.get(&112).cloned()),
            MsgType::Heartbeat => Decision::Ignore,
            MsgType::Logout => Decision::Logout,
            MsgType::NewOrderSingle => match order_from(&message.fields) {
                Some((cl_ord_id, symbol, side, order_qty)) => {
                    orders = orders.checked_add(1).unwrap_or(1);
                    info!(cl_ord_id, symbol, order = orders, "new order");
                    Decision::AcceptOrder {
                        cl_ord_id: cl_ord_id.to_string(),
                        symbol: symbol.to_string(),
                        side: side.to_string(),
                        order_qty: order_qty.to_string(),
                        order_number: orders,
                    }
                }
                None => Decision::Reject {
                    ref_seq_num: message
                        .fields
                        .get(&34)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0),
                    text: "NewOrderSingle is missing a required field".to_string(),
                },
            },
            other => {
                warn!(msg_type = %other.as_str(), "message type not handled by this demo");
                Decision::Ignore
            }
        };

        // The reader task may have gone; that is not an error here.
        let _ = message.reply.send(decision);
    }

    info!("processor stopped");
}

/// Pulls the four order fields out of the forwarded set.
fn order_from(fields: &HashMap<u32, String>) -> Option<(&str, &str, &str, &str)> {
    Some((
        fields.get(&11)?.as_str(),
        fields.get(&55)?.as_str(),
        fields.get(&54)?.as_str(),
        fields.get(&38)?.as_str(),
    ))
}
