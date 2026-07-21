//! FIX 4.4 Server Example with Channel-based Message Processing
//!
//! This example demonstrates a production-ready architecture where:
//! - Network I/O is handled in separate tasks
//! - Messages are sent through channels for processing
//! - Business logic is decoupled from network handling
//! - Responses are sent back through a response channel

use std::collections::HashMap;
use std::sync::Arc;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tracing::{error, info, warn};

use ironfix_core::MsgType;
use ironfix_core::error::EncodeError;
use ironfix_tagvalue::{Decoder, Encoder};

mod common;
use common::{ExampleConfig, format_timestamp, init_logging, try_decode_message};

const FIX_VERSION: &str = "FIX.4.4";
const CHANNEL_BUFFER_SIZE: usize = 1000;

/// Incoming FIX message with session context
#[derive(Debug, Clone)]
pub struct IncomingMessage {
    /// Session identifier (sender:target)
    pub session_id: String,
    /// Message type
    pub msg_type: MsgType,
    /// Raw message fields (tag -> value)
    pub fields: HashMap<u32, String>,
    /// Response channel for this message
    pub response_tx: mpsc::Sender<OutgoingMessage>,
}

/// Outgoing FIX message
#[derive(Debug, Clone)]
pub struct OutgoingMessage {
    /// Session identifier
    pub session_id: String,
    /// Encoded message bytes
    pub data: Vec<u8>,
    /// Whether to close connection after sending
    pub close_after: bool,
}

/// Session state
#[allow(dead_code)]
struct Session {
    seq: u64,
    logged_in: bool,
    response_tx: mpsc::Sender<OutgoingMessage>,
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    init_logging();
    let cfg = ExampleConfig::server();
    info!(
        "Starting {} server with channels on {}",
        FIX_VERSION,
        cfg.addr()
    );

    // Create the main message processing channel
    let (msg_tx, msg_rx) = mpsc::channel::<IncomingMessage>(CHANNEL_BUFFER_SIZE);

    // Spawn the message processor
    let processor_cfg = cfg.clone();
    tokio::spawn(async move {
        message_processor(msg_rx, processor_cfg).await;
    });

    // Start accepting connections
    let listener: TcpListener = TcpListener::bind(&cfg.addr()).await?;
    let sessions = Arc::new(Mutex::new(HashMap::<String, Session>::new()));

    loop {
        let (socket, addr) = listener.accept().await?;
        info!("Connection from {}", addr);

        let msg_tx = msg_tx.clone();
        let sessions = Arc::clone(&sessions);
        let cfg = cfg.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, msg_tx, sessions, cfg).await {
                error!("Connection error: {}", e);
            }
        });
    }
}

/// Handles a single client connection
async fn handle_connection(
    socket: TcpStream,
    msg_tx: mpsc::Sender<IncomingMessage>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    cfg: ExampleConfig,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let session_id = format!("{}:{}", cfg.target_comp_id, cfg.sender_comp_id);

    // Create response channel for this connection
    let (response_tx, mut response_rx) = mpsc::channel::<OutgoingMessage>(100);

    // Register session
    sessions.lock().await.insert(
        session_id.clone(),
        Session {
            seq: 1,
            logged_in: false,
            response_tx: response_tx.clone(),
        },
    );

    // Use into_split for 'static lifetime
    let (mut read_half, mut write_half) = socket.into_split();

    // Spawn writer task
    let writer_session_id = session_id.clone();
    let writer_handle = tokio::spawn(async move {
        while let Some(msg) = response_rx.recv().await {
            if let Err(e) = write_half.write_all(&msg.data).await {
                error!("Write error for {}: {}", writer_session_id, e);
                break;
            }
            if msg.close_after {
                info!("Closing connection for {}", writer_session_id);
                break;
            }
        }
    });

    // Read loop
    let mut buf = BytesMut::with_capacity(4096);
    loop {
        match read_half.read_buf(&mut buf).await {
            Ok(0) => {
                info!("Client disconnected: {}", session_id);
                break;
            }
            Ok(_) => {
                while let Some(len) = try_decode_message(&buf) {
                    let msg_bytes = buf.split_to(len);
                    let mut decoder = Decoder::new(&msg_bytes);

                    if let Ok(raw) = decoder.decode() {
                        // Extract fields into a HashMap
                        let mut fields = HashMap::new();
                        for tag in [11, 35, 38, 49, 54, 55, 56, 112] {
                            if let Some(val) = raw.get_field_str(tag) {
                                fields.insert(tag, val.to_string());
                            }
                        }

                        let incoming = IncomingMessage {
                            session_id: session_id.clone(),
                            msg_type: raw.msg_type().clone(),
                            fields,
                            response_tx: response_tx.clone(),
                        };

                        // Send to processor through channel
                        if let Err(e) = msg_tx.send(incoming).await {
                            error!("Failed to send message to processor: {}", e);
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                error!("Read error: {}", e);
                break;
            }
        }
    }

    // Cleanup
    sessions.lock().await.remove(&session_id);
    drop(response_tx);
    let _ = writer_handle.await;

    Ok(())
}

/// Message processor - handles business logic
/// Unwraps an encoded frame, dropping the response if the encoder refused it.
///
/// A rejected value has no legal wire form, so there is nothing to send; the
/// processor logs it and carries on rather than taking the session down.
fn encoded(session_id: &str, frame: Result<Vec<u8>, EncodeError>) -> Option<Vec<u8>> {
    match frame {
        Ok(frame) => Some(frame),
        Err(err) => {
            error!("cannot encode response for session {session_id}: {err}");
            None
        }
    }
}

async fn message_processor(mut rx: mpsc::Receiver<IncomingMessage>, cfg: ExampleConfig) {
    info!("Message processor started");

    // This could be replaced with your own order management system,
    // market data handler, or any other business logic
    let mut order_counter: u64 = 0;

    while let Some(msg) = rx.recv().await {
        info!(
            "Processing: session={} type={:?}",
            msg.session_id, msg.msg_type
        );

        let response = match msg.msg_type {
            MsgType::Logon => {
                info!("Session {} logged in", msg.session_id);
                encoded(&msg.session_id, build_logon(&cfg)).map(|data| OutgoingMessage {
                    session_id: msg.session_id.clone(),
                    data,
                    close_after: false,
                })
            }
            MsgType::TestRequest => {
                let test_req_id = msg.fields.get(&112).map(|s| s.as_str());
                encoded(&msg.session_id, build_heartbeat(&cfg, test_req_id)).map(|data| {
                    OutgoingMessage {
                        session_id: msg.session_id.clone(),
                        data,
                        close_after: false,
                    }
                })
            }
            MsgType::Heartbeat => {
                // Just acknowledge, no response needed
                None
            }
            MsgType::Logout => {
                encoded(&msg.session_id, build_logout(&cfg)).map(|data| OutgoingMessage {
                    session_id: msg.session_id.clone(),
                    data,
                    close_after: true,
                })
            }
            MsgType::NewOrderSingle => {
                order_counter += 1;
                let clid = msg.fields.get(&11).map(|s| s.as_str()).unwrap_or("0");
                let sym = msg.fields.get(&55).map(|s| s.as_str()).unwrap_or("N/A");
                let side = msg.fields.get(&54).map(|s| s.as_str()).unwrap_or("1");
                let qty = msg.fields.get(&38).map(|s| s.as_str()).unwrap_or("0");

                info!(
                    "New order: clOrdId={} symbol={} side={} qty={} (order #{})",
                    clid, sym, side, qty, order_counter
                );

                encoded(
                    &msg.session_id,
                    build_exec(&cfg, clid, sym, side, qty, order_counter),
                )
                .map(|data| OutgoingMessage {
                    session_id: msg.session_id.clone(),
                    data,
                    close_after: false,
                })
            }
            _ => {
                warn!("Unhandled message type: {:?}", msg.msg_type);
                None
            }
        };

        // Send response back through the session's response channel
        if let Some(resp) = response
            && let Err(e) = msg.response_tx.send(resp).await
        {
            warn!("Failed to send response: {}", e);
        }
    }

    info!("Message processor stopped");
}

fn build_logon(c: &ExampleConfig) -> Result<Vec<u8>, EncodeError> {
    let mut e = Encoder::new(FIX_VERSION);
    e.put_str(35, "A");
    e.put_str(49, &c.sender_comp_id);
    e.put_str(56, &c.target_comp_id);
    e.put_str(34, "1");
    e.put_str(52, &format_timestamp());
    e.put_str(98, "0");
    e.put_str(108, &c.heartbeat_interval.to_string());
    Ok(e.finish()?.to_vec())
}

fn build_heartbeat(c: &ExampleConfig, test_req_id: Option<&str>) -> Result<Vec<u8>, EncodeError> {
    let mut e = Encoder::new(FIX_VERSION);
    e.put_str(35, "0");
    e.put_str(49, &c.sender_comp_id);
    e.put_str(56, &c.target_comp_id);
    e.put_str(34, "1");
    e.put_str(52, &format_timestamp());
    if let Some(id) = test_req_id {
        e.put_str(112, id);
    }
    Ok(e.finish()?.to_vec())
}

fn build_logout(c: &ExampleConfig) -> Result<Vec<u8>, EncodeError> {
    let mut e = Encoder::new(FIX_VERSION);
    e.put_str(35, "5");
    e.put_str(49, &c.sender_comp_id);
    e.put_str(56, &c.target_comp_id);
    e.put_str(34, "1");
    e.put_str(52, &format_timestamp());
    Ok(e.finish()?.to_vec())
}

fn build_exec(
    c: &ExampleConfig,
    clid: &str,
    sym: &str,
    side: &str,
    qty: &str,
    order_id: u64,
) -> Result<Vec<u8>, EncodeError> {
    let mut e = Encoder::new(FIX_VERSION);
    e.put_str(35, "8");
    e.put_str(49, &c.sender_comp_id);
    e.put_str(56, &c.target_comp_id);
    e.put_str(34, "1");
    e.put_str(52, &format_timestamp());
    e.put_str(37, &format!("ORD{}", order_id));
    e.put_str(11, clid);
    e.put_str(17, &format!("EX{}", order_id));
    e.put_str(150, "0"); // ExecType = New
    e.put_str(39, "0"); // OrdStatus = New
    e.put_str(55, sym);
    e.put_str(54, side);
    e.put_str(151, qty); // LeavesQty
    e.put_str(14, "0"); // CumQty
    e.put_str(6, "0"); // AvgPx
    Ok(e.finish()?.to_vec())
}
