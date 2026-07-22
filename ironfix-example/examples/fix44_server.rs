//! FIX 4.4 Server Example

use std::collections::HashMap;
use std::sync::Arc;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use ironfix_core::MsgType;
use ironfix_core::error::EncodeError;
use ironfix_tagvalue::{Decoder, Encoder};

mod common;
use common::{ExampleConfig, format_timestamp, init_logging, try_decode_message};

const FIX_VERSION: &str = "FIX.4.4";

struct Session {
    seq: u64,
    logged_in: bool,
}
impl Session {
    fn new() -> Self {
        Self {
            seq: 1,
            logged_in: false,
        }
    }
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    init_logging();
    let cfg = ExampleConfig::server();
    info!("Starting {} server on {}", FIX_VERSION, cfg.addr());

    let listener: TcpListener = TcpListener::bind(&cfg.addr()).await?;
    let state = Arc::new(Mutex::new(HashMap::<String, Session>::new()));

    loop {
        let (socket, addr) = listener.accept().await?;
        info!("Connection from {}", addr);
        let state = Arc::clone(&state);
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(socket, state, cfg).await {
                error!("Error: {}", e);
            }
        });
    }
}

async fn handle(
    mut sock: TcpStream,
    state: Arc<Mutex<HashMap<String, Session>>>,
    cfg: ExampleConfig,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = BytesMut::with_capacity(4096);
    let key = format!("{}:{}", cfg.target_comp_id, cfg.sender_comp_id);
    state.lock().await.insert(key.clone(), Session::new());

    loop {
        if sock.read_buf(&mut buf).await? == 0 {
            break;
        }

        while let Some(len) = try_decode_message(&buf) {
            let msg = buf.split_to(len);
            let mut decoder = Decoder::new(&msg);

            if let Ok(raw) = decoder.decode() {
                info!("Received: {:?}", raw.msg_type());

                let seq = {
                    let mut sessions = state.lock().await;
                    let s = sessions.get_mut(&key).expect("session present");
                    let seq = s.seq;
                    s.seq += 1;
                    seq
                };

                let resp = match raw.msg_type() {
                    MsgType::Logon => {
                        if let Some(s) = state.lock().await.get_mut(&key) {
                            s.logged_in = true;
                        }
                        info!("Client logged in");
                        Some(build_logon(&cfg, seq)?)
                    }
                    MsgType::TestRequest => {
                        let id = raw.get_field_str(112);
                        Some(build_heartbeat(&cfg, seq, id)?)
                    }
                    MsgType::Logout => {
                        sock.write_all(&build_logout(&cfg, seq)?).await?;
                        return Ok(());
                    }
                    MsgType::NewOrderSingle => {
                        let clid = raw.get_field_str(11).unwrap_or("0");
                        let sym = raw.get_field_str(55).unwrap_or("N/A");
                        let side = raw.get_field_str(54).unwrap_or("1");
                        let qty = raw.get_field_str(38).unwrap_or("0");
                        Some(build_exec(&cfg, seq, clid, sym, side, qty)?)
                    }
                    _ => {
                        warn!("Unhandled: {:?}", raw.msg_type());
                        // Sequence number not consumed: give it back.
                        if let Some(s) = state.lock().await.get_mut(&key) {
                            s.seq -= 1;
                        }
                        None
                    }
                };

                if let Some(r) = resp {
                    sock.write_all(&r).await?;
                }
            }
        }
    }
    Ok(())
}

fn build_logon(c: &ExampleConfig, seq: u64) -> Result<Vec<u8>, EncodeError> {
    let mut e = Encoder::new(FIX_VERSION);
    e.put_str(35, "A");
    e.put_str(49, &c.sender_comp_id);
    e.put_str(56, &c.target_comp_id);
    e.put_str(34, &seq.to_string());
    e.put_str(52, &format_timestamp());
    e.put_str(98, "0");
    e.put_str(108, &c.heartbeat_interval.to_string());
    Ok(e.finish()?.to_vec())
}

fn build_heartbeat(
    c: &ExampleConfig,
    seq: u64,
    test_req_id: Option<&str>,
) -> Result<Vec<u8>, EncodeError> {
    let mut e = Encoder::new(FIX_VERSION);
    e.put_str(35, "0");
    e.put_str(49, &c.sender_comp_id);
    e.put_str(56, &c.target_comp_id);
    e.put_str(34, &seq.to_string());
    e.put_str(52, &format_timestamp());
    if let Some(id) = test_req_id {
        e.put_str(112, id);
    }
    Ok(e.finish()?.to_vec())
}

fn build_logout(c: &ExampleConfig, seq: u64) -> Result<Vec<u8>, EncodeError> {
    let mut e = Encoder::new(FIX_VERSION);
    e.put_str(35, "5");
    e.put_str(49, &c.sender_comp_id);
    e.put_str(56, &c.target_comp_id);
    e.put_str(34, &seq.to_string());
    e.put_str(52, &format_timestamp());
    Ok(e.finish()?.to_vec())
}

fn build_exec(
    c: &ExampleConfig,
    seq: u64,
    clid: &str,
    sym: &str,
    side: &str,
    qty: &str,
) -> Result<Vec<u8>, EncodeError> {
    let mut e = Encoder::new(FIX_VERSION);
    e.put_str(35, "8");
    e.put_str(49, &c.sender_comp_id);
    e.put_str(56, &c.target_comp_id);
    e.put_str(34, &seq.to_string());
    e.put_str(52, &format_timestamp());
    e.put_str(37, &format!("ORD{}", clid));
    e.put_str(11, clid);
    e.put_str(17, &format!("EX{}", clid));
    e.put_str(150, "0");
    e.put_str(39, "0");
    e.put_str(55, sym);
    e.put_str(54, side);
    e.put_str(151, qty);
    e.put_str(14, "0");
    e.put_str(6, "0");
    Ok(e.finish()?.to_vec())
}
