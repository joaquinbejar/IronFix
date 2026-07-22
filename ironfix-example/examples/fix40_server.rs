//! FIX 4.0 Server Example

use bytes::BytesMut;
use ironfix_core::MsgType;
use ironfix_core::error::EncodeError;
use ironfix_tagvalue::{Decoder, Encoder};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

mod common;
use common::{ExampleConfig, format_timestamp, init_logging, try_decode_message};

const FIX_VERSION: &str = "FIX.4.0";
const DEFAULT_PORT: u16 = 9870;

struct Session {
    seq: u64,
    _logged_in: bool,
}
impl Session {
    fn new() -> Self {
        Self {
            seq: 1,
            _logged_in: false,
        }
    }
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    init_logging();
    let mut cfg = ExampleConfig::server();
    cfg.port = std::env::var("FIX_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);
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
                let resp = match raw.msg_type() {
                    MsgType::Logon => {
                        info!("Logon");
                        Some(build_logon(&cfg)?)
                    }
                    MsgType::TestRequest => Some(build_hb(&cfg, raw.get_field_str(112))?),
                    MsgType::Logout => {
                        sock.write_all(&build_logout(&cfg)?).await?;
                        return Ok(());
                    }
                    MsgType::NewOrderSingle => {
                        let clid = raw.get_field_str(11).unwrap_or("0");
                        Some(build_exec(
                            &cfg,
                            clid,
                            raw.get_field_str(55).unwrap_or("N/A"),
                            raw.get_field_str(54).unwrap_or("1"),
                            raw.get_field_str(38).unwrap_or("0"),
                        )?)
                    }
                    _ => {
                        warn!("Unhandled: {:?}", raw.msg_type());
                        None
                    }
                };
                if let Some(r) = resp {
                    sock.write_all(&r).await?;
                    if let Some(s) = state.lock().await.get_mut(&key) {
                        s.seq += 1;
                    }
                }
            }
        }
    }
    Ok(())
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

fn build_hb(c: &ExampleConfig, id: Option<&str>) -> Result<Vec<u8>, EncodeError> {
    let mut e = Encoder::new(FIX_VERSION);
    e.put_str(35, "0");
    e.put_str(49, &c.sender_comp_id);
    e.put_str(56, &c.target_comp_id);
    e.put_str(34, "1");
    e.put_str(52, &format_timestamp());
    if let Some(i) = id {
        e.put_str(112, i);
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
) -> Result<Vec<u8>, EncodeError> {
    let mut e = Encoder::new(FIX_VERSION);
    e.put_str(35, "8");
    e.put_str(49, &c.sender_comp_id);
    e.put_str(56, &c.target_comp_id);
    e.put_str(34, "1");
    e.put_str(52, &format_timestamp());
    e.put_str(37, &format!("ORD{}", clid));
    e.put_str(11, clid);
    e.put_str(17, &format!("EX{}", clid));
    e.put_str(20, "0");
    e.put_str(150, "0");
    e.put_str(39, "0");
    e.put_str(55, sym);
    e.put_str(54, side);
    e.put_str(151, qty);
    e.put_str(14, "0");
    e.put_str(6, "0");
    Ok(e.finish()?.to_vec())
}
