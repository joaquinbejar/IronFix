//! FIX 4.2 Server Example
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

const FIX_VERSION: &str = "FIX.4.2";
const DEFAULT_PORT: u16 = 9872;

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
    let state = Arc::new(Mutex::new(HashMap::<String, u64>::new()));
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
    state: Arc<Mutex<HashMap<String, u64>>>,
    cfg: ExampleConfig,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = BytesMut::with_capacity(4096);
    let key = format!("{}:{}", cfg.target_comp_id, cfg.sender_comp_id);
    state.lock().await.insert(key.clone(), 1);
    loop {
        if sock.read_buf(&mut buf).await? == 0 {
            break;
        }
        while let Some(len) = try_decode_message(&buf) {
            let msg = buf.split_to(len);
            let mut dec = Decoder::new(&msg);
            if let Ok(raw) = dec.decode() {
                let resp = match raw.msg_type() {
                    MsgType::Logon => {
                        info!("Logon");
                        Some(build_msg(&cfg, "A", None)?)
                    }
                    MsgType::TestRequest => Some(build_msg(&cfg, "0", raw.get_field_str(112))?),
                    MsgType::Logout => {
                        sock.write_all(&build_msg(&cfg, "5", None)?).await?;
                        return Ok(());
                    }
                    MsgType::NewOrderSingle => Some(build_exec(&cfg, &raw)?),
                    _ => {
                        warn!("Unhandled: {:?}", raw.msg_type());
                        None
                    }
                };
                if let Some(r) = resp {
                    sock.write_all(&r).await?;
                    *state.lock().await.get_mut(&key).unwrap() += 1;
                }
            }
        }
    }
    Ok(())
}

fn build_msg(c: &ExampleConfig, mt: &str, id: Option<&str>) -> Result<Vec<u8>, EncodeError> {
    let mut e = Encoder::new(FIX_VERSION);
    e.put_str(35, mt);
    e.put_str(49, &c.sender_comp_id);
    e.put_str(56, &c.target_comp_id);
    e.put_str(34, "1");
    e.put_str(52, &format_timestamp());
    if mt == "A" {
        e.put_str(98, "0");
        e.put_str(108, &c.heartbeat_interval.to_string());
    }
    if let Some(i) = id {
        e.put_str(112, i);
    }
    Ok(e.finish()?.to_vec())
}

fn build_exec(
    c: &ExampleConfig,
    raw: &ironfix_tagvalue::RawMessage<'_>,
) -> Result<Vec<u8>, EncodeError> {
    let clid = raw.get_field_str(11).unwrap_or("0");
    let mut e = Encoder::new(FIX_VERSION);
    e.put_str(35, "8");
    e.put_str(49, &c.sender_comp_id);
    e.put_str(56, &c.target_comp_id);
    e.put_str(34, "1");
    e.put_str(52, &format_timestamp());
    e.put_str(37, &format!("O{}", clid));
    e.put_str(11, clid);
    e.put_str(17, &format!("E{}", clid));
    e.put_str(20, "0");
    e.put_str(150, "0");
    e.put_str(39, "0");
    e.put_str(55, raw.get_field_str(55).unwrap_or("N/A"));
    e.put_str(54, raw.get_field_str(54).unwrap_or("1"));
    e.put_str(151, raw.get_field_str(38).unwrap_or("0"));
    e.put_str(14, "0");
    e.put_str(6, "0");
    Ok(e.finish()?.to_vec())
}
