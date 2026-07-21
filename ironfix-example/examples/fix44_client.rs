//! FIX 4.4 Client Example

use bytes::BytesMut;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{interval, timeout};
use tracing::{error, info};

use ironfix_core::error::EncodeError;
use ironfix_core::{MsgType, Side};
use ironfix_tagvalue::{Decoder, Encoder};

mod common;
use common::{ExampleConfig, format_timestamp, init_logging, try_decode_message};

const FIX_VERSION: &str = "FIX.4.4";

struct Sess {
    seq: u64,
}
impl Sess {
    fn new() -> Self {
        Self { seq: 1 }
    }
    fn next(&mut self) -> u64 {
        let s = self.seq;
        self.seq += 1;
        s
    }
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    init_logging();
    let cfg = ExampleConfig::client();
    info!("{} Client connecting to {}", FIX_VERSION, cfg.addr());

    let mut sock: TcpStream = TcpStream::connect(&cfg.addr()).await?;
    let mut sess = Sess::new();
    let mut buf = BytesMut::with_capacity(4096);

    // Logon
    sock.write_all(&build_logon(&cfg, sess.next())?).await?;
    match timeout(Duration::from_secs(10), read_msg(&mut sock, &mut buf)).await {
        Ok(Ok(m))
            if Decoder::new(&m)
                .decode()
                .map(|r| *r.msg_type() == MsgType::Logon)
                .unwrap_or(false) =>
        {
            info!("Logon OK")
        }
        _ => {
            error!("Logon failed");
            return Ok(());
        }
    }

    // Send order
    sock.write_all(&build_order(
        &cfg,
        sess.next(),
        "ORD001",
        "AAPL",
        Side::Buy,
        100,
        150.50,
    )?)
    .await?;
    if let Ok(Ok(m)) = timeout(Duration::from_secs(5), read_msg(&mut sock, &mut buf)).await
        && let Ok(r) = Decoder::new(&m).decode()
    {
        info!("Got {:?}", r.msg_type());
    }

    // Heartbeats
    let mut hb = interval(Duration::from_secs(cfg.heartbeat_interval));
    for _ in 0..2 {
        hb.tick().await;
        sock.write_all(&build_hb(&cfg, sess.next())?).await?;
        info!("Sent HB");
    }

    // Logout
    sock.write_all(&build_logout(&cfg, sess.next())?).await?;
    info!("Done");
    Ok(())
}

async fn read_msg(
    s: &mut TcpStream,
    b: &mut BytesMut,
) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    loop {
        if let Some(len) = try_decode_message(b) {
            return Ok(b.split_to(len).to_vec());
        }
        if s.read_buf(b).await? == 0 {
            return Err("closed".into());
        }
    }
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

fn build_hb(c: &ExampleConfig, seq: u64) -> Result<Vec<u8>, EncodeError> {
    let mut e = Encoder::new(FIX_VERSION);
    e.put_str(35, "0");
    e.put_str(49, &c.sender_comp_id);
    e.put_str(56, &c.target_comp_id);
    e.put_str(34, &seq.to_string());
    e.put_str(52, &format_timestamp());
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

fn build_order(
    c: &ExampleConfig,
    seq: u64,
    id: &str,
    sym: &str,
    side: Side,
    qty: u64,
    px: f64,
) -> Result<Vec<u8>, EncodeError> {
    let mut e = Encoder::new(FIX_VERSION);
    e.put_str(35, "D");
    e.put_str(49, &c.sender_comp_id);
    e.put_str(56, &c.target_comp_id);
    e.put_str(34, &seq.to_string());
    e.put_str(52, &format_timestamp());
    e.put_str(11, id);
    e.put_str(21, "1");
    e.put_str(55, sym);
    e.put_char(54, side.as_char());
    e.put_str(60, &format_timestamp());
    e.put_str(38, &qty.to_string());
    e.put_str(40, "2");
    e.put_str(44, &format!("{:.2}", px));
    Ok(e.finish()?.to_vec())
}
