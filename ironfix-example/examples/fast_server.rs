//! FAST protocol server example.
//!
//! This example demonstrates a simple FAST market data server that sends
//! encoded market data messages to connected clients.

mod common;

use common::{ExampleConfig, format_timestamp, init_logging};
use ironfix_fast::{FastEncoder, FastError};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, interval};
use tracing::{error, info, warn};

const DEFAULT_PORT: u16 = 9890;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();

    let cfg = ExampleConfig::server();
    let port = std::env::var("FAST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    let addr = format!("{}:{}", cfg.host, port);
    let listener: TcpListener = TcpListener::bind(&addr).await?;
    info!("FAST server listening on {}", addr);

    loop {
        let (socket, peer) = listener.accept().await?;
        info!("Client connected: {}", peer);

        tokio::spawn(async move {
            if let Err(e) = handle_client(socket).await {
                error!("Client error: {}", e);
            }
            info!("Client disconnected: {}", peer);
        });
    }
}

async fn handle_client(mut socket: TcpStream) -> anyhow::Result<()> {
    let mut seq_num: u64 = 1;
    let mut ticker_interval = interval(Duration::from_millis(100));

    // Simulated market data
    let symbols = ["AAPL", "GOOGL", "MSFT", "AMZN", "META"];
    let mut prices: Vec<f64> = vec![150.0, 140.0, 380.0, 175.0, 500.0];

    loop {
        tokio::select! {
            _ = ticker_interval.tick() => {
                // Generate market data update for a random symbol
                let idx = (seq_num as usize) % symbols.len();
                let symbol = symbols[idx];

                // Simulate price movement
                let delta = ((seq_num % 10) as f64 - 5.0) * 0.01;
                prices[idx] += delta;
                let price = prices[idx];
                let size: u64 = 100 + (seq_num % 900);

                // Build FAST message
                let msg = match build_market_data(seq_num, symbol, price, size) {
                    Ok(msg) => msg,
                    Err(e) => {
                        error!("Failed to encode market data: {}", e);
                        break;
                    }
                };

                if let Err(e) = socket.write_all(&msg).await {
                    warn!("Write error: {}", e);
                    break;
                }

                info!("Sent: seq={} symbol={} price={:.2} size={}", seq_num, symbol, price, size);
                seq_num += 1;
            }
            result = socket.readable() => {
                if result.is_err() {
                    break;
                }
                // Check if client disconnected
                let mut buf = [0u8; 1];
                match socket.try_read(&mut buf) {
                    Ok(0) => {
                        info!("Client closed connection");
                        break;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // No data available, continue
                    }
                    Err(e) => {
                        warn!("Read error: {}", e);
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

/// Build a FAST-encoded market data message.
///
/// Message structure:
/// - Presence map (1 byte with stop bit)
/// - Template ID (uint32)
/// - Sequence number (uint64)
/// - Timestamp (string)
/// - Symbol (string)
/// - Price (scaled decimal as uint64, scale 2)
/// - Size (uint64)
///
/// # Errors
/// Returns `FastError::InvalidString` if the timestamp or symbol is not
/// representable as a FAST ASCII string.
fn build_market_data(
    seq_num: u64,
    symbol: &str,
    price: f64,
    size: u64,
) -> Result<Vec<u8>, FastError> {
    let mut encoder = FastEncoder::new();

    // Presence map: all fields present (6 bits set + stop bit)
    // Bits: template_id, seq_num, timestamp, symbol, price, size
    let pmap_byte: u8 = 0b1111_1100 | 0x80; // 6 bits set + stop bit
    encoder.encode_uint(pmap_byte as u64);

    // Template ID = 1 (Market Data)
    encoder.encode_uint(1);

    // Sequence number
    encoder.encode_uint(seq_num);

    // Timestamp
    encoder.encode_ascii(&format_timestamp())?;

    // Symbol
    encoder.encode_ascii(symbol)?;

    // Price as scaled integer (price * 100)
    let scaled_price = (price * 100.0) as u64;
    encoder.encode_uint(scaled_price);

    // Size
    encoder.encode_uint(size);

    Ok(encoder.finish())
}
