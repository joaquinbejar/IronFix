//! FAST protocol server example with SPSC Lock-Free Channel
//!
//! This example demonstrates a high-performance FAST market data server using
//! a Single-Producer Single-Consumer (SPSC) lock-free channel for ultra-low
//! latency message passing between the network thread and the market data
//! generator thread.
//!
//! Architecture:
//! ```text
//! ┌─────────────────┐     SPSC Channel      ┌─────────────────┐
//! │  Market Data    │ ──────────────────▶   │   Network I/O   │
//! │   Generator     │   (lock-free)         │     Thread      │
//! │   (Producer)    │                       │   (Consumer)    │
//! └─────────────────┘                       └─────────────────┘
//!         │                                         │
//!         │ Generates ticks                         │ Sends to clients
//!         ▼                                         ▼
//!   [MarketDataTick]                          [TCP Sockets]
//! ```

mod common;

use common::{ExampleConfig, format_timestamp, init_logging};
use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use ironfix_fast::{FastEncoder, FastError};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

const DEFAULT_PORT: u16 = 9891;
const CHANNEL_CAPACITY: usize = 10_000;

/// Market data tick - the data structure passed through the SPSC channel
#[derive(Debug, Clone)]
pub struct MarketDataTick {
    pub seq_num: u64,
    pub symbol: &'static str,
    pub bid_price: u64,
    pub ask_price: u64,
    pub bid_size: u64,
    pub ask_size: u64,
    pub timestamp_ns: u64,
}

/// Statistics for monitoring
#[derive(Debug, Default)]
pub struct Stats {
    pub ticks_generated: AtomicU64,
    pub ticks_sent: AtomicU64,
    pub ticks_dropped: AtomicU64,
    pub clients_connected: AtomicU64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();

    let cfg = ExampleConfig::server();
    let port = std::env::var("FAST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    let addr = format!("{}:{}", cfg.host, port);
    info!("FAST SPSC server starting on {}", addr);

    // Create SPSC channel
    let (tx, rx): (Sender<MarketDataTick>, Receiver<MarketDataTick>) = bounded(CHANNEL_CAPACITY);

    // Shared state
    let running = Arc::new(AtomicBool::new(true));
    let stats = Arc::new(Stats::default());
    let clients: Arc<RwLock<HashMap<u64, tokio::sync::mpsc::Sender<Vec<u8>>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // Spawn market data generator thread (producer)
    let producer_running = Arc::clone(&running);
    let producer_stats = Arc::clone(&stats);
    let _producer_handle = thread::spawn(move || {
        market_data_generator(tx, producer_running, producer_stats);
    });

    // Spawn consumer task that broadcasts to clients
    let consumer_rx = rx;
    let consumer_clients = Arc::clone(&clients);
    let consumer_stats = Arc::clone(&stats);
    let consumer_running = Arc::clone(&running);
    tokio::spawn(async move {
        market_data_broadcaster(
            consumer_rx,
            consumer_clients,
            consumer_stats,
            consumer_running,
        )
        .await;
    });

    // Spawn stats reporter
    let stats_reporter = Arc::clone(&stats);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let generated = stats_reporter.ticks_generated.load(Ordering::Relaxed);
            let sent = stats_reporter.ticks_sent.load(Ordering::Relaxed);
            let dropped = stats_reporter.ticks_dropped.load(Ordering::Relaxed);
            let clients = stats_reporter.clients_connected.load(Ordering::Relaxed);
            info!(
                "Stats: generated={} sent={} dropped={} clients={}",
                generated, sent, dropped, clients
            );
        }
    });

    // Accept connections
    let listener: TcpListener = TcpListener::bind(&addr).await?;
    let mut client_id: u64 = 0;

    info!("FAST SPSC server listening on {}", addr);

    loop {
        let (socket, peer) = listener.accept().await?;
        client_id += 1;
        info!("Client {} connected from {}", client_id, peer);

        let clients = Arc::clone(&clients);
        let stats = Arc::clone(&stats);
        let id = client_id;

        tokio::spawn(async move {
            handle_client(socket, id, clients, stats).await;
        });
    }
}

/// Market data generator - runs in a dedicated thread (producer)
fn market_data_generator(tx: Sender<MarketDataTick>, running: Arc<AtomicBool>, stats: Arc<Stats>) {
    info!("Market data generator started");

    let symbols: [&'static str; 5] = ["AAPL", "GOOGL", "MSFT", "AMZN", "META"];
    let mut prices: [u64; 5] = [15000, 14000, 38000, 17500, 50000]; // Prices in cents
    let mut seq_num: u64 = 0;

    while running.load(Ordering::Relaxed) {
        for (i, &symbol) in symbols.iter().enumerate() {
            seq_num += 1;

            // Simulate price movement (random walk)
            let delta = ((seq_num % 11) as i64 - 5) * 10; // -50 to +50 cents
            prices[i] = (prices[i] as i64 + delta).max(100) as u64;

            let tick = MarketDataTick {
                seq_num,
                symbol,
                bid_price: prices[i] - 5, // 5 cent spread
                ask_price: prices[i] + 5,
                bid_size: 100 + (seq_num % 900),
                ask_size: 100 + ((seq_num + 50) % 900),
                timestamp_ns: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64,
            };

            // Try to send without blocking (lock-free)
            match tx.try_send(tick) {
                Ok(()) => {
                    stats.ticks_generated.fetch_add(1, Ordering::Relaxed);
                }
                Err(TrySendError::Full(_)) => {
                    stats.ticks_dropped.fetch_add(1, Ordering::Relaxed);
                }
                Err(TrySendError::Disconnected(_)) => {
                    info!("Channel disconnected, stopping generator");
                    return;
                }
            }
        }

        // Generate ~50,000 ticks/second (5 symbols * 10,000 iterations)
        thread::sleep(Duration::from_micros(100));
    }

    info!("Market data generator stopped");
}

/// Market data broadcaster - consumes from SPSC channel and broadcasts to clients
async fn market_data_broadcaster(
    rx: Receiver<MarketDataTick>,
    clients: Arc<RwLock<HashMap<u64, tokio::sync::mpsc::Sender<Vec<u8>>>>>,
    stats: Arc<Stats>,
    running: Arc<AtomicBool>,
) {
    info!("Market data broadcaster started");

    while running.load(Ordering::Relaxed) {
        // Non-blocking receive with timeout
        match rx.recv_timeout(Duration::from_millis(10)) {
            Ok(tick) => {
                let encoded = match encode_market_data(&tick) {
                    Ok(encoded) => encoded,
                    Err(e) => {
                        warn!("Failed to encode tick {}: {}", tick.seq_num, e);
                        continue;
                    }
                };

                // Broadcast to all clients
                let clients_read = clients.read().await;
                for (client_id, tx) in clients_read.iter() {
                    if tx.try_send(encoded.clone()).is_err() {
                        warn!("Client {} buffer full, dropping tick", client_id);
                    } else {
                        stats.ticks_sent.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                // No data available, continue
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                info!("Channel disconnected, stopping broadcaster");
                break;
            }
        }
    }

    info!("Market data broadcaster stopped");
}

/// Handle a single client connection
async fn handle_client(
    mut socket: TcpStream,
    client_id: u64,
    clients: Arc<RwLock<HashMap<u64, tokio::sync::mpsc::Sender<Vec<u8>>>>>,
    stats: Arc<Stats>,
) {
    // Create per-client channel for outgoing messages
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1000);

    // Register client
    {
        let mut clients_write = clients.write().await;
        clients_write.insert(client_id, tx);
        stats.clients_connected.fetch_add(1, Ordering::Relaxed);
    }

    info!("Client {} registered", client_id);

    // Write loop - send market data to client
    loop {
        match rx.recv().await {
            Some(data) => {
                if let Err(e) = socket.write_all(&data).await {
                    error!("Client {} write error: {}", client_id, e);
                    break;
                }
            }
            None => {
                info!("Client {} channel closed", client_id);
                break;
            }
        }
    }

    // Cleanup
    {
        let mut clients_write = clients.write().await;
        clients_write.remove(&client_id);
        stats.clients_connected.fetch_sub(1, Ordering::Relaxed);
    }

    info!("Client {} disconnected", client_id);
}

/// Encode a market data tick to FAST format
///
/// # Errors
/// Returns `FastError::InvalidString` if the timestamp or symbol is not
/// representable as a FAST ASCII string.
fn encode_market_data(tick: &MarketDataTick) -> Result<Vec<u8>, FastError> {
    let mut encoder = FastEncoder::new();

    // Presence map: all fields present
    let pmap_byte: u8 = 0b1111_1110 | 0x80; // 7 bits + stop bit
    encoder.encode_uint(pmap_byte as u64);

    // Template ID = 2 (Quote)
    encoder.encode_uint(2);

    // Sequence number
    encoder.encode_uint(tick.seq_num);

    // Timestamp (as string for simplicity)
    encoder.encode_ascii(&format_timestamp())?;

    // Symbol
    encoder.encode_ascii(tick.symbol)?;

    // Bid price (in cents)
    encoder.encode_uint(tick.bid_price);

    // Ask price (in cents)
    encoder.encode_uint(tick.ask_price);

    // Bid size
    encoder.encode_uint(tick.bid_size);

    // Ask size
    encoder.encode_uint(tick.ask_size);

    Ok(encoder.finish())
}
