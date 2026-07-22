/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/

//! FAST market data server with a lock-free hand-off between threads.
//!
//! A dedicated generator thread produces ticks and a dedicated broadcaster
//! thread encodes and fans them out; the two are joined by a bounded lock-free
//! channel. Neither thread belongs to the Tokio runtime, so neither can park a
//! runtime worker.
//!
//! ```text
//! ┌─────────────────┐   crossbeam-channel   ┌─────────────────┐   tokio mpsc
//! │  Market data    │ ────────────────────▶ │  Broadcaster    │ ───────────▶ per-client
//! │  generator      │   bounded, lock-free  │  (encode + fan) │              writer tasks
//! │  (std::thread)  │                       │  (std::thread)  │
//! └─────────────────┘                       └─────────────────┘
//! ```
//!
//! # What "lock-free" does and does not mean here
//!
//! The channel is [`crossbeam_channel::bounded`], which is a lock-free **MPMC**
//! queue. This example wires it with exactly one producer and one consumer, but
//! it is not an SPSC-only primitive and this file does not claim otherwise —
//! the previous version of these docs promised an SPSC queue over an MPMC one.
//!
//! The registry of connected clients is a `parking_lot::RwLock<HashMap<…>>`.
//! It is read once per tick and written only when a client connects or leaves,
//! and it is never held across an `.await` — the guard is dropped before any
//! suspension point. See `CLAUDE.md`, "Governance precedence", override 2.
//!
//! # Fan-out cost
//!
//! An encoded tick is wrapped in [`Bytes`], so sending it to N clients is N
//! reference-count bumps rather than N heap copies of the frame.
//!
//! ```text
//! FIX_HOST=0.0.0.0 FAST_PORT=9891 cargo run --example fast_server_lockfree
//! ```

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use bytes::Bytes;
use common::{ExampleConfig, init_logging};
use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use ironfix_core::Timestamp;
use ironfix_example::fast_market_data::{MarketData, encode};
use parking_lot::RwLock;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// Port bound when neither `FAST_PORT` nor `FIX_PORT` is set.
const DEFAULT_PORT: u16 = 9891;

/// Capacity of the generator-to-broadcaster channel, in ticks.
const CHANNEL_CAPACITY: usize = 10_000;

/// Capacity of each client's outbound queue, in frames.
const CLIENT_QUEUE_CAPACITY: usize = 1_000;

/// Pause between generator batches.
const GENERATOR_PAUSE: Duration = Duration::from_micros(100);

/// Instruments this feed publishes.
const SYMBOLS: [&str; 5] = ["AAPL", "GOOGL", "MSFT", "AMZN", "META"];

/// Opening prices, in hundredths.
const OPENING_PRICES: [u64; 5] = [15_000, 14_000, 38_000, 17_500, 50_000];

/// Floor a simulated price never goes below, in hundredths.
const PRICE_FLOOR: u64 = 100;

/// Bid/ask half-spread, in hundredths.
const HALF_SPREAD: u64 = 5;

/// A generated tick, before encoding.
#[derive(Debug, Clone)]
struct Tick {
    /// Sequence number of this update.
    seq_num: u64,
    /// Instrument.
    symbol: &'static str,
    /// Bid price in hundredths.
    bid_scaled: u64,
    /// Quantity at the bid.
    bid_size: u64,
}

/// Counters reported every few seconds.
#[derive(Debug, Default)]
struct Stats {
    /// Ticks the generator produced.
    generated: AtomicU64,
    /// Frames handed to a client queue.
    sent: AtomicU64,
    /// Ticks or frames dropped because a queue was full.
    dropped: AtomicU64,
    /// Clients currently connected.
    clients: AtomicU64,
}

/// Registry of connected clients, keyed by connection id.
type Clients = Arc<RwLock<HashMap<u64, mpsc::Sender<Bytes>>>>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();

    let cfg = ExampleConfig::fast_server(DEFAULT_PORT);
    let (tx, rx) = bounded::<Tick>(CHANNEL_CAPACITY);

    let running = Arc::new(AtomicBool::new(true));
    let stats = Arc::new(Stats::default());
    let clients: Clients = Arc::new(RwLock::new(HashMap::new()));

    let generator = {
        let running = Arc::clone(&running);
        let stats = Arc::clone(&stats);
        thread::spawn(move || generate(&tx, &running, &stats))
    };

    let broadcaster = {
        let clients = Arc::clone(&clients);
        let stats = Arc::clone(&stats);
        thread::spawn(move || broadcast(&rx, &clients, &stats))
    };

    {
        let stats = Arc::clone(&stats);
        let running = Arc::clone(&running);
        tokio::spawn(async move {
            while running.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(5)).await;
                info!(
                    generated = stats.generated.load(Ordering::Relaxed),
                    sent = stats.sent.load(Ordering::Relaxed),
                    dropped = stats.dropped.load(Ordering::Relaxed),
                    clients = stats.clients.load(Ordering::Relaxed),
                    "stats"
                );
            }
        });
    }

    let listener = TcpListener::bind(cfg.addr()).await?;
    info!(addr = %cfg.addr(), "FAST server listening");

    let mut next_client_id: u64 = 0;
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (socket, peer) = accepted?;
                next_client_id = next_client_id.checked_add(1).unwrap_or(0);
                let id = next_client_id;
                info!(client = id, %peer, "client connected");

                let clients = Arc::clone(&clients);
                let stats = Arc::clone(&stats);
                tokio::spawn(async move {
                    serve(socket, id, &clients, &stats).await;
                });
            }
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    error!(%error, "cannot listen for Ctrl-C; shutting down anyway");
                }
                info!("shutdown requested");
                break;
            }
        }
    }

    // Stopping the generator drops the sending half, which ends the
    // broadcaster's receive loop; both threads then join.
    running.store(false, Ordering::Relaxed);
    if generator.join().is_err() {
        error!("the generator thread panicked");
    }
    if broadcaster.join().is_err() {
        error!("the broadcaster thread panicked");
    }
    info!("stopped");
    Ok(())
}

/// Produces ticks until `running` is cleared or the channel is disconnected.
fn generate(tx: &Sender<Tick>, running: &AtomicBool, stats: &Stats) {
    info!("generator started");
    let mut prices = OPENING_PRICES;
    let mut seq_num: u64 = 0;

    while running.load(Ordering::Relaxed) {
        for (index, symbol) in SYMBOLS.iter().enumerate() {
            // A sequence number never wraps: reusing a number would misrepresent
            // a fresh tick as a replay. On exhaustion the generator stops rather
            // than silently reusing 1.
            let Some(next) = seq_num.checked_add(1) else {
                warn!("market-data sequence number exhausted; stopping the generator");
                return;
            };
            seq_num = next;
            let Some(price) = prices.get_mut(index) else {
                continue;
            };
            *price = walk(*price, seq_num);

            let tick = Tick {
                seq_num,
                symbol,
                bid_scaled: price.checked_sub(HALF_SPREAD).unwrap_or(PRICE_FLOOR),
                bid_size: 100 + (seq_num % 900),
            };

            match tx.try_send(tick) {
                Ok(()) => {
                    stats.generated.fetch_add(1, Ordering::Relaxed);
                }
                // A full queue means the consumer is behind. A market data feed
                // drops rather than blocks: a stale tick is worth less than a
                // late one.
                Err(TrySendError::Full(_)) => {
                    stats.dropped.fetch_add(1, Ordering::Relaxed);
                }
                Err(TrySendError::Disconnected(_)) => {
                    info!("channel disconnected, generator stopping");
                    return;
                }
            }
        }

        thread::sleep(GENERATOR_PAUSE);
    }

    info!("generator stopped");
}

/// Encodes each tick once and hands it to every connected client.
///
/// Runs on its own thread, so the blocking `recv` costs nothing but that
/// thread. Calling it from an `async fn` — as this example used to, via
/// `recv_timeout` — parks a Tokio worker instead.
fn broadcast(rx: &Receiver<Tick>, clients: &Clients, stats: &Stats) {
    info!("broadcaster started");

    while let Ok(tick) = rx.recv() {
        let message = MarketData {
            seq_num: tick.seq_num,
            sending_time: Some(Timestamp::now().format_millis().to_string()),
            symbol: Some(tick.symbol.to_string()),
            price_scaled: Some(tick.bid_scaled),
            size: Some(tick.bid_size),
        };

        let frame = match encode(&message) {
            Ok(frame) => Bytes::from(frame),
            Err(error) => {
                warn!(seq_num = tick.seq_num, %error, "cannot encode a tick");
                continue;
            }
        };

        // The guard is confined to this block: the registry is read, the
        // frames are queued, and it is released before the next tick.
        let registry = clients.read();
        for (id, sender) in registry.iter() {
            match sender.try_send(frame.clone()) {
                Ok(()) => {
                    stats.sent.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    stats.dropped.fetch_add(1, Ordering::Relaxed);
                    warn!(client = id, "client queue full, dropping tick");
                }
            }
        }
    }

    info!("broadcaster stopped");
}

/// Registers a client, writes its queue to the socket, and deregisters it.
async fn serve(mut socket: TcpStream, id: u64, clients: &Clients, stats: &Stats) {
    let (tx, mut rx) = mpsc::channel::<Bytes>(CLIENT_QUEUE_CAPACITY);
    clients.write().insert(id, tx);
    stats.clients.fetch_add(1, Ordering::Relaxed);

    while let Some(frame) = rx.recv().await {
        if let Err(error) = socket.write_all(&frame).await {
            warn!(client = id, %error, "write failed");
            break;
        }
    }

    clients.write().remove(&id);
    stats.clients.fetch_sub(1, Ordering::Relaxed);
    info!(client = id, "client disconnected");
}

/// Moves a price by a deterministic pseudo-random step, in hundredths.
fn walk(price: u64, seq_num: u64) -> u64 {
    let step = (seq_num % 11) * 10;
    let moved = if seq_num.is_multiple_of(2) {
        price.checked_add(step).unwrap_or(price)
    } else {
        price.checked_sub(step).unwrap_or(PRICE_FLOOR)
    };
    moved.max(PRICE_FLOOR)
}
