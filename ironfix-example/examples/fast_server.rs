/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/

//! FAST market data server example.
//!
//! Publishes a MarketData tick every 100 ms to each connected client, encoded
//! with the illustrative framing in [`ironfix_example::fast_market_data`] — an
//! honest [`PresenceMap`](ironfix_fast::PresenceMap), not a hand-rolled byte,
//! though the framing itself is this example's own and not a conforming FAST
//! template (see that module's docs).
//!
//! Prices are carried as scaled integers (hundredths) and are exact; they
//! become [`Decimal`] values, never `f64`. Every fifth tick omits `Size`, so a
//! reader can see the presence map doing its job rather than being decoration.
//!
//! ```text
//! FIX_HOST=0.0.0.0 FAST_PORT=9890 cargo run --example fast_server
//! ```
//!
//! `ironfix-fast` is standalone: there is no template-XML parser and no
//! integration with the session layer. This example carries its framing in
//! Rust because that is what exists today.

mod common;

use common::{ExampleConfig, init_logging};
use ironfix_core::Timestamp;
use ironfix_example::fast_market_data::{MarketData, PRICE_SCALE, encode};
use rust_decimal::Decimal;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, interval};
use tracing::{error, info, warn};

/// Port bound when neither `FAST_PORT` nor `FIX_PORT` is set.
const DEFAULT_PORT: u16 = 9890;

/// Instruments this feed publishes.
const SYMBOLS: [&str; 5] = ["AAPL", "GOOGL", "MSFT", "AMZN", "META"];

/// Opening prices, in hundredths.
const OPENING_PRICES: [u64; 5] = [15_000, 14_000, 38_000, 17_500, 50_000];

/// Floor a simulated price never goes below, in hundredths.
const PRICE_FLOOR: u64 = 100;

/// Interval between ticks.
const TICK: Duration = Duration::from_millis(100);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();

    let cfg = ExampleConfig::fast_server(DEFAULT_PORT);
    let listener = TcpListener::bind(cfg.addr()).await?;
    info!(addr = %cfg.addr(), "FAST server listening");

    loop {
        let (socket, peer) = listener.accept().await?;
        info!(%peer, "client connected");
        tokio::spawn(async move {
            if let Err(error) = publish(socket).await {
                warn!(%peer, %error, "client stream ended");
            }
            info!(%peer, "client disconnected");
        });
    }
}

/// Publishes ticks to one client until it goes away.
async fn publish(mut socket: TcpStream) -> anyhow::Result<()> {
    let mut ticker = interval(TICK);
    let mut prices = OPENING_PRICES;
    let mut seq_num: u64 = 1;

    loop {
        ticker.tick().await;

        let index = usize::try_from(seq_num % SYMBOLS.len() as u64).unwrap_or(0);
        let Some(symbol) = SYMBOLS.get(index) else {
            break;
        };
        let Some(price) = prices.get_mut(index) else {
            break;
        };
        *price = walk(*price, seq_num);

        let message = MarketData {
            seq_num,
            sending_time: Some(Timestamp::now().format_millis().to_string()),
            symbol: Some((*symbol).to_string()),
            price_scaled: Some(*price),
            // Every fifth tick is an indicative quote with no size attached.
            size: (!seq_num.is_multiple_of(5)).then(|| 100 + (seq_num % 900)),
        };

        let frame = match encode(&message) {
            Ok(frame) => frame,
            Err(error) => {
                error!(%error, "cannot encode a tick");
                break;
            }
        };

        if let Err(error) = socket.write_all(&frame).await {
            warn!(%error, "write failed");
            break;
        }

        info!(
            seq_num,
            symbol,
            price = %Decimal::new(i64::try_from(*price).unwrap_or(i64::MAX), PRICE_SCALE),
            size = ?message.size,
            "published"
        );

        // A sequence number never wraps: reusing a number would misrepresent a
        // fresh tick as a replay. On exhaustion the feed stops rather than
        // silently reusing 1.
        let Some(next) = seq_num.checked_add(1) else {
            warn!("market-data sequence number exhausted; stopping this client");
            break;
        };
        seq_num = next;
    }

    Ok(())
}

/// Moves a price by a deterministic pseudo-random step, in hundredths.
///
/// Checked throughout: a simulated feed that overflows into a nonsense price is
/// exactly the bug an example must not teach.
fn walk(price: u64, seq_num: u64) -> u64 {
    let step = (seq_num % 11) * 10;
    let moved = if seq_num.is_multiple_of(2) {
        price.checked_add(step).unwrap_or(price)
    } else {
        price.checked_sub(step).unwrap_or(PRICE_FLOOR)
    };
    moved.max(PRICE_FLOOR)
}
