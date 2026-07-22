/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/

//! FAST market data client example.
//!
//! Connects to `fast_server` and decodes the MarketData stream using the shared
//! template in [`ironfix_example::fast_market_data`], which reads a real
//! presence map and reports an absent optional field as absent.
//!
//! ```text
//! FIX_HOST=127.0.0.1 FAST_PORT=9890 cargo run --example fast_client
//! ```
//!
//! # Reading an untrusted stream
//!
//! Two rules keep this loop from being a denial-of-service target, and both are
//! worth copying:
//!
//! * A decode failure is triaged. Only [`FastError::UnexpectedEof`] means "the
//!   message is not all here yet"; anything else means the stream is corrupt at
//!   this position, and the connection is dropped. Treating every error as
//!   "need more data" — as this example used to — means one bad byte stalls the
//!   decoder forever while the buffer grows without bound.
//! * The buffer has a ceiling. A peer that never completes a message cannot
//!   make this process allocate indefinitely.

mod common;

use anyhow::{Context, bail};
use common::{ExampleConfig, init_logging};
use ironfix_example::fast_market_data::{MarketData, decode, needs_more_data};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tracing::{info, warn};

/// Port dialled when neither `FAST_PORT` nor `FIX_PORT` is set.
const DEFAULT_PORT: u16 = 9890;

/// Largest amount of undecoded data held before the peer is disconnected.
///
/// Far above any single template-1 message, so it can only be reached by a peer
/// that is not sending complete messages.
const MAX_BUFFERED: usize = 64 * 1024;

/// Size of each socket read.
const READ_CHUNK: usize = 4096;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();

    let cfg = ExampleConfig::fast_client(DEFAULT_PORT);
    info!(addr = %cfg.addr(), "connecting to FAST server");
    let mut socket = TcpStream::connect(cfg.addr())
        .await
        .with_context(|| format!("connecting to {}", cfg.addr()))?;
    info!("connected");

    let mut chunk = vec![0u8; READ_CHUNK];
    let mut buffered: Vec<u8> = Vec::with_capacity(READ_CHUNK);

    loop {
        let read = socket
            .read(&mut chunk)
            .await
            .context("reading the stream")?;
        if read == 0 {
            info!("server closed the connection");
            return Ok(());
        }
        let Some(received) = chunk.get(..read) else {
            bail!("short read reported {read} bytes");
        };
        buffered.extend_from_slice(received);

        drain(&mut buffered)?;

        if buffered.len() > MAX_BUFFERED {
            bail!(
                "{} bytes buffered without a complete message; disconnecting",
                buffered.len()
            );
        }
    }
}

/// Decodes every complete message in `buffered` and discards the bytes they
/// consumed.
///
/// # Errors
/// Any [`FastError`](ironfix_fast::FastError) that is not a request for more
/// data: the stream is corrupt and cannot be resynchronised without a template
/// boundary, which FAST over TCP does not provide.
fn drain(buffered: &mut Vec<u8>) -> anyhow::Result<()> {
    let mut consumed = 0usize;

    loop {
        let mut offset = consumed;
        match decode(buffered, &mut offset) {
            Ok(message) => {
                report(&message)?;
                consumed = offset;
            }
            Err(error) if needs_more_data(&error) => break,
            Err(error) => {
                warn!(%error, at = consumed, "corrupt FAST stream");
                bail!("corrupt FAST stream at byte {consumed}: {error}");
            }
        }
    }

    if consumed > 0 {
        buffered.drain(..consumed);
    }
    Ok(())
}

/// Logs one decoded update.
fn report(message: &MarketData) -> anyhow::Result<()> {
    let price = message.price().context("price out of decimal range")?;
    info!(
        seq_num = message.seq_num,
        symbol = message.symbol.as_deref().unwrap_or("<absent>"),
        price = %price.map_or_else(|| "<absent>".to_string(), |p| p.to_string()),
        size = ?message.size,
        sending_time = message.sending_time.as_deref().unwrap_or("<absent>"),
        "market data"
    );
    Ok(())
}
