/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 21/7/26
******************************************************************************/

//! The market-data message the `fast_server` / `fast_client` pair exchanges.
//!
//! Kept in one file so the encoder and the decoder cannot drift: the layout is
//! self-describing only to a peer that shares it, and the two examples
//! previously agreed on nothing but the field order.
//!
//! # This is an illustrative framing, not a conforming FAST template
//!
//! It is built from `ironfix-fast`'s stop-bit primitives — the `uint` / `ascii`
//! field encoders and a real [`PresenceMap`] — but the way it *arranges* them is
//! this example's own convention, not FAST 1.1. Do not copy it as a conforming
//! FAST template. Two differences in particular:
//!
//! * Conforming FAST reserves presence-map bit 0 for the template-identifier
//!   copy operator. This framing does not: it writes the message id as a plain
//!   mandatory `uint` and gives bit 0 to the first optional field.
//! * A conforming optional field that has no field operator is carried by FAST
//!   *nullable* encoding — the value is shifted so one representation is
//!   reserved to mean "absent" — not by a presence-map bit. This framing signals
//!   optional presence with presence-map bits because `ironfix-fast` implements
//!   neither field operators nor nullable encoding yet.
//!
//! Both are `ironfix-fast` crate-level gaps; until they are filled this file is
//! deliberately a private framing, so the examples have something to exchange
//! without overstating what the crate delivers.
//!
//! # Layout
//!
//! ```text
//! presence map      real stop-bit pmap bytes (see PresenceMap)
//! message id        uint    mandatory, no pmap bit
//! MsgSeqNum         uint    mandatory, no pmap bit
//! SendingTime       ascii   optional, pmap bit 0
//! Symbol            ascii   optional, pmap bit 1
//! Price             uint    optional, pmap bit 2 — scaled by PRICE_SCALE
//! Size              uint    optional, pmap bit 3
//! ```
//!
//! Here a presence-map bit signals each optional field, and the two mandatory
//! leading fields carry no bit. The map is built with [`PresenceMapBuilder`] and
//! written as raw stop-bit bytes. It is **not** an integer: the earlier version
//! of these examples ran a byte like `0b1111_1100 | 0x80` through `encode_uint`,
//! which stop-bit-varints `0xFC` into two bytes. The wire then carried a uint
//! that no presence-map reader would accept, and the client decoded and
//! discarded it — the pair interoperated with itself and nothing else.
//!
//! # Prices
//!
//! On the wire a price is a scaled integer: a count of hundredths, which is
//! exact. It becomes a [`Decimal`] the moment it is a value rather than bytes.
//! `f64` never appears — see `CLAUDE.md`, "Governance precedence", override 3.
//!
//! This lives in `src/` rather than in `examples/` so that `cargo test` runs the
//! round-trip and malformed-input tests below; tests declared inside an example
//! target are never executed.

use ironfix_fast::{FastDecoder, FastEncoder, FastError, PresenceMap, PresenceMapBuilder};
use rust_decimal::Decimal;

/// Leading message-identifier value for this framing's MarketData message.
///
/// It plays the role a FAST template id would, but it is written as a plain
/// mandatory `uint`, not through the template-copy operator a conforming FAST
/// stream uses — see the module docs. A mismatch decodes to
/// [`FastError::UnknownTemplate`].
pub const TEMPLATE_ID: u64 = 1;

/// Number of decimal places the wire price is scaled by.
pub const PRICE_SCALE: u32 = 2;

/// Number of presence-map bits this framing defines.
pub const PMAP_BITS: usize = 4;

/// A decoded MarketData message.
///
/// Every optional field is an [`Option`], because "absent" is what the presence
/// map actually says — substituting a default would invent market data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarketData {
    /// Sequence number of this update.
    pub seq_num: u64,
    /// `SendingTime`, in FIX `YYYYMMDD-HH:MM:SS.sss` form.
    pub sending_time: Option<String>,
    /// Instrument symbol.
    pub symbol: Option<String>,
    /// Price in hundredths, as carried on the wire.
    pub price_scaled: Option<u64>,
    /// Quantity available at that price.
    pub size: Option<u64>,
}

impl MarketData {
    /// Returns the price as an exact decimal, or `None` when it was absent.
    ///
    /// # Errors
    /// Returns [`FastError::IntegerOverflow`] if the scaled price does not fit
    /// in the mantissa a [`Decimal`] can hold.
    pub fn price(&self) -> Result<Option<Decimal>, FastError> {
        match self.price_scaled {
            None => Ok(None),
            Some(scaled) => {
                let mantissa = i64::try_from(scaled).map_err(|_| FastError::IntegerOverflow)?;
                Ok(Some(Decimal::new(mantissa, PRICE_SCALE)))
            }
        }
    }
}

/// Encodes a MarketData message.
///
/// # Arguments
/// * `message` - The update to encode
///
/// # Errors
/// [`FastError::InvalidString`] if a string field is not representable as FAST
/// ASCII, or [`FastError::PresenceMapTooLarge`] if the map exceeds the encoder's
/// ceiling — neither can happen for template 1, but neither is assumed away.
pub fn encode(message: &MarketData) -> Result<Vec<u8>, FastError> {
    let pmap = PresenceMapBuilder::new()
        .bit(message.sending_time.is_some())
        .bit(message.symbol.is_some())
        .bit(message.price_scaled.is_some())
        .bit(message.size.is_some())
        .build();

    // The presence map precedes the fields it describes and is written as raw
    // stop-bit bytes, not as an encoded integer.
    let mut frame = pmap.encode()?;

    let mut encoder = FastEncoder::new();
    encoder.encode_uint(TEMPLATE_ID);
    encoder.encode_uint(message.seq_num);
    if let Some(sending_time) = &message.sending_time {
        encoder.encode_ascii(sending_time)?;
    }
    if let Some(symbol) = &message.symbol {
        encoder.encode_ascii(symbol)?;
    }
    if let Some(price_scaled) = message.price_scaled {
        encoder.encode_uint(price_scaled);
    }
    if let Some(size) = message.size {
        encoder.encode_uint(size);
    }

    frame.extend_from_slice(&encoder.finish());
    Ok(frame)
}

/// Decodes one MarketData message from `data`, advancing `offset` past it.
///
/// # Arguments
/// * `data` - Bytes received so far
/// * `offset` - Position to decode from; advanced only on success
///
/// # Errors
/// [`FastError::UnexpectedEof`] when `data` holds only part of a message — the
/// caller keeps buffering. Any other variant means the stream is corrupt at
/// this position and buffering more will not help:
/// [`FastError::UnknownTemplate`] for a message id this framing does not carry,
/// [`FastError::PresenceMapExhausted`] for a map shorter than this framing
/// defines, [`FastError::InvalidString`] for an over-long ASCII encoding.
pub fn decode(data: &[u8], offset: &mut usize) -> Result<MarketData, FastError> {
    let mut cursor = *offset;

    let mut pmap = PresenceMap::decode(data, &mut cursor)?;
    let template_id = FastDecoder::decode_uint(data, &mut cursor)?;
    if template_id != TEMPLATE_ID {
        let narrowed = u32::try_from(template_id).unwrap_or(u32::MAX);
        return Err(FastError::UnknownTemplate(narrowed));
    }
    let seq_num = FastDecoder::decode_uint(data, &mut cursor)?;

    let sending_time = if pmap.next_bit()? {
        Some(FastDecoder::decode_ascii(data, &mut cursor)?)
    } else {
        None
    };
    let symbol = if pmap.next_bit()? {
        Some(FastDecoder::decode_ascii(data, &mut cursor)?)
    } else {
        None
    };
    let price_scaled = if pmap.next_bit()? {
        Some(FastDecoder::decode_uint(data, &mut cursor)?)
    } else {
        None
    };
    let size = if pmap.next_bit()? {
        Some(FastDecoder::decode_uint(data, &mut cursor)?)
    } else {
        None
    };

    *offset = cursor;
    Ok(MarketData {
        seq_num,
        sending_time,
        symbol,
        price_scaled,
        size,
    })
}

/// Reports whether `error` means "the message is not all here yet".
///
/// Everything else is a corrupt stream: the connection must be dropped rather
/// than retried, because no additional byte makes a bad presence map good.
#[must_use]
pub fn needs_more_data(error: &FastError) -> bool {
    matches!(error, FastError::UnexpectedEof)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A message with every optional field present.
    fn full() -> MarketData {
        MarketData {
            seq_num: 42,
            sending_time: Some("20260721-12:34:56.789".to_string()),
            symbol: Some("AAPL".to_string()),
            price_scaled: Some(15_025),
            size: Some(300),
        }
    }

    #[test]
    fn a_full_message_round_trips() {
        let frame = encode(&full()).expect("encodes");
        let mut offset = 0;
        let decoded = decode(&frame, &mut offset).expect("decodes");
        assert_eq!(decoded, full());
        assert_eq!(offset, frame.len(), "the whole frame is consumed");
    }

    #[test]
    fn an_absent_optional_field_round_trips_as_absent() {
        let mut message = full();
        message.size = None;
        message.sending_time = None;

        let frame = encode(&message).expect("encodes");
        let mut offset = 0;
        let decoded = decode(&frame, &mut offset).expect("decodes");

        assert_eq!(decoded.size, None);
        assert_eq!(decoded.sending_time, None);
        assert_eq!(decoded.symbol.as_deref(), Some("AAPL"));
        assert_eq!(decoded.price_scaled, Some(15_025));
        assert_eq!(offset, frame.len());
    }

    #[test]
    fn the_presence_map_is_a_pmap_not_an_encoded_integer() {
        let mut message = full();
        message.sending_time = None;
        message.symbol = None;
        message.price_scaled = None;
        message.size = None;

        let frame = encode(&message).expect("encodes");
        // A four-bit map with every bit clear is one byte: payload 0, stop bit
        // set. Running that through `encode_uint` would have produced 0x80 too,
        // but a *set* map would not: bits 1111 are 0x78 | stop = 0xF8, whereas
        // `encode_uint(0xF8)` is two bytes.
        assert_eq!(frame.first(), Some(&0x80));

        let all_present = encode(&full()).expect("encodes");
        assert_eq!(all_present.first(), Some(&0xF8));
    }

    #[test]
    fn a_truncated_frame_asks_for_more_data() {
        let frame = encode(&full()).expect("encodes");
        for length in 0..frame.len() {
            let mut offset = 0;
            let error =
                decode(&frame[..length], &mut offset).expect_err("a partial frame must not decode");
            assert!(
                needs_more_data(&error),
                "{length} bytes reported {error} rather than EOF"
            );
            assert_eq!(offset, 0, "a failed decode must not consume bytes");
        }
    }

    #[test]
    fn an_unknown_template_is_not_a_request_for_more_data() {
        let mut encoder = FastEncoder::new();
        encoder.encode_uint(TEMPLATE_ID + 1);
        encoder.encode_uint(1);
        let mut frame = PresenceMapBuilder::new()
            .bit(false)
            .bit(false)
            .bit(false)
            .bit(false)
            .build()
            .encode()
            .expect("encodes");
        frame.extend_from_slice(&encoder.finish());

        let mut offset = 0;
        let error = decode(&frame, &mut offset).expect_err("rejected");
        assert!(matches!(error, FastError::UnknownTemplate(2)));
        assert!(!needs_more_data(&error), "a corrupt stream must not stall");
    }

    #[test]
    fn an_over_long_ascii_field_is_corrupt_not_incomplete() {
        // Symbol present, everything else absent.
        let mut frame = PresenceMapBuilder::new()
            .bit(false)
            .bit(true)
            .bit(false)
            .bit(false)
            .build()
            .encode()
            .expect("encodes");

        let mut encoder = FastEncoder::new();
        encoder.encode_uint(TEMPLATE_ID);
        encoder.encode_uint(9);
        frame.extend_from_slice(&encoder.finish());
        // A leading NUL is legal only as the one-character NUL string; longer
        // is an over-long encoding the decoder must refuse.
        frame.extend_from_slice(&[0x00, 0x41 | 0x80]);

        let mut offset = 0;
        let error = decode(&frame, &mut offset).expect_err("rejected");
        assert!(matches!(error, FastError::InvalidString));
        assert!(
            !needs_more_data(&error),
            "buffering more bytes cannot repair this"
        );
    }

    #[test]
    fn a_price_becomes_an_exact_decimal() {
        let message = MarketData {
            seq_num: 1,
            sending_time: None,
            symbol: None,
            price_scaled: Some(10),
            size: None,
        };
        let price = message.price().expect("in range").expect("present");
        assert_eq!(price.to_string(), "0.10");

        let sum = price + price + price;
        assert_eq!(sum.to_string(), "0.30", "decimal arithmetic stays exact");
    }

    #[test]
    fn an_absent_price_is_absent_not_zero() {
        let message = MarketData {
            seq_num: 1,
            sending_time: None,
            symbol: None,
            price_scaled: None,
            size: None,
        };
        assert_eq!(message.price().expect("in range"), None);
    }

    #[test]
    fn several_messages_decode_from_one_buffer() {
        let mut buffer = Vec::new();
        for seq_num in 1..=3u64 {
            let mut message = full();
            message.seq_num = seq_num;
            buffer.extend_from_slice(&encode(&message).expect("encodes"));
        }

        let mut offset = 0;
        for seq_num in 1..=3u64 {
            let decoded = decode(&buffer, &mut offset).expect("decodes");
            assert_eq!(decoded.seq_num, seq_num);
        }
        assert_eq!(offset, buffer.len());
    }
}
