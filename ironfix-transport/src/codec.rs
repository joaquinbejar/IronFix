/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! Tokio codec for FIX message framing.
//!
//! This module provides a codec that handles FIX message framing over TCP,
//! including BeginString, BodyLength, and Checksum validation.
//!
//! The codec sits at the untrusted-input boundary of the engine: every byte it
//! sees is chosen by the counterparty. Three properties follow from that and
//! are enforced here rather than assumed:
//!
//! * **Bounded buffering.** A frame is never accumulated past
//!   [`FixCodec::with_max_message_size`], and the header region
//!   (`8=…<SOH>9=…<SOH>`) is additionally capped at 64 bytes, so a peer that
//!   never sends a delimiter cannot grow the read buffer. Note this bounds the
//!   buffer's *length*, not its resident cost: on seeing a valid header the
//!   codec reserves the declared frame size up front, so a peer can pin up to
//!   `max_message_size` per connection with a 20-byte header and then stall.
//!   That is the same trade-off `tokio_util`'s own `LengthDelimitedCodec`
//!   makes; lower the ceiling if it matters for your deployment.
//! * **Structural verification.** The trailer implied by the declared
//!   BodyLength is checked to actually be `<SOH>10=NNN<SOH>` before any frame is
//!   handed up, independently of whether checksum *values* are verified.
//! * **Checked arithmetic.** Every offset derived from BodyLength is folded with
//!   `checked_*`; a hostile declared length errors instead of wrapping into a
//!   plausible-looking offset.
//!
//! Malformed input maps to a typed [`CodecError`]. See the module docs on
//! [`CodecError`] for what each variant does to the read buffer, and
//! `doc/fix_operations.md` ("Garbled Messages and Transport Resynchronization")
//! for the protocol-level policy.

use bytes::{Buf, BufMut, BytesMut};
use ironfix_tagvalue::checksum::{calculate_checksum, parse_checksum};
use memchr::memchr;
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

/// Errors that can occur during codec operations.
///
/// # Effect on the read buffer
///
/// [`Decoder::decode`] consumes bytes on some error paths so that a caller that
/// chooses to continue reading is not stuck re-parsing the same garbage:
///
/// | Variant | Bytes consumed |
/// |---|---|
/// | [`Self::InvalidBeginString`] | up to and including the `<SOH>` of the next `<SOH>8` pair, so the buffer restarts at the `8` (the whole buffer if there is no such pair, minus a trailing `<SOH>` that may still be the start of one) |
/// | [`Self::InvalidTrailer`] | same resync as above — BodyLength is not corroborated by anything, so the length it declares is not trusted to bound the discard |
/// | [`Self::InvalidChecksumFormat`], [`Self::ChecksumMismatch`] | the whole declared frame — the trailer literal is exactly where BodyLength said, so the boundary is corroborated |
/// | all other variants | none — the frame boundary is unknown |
///
/// The consumption above is observable only by a caller that drives
/// [`Decoder::decode`] itself. `tokio_util::Framed` terminates its stream after
/// any decoder error, and the in-repo engine treats every `Err` as fatal, so
/// neither can act on it. It is specified and tested regardless, so that a
/// caller which does drive the codec directly has a defined contract.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CodecError {
    /// Message is incomplete, need more data.
    #[deprecated(
        since = "0.4.0",
        note = "never emitted: incomplete input is signalled by `Ok(None)`, the tokio-util idiom. Scheduled for removal in the next breaking release."
    )]
    #[error("incomplete message")]
    Incomplete,

    /// Invalid BeginString field.
    #[error("invalid begin string: message must start with 8=")]
    InvalidBeginString,

    /// Missing BodyLength field.
    #[error("missing body length field (tag 9)")]
    MissingBodyLength,

    /// Invalid BodyLength value.
    #[error("invalid body length value")]
    InvalidBodyLength,

    /// No complete `8=…<SOH>9=…<SOH>` header within the header-region ceiling.
    ///
    /// Emitted instead of asking for more data, so a peer that never sends a
    /// delimiter cannot grow the read buffer without bound.
    #[error(
        "malformed header: no complete BeginString/BodyLength header in the first {max_header_len} bytes"
    )]
    HeaderTooLong {
        /// Header-region ceiling in bytes (64).
        max_header_len: usize,
    },

    /// The bytes at the offsets implied by BodyLength are not a CheckSum
    /// trailer.
    ///
    /// A well-formed frame ends with `<SOH>10=NNN<SOH>`. This is checked
    /// unconditionally: the CheckSum field's *presence* is structural, while
    /// [`FixCodec::with_checksum_validation`] only governs whether its *value*
    /// is verified.
    #[error("invalid trailer: expected <SOH>10=NNN<SOH> at offset {offset}")]
    InvalidTrailer {
        /// Offset at which the CheckSum field was expected to start.
        offset: usize,
    },

    /// The CheckSum field value is not three decimal digits in `0..=255`.
    #[error("invalid checksum format: tag 10 is not three decimal digits in 0..=255")]
    InvalidChecksumFormat,

    /// Checksum mismatch.
    #[error("checksum mismatch: calculated {calculated}, declared {declared}")]
    ChecksumMismatch {
        /// Calculated checksum.
        calculated: u8,
        /// Declared checksum in message.
        declared: u8,
    },

    /// Message exceeds maximum size.
    #[error("message too large: {size} bytes exceeds maximum {max_size}")]
    MessageTooLarge {
        /// Actual message size.
        size: usize,
        /// Maximum allowed size.
        max_size: usize,
    },

    /// I/O error.
    #[error("io error: {0}")]
    Io(String),
}

impl From<std::io::Error> for CodecError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

/// SOH delimiter.
const SOH: u8 = 0x01;

/// The two bytes every FIX frame starts with.
const BEGIN_STRING_PREFIX: &[u8] = b"8=";

/// The two bytes that open the BodyLength field.
const BODY_LENGTH_PREFIX: &[u8] = b"9=";

/// The three bytes that open the CheckSum field.
const CHECKSUM_PREFIX: &[u8] = b"10=";

/// Length of the `10=NNN<SOH>` trailer in bytes.
const TRAILER_LEN: usize = 7;

/// Number of digits in a CheckSum value.
const CHECKSUM_DIGITS: usize = 3;

/// Shortest byte count that can possibly hold a complete frame.
///
/// The smallest legal FIX message — `8=FIX.4.0<SOH>9=5<SOH>35=0<SOH>10=NNN<SOH>`
/// — is 26 bytes, so 20 is a conservative floor for any conforming peer. It is
/// load-bearing rather than a pure optimisation: the framing arithmetic alone
/// admits frames as short as 14 bytes, and those stall here until more bytes
/// arrive. No real BeginString can produce one — the shortest, `FIX.4.4`,
/// yields 21 bytes — so this is unreachable for a conforming counterparty.
const MIN_FRAME_LEN: usize = 20;

/// Maximum size of the header region `8=…<SOH>9=…<SOH>`, in bytes.
///
/// The header of a legal frame is short and its length is bounded by the
/// specification, not by the payload: `8=` plus the longest BeginString in the
/// FIX family (`FIXT.1.1`, 8 bytes) plus SOH is at most 12 bytes, and `9=` plus
/// a 10-digit BodyLength plus SOH is at most 13 more — 25 bytes in the worst
/// case. A buffer that has not produced both delimiters within 64 bytes is
/// therefore already malformed, and continuing to ask for more data would let a
/// peer sending `8=` followed by endless non-SOH bytes grow the read buffer
/// (and force a quadratic re-scan on every poll). The ceiling is well above any
/// legal header, so it can only reject garbage.
const MAX_HEADER_LEN: usize = 64;

/// Maximum number of digits accepted in a BodyLength value.
///
/// Ten digits already exceed any deliverable frame; the bound keeps the fold in
/// [`parse_body_length`] short and makes an overflow attempt fail fast.
const MAX_BODY_LENGTH_DIGITS: usize = 10;

/// Parses a BodyLength value from ASCII digits.
///
/// FIX defines tag 9 as an unsigned integer, so a leading sign or any
/// non-digit byte is rejected rather than coerced.
///
/// # Returns
/// The declared body length, or `None` if the value is empty, non-numeric, too
/// long, or overflows `usize`.
#[inline]
fn parse_body_length(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() || bytes.len() > MAX_BODY_LENGTH_DIGITS {
        return None;
    }

    let mut result: usize = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        result = result.checked_mul(10)?.checked_add(usize::from(b - b'0'))?;
    }

    Some(result)
}

/// Returns how many bytes to discard so the buffer restarts at a candidate
/// frame.
///
/// Scans for the next `<SOH>8` pair and returns the offset of that `8`, so the
/// surviving buffer begins where a new BeginString may start. When no such pair
/// exists the whole buffer is garbage and is discarded, except for a trailing
/// SOH — that byte may be the first half of a pair whose `8` has not arrived
/// yet, so it is kept.
///
/// Anchoring on `<SOH>8` rather than on a bare `8=` is deliberate: `8=` occurs
/// as a substring of ordinary tags (`18=`, `58=`, …), so a bare scan would
/// resynchronise onto the middle of a field. The cost is that a well-formed
/// frame arriving immediately after garbage is normally lost too — its `8=` is
/// preceded by that garbage rather than by SOH — unless the garbage happens to
/// end on an SOH. Recovery resumes at the frame after it.
#[must_use]
fn resync_offset(src: &[u8]) -> usize {
    let mut from = 0usize;
    while let Some(relative) = memchr(SOH, src.get(from..).unwrap_or(&[])) {
        let Some(soh) = from.checked_add(relative) else {
            return src.len();
        };
        let Some(candidate) = soh.checked_add(1) else {
            return src.len();
        };
        match src.get(candidate) {
            // A frame may start here; keep everything from this byte on.
            Some(&b'8') => return candidate,
            // The SOH is the last byte: its partner may still arrive.
            None => return soh,
            Some(_) => from = candidate,
        }
    }
    src.len()
}

/// Tokio codec for FIX message framing.
///
/// Handles parsing of FIX messages from a byte stream, validating
/// BeginString, BodyLength, and optionally Checksum.
#[derive(Debug, Clone)]
pub struct FixCodec {
    /// Maximum message size in bytes.
    max_message_size: usize,
    /// Whether to validate checksums.
    validate_checksum: bool,
}

impl FixCodec {
    /// Creates a new codec with default settings.
    ///
    /// Defaults: a 1 MiB maximum message size and checksum validation enabled.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_message_size: 1024 * 1024, // 1MB
            validate_checksum: true,
        }
    }

    /// Sets the maximum message size.
    ///
    /// The limit applies in both directions: a larger frame is neither
    /// accumulated on decode nor written on encode.
    #[must_use]
    pub const fn with_max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    /// Sets whether to validate checksums.
    ///
    /// This governs only whether the CheckSum *value* is compared. The presence
    /// and shape of the trailer are structural and are always verified.
    #[must_use]
    pub const fn with_checksum_validation(mut self, validate: bool) -> Self {
        self.validate_checksum = validate;
        self
    }

    /// Decides what a header-phase miss means for a buffer of `src_len` bytes.
    ///
    /// Returns `Ok(None)` ("read more") only while the buffer is still within
    /// both ceilings; past either one the input can no longer become a legal
    /// frame, so it is rejected instead of buffered.
    ///
    /// # Errors
    /// * [`CodecError::MessageTooLarge`] - the buffered prefix already exceeds
    ///   the configured maximum message size.
    /// * [`CodecError::HeaderTooLong`] - no complete header within
    ///   [`MAX_HEADER_LEN`] bytes.
    fn header_needs_more(&self, src_len: usize) -> Result<Option<BytesMut>, CodecError> {
        // Checked first: when a single read delivers more bytes than any legal
        // frame, the frame ceiling is the more informative diagnostic.
        if src_len > self.max_message_size {
            return Err(CodecError::MessageTooLarge {
                size: src_len,
                max_size: self.max_message_size,
            });
        }
        if src_len >= MAX_HEADER_LEN {
            return Err(CodecError::HeaderTooLong {
                max_header_len: MAX_HEADER_LEN,
            });
        }
        Ok(None)
    }
}

impl Default for FixCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for FixCodec {
    type Item = BytesMut;
    type Error = CodecError;

    /// Extracts one complete FIX frame from `src`.
    ///
    /// # Errors
    /// Returns a [`CodecError`] for any malformed frame; see that type for
    /// which variants consume bytes from `src`.
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < MIN_FRAME_LEN {
            return Ok(None);
        }

        // Validate BeginString starts with "8=". A frame that does not is
        // garbled: discard up to the next candidate frame so a caller that
        // keeps reading makes progress instead of re-parsing these bytes.
        if src.get(..BEGIN_STRING_PREFIX.len()) != Some(BEGIN_STRING_PREFIX) {
            let discarded = resync_offset(src);
            src.advance(discarded);
            tracing::warn!(
                discarded,
                "garbled FIX frame: resynchronised to the next <SOH>8"
            );
            return Err(CodecError::InvalidBeginString);
        }

        // The header is parsed inside a bounded window, so every "need more
        // data" answer below is capped by MAX_HEADER_LEN rather than by the
        // peer's willingness to send a delimiter.
        let bytes: &[u8] = src.as_ref();
        let header = bytes.get(..MAX_HEADER_LEN).unwrap_or(bytes);

        // Find first SOH to get BeginString value
        let Some(first_soh) = memchr(SOH, header) else {
            return self.header_needs_more(src.len());
        };

        // Find BodyLength field (9=XXX|)
        let Some(body_len_start) = first_soh.checked_add(1) else {
            return Err(CodecError::InvalidBodyLength);
        };
        let Some(body_len_end) = body_len_start.checked_add(BODY_LENGTH_PREFIX.len()) else {
            return Err(CodecError::InvalidBodyLength);
        };
        match header.get(body_len_start..body_len_end) {
            Some(prefix) if prefix == BODY_LENGTH_PREFIX => {}
            Some(_) => return Err(CodecError::MissingBodyLength),
            None => return self.header_needs_more(src.len()),
        }

        // Find SOH after BodyLength
        let Some(after_prefix) = header.get(body_len_end..) else {
            return self.header_needs_more(src.len());
        };
        let Some(digits_len) = memchr(SOH, after_prefix) else {
            return self.header_needs_more(src.len());
        };
        let Some(digits) = after_prefix.get(..digits_len) else {
            return Err(CodecError::InvalidBodyLength);
        };
        let body_length = parse_body_length(digits).ok_or(CodecError::InvalidBodyLength)?;
        let body_len_soh = body_len_end
            .checked_add(digits_len)
            .ok_or(CodecError::InvalidBodyLength)?;

        // BodyLength counts the bytes between the SOH that terminates it and
        // the start of the CheckSum field, so the frame is
        // `header + body + 10=NNN<SOH>`. BodyLength is attacker-controlled:
        // fold with checked arithmetic so a hostile declared length errors
        // instead of overflowing usize.
        let body_start = body_len_soh
            .checked_add(1)
            .ok_or(CodecError::InvalidBodyLength)?;
        let body_end = body_start
            .checked_add(body_length)
            .ok_or(CodecError::InvalidBodyLength)?;
        let total_length = body_end
            .checked_add(TRAILER_LEN)
            .ok_or(CodecError::InvalidBodyLength)?;

        // Check maximum size
        if total_length > self.max_message_size {
            return Err(CodecError::MessageTooLarge {
                size: total_length,
                max_size: self.max_message_size,
            });
        }

        // Check if we have the complete message
        match total_length.checked_sub(src.len()) {
            Some(0) | None => {}
            Some(missing) => {
                src.reserve(missing);
                return Ok(None);
            }
        }

        // Verify the trailer the declared BodyLength points at. Without this a
        // wrong BodyLength silently mis-frames the stream when checksum
        // validation is off, and surfaces as a misleading ChecksumMismatch when
        // it is on.
        //
        // How much to discard on failure depends on whether BodyLength is
        // corroborated by anything:
        //
        // * the trailer is absent from the offsets it implies -> BodyLength is
        //   not corroborated, and consuming `total_length` would discard an
        //   attacker-chosen span. A 21-byte header declaring a large body can
        //   name tens of thousands of well-formed frames that merely follow it.
        //   Resync to the next candidate frame instead.
        // * the trailer literal is exactly where BodyLength said, and only the
        //   digits are wrong -> the boundary is corroborated, so consuming the
        //   declared frame keeps a stream of good frames aligned.
        //
        // Bound before matching: the borrow of `src` must end before the error
        // arms advance it.
        let trailer = verify_trailer(src.as_ref(), body_end, total_length);
        let declared = match trailer {
            Ok(value) => value,
            Err(error @ CodecError::InvalidTrailer { .. }) => {
                let discarded = resync_offset(src);
                src.advance(discarded);
                tracing::warn!(
                    discarded,
                    "FIX trailer absent at the declared BodyLength offset: resynchronised"
                );
                return Err(error);
            }
            Err(error) => {
                src.advance(total_length);
                return Err(error);
            }
        };

        // Validate checksum if enabled
        if self.validate_checksum {
            // Everything before the CheckSum field is covered by the checksum.
            // The slice is always present here (`body_end < total_length <=
            // src.len()`), but it is taken with `get` rather than indexed.
            let calculated = src.get(..body_end).map(calculate_checksum);
            match calculated {
                Some(sum) if sum == declared => {}
                Some(sum) => {
                    src.advance(total_length);
                    return Err(CodecError::ChecksumMismatch {
                        calculated: sum,
                        declared,
                    });
                }
                None => {
                    let discarded = resync_offset(src);
                    src.advance(discarded);
                    return Err(CodecError::InvalidTrailer { offset: body_end });
                }
            }
        }

        // Extract the complete message
        let message = src.split_to(total_length);
        Ok(Some(message))
    }
}

/// Verifies the `<SOH>10=NNN<SOH>` trailer at `body_end` and returns the
/// declared checksum.
///
/// `src` is known to hold at least `total_length` bytes, and
/// `total_length == body_end + TRAILER_LEN`.
///
/// # Errors
/// * [`CodecError::InvalidTrailer`] - the CheckSum field literal or either
///   surrounding SOH is absent at the offsets BodyLength implies.
/// * [`CodecError::InvalidChecksumFormat`] - the three CheckSum digits are not
///   a decimal value in `0..=255`.
fn verify_trailer(src: &[u8], body_end: usize, total_length: usize) -> Result<u8, CodecError> {
    let malformed = || CodecError::InvalidTrailer { offset: body_end };

    // The body's own terminating SOH sits immediately before the CheckSum field.
    if body_end
        .checked_sub(1)
        .and_then(|index| src.get(index))
        .copied()
        != Some(SOH)
    {
        return Err(malformed());
    }

    let trailer = src.get(body_end..total_length).ok_or_else(malformed)?;
    if trailer.get(..CHECKSUM_PREFIX.len()) != Some(CHECKSUM_PREFIX) {
        return Err(malformed());
    }
    if trailer.last().copied() != Some(SOH) {
        return Err(malformed());
    }

    let digits_end = CHECKSUM_PREFIX
        .len()
        .checked_add(CHECKSUM_DIGITS)
        .ok_or_else(malformed)?;
    let digits = trailer
        .get(CHECKSUM_PREFIX.len()..digits_end)
        .ok_or_else(malformed)?;

    // The digits are structural too: a caller that disabled checksum
    // *comparison* still gets a frame whose trailer is well formed.
    parse_checksum(digits).ok_or(CodecError::InvalidChecksumFormat)
}

impl Encoder<&[u8]> for FixCodec {
    type Error = CodecError;

    /// Appends `item` to `dst` verbatim.
    ///
    /// # Errors
    /// Returns [`CodecError::MessageTooLarge`] when `item` exceeds the
    /// configured maximum message size, so the codec never transmits a frame it
    /// would refuse to receive.
    fn encode(&mut self, item: &[u8], dst: &mut BytesMut) -> Result<(), Self::Error> {
        if item.len() > self.max_message_size {
            return Err(CodecError::MessageTooLarge {
                size: item.len(),
                max_size: self.max_message_size,
            });
        }
        dst.reserve(item.len());
        dst.put_slice(item);
        Ok(())
    }
}

impl Encoder<BytesMut> for FixCodec {
    type Error = CodecError;

    /// Appends `item` to `dst` verbatim, delegating to the `&[u8]` impl.
    ///
    /// # Errors
    /// Returns [`CodecError::MessageTooLarge`] when `item` exceeds the
    /// configured maximum message size.
    fn encode(&mut self, item: BytesMut, dst: &mut BytesMut) -> Result<(), Self::Error> {
        Encoder::<&[u8]>::encode(self, item.as_ref(), dst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a well-formed frame around `body` with a correct checksum.
    fn make_fix_message(body: &str) -> Vec<u8> {
        let without_checksum = format!("8=FIX.4.4\x019={}\x01{}", body.len(), body);
        let checksum = calculate_checksum(without_checksum.as_bytes());
        format!("{without_checksum}10={checksum:03}\x01").into_bytes()
    }

    /// Decodes expecting success, returning the extracted frame.
    fn decode_frame(codec: &mut FixCodec, buf: &mut BytesMut) -> BytesMut {
        match codec.decode(buf) {
            Ok(Some(frame)) => frame,
            other => panic!("expected a complete frame, got {other:?}"),
        }
    }

    #[test]
    fn test_decode_complete_message_consumes_the_frame() {
        let mut codec = FixCodec::new();
        let msg = make_fix_message("35=0\x01");
        let mut buf = BytesMut::from(&msg[..]);

        let frame = decode_frame(&mut codec, &mut buf);
        assert_eq!(&frame[..], &msg[..]);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_decode_truncated_message_is_none() {
        let mut codec = FixCodec::new();
        let msg = make_fix_message("35=0\x01");
        let Some(head) = msg.get(..msg.len() - 5) else {
            panic!("message is longer than the truncation");
        };
        let mut buf = BytesMut::from(head);

        assert!(matches!(codec.decode(&mut buf), Ok(None)));
    }

    #[test]
    fn test_decode_split_buffer_remainder_reassembles() {
        let mut codec = FixCodec::new();
        let msg = make_fix_message("35=0\x0149=SENDER\x0156=TARGET\x01");
        let split_at = msg.len() - 5;
        let (Some(head), Some(tail)) = (msg.get(..split_at), msg.get(split_at..)) else {
            panic!("split point is inside the message");
        };

        let mut buf = BytesMut::from(head);
        assert!(matches!(codec.decode(&mut buf), Ok(None)));

        buf.extend_from_slice(tail);
        let frame = decode_frame(&mut codec, &mut buf);
        assert_eq!(&frame[..], &msg[..]);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_decode_byte_by_byte_feed_reassembles_one_message() {
        let mut codec = FixCodec::new();
        let msg = make_fix_message("35=A\x0149=SENDER\x0156=TARGET\x0198=0\x01108=30\x01");
        let mut buf = BytesMut::new();
        let mut decoded = None;

        for (index, byte) in msg.iter().enumerate() {
            buf.extend_from_slice(&[*byte]);
            match codec.decode(&mut buf) {
                Ok(None) => {}
                Ok(Some(frame)) => {
                    assert_eq!(index + 1, msg.len(), "frame emitted before the last byte");
                    decoded = Some(frame);
                }
                Err(error) => panic!("byte {index} produced {error:?}"),
            }
        }

        let Some(frame) = decoded else {
            panic!("byte-by-byte feed never produced a frame");
        };
        assert_eq!(&frame[..], &msg[..]);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_decode_chunk_boundary_inside_body_length_field() {
        let mut codec = FixCodec::new();
        // Body long enough that BodyLength is three digits, so a boundary can
        // fall between them.
        let body = format!("35=D\x0158={}\x01", "x".repeat(120));
        let msg = make_fix_message(&body);
        // "8=FIX.4.4<SOH>9=" is 12 bytes; cut after the first BodyLength digit.
        let split_at = 13;
        let (Some(head), Some(tail)) = (msg.get(..split_at), msg.get(split_at..)) else {
            panic!("split point is inside the message");
        };

        let mut buf = BytesMut::from(head);
        assert!(matches!(codec.decode(&mut buf), Ok(None)));

        buf.extend_from_slice(tail);
        let frame = decode_frame(&mut codec, &mut buf);
        assert_eq!(&frame[..], &msg[..]);
    }

    #[test]
    fn test_decode_chunk_boundary_inside_trailer() {
        let mut codec = FixCodec::new();
        let msg = make_fix_message("35=0\x0149=SENDER\x01");
        // Cut between the "10=" literal and its digits.
        let split_at = msg.len() - 4;
        let (Some(head), Some(tail)) = (msg.get(..split_at), msg.get(split_at..)) else {
            panic!("split point is inside the message");
        };

        let mut buf = BytesMut::from(head);
        assert!(matches!(codec.decode(&mut buf), Ok(None)));

        buf.extend_from_slice(tail);
        let frame = decode_frame(&mut codec, &mut buf);
        assert_eq!(&frame[..], &msg[..]);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_decode_two_back_to_back_messages_both_decode() {
        let mut codec = FixCodec::new();
        let first = make_fix_message("35=0\x0149=A\x0156=B\x01");
        let second = make_fix_message("35=A\x0149=CCCC\x0156=DDDD\x01");
        let mut buf = BytesMut::from(&first[..]);
        buf.extend_from_slice(&second);

        let frame_one = decode_frame(&mut codec, &mut buf);
        assert_eq!(&frame_one[..], &first[..]);

        let frame_two = decode_frame(&mut codec, &mut buf);
        assert_eq!(&frame_two[..], &second[..]);

        assert!(buf.is_empty());
        assert!(matches!(codec.decode(&mut buf), Ok(None)));
    }

    #[test]
    fn test_decode_two_messages_exceeding_the_ceiling_in_total_still_decode() {
        // The ceiling bounds one frame, not one read: a buffer holding several
        // legal frames must not be rejected for its total size.
        let mut codec = FixCodec::new().with_max_message_size(128);
        let first = make_fix_message(&format!("35=0\x0158={}\x01", "a".repeat(60)));
        let second = make_fix_message(&format!("35=0\x0158={}\x01", "b".repeat(60)));
        assert!(first.len() <= 128 && second.len() <= 128);
        assert!(first.len() + second.len() > 128);

        let mut buf = BytesMut::from(&first[..]);
        buf.extend_from_slice(&second);

        let frame_one = decode_frame(&mut codec, &mut buf);
        assert_eq!(&frame_one[..], &first[..]);
        let frame_two = decode_frame(&mut codec, &mut buf);
        assert_eq!(&frame_two[..], &second[..]);
    }

    #[test]
    fn test_decode_soh_free_buffer_over_ceiling_is_message_too_large() {
        let ceiling = 128;
        let mut codec = FixCodec::new().with_max_message_size(ceiling);
        let mut buf = BytesMut::from(&b"8="[..]);
        buf.extend_from_slice(&vec![b'X'; ceiling]);
        assert_eq!(buf.len(), ceiling + 2);

        assert!(matches!(
            codec.decode(&mut buf),
            Err(CodecError::MessageTooLarge { max_size, .. }) if max_size == ceiling
        ));
    }

    #[test]
    fn test_decode_soh_free_header_is_bounded_and_never_asks_for_more() {
        // A peer that sends "8=" and then never a delimiter must not be able to
        // grow the read buffer: the codec errors once the header ceiling is
        // reached, long before the message ceiling.
        let mut codec = FixCodec::new();
        let garbage = vec![b'X'; 4096];
        let mut buf = BytesMut::from(&b"8="[..]);
        let mut error = None;

        for byte in &garbage {
            buf.extend_from_slice(&[*byte]);
            match codec.decode(&mut buf) {
                Ok(None) => {}
                Ok(Some(frame)) => panic!("garbage produced a frame of {} bytes", frame.len()),
                Err(err) => {
                    error = Some(err);
                    break;
                }
            }
            assert!(
                buf.len() <= MAX_HEADER_LEN,
                "buffer grew to {} bytes without an error",
                buf.len()
            );
        }

        assert_eq!(
            error,
            Some(CodecError::HeaderTooLong {
                max_header_len: MAX_HEADER_LEN
            })
        );
        assert!(buf.len() <= MAX_HEADER_LEN + 1);
    }

    #[test]
    fn test_decode_long_body_length_digits_is_header_too_long() {
        let mut codec = FixCodec::new();
        let mut buf = BytesMut::from(&b"8=FIX.4.4\x019="[..]);
        buf.extend_from_slice(&[b'9'; MAX_HEADER_LEN]);

        assert_eq!(
            codec.decode(&mut buf).err(),
            Some(CodecError::HeaderTooLong {
                max_header_len: MAX_HEADER_LEN
            })
        );
    }

    #[test]
    fn test_decode_body_length_overflow_is_invalid_body_length() {
        let mut codec = FixCodec::new();
        let msg = format!("8=FIX.4.4\x019={}\x0135=0\x0110=000\x01", usize::MAX);
        let mut buf = BytesMut::from(msg.as_bytes());

        // Must error, not overflow the framing arithmetic.
        assert_eq!(
            codec.decode(&mut buf).err(),
            Some(CodecError::InvalidBodyLength)
        );
    }

    #[test]
    fn test_decode_non_numeric_body_length_is_invalid_body_length() {
        let mut codec = FixCodec::new();
        let mut buf = BytesMut::from(&b"8=FIX.4.4\x019=abc\x0135=0\x0110=000\x01"[..]);

        assert_eq!(
            codec.decode(&mut buf).err(),
            Some(CodecError::InvalidBodyLength)
        );
    }

    #[test]
    fn test_decode_empty_body_length_is_invalid_body_length() {
        let mut codec = FixCodec::new();
        let mut buf = BytesMut::from(&b"8=FIX.4.4\x019=\x0135=0\x0110=000\x01"[..]);

        assert_eq!(
            codec.decode(&mut buf).err(),
            Some(CodecError::InvalidBodyLength)
        );
    }

    #[test]
    fn test_decode_signed_body_length_is_invalid_body_length() {
        let mut codec = FixCodec::new();
        let mut buf = BytesMut::from(&b"8=FIX.4.4\x019=+5\x0135=0\x0110=000\x01"[..]);

        assert_eq!(
            codec.decode(&mut buf).err(),
            Some(CodecError::InvalidBodyLength)
        );
    }

    #[test]
    fn test_decode_missing_body_length_field_is_missing_body_length() {
        let mut codec = FixCodec::new();
        // Tag 35 where tag 9 must be.
        let mut buf = BytesMut::from(&b"8=FIX.4.4\x0135=0\x0149=A\x0110=000\x01"[..]);
        let total = buf.len();

        assert_eq!(
            codec.decode(&mut buf).err(),
            Some(CodecError::MissingBodyLength)
        );
        // The frame boundary is unknown, so nothing is consumed.
        assert_eq!(buf.len(), total);
    }

    #[test]
    fn test_decode_body_length_too_large_is_message_too_large() {
        let mut codec = FixCodec::new();
        let msg = format!("8=FIX.4.4\x019={}\x0135=0\x0110=000\x01", 10 * 1024 * 1024);
        let mut buf = BytesMut::from(msg.as_bytes());

        assert!(matches!(
            codec.decode(&mut buf),
            Err(CodecError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn test_decode_body_length_pointing_at_non_trailer_is_invalid_trailer() {
        // BodyLength says 3 where the body is 5 bytes, so the trailer offsets
        // land inside the body. This must be a framing error on both paths:
        // with validation off it used to mis-frame silently, with it on it used
        // to surface as a misleading ChecksumMismatch.
        for validate in [true, false] {
            let mut codec = FixCodec::new().with_checksum_validation(validate);
            let mut buf = BytesMut::from(&b"8=FIX.4.4\x019=3\x0135=0\x0110=000\x01"[..]);
            let total = buf.len();

            let result = codec.decode(&mut buf);
            assert!(
                matches!(result, Err(CodecError::InvalidTrailer { .. })),
                "validate_checksum={validate} must report a framing error, got {result:?}"
            );
            // BodyLength is not corroborated by anything here, so its declared
            // length is NOT used to bound the discard. The codec resyncs to the
            // next `<SOH>8` instead; there is none, so everything but a
            // trailing SOH goes.
            assert!(
                buf.len() < total,
                "validate_checksum={validate} must make progress"
            );
            assert!(
                buf.len() <= 1,
                "validate_checksum={validate} resync should leave at most a trailing SOH, left {}",
                buf.len()
            );
        }
    }

    #[test]
    fn test_decode_invalid_trailer_does_not_discard_the_frames_that_follow() {
        // A 21-byte hostile header declares a 222-byte body. Consuming the
        // declared frame would swallow every well-formed frame that merely
        // follows it -- at the default 1 MiB ceiling, tens of thousands of
        // them, reported as a single error. BodyLength is not corroborated by
        // any trailer here, so it must not bound the discard.
        let good = b"8=FIX.4.4\x019=15\x0135=0\x0149=A\x0156=B\x0110=171\x01";
        let mut raw = Vec::from(&b"8=FIX.4.4\x019=222\x0135=0\x01"[..]);
        let hostile_len = raw.len();
        for _ in 0..6 {
            raw.extend_from_slice(good);
        }
        // The declared frame ends two bytes past the last good frame, so the
        // buffer must hold it in full for the trailer check to run at all.
        let padding: &[u8] = b"\x01\x01\x01\x01\x01\x01\x01";
        raw.extend_from_slice(padding);
        let mut buf = BytesMut::from(&raw[..]);

        let mut codec = FixCodec::new();
        let result = codec.decode(&mut buf);
        assert!(
            matches!(result, Err(CodecError::InvalidTrailer { .. })),
            "expected a trailer error, got {result:?}"
        );
        // Only the hostile header is discarded: the good frames survive. Under
        // the previous policy this single error consumed 245 of 250 bytes.
        assert_eq!(buf.len(), raw.len() - hostile_len);

        for index in 0..6 {
            match codec.decode(&mut buf) {
                Ok(Some(frame)) => assert_eq!(&frame[..], &good[..]),
                other => panic!("frame {index} must survive the resync, got {other:?}"),
            }
        }
        assert_eq!(buf.len(), padding.len());
    }

    #[test]
    fn test_decode_missing_final_soh_is_invalid_trailer() {
        let mut codec = FixCodec::new();
        // Trailer terminated by 'X' instead of SOH.
        let mut buf = BytesMut::from(&b"8=FIX.4.4\x019=5\x0135=0\x0110=000X"[..]);

        assert!(matches!(
            codec.decode(&mut buf),
            Err(CodecError::InvalidTrailer { .. })
        ));
    }

    #[test]
    fn test_decode_malformed_checksum_digits_is_invalid_checksum_format() {
        // "10=0x0" has the right shape but is not a decimal value. It used to
        // be reported as InvalidBodyLength.
        for validate in [true, false] {
            let mut codec = FixCodec::new().with_checksum_validation(validate);
            let mut buf = BytesMut::from(&b"8=FIX.4.4\x019=5\x0135=0\x0110=0x0\x01"[..]);

            assert_eq!(
                codec.decode(&mut buf).err(),
                Some(CodecError::InvalidChecksumFormat),
                "validate_checksum={validate}"
            );
            assert!(buf.is_empty(), "the declared frame must be consumed");
        }
    }

    #[test]
    fn test_decode_out_of_range_checksum_is_invalid_checksum_format() {
        let mut codec = FixCodec::new();
        // 999 does not fit in a u8 checksum.
        let mut buf = BytesMut::from(&b"8=FIX.4.4\x019=5\x0135=0\x0110=999\x01"[..]);

        assert_eq!(
            codec.decode(&mut buf).err(),
            Some(CodecError::InvalidChecksumFormat)
        );
    }

    #[test]
    fn test_decode_checksum_mismatch_consumes_the_declared_frame() {
        let mut codec = FixCodec::new();
        let mut buf = BytesMut::from(&b"8=FIX.4.4\x019=5\x0135=0\x0110=000\x01"[..]);

        assert!(matches!(
            codec.decode(&mut buf),
            Err(CodecError::ChecksumMismatch { .. })
        ));
        assert!(buf.is_empty());
    }

    #[test]
    fn test_decode_checksum_mismatch_keeps_the_next_frame_aligned() {
        let mut codec = FixCodec::new();
        let good = make_fix_message("35=0\x0149=A\x01");
        let mut buf = BytesMut::from(&b"8=FIX.4.4\x019=5\x0135=0\x0110=000\x01"[..]);
        buf.extend_from_slice(&good);

        assert!(matches!(
            codec.decode(&mut buf),
            Err(CodecError::ChecksumMismatch { .. })
        ));
        let frame = decode_frame(&mut codec, &mut buf);
        assert_eq!(&frame[..], &good[..]);
    }

    #[test]
    fn test_decode_no_checksum_validation_accepts_a_wrong_checksum() {
        let mut codec = FixCodec::new().with_checksum_validation(false);
        let mut buf = BytesMut::from(&b"8=FIX.4.4\x019=5\x0135=0\x0110=000\x01"[..]);

        let frame = decode_frame(&mut codec, &mut buf);
        assert_eq!(frame.len(), 26);
    }

    #[test]
    fn test_decode_invalid_begin_string_resyncs_to_the_next_frame() {
        let mut codec = FixCodec::new();
        let garbage: &[u8] = b"9=FIX.4.4\x0135=0\x0110=000\x01";
        let good = make_fix_message("35=0\x0149=A\x0156=B\x01");
        let mut buf = BytesMut::from(garbage);
        buf.extend_from_slice(&good);
        let total = buf.len();

        assert_eq!(
            codec.decode(&mut buf).err(),
            Some(CodecError::InvalidBeginString)
        );
        // The first "<SOH>8" pair is the SOH ending "10=000" plus the '8' of the
        // following frame, so exactly the garbage is discarded.
        assert_eq!(total - buf.len(), garbage.len());

        let frame = decode_frame(&mut codec, &mut buf);
        assert_eq!(&frame[..], &good[..]);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_decode_invalid_begin_string_without_a_candidate_discards_all_but_a_trailing_soh() {
        let mut codec = FixCodec::new();
        let mut buf = BytesMut::from(&b"garbage without any candidate start\x01"[..]);

        assert_eq!(
            codec.decode(&mut buf).err(),
            Some(CodecError::InvalidBeginString)
        );
        // Only the trailing SOH survives: its '8' partner may still arrive.
        assert_eq!(&buf[..], &[SOH]);
    }

    #[test]
    fn test_decode_invalid_begin_string_with_no_soh_discards_everything() {
        let mut codec = FixCodec::new();
        let mut buf = BytesMut::from(&b"garbage without any delimiter at all"[..]);

        assert_eq!(
            codec.decode(&mut buf).err(),
            Some(CodecError::InvalidBeginString)
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn test_resync_offset_skips_non_candidate_soh_pairs() {
        // The first SOH is followed by '3', not '8'; the second one starts a
        // candidate frame.
        let input: &[u8] = b"junk\x0135=0\x018=FIX.4.4\x01";
        let offset = resync_offset(input);
        assert_eq!(input.get(offset..offset + 2), Some(&b"8="[..]));
    }

    #[test]
    fn test_parse_body_length_rejects_hostile_values() {
        assert_eq!(parse_body_length(b"0"), Some(0));
        assert_eq!(parse_body_length(b"512"), Some(512));
        assert_eq!(parse_body_length(b""), None);
        assert_eq!(parse_body_length(b"-1"), None);
        assert_eq!(parse_body_length(b"1a"), None);
        assert_eq!(parse_body_length(b" 12"), None);
        assert_eq!(parse_body_length(b"99999999999999999999"), None);
    }

    #[test]
    fn test_encode_slice_appends_the_frame() {
        let mut codec = FixCodec::new();
        let msg = b"8=FIX.4.4\x019=5\x0135=0\x0110=123\x01";
        let mut dst = BytesMut::new();

        assert!(matches!(codec.encode(&msg[..], &mut dst), Ok(())));
        assert_eq!(&dst[..], msg);
    }

    #[test]
    fn test_encode_slice_over_the_ceiling_is_message_too_large() {
        let mut codec = FixCodec::new().with_max_message_size(16);
        let msg = [b'X'; 17];
        let mut dst = BytesMut::new();

        assert_eq!(
            codec.encode(&msg[..], &mut dst).err(),
            Some(CodecError::MessageTooLarge {
                size: 17,
                max_size: 16
            })
        );
        assert!(dst.is_empty(), "a rejected frame must not be written");
    }

    #[test]
    fn test_encode_bytes_mut_appends_the_frame() {
        let mut codec = FixCodec::new();
        let msg = BytesMut::from(&b"8=FIX.4.4\x019=5\x0135=0\x0110=123\x01"[..]);
        let mut dst = BytesMut::new();

        assert!(matches!(codec.encode(msg.clone(), &mut dst), Ok(())));
        assert_eq!(&dst[..], &msg[..]);
    }

    #[test]
    fn test_encode_bytes_mut_over_the_ceiling_is_message_too_large() {
        let mut codec = FixCodec::new().with_max_message_size(16);
        let msg = BytesMut::from(&vec![b'X'; 17][..]);
        let mut dst = BytesMut::new();

        assert_eq!(
            codec.encode(msg, &mut dst).err(),
            Some(CodecError::MessageTooLarge {
                size: 17,
                max_size: 16
            })
        );
        assert!(dst.is_empty());
    }

    #[test]
    fn test_encode_at_the_ceiling_is_accepted() {
        let mut codec = FixCodec::new().with_max_message_size(16);
        let msg = [b'X'; 16];
        let mut dst = BytesMut::new();

        assert!(matches!(codec.encode(&msg[..], &mut dst), Ok(())));
        assert_eq!(dst.len(), 16);
    }
}
