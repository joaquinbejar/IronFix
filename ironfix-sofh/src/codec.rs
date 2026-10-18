/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! Tokio codec for SOFH message framing.
//!
//! [`SofhCodec`] is the binary counterpart of `ironfix_transport::FixCodec`.
//! It splits a byte stream into [`SofhFrame`]s by the `Message_Length` of each
//! Simple Open Framing Header, and frames payloads back onto the wire. It
//! never interprets the payload.
//!
//! The codec sits at the untrusted-input boundary: every byte it reads is
//! chosen by the counterparty. Three properties follow, and are enforced here
//! rather than assumed:
//!
//! * **Bounded buffering.** A declared `Message_Length` above
//!   [`SofhCodec::with_max_message_size`] is refused as soon as its six header
//!   bytes are buffered, before anything is reserved. Below the ceiling, the
//!   codec reserves the rest of the declared frame once, so the reservation is
//!   never larger than the ceiling. As with `FixCodec` and `tokio_util`'s
//!   `LengthDelimitedCodec`, that bounds the buffer's length, not its resident
//!   cost: a peer can pin up to the ceiling per connection with a 6-byte
//!   header and then stall. Lower the ceiling if that matters.
//! * **Checked arithmetic.** Every length derived from the header is computed
//!   with `checked_*` or a fallible conversion, so a hostile length errors
//!   instead of wrapping into a plausible one.
//! * **Zero copy on decode.** A frame's payload is split off the read buffer
//!   with `split_to`, sharing its allocation; the header bytes are dropped by
//!   advancing past them.
//!
//! Every [`SofhError`] is fatal for the stream; see that type for why SOFH,
//! unlike tag=value FIX, has nothing to resynchronise on.

use std::fmt;

use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::encoding::EncodingType;
use crate::error::SofhError;
use crate::header::SofhHeader;

/// One framed message: its header and its payload.
///
/// Yielded by [`SofhCodec`]'s decoder, and accepted by its encoder, which
/// writes it back byte for byte. The fields are private so that the header
/// always describes the payload it travels with.
///
/// `Debug` prints the header and the payload *length*, never the payload
/// bytes: a framed message can carry credentials (a tag=value Logon with
/// `Password` (554), a FIXP `Negotiate` with its credentials field).
#[derive(Clone, PartialEq, Eq)]
pub struct SofhFrame {
    /// The header; its `payload_len` equals `payload.len()`.
    header: SofhHeader,
    /// The message bytes, header excluded.
    payload: BytesMut,
}

impl SofhFrame {
    /// Frames `payload` with the given encoding type.
    ///
    /// The codec's size ceiling is not applied here; the encoder applies it.
    ///
    /// # Errors
    /// - [`SofhError::MessageLengthTooSmall`] for an empty payload;
    /// - [`SofhError::PayloadTooLong`] when the payload plus the 6-byte header
    ///   does not fit the 4-octet `Message_Length` field.
    pub fn new(encoding_type: EncodingType, payload: BytesMut) -> Result<Self, SofhError> {
        let header = SofhHeader::for_payload(payload.len(), encoding_type)?;
        Ok(Self { header, payload })
    }

    /// Returns the header.
    #[must_use]
    #[inline]
    pub const fn header(&self) -> SofhHeader {
        self.header
    }

    /// Returns the encoding type of the payload.
    #[must_use]
    #[inline]
    pub const fn encoding_type(&self) -> EncodingType {
        self.header.encoding_type()
    }

    /// Returns the payload, header excluded.
    #[must_use]
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Consumes the frame and returns its payload.
    #[must_use]
    #[inline]
    pub fn into_payload(self) -> BytesMut {
        self.payload
    }

    /// Consumes the frame and returns its header and payload.
    #[must_use]
    #[inline]
    pub fn into_parts(self) -> (SofhHeader, BytesMut) {
        (self.header, self.payload)
    }
}

impl fmt::Debug for SofhFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SofhFrame")
            .field("header", &self.header)
            .field("payload_len", &self.payload.len())
            .finish_non_exhaustive()
    }
}

/// Tokio codec for SOFH framing.
///
/// - `Decoder` yields one [`SofhFrame`] per complete frame, `Ok(None)` while a
///   frame is incomplete, and a [`SofhError`] for a header that cannot frame a
///   legal message. Its `decode_eof` reports a frame cut short by the end of
///   the stream as [`SofhError::Truncated`].
/// - `Encoder<SofhFrame>` writes a frame back byte for byte, and
///   `Encoder<(EncodingType, &[u8])>` frames a borrowed payload.
///
/// The size ceiling applies in both directions: a larger frame is neither
/// buffered on decode nor written on encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SofhCodec {
    /// Largest accepted `Message_Length`, in bytes, header included.
    max_message_size: u32,
}

impl SofhCodec {
    /// Default ceiling on `Message_Length`: 1 MiB (1,048,576 bytes), header
    /// included. The same default as `FixCodec`.
    pub const DEFAULT_MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

    /// Creates a codec with the default ceiling,
    /// [`SofhCodec::DEFAULT_MAX_MESSAGE_SIZE`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_message_size: Self::DEFAULT_MAX_MESSAGE_SIZE,
        }
    }

    /// Sets the largest accepted `Message_Length`, in bytes, header included.
    ///
    /// The parameter is a `u32` because `Message_Length` is a 4-octet field: a
    /// ceiling above `u32::MAX` would be meaningless. A ceiling below
    /// [`SofhHeader::MIN_MESSAGE_LENGTH`] (7 bytes) refuses every frame.
    #[must_use]
    pub const fn with_max_message_size(mut self, size: u32) -> Self {
        self.max_message_size = size;
        self
    }

    /// Returns the largest accepted `Message_Length`, in bytes, header
    /// included.
    #[must_use]
    pub const fn max_message_size(&self) -> u32 {
        self.max_message_size
    }

    /// Returns the frame length a header declares, once it passes the
    /// ceiling.
    ///
    /// # Errors
    /// [`SofhError::MessageTooLarge`] when the declared length is above the
    /// ceiling, or does not fit `usize` on this target (only possible where
    /// `usize` is narrower than 32 bits).
    fn frame_len(&self, header: SofhHeader) -> Result<usize, SofhError> {
        let size = header.message_length();
        if size <= self.max_message_size
            && let Ok(frame_len) = usize::try_from(size)
        {
            return Ok(frame_len);
        }
        Err(SofhError::MessageTooLarge {
            size,
            max_size: self.max_message_size,
        })
    }

    /// Appends `header` then `payload` to `dst`, or nothing on error.
    ///
    /// `header` is known to describe `payload`.
    ///
    /// # Errors
    /// [`SofhError::MessageTooLarge`] when the frame is above the ceiling;
    /// [`SofhError::PayloadTooLong`] in the unreachable case that the frame
    /// length does not fit `usize`.
    fn put_frame(
        &self,
        header: SofhHeader,
        payload: &[u8],
        dst: &mut BytesMut,
    ) -> Result<(), SofhError> {
        self.frame_len(header)?;
        let additional =
            payload
                .len()
                .checked_add(SofhHeader::LEN)
                .ok_or(SofhError::PayloadTooLong {
                    payload_len: payload.len(),
                })?;
        dst.reserve(additional);
        dst.put_slice(&header.to_bytes());
        dst.put_slice(payload);
        Ok(())
    }
}

impl Default for SofhCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for SofhCodec {
    type Item = SofhFrame;
    type Error = SofhError;

    /// Extracts one complete frame from `src`.
    ///
    /// Returns `Ok(None)` while fewer than six bytes, or fewer than the
    /// declared `Message_Length`, are buffered; in the second case the rest of
    /// the frame is reserved in `src` (at most the ceiling). A complete frame
    /// is split off the front of `src` without copying.
    ///
    /// # Errors
    /// [`SofhError::MessageLengthTooSmall`] or [`SofhError::MessageTooLarge`]
    /// for a header that cannot frame a legal message. Nothing is consumed:
    /// the error is fatal for the stream.
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(header) = SofhHeader::decode(src)? else {
            return Ok(None);
        };
        let frame_len = self.frame_len(header)?;

        match frame_len.checked_sub(src.len()) {
            Some(0) | None => {}
            Some(missing) => {
                src.reserve(missing);
                return Ok(None);
            }
        }

        // Both offsets are in bounds: the match above returned unless
        // `frame_len <= src.len()`, and `frame_len >= MIN_MESSAGE_LENGTH`
        // (7) is greater than the 6 header bytes skipped.
        let mut payload = src.split_to(frame_len);
        payload.advance(SofhHeader::LEN);
        Ok(Some(SofhFrame { header, payload }))
    }

    /// Extracts the last frames at the end of the stream.
    ///
    /// # Errors
    /// [`SofhError::Truncated`] when the stream ends inside a frame (bytes are
    /// buffered but do not complete one), plus every error of
    /// [`Decoder::decode`].
    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if let Some(frame) = self.decode(src)? {
            return Ok(Some(frame));
        }
        if src.is_empty() {
            return Ok(None);
        }
        // `decode` returned Ok(None) on a non-empty buffer: either the header
        // is incomplete, or it is valid and the frame is not.
        let expected = match SofhHeader::decode(src)? {
            Some(header) => self.frame_len(header)?,
            None => SofhHeader::LEN,
        };
        Err(SofhError::Truncated {
            received: src.len(),
            expected,
        })
    }
}

impl Encoder<SofhFrame> for SofhCodec {
    type Error = SofhError;

    /// Appends the frame to `dst`, header then payload, exactly as it would
    /// have arrived on the wire.
    ///
    /// # Errors
    /// [`SofhError::MessageTooLarge`] when the frame is above the ceiling, so
    /// the codec never sends a frame it would refuse to receive. Nothing is
    /// written on error.
    fn encode(&mut self, item: SofhFrame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.put_frame(item.header, &item.payload, dst)
    }
}

impl<'a> Encoder<(EncodingType, &'a [u8])> for SofhCodec {
    type Error = SofhError;

    /// Frames a borrowed payload with the given encoding type and appends the
    /// frame to `dst`.
    ///
    /// # Errors
    /// - [`SofhError::MessageLengthTooSmall`] for an empty payload;
    /// - [`SofhError::PayloadTooLong`] when the payload cannot fit the
    ///   4-octet `Message_Length` field;
    /// - [`SofhError::MessageTooLarge`] when the frame is above the ceiling.
    ///
    /// Nothing is written on error.
    fn encode(
        &mut self,
        (encoding_type, payload): (EncodingType, &'a [u8]),
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        let header = SofhHeader::for_payload(payload.len(), encoding_type)?;
        self.put_frame(header, payload, dst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a frame by hand, independently of the encoder: big-endian
    /// length (header included), big-endian encoding type, payload.
    fn wire(encoding: u16, payload: &[u8]) -> Vec<u8> {
        let Some(length) = u32::try_from(payload.len())
            .ok()
            .and_then(|len| len.checked_add(6))
        else {
            panic!("fixture payload fits a frame");
        };
        let mut out = Vec::with_capacity(payload.len() + 6);
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&encoding.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// Builds a header with an arbitrary declared length, valid or not.
    fn raw_header(length: u32, encoding: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(6);
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&encoding.to_be_bytes());
        out
    }

    /// A frame's observable content: encoding type, declared length, payload.
    type Seen = (u16, u32, Vec<u8>);

    fn seen(frame: &SofhFrame) -> Seen {
        (
            frame.encoding_type().to_u16(),
            frame.header().message_length(),
            frame.payload().to_vec(),
        )
    }

    /// Drains every complete frame from `buf`, failing on any error.
    fn drain(codec: &mut SofhCodec, buf: &mut BytesMut, out: &mut Vec<Seen>) {
        loop {
            match codec.decode(buf) {
                Ok(Some(frame)) => out.push(seen(&frame)),
                Ok(None) => return,
                Err(error) => panic!("unexpected framing error: {error}"),
            }
        }
    }

    /// Decodes `bytes` delivered as consecutive reads cut at `cuts`.
    fn decode_in_reads(bytes: &[u8], cuts: &[usize]) -> (Vec<Seen>, usize) {
        let mut codec = SofhCodec::new();
        let mut buf = BytesMut::new();
        let mut out = Vec::new();
        let mut start = 0;
        for &cut in cuts.iter().chain(std::iter::once(&bytes.len())) {
            let Some(chunk) = bytes.get(start..cut) else {
                panic!("cut {start}..{cut} is inside the input");
            };
            buf.extend_from_slice(chunk);
            drain(&mut codec, &mut buf, &mut out);
            start = cut;
        }
        (out, buf.len())
    }

    /// Three frames of different encodings and sizes, back to back.
    fn three_frames() -> Vec<u8> {
        let mut bytes = wire(0xEB50, b"first sbe message");
        bytes.extend_from_slice(&wire(0xF000, b"8=FIX.4.4\x019=5\x0135=0\x0110=000\x01"));
        bytes.extend_from_slice(&wire(0x0000, b"!"));
        bytes
    }

    fn decode_one(codec: &mut SofhCodec, buf: &mut BytesMut) -> SofhFrame {
        match codec.decode(buf) {
            Ok(Some(frame)) => frame,
            other => panic!("expected a complete frame, got {other:?}"),
        }
    }

    fn frame(encoding_type: EncodingType, payload: &[u8]) -> SofhFrame {
        match SofhFrame::new(encoding_type, BytesMut::from(payload)) {
            Ok(frame) => frame,
            Err(error) => panic!("fixture frame is valid: {error}"),
        }
    }

    // ----- decode: happy path -------------------------------------------------

    #[test]
    fn test_decode_single_frame_yields_header_and_payload() {
        let mut codec = SofhCodec::new();
        let mut buf = BytesMut::from(&wire(0x5BE0, b"payload")[..]);

        let frame = decode_one(&mut codec, &mut buf);
        assert_eq!(frame.encoding_type(), EncodingType::SbeV1BigEndian);
        assert_eq!(frame.header().message_length(), 13);
        assert_eq!(frame.header().payload_len(), 7);
        assert_eq!(frame.payload(), b"payload");
        assert!(buf.is_empty());
    }

    #[test]
    fn test_decode_payload_is_split_from_the_read_buffer_without_copying() {
        let mut codec = SofhCodec::new();
        let mut buf = BytesMut::from(&wire(0xEB50, b"zero copy")[..]);
        let Some(expected) = buf.get(SofhHeader::LEN..).map(<[u8]>::as_ptr) else {
            panic!("frame has a payload");
        };

        let frame = decode_one(&mut codec, &mut buf);
        assert!(std::ptr::eq(frame.payload().as_ptr(), expected));
    }

    #[test]
    fn test_decode_minimum_frame_of_one_payload_byte() {
        let mut codec = SofhCodec::new();
        let mut buf = BytesMut::from(&[0, 0, 0, 7, 0xF5, 0x00, b'x'][..]);

        let frame = decode_one(&mut codec, &mut buf);
        assert_eq!(frame.encoding_type(), EncodingType::Json);
        assert_eq!(frame.payload(), b"x");
    }

    #[test]
    fn test_decode_back_to_back_frames_in_one_read() {
        let bytes = three_frames();
        let (frames, left) = decode_in_reads(&bytes, &[]);
        assert_eq!(left, 0);
        assert_eq!(frames.len(), 3);
        assert_eq!(
            frames.first().map(|f| f.2.as_slice()),
            Some(&b"first sbe message"[..])
        );
        assert_eq!(frames.get(2).map(|f| (f.0, f.1)), Some((0x0000, 7)));
    }

    #[test]
    fn test_decode_every_split_point_matches_one_read() {
        let bytes = three_frames();
        let (whole, _) = decode_in_reads(&bytes, &[]);
        for cut in 0..=bytes.len() {
            let (split, left) = decode_in_reads(&bytes, &[cut]);
            assert_eq!(split, whole, "split at {cut}");
            assert_eq!(left, 0, "split at {cut}");
        }
    }

    #[test]
    fn test_decode_every_pair_of_split_points_matches_one_read() {
        let bytes = three_frames();
        let (whole, _) = decode_in_reads(&bytes, &[]);
        for first in 0..=bytes.len() {
            for second in first..=bytes.len() {
                let (split, left) = decode_in_reads(&bytes, &[first, second]);
                assert_eq!(split, whole, "splits at {first} and {second}");
                assert_eq!(left, 0, "splits at {first} and {second}");
            }
        }
    }

    #[test]
    fn test_decode_byte_by_byte_matches_one_read() {
        let bytes = three_frames();
        let (whole, _) = decode_in_reads(&bytes, &[]);
        let cuts: Vec<usize> = (1..bytes.len()).collect();
        let (split, left) = decode_in_reads(&bytes, &cuts);
        assert_eq!(split, whole);
        assert_eq!(left, 0);
    }

    #[test]
    fn test_decode_unregistered_encoding_types_are_preserved() {
        for encoding in [0x0000, 0x5BE1, 0xEB51, 0xFA00, 0xFFFF] {
            let bytes = wire(encoding, b"opaque");
            let mut codec = SofhCodec::new();
            let mut buf = BytesMut::from(&bytes[..]);

            let decoded = decode_one(&mut codec, &mut buf);
            assert!(matches!(
                decoded.encoding_type(),
                EncodingType::Unregistered(raw) if raw.value() == encoding
            ));

            let mut out = BytesMut::new();
            assert_eq!(codec.encode(decoded, &mut out), Ok(()));
            assert_eq!(&out[..], &bytes[..], "{encoding:#06X}");
        }
    }

    // ----- decode: incomplete input -------------------------------------------

    #[test]
    fn test_decode_truncated_header_is_none_and_consumes_nothing() {
        let bytes = wire(0xEB50, b"abc");
        for available in 0..SofhHeader::LEN {
            let Some(prefix) = bytes.get(..available) else {
                panic!("prefix is inside the frame");
            };
            let mut codec = SofhCodec::new();
            let mut buf = BytesMut::from(prefix);
            assert_eq!(codec.decode(&mut buf), Ok(None), "{available} bytes");
            assert_eq!(buf.len(), available);
        }
    }

    #[test]
    fn test_decode_truncated_body_is_none_and_reserves_the_rest_of_the_frame() {
        let payload = vec![0xAB; 4_000];
        let bytes = wire(0x5BE0, &payload);
        let Some(head) = bytes.get(..10) else {
            panic!("prefix is inside the frame");
        };
        let mut codec = SofhCodec::new();
        let mut buf = BytesMut::from(head);

        assert_eq!(codec.decode(&mut buf), Ok(None));
        assert_eq!(buf.len(), 10, "nothing consumed");
        assert!(
            buf.capacity() >= bytes.len(),
            "the rest of the frame is reserved"
        );
    }

    #[test]
    fn test_decode_reservation_is_bounded_by_the_ceiling() {
        let ceiling: u32 = 64 * 1024;
        let mut codec = SofhCodec::new().with_max_message_size(ceiling);

        // A header declaring exactly the ceiling reserves up to it, not more
        // than the allocator's rounding of it.
        let mut buf = BytesMut::from(&raw_header(ceiling, 0xEB50)[..]);
        assert_eq!(codec.decode(&mut buf), Ok(None));
        let Ok(ceiling_bytes) = usize::try_from(ceiling) else {
            panic!("the ceiling fits usize");
        };
        assert!(buf.capacity() >= ceiling_bytes);
        assert!(buf.capacity() < 2 * ceiling_bytes);

        // A header declaring the whole 4-octet range is refused before any
        // reservation: the capacity does not grow.
        let mut buf = BytesMut::from(&raw_header(u32::MAX, 0xEB50)[..]);
        let before = buf.capacity();
        assert_eq!(
            codec.decode(&mut buf),
            Err(SofhError::MessageTooLarge {
                size: u32::MAX,
                max_size: ceiling,
            })
        );
        assert_eq!(buf.capacity(), before);
    }

    // ----- decode: malformed input --------------------------------------------

    #[test]
    fn test_decode_length_below_minimum_is_an_error_for_every_value() {
        for length in 0..SofhHeader::MIN_MESSAGE_LENGTH {
            let mut bytes = raw_header(length, 0xEB50);
            bytes.extend_from_slice(b"trailing payload bytes");
            let mut codec = SofhCodec::new();
            let mut buf = BytesMut::from(&bytes[..]);
            let expected = Err(SofhError::MessageLengthTooSmall {
                length,
                min_length: 7,
            });

            assert_eq!(codec.decode(&mut buf), expected, "length {length}");
            assert_eq!(buf.len(), bytes.len(), "nothing consumed");
            // Fatal and deterministic: the same bytes give the same error.
            assert_eq!(codec.decode(&mut buf), expected, "length {length}");
        }
    }

    #[test]
    fn test_decode_length_above_default_ceiling_is_an_error() {
        for length in [SofhCodec::DEFAULT_MAX_MESSAGE_SIZE + 1, u32::MAX] {
            let mut codec = SofhCodec::new();
            let mut buf = BytesMut::from(&raw_header(length, 0x5BE0)[..]);
            assert_eq!(
                codec.decode(&mut buf),
                Err(SofhError::MessageTooLarge {
                    size: length,
                    max_size: 1_048_576,
                })
            );
            assert_eq!(buf.len(), SofhHeader::LEN, "nothing consumed");
        }
    }

    #[test]
    fn test_decode_custom_ceiling_accepts_at_and_refuses_above() {
        let mut codec = SofhCodec::new().with_max_message_size(16);

        let mut at = BytesMut::from(&wire(0xA500, b"0123456789")[..]);
        assert_eq!(decode_one(&mut codec, &mut at).payload(), b"0123456789");

        let mut above = BytesMut::from(&wire(0xA500, b"0123456789A")[..]);
        assert_eq!(
            codec.decode(&mut above),
            Err(SofhError::MessageTooLarge {
                size: 17,
                max_size: 16,
            })
        );
    }

    #[test]
    fn test_decode_ceiling_below_minimum_refuses_every_frame() {
        let mut codec = SofhCodec::new().with_max_message_size(6);
        let mut buf = BytesMut::from(&wire(0xF000, b"x")[..]);
        assert_eq!(
            codec.decode(&mut buf),
            Err(SofhError::MessageTooLarge {
                size: 7,
                max_size: 6,
            })
        );
    }

    #[test]
    fn test_decode_good_frames_before_a_bad_header_are_returned_first() {
        let mut bytes = wire(0xEB50, b"good");
        bytes.extend_from_slice(&raw_header(2, 0xEB50));
        let mut codec = SofhCodec::new();
        let mut buf = BytesMut::from(&bytes[..]);

        assert_eq!(decode_one(&mut codec, &mut buf).payload(), b"good");
        assert_eq!(
            codec.decode(&mut buf),
            Err(SofhError::MessageLengthTooSmall {
                length: 2,
                min_length: 7,
            })
        );
    }

    // ----- decode_eof -----------------------------------------------------------

    #[test]
    fn test_decode_eof_empty_buffer_is_none() {
        let mut codec = SofhCodec::new();
        let mut buf = BytesMut::new();
        assert_eq!(codec.decode_eof(&mut buf), Ok(None));
    }

    #[test]
    fn test_decode_eof_returns_the_last_complete_frames() {
        let mut codec = SofhCodec::new();
        let mut buf = BytesMut::from(&three_frames()[..]);
        let mut count = 0;
        loop {
            match codec.decode_eof(&mut buf) {
                Ok(Some(_)) => count += 1,
                Ok(None) => break,
                Err(error) => panic!("unexpected error at end of stream: {error}"),
            }
        }
        assert_eq!(count, 3);
    }

    #[test]
    fn test_decode_eof_inside_the_header_is_truncated() {
        let mut codec = SofhCodec::new();
        let mut buf = BytesMut::from(&[0x00, 0x00, 0x01][..]);
        assert_eq!(
            codec.decode_eof(&mut buf),
            Err(SofhError::Truncated {
                received: 3,
                expected: 6,
            })
        );
    }

    #[test]
    fn test_decode_eof_inside_the_payload_is_truncated() {
        let bytes = wire(0x5BE0, b"cut short");
        let Some(head) = bytes.get(..9) else {
            panic!("prefix is inside the frame");
        };
        let mut codec = SofhCodec::new();
        let mut buf = BytesMut::from(head);
        assert_eq!(
            codec.decode_eof(&mut buf),
            Err(SofhError::Truncated {
                received: 9,
                expected: 15,
            })
        );
    }

    #[test]
    fn test_decode_eof_bad_header_reports_the_header_error() {
        let mut codec = SofhCodec::new();
        let mut buf = BytesMut::from(&raw_header(1, 0x5BE0)[..]);
        assert_eq!(
            codec.decode_eof(&mut buf),
            Err(SofhError::MessageLengthTooSmall {
                length: 1,
                min_length: 7,
            })
        );
    }

    // ----- encode ---------------------------------------------------------------

    #[test]
    fn test_encode_borrowed_payload_writes_header_then_payload() {
        let mut codec = SofhCodec::new();
        let mut dst = BytesMut::new();
        assert_eq!(
            codec.encode((EncodingType::SbeV1LittleEndian, &b"hello"[..]), &mut dst),
            Ok(())
        );
        assert_eq!(&dst[..], &wire(0xEB50, b"hello")[..]);
    }

    #[test]
    fn test_encode_appends_after_existing_bytes() {
        let mut codec = SofhCodec::new();
        let mut dst = BytesMut::from(&b"already here"[..]);
        assert_eq!(
            codec.encode(frame(EncodingType::GpbV1, b"next"), &mut dst),
            Ok(())
        );

        let mut expected = b"already here".to_vec();
        expected.extend_from_slice(&wire(0x4700, b"next"));
        assert_eq!(&dst[..], &expected[..]);
    }

    #[test]
    fn test_encode_then_decode_round_trips() {
        let encodings = [
            EncodingType::SbeV1BigEndian,
            EncodingType::SbeV1LittleEndian,
            EncodingType::TagValue,
            EncodingType::from_u16(0x0042),
            EncodingType::from_u16(0xFA03),
            EncodingType::from_u16(0x5BE1),
        ];
        let sizes = [1usize, 2, 255, 256, 65_535, 65_536 + 3];
        let mut codec = SofhCodec::new();
        for encoding in encodings {
            for size in sizes {
                let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
                let mut wire_bytes = BytesMut::new();
                assert_eq!(
                    codec.encode((encoding, &payload[..]), &mut wire_bytes),
                    Ok(())
                );
                assert_eq!(wire_bytes.len(), size + 6);

                let decoded = decode_one(&mut codec, &mut wire_bytes);
                assert_eq!(decoded.encoding_type(), encoding);
                assert_eq!(decoded.payload(), &payload[..]);
                assert!(wire_bytes.is_empty());
            }
        }
    }

    #[test]
    fn test_encode_decoded_frame_reproduces_the_wire_bytes() {
        let bytes = three_frames();
        let mut codec = SofhCodec::new();
        let mut buf = BytesMut::from(&bytes[..]);
        let mut relayed = BytesMut::new();
        while let Ok(Some(frame)) = codec.decode(&mut buf) {
            assert_eq!(codec.encode(frame, &mut relayed), Ok(()));
        }
        assert_eq!(&relayed[..], &bytes[..]);
    }

    #[test]
    fn test_encode_empty_payload_is_refused_and_writes_nothing() {
        let mut codec = SofhCodec::new();
        let mut dst = BytesMut::from(&b"prefix"[..]);
        assert_eq!(
            codec.encode((EncodingType::TagValue, &b""[..]), &mut dst),
            Err(SofhError::MessageLengthTooSmall {
                length: 6,
                min_length: 7,
            })
        );
        assert_eq!(&dst[..], b"prefix");
    }

    #[test]
    fn test_encode_payload_over_ceiling_is_refused_and_writes_nothing() {
        let mut codec = SofhCodec::new().with_max_message_size(10);
        let mut dst = BytesMut::new();
        assert_eq!(
            codec.encode((EncodingType::Json, &b"12345"[..]), &mut dst),
            Err(SofhError::MessageTooLarge {
                size: 11,
                max_size: 10,
            })
        );
        assert!(dst.is_empty());

        // A frame built outside the codec meets the same ceiling.
        assert_eq!(
            codec.encode(frame(EncodingType::Json, b"12345"), &mut dst),
            Err(SofhError::MessageTooLarge {
                size: 11,
                max_size: 10,
            })
        );
        assert!(dst.is_empty());

        // At the ceiling it is written.
        assert_eq!(
            codec.encode((EncodingType::Json, &b"1234"[..]), &mut dst),
            Ok(())
        );
        assert_eq!(dst.len(), 10);
    }

    // ----- SofhFrame and configuration ------------------------------------------

    #[test]
    fn test_sofh_frame_new_rejects_an_empty_payload() {
        assert_eq!(
            SofhFrame::new(EncodingType::Bson, BytesMut::new()),
            Err(SofhError::MessageLengthTooSmall {
                length: 6,
                min_length: 7,
            })
        );
    }

    #[test]
    fn test_sofh_frame_into_parts_returns_header_and_payload() {
        let (header, payload) = frame(EncodingType::Asn1OerV1, b"parts").into_parts();
        assert_eq!(header.encoding_type(), EncodingType::Asn1OerV1);
        assert_eq!(header.message_length(), 11);
        assert_eq!(&payload[..], b"parts");
        assert_eq!(
            &frame(EncodingType::Asn1OerV1, b"own").into_payload()[..],
            b"own"
        );
    }

    #[test]
    fn test_sofh_frame_debug_never_prints_the_payload() {
        let secret = frame(EncodingType::TagValue, b"35=A\x01554=hunter2\x01");
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("payload_len: 17"), "{rendered}");
    }

    #[test]
    fn test_codec_default_ceiling_is_one_mebibyte() {
        assert_eq!(SofhCodec::new().max_message_size(), 1_048_576);
        assert_eq!(SofhCodec::default(), SofhCodec::new());
        assert_eq!(
            SofhCodec::new()
                .with_max_message_size(4096)
                .max_message_size(),
            4096
        );
    }
}
