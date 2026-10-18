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
//!
//! # Garbled-frame recovery
//!
//! FIX ignores a garbled message rather than ending the session over it, but
//! `tokio_util::Framed` ends its stream after the first decoder error. The two
//! are reconciled by [`FixCodec::with_garbled_recovery`]: with it enabled, a
//! [recoverable](CodecError::is_recoverable) framing error is skipped *inside*
//! [`Decoder::decode`], which then goes on to return the next valid frame if
//! one is already buffered, and the skip is counted for
//! [`FixCodec::take_garbled_count`]. Only a fatal error (an oversized frame, an
//! I/O error) is still returned. Recovery is off by default, so a caller that
//! does not ask for it keeps the error-per-garbled-frame contract. See
//! `doc/adr/0004-garbled-frame-recovery.md` for the design.

use bytes::{Buf, BufMut, BytesMut};
use ironfix_tagvalue::checksum::{calculate_checksum, parse_checksum};
use memchr::memchr;
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

/// Errors that can occur during codec operations.
///
/// # Recoverable and fatal errors
///
/// [`CodecError::is_recoverable`] splits the variants in two. A *recoverable*
/// error describes garbled input, a frame whose BeginString, BodyLength or
/// CheckSum cannot be trusted, which FIX says to ignore. A *fatal* error is a
/// condition the stream cannot continue past: an I/O failure, or a frame whose
/// declared size exceeds [`FixCodec::with_max_message_size`] (skipping it would
/// mean either buffering it or trusting its attacker-chosen length to size the
/// discard, and the ceiling exists to refuse both).
///
/// # Effect on the read buffer
///
/// [`Decoder::decode`] consumes bytes on the recoverable paths so that a caller
/// that keeps reading is not stuck re-parsing the same garbage. *Resync* means:
/// discard up to the next candidate frame start, so the buffer restarts there.
/// Without recovery a candidate is the `8` of a `<SOH>8` pair. With
/// [`FixCodec::with_garbled_recovery`] it is a complete header opening
/// (`8=<BeginString><SOH>9=`) after a plausible boundary (see that method for
/// why). When there is no candidate the whole buffer is discarded, except a
/// tail that may still become one: a trailing `<SOH>` without recovery, a
/// partial header opening with it.
///
/// | Variant | Recoverable | Bytes consumed |
/// |---|---|---|
/// | [`Self::InvalidBeginString`] | yes | resync |
/// | [`Self::InvalidTrailer`] | yes | resync: BodyLength is not corroborated by anything, so the length it declares is not trusted to bound the discard |
/// | [`Self::InvalidChecksumFormat`], [`Self::ChecksumMismatch`] | yes | the whole declared frame: the trailer literal is exactly where BodyLength said, so the boundary is corroborated |
/// | [`Self::MissingBodyLength`], [`Self::InvalidBodyLength`], [`Self::HeaderTooLong`] | yes | none without recovery (the frame boundary is unknown); resync with it |
/// | [`Self::MessageTooLarge`], [`Self::Io`] | no | none |
///
/// Without recovery, the consumption above is observable only by a caller that
/// drives [`Decoder::decode`] itself: `tokio_util::Framed` terminates its stream
/// after any decoder error. With recovery, recoverable errors are never
/// returned at all; they are skipped and counted.
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

impl CodecError {
    /// Returns whether this error describes garbled input that can be skipped.
    ///
    /// `true` for every framing error FIX classes as a garbled message: a
    /// BeginString (8) that is not first, a BodyLength (9) that is missing,
    /// malformed or disagrees with the frame layout, a header that never
    /// completes, and a CheckSum (10) that is absent, malformed or wrong. Such
    /// a frame is ignored and the stream continues; its `MsgSeqNum` (34) is
    /// not consumed, because it cannot be trusted.
    ///
    /// `false` for the conditions the stream cannot continue past:
    /// [`Self::Io`], and [`Self::MessageTooLarge`] (a frame above the
    /// configured ceiling is refused rather than buffered or skipped by its
    /// declared length). The deprecated, never-emitted [`Self::Incomplete`] is
    /// also `false`: incomplete input is `Ok(None)`, not garbling.
    ///
    /// This is the classification [`FixCodec::with_garbled_recovery`] acts on.
    #[must_use]
    #[allow(deprecated)] // `Incomplete` is matched so the classification stays exhaustive.
    pub const fn is_recoverable(&self) -> bool {
        match self {
            Self::InvalidBeginString
            | Self::MissingBodyLength
            | Self::InvalidBodyLength
            | Self::HeaderTooLong { .. }
            | Self::InvalidTrailer { .. }
            | Self::InvalidChecksumFormat
            | Self::ChecksumMismatch { .. } => true,
            Self::Incomplete | Self::MessageTooLarge { .. } | Self::Io(_) => false,
        }
    }
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

/// The header openings recovery mode accepts as a frame start.
///
/// `8=`, a BeginString of the FIX family (`FIX.4.0` to `FIX.4.4`, and
/// `FIXT.1.1` for every 5.0 session), SOH, then the `9=` that must follow. A
/// resync only lands on one of these exact openings; see
/// [`recovery_resync_offset`]. [`FixCodec::with_begin_string`] narrows the set
/// to the one opening of the session's own version.
///
/// A `static` rather than a `const`, so a codec can hold a `'static` sub-slice
/// of it.
static RECOVERY_ANCHORS: [&[u8]; 6] = [
    b"8=FIX.4.0\x019=",
    b"8=FIX.4.1\x019=",
    b"8=FIX.4.2\x019=",
    b"8=FIX.4.3\x019=",
    b"8=FIX.4.4\x019=",
    b"8=FIXT.1.1\x019=",
];

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
/// [`recovery_resync_offset`] closes that gap for recovery mode.
///
/// The returned offset never exceeds `src.len()`, and the scan stops at the
/// first candidate, so its cost is linear in the bytes it discards.
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

/// How the bytes at a candidate frame start compare with [`RECOVERY_ANCHORS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnchorShape {
    /// The bytes open with one of the accepted headers.
    Complete,
    /// The buffer ends inside what could still become an accepted header.
    Partial,
    /// The bytes cannot open an accepted header.
    Rejected,
}

/// Classifies `rest`, which starts at a candidate `8`, against every accepted
/// header opening in `anchors`. At most a dozen bytes are compared per
/// opening, and a mismatch is normally found within the first two.
#[must_use]
fn anchor_shape(rest: &[u8], anchors: &[&[u8]]) -> AnchorShape {
    let mut shape = AnchorShape::Rejected;
    for &anchor in anchors {
        if rest.starts_with(anchor) {
            return AnchorShape::Complete;
        }
        if rest.len() < anchor.len() && anchor.starts_with(rest) {
            shape = AnchorShape::Partial;
        }
    }
    shape
}

/// Returns whether a frame may start right after `prev`, the byte before a
/// candidate `8` (`None` at the start of the buffer).
///
/// A frame follows an SOH, or garbage. It never follows an ASCII digit or `=`:
/// that `8` is part of a tag (`448=`, `18=`) or the first byte of a field value
/// (`96=8=FIX…`, `213=8=FIX…`). Only those two positions are excluded: an
/// opening further inside a value, after a space, `|`, `MSG:` or `<![CDATA[`,
/// passes this check (see [`recovery_resync_offset`] for the residual risk).
#[must_use]
const fn boundary_before(prev: Option<u8>) -> bool {
    match prev {
        None => true,
        Some(byte) => !byte.is_ascii_digit() && byte != b'=',
    }
}

/// Recovery-mode counterpart of [`resync_offset`]: returns how many bytes to
/// discard so the buffer restarts at the next candidate frame.
///
/// A candidate is an `8` at offset 1 or later that passes two checks before it
/// is returned. The byte before it must be a plausible frame boundary (see
/// [`boundary_before`]), and the bytes from it must open a real header: `8=`, an
/// accepted BeginString, SOH, `9=` (`anchors`, a subset of
/// [`RECOVERY_ANCHORS`]). Checking the shape here, rather than letting the
/// decoder find out, means a false start such as a tag `851=` after an SOH,
/// `58=8=FIX`, or `448=FIX.4.4` costs about a dozen byte comparisons and is
/// never counted as a garbled frame. The boundary check keeps a complete frame
/// embedded at the very start of a data field value (`96=8=FIX…`, `213=8=FIX…`)
/// of a garbled outer frame from being resynchronised onto and handed up as a
/// phantom inbound message.
///
/// Residual risk: a data field value that carries a complete header opening
/// of an accepted BeginString after any byte other than an ASCII digit or `=`
/// (a space, `|`, `MSG:`, `<![CDATA[`, an SOH) inside a frame that is already
/// garbled badly enough to be resynchronised through. That opening is a
/// candidate, and if a well-formed frame follows it, it is handed up.
/// Restricting `anchors` to the session's own BeginString
/// ([`FixCodec::with_begin_string`]) narrows this to embedded frames of the
/// same version.
///
/// The anchor is also what lets a well-formed frame that arrives straight
/// after garbage survive: its opening follows the garbage, not an SOH, which
/// [`resync_offset`] would miss. What it cannot see is a frame whose preceding
/// byte is an ASCII digit or `=`, for example after garbage that ends in a
/// digit; that frame is skipped and its gap recovered like any other.
///
/// Offset 0 is never a candidate (it is the frame that just failed), so the
/// result is at least 1 for any buffer of two or more bytes, which is what
/// guarantees that recovery makes progress. When there is no candidate the
/// whole buffer is garbage, except a tail that is a partial header opening the
/// next read may complete. Unlike [`resync_offset`], a lone trailing SOH is not
/// kept: it would only make the next read's frame start look garbled and count
/// the same garbage twice.
///
/// One forward pass that stops at the first candidate, so the cost is linear
/// in the bytes discarded; the result never exceeds `src.len()`.
#[must_use]
fn recovery_resync_offset(src: &[u8], anchors: &[&[u8]]) -> usize {
    let mut from = 1usize;
    while let Some(relative) = src.get(from..).and_then(|rest| memchr(b'8', rest)) {
        let Some(candidate) = from.checked_add(relative) else {
            return src.len();
        };
        let prev = candidate
            .checked_sub(1)
            .and_then(|index| src.get(index))
            .copied();
        if boundary_before(prev) {
            let shape = src
                .get(candidate..)
                .map_or(AnchorShape::Rejected, |rest| anchor_shape(rest, anchors));
            if shape != AnchorShape::Rejected {
                return candidate;
            }
        }
        let Some(next) = candidate.checked_add(1) else {
            return src.len();
        };
        from = next;
    }
    src.len()
}

/// Where a frame's body ends and the frame itself ends, as implied by its
/// header.
#[derive(Debug, Clone, Copy)]
struct FrameLayout {
    /// Offset of the CheckSum field: everything before it is covered by the
    /// checksum.
    body_end: usize,
    /// Length of the whole frame, trailer included.
    total_length: usize,
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
    /// Whether recoverable framing errors are skipped instead of returned.
    garbled_recovery: bool,
    /// Garbled frames skipped since the last [`FixCodec::take_garbled_count`].
    garbled_count: u64,
    /// The header openings a recovery-mode resync may land on: all of
    /// [`RECOVERY_ANCHORS`] by default, or the session's own one.
    recovery_anchors: &'static [&'static [u8]],
    /// What the last recovery-mode resync left for the next read to settle,
    /// so its checks hold across a read boundary. Settled once the start of
    /// the buffer is judged a frame start, and whenever a frame is returned.
    resync_state: ResyncState,
}

/// What a recovery-mode resync left behind for the next read to settle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResyncState {
    /// Nothing pending: the buffer starts where a frame may start.
    Settled,
    /// The resync emptied the buffer, and this was the last byte it
    /// discarded. Whatever the next read starts with follows that byte.
    EmptiedAfter(u8),
    /// The resync stopped on a partial header opening at the end of the
    /// buffer. Its preceding byte passed the boundary check, but the opening
    /// itself can only be validated once the next read completes it.
    PartialOpening,
}

/// What judging the start of the buffer against a [`ResyncState`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpanVerdict {
    /// The buffer starts where a frame may start: frame it normally.
    Proceed,
    /// Not enough bytes to decide: ask for more, keep the state.
    NeedMore,
    /// The start belonged to the same garbled span and was resynchronised
    /// past (consuming at least one byte, not counted): judge again.
    Resynced,
}

impl FixCodec {
    /// Creates a new codec with default settings.
    ///
    /// Defaults: a 1 MiB maximum message size, checksum validation enabled,
    /// garbled-frame recovery disabled, and, should recovery be enabled, every
    /// FIX-family BeginString accepted as a resync anchor.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_message_size: 1024 * 1024, // 1MB
            validate_checksum: true,
            garbled_recovery: false,
            garbled_count: 0,
            recovery_anchors: &RECOVERY_ANCHORS,
            resync_state: ResyncState::Settled,
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

    /// Sets whether garbled frames are skipped instead of reported.
    ///
    /// Off (the default), every malformed frame is an `Err` from
    /// [`Decoder::decode`], and a `tokio_util::Framed` stream ends at the
    /// first one.
    ///
    /// On, a [recoverable](CodecError::is_recoverable) error is never returned:
    /// the codec discards the garbled bytes, counts the skip (see
    /// [`FixCodec::take_garbled_count`]), and carries on in the **same** call,
    /// returning the next valid frame if it is already buffered and `Ok(None)`
    /// only when it genuinely needs more bytes. Returning `Ok(None)` with a
    /// whole frame buffered would stall `Framed`, which polls the decoder again
    /// only after the next read. [`CodecError::MessageTooLarge`] and
    /// [`CodecError::Io`] are still returned.
    ///
    /// Recovery changes three framing details, all on error paths:
    ///
    /// - `MissingBodyLength`, `InvalidBodyLength` and `HeaderTooLong`, which
    ///   consume nothing without recovery, resynchronise instead, so the skip
    ///   makes progress.
    /// - The resync anchors on a complete header opening instead of a bare
    ///   `<SOH>8`: `8=`, a FIX-family BeginString (`FIX.4.0` to `FIX.4.4`,
    ///   `FIXT.1.1`; only the session's own with
    ///   [`FixCodec::with_begin_string`]), SOH, `9=`, preceded by SOH, the start
    ///   of the buffer, or any byte that is neither an ASCII digit nor `=`.
    ///   Both checks hold across a read boundary: when a resync empties the
    ///   buffer, or stops on a partial opening the next read completes, the
    ///   start of that read is judged exactly as the scan judges a candidate,
    ///   and anything else it opens with (another version's frame included)
    ///   is treated as the rest of the same garbled span. Where TCP splits the
    ///   bytes therefore changes neither the frames handed up nor the skip
    ///   count. A valid frame that arrives straight after garbage is
    ///   therefore not lost with it, a tag such as `851=` inside a skipped frame
    ///   is not mistaken for a frame start, and a frame embedded at the very
    ///   start of a data field value (`96=8=FIX…`) or after a digit is not
    ///   resynchronised onto. A false start is rejected inside the scan, so it
    ///   is not counted.
    ///
    ///   Residual risk: inside a frame that is already garbled, a data field
    ///   value that contains a complete opening of an accepted BeginString
    ///   after any byte other than an ASCII digit or `=` (a space, `|`, `MSG:`,
    ///   `<![CDATA[`, an SOH) is a candidate, and a well-formed frame after it
    ///   is handed up. With [`FixCodec::with_begin_string`] only an opening of
    ///   the session's own version qualifies. A stream whose BeginString is not
    ///   accepted still frames, but a resync does not land on it.
    /// - In the header phase, the 64-byte header ceiling is checked before the
    ///   frame ceiling, so whether malformed header bytes are skipped never
    ///   depends on how many good frames happen to be buffered behind them.
    ///
    /// Every skip consumes at least one byte, so one call does work linear in
    /// the buffered bytes, and skipping itself never allocates. The frame
    /// bytes are never logged: a garbled Logon can still carry `Password`
    /// (554).
    ///
    /// Recovery is a framing policy only. The codec has no session state: it
    /// is the caller that must not consume a `MsgSeqNum` (34) for a skipped
    /// frame, nor count it as proof that the peer is alive.
    #[must_use]
    pub const fn with_garbled_recovery(mut self, recover: bool) -> Self {
        self.garbled_recovery = recover;
        self
    }

    /// Returns how many garbled frames recovery has skipped since the last
    /// call, and resets the count to zero.
    ///
    /// Each skip is one recoverable framing error the codec resynchronised
    /// past, which is one per garbled frame: false frame starts inside it are
    /// rejected by the resync scan and never counted. A run of garbage up to
    /// the next accepted frame start is one span and counts once, however it
    /// is split across reads: a partial header opening kept for the next read,
    /// or garbage that keeps arriving in later reads, joins the span already
    /// counted. (A codec with no anchor at all is the exception, see
    /// [`FixCodec::with_begin_string`].) Always zero when recovery is off,
    /// because every malformed frame is then returned as an error.
    #[must_use = "the count is reset by this call; dropping it loses the skips it reports"]
    pub const fn take_garbled_count(&mut self) -> u64 {
        std::mem::replace(&mut self.garbled_count, 0)
    }

    /// Restricts recovery-mode resync anchors to the header opening of one
    /// BeginString (8), the session's own.
    ///
    /// Every real frame on a session carries the session's BeginString, so
    /// this loses no real frame. What it removes is every embedded frame of
    /// another version from the residual phantom-frame risk described on
    /// [`FixCodec::with_garbled_recovery`]. The preceding-byte rule is kept as
    /// it is, so a valid frame straight after garbage is still recovered.
    ///
    /// `begin_string` is matched against the FIX family (`FIX.4.0` to
    /// `FIX.4.4`, `FIXT.1.1`; a FIX 5.0 session uses `FIXT.1.1` on the wire).
    /// Any other value leaves no anchor at all: a resync then never lands
    /// inside a buffer, and the codec waits for the next read to start on a
    /// frame, which is what an unrecognised BeginString already got before.
    /// With nothing to compare a read's start with, a read that starts after
    /// a plausible boundary is framed as it is, so that fallback is the one
    /// case where the outcome depends on how the bytes are split across reads.
    /// Without recovery this setting has no effect.
    #[must_use]
    pub fn with_begin_string(mut self, begin_string: &str) -> Self {
        let wanted = begin_string.as_bytes();
        let position = RECOVERY_ANCHORS.iter().position(|anchor| {
            anchor
                .strip_prefix(BEGIN_STRING_PREFIX)
                .and_then(|rest| rest.strip_suffix(b"\x019="))
                == Some(wanted)
        });
        self.recovery_anchors = position
            .and_then(|index| RECOVERY_ANCHORS.get(index..=index))
            .unwrap_or(&[]);
        self
    }

    /// Judges the start of the buffer against what the last resync left
    /// pending, so the resync's checks hold across a read boundary.
    ///
    /// [`recovery_resync_offset`] only sees the current buffer, so the byte at
    /// offset 0 of the next read is never one of its candidates. Left to the
    /// ordinary path, that byte would be framed whatever it opens with:
    /// another version's frame embedded in the garbled span, say, which the
    /// same bytes in one read would have resynchronised past. So the start is
    /// judged here exactly as the scan judges a candidate, and the outcome
    /// never depends on where the bytes were split:
    ///
    /// 1. **Boundary.** The byte before it must pass [`boundary_before`]. For
    ///    [`ResyncState::EmptiedAfter`] that is the byte the resync discarded
    ///    last (a resync that stopped right after `96=` fails it). For
    ///    [`ResyncState::PartialOpening`] the scan already checked it.
    /// 2. **Shape.** The bytes must open an accepted header ([`anchor_shape`]
    ///    against the codec's anchors, so with
    ///    [`FixCodec::with_begin_string`] only the session's own BeginString).
    ///    A complete opening proceeds and is framed; a partial one waits for
    ///    the bytes that settle it, keeping the state.
    ///
    /// A start that fails either check continues the same garbled span: it is
    /// resynchronised past from offset 1, as the scan would have continued,
    /// and is not counted again, since that span is already counted. An
    /// ordinary aligned frame never reaches here, because only a resync leaves
    /// a state pending.
    ///
    /// The one exception is a codec with no anchor at all (a BeginString
    /// outside the FIX family passed to [`FixCodec::with_begin_string`]).
    /// There is nothing to compare the shape with, and a resync can never land
    /// inside a buffer, so a start after a plausible boundary is framed as it
    /// is: a read boundary is the only frame start such a codec can find.
    #[cold]
    fn judge_resync_start(&mut self, src: &mut BytesMut) -> SpanVerdict {
        let after_boundary = match self.resync_state {
            ResyncState::Settled => return SpanVerdict::Proceed,
            ResyncState::EmptiedAfter(prev) => boundary_before(Some(prev)),
            ResyncState::PartialOpening => true,
        };
        if src.is_empty() {
            return SpanVerdict::NeedMore;
        }
        if after_boundary {
            let anchors = self.recovery_anchors;
            let shape = if anchors.is_empty() {
                AnchorShape::Complete
            } else {
                anchor_shape(src.as_ref(), anchors)
            };
            match shape {
                AnchorShape::Complete => {
                    self.resync_state = ResyncState::Settled;
                    return SpanVerdict::Proceed;
                }
                AnchorShape::Partial => return SpanVerdict::NeedMore,
                AnchorShape::Rejected => {}
            }
        }
        self.resync(src);
        SpanVerdict::Resynced
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
    fn header_needs_more(&self, src_len: usize) -> Result<Option<FrameLayout>, CodecError> {
        let too_large = src_len > self.max_message_size;
        let too_long = src_len >= MAX_HEADER_LEN;
        let header_too_long = CodecError::HeaderTooLong {
            max_header_len: MAX_HEADER_LEN,
        };
        // Without recovery the frame ceiling is checked first: when a single
        // read delivers more bytes than any legal frame, it is the more
        // informative diagnostic. With recovery the header verdict wins, because
        // it is the recoverable one: whether malformed header bytes end the
        // stream must not depend on how many good frames TCP happened to
        // deliver behind them.
        if self.garbled_recovery && too_long {
            return Err(header_too_long);
        }
        if too_large {
            return Err(CodecError::MessageTooLarge {
                size: src_len,
                max_size: self.max_message_size,
            });
        }
        if too_long {
            return Err(header_too_long);
        }
        Ok(None)
    }

    /// Parses the `8=…<SOH>9=…<SOH>` header at the start of `bytes` and
    /// derives the frame layout it declares.
    ///
    /// Pure: nothing is consumed here, so the caller decides what an error does
    /// to the buffer. `bytes` is known to start with `8=`.
    ///
    /// # Errors
    /// [`CodecError::MissingBodyLength`], [`CodecError::InvalidBodyLength`],
    /// [`CodecError::HeaderTooLong`] or [`CodecError::MessageTooLarge`] for a
    /// header that cannot frame a legal message.
    fn scan_header(&self, bytes: &[u8]) -> Result<Option<FrameLayout>, CodecError> {
        // The header is parsed inside a bounded window, so every "need more
        // data" answer below is capped by MAX_HEADER_LEN rather than by the
        // peer's willingness to send a delimiter.
        let header = bytes.get(..MAX_HEADER_LEN).unwrap_or(bytes);

        // Find first SOH to get BeginString value
        let Some(first_soh) = memchr(SOH, header) else {
            return self.header_needs_more(bytes.len());
        };

        // Find BodyLength field (9=XXX|)
        let body_len_start = first_soh
            .checked_add(1)
            .ok_or(CodecError::InvalidBodyLength)?;
        let body_len_end = body_len_start
            .checked_add(BODY_LENGTH_PREFIX.len())
            .ok_or(CodecError::InvalidBodyLength)?;
        match header.get(body_len_start..body_len_end) {
            Some(prefix) if prefix == BODY_LENGTH_PREFIX => {}
            Some(_) => return Err(CodecError::MissingBodyLength),
            None => return self.header_needs_more(bytes.len()),
        }

        // Find SOH after BodyLength
        let Some(after_prefix) = header.get(body_len_end..) else {
            return self.header_needs_more(bytes.len());
        };
        let Some(digits_len) = memchr(SOH, after_prefix) else {
            return self.header_needs_more(bytes.len());
        };
        let digits = after_prefix
            .get(..digits_len)
            .ok_or(CodecError::InvalidBodyLength)?;
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

        Ok(Some(FrameLayout {
            body_end,
            total_length,
        }))
    }

    /// Discards bytes up to the next candidate frame start and returns how
    /// many were discarded.
    ///
    /// The anchor depends on the mode: [`resync_offset`] without recovery,
    /// [`recovery_resync_offset`] with it. Both return an offset within
    /// `src`, so the advance is always in bounds.
    ///
    /// In recovery mode the resync records what it leaves pending: the last
    /// byte it discarded when it empties the buffer, or that it stopped on a
    /// partial opening, so the next read can be judged consistently
    /// ([`FixCodec::judge_resync_start`]).
    #[cold]
    fn resync(&mut self, src: &mut BytesMut) -> usize {
        let discarded = if self.garbled_recovery {
            let anchors = self.recovery_anchors;
            let discarded = recovery_resync_offset(src, anchors);
            self.resync_state = if discarded == src.len() {
                discarded
                    .checked_sub(1)
                    .and_then(|last| src.get(last))
                    .copied()
                    .map_or(ResyncState::Settled, ResyncState::EmptiedAfter)
            } else if src
                .get(discarded..)
                .is_some_and(|rest| anchor_shape(rest, anchors) == AnchorShape::Partial)
            {
                ResyncState::PartialOpening
            } else {
                ResyncState::Settled
            };
            discarded
        } else {
            resync_offset(src)
        };
        src.advance(discarded);
        discarded
    }

    /// Logs a resynchronisation without recovery, naming how many bytes it
    /// discarded and never the bytes themselves.
    ///
    /// Without recovery a resync accompanies a returned error, so it is a
    /// warning. With recovery it is routine and is reported once per skip, at
    /// debug, by [`FixCodec::record_skip`]; logging here too would double it,
    /// and a warning per skip would let a peer streaming garbage flood the log.
    #[cold]
    fn log_resync(&self, discarded: usize, cause: &'static str) {
        if !self.garbled_recovery {
            tracing::warn!(discarded, cause, "garbled FIX frame: resynchronised");
        }
    }

    /// Bookkeeping for one skipped garbled frame in recovery mode: count it,
    /// guarantee progress, and emit the single debug event for the skip.
    ///
    /// `before` is the buffer length before the failed framing attempt, so
    /// `before - src.len()` is what the skip discarded.
    ///
    /// # Errors
    /// Returns `error` itself when the counter cannot represent another skip,
    /// rather than hiding the frame. Unreachable in practice: every skip
    /// consumes at least one byte, so it takes 2^64 bytes.
    #[cold]
    #[inline(never)]
    fn record_skip(
        &mut self,
        src: &mut BytesMut,
        before: usize,
        error: CodecError,
    ) -> Result<(), CodecError> {
        let Some(count) = self.garbled_count.checked_add(1) else {
            return Err(error);
        };
        self.garbled_count = count;

        // Every recoverable path consumes at least one byte in recovery mode,
        // and that is what bounds the decode loop by the buffer length. It is
        // enforced rather than assumed: a path that consumed nothing would
        // otherwise spin forever on the same bytes.
        debug_assert!(
            src.len() < before,
            "a recoverable framing error must consume input"
        );
        if src.len() >= before && !src.is_empty() {
            src.advance(1);
        }
        // The buffer never grows inside a framing attempt, so the subtraction
        // always succeeds; the other arm still emits the one event per skip.
        match before.checked_sub(src.len()) {
            Some(discarded) => tracing::debug!(
                cause = %error,
                discarded,
                skipped = count,
                "skipped a garbled FIX frame"
            ),
            None => tracing::debug!(cause = %error, skipped = count, "skipped a garbled FIX frame"),
        }
        Ok(())
    }

    /// Reports a header that cannot frame a legal message.
    ///
    /// Without recovery nothing is consumed: the frame boundary is unknown and
    /// the error is the caller's to act on. With recovery a recoverable header
    /// error is about to be skipped, so the codec resynchronises first and the
    /// skip makes progress. A fatal error is never resynchronised.
    #[cold]
    fn reject_header(
        &mut self,
        src: &mut BytesMut,
        error: CodecError,
    ) -> Result<Option<BytesMut>, CodecError> {
        if self.garbled_recovery && error.is_recoverable() {
            let discarded = self.resync(src);
            self.log_resync(discarded, "malformed header");
        }
        Err(error)
    }

    /// Extracts one complete FIX frame from `src`, or reports why it cannot.
    ///
    /// This is a single framing attempt; [`Decoder::decode`] wraps it with the
    /// recovery loop.
    ///
    /// # Errors
    /// A [`CodecError`] for any malformed frame; see that type for which
    /// variants consume bytes from `src`.
    fn decode_one(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, CodecError> {
        if src.len() < MIN_FRAME_LEN {
            return Ok(None);
        }

        // Validate BeginString starts with "8=". A frame that does not is
        // garbled: discard up to the next candidate frame so a caller that
        // keeps reading makes progress instead of re-parsing these bytes.
        if src.get(..BEGIN_STRING_PREFIX.len()) != Some(BEGIN_STRING_PREFIX) {
            let discarded = self.resync(src);
            self.log_resync(discarded, "frame does not start with 8=");
            return Err(CodecError::InvalidBeginString);
        }

        // Bound before matching: the borrow of `src` must end before the error
        // arm resynchronises it.
        let scanned = self.scan_header(src.as_ref());
        let FrameLayout {
            body_end,
            total_length,
        } = match scanned {
            Ok(Some(layout)) => layout,
            Ok(None) => return Ok(None),
            Err(error) => return self.reject_header(src, error),
        };

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
                let discarded = self.resync(src);
                self.log_resync(
                    discarded,
                    "trailer absent at the declared BodyLength offset",
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
                    let discarded = self.resync(src);
                    self.log_resync(discarded, "checksum span out of bounds");
                    return Err(CodecError::InvalidTrailer { offset: body_end });
                }
            }
        }

        // Extract the complete message
        let message = src.split_to(total_length);
        Ok(Some(message))
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
    /// With [`FixCodec::with_garbled_recovery`] enabled, recoverable framing
    /// errors are skipped and counted within this call, which then returns the
    /// next valid frame if one is buffered. Each skip consumes at least one
    /// byte, so the loop is bounded by the buffer length.
    ///
    /// # Errors
    /// Without recovery, a [`CodecError`] for any malformed frame. With it,
    /// only the fatal ones ([`CodecError::is_recoverable`] is `false`). See
    /// [`CodecError`] for which variants consume bytes from `src`.
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            // After a resync, the start of this buffer may still sit inside
            // the same garbled span, or complete an opening that has yet to
            // be validated.
            if self.garbled_recovery && self.resync_state != ResyncState::Settled {
                match self.judge_resync_start(src) {
                    SpanVerdict::Proceed => {}
                    SpanVerdict::NeedMore => return Ok(None),
                    SpanVerdict::Resynced => continue,
                }
            }
            let before = src.len();
            let error = match self.decode_one(src) {
                Ok(Some(frame)) => {
                    self.resync_state = ResyncState::Settled;
                    return Ok(Some(frame));
                }
                Ok(None) => return Ok(None),
                Err(error) => error,
            };
            if !self.garbled_recovery || !error.is_recoverable() {
                return Err(error);
            }
            self.record_skip(src, before, error)?;
        }
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

    // --- Garbled-frame recovery ----------------------------------------------

    /// A codec with garbled-frame recovery enabled and default limits.
    fn recovering() -> FixCodec {
        FixCodec::new().with_garbled_recovery(true)
    }

    /// Builds a frame around `body` whose CheckSum is off by one.
    fn make_bad_checksum_message(body: &str) -> Vec<u8> {
        let without_checksum = format!("8=FIX.4.4\x019={}\x01{}", body.len(), body);
        let correct = u16::from(calculate_checksum(without_checksum.as_bytes()));
        let wrong = (correct + 1) % 256;
        format!("{without_checksum}10={wrong:03}\x01").into_bytes()
    }

    /// Decodes until the codec asks for more data or errors, collecting every
    /// frame. Fails the test if the codec does not settle, which would mean a
    /// recovery path that makes no progress.
    fn drain(
        codec: &mut FixCodec,
        buf: &mut BytesMut,
        out: &mut Vec<BytesMut>,
    ) -> Option<CodecError> {
        for _ in 0..100_000 {
            match codec.decode(buf) {
                Ok(Some(frame)) => out.push(frame),
                Ok(None) => return None,
                Err(error) => return Some(error),
            }
        }
        panic!("decode did not settle: a recovery path is not making progress");
    }

    #[test]
    #[allow(deprecated)] // `Incomplete` is classified like every other variant.
    fn test_is_recoverable_classifies_every_variant() {
        let recoverable = [
            CodecError::InvalidBeginString,
            CodecError::MissingBodyLength,
            CodecError::InvalidBodyLength,
            CodecError::HeaderTooLong { max_header_len: 64 },
            CodecError::InvalidTrailer { offset: 3 },
            CodecError::InvalidChecksumFormat,
            CodecError::ChecksumMismatch {
                calculated: 1,
                declared: 2,
            },
        ];
        for error in &recoverable {
            assert!(error.is_recoverable(), "{error:?} is garbling");
        }

        let fatal = [
            CodecError::Incomplete,
            CodecError::MessageTooLarge {
                size: 2,
                max_size: 1,
            },
            CodecError::Io("connection reset".to_string()),
            CodecError::from(std::io::Error::other("boom")),
        ];
        for error in &fatal {
            assert!(!error.is_recoverable(), "{error:?} must end the stream");
        }
    }

    #[test]
    fn test_recovery_checksum_mismatch_returns_the_next_frame_in_one_call() {
        let mut codec = recovering();
        let bad = make_bad_checksum_message("35=0\x0149=A\x0156=B\x01");
        let good = make_fix_message("35=1\x01112=PING\x01");
        let mut buf = BytesMut::from(&bad[..]);
        buf.extend_from_slice(&good);

        let frame = decode_frame(&mut codec, &mut buf);
        assert_eq!(&frame[..], &good[..]);
        assert!(buf.is_empty());
        assert_eq!(codec.take_garbled_count(), 1);
    }

    #[test]
    fn test_recovery_short_body_length_returns_the_next_frame_in_one_call() {
        // BodyLength says 3 where the body is 5 bytes: InvalidTrailer.
        let mut codec = recovering();
        let good = make_fix_message("35=0\x0149=A\x01");
        let mut buf = BytesMut::from(&b"8=FIX.4.4\x019=3\x0135=0\x0110=000\x01"[..]);
        buf.extend_from_slice(&good);

        let frame = decode_frame(&mut codec, &mut buf);
        assert_eq!(&frame[..], &good[..]);
        assert!(buf.is_empty());
        assert_eq!(codec.take_garbled_count(), 1);
    }

    #[test]
    fn test_recovery_long_body_length_returns_the_next_frame_once_its_span_is_buffered() {
        // BodyLength says 60 where the body is 5 bytes. The trailer can only
        // be checked once 82 bytes are buffered; until then the codec waits,
        // exactly as it would for a real frame that long.
        let mut codec = recovering();
        let good = b"8=FIX.4.4\x019=15\x0135=0\x0149=A\x0156=B\x0110=171\x01";
        let mut buf = BytesMut::from(&b"8=FIX.4.4\x019=60\x0135=0\x0110=000\x01"[..]);
        buf.extend_from_slice(good);

        assert!(matches!(codec.decode(&mut buf), Ok(None)));
        assert_eq!(codec.take_garbled_count(), 0, "nothing is skipped yet");

        buf.extend_from_slice(good);
        buf.extend_from_slice(good);
        // The declared span is now buffered: the trailer check fails, the
        // hostile header is skipped, and the first good frame comes back in
        // the same call. BodyLength was not corroborated, so it did not bound
        // the discard and every good frame survives.
        for index in 0..3 {
            match codec.decode(&mut buf) {
                Ok(Some(frame)) => assert_eq!(&frame[..], &good[..]),
                other => panic!("good frame {index} must survive, got {other:?}"),
            }
        }
        assert!(buf.is_empty());
        assert_eq!(codec.take_garbled_count(), 1);
    }

    #[test]
    fn test_recovery_leading_garbage_without_soh_returns_the_frame_in_one_call() {
        let garbage: &[u8] = b"\x00garbage!\xff";
        let good = make_fix_message("35=0\x0149=A\x0156=B\x01");

        let mut codec = recovering();
        let mut buf = BytesMut::from(garbage);
        buf.extend_from_slice(&good);
        let frame = decode_frame(&mut codec, &mut buf);
        assert_eq!(&frame[..], &good[..]);
        assert!(buf.is_empty());
        assert_eq!(codec.take_garbled_count(), 1);

        // Without recovery the `<SOH>8` anchor cannot see this frame: its
        // `8=` follows the garbage, not an SOH, so it is discarded with it.
        let mut strict = FixCodec::new();
        let mut buf = BytesMut::from(garbage);
        buf.extend_from_slice(&good);
        assert_eq!(
            strict.decode(&mut buf).err(),
            Some(CodecError::InvalidBeginString)
        );
        assert!(matches!(strict.decode(&mut buf), Ok(None)));
    }

    #[test]
    fn test_recovery_leading_garbage_ending_in_soh_returns_the_frame_in_one_call() {
        let mut codec = recovering();
        let good = make_fix_message("35=0\x0149=A\x01");
        let mut buf = BytesMut::from(&b"junk\x01"[..]);
        buf.extend_from_slice(&good);

        let frame = decode_frame(&mut codec, &mut buf);
        assert_eq!(&frame[..], &good[..]);
        assert_eq!(codec.take_garbled_count(), 1);
    }

    #[test]
    fn test_recovery_missing_body_length_resyncs_to_the_next_frame() {
        let mut codec = recovering();
        let good = make_fix_message("35=0\x0149=A\x01");
        let mut buf = BytesMut::from(&b"8=FIX.4.4\x0135=0\x0149=A\x0110=000\x01"[..]);
        buf.extend_from_slice(&good);

        let frame = decode_frame(&mut codec, &mut buf);
        assert_eq!(&frame[..], &good[..]);
        assert!(buf.is_empty());
        assert_eq!(codec.take_garbled_count(), 1);
    }

    #[test]
    fn test_recovery_invalid_body_length_resyncs_to_the_next_frame() {
        for bad in [
            &b"8=FIX.4.4\x019=abc\x0135=0\x0110=000\x01"[..],
            &b"8=FIX.4.4\x019=\x0135=0\x0110=000\x01"[..],
            &b"8=FIX.4.4\x019=+5\x0135=0\x0110=000\x01"[..],
        ] {
            let mut codec = recovering();
            let good = make_fix_message("35=0\x0149=A\x01");
            let mut buf = BytesMut::from(bad);
            buf.extend_from_slice(&good);

            let frame = decode_frame(&mut codec, &mut buf);
            assert_eq!(&frame[..], &good[..]);
            assert_eq!(codec.take_garbled_count(), 1);
        }
    }

    #[test]
    fn test_recovery_body_length_overflow_resyncs_to_the_next_frame() {
        let mut codec = recovering();
        let good = make_fix_message("35=0\x0149=A\x01");
        let hostile = format!("8=FIX.4.4\x019={}\x0135=0\x0110=000\x01", usize::MAX);
        let mut buf = BytesMut::from(hostile.as_bytes());
        buf.extend_from_slice(&good);

        let frame = decode_frame(&mut codec, &mut buf);
        assert_eq!(&frame[..], &good[..]);
        assert_eq!(codec.take_garbled_count(), 1);
    }

    #[test]
    fn test_recovery_header_too_long_resyncs_to_the_next_frame() {
        let mut codec = recovering();
        let good = make_fix_message("35=0\x0149=A\x01");
        let mut buf = BytesMut::from(&b"8="[..]);
        buf.extend_from_slice(&[b'X'; 70]);
        buf.extend_from_slice(&good);

        let frame = decode_frame(&mut codec, &mut buf);
        assert_eq!(&frame[..], &good[..]);
        assert!(buf.is_empty());
        assert_eq!(codec.take_garbled_count(), 1);
    }

    #[test]
    fn test_recovery_message_too_large_is_still_an_error_and_consumes_nothing() {
        let mut codec = recovering();
        let msg = format!("8=FIX.4.4\x019={}\x0135=0\x0110=000\x01", 10 * 1024 * 1024);
        let mut buf = BytesMut::from(msg.as_bytes());
        let total = buf.len();

        assert!(matches!(
            codec.decode(&mut buf),
            Err(CodecError::MessageTooLarge { .. })
        ));
        assert_eq!(buf.len(), total);
        assert_eq!(codec.take_garbled_count(), 0);
    }

    #[test]
    fn test_recovery_soh_free_buffer_over_ceiling_is_skipped_not_fatal() {
        // Without recovery this buffer is MessageTooLarge (see
        // `test_decode_soh_free_buffer_over_ceiling_is_message_too_large`):
        // the frame ceiling is checked first. With recovery the header ceiling
        // wins, so the same garbage is skipped however many bytes TCP happened
        // to deliver with it.
        let ceiling = 128;
        let mut codec = recovering().with_max_message_size(ceiling);
        let mut buf = BytesMut::from(&b"8="[..]);
        buf.extend_from_slice(&vec![b'X'; ceiling]);

        assert!(matches!(codec.decode(&mut buf), Ok(None)));
        assert!(buf.is_empty());
        assert_eq!(codec.take_garbled_count(), 1);
    }

    #[test]
    fn test_recovery_eof_with_a_truncated_frame_is_a_fatal_io_error() {
        let mut codec = recovering();
        let msg = make_fix_message("35=0\x0149=A\x01");
        let Some(head) = msg.get(..msg.len() - 3) else {
            panic!("message is longer than the truncation");
        };
        let mut buf = BytesMut::from(head);

        match codec.decode_eof(&mut buf) {
            Err(error @ CodecError::Io(_)) => assert!(!error.is_recoverable()),
            other => panic!("a stream ending mid-frame must be an I/O error, got {other:?}"),
        }
    }

    #[test]
    fn test_recovery_off_keeps_the_error_per_frame_contract() {
        let good = make_fix_message("35=0\x0149=A\x01");
        let bad: &[u8] = b"8=FIX.4.4\x0135=0\x0149=A\x0110=000\x01";

        let mut strict = FixCodec::new();
        let mut buf = BytesMut::from(bad);
        buf.extend_from_slice(&good);
        let total = buf.len();
        assert_eq!(
            strict.decode(&mut buf).err(),
            Some(CodecError::MissingBodyLength)
        );
        assert_eq!(buf.len(), total, "without recovery nothing is consumed");
        assert_eq!(strict.take_garbled_count(), 0);

        let mut lenient = recovering();
        let mut buf = BytesMut::from(bad);
        buf.extend_from_slice(&good);
        let frame = decode_frame(&mut lenient, &mut buf);
        assert_eq!(&frame[..], &good[..]);
        assert_eq!(lenient.take_garbled_count(), 1);
    }

    #[test]
    fn test_recovery_garbled_count_counts_each_skip_and_resets() {
        let mut codec = recovering();
        let first = make_fix_message("35=0\x0149=A\x01");
        let second = make_fix_message("35=0\x0149=B\x01");
        let mut buf = BytesMut::from(&make_bad_checksum_message("35=0\x0149=X\x01")[..]);
        buf.extend_from_slice(b"\x00\x00noise");
        buf.extend_from_slice(&first);
        buf.extend_from_slice(b"8=FIX.4.4\x019=abc\x0135=0\x0110=000\x01");
        buf.extend_from_slice(&second);

        assert_eq!(&decode_frame(&mut codec, &mut buf)[..], &first[..]);
        assert_eq!(&decode_frame(&mut codec, &mut buf)[..], &second[..]);
        assert_eq!(codec.take_garbled_count(), 3);
        assert_eq!(codec.take_garbled_count(), 0, "the count resets on take");
    }

    #[test]
    fn test_recovery_false_anchor_inside_a_field_is_not_an_anchor() {
        // The garbled frame's Text (58) carries `8=FIX`. The resync scan
        // rejects it (it follows `=` and is not a complete header opening), so
        // it is never counted, and the real frame after it is still returned in
        // the same call.
        let mut codec = recovering();
        let good = make_fix_message("35=0\x0149=A\x01");
        let mut buf =
            BytesMut::from(&b"8=FIX.4.4\x019=3\x0135=0\x0158=8=FIX here\x0110=000\x01"[..]);
        buf.extend_from_slice(&good);

        let frame = decode_frame(&mut codec, &mut buf);
        assert_eq!(&frame[..], &good[..]);
        assert!(buf.is_empty());
        assert_eq!(codec.take_garbled_count(), 1);
    }

    /// Builds a well-formed frame with the given BeginString around `body`.
    fn make_message_with(begin_string: &str, body: &str) -> Vec<u8> {
        let without_checksum = format!("8={begin_string}\x019={}\x01{}", body.len(), body);
        let checksum = calculate_checksum(without_checksum.as_bytes());
        format!("{without_checksum}10={checksum:03}\x01").into_bytes()
    }

    #[test]
    fn test_recovery_phantom_split_across_reads_is_not_delivered() {
        // The resync through a garbled frame empties the buffer right after
        // `96=`; the frame embedded in that field then arrives at offset 0 of
        // the next read, where the current buffer alone shows no `=` before
        // it. The codec remembers the discarded tail and treats the opening as
        // the same garbled span: not delivered, not counted again.
        let inner = make_fix_message("35=0\x0149=X\x0156=Y\x0134=99\x01");
        let first_read = format!("8=FIX.4.4\x019=abc\x0135=D\x0195={}\x0196=", inner.len());
        let good = make_fix_message("35=1\x0149=A\x01112=PING\x01");
        let mut second_read = inner.clone();
        second_read.extend_from_slice(b"\x0110=000\x01");
        second_read.extend_from_slice(&good);

        for codec in [recovering(), recovering().with_begin_string("FIX.4.4")] {
            let mut codec = codec;
            let mut buf = BytesMut::from(first_read.as_bytes());
            assert!(matches!(codec.decode(&mut buf), Ok(None)));
            assert!(buf.is_empty(), "the resync emptied the buffer");
            buf.extend_from_slice(&second_read);
            let mut frames = Vec::new();
            assert_eq!(drain(&mut codec, &mut buf, &mut frames), None);
            let got: Vec<&[u8]> = frames.iter().map(|frame| &frame[..]).collect();
            assert_eq!(got, vec![&good[..]], "two reads");
            assert_eq!(codec.take_garbled_count(), 1, "one garbled span, two reads");

            // The same bytes in one read.
            let mut codec = recovering();
            let mut buf = BytesMut::from(first_read.as_bytes());
            buf.extend_from_slice(&second_read);
            let mut frames = Vec::new();
            assert_eq!(drain(&mut codec, &mut buf, &mut frames), None);
            let got: Vec<&[u8]> = frames.iter().map(|frame| &frame[..]).collect();
            assert_eq!(got, vec![&good[..]], "one read");
            assert_eq!(codec.take_garbled_count(), 1, "one read");
        }
    }

    #[test]
    fn test_recovery_other_version_frame_after_a_split_data_field_is_not_delivered() {
        // Restricted to FIX.4.4. The resync empties the buffer right after
        // `96=`, and the next read starts with a checksum-valid FIX.4.2 frame
        // embedded in that field. Its opening is not an accepted anchor, but
        // it is still a frame start the ordinary path would frame: it must be
        // treated as the rest of the garbled span, exactly as in one read.
        let inner = make_message_with("FIX.4.2", "35=0\x0149=X\x0156=Y\x0134=99\x01");
        let first_read = format!("8=FIX.4.4\x019=abc\x0135=D\x0195={}\x0196=", inner.len());
        let good = make_fix_message("35=1\x0149=A\x01112=PING\x01");
        let mut second_read = inner.clone();
        second_read.extend_from_slice(b"\x0110=000\x01");
        second_read.extend_from_slice(&good);

        let mut codec = recovering().with_begin_string("FIX.4.4");
        let mut buf = BytesMut::from(first_read.as_bytes());
        assert!(matches!(codec.decode(&mut buf), Ok(None)));
        assert!(buf.is_empty());
        buf.extend_from_slice(&second_read);
        let mut frames = Vec::new();
        assert_eq!(drain(&mut codec, &mut buf, &mut frames), None);
        let got: Vec<&[u8]> = frames.iter().map(|frame| &frame[..]).collect();
        assert_eq!(got, vec![&good[..]], "two reads");
        assert_eq!(codec.take_garbled_count(), 1);

        let mut codec = recovering().with_begin_string("FIX.4.4");
        let mut buf = BytesMut::from(first_read.as_bytes());
        buf.extend_from_slice(&second_read);
        let mut frames = Vec::new();
        assert_eq!(drain(&mut codec, &mut buf, &mut frames), None);
        let got: Vec<&[u8]> = frames.iter().map(|frame| &frame[..]).collect();
        assert_eq!(got, vec![&good[..]], "one read");
        assert_eq!(codec.take_garbled_count(), 1);
    }

    #[test]
    fn test_recovery_partial_opening_completed_as_another_version_is_rejected() {
        // Restricted to FIX.4.4. The resync stops on `8=FIX.4.` at the end of
        // the first read: a partial opening that may still become FIX.4.4.
        // The next read completes it as FIX.4.2. In one read the resync would
        // have rejected that opening; split across reads it must be too.
        let other = make_message_with("FIX.4.2", "35=0\x0149=X\x0156=Y\x0134=7\x01");
        let good = make_fix_message("35=1\x0149=A\x01112=PING\x01");
        let mut stream = Vec::from(&b"some leading garbage!"[..]);
        stream.extend_from_slice(&other);
        stream.extend_from_slice(&good);
        let split = b"some leading garbage!8=FIX.4.".len();
        let (Some(first_read), Some(second_read)) = (stream.get(..split), stream.get(split..))
        else {
            panic!("split point is inside the stream");
        };

        let mut codec = recovering().with_begin_string("FIX.4.4");
        let mut buf = BytesMut::from(first_read);
        assert!(matches!(codec.decode(&mut buf), Ok(None)));
        assert_eq!(&buf[..], b"8=FIX.4.", "the partial opening is kept");
        buf.extend_from_slice(second_read);
        let mut frames = Vec::new();
        assert_eq!(drain(&mut codec, &mut buf, &mut frames), None);
        let got: Vec<&[u8]> = frames.iter().map(|frame| &frame[..]).collect();
        assert_eq!(got, vec![&good[..]], "two reads");
        assert_eq!(codec.take_garbled_count(), 1);

        let mut codec = recovering().with_begin_string("FIX.4.4");
        let mut buf = BytesMut::from(&stream[..]);
        let mut frames = Vec::new();
        assert_eq!(drain(&mut codec, &mut buf, &mut frames), None);
        let got: Vec<&[u8]> = frames.iter().map(|frame| &frame[..]).collect();
        assert_eq!(got, vec![&good[..]], "one read");
        assert_eq!(codec.take_garbled_count(), 1);
    }

    #[test]
    fn test_recovery_partial_opening_completed_as_the_session_version_is_framed() {
        // The same split, completed as the session's own version: an ordinary
        // frame that the partial opening correctly waited for.
        let mut codec = recovering().with_begin_string("FIX.4.4");
        let good = make_fix_message("35=1\x0149=A\x01112=PING\x01");
        let mut stream = Vec::from(&b"some leading garbage!"[..]);
        stream.extend_from_slice(&good);
        let split = b"some leading garbage!8=FIX.4.".len();
        let (Some(first_read), Some(second_read)) = (stream.get(..split), stream.get(split..))
        else {
            panic!("split point is inside the stream");
        };
        let mut buf = BytesMut::from(first_read);
        assert!(matches!(codec.decode(&mut buf), Ok(None)));
        buf.extend_from_slice(second_read);
        assert_eq!(&decode_frame(&mut codec, &mut buf)[..], &good[..]);
        assert_eq!(codec.take_garbled_count(), 1);
    }

    #[test]
    fn test_recovery_discarded_tail_is_forgotten_after_a_plausible_boundary() {
        // A resync that empties the buffer on a byte that is a plausible
        // boundary does not hold back the frame at the start of the next read.
        let mut codec = recovering();
        let good = make_fix_message("35=0\x0149=A\x01");
        let mut buf = BytesMut::from(&b"garbage that ends on a delimiter\x01"[..]);
        assert!(matches!(codec.decode(&mut buf), Ok(None)));
        buf.extend_from_slice(&good);
        assert_eq!(&decode_frame(&mut codec, &mut buf)[..], &good[..]);
        assert_eq!(codec.take_garbled_count(), 1);
    }

    #[test]
    fn test_recovery_documented_residual_risk_is_pinned() {
        // The documented residual risk, pinned so a change to it is a visible
        // decision: inside an already garbled frame, a complete opening of
        // the session's own BeginString after a byte other than a digit or `=`
        // (here a space in `213=MSG: …`) IS resynchronised onto and delivered.
        // An embedded frame of another version is not, once the codec is
        // restricted to the session's BeginString.
        let same = make_fix_message("35=0\x0149=X\x0156=Y\x0134=99\x01");
        let other = make_message_with("FIX.4.2", "35=0\x0149=X\x0156=Y\x0134=99\x01");
        let good = make_fix_message("35=1\x0149=A\x01112=PING\x01");
        let garbled_around = |inner: &[u8]| {
            let mut outer = format!(
                "8=FIX.4.4\x019=5\x0135=D\x01212={}\x01213=MSG: ",
                inner.len() + 5
            )
            .into_bytes();
            outer.extend_from_slice(inner);
            outer.extend_from_slice(b"\x0110=000\x01");
            outer.extend_from_slice(&good);
            outer
        };
        let deliver = |mut codec: FixCodec, bytes: &[u8]| {
            let mut buf = BytesMut::from(bytes);
            let mut frames = Vec::new();
            assert_eq!(drain(&mut codec, &mut buf, &mut frames), None);
            frames
        };

        let session = || recovering().with_begin_string("FIX.4.4");
        let frames = deliver(session(), &garbled_around(&same));
        let got: Vec<&[u8]> = frames.iter().map(|frame| &frame[..]).collect();
        assert_eq!(got, vec![&same[..], &good[..]], "same version: the risk");

        let frames = deliver(session(), &garbled_around(&other));
        let got: Vec<&[u8]> = frames.iter().map(|frame| &frame[..]).collect();
        assert_eq!(got, vec![&good[..]], "other version: excluded");

        // Without the restriction every family version is an anchor.
        let frames = deliver(recovering(), &garbled_around(&other));
        let got: Vec<&[u8]> = frames.iter().map(|frame| &frame[..]).collect();
        assert_eq!(got, vec![&other[..], &good[..]], "unrestricted");
    }

    /// What a codec made of a sequence of reads: the frames it handed up, the
    /// garbled frames it counted, and the bytes it left buffered.
    type Outcome = (Vec<Vec<u8>>, u64, Vec<u8>);

    /// Feeds `reads` to `codec` one read at a time, draining after each, as
    /// `Framed` does, and reports the [`Outcome`]. Fails the test if the codec
    /// returns an error: recovery must skip every garbled frame here.
    fn feed(mut codec: FixCodec, reads: &[&[u8]]) -> Outcome {
        let mut buf = BytesMut::new();
        let mut frames = Vec::new();
        for read in reads {
            buf.extend_from_slice(read);
            if let Some(error) = drain(&mut codec, &mut buf, &mut frames) {
                panic!("recovery must not return an error, got {error:?}");
            }
        }
        let frames = frames.iter().map(|frame| frame.to_vec()).collect();
        (frames, codec.take_garbled_count(), buf.to_vec())
    }

    #[test]
    fn test_recovery_foreign_frame_after_a_split_at_a_plausible_boundary_is_not_delivered() {
        // Issue #116. Restricted to FIX.4.4. The first read ends inside a
        // garbled frame right after a byte that IS a plausible boundary (a
        // space, an SOH, a `|`), and the resync through it empties the
        // buffer. The next read starts with a checksum-valid FIX.4.2 frame.
        // In one read the resync rejects that opening (not the session's
        // version); split across reads it must be rejected too, never framed
        // by the ordinary path and handed up as a phantom.
        let foreign = make_message_with("FIX.4.2", "35=0\x0134=2\x0149=VENUE\x0156=CLIENT\x01");
        let good = make_fix_message("35=1\x0149=A\x01112=PING\x01");
        let session = || recovering().with_begin_string("FIX.4.4");

        for first_read in [
            &b"8=FIX.4.4\x01not-nine=1\x0196= "[..],
            b"8=FIX.4.4\x01not-nine=1\x0196=\x01",
            b"8=FIX.4.4\x01not-nine=1\x0196=|",
        ] {
            let context = String::from_utf8_lossy(first_read);

            // The exact probe from the review: nothing after the foreign frame.
            let split = feed(session(), &[first_read, &foreign]);
            let whole = feed(session(), &[&[first_read, &foreign[..]].concat()]);
            assert!(
                split.0.is_empty(),
                "{context}: two reads delivered {split:?}"
            );
            assert_eq!(split, whole, "{context}: two reads differ from one");
            assert_eq!(whole, (Vec::new(), 1, Vec::new()), "{context}: one read");

            // The stream goes on: the session's next frame is still delivered,
            // and the garbled span counts once however it was split.
            let rest = [&foreign[..], &good[..]].concat();
            let split = feed(session(), &[first_read, &rest]);
            let whole = feed(session(), &[&[first_read, &rest[..]].concat()]);
            assert_eq!(split, whole, "{context}: two reads differ from one");
            assert_eq!(whole, (vec![good.clone()], 1, Vec::new()), "{context}");
        }
    }

    #[test]
    fn test_recovery_every_split_point_matches_the_single_read_result() {
        // Issue #116, as a property: the outcome of a resync never depends on
        // where TCP splits the bytes. A garbled outer frame carries a complete,
        // checksum-valid frame in a data field, then a valid frame follows.
        // For every combination below, the bytes are delivered in one read, in
        // two reads split at every offset, and one byte per read; the frames
        // handed up, the garbled count and the bytes left over must agree.
        //
        // The single-read result itself is pinned to the documented rule: an
        // embedded opening after `=` (the very start of the value) is never a
        // candidate; after any other byte it is, but only for a BeginString
        // the codec accepts. Restricted to FIX.4.4, an embedded FIX.4.2 frame
        // is therefore never delivered, and an embedded FIX.4.4 frame after a
        // plausible boundary is (the residual risk ADR-0004 documents).
        let foreign = make_message_with("FIX.4.2", "35=0\x0134=2\x0149=VENUE\x0156=CLIENT\x01");
        let same = make_fix_message("35=0\x0134=99\x0149=X\x0156=Y\x01");
        let good = make_fix_message("35=1\x0149=A\x01112=PING\x01");
        // Two ways a frame is garbled before its data field: no BodyLength
        // (resynchronised as soon as the header is seen), and a BodyLength
        // that does not reach the trailer (resynchronised once its span is in).
        let openings: [&[u8]; 2] = [
            b"8=FIX.4.4\x01not-nine=1\x0196=",
            b"8=FIX.4.4\x019=5\x0135=D\x01212=60\x01213=",
        ];
        // What the data field value holds before the embedded frame. Empty is
        // the very start of the value, after `=`.
        let separators: [&[u8]; 5] = [b"", b" ", b"\x01", b"|", b"MSG: "];

        let mut checked = 0usize;
        for restricted in [true, false] {
            let codec = || {
                if restricted {
                    recovering().with_begin_string("FIX.4.4")
                } else {
                    recovering()
                }
            };
            for (inner, accepted) in [(&foreign, !restricted), (&same, true)] {
                for opening in openings {
                    for separator in separators {
                        let stream =
                            [opening, separator, &inner[..], b"\x0110=000\x01", &good[..]].concat();
                        let context = format!(
                            "restricted={restricted} {:?}",
                            String::from_utf8_lossy(&stream)
                        );

                        let whole = feed(codec(), &[&stream]);
                        let delivered = accepted && !separator.is_empty();
                        let expected = if delivered {
                            (vec![inner.clone(), good.clone()], 2, Vec::new())
                        } else {
                            (vec![good.clone()], 1, Vec::new())
                        };
                        assert_eq!(whole, expected, "{context}: one read");

                        for split in 0..=stream.len() {
                            let (Some(head), Some(tail)) =
                                (stream.get(..split), stream.get(split..))
                            else {
                                panic!("split {split} is inside the stream");
                            };
                            let parts = feed(codec(), &[head, tail]);
                            assert_eq!(parts, whole, "{context}: split at {split}");
                            checked += 1;
                        }

                        let bytes: Vec<&[u8]> = stream.chunks(1).collect();
                        assert_eq!(feed(codec(), &bytes), whole, "{context}: one byte per read");
                    }
                }
            }
        }
        assert!(checked > 1000, "the sweep must cover every split point");
    }

    #[test]
    fn test_recovery_seeded_noise_every_split_point_matches_the_single_read_result() {
        // The same property over deterministic noise (xorshift, fixed seed)
        // dense in the bytes the framer and the resync judge (`8`, `=`, SOH,
        // digits, a space, a `|`), interleaved with frames of the session's
        // version, of another version, and with a wrong checksum.
        let good = make_fix_message("35=0\x0149=A\x0156=B\x01");
        let foreign = make_message_with("FIX.4.2", "35=0\x0149=X\x0156=Y\x01");
        let bad = make_bad_checksum_message("35=0\x0149=Z\x01");
        let alphabet: &[u8] = b"8=FIX.4\x019\x0110=35 2|";
        let mut state: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        let mut stream = Vec::new();
        for _ in 0..24 {
            for _ in 0..next() % 24 {
                let pick = usize::try_from(next() % 18).unwrap_or(0);
                stream.push(alphabet.get(pick).copied().unwrap_or(b'X'));
            }
            let frame = match next() % 3 {
                0 => &good,
                1 => &foreign,
                _ => &bad,
            };
            stream.extend_from_slice(frame);
        }

        for restricted in [true, false] {
            let codec = || {
                if restricted {
                    recovering().with_begin_string("FIX.4.4")
                } else {
                    recovering()
                }
                .with_max_message_size(4096)
            };
            let whole = feed(codec(), &[&stream]);
            assert!(
                whole.0.len() >= 4 && whole.1 >= 4,
                "restricted={restricted}: the seed must leave frames and skips to compare"
            );
            assert!(
                whole
                    .0
                    .iter()
                    .all(|frame| *frame == good || (!restricted && *frame == foreign)),
                "restricted={restricted}: only real frames are handed up"
            );
            for split in 0..=stream.len() {
                let (Some(head), Some(tail)) = (stream.get(..split), stream.get(split..)) else {
                    panic!("split {split} is inside the stream");
                };
                let parts = feed(codec(), &[head, tail]);
                assert_eq!(parts, whole, "restricted={restricted}: split at {split}");
            }
            let bytes: Vec<&[u8]> = stream.chunks(1).collect();
            assert_eq!(
                feed(codec(), &bytes),
                whole,
                "restricted={restricted}: one byte per read"
            );
        }
    }

    #[test]
    fn test_recovery_garbage_at_the_start_of_the_next_read_is_the_same_span() {
        // After a resync empties the buffer, a read that does not open with
        // an accepted header continues the garbled span: it is resynchronised
        // past without being counted again, exactly as in one read. A partial
        // opening at its start waits for the bytes that settle it.
        let good = make_fix_message("35=1\x0149=A\x01112=PING\x01");
        let session = || recovering().with_begin_string("FIX.4.4");
        let garbage: &[u8] = b"garbage that ends on a delimiter\x01";
        let more: &[u8] = b"and more garbage, then ";

        let split = feed(session(), &[garbage, more, &good]);
        let whole = feed(session(), &[&[garbage, more, &good[..]].concat()]);
        assert_eq!(split, whole);
        assert_eq!(whole, (vec![good.clone()], 1, Vec::new()));

        let mut codec = session();
        let mut buf = BytesMut::from(garbage);
        assert!(matches!(codec.decode(&mut buf), Ok(None)));
        assert!(buf.is_empty());
        buf.extend_from_slice(b"8=FIX.4.");
        assert!(matches!(codec.decode(&mut buf), Ok(None)));
        assert_eq!(&buf[..], b"8=FIX.4.", "a partial opening is kept");
        buf.extend_from_slice(b"2\x019=5\x0135=0\x0110=000\x01");
        buf.extend_from_slice(&good);
        assert_eq!(&decode_frame(&mut codec, &mut buf)[..], &good[..]);
        assert!(buf.is_empty());
        assert_eq!(codec.take_garbled_count(), 1, "one garbled span");
    }

    #[test]
    fn test_recovery_without_an_anchor_frames_the_next_read_after_a_plausible_boundary() {
        // The one configuration the read-start judgement cannot apply to: a
        // codec restricted to a BeginString outside the FIX family has no
        // anchor to compare with, so a resync never lands inside a buffer and
        // a read that starts after a plausible boundary is framed as it is.
        // Pinned as documented on `with_begin_string`.
        let good = make_fix_message("35=0\x0149=A\x01");
        let mut codec = recovering().with_begin_string("NOT.FIX");
        let mut buf = BytesMut::from(&b"garbage that ends on a delimiter\x01"[..]);
        assert!(matches!(codec.decode(&mut buf), Ok(None)));
        assert!(buf.is_empty());
        buf.extend_from_slice(&good);
        assert_eq!(&decode_frame(&mut codec, &mut buf)[..], &good[..]);
        assert_eq!(codec.take_garbled_count(), 1);
    }

    #[test]
    fn test_with_begin_string_selects_the_session_anchor() {
        let only = |codec: FixCodec| codec.recovery_anchors.to_vec();
        assert_eq!(
            only(FixCodec::new().with_begin_string("FIX.4.2")),
            vec![&b"8=FIX.4.2\x019="[..]]
        );
        assert_eq!(
            only(FixCodec::new().with_begin_string("FIXT.1.1")),
            vec![&b"8=FIXT.1.1\x019="[..]]
        );
        assert_eq!(only(FixCodec::new()).len(), RECOVERY_ANCHORS.len());
        // An unrecognised BeginString leaves no anchor at all.
        assert!(only(FixCodec::new().with_begin_string("FIX.5.0")).is_empty());

        // No real frame of the session is lost: garbage then a frame of the
        // session's version is still recovered in the same buffer.
        let mut codec = recovering().with_begin_string("FIX.4.4");
        let good = make_fix_message("35=0\x0149=A\x01");
        let mut buf = BytesMut::from(&b"\x00garbage!\xff"[..]);
        buf.extend_from_slice(&good);
        assert_eq!(&decode_frame(&mut codec, &mut buf)[..], &good[..]);

        // With no anchor, a resync never lands inside the buffer: the frame
        // behind the garbage is discarded with it.
        let mut codec = recovering().with_begin_string("NOT.FIX");
        let mut buf = BytesMut::from(&b"\x00garbage!\xff"[..]);
        buf.extend_from_slice(&good);
        assert!(matches!(codec.decode(&mut buf), Ok(None)));
        assert!(buf.is_empty());
    }

    #[test]
    fn test_recovery_execution_report_with_8xx_tags_counts_once() {
        // One ExecutionReport whose BodyLength is wrong, carrying tags 851, 828
        // and 880. Each of them is an `8` after an SOH; a bare `<SOH>8` anchor
        // resynchronised onto every one and counted it, so a limit of 3 logged
        // the session out over a single garbled fill.
        let mut codec = recovering();
        let good = make_fix_message("35=0\x0149=A\x01");
        let mut buf = BytesMut::from(
            &b"8=FIX.4.4\x019=3\x0135=8\x0137=1\x01851=1\x01828=0\x01880=X\x0110=000\x01"[..],
        );
        buf.extend_from_slice(&good);

        let mut frames = Vec::new();
        assert_eq!(drain(&mut codec, &mut buf, &mut frames), None);
        let got: Vec<&[u8]> = frames.iter().map(|frame| &frame[..]).collect();
        assert_eq!(got, vec![&good[..]]);
        assert_eq!(codec.take_garbled_count(), 1);
    }

    #[test]
    fn test_recovery_frame_embedded_in_a_data_field_is_not_delivered() {
        // A complete, checksum-valid frame inside RawData (96) or XmlData (213)
        // of a garbled outer frame. The outer BodyLength is wrong, so the codec
        // resyncs through the outer body; the embedded frame follows `=` and
        // must never be resynchronised onto and handed up as a phantom.
        let inner = make_fix_message("35=0\x0149=X\x0156=Y\x0134=99\x01");
        for (length_tag, data_tag) in [(95u32, 96u32), (212, 213)] {
            let mut outer = format!(
                "8=FIX.4.4\x019=5\x0135=D\x01{length_tag}={}\x01",
                inner.len()
            )
            .into_bytes();
            outer.extend_from_slice(format!("{data_tag}=").as_bytes());
            outer.extend_from_slice(&inner);
            outer.extend_from_slice(b"\x0110=000\x01");
            let good = make_fix_message("35=1\x0149=A\x01112=PING\x01");

            let mut codec = recovering();
            let mut buf = BytesMut::from(&outer[..]);
            buf.extend_from_slice(&good);
            let mut frames = Vec::new();
            assert_eq!(drain(&mut codec, &mut buf, &mut frames), None);

            let got: Vec<&[u8]> = frames.iter().map(|frame| &frame[..]).collect();
            assert_eq!(got, vec![&good[..]], "data tag {data_tag}");
            assert_eq!(codec.take_garbled_count(), 1, "data tag {data_tag}");
        }
    }

    #[test]
    fn test_recovery_keeps_a_partial_anchor_tail_for_the_next_read() {
        let mut codec = recovering();
        let good = make_fix_message("35=0\x0149=A\x01");
        let mut buf = BytesMut::from(&b"some garbage text 8=FI"[..]);

        assert!(matches!(codec.decode(&mut buf), Ok(None)));
        assert_eq!(&buf[..], b"8=FI", "the tail may still become a frame start");
        assert_eq!(codec.take_garbled_count(), 1);

        let Some(rest) = good.get(4..) else {
            panic!("the frame is longer than its anchor");
        };
        buf.extend_from_slice(rest);
        let frame = decode_frame(&mut codec, &mut buf);
        assert_eq!(&frame[..], &good[..]);
    }

    #[test]
    fn test_recovery_garbage_ending_in_soh_split_across_reads_counts_once() {
        // The garbage arrives in one read and ends on an SOH; the frame arrives
        // in the next. Keeping that SOH would make the frame's start look
        // garbled and count the same garbage twice.
        let mut codec = recovering();
        let good = make_fix_message("35=0\x0149=A\x01");
        let mut buf = BytesMut::from(&b"garbage that ends on a delimiter\x01"[..]);

        assert!(matches!(codec.decode(&mut buf), Ok(None)));
        assert!(buf.is_empty());

        buf.extend_from_slice(&good);
        let frame = decode_frame(&mut codec, &mut buf);
        assert_eq!(&frame[..], &good[..]);
        assert_eq!(codec.take_garbled_count(), 1);
    }

    #[test]
    fn test_recovery_resync_offset_anchors() {
        // A complete header opening after garbage, after an SOH, or for every
        // BeginString in the family is a candidate.
        assert_eq!(
            recovery_resync_offset(b"xx8=FIX.4.4\x019=5\x01", &RECOVERY_ANCHORS),
            2
        );
        assert_eq!(
            recovery_resync_offset(b"x\x018=FIX.4.0\x019=5\x01", &RECOVERY_ANCHORS),
            2
        );
        assert_eq!(
            recovery_resync_offset(b"x 8=FIXT.1.1\x019=5\x01", &RECOVERY_ANCHORS),
            2
        );
        // None of the following holds a candidate, so all of it goes:
        let no_candidate: [&[u8]; 7] = [
            // tags that start with 8 after an SOH, however many;
            b"x\x01851=1\x01828=0\x01880=X\x01",
            // an opening inside a field value or a tag (`=` or a digit before);
            b"x\x01213=8=FIX.4.4\x019=5\x01",
            b"x\x01448=FIX.4.4\x019=5\x01",
            b"x 58=1 18=2\x01",
            // an unknown BeginString, or an opening without `<SOH>9=`;
            b"x 8=FIX.9.9\x019=5\x01",
            b"x 8=FIX.4.4\x0135=0\x01",
            // offset 0, which is the frame that failed.
            b"8=FIX.4.4\x019=5\x01",
        ];
        for input in no_candidate {
            assert_eq!(
                recovery_resync_offset(input, &RECOVERY_ANCHORS),
                input.len(),
                "{input:?}"
            );
        }
        // A partial opening cut off by the end of the buffer is kept for the
        // next read; anything else goes. A trailing SOH is not kept.
        assert_eq!(recovery_resync_offset(b"abc8=", &RECOVERY_ANCHORS), 3);
        assert_eq!(
            recovery_resync_offset(b"abc 8=FIX.4.4\x01", &RECOVERY_ANCHORS),
            4
        );
        assert_eq!(recovery_resync_offset(b"abc8=FOO", &RECOVERY_ANCHORS), 8);
        assert_eq!(recovery_resync_offset(b"abc\x01", &RECOVERY_ANCHORS), 4);
        assert_eq!(recovery_resync_offset(b"abcdef", &RECOVERY_ANCHORS), 6);
        // Progress is guaranteed for every buffer of two or more bytes.
        for input in [&b"8="[..], b"8\x01", b"\x01\x01", b"88", b"8=FIX", b"8=FI"] {
            assert!(
                recovery_resync_offset(input, &RECOVERY_ANCHORS) >= 1,
                "{input:?}"
            );
        }
    }

    #[test]
    fn test_anchor_shape_and_boundary_classify_candidates() {
        assert_eq!(
            anchor_shape(b"8=FIX.4.2\x019=12\x01", &RECOVERY_ANCHORS),
            AnchorShape::Complete
        );
        assert_eq!(
            anchor_shape(b"8=FIXT.1.1\x019=", &RECOVERY_ANCHORS),
            AnchorShape::Complete
        );
        assert_eq!(
            anchor_shape(b"8=FIX.4", &RECOVERY_ANCHORS),
            AnchorShape::Partial
        );
        assert_eq!(anchor_shape(b"8", &RECOVERY_ANCHORS), AnchorShape::Partial);
        assert_eq!(
            anchor_shape(b"851=1", &RECOVERY_ANCHORS),
            AnchorShape::Rejected
        );
        assert_eq!(
            anchor_shape(b"8=FIX.4.4\x0135=", &RECOVERY_ANCHORS),
            AnchorShape::Rejected
        );

        assert!(boundary_before(None));
        assert!(boundary_before(Some(SOH)));
        assert!(boundary_before(Some(b'!')));
        assert!(boundary_before(Some(0xff)));
        assert!(!boundary_before(Some(b'=')));
        assert!(!boundary_before(Some(b'4')));
    }

    #[test]
    fn test_recovery_soh_free_header_fed_byte_by_byte_stays_bounded() {
        // The recovery-mode version of
        // `test_decode_soh_free_header_is_bounded_and_never_asks_for_more`: the
        // buffer must stay bounded and the codec must never return an error.
        let mut codec = recovering();
        let mut buf = BytesMut::from(&b"8="[..]);
        for _ in 0..4096 {
            buf.extend_from_slice(b"X");
            match codec.decode(&mut buf) {
                Ok(None) => {}
                other => panic!("garbage must be skipped quietly, got {other:?}"),
            }
            assert!(
                buf.len() <= MAX_HEADER_LEN,
                "buffer grew to {} bytes",
                buf.len()
            );
        }
        assert!(codec.take_garbled_count() >= 1);
    }

    #[test]
    fn test_recovery_byte_by_byte_feed_reassembles_one_message() {
        let mut codec = recovering();
        let msg = make_fix_message("35=A\x0149=SENDER\x0156=TARGET\x0198=0\x01108=30\x01");
        let mut buf = BytesMut::new();
        let mut frames = Vec::new();
        for byte in &msg {
            buf.extend_from_slice(&[*byte]);
            assert_eq!(drain(&mut codec, &mut buf, &mut frames), None);
        }
        assert_eq!(frames.len(), 1);
        assert_eq!(frames.first().map(|f| &f[..]), Some(&msg[..]));
        assert_eq!(codec.take_garbled_count(), 0);
    }

    #[test]
    fn test_recovery_hostile_header_does_not_discard_the_frames_that_follow() {
        // The recovery-mode version of
        // `test_decode_invalid_trailer_does_not_discard_the_frames_that_follow`.
        let good = b"8=FIX.4.4\x019=15\x0135=0\x0149=A\x0156=B\x0110=171\x01";
        let mut raw = Vec::from(&b"8=FIX.4.4\x019=222\x0135=0\x01"[..]);
        for _ in 0..6 {
            raw.extend_from_slice(good);
        }
        let padding: &[u8] = b"\x01\x01\x01\x01\x01\x01\x01";
        raw.extend_from_slice(padding);
        let mut buf = BytesMut::from(&raw[..]);

        let mut codec = recovering();
        let mut frames = Vec::new();
        assert_eq!(drain(&mut codec, &mut buf, &mut frames), None);
        assert_eq!(frames.len(), 6);
        assert!(frames.iter().all(|frame| frame[..] == good[..]));
        assert_eq!(codec.take_garbled_count(), 1);
    }

    #[test]
    fn test_recovery_every_single_byte_corruption_is_skipped_and_the_rest_survives() {
        // Property sweep: corrupt every byte of the first frame with every byte
        // that matters to the framer. Whatever the corruption, the codec must
        // not panic, must not report an error, must settle, must never hand up
        // the corrupted frame, must count it exactly once, and must deliver
        // every frame after it intact. B is long enough that no single-byte
        // change to A's BodyLength can reach B's trailer, so B's survival is
        // part of the property, with one designed exception: when A's final
        // SOH becomes a digit or `=`, B's opening no longer follows a plausible
        // frame boundary, so the resync passes over it (B's gap is then
        // recovered by ResendRequest like any other).
        let a = make_fix_message("35=0\x0149=A\x0156=B\x01");
        let b = make_fix_message(&format!("35=0\x0149=B\x0158={}\x01", "t".repeat(120)));
        let c = make_fix_message("35=1\x0149=C\x01112=PING\x01");
        let filler = make_fix_message("35=0\x0149=D\x01");
        let replacements = [0x00, SOH, b'8', b'=', b'9', b'1', b'0', b'X', 0xff];

        for index in 0..a.len() {
            for &replacement in &replacements {
                let Some(&original) = a.get(index) else {
                    panic!("index {index} is inside the frame");
                };
                if original == replacement {
                    continue;
                }
                let mut corrupted = a.clone();
                if let Some(byte) = corrupted.get_mut(index) {
                    *byte = replacement;
                }

                let mut codec = recovering().with_max_message_size(4096);
                let mut buf = BytesMut::from(&corrupted[..]);
                buf.extend_from_slice(&b);
                buf.extend_from_slice(&c);
                let mut frames = Vec::new();
                let first = drain(&mut codec, &mut buf, &mut frames);
                // A corrupted BodyLength may declare a span longer than what is
                // buffered; more traffic is what lets the codec decide.
                for _ in 0..8 {
                    buf.extend_from_slice(&filler);
                }
                let second = drain(&mut codec, &mut buf, &mut frames);

                let context = format!("byte {index} -> 0x{replacement:02x}");
                assert_eq!(first, None, "{context}: recovery must not error");
                assert_eq!(second, None, "{context}: recovery must not error");
                let b_hidden =
                    index + 1 == a.len() && (replacement.is_ascii_digit() || replacement == b'=');
                let mut expected: Vec<&[u8]> = if b_hidden {
                    vec![&c[..]]
                } else {
                    vec![&b[..], &c[..]]
                };
                expected.extend(std::iter::repeat_n(&filler[..], 8));
                let got: Vec<&[u8]> = frames.iter().map(|frame| &frame[..]).collect();
                assert_eq!(got, expected, "{context}");
                assert_eq!(
                    codec.take_garbled_count(),
                    1,
                    "{context}: A is skipped exactly once"
                );
                assert!(buf.is_empty(), "{context}: {} bytes left", buf.len());
            }
        }
    }

    #[test]
    fn test_decode_every_single_byte_corruption_without_recovery_is_a_recoverable_error() {
        // The same sweep without recovery: never a panic, and the error is
        // always one recovery would have skipped, so turning recovery on can
        // only ever change an error into a skip.
        let a = make_fix_message("35=0\x0149=A\x0156=B\x01");
        let b = make_fix_message("35=1\x0149=C\x01112=PING\x01");
        let replacements = [0x00, SOH, b'8', b'=', b'9', b'1', b'0', b'X', 0xff];
        for index in 0..a.len() {
            for &replacement in &replacements {
                let mut corrupted = a.clone();
                if let Some(byte) = corrupted.get_mut(index) {
                    if *byte == replacement {
                        continue;
                    }
                    *byte = replacement;
                }
                let mut codec = FixCodec::new().with_max_message_size(4096);
                let mut buf = BytesMut::from(&corrupted[..]);
                buf.extend_from_slice(&b);
                for _ in 0..4 {
                    buf.extend_from_slice(&b);
                }
                let mut frames = Vec::new();
                if let Some(error) = drain(&mut codec, &mut buf, &mut frames) {
                    assert!(
                        error.is_recoverable(),
                        "byte {index} -> 0x{replacement:02x}: {error:?}"
                    );
                }
                assert!(
                    frames.iter().all(|frame| frame[..] != corrupted[..]),
                    "byte {index} -> 0x{replacement:02x}: the corrupted frame was handed up"
                );
            }
        }
    }

    #[test]
    fn test_decode_every_truncation_point_reassembles_in_both_modes() {
        let a = make_fix_message("35=0\x0149=A\x0156=B\x01");
        let b = make_fix_message("35=1\x0149=C\x01112=PING\x01");
        let c = make_fix_message("35=0\x0149=D\x01");
        let stream: Vec<u8> = [&a[..], &b[..], &c[..]].concat();

        for recovery in [false, true] {
            for cut in 0..=stream.len() {
                let (Some(head), Some(tail)) = (stream.get(..cut), stream.get(cut..)) else {
                    panic!("cut {cut} is inside the stream");
                };
                let mut codec = FixCodec::new().with_garbled_recovery(recovery);
                let mut buf = BytesMut::from(head);
                let mut frames = Vec::new();
                assert_eq!(drain(&mut codec, &mut buf, &mut frames), None);
                buf.extend_from_slice(tail);
                assert_eq!(drain(&mut codec, &mut buf, &mut frames), None);

                let got: Vec<&[u8]> = frames.iter().map(|frame| &frame[..]).collect();
                assert_eq!(
                    got,
                    vec![&a[..], &b[..], &c[..]],
                    "recovery={recovery} cut={cut}"
                );
                assert_eq!(codec.take_garbled_count(), 0, "recovery={recovery}");
            }
        }
    }

    #[test]
    fn test_recovery_byte_by_byte_garbled_stream_recovers_every_valid_frame() {
        let a = make_fix_message("35=0\x0149=A\x01");
        let b = make_fix_message("35=0\x0149=B\x01");
        let c = make_fix_message("35=0\x0149=C\x01");
        let mut stream = Vec::new();
        stream.extend_from_slice(b"\x00\x7fjunk-bytes\xff");
        stream.extend_from_slice(&a);
        stream.extend_from_slice(&make_bad_checksum_message("35=0\x0149=X\x01"));
        stream.extend_from_slice(&b);
        stream.extend_from_slice(b"more junk, with ; punctuation");
        stream.extend_from_slice(&c);

        let mut codec = recovering();
        let mut buf = BytesMut::new();
        let mut frames = Vec::new();
        for byte in &stream {
            buf.extend_from_slice(&[*byte]);
            assert_eq!(drain(&mut codec, &mut buf, &mut frames), None);
            assert!(buf.len() <= MAX_HEADER_LEN.max(c.len()));
        }
        let got: Vec<&[u8]> = frames.iter().map(|frame| &frame[..]).collect();
        assert_eq!(got, vec![&a[..], &b[..], &c[..]]);
        assert!(codec.take_garbled_count() >= 3);
    }

    #[test]
    fn test_recovery_anchor_floods_settle_in_one_call_and_stay_bounded() {
        // Buffers dense in near-anchors: every `8=FIX`, every `<SOH>8`, every
        // `8=FIX.4.4<SOH>` without its `9=`. Each one is rejected inside the
        // resync scan, so one call settles, leaves a bounded remainder (the
        // final partial opening), returns nothing, and counts the whole buffer
        // as a single garbled span.
        for unit in [&b"8=FIX"[..], b"\x018", b"8=FIX.4.4\x01"] {
            let mut codec = recovering();
            let mut buf = BytesMut::new();
            for _ in 0..20_000 {
                buf.extend_from_slice(unit);
            }
            assert!(matches!(codec.decode(&mut buf), Ok(None)), "{unit:?}");
            assert!(
                buf.len() < MAX_HEADER_LEN,
                "{unit:?}: {} bytes left",
                buf.len()
            );
            assert_eq!(codec.take_garbled_count(), 1, "{unit:?}");
        }
    }

    #[test]
    fn test_recovery_seeded_noise_never_panics_and_only_hands_up_real_frames() {
        // Deterministic noise (xorshift, fixed seed) drawn from an alphabet
        // heavy in the bytes the framer cares about, interleaved with one known
        // frame. Every frame handed up must be that frame, byte for byte.
        let good = make_fix_message("35=0\x0149=A\x0156=B\x01");
        let alphabet: &[u8] = b"8=FIX.4\x019\x0110=35";
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        let mut stream = Vec::new();
        let rounds = 300;
        // Frames whose opening follows a plausible boundary: no noise before
        // them, or noise that ends in neither a digit nor `=`. A frame after a
        // digit or `=` is passed over by design (it is indistinguishable from
        // `448=FIX…` or `96=8=FIX…`), so only these can be expected back.
        let mut eligible = 0usize;
        for _ in 0..rounds {
            let noise_len = next() % 48;
            let mut last = None;
            for _ in 0..noise_len {
                let pick = usize::try_from(next() % 15).unwrap_or(0);
                let byte = alphabet.get(pick).copied().unwrap_or(b'X');
                stream.push(byte);
                last = Some(byte);
            }
            if last.is_none_or(|byte| boundary_before(Some(byte))) {
                eligible += 1;
            }
            stream.extend_from_slice(&good);
        }

        let mut codec = recovering().with_max_message_size(4096);
        let mut buf = BytesMut::from(&stream[..]);
        let mut frames = Vec::new();
        assert_eq!(drain(&mut codec, &mut buf, &mut frames), None);
        assert!(frames.iter().all(|frame| frame[..] == good[..]));
        assert!(frames.len() <= rounds);
        assert!(
            eligible * 4 >= rounds,
            "the seed must leave enough eligible frames to mean something"
        );
        // Not every eligible frame need survive either: noise that happens to
        // spell a header whose declared BodyLength lands exactly on the next
        // frame's `<SOH>10=NNN<SOH>` has a corroborated boundary, and a checksum
        // error consumes that whole declared span, frame included. With this
        // seed all 117 eligible frames (of 300) survive; the bound leaves room
        // for that policy without letting a resync regression go unnoticed.
        assert!(
            frames.len() * 10 >= eligible * 9,
            "only {} of {eligible} eligible frames survived the noise",
            frames.len()
        );
    }
}
