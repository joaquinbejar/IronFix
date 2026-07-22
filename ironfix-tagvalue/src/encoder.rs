/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! FIX message encoder.
//!
//! [`Encoder`] builds a complete tag=value frame —
//! `8=<BeginString><SOH>9=<BodyLength><SOH>` … `10=<CheckSum><SOH>` — in one
//! buffer.
//!
//! # The frame is assembled once
//!
//! `BodyLength` (tag 9) is not known until the body is complete, which is why
//! a header cannot simply be written first. Instead the buffer opens with
//! a fixed, worst-case-sized run of unused bytes and the body is written after
//! them; [`Encoder::finish`] formats the header into the **tail** of that
//! reserved prefix, so the header ends exactly where the body begins and the
//! frame is contiguous. Nothing is copied and no intermediate buffer exists.
//! [`Encoder::clear`] rewinds to that same starting state with the buffer's
//! capacity retained, so a long-lived encoder encodes without allocating.
//!
//! # A rejected value never reaches the wire
//!
//! An application string carrying a SOH byte would terminate its own field
//! early and let the rest of the value inject tag/value pairs into the frame —
//! with a `BodyLength` and `CheckSum` correct for the corrupted bytes, so the
//! counterparty accepts it. The encoder therefore refuses such a value, along
//! with an empty one, tag `0`, and the framing tags it stamps itself.
//!
//! The `put_*` methods stay infallible and **record** the first rejection;
//! [`Encoder::finish`] returns it and yields no bytes. That is deliberate: a
//! fallible `put_*` whose `Result` a caller drops would silently omit the
//! field and produce a well-formed frame that is missing data, which is the
//! harder failure to notice. Callers that want the rejection at the point of
//! the write can use [`Encoder::try_put_raw`] / [`Encoder::try_put_data`], or
//! read [`Encoder::error`].
//!
//! # `DATA` fields
//!
//! A FIX `DATA` field (`RawData`/96, `Signature`/89, the `Encoded*` family)
//! legally contains SOH and `=`; it is decodable only because its paired
//! `LENGTH` field declares its byte count. [`Encoder::put_data`] emits the
//! pair together and derives the count from the value, so the two cannot
//! disagree. Writing either half through [`Encoder::put_raw`] is refused.

use crate::checksum::{calculate_checksum, format_checksum};
use crate::decoder::{is_data_tag, paired_data_tag};
pub use crate::{EQUALS, SOH};
use bytes::{BufMut, BytesMut};
use ironfix_core::error::{EncodeError, MsgTypeError};
use ironfix_core::message::MsgType;
use memchr::memchr;

/// Maximum length of a `BeginString` (tag 8) value in bytes.
///
/// Every `BeginString` the FIX family defines is at most ten bytes
/// (`FIX.5.0SP2`), and the longest that actually reaches the wire is
/// `FIXT.1.1`. Like [`ironfix_core::types::COMP_ID_MAX_LEN`] this bound is an
/// IronFix engineering choice, not a specification limit: it is what lets the
/// value live inline in the encoder and what bounds the reserved header
/// prefix. A longer value is [`EncodeError::FieldTooLong`], never a truncation.
pub const BEGIN_STRING_MAX_LEN: usize = 16;

/// Maximum number of digits a `BodyLength` (tag 9) value can need.
///
/// `usize::MAX` is 20 decimal digits on a 64-bit target, so no body length is
/// longer than this and the reserved header prefix can never be too small.
const MAX_BODY_LENGTH_DIGITS: usize = 20;

/// Bytes reserved at the front of the buffer for `8=…<SOH>9=…<SOH>`.
///
/// The worst case exactly: `8=` + a [`BEGIN_STRING_MAX_LEN`]-byte BeginString
/// + SOH + `9=` + [`MAX_BODY_LENGTH_DIGITS`] digits + SOH.
const HEADER_RESERVE: usize = 2 + BEGIN_STRING_MAX_LEN + 1 + 2 + MAX_BODY_LENGTH_DIGITS + 1;

/// Length of the `10=NNN<SOH>` trailer in bytes.
const TRAILER_LEN: usize = 7;

/// Default body capacity of a new encoder, in bytes.
const DEFAULT_BODY_CAPACITY: usize = 256;

/// FIX message encoder.
///
/// The encoder appends body fields in tag=value form and stamps
/// `BeginString` (8), `BodyLength` (9) and `CheckSum` (10) itself.
///
/// # Example
///
/// ```
/// use ironfix_tagvalue::Encoder;
///
/// let mut encoder = Encoder::new("FIX.4.4");
/// encoder.put_str(35, "0");
/// encoder.put_str(49, "SENDER");
/// let frame = encoder.finish()?;
/// assert!(frame.starts_with(b"8=FIX.4.4\x01"));
/// # Ok::<(), ironfix_core::error::EncodeError>(())
/// ```
#[derive(Debug)]
pub struct Encoder {
    /// Frame buffer: `HEADER_RESERVE` bytes of header space, then the body,
    /// then the trailer once [`Encoder::finish`] has stamped it.
    buf: BytesMut,
    /// Validated `BeginString` bytes, held inline.
    begin_string: [u8; BEGIN_STRING_MAX_LEN],
    /// Number of leading bytes of `begin_string` in use.
    begin_string_len: usize,
    /// Bytes of body written so far — the value stamped into tag 9.
    body_len: usize,
    /// Tag of the first body field, which FIX requires to be MsgType (35).
    first_tag: Option<u32>,
    /// Offset of the frame's first byte once the header has been stamped.
    frame_start: Option<usize>,
    /// Rejection recorded when the `BeginString` was set.
    ///
    /// Survives [`Encoder::clear`]: an encoder built with an unusable
    /// BeginString cannot frame any message, not just the current one.
    begin_string_error: Option<EncodeError>,
    /// First rejected write of the current message, cleared by
    /// [`Encoder::clear`].
    error: Option<EncodeError>,
}

impl Encoder {
    /// Creates a new encoder with the specified `BeginString`.
    ///
    /// A `BeginString` that is empty, longer than [`BEGIN_STRING_MAX_LEN`], or
    /// carries a byte that cannot appear in tag 8 is recorded and reported by
    /// [`Encoder::finish`]; no such frame is ever produced.
    ///
    /// # Arguments
    /// * `begin_string` - The FIX version string (e.g., "FIX.4.4")
    #[must_use]
    pub fn new(begin_string: &str) -> Self {
        Self::with_capacity(begin_string, DEFAULT_BODY_CAPACITY)
    }

    /// Creates a new encoder with a pre-allocated body capacity.
    ///
    /// The buffer is sized for `capacity` bytes of body plus the reserved
    /// header prefix and the trailer, so a message whose body fits in
    /// `capacity` is encoded without the buffer growing.
    ///
    /// # Arguments
    /// * `begin_string` - The FIX version string
    /// * `capacity` - Expected body size in bytes
    #[must_use]
    pub fn with_capacity(begin_string: &str, capacity: usize) -> Self {
        let total = match HEADER_RESERVE
            .checked_add(capacity)
            .and_then(|n| n.checked_add(TRAILER_LEN))
        {
            Some(total) => total,
            // A capacity this close to `usize::MAX` cannot be allocated
            // anyway; fall back to the frame overhead alone rather than
            // wrapping into a small one.
            None => HEADER_RESERVE + TRAILER_LEN,
        };

        let mut buf = BytesMut::with_capacity(total);
        buf.resize(HEADER_RESERVE, 0);

        let mut encoder = Self {
            buf,
            begin_string: [0; BEGIN_STRING_MAX_LEN],
            begin_string_len: 0,
            body_len: 0,
            first_tag: None,
            frame_start: None,
            begin_string_error: None,
            error: None,
        };

        match copy_begin_string(begin_string, &mut encoder.begin_string) {
            Ok(len) => encoder.begin_string_len = len,
            Err(err) => encoder.begin_string_error = Some(err),
        }

        encoder
    }

    /// Appends a field with a string value.
    ///
    /// A rejected value is recorded and surfaced by [`Encoder::finish`]; see
    /// [`Encoder::try_put_raw`] for the exact preconditions.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    /// * `value` - The field value
    #[inline]
    pub fn put_str(&mut self, tag: u32, value: &str) {
        self.put_raw(tag, value.as_bytes());
    }

    /// Appends a field with an integer value.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    /// * `value` - The field value
    #[inline]
    pub fn put_int(&mut self, tag: u32, value: i64) {
        let mut buf = itoa::Buffer::new();
        let s = buf.format(value);
        self.put_raw(tag, s.as_bytes());
    }

    /// Appends a field with an unsigned integer value.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    /// * `value` - The field value
    #[inline]
    pub fn put_uint(&mut self, tag: u32, value: u64) {
        let mut buf = itoa::Buffer::new();
        let s = buf.format(value);
        self.put_raw(tag, s.as_bytes());
    }

    /// Appends a field with a boolean value (Y/N).
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    /// * `value` - The field value
    #[inline]
    pub fn put_bool(&mut self, tag: u32, value: bool) {
        self.put_raw(tag, if value { b"Y" } else { b"N" });
    }

    /// Appends a field with a single character value.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    /// * `value` - The field value
    #[inline]
    pub fn put_char(&mut self, tag: u32, value: char) {
        let mut buf = [0u8; 4];
        let s = value.encode_utf8(&mut buf);
        self.put_raw(tag, s.as_bytes());
    }

    /// Appends a field with raw bytes.
    ///
    /// A rejected value is recorded and surfaced by [`Encoder::finish`]; see
    /// [`Encoder::try_put_raw`] for the exact preconditions.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    /// * `value` - The field value bytes
    #[inline]
    pub fn put_raw(&mut self, tag: u32, value: &[u8]) {
        if let Err(err) = self.try_put_raw(tag, value) {
            self.record(err);
        }
    }

    /// Appends a field with raw bytes, reporting a rejection immediately.
    ///
    /// Nothing is written when this returns `Err`, and the rejection is **not**
    /// recorded: the caller has it.
    ///
    /// # Arguments
    /// * `tag` - The field tag number
    /// * `value` - The field value bytes
    ///
    /// # Errors
    /// [`EncodeError::InvalidFieldValue`] if:
    /// * `tag` is `0`, which is not a legal FIX tag;
    /// * `tag` is `8`, `9` or `10` — the framing fields [`Encoder::finish`]
    ///   stamps itself, so a second copy would break the frame;
    /// * `tag` is a `LENGTH` or `DATA` field of a spec-defined pair, which must
    ///   be written together through [`Encoder::put_data`];
    /// * `value` is empty, which FIX rejects as "tag specified without a
    ///   value";
    /// * `value` contains SOH, which would terminate the field early and let
    ///   the remainder inject fields into the frame;
    /// * `tag` is 35 and `value` is not a code
    ///   [`ironfix_core::message::MsgType`] can represent;
    /// * the frame is already finished — call [`Encoder::clear`] first.
    ///
    /// [`EncodeError::FieldTooLong`] if `tag` is 35 and `value` exceeds
    /// [`ironfix_core::message::MSG_TYPE_MAX_LEN`].
    ///
    /// A `=` byte inside a value is **accepted**: a decoder splits a field at
    /// its first `=`, so `58=a=b` reads back as the value `a=b`, and Text
    /// fields legitimately carry it.
    pub fn try_put_raw(&mut self, tag: u32, value: &[u8]) -> Result<(), EncodeError> {
        self.check_open(tag)?;
        check_body_tag(tag)?;
        if value.is_empty() {
            return Err(empty_value(tag));
        }
        if let Some(position) = memchr(SOH, value) {
            return Err(soh_in_value(tag, position));
        }
        if tag == 35 {
            check_msg_type(value)?;
        }
        self.write_field(tag, value);
        Ok(())
    }

    /// Appends a `LENGTH`/`DATA` field pair.
    ///
    /// Emits `length_tag=<value.len()><SOH>data_tag=<value><SOH>`. The count is
    /// derived from `value`, so the declared length and the payload cannot
    /// disagree, and `value` may contain SOH and `=` — that is what the pair
    /// exists for.
    ///
    /// A rejected pair is recorded and surfaced by [`Encoder::finish`]; see
    /// [`Encoder::try_put_data`] for the exact preconditions.
    ///
    /// # Arguments
    /// * `length_tag` - The `LENGTH` field tag (e.g., 95 `RawDataLength`)
    /// * `data_tag` - The paired `DATA` field tag (e.g., 96 `RawData`)
    /// * `value` - The raw payload; at least one byte
    #[inline]
    pub fn put_data(&mut self, length_tag: u32, data_tag: u32, value: &[u8]) {
        if let Err(err) = self.try_put_data(length_tag, data_tag, value) {
            self.record(err);
        }
    }

    /// Appends a `LENGTH`/`DATA` field pair, reporting a rejection immediately.
    ///
    /// Nothing is written when this returns `Err`.
    ///
    /// # Arguments
    /// * `length_tag` - The `LENGTH` field tag (e.g., 95 `RawDataLength`)
    /// * `data_tag` - The paired `DATA` field tag (e.g., 96 `RawData`)
    /// * `value` - The raw payload; at least one byte
    ///
    /// # Errors
    /// [`EncodeError::InvalidFieldValue`] if either tag is `0`, if `data_tag`
    /// is not the `DATA` field the FIX specification pairs with `length_tag`,
    /// if `value` is empty, or if the frame is already finished. An unpaired
    /// combination is refused because a decoder frames a `DATA` value by the
    /// count in *its own* paired `LENGTH` field: under any other tag the
    /// payload's SOH bytes are read as field terminators. An empty payload is
    /// refused for the same reason an ordinary empty value is — FIX treats a
    /// tag specified without a value as malformed.
    pub fn try_put_data(
        &mut self,
        length_tag: u32,
        data_tag: u32,
        value: &[u8],
    ) -> Result<(), EncodeError> {
        self.check_open(data_tag)?;
        check_tag(length_tag)?;
        check_tag(data_tag)?;
        if paired_data_tag(length_tag) != Some(data_tag) {
            return Err(unpaired_data_tag(length_tag, data_tag));
        }
        if value.is_empty() {
            return Err(empty_value(data_tag));
        }

        let mut len_buf = itoa::Buffer::new();
        let len_str = len_buf.format(value.len());
        self.write_field(length_tag, len_str.as_bytes());
        self.write_field(data_tag, value);
        Ok(())
    }

    /// Stamps the frame and returns it.
    ///
    /// Writes `8=<BeginString><SOH>9=<BodyLength><SOH>` into the reserved
    /// prefix so that it ends exactly where the body starts, then appends
    /// `10=<CheckSum><SOH>`. The returned slice borrows the encoder's own
    /// buffer: no intermediate buffer is allocated and the body is not moved.
    ///
    /// Calling it again returns the same frame; call [`Encoder::clear`] to
    /// start the next message.
    ///
    /// # Errors
    /// * The first rejection recorded by any `put_*` call, or by
    ///   [`Encoder::new`] for an unusable `BeginString`.
    /// * [`EncodeError::MissingRequiredField`] for tag 35 if no field was
    ///   written, or if the first body field is not `MsgType` — FIX fixes it as
    ///   the third field of every message, and a frame without it there is one
    ///   no decoder can route.
    pub fn finish(&mut self) -> Result<&[u8], EncodeError> {
        if let Some(err) = self.first_error() {
            return Err(err.clone());
        }
        if self.frame_start.is_none() {
            self.stamp()?;
        }
        let start = self.frame_start.ok_or_else(|| header_overflow(0))?;
        self.buf.get(start..).ok_or_else(|| header_overflow(start))
    }

    /// Stamps the frame and appends it to `dst`.
    ///
    /// For callers that need the frame in a buffer they own — a transport
    /// write queue, for instance. The encoder's own buffer is left holding the
    /// finished frame, so [`Encoder::clear`] still retains its capacity.
    ///
    /// # Arguments
    /// * `dst` - Buffer the frame is appended to
    ///
    /// # Errors
    /// The same rejections as [`Encoder::finish`]; `dst` is left untouched.
    pub fn finish_into(&mut self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        let frame = self.finish()?;
        dst.reserve(frame.len());
        dst.put_slice(frame);
        Ok(())
    }

    /// Returns the current body length in bytes — the value stamped into
    /// `BodyLength` (tag 9).
    #[inline]
    #[must_use]
    pub const fn body_len(&self) -> usize {
        self.body_len
    }

    /// Returns the first rejection recorded so far, if any.
    ///
    /// Lets a caller using the infallible `put_*` methods check before
    /// [`Encoder::finish`].
    #[inline]
    pub fn error(&self) -> Option<&EncodeError> {
        self.first_error()
    }

    /// Clears the encoder for the next message, retaining its capacity.
    ///
    /// A rejection recorded for the `BeginString` is **not** cleared: it makes
    /// every message this encoder could build unframeable, not just the one
    /// being discarded.
    #[inline]
    pub fn clear(&mut self) {
        self.buf.clear();
        self.buf.resize(HEADER_RESERVE, 0);
        self.body_len = 0;
        self.first_tag = None;
        self.frame_start = None;
        self.error = None;
    }

    /// Returns the construction rejection if there is one, else the first
    /// rejected write.
    #[inline]
    fn first_error(&self) -> Option<&EncodeError> {
        self.begin_string_error.as_ref().or(self.error.as_ref())
    }

    /// Records the first rejected write; later ones are dropped, since the
    /// frame is already unproducible and the first is the one that explains
    /// why.
    #[cold]
    #[inline(never)]
    fn record(&mut self, err: EncodeError) {
        if self.error.is_none() {
            self.error = Some(err);
        }
    }

    /// Rejects a write into a frame that has already been stamped.
    #[inline]
    fn check_open(&self, tag: u32) -> Result<(), EncodeError> {
        if self.frame_start.is_some() {
            return Err(already_finished(tag));
        }
        Ok(())
    }

    /// Appends `tag=value<SOH>` to the body. The caller has validated both.
    #[inline]
    fn write_field(&mut self, tag: u32, value: &[u8]) {
        let mut tag_buf = itoa::Buffer::new();
        let tag_str = tag_buf.format(tag);

        // The running body length is what gets stamped into tag 9, so it is
        // folded with checked arithmetic rather than recovered from the
        // buffer's length by subtraction. `+ 2` is `=` and SOH.
        let Some(body_len) = tag_str
            .len()
            .checked_add(value.len())
            .and_then(|n| n.checked_add(2))
            .and_then(|n| self.body_len.checked_add(n))
        else {
            self.record(body_overflow(value.len()));
            return;
        };

        self.buf.put_slice(tag_str.as_bytes());
        self.buf.put_u8(EQUALS);
        self.buf.put_slice(value);
        self.buf.put_u8(SOH);

        if self.first_tag.is_none() {
            self.first_tag = Some(tag);
        }
        self.body_len = body_len;
    }

    /// Writes the header into the reserved prefix and appends the trailer.
    fn stamp(&mut self) -> Result<(), EncodeError> {
        if self.first_tag != Some(35) {
            return Err(EncodeError::MissingRequiredField { tag: 35 });
        }

        let begin_string = self
            .begin_string
            .get(..self.begin_string_len)
            .ok_or_else(|| header_overflow(self.begin_string_len))?;

        let mut len_buf = itoa::Buffer::new();
        let body_len_str = len_buf.format(self.body_len);

        // `8=` + BeginString + SOH + `9=` + digits + SOH.
        let header_len = [2, begin_string.len(), 1, 2, body_len_str.len(), 1]
            .into_iter()
            .try_fold(0usize, usize::checked_add)
            .ok_or_else(|| header_overflow(usize::MAX))?;
        // Right-align the header so its last byte is the SOH immediately
        // before the body: that is what makes the frame contiguous without
        // moving the body.
        let frame_start = HEADER_RESERVE
            .checked_sub(header_len)
            .ok_or_else(|| header_overflow(header_len))?;

        {
            let slot = self
                .buf
                .get_mut(frame_start..HEADER_RESERVE)
                .ok_or_else(|| header_overflow(header_len))?;
            let mut written = 0usize;
            let overflow = || header_overflow(header_len);
            push_bytes(slot, &mut written, b"8=").ok_or_else(overflow)?;
            push_bytes(slot, &mut written, begin_string).ok_or_else(overflow)?;
            push_bytes(slot, &mut written, &[SOH]).ok_or_else(overflow)?;
            push_bytes(slot, &mut written, b"9=").ok_or_else(overflow)?;
            push_bytes(slot, &mut written, body_len_str.as_bytes()).ok_or_else(overflow)?;
            push_bytes(slot, &mut written, &[SOH]).ok_or_else(overflow)?;
        }

        let checksum = {
            let span = self
                .buf
                .get(frame_start..)
                .ok_or_else(|| header_overflow(header_len))?;
            calculate_checksum(span)
        };
        let digits = format_checksum(checksum);
        self.buf.put_slice(b"10=");
        self.buf.put_slice(&digits);
        self.buf.put_u8(SOH);

        self.frame_start = Some(frame_start);
        Ok(())
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new("FIX.4.4")
    }
}

/// Copies a validated `BeginString` into inline storage, returning its length.
///
/// Tag 8 opens every frame, so a value carrying SOH would make the very first
/// field of the message ambiguous. The charset matches
/// [`ironfix_core::message::MsgType`]: printable ASCII, no `=`.
///
/// # Errors
/// [`EncodeError::InvalidFieldValue`] for an empty value or an illegal byte,
/// [`EncodeError::FieldTooLong`] past [`BEGIN_STRING_MAX_LEN`].
fn copy_begin_string(
    value: &str,
    slot: &mut [u8; BEGIN_STRING_MAX_LEN],
) -> Result<usize, EncodeError> {
    if value.is_empty() {
        return Err(empty_value(8));
    }
    if value.len() > BEGIN_STRING_MAX_LEN {
        return Err(EncodeError::FieldTooLong {
            tag: 8,
            length: value.len(),
            max_length: BEGIN_STRING_MAX_LEN,
        });
    }
    for (position, &byte) in value.as_bytes().iter().enumerate() {
        if !byte.is_ascii_graphic() || byte == EQUALS {
            return Err(illegal_begin_string_byte(byte, position));
        }
    }
    slot.get_mut(..value.len())
        .ok_or_else(|| header_overflow(value.len()))?
        .copy_from_slice(value.as_bytes());
    Ok(value.len())
}

/// Rejects a `MsgType` (tag 35) value the decoder would refuse.
///
/// The decoder builds an [`MsgType`] out of tag 35 and rejects the whole frame
/// if the value is empty, over-long, or carries a byte that cannot appear
/// there, so emitting one would mean emitting a frame this crate's own decoder
/// will not read back. The check delegates to [`MsgType::new`] rather than
/// restating its rule, so the two cannot drift.
///
/// # Errors
/// [`EncodeError::FieldTooLong`] past
/// [`ironfix_core::message::MSG_TYPE_MAX_LEN`], otherwise
/// [`EncodeError::InvalidFieldValue`].
fn check_msg_type(value: &[u8]) -> Result<(), EncodeError> {
    // A legal MsgType is printable ASCII, so anything that fails UTF-8 here
    // would fail the byte check anyway.
    let Ok(code) = std::str::from_utf8(value) else {
        return Err(invalid_msg_type("msg type is not valid UTF-8".to_string()));
    };
    match MsgType::new(code) {
        Ok(_) => Ok(()),
        Err(MsgTypeError::TooLong { len, max_len }) => Err(EncodeError::FieldTooLong {
            tag: 35,
            length: len,
            max_length: max_len,
        }),
        Err(err) => Err(invalid_msg_type(err.to_string())),
    }
}

/// Builds the rejection for an unrepresentable `MsgType` value.
#[cold]
#[inline(never)]
fn invalid_msg_type(reason: String) -> EncodeError {
    EncodeError::InvalidFieldValue { tag: 35, reason }
}

/// Appends `src` to `dst` at `*len`, advancing it.
///
/// Returns `None` rather than writing out of bounds, which the caller turns
/// into a typed error.
#[inline]
fn push_bytes(dst: &mut [u8], len: &mut usize, src: &[u8]) -> Option<()> {
    let end = len.checked_add(src.len())?;
    dst.get_mut(*len..end)?.copy_from_slice(src);
    *len = end;
    Some(())
}

/// Rejects a tag that is not a legal FIX field tag.
#[inline]
fn check_tag(tag: u32) -> Result<(), EncodeError> {
    if tag == 0 {
        return Err(zero_tag());
    }
    Ok(())
}

/// Rejects a tag that may not be written as an ordinary body field.
#[inline]
fn check_body_tag(tag: u32) -> Result<(), EncodeError> {
    check_tag(tag)?;
    // 8 BeginString, 9 BodyLength, 10 CheckSum.
    if matches!(tag, 8..=10) {
        return Err(framing_tag(tag));
    }
    if paired_data_tag(tag).is_some() || is_data_tag(tag) {
        return Err(data_tag_needs_pair(tag));
    }
    Ok(())
}

/// Builds the rejection for tag `0`.
///
/// The error constructors below are out of line because each formats a
/// `String`: that allocation belongs on the rejection path, not in the
/// instruction-cache footprint of the field-writing loop.
#[cold]
#[inline(never)]
fn zero_tag() -> EncodeError {
    EncodeError::InvalidFieldValue {
        tag: 0,
        reason: "0 is not a legal FIX field tag: tags are positive integers starting at 1"
            .to_string(),
    }
}

/// Builds the rejection for a framing tag written as a body field.
#[cold]
#[inline(never)]
fn framing_tag(tag: u32) -> EncodeError {
    EncodeError::InvalidFieldValue {
        tag,
        reason: format!(
            "tag {tag} is stamped by the encoder itself; writing it into the body \
             would give the frame two of it"
        ),
    }
}

/// Builds the rejection for half of a `LENGTH`/`DATA` pair written alone.
#[cold]
#[inline(never)]
fn data_tag_needs_pair(tag: u32) -> EncodeError {
    EncodeError::InvalidFieldValue {
        tag,
        reason: format!(
            "tag {tag} belongs to a LENGTH/DATA field pair and must be written with put_data, \
             which derives the declared count from the payload"
        ),
    }
}

/// Builds the rejection for a `DATA` tag that is not paired with the
/// `LENGTH` tag it was offered with.
#[cold]
#[inline(never)]
fn unpaired_data_tag(length_tag: u32, data_tag: u32) -> EncodeError {
    EncodeError::InvalidFieldValue {
        tag: data_tag,
        reason: format!(
            "tag {data_tag} is not the DATA field the FIX specification pairs with LENGTH \
             field {length_tag}; a decoder frames a DATA value by the count in its own \
             paired LENGTH field"
        ),
    }
}

/// Builds the rejection for an empty field value.
#[cold]
#[inline(never)]
fn empty_value(tag: u32) -> EncodeError {
    EncodeError::InvalidFieldValue {
        tag,
        reason: "value is empty; a FIX field carries at least one byte".to_string(),
    }
}

/// Builds the rejection for a value carrying the SOH delimiter.
#[cold]
#[inline(never)]
fn soh_in_value(tag: u32, position: usize) -> EncodeError {
    EncodeError::InvalidFieldValue {
        tag,
        reason: format!(
            "value contains the SOH delimiter at offset {position}, which would terminate \
             the field early and inject the remainder as further fields"
        ),
    }
}

/// Builds the rejection for an illegal `BeginString` byte.
#[cold]
#[inline(never)]
fn illegal_begin_string_byte(byte: u8, position: usize) -> EncodeError {
    EncodeError::InvalidFieldValue {
        tag: 8,
        reason: format!(
            "begin string contains illegal byte {byte:#04x} at offset {position}: \
             only printable ASCII (0x21..=0x7e) except '=' is allowed"
        ),
    }
}

/// Builds the rejection for a write into an already-stamped frame.
#[cold]
#[inline(never)]
fn already_finished(tag: u32) -> EncodeError {
    EncodeError::InvalidFieldValue {
        tag,
        reason: "the frame is already finished; call clear() before encoding the next message"
            .to_string(),
    }
}

/// Builds the rejection for a body that cannot grow further.
///
/// The body length is a `usize` counting bytes already in memory, so this is
/// unreachable on any real machine; it exists so the fold that proves it has
/// somewhere to fail instead of wrapping.
#[cold]
#[inline(never)]
fn body_overflow(needed: usize) -> EncodeError {
    EncodeError::BufferOverflow {
        needed,
        available: 0,
    }
}

/// Builds the rejection for a header that does not fit the reserved prefix.
///
/// [`HEADER_RESERVE`] is sized for the worst case, so this is unreachable; it
/// exists so the arithmetic and slicing that prove it have somewhere to fail
/// instead of panicking.
#[cold]
#[inline(never)]
fn header_overflow(needed: usize) -> EncodeError {
    EncodeError::BufferOverflow {
        needed,
        available: HEADER_RESERVE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::Decoder;
    use ironfix_core::error::DecodeError;
    use ironfix_core::message::MsgType;

    /// Returns the finished frame, failing the test with the rejection.
    #[track_caller]
    fn frame_of(encoder: &mut Encoder) -> Vec<u8> {
        match encoder.finish() {
            Ok(frame) => frame.to_vec(),
            Err(err) => panic!("frame must encode: {err}"),
        }
    }

    /// Builds a minimal valid frame carrying the extra fields in `fields`.
    fn encode(fields: &[(u32, &[u8])]) -> Vec<u8> {
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "0");
        for (tag, value) in fields {
            encoder.put_raw(*tag, value);
        }
        frame_of(&mut encoder)
    }

    /// Asserts that `encoder` refuses to produce a frame, with
    /// `InvalidFieldValue` for `tag`.
    #[track_caller]
    fn assert_rejected(encoder: &mut Encoder, tag: u32) {
        match encoder.finish() {
            Err(EncodeError::InvalidFieldValue { tag: actual, .. }) => assert_eq!(actual, tag),
            Ok(frame) => panic!(
                "the frame must be refused, got {:?}",
                String::from_utf8_lossy(frame)
            ),
            Err(other) => panic!("expected InvalidFieldValue for tag {tag}, got {other}"),
        }
    }

    /// Reads the value of `tag` out of a finished frame.
    #[track_caller]
    fn field_of(frame: &[u8], tag: u32) -> Option<String> {
        match Decoder::new(frame).decode() {
            Ok(decoded) => decoded
                .get_field(tag)
                .map(|field| String::from_utf8_lossy(field.value).into_owned()),
            Err(err) => panic!("frame must decode: {err}"),
        }
    }

    #[test]
    fn test_encoder_basic_frame_is_well_formed() {
        let frame = encode(&[]);
        let text = String::from_utf8_lossy(&frame).into_owned();

        assert!(text.starts_with("8=FIX.4.4\x019="));
        assert!(text.contains("35=0\x01"));
        assert!(text.ends_with('\x01'));
        assert_eq!(field_of(&frame, 35).as_deref(), Some("0"));
    }

    #[test]
    fn test_encoder_multiple_fields_round_trip() {
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "D");
        encoder.put_str(49, "SENDER");
        encoder.put_str(56, "TARGET");
        encoder.put_uint(34, 1);
        encoder.put_int(44, -7);
        encoder.put_bool(43, true);
        encoder.put_char(54, '1');
        let frame = frame_of(&mut encoder);

        let Ok(decoded) = Decoder::new(&frame).decode() else {
            panic!("frame must decode");
        };
        assert_eq!(*decoded.msg_type(), MsgType::NewOrderSingle);
        assert_eq!(decoded.get_field_str(49), Some("SENDER"));
        assert_eq!(decoded.get_field_str(56), Some("TARGET"));
        assert_eq!(decoded.get_field_str(34), Some("1"));
        assert_eq!(decoded.get_field_str(44), Some("-7"));
        assert_eq!(decoded.get_field_str(43), Some("Y"));
        assert_eq!(decoded.get_field_str(54), Some("1"));
        // 8, 9, 35, 49, 56, 34, 44, 43, 54, 10 — the CheckSum field is not
        // collected into the field list.
        assert_eq!(decoded.field_count(), 9);
    }

    #[test]
    fn test_encoder_stamps_the_exact_body_length_and_checksum() {
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "D");
        encoder.put_str(49, "SENDER");
        encoder.put_uint(34, 42);
        let body_len = encoder.body_len();
        let frame = frame_of(&mut encoder);

        // The body is exactly what the encoder counted.
        let body = b"35=D\x0149=SENDER\x0134=42\x01";
        assert_eq!(body_len, body.len());

        let expected_header = format!("8=FIX.4.4\x019={}\x01", body.len());
        let mut expected = expected_header.into_bytes();
        expected.extend_from_slice(body);
        let checksum: u64 = expected.iter().map(|&b| u64::from(b)).sum();
        let expected_checksum = (checksum % 256) as u8;
        expected.extend_from_slice(format!("10={expected_checksum:03}\x01").as_bytes());

        assert_eq!(frame, expected);

        // And the stamped values are what the decoder recomputes.
        let Ok(decoded) = Decoder::new(&frame).decode() else {
            panic!("frame must decode with checksum validation on");
        };
        assert_eq!(decoded.body(), Ok(&body[..]));
        assert_eq!(
            decoded.get_field_str(9),
            Some(body.len().to_string().as_str())
        );
    }

    #[test]
    fn test_encoder_body_length_digit_growth_keeps_the_frame_contiguous() {
        // The header is right-aligned in the reserved prefix, so its length
        // changes with the digit count of BodyLength. Each of these must still
        // decode with the checksum computed over the frame actually emitted.
        for filler in [1usize, 8, 97, 1000] {
            let payload = vec![b'x'; filler];
            let mut encoder = Encoder::new("FIX.4.4");
            encoder.put_str(35, "D");
            encoder.put_raw(58, &payload);
            let frame = frame_of(&mut encoder);

            assert!(frame.starts_with(b"8=FIX.4.4\x019="));
            let Ok(decoded) = Decoder::new(&frame).decode() else {
                panic!("frame with a {filler}-byte value must decode");
            };
            assert_eq!(decoded.get_field(58).map(|f| f.value.len()), Some(filler));
        }
    }

    #[test]
    fn test_encoder_reuse_after_clear_produces_an_independent_frame() {
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "A");
        encoder.put_str(49, "FIRST");
        let first = frame_of(&mut encoder);

        encoder.clear();
        assert_eq!(encoder.body_len(), 0);
        encoder.put_str(35, "0");
        encoder.put_str(49, "SECOND");
        let second = frame_of(&mut encoder);

        assert_eq!(field_of(&first, 49).as_deref(), Some("FIRST"));
        assert_eq!(field_of(&second, 49).as_deref(), Some("SECOND"));
        // No residue of the first message, in particular no second trailer.
        assert_eq!(second.iter().filter(|&&b| b == SOH).count(), 5);
    }

    #[test]
    fn test_encoder_finish_is_idempotent() {
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "0");
        let first = frame_of(&mut encoder);
        let second = frame_of(&mut encoder);
        assert_eq!(first, second);
    }

    #[test]
    fn test_encoder_finish_into_appends_the_same_frame() {
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "0");
        encoder.put_str(49, "SENDER");

        let mut dst = BytesMut::from(&b"PRE"[..]);
        match encoder.finish_into(&mut dst) {
            Ok(()) => {}
            Err(err) => panic!("frame must encode: {err}"),
        }
        let frame = frame_of(&mut encoder);

        assert_eq!(dst.len(), 3 + frame.len());
        assert_eq!(dst.get(3..), Some(&frame[..]));
    }

    #[test]
    fn test_encoder_value_with_embedded_soh_is_rejected() {
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "D");
        // The injection this rejection exists for: without it the frame carries
        // a phantom 49=EVIL with a BodyLength and CheckSum correct for it.
        encoder.put_str(58, "text\x0149=EVIL");
        assert_rejected(&mut encoder, 58);
    }

    #[test]
    fn test_encoder_try_put_raw_reports_soh_immediately_and_writes_nothing() {
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "D");
        let before = encoder.body_len();

        let result = encoder.try_put_raw(58, b"a\x01b");
        assert!(matches!(
            result,
            Err(EncodeError::InvalidFieldValue { tag: 58, .. })
        ));
        assert_eq!(encoder.body_len(), before);
        // A rejection the caller took delivery of is not also recorded.
        assert!(encoder.error().is_none());
        assert!(encoder.finish().is_ok());
    }

    #[test]
    fn test_encoder_value_with_equals_is_accepted_and_round_trips() {
        // '=' inside a value is legal FIX: a decoder splits at the first '='.
        let frame = encode(&[(58, b"key=value")]);
        assert_eq!(field_of(&frame, 58).as_deref(), Some("key=value"));
    }

    #[test]
    fn test_encoder_empty_value_is_rejected() {
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "D");
        encoder.put_str(58, "");
        assert_rejected(&mut encoder, 58);
    }

    #[test]
    fn test_encoder_zero_tag_is_rejected() {
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "D");
        encoder.put_str(0, "x");
        assert_rejected(&mut encoder, 0);
    }

    #[test]
    fn test_encoder_framing_tags_are_rejected() {
        // Writing 8, 9 or 10 into the body gives the frame two of them; a
        // mid-body 10= in particular is read as the trailer by the decoder.
        for tag in [8u32, 9, 10] {
            let mut encoder = Encoder::new("FIX.4.4");
            encoder.put_str(35, "D");
            encoder.put_str(tag, "1");
            assert_rejected(&mut encoder, tag);
        }
    }

    #[test]
    fn test_encoder_length_or_data_tag_written_alone_is_rejected() {
        // The frame this prevents: `95=3<SOH>96=abcdefg<SOH>` declares a count
        // that disagrees with the payload, which the decoder rejects.
        for tag in [95u32, 96, 93, 89, 354, 355] {
            let mut encoder = Encoder::new("FIX.4.4");
            encoder.put_str(35, "D");
            encoder.put_str(tag, "3");
            assert_rejected(&mut encoder, tag);
        }
    }

    #[test]
    fn test_encoder_missing_msg_type_is_rejected() {
        let mut encoder = Encoder::new("FIX.4.4");
        assert_eq!(
            encoder.finish().err(),
            Some(EncodeError::MissingRequiredField { tag: 35 })
        );

        // Present but not first: the decoder reads the third field of the frame
        // as MsgType, so this would frame 49 as the message type.
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(49, "SENDER");
        encoder.put_str(35, "D");
        assert_eq!(
            encoder.finish().err(),
            Some(EncodeError::MissingRequiredField { tag: 35 })
        );
    }

    #[test]
    fn test_encoder_unrepresentable_msg_type_is_rejected() {
        // Each of these frames decodes as far as tag 35 and is then refused by
        // the decoder, so the encoder must not produce it in the first place.
        for code in ["A B", "A=B", "\u{7f}"] {
            let mut encoder = Encoder::new("FIX.4.4");
            encoder.put_str(35, code);
            assert_rejected(&mut encoder, 35);
        }

        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "U99999999");
        assert_eq!(
            encoder.finish().err(),
            Some(EncodeError::FieldTooLong {
                tag: 35,
                length: 9,
                max_length: 8,
            })
        );
    }

    #[test]
    fn test_encoder_representable_custom_msg_type_is_accepted() {
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "U9999999");
        let frame = frame_of(&mut encoder);
        let Ok(decoded) = Decoder::new(&frame).decode() else {
            panic!("a representable custom MsgType must decode");
        };
        assert_eq!(decoded.msg_type().as_str(), "U9999999");
    }

    #[test]
    fn test_encoder_write_after_finish_is_rejected() {
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "0");
        let frame = frame_of(&mut encoder);

        assert!(matches!(
            encoder.try_put_raw(58, b"late"),
            Err(EncodeError::InvalidFieldValue { tag: 58, .. })
        ));
        // The stamped frame is unchanged.
        assert_eq!(frame_of(&mut encoder), frame);
    }

    #[test]
    fn test_encoder_illegal_begin_string_is_rejected() {
        for begin_string in ["", "FIX\x014.4", "FIX=4.4", "FIX 4.4"] {
            let mut encoder = Encoder::new(begin_string);
            encoder.put_str(35, "0");
            match encoder.finish() {
                Err(EncodeError::InvalidFieldValue { tag: 8, .. }) => {}
                other => panic!("{begin_string:?} must be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_encoder_over_long_begin_string_is_rejected() {
        let begin_string = "F".repeat(BEGIN_STRING_MAX_LEN + 1);
        let mut encoder = Encoder::new(&begin_string);
        encoder.put_str(35, "0");
        assert_eq!(
            encoder.finish().err(),
            Some(EncodeError::FieldTooLong {
                tag: 8,
                length: BEGIN_STRING_MAX_LEN + 1,
                max_length: BEGIN_STRING_MAX_LEN,
            })
        );
    }

    #[test]
    fn test_encoder_begin_string_rejection_survives_clear() {
        let mut encoder = Encoder::new("FIX\x014.4");
        encoder.put_str(35, "0");
        assert!(encoder.finish().is_err());
        encoder.clear();
        encoder.put_str(35, "0");
        assert!(
            encoder.finish().is_err(),
            "an unusable BeginString makes every message unframeable"
        );
    }

    #[test]
    fn test_encoder_begin_string_at_the_bound_is_accepted() {
        let begin_string = "F".repeat(BEGIN_STRING_MAX_LEN);
        let mut encoder = Encoder::new(&begin_string);
        encoder.put_str(35, "0");
        let frame = frame_of(&mut encoder);
        let Ok(decoded) = Decoder::new(&frame).decode() else {
            panic!("frame must decode");
        };
        assert_eq!(decoded.begin_string(), Ok(begin_string.as_str()));
    }

    #[test]
    fn test_encoder_first_rejection_is_the_one_reported() {
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "D");
        encoder.put_str(58, "a\x01b");
        encoder.put_str(11, "");
        assert_rejected(&mut encoder, 58);
    }

    #[test]
    fn test_encoder_put_data_round_trips_a_payload_carrying_soh_and_equals() {
        let payload: &[u8] = b"a\x01b=c\x01d";
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "A");
        encoder.put_data(95, 96, payload);
        encoder.put_str(58, "after");
        let frame = frame_of(&mut encoder);

        let Ok(decoded) = Decoder::new(&frame).decode() else {
            panic!("frame with RawData must decode");
        };
        assert_eq!(decoded.get_field(95).map(|f| f.value), Some(&b"7"[..]));
        assert_eq!(decoded.get_field(96).map(|f| f.value), Some(payload));
        assert_eq!(decoded.get_field_str(58), Some("after"));
        // 8, 9, 35, 95, 96, 58 — no phantom field from inside the payload.
        assert_eq!(decoded.field_count(), 6);
    }

    #[test]
    fn test_encoder_put_data_empty_payload_is_rejected() {
        // `96=<SOH>` (empty-valued DATA) is malformed FIX and inconsistent with
        // the encoder rejecting an empty ordinary value; the rejection names the
        // DATA tag, as an empty ordinary value names its own tag.
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "A");
        encoder.put_data(95, 96, b"");
        assert_rejected(&mut encoder, 96);
    }

    #[test]
    fn test_encoder_try_put_data_empty_payload_reports_immediately() {
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "A");
        let before = encoder.body_len();

        let result = encoder.try_put_data(95, 96, b"");
        assert!(matches!(
            result,
            Err(EncodeError::InvalidFieldValue { tag: 96, .. })
        ));
        // Nothing written, and the caller took delivery of the rejection.
        assert_eq!(encoder.body_len(), before);
        assert!(encoder.error().is_none());
    }

    #[test]
    fn test_encoder_put_data_round_trips_every_spec_pair() {
        // Each pair the decoder frames by count must also be emittable.
        let pairs = [
            (90u32, 91u32),
            (93, 89),
            (95, 96),
            (212, 213),
            (348, 349),
            (350, 351),
            (352, 353),
            (354, 355),
            (356, 357),
            (358, 359),
            (360, 361),
            (362, 363),
            (364, 365),
            (445, 446),
            (618, 619),
            (621, 622),
        ];
        let payload: &[u8] = b"\x01=\x01";
        for (length_tag, data_tag) in pairs {
            let mut encoder = Encoder::new("FIX.4.4");
            encoder.put_str(35, "A");
            encoder.put_data(length_tag, data_tag, payload);
            let frame = frame_of(&mut encoder);

            let Ok(decoded) = Decoder::new(&frame).decode() else {
                panic!("frame carrying {length_tag}/{data_tag} must decode");
            };
            assert_eq!(decoded.get_field(data_tag).map(|f| f.value), Some(payload));
        }
    }

    #[test]
    fn test_encoder_put_data_unpaired_tags_are_rejected() {
        // 96 is paired with 95, not with 93: emitting it under 93 would leave
        // the payload's SOH bytes to be read as field terminators.
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "A");
        encoder.put_data(93, 96, b"x\x01y");
        assert_rejected(&mut encoder, 96);

        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "A");
        encoder.put_data(58, 59, b"x");
        assert_rejected(&mut encoder, 59);
    }

    #[test]
    fn test_encoder_put_data_zero_tag_is_rejected() {
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "A");
        encoder.put_data(0, 96, b"x");
        assert_rejected(&mut encoder, 0);
    }

    #[test]
    fn test_encoder_output_always_decodes_under_checksum_validation() {
        // The property the whole module exists to hold: anything `finish`
        // yields is a frame this crate's decoder accepts.
        let mut encoder = Encoder::new("FIXT.1.1");
        encoder.put_str(35, "A");
        encoder.put_str(49, "CLIENT");
        encoder.put_str(56, "VENUE");
        encoder.put_uint(34, 1);
        encoder.put_str(52, "20260721-12:00:00.000");
        encoder.put_data(95, 96, b"\x01\x01\x01");
        encoder.put_str(1137, "9");
        let frame = frame_of(&mut encoder);

        let Ok(decoded) = Decoder::new(&frame).decode() else {
            panic!("frame must decode");
        };
        assert_eq!(decoded.begin_string(), Ok("FIXT.1.1"));
        assert_eq!(*decoded.msg_type(), MsgType::Logon);
        assert_eq!(decoded.len(), frame.len());
    }

    #[test]
    fn test_encoder_frame_is_rejected_when_a_byte_is_flipped() {
        // Guards the assertion above against being vacuous: the decoder really
        // is checking the checksum the encoder stamped.
        let mut encoder = Encoder::new("FIX.4.4");
        encoder.put_str(35, "0");
        encoder.put_str(49, "SENDER");
        let mut frame = frame_of(&mut encoder);
        let Some(position) = memchr(b'S', &frame) else {
            panic!("the frame carries the SENDER value");
        };
        let Some(byte) = frame.get_mut(position) else {
            panic!("the position came from the frame itself");
        };
        // Case flip: same length, so only the checksum can catch it.
        *byte ^= 0x20;

        assert!(matches!(
            Decoder::new(&frame).decode(),
            Err(DecodeError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn test_encoder_never_emits_a_frame_its_own_decoder_rejects() {
        // The invariant, stated as a property over hostile inputs: for every
        // tag and value, `finish` either refuses or yields a frame `decode`
        // accepts with checksum validation on. There is no third outcome.
        let tags: [u32; 12] = [0, 1, 8, 9, 10, 35, 49, 58, 93, 95, 96, u32::MAX];
        let values: [&[u8]; 12] = [
            b"",
            b"x",
            b"a\x01b",
            b"\x01",
            b"=",
            b"a=b",
            b"10=999",
            b"\x0110=000\x01",
            b"\xff\xfe",
            b"\x00",
            b" ",
            b"U99999999",
        ];

        for tag in tags {
            for value in values {
                // As a trailing field of an otherwise valid message...
                let mut encoder = Encoder::new("FIX.4.4");
                encoder.put_str(35, "D");
                encoder.put_raw(tag, value);
                assert_frame_or_rejection(&mut encoder, tag, value);

                // ...and as the message's very first field.
                let mut encoder = Encoder::new("FIX.4.4");
                encoder.put_raw(tag, value);
                assert_frame_or_rejection(&mut encoder, tag, value);

                // The Length/Data path takes the same payloads.
                let mut encoder = Encoder::new("FIX.4.4");
                encoder.put_str(35, "D");
                encoder.put_data(95, tag, value);
                assert_frame_or_rejection(&mut encoder, tag, value);
            }
        }
    }

    /// Asserts that `encoder` either refuses, or yields a frame the decoder
    /// accepts. Used by the property test above.
    #[track_caller]
    fn assert_frame_or_rejection(encoder: &mut Encoder, tag: u32, value: &[u8]) {
        let Ok(frame) = encoder.finish() else {
            return;
        };
        let frame = frame.to_vec();
        if let Err(err) = Decoder::new(&frame).decode() {
            panic!(
                "tag {tag} value {value:?} produced a frame the decoder rejects \
                 ({err}): {:?}",
                String::from_utf8_lossy(&frame)
            );
        }
    }

    #[test]
    fn test_encoder_default_uses_fix44() {
        let mut encoder = Encoder::default();
        encoder.put_str(35, "0");
        let frame = frame_of(&mut encoder);
        assert!(frame.starts_with(b"8=FIX.4.4\x01"));
    }

    #[test]
    fn test_encoder_with_capacity_encodes_without_growing_the_buffer() {
        let mut encoder = Encoder::with_capacity("FIX.4.4", 512);
        encoder.put_str(35, "D");
        encoder.put_raw(58, &vec![b'x'; 400]);
        let frame = frame_of(&mut encoder);
        assert!(Decoder::new(&frame).decode().is_ok());
    }
}
