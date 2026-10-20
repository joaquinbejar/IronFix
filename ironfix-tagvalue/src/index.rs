/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 19/10/26
******************************************************************************/

//! A caller-owned, bounded, reusable index of field spans.
//!
//! [`crate::Decoder::decode`] collects a message's fields into a
//! `SmallVec<[FieldRef; 32]>`, which spills to the heap for any message with
//! more than 32 fields. [`FieldIndex`] is the alternative for a caller that
//! decodes many messages: it is allocated once, with a fixed capacity, and
//! [`crate::Decoder::decode_into`] fills it with one [`FieldSpan`] per field.
//!
//! - **No allocation per message.** The index never grows: its storage is
//!   reserved by [`FieldIndex::with_capacity`] and cleared, not freed, at the
//!   start of every decode.
//! - **Bounded.** A message with more fields than the capacity is
//!   [`DecodeError::TooManyFields`], never a reallocation. The capacity is the
//!   caller's resource ceiling; nothing about it is sized from the input.
//! - **Lifetime-free.** A span is a `(tag, start, end)` triple of offsets into
//!   the decoded frame, not a borrow, so the same index is reused across
//!   frames held in different buffers. [`IndexedMessage`] pairs the index with
//!   the frame it describes and hands out zero-copy
//!   [`ironfix_core::field::FieldRef`] values.

use ironfix_core::error::DecodeError;
use ironfix_core::field::FieldRef;
use ironfix_core::message::{MsgType, RawMessage};
use smallvec::SmallVec;
use std::ops::Range;

/// One decoded field: its tag and the frame-relative range of its value.
///
/// The range excludes `tag=` and the terminating SOH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSpan {
    /// The field's tag number.
    tag: u32,
    /// Offset of the first value byte, relative to the frame.
    start: usize,
    /// Offset one past the last value byte, relative to the frame.
    end: usize,
}

impl FieldSpan {
    /// Returns the field's tag number.
    #[inline]
    #[must_use]
    pub const fn tag(&self) -> u32 {
        self.tag
    }

    /// Returns the frame-relative range of the field's value.
    #[inline]
    #[must_use]
    pub const fn range(&self) -> Range<usize> {
        self.start..self.end
    }
}

/// A caller-owned, fixed-capacity index of the fields of one message.
///
/// Build it once, sized for the largest message the caller accepts, and pass
/// it to [`crate::Decoder::decode_into`] for every frame.
///
/// ```
/// use ironfix_tagvalue::{Decoder, Encoder, FieldIndex};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut encoder = Encoder::new("FIX.4.4");
/// encoder.put_str(35, "0");
/// encoder.put_uint(34, 7);
/// let frame = encoder.finish()?.to_vec();
///
/// let mut index = FieldIndex::with_capacity(64);
/// let message = Decoder::new(&frame).decode_into(&mut index)?;
/// assert_eq!(message.msg_type().as_str(), "0");
/// assert_eq!(message.get_field_str(34), Some("7"));
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct FieldIndex {
    /// Spans of the last decoded message, in wire order.
    spans: Vec<FieldSpan>,
    /// Maximum number of spans; never exceeded, so `spans` never reallocates.
    capacity: usize,
}

impl Clone for FieldIndex {
    /// Clones the index with its full backing storage reserved.
    ///
    /// A derived `Clone` would clone the `Vec`, which reserves only the
    /// entries it holds: the clone would keep the logical capacity but
    /// reallocate on its next decode.
    fn clone(&self) -> Self {
        let mut spans = Vec::with_capacity(self.capacity.max(self.spans.len()));
        spans.extend(self.spans.iter().cloned());
        Self {
            spans,
            capacity: self.capacity,
        }
    }
}

impl FieldIndex {
    /// Creates an index that holds at most `capacity` fields.
    ///
    /// This is the only allocation the index ever makes. Every frame carries
    /// at least BeginString (8), BodyLength (9), MsgType (35) and CheckSum
    /// (10); CheckSum is not indexed, so a capacity below 3 rejects every
    /// message with [`DecodeError::TooManyFields`].
    ///
    /// # Arguments
    /// * `capacity` - Maximum number of fields a decoded message may carry,
    ///   CheckSum (10) excluded.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            spans: Vec::with_capacity(capacity),
            capacity,
        }
    }

    /// Returns the maximum number of fields the index holds.
    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the number of fields of the last decoded message.
    ///
    /// After a failed decode this is whatever was indexed before the failure;
    /// read fields through the [`IndexedMessage`] a successful decode returns.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.spans.len()
    }

    /// Returns true if the index holds no fields.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    /// Returns the indexed spans, in wire order.
    #[inline]
    #[must_use]
    pub fn spans(&self) -> &[FieldSpan] {
        &self.spans
    }

    /// Empties the index, keeping its storage.
    #[inline]
    pub fn clear(&mut self) {
        self.spans.clear();
    }

    /// Appends a span, refusing to grow past the capacity.
    ///
    /// # Errors
    /// [`DecodeError::TooManyFields`] when the index is full.
    #[inline]
    pub(crate) fn push(&mut self, tag: u32, value: Range<usize>) -> Result<(), DecodeError> {
        if self.spans.len() >= self.capacity {
            return Err(DecodeError::TooManyFields {
                capacity: self.capacity,
            });
        }
        // `spans` was reserved with `capacity` slots and holds fewer, so this
        // push never reallocates.
        self.spans.push(FieldSpan {
            tag,
            start: value.start,
            end: value.end,
        });
        Ok(())
    }
}

/// A message decoded into a [`FieldIndex`]: the frame it borrows plus the
/// index that describes it.
///
/// Every accessor slices the frame through a span; a span that does not fit
/// the frame (impossible for an index filled by
/// [`crate::Decoder::decode_into`]) yields no field rather than a panic.
#[derive(Debug, Clone)]
pub struct IndexedMessage<'a, 'i> {
    /// The complete frame, `8=` through the CheckSum SOH.
    buffer: &'a [u8],
    /// The spans of `buffer`'s fields.
    index: &'i FieldIndex,
    /// The parsed MsgType (35).
    msg_type: MsgType,
    /// Frame-relative range of the BeginString (8) value.
    begin_string: Range<usize>,
    /// Frame-relative range of the body, MsgType through the last field
    /// before CheckSum.
    body: Range<usize>,
}

impl<'a, 'i> IndexedMessage<'a, 'i> {
    /// Assembles a view; only the decoder builds one.
    pub(crate) const fn new(
        buffer: &'a [u8],
        index: &'i FieldIndex,
        msg_type: MsgType,
        begin_string: Range<usize>,
        body: Range<usize>,
    ) -> Self {
        Self {
            buffer,
            index,
            msg_type,
            begin_string,
            body,
        }
    }

    /// Returns the complete frame.
    #[inline]
    #[must_use]
    pub const fn buffer(&self) -> &'a [u8] {
        self.buffer
    }

    /// Returns the message type.
    #[inline]
    #[must_use]
    pub const fn msg_type(&self) -> &MsgType {
        &self.msg_type
    }

    /// Returns the BeginString (8) value.
    ///
    /// # Errors
    /// [`DecodeError::InvalidUtf8`] if the value is not UTF-8.
    pub fn begin_string(&self) -> Result<&'a str, DecodeError> {
        let bytes = self
            .buffer
            .get(self.begin_string.clone())
            .ok_or_else(|| self.out_of_bounds(&self.begin_string))?;
        Ok(std::str::from_utf8(bytes)?)
    }

    /// Returns the body bytes.
    ///
    /// # Errors
    /// [`DecodeError::RangeOutOfBounds`] if the body range does not fit the
    /// frame.
    pub fn body(&self) -> Result<&'a [u8], DecodeError> {
        self.buffer
            .get(self.body.clone())
            .ok_or_else(|| self.out_of_bounds(&self.body))
    }

    /// Returns the number of indexed fields, CheckSum (10) excluded.
    #[inline]
    #[must_use]
    pub fn field_count(&self) -> usize {
        self.index.len()
    }

    /// Returns the field at `position` in wire order.
    #[inline]
    #[must_use]
    pub fn field(&self, position: usize) -> Option<FieldRef<'a>> {
        self.index
            .spans()
            .get(position)
            .and_then(|span| self.resolve(span))
    }

    /// Returns an iterator over the fields in wire order.
    pub fn fields(&self) -> impl Iterator<Item = FieldRef<'a>> + '_ {
        self.index
            .spans()
            .iter()
            .filter_map(|span| self.resolve(span))
    }

    /// Returns the first field with `tag`.
    #[must_use]
    pub fn get_field(&self, tag: u32) -> Option<FieldRef<'a>> {
        self.index
            .spans()
            .iter()
            .find(|span| span.tag == tag)
            .and_then(|span| self.resolve(span))
    }

    /// Returns the first field with `tag` as a string, if it is UTF-8.
    #[must_use]
    pub fn get_field_str(&self, tag: u32) -> Option<&'a str> {
        self.get_field(tag).and_then(|field| field.as_str().ok())
    }

    /// Copies the view into a [`RawMessage`].
    ///
    /// The field references still borrow the frame, but `RawMessage` keeps
    /// them in a `SmallVec<[FieldRef; 32]>`: this allocates for a message with
    /// more than 32 fields.
    ///
    /// # Errors
    /// [`DecodeError::RangeOutOfBounds`] if a range does not fit the frame.
    pub fn to_raw_message(&self) -> Result<RawMessage<'a>, DecodeError> {
        let mut fields: SmallVec<[FieldRef<'a>; 32]> = SmallVec::new();
        for span in self.index.spans() {
            fields.push(
                self.resolve(span)
                    .ok_or_else(|| self.out_of_bounds(&span.range()))?,
            );
        }
        RawMessage::new(
            self.buffer,
            self.begin_string.clone(),
            self.body.clone(),
            self.msg_type.clone(),
            fields,
        )
    }

    /// Builds the view as a [`RawMessage`] whose field references live in
    /// `refs`, a buffer the caller owns and reuses across messages
    /// ([`recycle_field_refs`]): no field list is allocated per message,
    /// whatever its field count, once `refs` has the capacity. `refs` is
    /// cleared first.
    ///
    /// # Errors
    /// [`DecodeError::RangeOutOfBounds`] if a range does not fit the frame.
    pub fn to_raw_message_in<'r>(
        &self,
        refs: &'r mut Vec<FieldRef<'a>>,
    ) -> Result<RawMessage<'r>, DecodeError>
    where
        'a: 'r,
    {
        refs.clear();
        for span in self.index.spans() {
            refs.push(
                self.resolve(span)
                    .ok_or_else(|| self.out_of_bounds(&span.range()))?,
            );
        }
        RawMessage::with_field_slice(
            self.buffer,
            self.begin_string.clone(),
            self.body.clone(),
            self.msg_type.clone(),
            refs,
        )
    }

    /// Resolves a span against the frame.
    #[inline]
    fn resolve(&self, span: &FieldSpan) -> Option<FieldRef<'a>> {
        self.buffer
            .get(span.start..span.end)
            .map(|value| FieldRef::new(span.tag, value))
    }

    /// Builds the out-of-bounds error for `range`.
    #[cold]
    fn out_of_bounds(&self, range: &Range<usize>) -> DecodeError {
        DecodeError::RangeOutOfBounds {
            start: range.start,
            end: range.end,
            buffer_len: self.buffer.len(),
        }
    }
}

/// Empties `refs` and hands back its allocation as a buffer for field
/// references of another lifetime: the buffer a caller keeps between frames
/// and lends to [`IndexedMessage::to_raw_message_in`] for each one.
///
/// A field reference borrows its frame, so a buffer holding the references
/// of one frame cannot hold the next frame's under the same type. Emptied,
/// it holds nothing, and the standard library collects an empty iterator of
/// a same-sized type back into the same allocation, so no block is freed or
/// allocated; the engine's allocation test checks that it stays so.
#[must_use]
pub fn recycle_field_refs<'x, 'y>(mut refs: Vec<FieldRef<'x>>) -> Vec<FieldRef<'y>> {
    refs.clear();
    // An adapter that yields nothing, so the collect needs no element and
    // no panic path; `filter_map` is one the standard library collects in
    // place.
    #[allow(clippy::unnecessary_filter_map)]
    let recycled = refs.into_iter().filter_map(|_| None).collect();
    recycled
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_refuses_past_capacity() {
        let mut index = FieldIndex::with_capacity(1);
        assert_eq!(index.push(8, 2..9), Ok(()));
        assert_eq!(
            index.push(9, 12..14),
            Err(DecodeError::TooManyFields { capacity: 1 })
        );
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn test_zero_capacity_refuses_every_field() {
        let mut index = FieldIndex::with_capacity(0);
        assert_eq!(
            index.push(8, 2..9),
            Err(DecodeError::TooManyFields { capacity: 0 })
        );
        assert!(index.is_empty());
    }

    #[test]
    fn test_clone_keeps_the_backing_capacity() {
        let empty = FieldIndex::with_capacity(100).clone();
        assert!(empty.spans.capacity() >= 100);
        let mut partial = FieldIndex::with_capacity(100);
        assert_eq!(partial.push(8, 2..9), Ok(()));
        let partial = partial.clone();
        assert!(partial.spans.capacity() >= 100);
        assert_eq!(partial.len(), 1);
        assert_eq!(partial.capacity(), 100);
    }

    #[test]
    fn test_clear_keeps_capacity() {
        let mut index = FieldIndex::with_capacity(2);
        assert_eq!(index.push(8, 2..9), Ok(()));
        index.clear();
        assert!(index.is_empty());
        assert_eq!(index.capacity(), 2);
    }

    #[test]
    fn test_span_out_of_frame_yields_no_field() {
        let mut index = FieldIndex::with_capacity(1);
        assert_eq!(index.push(8, 2..90), Ok(()));
        let view = IndexedMessage::new(b"8=FIX.4.4\x01", &index, MsgType::Heartbeat, 2..9, 0..0);
        assert!(view.field(0).is_none());
        assert!(matches!(
            view.to_raw_message(),
            Err(DecodeError::RangeOutOfBounds { .. })
        ));
    }
}
