# ADR-0028: Decode into a caller-owned, bounded field index

- **Status:** Accepted (issue #77, in the plan the owner approved)
- **Date:** 2026-10-19

## Context

`Decoder::decode` collects a message's fields into the
`SmallVec<[FieldRef; 32]>` that `RawMessage` owns. The vector is inline for up
to 32 fields and spills to the heap above that, so every ExecutionReport with
a few repeating groups costs an allocation, and the field count of a hostile
message bounds nothing but the frame size. A caller that decodes many
messages wants to own the index, size it once, and have a message above the
size refused rather than allocated for.

Constraints any answer keeps:

- additive only at v0.4.1: `Decoder::decode` and `RawMessage` unchanged;
- the decoder stays dictionary-free, with no `unsafe`;
- checked arithmetic, and every malformed input a typed `DecodeError`.

## Decision

1. **`ironfix_tagvalue::FieldIndex`**, an index of spans. Each entry is a
   `FieldSpan` of a tag and the frame-relative range of its value, not a
   borrow, so one index is reused across frames held in different buffers.
   `FieldIndex::with_capacity` is its only allocation; it is cleared, never
   grown.
2. **`Decoder::decode_into(&mut FieldIndex) -> IndexedMessage<'a, '_>`.** It
   shares one generic decode loop with `decode` (a private `FieldSink` trait,
   monomorphised for both), so framing, BodyLength, CheckSum and every error
   are identical. `IndexedMessage` pairs the frame with the index and hands
   out `ironfix_core::field::FieldRef<'a>` values; `to_raw_message` converts
   for code that speaks `RawMessage`.
3. **`DecodeError::TooManyFields { capacity }`** when a message carries more
   fields (CheckSum (10) excluded) than the index holds.
4. **`SessionConfig::max_inbound_fields`**, default 256, range 3 to 65 536,
   validated by `SessionConfig::validate`
   (`SessionConfigError::InboundFieldLimitOutOfRange`). The engine's reactor
   allocates one index of that size per session and decodes every inbound
   frame of an Active session into it.
5. **Over the bound, the engine falls back, it does not reject.** A frame
   whose field count exceeds the knob is decoded again through `decode`, and
   the reactor counts the fallback and logs it at debug level with the session
   and the counts, never the frame. Rejecting a well-formed message because of
   a local tuning knob would be a protocol behaviour the FIX specification does
   not define; the bound on hostile input remains `max_message_size`.

## Consequences

- A caller of `decode_into` with a sufficient index decodes without a heap
  allocation; `ironfix-tagvalue/tests/field_index_allocations.rs` proves it
  with `dhat` for a 100-field message.
- The engine hands the session layer and the application a `RawMessage`
  whose field references it does not own. Follow-up of #77:
  `RawMessage::with_field_slice` builds one over a borrowed slice (additive;
  `RawMessage::new` keeps the `SmallVec`), `IndexedMessage::to_raw_message_in`
  fills a caller-owned `Vec<FieldRef>` from the index, and
  `recycle_field_refs` hands that buffer from one frame's lifetime to the
  next without freeing it (the standard library collects an empty iterator
  of a same-sized type back into the same allocation; a tagvalue unit test
  checks the pointer and capacity survive, and the engine allocation test
  checks the result). The reactor and the application dispatcher each own
  one buffer, sized with the index at session start. The allocation matrix
  measured a 60-field ExecutionReport at 2.1 blocks more than a 12-field
  one before (a field list in the reactor and one in the dispatcher) and
  about 0.1 after, none of it a field list. A frame above
  `max_inbound_fields` still takes the `decode` fallback and its
  `SmallVec`: refusing it would refuse a legal message the operator sized
  the index below, and the fallback is bounded by `max_message_size`.
- The fallback count is internal to the reactor; it is not on the public
  `Connection` surface.
- The criterion group `tagvalue/decode_index` compares `decode` and
  `decode_into`. No baseline is recorded and no figure is claimed.
