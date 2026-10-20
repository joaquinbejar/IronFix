# ADR-0008: Pooled outbound messages

- **Status:** Accepted (issue #76, in the plan the owner approved)
- **Date:** 2026-10-19

## Context

Every outbound application message was built with `OutboundMessage::new` and
stored each field as an owned `Vec<u8>`: a NewOrderSingle of four fields cost
the field list and four value buffers before the session saw it. The session
side of the send path was already lean. `tests/allocations.rs` (dhat, since
#126) counts one block per live send once the order is built: the boxed
future of the `#[async_trait]` `to_app` call. The reactor's `MessageFactory`
reuses one `Encoder`, which writes `BodyLength` (9) and `CheckSum` (10) into
its own retained buffer, and the write buffer keeps its capacity, so framing
and writing allocate nothing per frame.

Measured first, with the same harness: 1024 orders of four fields built
inside the window with `OutboundMessage::new` and sent with
`Connection::send` cost 6152 blocks, six per message (the field list, the
four values, the `to_app` future), plus non-recurring blocks.

`doc/fix_operations.md` says nothing about allocation; this is an engine
choice. Constraints:

- additive only at v0.4.1; `send` and `send_tracked` unchanged;
- `to_app_checked` (ADR-0023) mutation and veto, the reserved-tag and body
  checks, the throttle (ADR-0024) and the frame observer (ADR-0026) work on
  the new path exactly as on the old;
- no sequence change, and the peek then spend order untouched;
- bounded: a message held forever or dropped unsent must not leak, and the
  pool must not grow without limit;
- no new dependency, no `unsafe`.

## Decision

**A pooled `OutboundMessage`, not a new type.** `Connection::acquire(msg_type)`
returns an ordinary `OutboundMessage` tied to the session's pool. The message
carries the pool handle in a private field, and `OutboundMessage` implements
`Drop`: a pooled message, wherever it is dropped (in the reactor after its
frame is fed, vetoed, refused by the throttle, discarded behind a resend or
at the close, or in the caller's hands without being sent), clears its body
and goes back to the pool, keeping its field list and its value buffers.
Because it is the same type, it travels the command queue, the throttle's
queue, `to_app_checked` and the factory with no new code path; nothing in the
reactor changed. A body writer closure run by the reactor (the other design
the issue named) would have needed a second command variant, a second gate
signature for `to_app_checked` and a second throttle classifier input, all
public.

**Copying push methods reuse the buffers.** `push_str`, `push_int`,
`push_uint`, `push_char` and `push_bool` now copy into a spare value buffer
when the message has one, and a new public `push_bytes(tag, &[u8])` does the
same for raw bytes. Integers are written with `write!` into a buffer reserved
for 20 bytes, so no intermediate `String`. On a message with no spare buffer
(any message from `OutboundMessage::new`) each push allocates one buffer, as
before. `push_raw` and `push_data` take an owned `Vec` the caller allocated,
so they keep their cost. `clear` hands the buffers back last field first, so
a body refilled with the same layout takes each field's own buffer back and
never regrows one (the first version handed them back in field order, and a
throttled window showed buffers rotating across fields and regrowing). A
reused buffer grows with `reserve_exact`, to exactly the value's size:
doubling could take a buffer past `POOLED_MAX_VALUE_BYTES` for a value under
it, and the buffer would then be freed and allocated again on every reuse.
`remove` is one linear pass (`retain_mut`) that keeps the removed buffers.

**Bounds.** The pool keeps at most as many idle messages as the session's
outbound queue holds (`with_outbound_capacity`, default 1024): with a plain
`send`, the queue bounds the messages waiting, so this covers them. It never
blocks and never fails: an empty pool builds a fresh message, and one dropped
into a full pool is freed outside the lock. A message the caller holds keeps
only itself out of the pool. A pooled message is not returned if its field
list has room for more than `POOLED_MAX_FIELDS` (256) fields; it keeps at
most `POOLED_MAX_SPARE` (256) spare buffers, each of at most
`POOLED_MAX_VALUE_BYTES` (1024) bytes of capacity, and frees larger ones. A
clone is not pooled. The pool is a `std::sync::Mutex<Vec<_>>`, locked for one
pop or one push and never across an `.await` (CLAUDE.md override 2).

## What remains, and why

Counted with `tests/allocations.rs`, 1024 messages a window, after the pool
is filled and warmed (block counts, debug and release builds on macOS; no
timing is claimed):

| Window | Blocks | Per message |
|---|---|---|
| orders built with `OutboundMessage::new` inside the window | 6152 | 6 |
| pooled orders, default `to_app_checked` | 1032 | 1 |
| pooled orders through the throttle | 1032 | 1 |
| pooled orders with a frame observer | 1032 | 1 |
| pooled orders, `to_app_checked` returning `SendVerdict::ready` | 8 (0 since the ring below) | about 1/128 (0) |

The windows allow up to 64 non-recurring blocks, except the ready-gate
window, which allows 4: 64 would hide a cost that recurs every 128 sends.

- **The `to_app` future.** `Application` is an `#[async_trait]` trait, so
  every `to_app` call boxes its future. The default `to_app_checked` forwards
  to `to_app` through `SendVerdict::forward`, which keeps the default path at
  that one allocation and adds none (ADR-0023). An application whose
  `to_app_checked` decides at once with `SendVerdict::ready` and calls no
  `to_app` avoids that block. Removing the box
  for everyone means changing the trait's shape, a breaking change, and is
  not done here.
- **The command queue.** Every send crossed the `tokio::sync::mpsc`
  command channel, which grows its slot list by one block about every 128
  sends (scaled to 4096 messages, the ready-gate window cost 32 blocks, all
  from that channel's block growth). Follow-up (issue #76 closed): the
  channel is replaced by the engine's private `command_queue`, a
  `VecDeque` allocated with the session's outbound capacity at session
  start and never grown, behind a `std::sync::Mutex` held only to push or
  pop one command. A send first takes a slot from a `tokio::sync::Semaphore`
  with that many permits, which admits waiting senders in order, so a send
  (or a Logout) already waiting cannot be overtaken by later ones; the
  receiver gives the permit back as it takes the command out, and
  `tokio::sync::Notify` wakes it. Dropping the receiver drops what is
  still queued, so a `Connection` that outlives the session keeps no
  command or pooled message alive (both from codex's review of #197). It
  keeps the channel's semantics (order, backpressure when full, `None` once
  every handle is dropped, close and drain, cancel-safe futures, a `Send`
  send future). The ready-gate window now measures **0 blocks for 1024
  sends**: through a gate that decides at once, with no store, a pooled
  send allocates nothing.
- **A store.** With a `MemoryStore` attached a send costs five blocks
  (`STORED_LIVE_BLOCKS` in the test): the `to_app` future above, the
  `file_outbound` future, the `store` and `set_next_sender_seq` futures of the `#[async_trait]`
  `MessageStore`, and the store's own copy of the frame (`MemoryStore` copies
  the frame into `Bytes`; it is a copy, not a reference counted slice of the
  write buffer, since that buffer is reused), plus its B-tree nodes. The pool
  does not change this.
- **A pool smaller than what is in flight** builds the missing messages
  fresh. A throttle with a `max_depth` above the outbound queue can hold
  more messages than the pool keeps; size the outbound queue to cover it.
- **Not done from the issue.** The full-profile test (a durable store,
  the capture hook, TLS and the inbound Reject path together) is not part of
  this change: there is no TLS in the engine yet (#81), so that profile
  cannot run, and the store's cost above is the `MemoryStore` one only.

## Consequences

- Additive public surface: `Connection::acquire`, `OutboundMessage::push_bytes`,
  `OutboundMessage::is_pooled`, and the constants `outbound::POOLED_MAX_FIELDS`,
  `POOLED_MAX_SPARE` and `POOLED_MAX_VALUE_BYTES`. `OutboundMessage` gains a
  `Drop` impl and a hand-written `Clone` (same behaviour, but a clone carries
  no pool and no spare buffers).
- A message from `OutboundMessage::new` behaves as before: it allocates one
  buffer per pushed field and is freed when dropped.
- No crate boundary, dependency, sequence or typestate change.
