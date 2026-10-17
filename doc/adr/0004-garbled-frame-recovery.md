# ADR-0004 — Skip garbled inbound frames inside the codec

- **Status:** Accepted (issue #66)
- **Date:** 2026-10-17

## Context

FIX classes a message whose framing cannot be trusted as *garbled*: BeginString
(8) is not the first field, BodyLength (9) is missing or disagrees with the
frame, or CheckSum (10) is absent, malformed or wrong. The FIX Session Layer
says a garbled message is ignored. It is not rejected and not counted, and its
`MsgSeqNum` (34) is not consumed, because it cannot be trusted. The gap it
leaves is recovered by the normal `ResendRequest` (2) path on the next
well-formed message (`doc/fix_operations.md`, "Garbled Messages and Transport
Resynchronization").

Before this change IronFix ended the session on the first garbled frame. The
reactor treated every codec `Err` as fatal, and that was not the only problem:
`tokio_util::Framed` latches an error flag after any decoder error and returns
`None` on the next poll, so the resynchronisation `FixCodec` already performed
on some error paths could not be reached from the engine at all. A frame that
frames but does not decode was already dropped with a warning
(`reactor.rs`, `on_frame`); the framing-level case was the inconsistent one.

The fix has to answer four questions: where the skip happens, where the codec
resynchronises after garbage, which errors are skippable, and whether a link
that keeps garbling is bounded.

## Options

1. **Skip inside the codec, keep `Framed`.** `FixCodec` gains an opt-in
   recovery mode in which a recoverable framing error is never returned:
   `Decoder::decode` discards the garbled bytes, counts the skip, and carries on
   in the same call. The engine reads the count.
2. **An engine-owned read loop.** Drop `Framed` from the read side and have the
   engine drive `Decoder::decode` over its own `BytesMut`, treating recoverable
   errors as "continue".

## Decision

### Option 1: skip inside the codec

`FixCodec::with_garbled_recovery(bool)` (default off) and
`FixCodec::take_garbled_count() -> u64`. Both engines turn recovery on for their
codec, during the Logon handshake and in the reactor.

Option 2 is rejected. It would duplicate `Framed`'s read and backpressure
handling in the engine, split the read and write halves the reactor and the
handshakes currently share, and leave every other `FixCodec` user with the same
latch problem. Option 1 is local to the codec, keeps `Framed`, and is opt-in,
so a caller that relies on one error per garbled frame keeps that contract.

One detail decides whether option 1 works at all: in recovery mode a single
`decode` call must return the **next valid frame** if it is already buffered.
Returning `Ok(None)` with a whole frame buffered would stall `Framed`, which
polls the decoder again only after the next socket read. The codec therefore
loops: skip, count, try again, until it has a frame, needs more bytes, or hits
a fatal error. Every skip consumes at least one byte (enforced, not assumed), so
one call does work linear in the buffered bytes and allocates nothing.

### Recoverable and fatal

`CodecError::is_recoverable()` is the single classification.

| `CodecError` | Class | In recovery mode |
|---|---|---|
| `InvalidBeginString` | recoverable | resync |
| `MissingBodyLength`, `InvalidBodyLength`, `HeaderTooLong` | recoverable | resync (these consumed nothing before, which would not make progress) |
| `InvalidTrailer` | recoverable | resync: BodyLength is not corroborated, so it does not size the discard |
| `InvalidChecksumFormat`, `ChecksumMismatch` | recoverable | consume the declared frame: the trailer literal is exactly where BodyLength said, so the boundary is corroborated |
| `MessageTooLarge` | **fatal** | returned, nothing consumed |
| `Io` | **fatal** | returned |

A frame declaring more than `max_message_size` stays fatal. Skipping it would
mean either buffering it, which is what the ceiling exists to refuse, or
trusting its attacker-chosen length to size the discard. In the header phase the
64-byte header ceiling is checked before the frame ceiling in recovery mode, so
whether malformed header bytes are skipped never depends on how many good frames
TCP happened to deliver behind them. The checksum and BodyLength checks
themselves are unchanged.

### The resync anchor

Without recovery the codec resyncs on `<SOH>8`, because a bare `8=` occurs
inside ordinary tags (`18=`, `58=`). The cost is that a valid frame arriving
straight after garbage is lost with it, since its `8=` follows the garbage and
not an SOH. In recovery mode the codec also anchors on `8=FIX`, the prefix of
every BeginString in the family (`FIX.4.x`, `FIXT.1.1`), so that frame
survives. A false match, such as `8=FIX` inside a Text (58) value, is not
trusted: it must still pass the full header and trailer checks, and it is
skipped in turn when it does not. The scan is one forward pass that stops at the
first candidate, so a buffer of many short garbled spans cannot make the codec
rescan the buffer once per span. A trailing partial `8=FIX`, or a trailing SOH,
is kept for the next read.

Known limit: a false candidate whose header is well-formed and declares a large
BodyLength makes the codec wait until that many bytes are buffered (at most
`max_message_size`) before the trailer check can reject it. That is the same
wait a real frame of that length imposes, and the frames behind it are kept, not
discarded. Also, garbage that spells a header whose declared span lands exactly
on a later frame's trailer has a corroborated boundary and is consumed with
that frame. Neither case is new to recovery mode.

### What the engine does with a skip

The reactor drains the count before handling each inbound frame and on every
100 ms tick. The tick matters because a garbled frame with nothing valid behind
it is counted while `Framed` goes on waiting for bytes. A garbled frame:

- consumes no `MsgSeqNum`. The next valid frame with a higher number is a gap
  and gets the usual `ResendRequest`;
- does not refresh the heartbeat clock, because garbled bytes are not proof of
  life. A peer that sends only garbage is timed out by the TestRequest cycle;
- is logged as a count with the session id, never as bytes, since it may carry
  `Password` (554). In recovery mode the codec's own per-skip log is at debug,
  so a garbage stream cannot flood the log at warn.

Garbled frames skipped during the Logon handshake are logged when the reactor
starts but not counted against the bound. The handshake is already bounded by
`logon_timeout`.

### The K-in-window bound

`SessionConfig::garbled_frame_limit: Option<GarbledFrameLimit>`, set with
`SessionConfigBuilder::garbled_frame_limit(max, window)` or
`SessionConfig::with_garbled_frame_limit`. Reaching `max` garbled frames within
a sliding `window` logs the session out with the reason in `Text` (58). The
engine then tears the session down without waiting for the acknowledgement,
because the link that keeps garbling is the one the acknowledgement would have
to cross. Range: `max` in `1..=1024`, `window` non-zero and at most 24 hours.
`GarbledFrameLimit::try_new` is the only constructor, so an invalid bound cannot
be represented; the builder reports one as
`SessionConfigError::GarbledFrameLimitOutOfRange`.

The default is **no bound**, because the specification sets none and the
heartbeat already bounds a peer that sends only garbage. The bound is for a
link that garbles intermittently while its valid traffic keeps the session
alive, and for `HeartBtInt = 0`, where there is no heartbeat to fall back on.

The window decision is a synchronous function that takes `now`, per ADR-0002.
The reactor supplies Tokio's clock converted at the boundary. The window keeps
at most `max` arrival times, so its memory is bounded by the configuration and
never by the input. Garbled frames are timestamped when the reactor observes
them, which is at most one tick after the codec skipped them.

## Consequences

- **Conformance:** a garbled frame no longer ends the session for either role;
  recovery is by `ResendRequest`. A garbled Logon or Logon ack is skipped and
  the handshake keeps waiting within `logon_timeout`, where it used to fail with
  `EngineError::Codec`.
- **Semver (additive):** `CodecError::is_recoverable`,
  `FixCodec::with_garbled_recovery`, `FixCodec::take_garbled_count`,
  `GarbledFrameLimit` (re-exported from `ironfix_session`),
  `MAX_GARBLED_FRAME_LIMIT`, `MAX_GARBLED_FRAME_WINDOW`,
  `SessionConfigError::GarbledFrameLimitOutOfRange` (the enum is already
  `#[non_exhaustive]`), `SessionConfig::with_garbled_frame_limit`, and
  `SessionConfigBuilder::garbled_frame_limit`.
- **Semver (breaking):** `SessionConfig` gains the public field
  `garbled_frame_limit` and becomes `#[non_exhaustive]`. Code outside
  `ironfix-session` that built a `SessionConfig` with a struct literal no longer
  compiles; it must start from `SessionConfig::new` or the builder. Reading and
  assigning fields is unaffected. The attribute makes the next knob additive.
- **Behaviour without recovery** is unchanged: every garbled frame is still an
  `Err`, with the same bytes consumed as before.
- **No performance claim.** The recovery branch is on error paths only, and the
  happy path gains one flag check per error. No figure is stated without a
  `make bench` run on named hardware (ADR-0001).
- The crate DAG is unchanged: `ironfix-transport` still depends on `core` and
  `tagvalue` only, `ironfix-session` on `core` only, and the window logic lives
  in `ironfix-engine` (crate-private) until the ADR-0002 extraction moves the
  reactor's decisions into the sans-IO core.
