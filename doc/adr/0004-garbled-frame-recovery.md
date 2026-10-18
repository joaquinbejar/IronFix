# ADR-0004 — Skip garbled inbound frames inside the codec

- **Status:** Accepted (issue #66, in the plan the owner approved on 2026-10-17)
- **Date:** 2026-10-17

## Context

FIX classes a message whose framing cannot be trusted as *garbled*: BeginString
(8) is not the first field, BodyLength (9) is not the second or disagrees with
the frame, MsgType (35) is not the third, or CheckSum (10) is absent, malformed,
wrong or not last. The FIX Session Layer says a garbled message is ignored. It
is not rejected and not counted, and its `MsgSeqNum` (34) is not consumed,
because it cannot be trusted. The gap it leaves is recovered by the normal
`ResendRequest` (2) path on the next well-formed message (`doc/fix_operations.md`,
"Garbled Messages and Transport Resynchronization").

Before this change IronFix ended the session on the first garbled frame. The
reactor treated every codec `Err` as fatal, and that was not the only problem:
`tokio_util::Framed` latches an error flag after any decoder error and returns
`None` on the next poll, so the resynchronisation `FixCodec` already performed
on some error paths could not be reached from the engine at all. A frame that
framed but did not decode was dropped with a warning in session but failed the
Logon handshake outright, and neither path distinguished it from other drops.

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
one call does work linear in the buffered bytes, and skipping itself never
allocates.

### Recoverable and fatal

`CodecError::is_recoverable()` is the single classification at the framing
level.

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

A frame that frames but fails to decode (MsgType not third, a malformed tag) is
garbled at the decode level. The codec cannot see that; the engine treats it
exactly like a frame the codec skipped (see below).

### The resync anchor

Without recovery the codec resyncs on `<SOH>8`, because a bare `8=` occurs
inside ordinary tags (`18=`, `58=`). The cost is that a valid frame arriving
straight after garbage is lost with it, since its `8=` follows the garbage and
not an SOH.

In recovery mode neither of those simple anchors is safe. A bare `<SOH>8`
matches every tag from 80 to 89 and from 800 up, so the resync through one
skipped frame stopped at each of them and counted it as another garbled frame:
one ExecutionReport carrying tags 851, 828 and 880 counted 4, enough to trip a
limit of 3. A bare `8=FIX` matches a complete frame embedded in a data field
(RawData 96, XmlData 213, EncodedText 355) of a garbled outer frame, and the
resync then handed that embedded frame up as a phantom inbound message.

So in recovery mode a candidate is accepted only when both hold:

- the bytes from it open a real header: `8=`, a FIX-family BeginString
  (`FIX.4.0` to `FIX.4.4`, `FIXT.1.1`), SOH, `9=`;
- the byte before it is a plausible frame boundary: SOH, the start of the
  buffer, or any byte that is neither an ASCII digit nor `=`. That excludes a
  tag (`448=FIX…`) and the first byte of a field value (`96=8=FIX…`,
  `213=8=FIX…`).

The shape is checked inside the resync scan before a candidate is returned, so
a false start costs about a dozen byte comparisons and is never counted as a
garbled frame. The scan is one forward pass that stops at the first candidate,
so a buffer of many near-anchors cannot make the codec rescan the buffer once
per near-anchor; such a buffer counts as a single garbled span. A partial
header opening cut off by the end of the buffer is kept for the next read to
complete. A lone trailing SOH is not kept: the anchor finds the next frame
without it, and keeping it would count the same garbage twice.

Residual risk: a data field whose value itself contains
`<SOH>8=FIX.4.x<SOH>9=`, inside a frame that is already garbled badly enough to
need a resync through it, can still be resynchronised onto. A frame whose
opening follows an ASCII digit or `=` (for example after garbage that ends in a
digit) is passed over by design, and its gap is recovered by `ResendRequest`. A
stream whose BeginString is not in the family still frames, but a resync never
lands on it.

### Known limits

These only show in recovery mode: without it the first garbled frame ends a
`Framed` stream, so nothing after it is ever framed.

- A real frame whose BodyLength is corrupted *upward* holds every later frame
  in the buffer until the declared span has arrived (at most
  `max_message_size`), because only then can its trailer be checked and
  rejected. The frames behind it are kept, not discarded, but they are delayed;
  on a quiet session the heartbeat and TestRequest timeout can fire first.
  Detecting this earlier is out of scope here.
- A candidate that passes the anchor check and declares a large BodyLength
  imposes the same wait. After the anchor change this needs a complete header
  opening after a boundary, which in practice means the data-field case above.
- Garbage that spells a header whose declared span ends exactly on a later
  frame's `<SOH>10=NNN<SOH>` has a corroborated boundary, and the checksum error
  consumes that frame with it. The gap is then recovered by `ResendRequest`.

### What the engine does with a skip

The reactor reads the codec's count before handling each inbound frame and on
every 100 ms tick. The tick matters because a garbled frame with nothing valid
behind it is counted while `Framed` goes on waiting for bytes. The read is
synchronous and the common case ends there: only a non-zero count reaches the
cold path, and only a configured limit reads the clock. A frame that frames but
does not decode joins the same path with a count of one. A garbled frame:

- consumes no `MsgSeqNum`. The next valid frame with a higher number is a gap
  and gets the usual `ResendRequest`;
- does not refresh the heartbeat clock, because garbled bytes are not proof of
  life. A peer that sends only garbage is timed out by the TestRequest cycle;
- is logged as a count and a static cause with the session id, never as bytes,
  since it may carry `Password` (554). A decode-level drop is labelled from the
  `DecodeError` variant, never from its `Display`, which can quote input. In
  recovery mode the codec emits one debug event per skip, so a garbage stream
  cannot flood the log at warn.

Both Logon handshakes read through one helper that skips garbled frames of
either kind under a single `logon_timeout`, so garbage cannot extend the wait. A
counterparty that never sends an intact Logon or Logon ack ends in
`EngineError::LogonTimeout`. The skips are reported once when the read ends,
including on the failure paths, so a timeout after garbage is diagnosable; they
are not counted against the bound.

A fatal codec error still closes the session. For an oversized frame the write
side still works, so an Active session first sends a Logout with `Text` (58)
"message too large". A typed close reason on the `Connection` is issue #69.

### The K-in-window bound

`SessionConfig::garbled_frame_limit: Option<GarbledFrameLimit>`, set with
`SessionConfigBuilder::garbled_frame_limit(max, window)` or
`SessionConfig::with_garbled_frame_limit`. Reaching `max` garbled frames within
a sliding `window` logs the session out with the reason in `Text` (58). The
engine then tears the session down without waiting for the acknowledgement,
because the link that keeps garbling is the one the acknowledgement would have
to cross; a session already waiting on its own Logout is torn down without a
second one. Range: `max` is a `NonZeroU32` of at most 1024, `window` non-zero
and at most 24 hours. `GarbledFrameLimit::try_new` is the only constructor, so
an invalid bound cannot be represented; the builder reports one as
`SessionConfigError::GarbledFrameLimitOutOfRange`.

The default is **no bound**, because the specification sets none and the
heartbeat already bounds a peer that sends only garbage. The bound is for a
link that garbles intermittently while its valid traffic keeps the session
alive, and for `HeartBtInt = 0`, where there is no heartbeat to fall back on.

The window decision is a synchronous function that takes `now`, per ADR-0002,
and its verdict is `#[must_use]`. The reactor supplies Tokio's clock converted
at the boundary. The window reserves room for `max` arrival times when it is
built and never holds more, so its memory is bounded by the configuration,
never by the input, and recording never reallocates. Garbled frames are
timestamped when the reactor observes them, at most one tick after the codec
skipped them.

## Consequences

- **Conformance:** a garbled frame no longer ends the session for either role;
  recovery is by `ResendRequest`.
- **Semver (additive):** `CodecError::is_recoverable`,
  `FixCodec::with_garbled_recovery`, `FixCodec::take_garbled_count`,
  `GarbledFrameLimit` (`try_new(NonZeroU32, Duration)`, `max`, `window`;
  re-exported from `ironfix_session`), `MAX_GARBLED_FRAME_LIMIT`,
  `MAX_GARBLED_FRAME_WINDOW`, `SessionConfigError::GarbledFrameLimitOutOfRange`
  (the enum is already `#[non_exhaustive]`),
  `SessionConfig::with_garbled_frame_limit`, and
  `SessionConfigBuilder::garbled_frame_limit`.
- **Semver (breaking):**
  - `SessionConfig` gains the public field `garbled_frame_limit` and becomes
    `#[non_exhaustive]`. Outside `ironfix-session`, building one with a struct
    literal no longer compiles, and neither does functional-update syntax
    (`SessionConfig { heartbeat_interval, ..SessionConfig::new(..) }`). To
    migrate, start from `SessionConfig::new` or `SessionConfigBuilder`, then use
    the `with_*` setters or assign the public fields on a `let mut` binding.
    Reading and assigning fields is unaffected, and the attribute makes the next
    knob additive. `ironfix-engine` and `ironfix-example` re-export
    `SessionConfig`, so the break reaches their users too; `cargo-semver-checks`
    reports it only on `ironfix-session`, because it cannot see re-exported
    items.
  - Behaviour: a counterparty that sends only garbled Logon (acceptor) or Logon
    ack (initiator) frames now ends the handshake in `EngineError::LogonTimeout`
    after `logon_timeout`, where it used to end at once in `EngineError::Codec`
    or `EngineError::Decode`.
- **Behaviour without recovery** is unchanged: every garbled frame is still an
  `Err`, with the same bytes consumed as before.
- **No performance claim.** The codec's recovery code runs on error paths only,
  and skipping itself never allocates. In the reactor the common path adds one
  integer read per inbound frame and per tick. `ironfix-transport/benches/framing.rs`
  measures a recovery-on clean batch and three garbled shapes, but no figure is
  stated without a `make bench` run on named hardware (ADR-0001).
- The crate DAG is unchanged: `ironfix-transport` still depends on `core` and
  `tagvalue` only, `ironfix-session` on `core` only, and the window logic lives
  in `ironfix-engine` (crate-private) until the ADR-0002 extraction moves the
  reactor's decisions into the sans-IO core.
