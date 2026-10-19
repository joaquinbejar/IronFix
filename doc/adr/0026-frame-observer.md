# ADR-0026: A capture hook for every inbound and outbound frame

- **Status:** Accepted (issue #70, in the plan the owner approved)
- **Date:** 2026-10-19

## Context

Audit and replay need a session reconstructed byte for byte. Before this
change nothing outside the engine saw the exact bytes: inbound frames reached
the application only after session processing (`from_admin`, or `from_app` on
a separate task), frames the session dropped or closed over were never
visible, and outbound frames were visible only to an attached store, which
never sees gap fills. Issue #70 asks for an optional, synchronous hook that
sees every inbound frame that passes framing and every outbound frame, with
its direction, `MsgSeqNum`, a monotonic timestamp and the session, plus a
write result per outbound frame so a capture never shows a frame as sent
when its write did not complete.

`doc/fix_operations.md` says nothing about capture: this is engine
behaviour, not FIX semantics.

Constraints any answer keeps:

- additive only at v0.4.1;
- no typestate, sequence, heartbeat or store change; the observer cannot
  change what the session does;
- no per-frame allocation from the hook, and one branch per frame without an
  observer (`ironfix-engine/tests/allocations.rs` measures it);
- the engine still never logs a frame (`Password` (554), `NewPassword` (925),
  `RawData` (96)).

## Decision

1. **`FrameObserver`** (`ironfix_engine::observer`, re-exported at the
   root): a `Send + Sync + 'static` trait with `on_inbound(&[u8],
   &Observation)`, `on_outbound(&[u8], &Observation)` and
   `on_outbound_result(&OutboundResult, &Observation)`, the last defaulted to
   a no-op. Synchronous and called inline on the reactor task (or the task
   running the handshake): it must be cheap, must not block, must not panic.
   Heavy work belongs on the observer's own queue.
2. **`Observation<'a>`**, `#[non_exhaustive]` with private fields and `const`
   getters: `direction()` (`Direction::{Inbound, Outbound}`), `kind()`
   (`FrameKind::{Handshake, Session, Replay, GapFill}`, with `is_replay()`),
   `msg_seq_num()`, `at()` (the driver's monotonic `Instant`, Tokio's clock
   per ADR-0002) and `session_id()` (borrowed). The inbound `MsgSeqNum` is
   read from the first 16 header fields with checked arithmetic, before any
   validation; it is `None` when absent or malformed.
3. **Inbound** is observed once framed, before the session acts on it: in
   the reactor before `on_frame`, and in the handshake reads before decode,
   so frames later rejected, dropped or closed over (wrong CompID,
   `SendingTime`) are in the capture. Bytes the codec skips as garbled never
   become a frame and are not observed. A Logon an `AcceptorRegistry` read
   before routing is observed by the `Acceptor` it is routed to; frames the
   registry skipped before that belong to no session and are not. Frames
   read and dropped while a closing session drains its last output are not
   observed.
4. **Outbound** is observed once built and before any byte goes to the
   stream: at feed time in the reactor (`Writer::feed_frame`, after the frame
   is in the write buffer, so a frame the codec refuses is not observed), and
   after filing and before the write in the handshake. `on_outbound` means
   queued for the wire, never written. Replays are `FrameKind::Replay`, gap
   fills `FrameKind::GapFill`, both under the number they re-occupy.
5. **Write results** use the classes of `SendOutcome` (ADR-0023):
   `OutboundResult::{Written, NotSent { reason }, Unknown { reason }}`, all
   `#[non_exhaustive]`, reusing `NotSentReason` and `UnknownReason`. Every
   observed frame gets exactly one result with the same kind and number:
   `Written` from the flush that covers it (`Writer::flushed`), `Unknown`
   from every path that resolves tracked receipts as `Unknown`
   (`Reactor::fail_receipts`). The writer keeps a queue of the observed
   frames awaiting a result, pre-allocated (256) only when an observer is
   attached. A message that reached the session and was never fed (veto,
   unframeable body, throttle, store refusal, logout pending, discarded at
   close, a gap fill `to_admin` left unframeable, a replay above
   `max_message_size`) is reported `NotSent` alone, never observed as a frame, with no
   `MsgSeqNum`; the outcome is built once and shared with the tracked
   receipt, if any. A frame numbered and filed but refused by the codec
   reports `Unknown`, as its tracked outcome does.
6. **Panics** are not caught. The release profile is `panic = "abort"`, so an
   observer that panics takes the process down; this is documented on the
   trait. Catching with `catch_unwind` would cost an unwind boundary per
   frame and would not help under `abort`.
7. **Credentials.** The observer receives raw bytes, credentials included.
   No redaction helper is offered (the issue asks for documentation, not a
   helper): redaction is the observer's responsibility, documented on the
   module, the trait and every `with_frame_observer`.
8. **Attachment:** `with_frame_observer(Arc<dyn FrameObserver>)` and
   `has_frame_observer()` on `Initiator`, `Acceptor` and `EngineBuilder`
   (which attaches it in every terminal method, each `Acceptor` of a registry
   included). Each session binds the observer to its `SessionId` once.

## Consequences

- Public surface: new module `observer` with `FrameObserver`, `Observation`,
  `OutboundResult`, `Direction`, `FrameKind`; new methods on three types.
  All additive.
- The observer delays the session for as long as it runs. A slow one shows
  up as late heartbeats and, under backpressure, as the write timeout.
- Kernel or NIC receive and transmit timestamps are out of scope; they need
  the transport seam of the generic stream work.
