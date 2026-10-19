# ADR-0002 — Sans-IO session core with the Tokio reactor as one driver

- **Status:** Accepted (owner decision on issue #64, 2026-10-17)
- **Date:** 2026-10-17

## Context

Issue #64 asks whether IronFix should offer a session engine that is not tied
to Tokio, so a consumer can drive FIX sessions from its own event loop (for
example a busy-polling, single-threaded agent that owns many non-blocking
sockets). The consumer behind the question runs "no async runtime on the
message path".

What the code does today:

- `ironfix-session` is pure protocol state (typestate FSM, `SequenceManager`,
  `HeartbeatManager`) with no I/O, but it reads the clock itself:
  `Instant::now()` in `heartbeat.rs` and `state.rs`, and `SystemTime::now()`
  for `TestReqID` generation in `heartbeat.rs`.
- The behaviour that makes a session conformant (gap recovery, resend replay,
  identity and `SendingTime` checks, the Logout handshake, heartbeat and
  TestRequest timing) lives in `ironfix-engine/src/reactor.rs` (1987 lines),
  a Tokio task per session (`spawn_session`). Its handlers take the framed
  socket and write inline, so deciding and acting are interleaved.
- The two handshakes (`acceptor.rs`, 751 lines; `initiator.rs`, 949 lines) are
  also async and write inline.
- `Application` and `MessageStore` are `#[async_trait]` traits, so every
  callback boxes a future.
- The README states "Async only" as a current limitation, and
  `doc/architecture.md` Decision 1 already sketches a sync hot path as a design
  target.

Constraints any answer keeps: the crate DAG (`session` never depends on
`tagvalue`, `store` or `transport`), the existing conformance tests, and no
performance claim without a measured baseline (ADR-0001).

## Options

1. **Keep Tokio only** and document it as a non-goal. Docs only.
2. **Sans-IO session core.** Move the reactor's decision logic into a
   poll-driven state machine whose inputs are decoded frames, ticks carrying an
   explicit monotonic time, and commands, and whose outputs are frame intents
   to write and events. The current Tokio reactor becomes one driver of it.
   Because `session` must not depend on `tagvalue`, the core emits intents and
   the driver (in `ironfix-engine`) encodes them.
3. **A second, synchronous engine** next to the async one, duplicating the
   reactor and both handshakes.

## Decision

Option 2, adopted now and built in stages:

1. **Immediately (applies to the open track-A issues #60–#82):** new session
   decision logic is written as synchronous functions that take `now` as a
   parameter and return what to do, with the async reactor only performing the
   I/O. Nothing new reads the clock inside decision code.
2. **After track A lands:** extract the reactor's decision logic into the
   sans-IO core, one handler family at a time, keeping every existing
   conformance test green on the Tokio driver at each step.
3. **Then:** add synchronous `Application` and store traits for the sans-IO
   path, and a non-Tokio driver example.

Option 1 is rejected because it leaves the consumer that raised #64 unserved.
Option 3 is rejected because it duplicates roughly 3.7k lines of conformance
code, so every protocol fix would have to land twice.

### Time source contract

The core never reads a clock. Every input that can change time-dependent state
carries a monotonic `Instant` supplied by the driver; wall-clock time for
`SendingTime` is likewise supplied, never read. `TestReqID` generation takes
its entropy from the caller. The Tokio driver passes `tokio::time::Instant`
converted at the boundary so paused-clock tests stay deterministic.

## Consequences

- **Semver:** stage 1 changes no existing API. Stage 2 changes `ironfix-session`'s
  public API (the clock becomes a parameter of `HeartbeatManager` and the state
  transitions that timestamp), which is a breaking change scheduled with the
  0.5.x/0.6 line and called out in that PR. Stage 3 is additive.
- **Track A** proceeds without waiting for the extraction, but the issues whose
  decision logic is new (#62, #66, #68, #69, #71, #76, #79, #82) follow the
  stage-1 rule, which keeps the later extraction mechanical.
- **No performance claim** is made for either driver. Any latency comparison
  between the Tokio driver and a busy-poll driver needs `make bench` on named
  hardware first.
- The crate DAG is unchanged: the core lives in `ironfix-session` (or a new
  crate depending on `core` only, decided in the stage-2 issue), and encoding
  stays in the driver.
- Follow-up issues: #90 (inject the clock into `ironfix-session`), #91
  (extract the reactor decision logic into the core), #92 (synchronous
  `Application` / store traits for the sans-IO path), #93 (a poll-driven,
  non-Tokio driver example).

## Progress

- **#90 (clock injection):** done. `HeartbeatManager::new`, `on_message_sent`,
  `on_message_received`, `should_send_heartbeat`, `should_send_test_request`,
  `is_timed_out`, `on_test_request_sent`, `time_since_last_received`,
  `time_since_last_sent` and `reset` take `now: Instant`;
  `Session::send_logon`, `Session::on_logon_received` and
  `Session::initiate_logout` take `now: Instant`; `generate_test_req_id` takes
  the `SystemTime` it encodes. These are breaking signature changes for the
  0.5.0 line. `ironfix-session/tests/no_clock_reads.rs` fails if a clock read
  returns to `ironfix-session/src`. The engine call sites still pass
  `std::time::Instant::now()`, exactly the clock the session used to read, so
  behaviour is unchanged; switching them to the reactor's paused-clock-aware
  `driver_now()` is left to #91, where the reactor's decision logic moves.
