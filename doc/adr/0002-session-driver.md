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
- **#91 stage 1 (sans-IO core, liveness family):** the core lives in
  `ironfix-session` as the `sans_io` module, not a new crate: it needs only
  `ironfix-core` and the session's own state, and the crate's dependencies are
  unchanged. It decides and never acts: no I/O, no clock read (it is covered
  by `tests/no_clock_reads.rs`), no `.await`; the driver supplies `now` and a
  summary of its output, and builds and encodes the frame it is told to send.
  Stage 1 extracts the per-tick liveness decisions: `decide_liveness`
  (heartbeat timeout, TestRequest after inbound silence, idle Heartbeat, gated
  by `LivenessGate::{DeadlinesOnly, Probe}`), `logout_timed_out` (the logout
  deadline from `Session<LogoutPending>::sent_at`) and `test_request_reply_id`
  (the `TestReqID` a Heartbeat echoes). The reactor's `on_tick` and its
  TestRequest reply now call them. Additive public surface only. The engine's
  session clock moved to `driver_now()` in the same change: every instant the
  heartbeat manager and the Logon/Logout typestate timestamps see (reactor,
  both handshakes, and `Connection::is_timed_out`) now comes from Tokio's
  clock converted at the boundary, so a paused-clock test drives them; with a
  running clock Tokio's `Instant` is the system monotonic clock, so nothing
  visible on the wire changes.
- **#91 stage 2 (sequence validation and gap recovery):** `sans_io` now also
  holds `classify_inbound` (in sequence, `PossDupFlag` (43) duplicate, too
  low, gap: `InboundSequence`), used by the reactor's main, GapFill and
  malformed-body paths; `ResendState`, moved out of the reactor with private
  fields, every clock start taking `now`; `decide_gap_request` and
  `merged_high_water` (no second request for the same gap start, a water mark
  that only rises); `note_inbound_progress` (`RecoveryProgress`);
  `decide_stall` (`StallAction::{Wait, Retry, Abandon}`); and
  `spanned_rerequest` / `spanned_high_water` (a duplicate GapFill whose
  `NewSeqNo` (36) spans missing numbers). The resend stall clock now runs on
  `driver_now()`, so paused-clock tests drive it too; with a running clock
  nothing changes on the wire. The reactor keeps every effect (writing the
  request, the Logout on an abandoned gap, the hold behind a resend). Additive
  public surface only. Remaining stages: resend replay, the Logout handshake,
  the two Logon handshakes, then the driver reduced to I/O and callbacks.
- **#91 stage 3 (resend replay):** the decisions of answering a
  `ResendRequest` (2) and the opening replay a `NextExpectedMsgSeqNum` (789)
  asks for (ADR-0021) moved into `sans_io` (in the private `replay.rs`,
  re-exported through `sans_io`). `decide_resend_request` validates
  `BeginSeqNo` (7) and `EndSeqNo` (16) and clamps the range to what was sent,
  reading infinity through `EndSeqNoInfinity` (moved from the engine's
  `wire.rs`: `999999` or `0` on FIX 4.0 and 4.1, only `0` later, issue #137);
  `decide_opening_replay` checks a 789 range. `ResendReplay` walks one range as
  request/response steps with the driver: `poll_store` asks for a page
  (`PageRequest`, answered with `on_page(PageRead)`) or completes with the
  trailing gap fill; per stored entry `screen_entry` skips what is out of
  range or administrative, and `decide_entry(seq, ReplayVerdict)` turns the
  driver's rebuild and `to_app_resend` outcome (issue #133) into a
  `ReplayAction`, so admin messages, holes, unrebuildable frames and vetoes
  coalesce into one gap fill per run. The bounds of #126 and #128 are core
  functions over core constants (`replay_step_continues`,
  `reads_yield_to_replay`, `replay_queue_full`, `hold_full`), and the rebuild's
  header decisions are `replay_field` and `orig_sending_time` (the `PossDupFlag`
  (43) and `OrigSendingTime` (122) rule). The driver keeps every effect: the
  async store read with its timeout and the corrupted-store close, the frame
  rebuild and encoding, the async replay gate, the writes, and the held
  output. A test-only transcription of the old reactor loop is checked against
  the core over 400 synthetic ranges. Additive public surface only; nothing on
  the wire changes. Remaining stages: the Logout handshake, the two Logon
  handshakes (including the 789 `plan`, still in the engine), then the driver
  reduced to I/O and callbacks.
- **#91 stage 4 (the Logout handshake):** the Logout decisions moved into
  `sans_io` (in the private `logout.rs`, re-exported through `sans_io` and the
  crate root). `check_logout_text` and `MAX_LOGOUT_TEXT_LEN` screen a
  caller's `Text` (58) (issue #69; the engine's constant of the same name is
  now an alias). `LogoutPhase` summarises the driver's phase (`Active`,
  `Queued`, `Pending`, issue #126): `decide_local_logout` lets only the first
  Logout start, `LocalLogoutReason::text` (with `resend_stalled_text`) picks
  its `Text`, `decide_logout_advance` moves a queued Logout to pending once it
  is written whole, and `accepts_application_messages` refuses new
  application messages behind it. `decide_peer_logout` decides what the
  counterparty's Logout means: it completes ours (crossed when ours was still
  queued), or it is owed a reply that waits behind a resend of ours;
  `OwedLogout` keeps the first arrival and text, and `owed_logout_due` is the
  deadline the driver checks on the tick, before each resend step and between
  held frames (issues #79, #128). `LogoutClose` is the close-reason family of
  the exchange with the graceful rule; `reply_close` and `settle_close` turn a
  close whose own Logout never reached the stream into `Unwritten`, and
  `close_resets` is the `reset_on_logout` / `reset_on_disconnect` gate, which
  is also when the durable owed-reset marker of #111 is recorded. The engine's
  `CloseReason` maps onto the family exhaustively, and `is_graceful`
  delegates to it. The driver keeps every effect: building and writing the
  Logout, the write mark, the typestate transitions, the store reset and its
  marker, and the callbacks. Test-only transcriptions of the old reactor rules
  are checked against the core. Additive public surface only; nothing on the
  wire changes. Remaining stages: the two Logon handshakes (including the 789
  `plan`, still in the engine), then the driver reduced to I/O and callbacks.
- **#91 stage 5 (the two Logon handshakes):** the Logon decisions of both
  roles moved into `sans_io` (in the private `logon.rs`, re-exported through
  `sans_io` and the crate root). Authentication order (ADR-0017):
  `decide_logon_refusal` over `LogonRole` and `LogonStage` says who gets a
  reply to a refused Logon (an initiator always files its refusal; an
  acceptor answers an unauthenticated peer with nothing while the session is
  live elsewhere or a store is attached, provisionally otherwise), and
  `default_appl_ver_id_required` is each role's `DefaultApplVerID` (1137)
  rule (#67). `ResetSeqNumFlag` (141): `reset_flag_contradicts`,
  `initiator_resets`, `acceptor_resets`, `owes_reset_durably` (the #111
  intent made durable first), `decide_ack_reset` (`AckReset`, with the
  `ADOPTED_RESET_*` counters), `classify_logon_seq` (the shared reset rule)
  and `decide_logon_gap` (hold for a 789 replay or request).
  `HeartBtInt` (108): `negotiate_logon_interval`, `interval_change` and
  `AckHeartBtIntDefect` (the Reject codes 1, 6, 5). 789 (ADR-0021):
  `declared_next_expected`, `screen_next_expected`, `NextExpectedBasis` and
  `plan_next_expected` with `NextExpectedPlan` and `NextExpectedAhead`; the
  engine's `plan` is now a mapping over it, and only the parse of the value
  stays in `next_expected.rs`. Seeding: `decide_seed_source` (`SeedSource`),
  `seed_from_initial`, `initial_below_store`, `seed_from_store`
  (`StoreSeed`), `initial_seed_applies`, `provisional_counters`, and
  `inbound_loss_span` for the #105 start report. Mismatch report (#80,
  ADR-0015): `mismatch_report_applies`, `LogonCounters` (the effective
  startup counters of each role), `compare_logon_inbound`,
  `compare_logon_outbound` and `compare_logon_sequences`; the engine's
  public `SequenceMismatch` maps the result exhaustively. Logon timeout:
  `logon_deadline`, `logon_timed_out` and `logon_ack_deadline` (from the
  typestate's `sent_at`); the handshake read in both roles and the
  registry's deadline now come from it on the driver clock. The driver keeps
  every effect: parsing the Logon's fields (CompIDs, `SendingTime`, 108,
  1137, 789), `from_admin`, the store calls and the durable marker, the
  writes, the callbacks and the typestate transitions. Test-only
  transcriptions of the old engine rules are checked against the core.
  Additive public surface only; nothing on the wire changes. Remaining
  stage: the reactor reduced to a thin driver (read, feed, encode, write,
  callbacks) over a core-owned state object.
