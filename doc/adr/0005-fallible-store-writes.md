# ADR-0005 — Fallible, ordered store writes and a fail-closed policy

- **Status:** Accepted (issue #62, in the plan the owner approved)
- **Date:** 2026-10-18

## Context

`MessageStore` could not express a durable write.
`set_next_sender_seq` and `set_next_target_seq` were synchronous and returned
nothing, and the engine treated a failed `store()` of an outbound frame as a
warning and sent the frame anyway. That is right for `MemoryStore`, but a
persistent or replicated store (#78) must be able to report a failed write
and, when the deployment requires it, keep the engine from putting a message
on the wire, or acting on an inbound one, that the store has not accepted.
Session state that must survive a crash or a takeover (the next outbound
number, the receive cursor, the outbound journal) is only trustworthy if the
engine never runs ahead of the store.

The write order was also inconsistent. The Logon handshake filed a frame and
mirrored the sender counter before writing it, but `Reactor::send` mirrored
the counter only after the write. The target counter was mirrored after each
event, after an application message had already been queued for `from_app`.
Both counters were written after every event, including the 100 ms tick.

#89, the joint crash and takeover acceptance gate, needs the ordering stated
precisely, and needs the inbound delivery semantics on a crash between the
counter write and `from_app` documented so it can test them.

## Options

1. **Setters stay synchronous, return `Result`.** Smallest change, but a store
   doing real I/O (a file, a replica) would block the reactor inside a
   synchronous call.
2. **Setters become `async` and return `Result`** (chosen). Matches `store`,
   `get_range`, `reset` and `refresh`, which are already async, and lets a
   durable store do I/O without blocking.
3. **Inbound semantics: at least once.** Persist the target counter only after
   `from_app` returns. That requires the application dispatcher (a separate
   task) to report completions and the reactor to persist a watermark behind
   the in-memory expectation. It also conflicts with the approved ordering
   "persisted before the message is handed to the application" and with the
   fail-closed requirement that a failed write keep the message from
   `from_app`.
4. **Inbound semantics: at most once** (chosen, as the consequence of that
   ordering).

## Decision

### The trait

`MessageStore::set_next_sender_seq` and `set_next_target_seq` become
`async fn (&self, u64) -> Result<(), StoreError>`. `MemoryStore` stays
infallible in practice. The trait's module docs state the ordering contract
below, and that a store error must never contain frame bytes.

### The order

The handshakes and the reactor go through the same helper
(`persistence::SessionStore`), so the order cannot drift between them:

1. **Outbound.** For a frame numbered N: file the frame under N; persist N+1
   as the next sender number; spend N in memory; write the bytes. Filing comes
   first, so the #89 row "counter update, before store write" cannot happen: a
   crash between the two writes leaves frame N with counter N, and N is reused
   for a message the peer never saw (overwriting the filed frame). A crash
   after both leaves frame N and counter N+1: N is never reused, and a resend
   of N replays the filed frame. Memory and store agree before any byte is
   written, so a failed write afterwards cannot lead to N being reused either.
2. **Inbound.** When M is accepted in sequence, M+1 is persisted as the next
   target number before M is acted on: before an administrative message is
   processed (so the receive cursor includes it, and a restart never asks for
   it again), and before an application message is handed to the application.
   For an application message a slot in the application queue is reserved
   first, so a full queue still closes the session with M unspent. In the
   initiator handshake, the Logon ack is validated (including `from_admin`)
   before its number is consumed, and that number is persisted before the
   session goes Active.
3. **Other changes** (a `SequenceReset`, a gap fill, a reset) are persisted at
   the end of the event that made them, before the next event is handled.
4. **Only on change.** The reactor remembers the counter values it last wrote
   and writes a counter only when it moved, so an idle tick costs two integer
   comparisons and no store call. Under `Continue` a value is recorded once its
   write was attempted, so a failing store is not retried on every tick.

### Inbound delivery semantics

At most once across a crash. With M+1 durable before M is handed over, a
crash after that write and before `from_app` has finished with M loses M to
the application: on restart the engine expects M+1 and never requests M again.
The window is the application queue (up to its capacity) plus the message
`from_app` is handling. The engine does not detect or report such a loss after
a restart. While the process runs, a message whose target write did not
succeed is never handed over, so nothing is skipped silently there.

#89 asks that a message lost this way be reported. Nothing in this change can
report it. That needs an application-acknowledged cursor (at least once, with
redelivery flagged by `PossDupFlag`) and is left for #89 to decide.

### The policy

`StoreFailurePolicy` (`#[non_exhaustive]`, in the public `persistence` module,
re-exported at the crate root) with `Initiator::with_store_failure_policy`:

- `Continue` (default, the behaviour before writes were fallible): log a
  warning without frame bytes and carry on; the frame is written anyway.
- `CloseSession`: fail closed. A failed frame filing or sender-counter write
  means the frame is not written; a failed target write means the inbound
  message is not acted on; the session closes without a Logout, since a Logout
  would have to be filed through the store that just failed. During the
  handshake `Initiator::connect` returns `EngineError::Store` and the frame is
  never written.

The policy is a session property, not an initiator one, so the Acceptor can
take it unchanged when it gets a store (#60).

### Not done

- **Filing inbound frames** (an optional `store_inbound` with a default no-op,
  for audit and for takeover by a replicated store) is deferred: it costs an
  allocation and a store call per inbound frame, and no consumer needs it yet.
- A failed `reset()` of the store when a session closes is still logged and
  ignored: the session is already over.
- The close reason is a log string; a typed close outcome on `Connection` is
  #69.

## Consequences

- **Semver (breaking):** `MessageStore::set_next_sender_seq` and
  `set_next_target_seq` change from `fn(&self, u64)` to
  `async fn(&self, u64) -> Result<(), StoreError>`. Every implementation must
  update both methods, and callers must await them and handle the `Result`.
  `cargo-semver-checks --baseline-rev origin/main` reports it as
  `trait_method_return_value_added` on both setters; it is also declared here
  and in the commit footer, because the tool does not describe the `async`
  half of the change.
- **Semver (additive):** `ironfix_engine::persistence` module,
  `StoreFailurePolicy` (with `closes_session`), and
  `Initiator::with_store_failure_policy`.
- **Behaviour:** with the default policy nothing changes on the wire. The
  sender counter is now persisted before the write in the reactor, as it
  already was in the handshake, and counters are no longer rewritten on every
  tick.
- **No performance claim.** The common path adds no store call per tick; the
  ordering adds no store call per message beyond the ones already made
  (filing, plus one counter write per message whose counter moved). No figure
  is stated without a `make bench` run on named hardware (ADR-0001).
- The crate DAG is unchanged: `ironfix-store` still depends on `core` only, and
  the policy lives in `ironfix-engine`. The ordering and policy decisions are
  synchronous and read no clock (ADR-0002); only the store calls are async.
