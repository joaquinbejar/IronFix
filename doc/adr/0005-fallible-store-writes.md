# ADR-0005 — Fallible, ordered store writes and a fail-closed policy

- **Status:** Accepted (issue #62, in the plan the owner approved; revised in
  the #62 review round)
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
   doing real I/O (a file, a replica) would block the runtime thread inside a
   synchronous call.
2. **Setters become `async` and return `Result`** (chosen). Matches `store`,
   `get_range`, `reset` and `refresh`, which are already async, and lets a
   durable store do I/O without blocking the runtime thread. The session still
   awaits each call, so a slow store still delays that session (see "Store
   calls run on the reactor" below).
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

A new defaulted method, `file_outbound(seq, msg_type, frame, next_sender)`,
files an outbound frame and then persists the next sender number. The default
calls `store()` and then `set_next_sender_seq()`, stopping at the first error.
A durable store can override it to make both changes in one atomic write, and
the engine then pays one call per outbound message instead of two. `FileStore`
does, with one journal record (ADR-0006).

A second defaulted method, `reset_to(next_sender, next_target)`, resets the
store and then sets both counters, for the counterparty's reset on its Logon
ack (see the order below). The default calls `reset()`, then the two setters,
stopping at the first error, and is **not atomic**: a crash between the calls
leaves the store cleared with its initial counters, and the next session's
Logon goes out at `MsgSeqNum` 1 without `ResetSeqNumFlag`, which the
counterparty reads as too low. A durable store (#78) should override it with
one atomic write; `FileStore` does, by renaming a new journal into place
(ADR-0006).

`store()` has **replace** semantics: filing under a number that is already
filed replaces the frame there. The engine relies on it, because a crash after
a frame is filed and before its number is persisted makes the next session
reuse that number for a message the peer never saw.

`set_next_sender_seq` is **not** monotonic, and a store must not reject a
lower value: a sequence reset brings it down (a Logon or Logon ack with
`ResetSeqNumFlag` (141) = Y, the `reset_on_logout` / `reset_on_disconnect`
close, a reset owed by the previous session), the close-time write after a
failed `file_outbound` writes back the number that was not spent (one below
what the failed call left behind, if it took effect and still reported a
failure, as a call that overran the store timeout can), and an explicit
`with_initial_sequences` seed can start below the stored value under
`Continue`.

`StoreError` gains `Timeout { timeout }` for a call that overran the store
timeout. Both `StoreError` and `EngineError` are `#[non_exhaustive]`.

### The order

The handshakes and the reactor go through the same step,
`persistence::file_and_spend`, so the outbound order cannot drift between them
(the acceptor's Reject and Logout, once it has a store (#60), take it too):

1. **Outbound.** For a frame numbered N: compute N+1 with checked arithmetic;
   file the frame under N and persist N+1 as the next sender number (one
   `file_outbound` call); spend N in memory and check that N was the number
   spent; write the bytes. Filing comes first, so the #89 row "counter update,
   before store write" cannot happen: a crash between the two writes leaves
   frame N with counter N, and N is reused for a message the peer never saw
   (replacing the filed frame). A crash after both leaves frame N and counter
   N+1: N is never reused, and a resend of N replays the filed frame. Memory
   and store agree before any byte is written, so a failed write afterwards
   cannot lead to N being reused either.
2. **Inbound.** When M is accepted in sequence, M+1 is persisted as the next
   target number before M is acted on, and before the in-memory expectation
   moves: before an administrative message is processed (so the receive
   cursor includes it, and a restart never asks for it again), before an
   in-sequence `SequenceReset`-GapFill reaches `from_admin` (the fill occupies
   M whatever happens next), and before an application message is handed to
   the application. For an application message a slot in the application
   queue is reserved first, so a full queue still closes the session with M
   unspent. An accepted `NewSeqNo` (36) is persisted before the expectation
   moves to it.
3. **Exceptions.** Two inbound messages reach `from_admin` before their write:
   - the initiator's Logon acknowledgement: `from_admin` may refuse the Logon,
     and the ack's `ResetSeqNumFlag` has to be applied before its number can
     be validated. Its number is persisted before the session goes Active and
     before `on_logon`;
   - a `SequenceReset` in Reset mode, which has no place in the sequence. Its
     `NewSeqNo` is persisted once `from_admin` has accepted it.
4. **Only on change.** The engine remembers the counter values it last wrote
   and writes a counter only when it moved, so an idle tick costs two integer
   comparisons and no store call. The handshake hands its record to the
   reactor (through `SessionParams`), and the counters a store reported at
   seeding are recorded as written, so the reactor's first pass writes nothing
   the handshake or the store already holds. Under `Continue` a value is
   recorded once its write was attempted, so a failing store is not retried on
   every tick.
5. **A counterparty reset on the Logon ack.** When the ack carries
   `ResetSeqNumFlag` = Y and our Logon did not ask for a reset, the store is
   reset and set to the new stream's counters (next sender 2, next target 2)
   in one `reset_to` call, before `on_logon`. Before this, the store kept the
   previous stream until the reactor's first pass: a connect abandoned inside
   `on_logon` and then retried replayed the previous stream's frames into the
   new session. A failure fails `connect` with `EngineError::Store`
   **whatever the policy**, and the reset is owed to the next connect (see "A
   reset that could not be made"): under `Continue`, carrying on with the
   previous stream filed let a `ResendRequest` in the new stream replay a
   previous-stream order at `MsgSeqNum` 1, live.
6. **A gap in the Logon exchange** is requested by the reactor as its first
   act, not by the handshake after `on_logon`. A failure to send that
   `ResendRequest` (a store refusal under `CloseSession`, a peer that stopped
   reading) then closes the session through the reactor's close path, which
   runs `on_logout`, the close-time reset and the last counter writes; before,
   `connect` returned the error after `on_logon` had fired, and none of them
   ran. Both roles do this.

### Store calls run on the reactor

Every store call is awaited inline, because its result decides whether a frame
may be written or a message acted on. A slow store therefore delays that
session's reads, heartbeats and timeout detection for as long as each call
takes. Every call is bounded by the store timeout
(`Initiator::with_store_timeout`, default: the write timeout), and an overrun
is `StoreError::Timeout`:

- a write that overruns is a failed write under the policy;
- a reset or refresh that overruns fails the connect with
  `EngineError::Store`, whatever the policy;
- a resend read (`get_page`) that overruns is answered with a gap fill, like
  any other failed read.

A session that is closing still uses the store until `Connection::wait_closed`
returns: its close-time reset, its last counter writes, and the record of a
reset it owes. `Initiator::connect` documents that, with a store attached, it
must be called again only after that; the engine does not enforce it.

### The policy

`StoreFailurePolicy` (`#[non_exhaustive]`, in the public `persistence` module,
re-exported at the crate root) with `Initiator::with_store_failure_policy`:

- `Continue` (default, the behaviour before writes were fallible): log a
  warning without frame bytes and carry on as if the write had succeeded; the
  frame is written anyway and the message acted on anyway. **It gives no crash
  guarantee**: after a failed write, a crash can leave the store behind what
  the counterparty has seen. It keeps a session running through a store
  outage, and nothing more.
- `CloseSession`: fail closed. A failed frame filing or sender-counter write
  means the frame is not written; a failed target write means the inbound
  message is not acted on and the expectation does not move; the session
  closes, not gracefully, without a Logout, since a Logout would have to be
  filed through the store that just failed. The failure is logged at error
  level. During the handshake `Initiator::connect` returns
  `EngineError::Store` and the frame is never written; that includes a store
  failure while a Logon ack is being refused, which stops the refusal (no
  Logout follows a refused Reject) and replaces the refusal's own error. A
  reply to the counterparty's Logout that the store refuses makes the close
  non-graceful, so `reset_on_logout` does not run. Only this policy turns the
  order above into a guarantee.

The resets and the refresh fail closed whatever the policy, because carrying
on past any of them runs one sequence stream over another: the reset for a
`ResetSeqNumFlag` Logon, the reset for the counterparty's `ResetSeqNumFlag`
on its Logon ack, a reset owed by an earlier session, and the refresh that
recovers the counters.

Under `CloseSession`, a sender seed from `with_initial_sequences` below the
store's next sender number is refused with
`EngineError::InitialSequenceBelowStore` before anything is written: the store
has frames at the numbers in between, so the counterparty has seen them.

The policy is a session property, not an initiator one, so the Acceptor can
take it unchanged when it gets a store (#60).

### A reset that could not be made

Two resets can fail after the decision to reset has been taken:

- `reset_on_logout` and `reset_on_disconnect` reset the store as the session
  closes. If that reset fails, **no counter is written**: the reset values
  written over a store still holding the previous stream would describe
  neither.
- The reset for the counterparty's `ResetSeqNumFlag` on its Logon ack (order
  item 5). The connect fails.

Either way the `Initiator` records that a reset is owed. Its next `connect`
resets the store before anything else, refusing the session with
`EngineError::Store` if it still cannot, whatever the policy, and its Logon
then declares `ResetSeqNumFlag` = Y and starts at 1. Without the flag the
retry would be stuck: after a failed ack reset the store still holds the old
counters (Logon at 7 against a counterparty expecting 2, and a `ResendRequest`
replaying old orders), and after a successful owed reset our Logon at 1 is
too low for a counterparty that did not reset. The record is cleared once that
Logon is acknowledged, so a connect that fails before then still owes it. It
lives in the `Initiator`, not in the store: a process restart forgets it, and
the next session starts from the counters the store still holds.

### Cancellation and timeouts

Two ways a store call can end without its error branch running, or without
the store having finished:

- **A dropped future.** A caller that drops a connect while a reset is
  pending, or a runtime that drops a closing session, runs no error branch.
  Every reset is therefore recorded as owed **before** the engine awaits it,
  and the record is cleared only once the reset has succeeded (for a reset
  declared on a Logon, once that Logon is acknowledged). This covers the
  reset for a counterparty's `ResetSeqNumFlag` on the ack, the close-time
  reset, and the reset at the start of a session that declares one.
- **A timeout.** A timeout drops the call's future, not necessarily the work
  the store has already submitted: a disk or replication write can land
  later. After any **mutation** overruns the store timeout, the engine treats
  the store as possibly holding an outstanding write and records a reset as
  owed, so the next session starts a new stream (a reset, and
  `ResetSeqNumFlag` = Y) rather than building on counters a late write may
  still move.

That second rule is sound only with a contract on the store, now stated in
the `MessageStore` documentation: **mutations take effect in call order, even
when a call's future is dropped before it completes** (a mutation takes effect
before any mutation called after it, or not at all). Serialising mutations
through an internal queue, or completing or aborting the submitted work
synchronously on drop, satisfies it. `MemoryStore` satisfies it because each
of its mutations runs to completion within one poll, under its lock and with
no await. With a conforming store a late write lands before the next session's
reset, which erases it. A store that does not conform can apply the late write
after the next session's own writes, erasing a filed frame or moving a counter
of the new stream: such a store must not be reused after a timed-out mutation.
Both behaviours are pinned by tests with a store whose reset lands after its
future is dropped.

The cost: under `Continue`, a store that overruns its timeout once costs a
sequence reset on the next session.

### Inbound delivery semantics

At most once. With M+1 durable before M is handed over, a crash after that
write and before `from_app` has finished with M loses M to the application:
on restart the engine expects M+1 and never requests M again. The window is
every message waiting in the application queue, up to its capacity
(`DEFAULT_APP_QUEUE_CAPACITY` = 1024, `Initiator::with_app_queue_capacity`),
plus the message `from_app` is handling.

The same messages can be lost **while the process runs**, without a crash:
when the session closes, the dispatcher gets `APP_DRAIN_TIMEOUT` (5 s) to
finish its queue and is then aborted. The dispatcher records the number of
each message it finishes, the reactor records the first and last numbers it
handed over, and on an abort the engine logs at error level the range it
handed over and `from_app` did not finish (the range can include the numbers
of administrative messages processed in between). A typed close reason for it
is #69.

Under `CloseSession` a message whose target write failed is never handed over.
Under `Continue` it is handed over anyway.

**What this does not provide.** The engine does not detect or report, after a
restart, the inbound messages lost across a crash, so #89's requirement that a
lost message be reported is **not met** for inbound traffic by this change.
Reporting needs:

- a completion signal from the dispatcher back to the reactor;
- a durable application watermark W, through a new defaulted `MessageStore`
  method;
- a typed report at restart of W+1 up to the persisted target minus one.

At-least-once delivery additionally needs an inbound journal, or redelivery
through a `ResendRequest` from W+1 with `PossDupFlag` handling. Both are
tracked in #105.

### Not done

- **Filing inbound frames** (an optional `store_inbound` with a default no-op,
  for audit and for takeover by a replicated store) is deferred: it costs an
  allocation and a store call per inbound frame, and no consumer needs it yet.
- **Reporting or redelivering inbound messages lost across a crash** is #105.
- The close reason is a log string; a typed close outcome on `Connection` is
  #69.
- The dispatcher-abort log line is not asserted by a test: capturing a
  `tracing` event needs a subscriber in the engine's dev-dependencies, which
  needs approval. The range computation is unit-tested.

## Consequences

- **Semver (breaking):** `MessageStore::set_next_sender_seq` and
  `set_next_target_seq` change from `fn(&self, u64)` to
  `async fn(&self, u64) -> Result<(), StoreError>`. Every implementation must
  update both methods, and callers must await them and handle the `Result`.
  `cargo-semver-checks --baseline-rev origin/main` reports it as
  `trait_method_return_value_added` on both setters; it is also declared here
  and in the commit footer, because the tool does not describe the `async`
  half of the change.
- **Semver (additive):** `MessageStore::file_outbound` and
  `MessageStore::reset_to` (both defaulted), `StoreError::Timeout`,
  `ironfix_engine::persistence` module,
  `StoreFailurePolicy` (with `closes_session`),
  `Initiator::with_store_failure_policy`, `Initiator::with_store_timeout`,
  and `EngineError::InitialSequenceBelowStore`.
- **Behaviour:** with the default policy and a working store nothing changes
  on the wire. The sender counter is now persisted before the write in the
  reactor, as it already was in the handshake, and counters are no longer
  rewritten on every tick or on the reactor's first pass. With a failing
  store, whatever the policy, a failed reset now refuses the session and the
  next Logon of the same `Initiator` declares `ResetSeqNumFlag` = Y at 1; and
  a failure to request a gap found in the Logon exchange now closes the
  session after `on_logon` (with `on_logout`) instead of failing `connect`.
- **Cost of the trait shape.** `MessageStore` is an `async_trait`, so every
  call allocates one boxed future. The outbound path makes one call per
  sequenced message (`file_outbound`), and each counter that moved costs one
  more. The engine holds the store as `&dyn MessageStore` while it writes
  (`SessionStore`), with no extra `Arc` traffic per call. No figure is stated:
  there is no measurement on named hardware (ADR-0001).
- The crate DAG is unchanged: `ironfix-store` still depends on `core` only, and
  the policy lives in `ironfix-engine`. The ordering and policy decisions are
  synchronous and read no clock (ADR-0002); only the store calls are async, and
  their timeout is the driver's.
