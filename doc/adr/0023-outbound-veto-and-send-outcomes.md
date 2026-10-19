# ADR-0023 — An outbound veto and per-message send outcomes

- **Status:** Accepted (issue #68, in the plan the owner approved; revised in
  the #68 architecture and protocol review round, and for the buffered writer
  of #126)
- **Date:** 2026-10-18

## Context

The outbound application path could neither refuse a message nor say what
became of it. `Application::to_app` could only mutate the body, a body the
engine then refused was dropped with a warning, and `Connection::send` returned
`Ok` once the message was queued, never the `MsgSeqNum` it went out with.

An initiator-side order gateway needs both. Its pre-trade risk check and kill
state must sit in a gate on the outbound application path that nothing
bypasses (the QuickFIX equivalent is throwing `DoNotSend` from `toApp`), and
it must know which messages reached the wire under which numbers, so that a
lost response can be marked unknown rather than assumed lost.

Constraints any answer keeps:

- no typestate change, and the ADR-0005 write order (file, persist, spend,
  write) for every message that is not refused;
- a refused message spends no number and is not filed, so it leaves no gap;
- administrative messages stay non-refusable: they are what keeps the
  session legal;
- `Connection::send` keeps its signature and stays fire-and-forget, with no
  per-message allocation;
- the public surface change is additive, and no credential (554, 925,
  `RawData`) reaches a log line or an outcome.

## Options

1. **Change `to_app` to return a verdict.** The direct shape, and QuickFIX's
   (`toApp` throws). It breaks every implementor of `Application`, published
   at 0.4.x, for a capability most of them do not use.
2. **A defaulted `to_app_checked`** (chosen). A new trait method whose
   verdict is `Result<(), RejectReason>`, and whose default runs `to_app` and
   sends. Existing implementors compile and behave exactly as before; an
   implementor that wants a gate overrides one method. The cost is a sharp
   edge for wrappers: one that delegates `to_app` alone inherits the default
   and silently skips the inner gate, so the documentation tells a wrapper to
   forward `to_app_checked` too.
3. **A separate gate object** registered on the builder. It splits the
   outbound callbacks across two places, and the gate would still need the
   same position in the reactor.

For the outcome:

1. **`send` returns the outcome.** Breaking, and it would make every send pay
   for tracking.
2. **A receipt handle** (`send_tracked` returning a future-like receipt
   inside a `Result`). It separates "queued" from "resolved", at the price of
   a public receipt type and two error channels.
3. **`send_tracked` returns a bare `SendOutcome`** (chosen). One opt-in
   method, one return type: the caller's own input errors (an administrative
   MsgType, a reserved tag) are `NotSent` with `Invalid`, the same class as a
   body the callback broke, and a closed session is `NotSent` with
   `SessionClosed`. Pipelining is still possible by polling several calls
   concurrently; each is queued when first polled.

## Decision

### The gate's shape: a `SendVerdict`, not an `async fn`

`to_app_checked` is a plain method returning `SendVerdict<'a>`, a small
future the engine awaits, rather than an `async fn` returning
`Result<(), RejectReason>`. The trait is an `async_trait` trait, so an `async
fn` default that awaited `to_app` would box two futures per application
message, the default's and `to_app`'s, where the engine boxed one before:
every existing implementor would pay an allocation per message for a gate it
does not use. The #126 allocation test (`ironfix-engine/tests/allocations.rs`)
pins the budget at one block per live send, and caught it.

The options weighed for the shape:

1. **`async fn to_app_checked(...) -> Result<(), RejectReason>`.** Rejected:
   two boxed futures per message on the default path, as above.
2. **A synchronous `fn to_app_checked(...) -> Result<(), RejectReason>`.**
   Rejected. A synchronous method cannot default to the asynchronous
   `to_app`, so the engine would need two callbacks per message (`to_app`,
   then the synchronous check) and would always pay `to_app`'s boxed future
   even for an application whose gate decides everything; and a gate that
   later needs to wait (a remote risk service) could only be added by
   changing the method's signature, a breaking change.
3. **A return-position `impl Future`.** Rejected: the trait would no longer
   be object-safe (see below).
4. **A concrete future type, `SendVerdict`** (chosen).

`SendVerdict` has three forms: the default wraps the boxed future `to_app`
already returns, without boxing it again (one block per message, as before);
`SendVerdict::ready` holds a decision taken at once and allocates nothing, so
an in-process kill switch or risk check costs nothing extra; and
`SendVerdict::new` boxes a decision that must wait, once. While a
`SendVerdict::new` decision is pending the reactor awaits it inline: it reads
nothing, flushes nothing and answers no Heartbeat or TestRequest, so a risk
check belongs in `ready`. A verdict polled again after it resolved vetoes
(`RejectReason` code 0, "verdict already consumed") rather than sending a
message it no longer decides about; the engine never repolls one. The trait
stays
object-safe: the method has lifetime parameters and a concrete return type,
nothing generic. A return-position `impl Future` would have avoided the type
but made the trait no longer object-safe, a breaking change for any
`dyn Application`. The price is that an override is written as a plain `fn`,
not an `async fn`, inside the `#[async_trait]` impl; the trait documentation
shows one.

### The gate

`Application::to_app_checked` runs inline in the reactor, on every **new**
outbound application message, when it is about to be written: before a
sequence number is peeked and before the store is touched. A veto spends
nothing and files nothing, and the next message takes the number the vetoed
one would have had. Because it runs at write time, not at queue time, a
message waiting behind a resend is checked once the resend is done, so a gate
closed meanwhile still stops it. `Connection::send` goes through it too: the
gate is useless if a second send path bypasses it, and an implementor that
overrides only `to_app` sees no change. A veto on a plain `send` is logged at
debug level with the reason's code.

Administrative messages (Logon, Logout, Heartbeat, TestRequest,
ResendRequest, SequenceReset, Reject, XmlMessage) go through `to_admin`,
which can mutate but not refuse them.

**Replays are not gated.** The answer to a `ResendRequest` and the
`NextExpectedMsgSeqNum` (789) resend write each filed frame as it was filed,
with `PossDupFlag` (43) = Y, without calling the gate. QuickFIX calls `toApp`
on each resent application message and gap-fills one that throws
`DoNotSend`. Gating replays needs the stored frame decoded back into an
`OutboundMessage` for the callback, and a veto turned into a gap fill inside
the resend writer; it is left to a follow-up issue and stated as a gap in the
README.

### Three outcome classes

`SendOutcome` has three classes, which never collapse into one another:

- **`Sent { seq, sending_time, filed }`**: a flush that covers the frame
  completed. `Sent` means **flushed**, handed to the stream in full, not
  queued, not buffered and not acknowledged. Whether the store confirmed it
  filed the frame is reported separately, in `filed`, because under
  `StoreFailurePolicy::Continue` a frame whose filing failed still goes out.
  `filed` false means filing was **not confirmed**, not that the frame is
  absent from the store: a store can save the frame and still return an
  error (or time out), so a `ResendRequest` covering an unconfirmed frame
  replays it if the store holds it and gap-fills it if not. `filed` is false
  without a store.
- **`NotSent { reason }`**: no byte of the frame reached the stream and no
  number was spent. `NotSentReason` is `Vetoed`, `Invalid`, `StoreRefused`,
  `SequenceExhausted`, `SessionClosed`, `LogoutPending`, `Discarded` or
  `DiscardedBehindResend`. `Invalid` carries a detail that names the tag (and,
  for an administrative MsgType, the MsgType) and never quotes a field value,
  plus the tag itself. `StoreRefused` carries `state_unknown`, always true
  today: a failed store write may have landed, which within the process the
  owed reset erases, but which a restart can replay (the owed record is in
  memory only, #111).
- **`Unknown { seq, reason }`**: the frame was numbered (being filed, or in
  the session's write buffer) and the session ended before a flush covering
  it completed: a failed write (`Transport`), output that made no progress
  for the write timeout (`WriteTimeout`), a closing flush that did not drain,
  or a reactor stopped mid-way (`Interrupted`). A number is spent when the
  frame is buffered, so a frame that never left the buffer is `Unknown`, not
  `NotSent`: the engine cannot say no byte of it reached the stream. The
  number stays spent. **The order may
  be live**: the documentation tells the caller to reconcile it by `ClOrdID`
  after the next Logon (`ExecutionReport`, `OrderStatusRequest`) and, if it
  must be resubmitted, to reuse the `ClOrdID` with `PossResend` (97) = Y. The
  frame is replayed only if it was filed, no reset erased it (at the close, or
  by `ResetSeqNumFlag` (141) on the next Logon), the store still holds it,
  and the counterparty asks; each condition is documented.

A receipt marks the frame as being filed before `file_and_spend` and as
buffered once it is fed, so a receipt dropped mid-way (a runtime shutting
down) reports `Unknown`, never `NotSent`. Every receipt resolves,
explicitly or as it is dropped, before `Connection::wait_closed` fires, and
`send_tracked` also waits on the close, so it cannot hang.

### Field types

`seq` is a `u64`, the type of every sequence number on the public surface
(`Connection::next_sender_seq` and the rest), not `SeqNum`. `sending_time` is
`ironfix_core::types::Timestamp`, the workspace's own time vocabulary type,
captured right after the frame is encoded and truncated to the precision the
session writes on the wire (whole seconds on FIX 4.0 and 4.1, milliseconds
from FIX 4.2, #134), so it equals the `SendingTime` (52) the counterparty
reads: a deliberate choice over
`chrono::DateTime<Utc>`, which would put a second time type on the engine's
surface; `Timestamp::to_datetime` converts when a caller needs one.

### `#[non_exhaustive]` posture

`SendOutcome`, `NotSentReason` and `UnknownReason` are `#[non_exhaustive]`,
and so is every variant that carries data, so a field can be added without a
major release. The reasons that report a session ending (`SessionClosed`,
`Discarded`, `DiscardedBehindResend`) are empty struct variants for the same
reason: a typed close reason (#69) is the candidate field. `SendOutcome` and
`send_tracked` are `#[must_use]`. A consequence is that code outside the
crate can match outcomes but not construct them, so a test double of a
`Connection` cannot return one yet; a constructor can be added later without
a break.

### Resolution on flush (#126)

The reactor writes through a buffer (#126): a frame is fed to it, and the
buffer is written out, and the stream flushed, while the reactor goes on
reading. Outcomes follow the buffer:

- When a tracked frame is fed, its receipt goes into a FIFO of pending
  entries `(seq, sending_time, filed, receipt)`, in number order.
- `Reactor::on_flushed`, the one place a completed flush is seen, is told the
  first and last new `MsgSeqNum` the flush covered (resends and gap fills
  re-occupy old numbers and are not counted). A completed flush wrote
  everything fed before it, so it resolves as `Sent` every pending entry,
  through one helper, `Reactor::resolve_sent`, without comparing numbers (a
  debug assertion checks the entries are in `MsgSeqNum` order).
- A failed flush and the tick's write timeout both end in
  `Reactor::close_on_write_failure`, which resolves every pending entry as
  `Unknown` with `Transport` or `WriteTimeout`, each with its spent number;
  so does a write-through that fails.
- At close, the session's last flush (`flush_on_close`) reports whether it
  drained the buffer: if it did, the pending entries are `Sent`; if not, they
  are `Unknown` with `Transport` (the write failed) or `WriteTimeout` (the
  stream stopped taking bytes). This happens before `wait_closed` fires.

A completed flush resolves every frame it wrote at once, so `Sent` for one
message can arrive after later messages were buffered, and a burst that the
stream takes in one flush resolves together.

## Consequences

- **Semver (additive):** `Application::to_app_checked` (defaulted) and
  `application::SendVerdict` (re-exported at the crate root),
  `Connection::send_tracked`, the public module `outcome` with `SendOutcome`,
  `NotSentReason` and `UnknownReason` (re-exported at the crate root), and
  `PartialEq`/`Eq` on `RejectReason`. `cargo semver-checks` reports no
  breaking change, so this is a minor release.
- **Cost:** an application message costs the same one allocation as before
  (`to_app`'s future) through the default gate, none more through a
  `SendVerdict::ready` gate, and one through a `SendVerdict::new` gate. A
  plain `send` allocates nothing for tracking; its queue slot
  grows by the size of an empty receipt option. A tracked send allocates one
  single-use channel. A veto costs the callback and nothing else.
- **Close path:** the reactor closes the outbound queue when the session
  ends and resolves whatever is still queued: `DiscardedBehindResend` when a
  resend was under way, or `LogoutPending` instead when that resend followed
  this session's own Logout, and `Discarded` otherwise, this session's
  Logout framed ahead of the message or not. A message the reactor reached
  while its own Logout was pending had already resolved `LogoutPending`. The
  count of discarded messages, tracked or not, is logged.
- **Tests:** `ironfix-engine/tests/send_outcome_tests.rs` covers the veto in
  both roles (no number spent, nothing filed, no gap), `Sent` only after the
  flush, `filed` under both store policies, `Unknown` on a stalled write with
  the replay from the store and the reset that prevents it, the closing
  flush (drained: `Sent`; stalled: `Unknown`), every `NotSentReason`, a
  redaction check on `Invalid`, administrative messages that cannot be
  vetoed, an application that overrides only `to_app`, sends held behind a
  resend and behind a 789 resend, a gate closed while one waits, and a full
  queue at a kill, at this session's Logout and at the counterparty's. The
  kill test asserts invariants rather than an exact split: which queued
  messages got a number before the reactor saw the dead stream depends on
  scheduling, and each of those is `Unknown`, with the numbers in order and
  `next_sender_seq` counting exactly them. `ironfix-engine/src/wire.rs`
  checks that the reported `SendingTime` is the one on the wire in both
  precisions.
- **Not done:** gating replays (a follow-up issue); durability of the owed
  reset across a restart (#111); a typed close reason (#69).
