# ADR-0024 — An optional per-session outbound throttle

- **Status:** Accepted (issue #82, in the plan the owner approved)
- **Date:** 2026-10-19

## Context

The engine framed application messages as fast as they were queued. Venues
publish per-session message limits and reject or disconnect a session that
exceeds them, so an initiator needs a local throttle at the venue's
published limit; and an acceptor that protects itself needs to know how fast
its counterparty sends. Issue #82 asks for a token bucket (rate, burst) per
session on outbound application messages, an optional classifier that puts
message types in separate budgets (cancels apart from new orders), a policy
per budget (`Queue { max_depth }` or `Refuse`, over-depth being a refusal),
refusals reported through the receipt of #68 (ADR-0023), and an inbound
count the application can act on.

`doc/fix_operations.md` is silent on throttling: the FIX session layer
defines no message rate. The semantics below are engine behaviour, taken
from the issue.

Constraints any answer keeps:

- no typestate or sequence change: a held message has no `MsgSeqNum` until
  it is framed, so a refusal leaves no gap;
- administrative messages are never throttled, or the session layer itself
  breaks (a Heartbeat held behind a budget lets the counterparty time the
  session out);
- the ordering guarantees of #79 and #126 (ADR-0021, ADR-0023): a resend
  stays ahead of every new number, an owed Logout stays after it, and
  `MsgSeqNum` stays unique and in order on the wire;
- the reactor never blocks: inbound reads, heartbeats and resends go on
  while application messages wait;
- the decision logic is synchronous and takes `now` (ADR-0002), on Tokio's
  clock so a paused-clock test drives it;
- no allocation per message on the steady path (the #126 allocation test);
- the public surface change is additive, and no payload reaches a log line.

## Options

Where the configuration lives:

1. **`SessionConfig`.** It is `ironfix-session`'s, which must stay pure
   protocol state with no notion of the outbound queue, and a classifier is a
   closure over `OutboundMessage`, an engine type.
2. **On the engines** (chosen): `with_throttle(ThrottleConfig)` on the
   `Initiator`, the `Acceptor` and the `EngineBuilder`, next to
   `with_outbound_capacity`. `AcceptorRegistry` gets none: it holds no
   per-session setting, and a routed session keeps the throttle of the
   `Acceptor` it is routed to.

How a message waits:

1. **Stop taking commands from the outbound queue** while the budget is
   empty, so the bounded queue itself is the delay queue and backpressures
   `Connection::send`. With one budget it is the simplest; with two, an
   order at the head of the queue would hold back every cancel behind it,
   which is what separate budgets are for, and there is no place for a
   refusal on over-depth.
2. **A bounded queue per budget inside the reactor** (chosen). The reactor
   goes on taking commands; each message is classified, and goes now with a
   token, is held behind the messages of its budget, or is refused. A
   single timer, moved to the instant the next token is earned, releases
   held messages one per loop pass.

Where it sits relative to the outbound gate (`to_app_checked`, ADR-0023):

1. **After the gate.** The gate would decide on a message that may then
   wait a long time, and a gate closed meanwhile would not stop it.
2. **Before the gate** (chosen). A held message goes through
   `to_app_checked` when it is released, at write time, as ADR-0023 wants of
   a message held behind a resend. A refusal happens before the gate runs,
   before a number is peeked and before the store is touched. A message the
   gate vetoes, or whose body the engine refuses, gives its token back: it
   never reached the wire.

The inbound side:

1. **A window count kept by the engine.** It needs a window length (one
   more knob), a lock or several atomics per inbound message for a
   consistent snapshot, and the application still needs its own rule.
2. **A hook.** `from_app` already sees every inbound application message
   and can refuse it with a `RejectReason`.
3. **A monotonic count** (chosen), `Connection::inbound_app_messages`,
   bumped by the reactor when it hands a message to the application (one
   relaxed load and store, no allocation). Sampled twice it gives the rate
   over any window the application chooses, measured where the session
   reads, not where `from_app` runs.

## Decision

### Configuration

`ironfix_engine::throttle` holds the public types. A `ThrottleBudget` is a
rate (messages, `u32`, at least 1) per window (`per`, above zero and at most
`MAX_THROTTLE_WINDOW`, one day), a burst (tokens, at least 1, default 1) and
a `ThrottlePolicy` (`Queue { max_depth }`, `max_depth` from 1 to
`MAX_THROTTLE_QUEUE_DEPTH`, 65 536, default 1024; or `Refuse`).
`ThrottleConfig::builder(default)` takes the default budget (`BudgetId` 0),
`budget` adds more (ids 1, 2, ..., at most `MAX_THROTTLE_BUDGETS`, 16, in
all), `classifier` sets an optional `Fn(&OutboundMessage) -> BudgetId`, and
`build` checks every value, returning a `ThrottleConfigError` that names the
budget and the value. A classifier that names a budget the configuration
does not define puts the message in the default budget, and the session logs
that once. `ThrottlePolicy`, `ThrottleConfigError` and the new
`NotSentReason` variants are `#[non_exhaustive]`.

### The bucket

A budget starts full (`burst` tokens) when the session becomes Active and
earns one token every `per / rate`, **rounded up** to whole nanoseconds (so
`rate` tokens never take less than `per`), up to `burst`; time spent full is
not banked. Over any half-open interval `[t, t + per)`, at most
`burst + rate - 1` messages go through a budget, so the default burst of 1
keeps a session within a venue limit of `rate` per `per` however the venue
places its window. A unit test checks that bound for a greedy sender.

The decision (`Throttle::admit`, `release`, `next_release`, `refund`) is
synchronous and takes `now`; the reactor reads `now` from Tokio's clock
(`driver_now`), and only while the throttle is in use.

### Order

Within a budget, a new message never overtakes one held before it, even
when a token is free. Across budgets, a message whose budget has a token goes
ahead of one held in another: with one budget the order is the order of the
`send` calls. Messages released at the same moment leave in the order they
were handed in (an arrival ticket per held message). The `MsgSeqNum` is
assigned when a message is framed, so the numbers on the wire stay unique
and in order.

### Release

A held message is released under the conditions a new command is taken (no
resend under way, waiting output under the 16 KiB live mark) and only while
the session is Active. A message whose token is already there is released by
an always-ready branch of the loop; one waiting for a token by a single timer
moved to the instant it is earned. Tokio's timer has a resolution of one
millisecond and rounds a deadline up, so a release through it is never early;
releasing through the always-ready branch is what lets a burst, and a budget
faster than one message per millisecond, keep its rate. Such a budget still
needs a burst of at least one millisecond's worth of tokens to keep its rate
while messages are held (with less it releases at most `burst` messages per
millisecond, never more than its rate), and the session warns at start when
it has not.

### What is never throttled

Logon, Logout, Heartbeat (the answer to a TestRequest included),
TestRequest, ResendRequest, SequenceReset and every gap fill, Reject and
XmlMessage take no token and never wait; nor does a replay (the answer to a
`ResendRequest`, the 789 resend), which resends frames that went through the
throttle when they were first sent. A held message waits behind a resend
like any new one.

### Close

When this session's own Logout is framed (asked for with
`Connection::logout`, caused by dropping every handle, or the engine's own),
it goes out at once and what the throttle holds resolves `NotSent` with
`DiscardedByThrottle`: no held message is written after the Logout. The same
happens when the session closes for any other reason (a kill, the
counterparty's Logout), before the close-time store work and before
`wait_closed` fires, so every tracked send still resolves. A released
message whose write is partial, or fails, is `Unknown`, as ADR-0023 defines.

## Consequences

- **Semver (additive):** the public module `throttle` (`BudgetId`,
  `ThrottlePolicy`, `ThrottleBudget`, `ThrottleConfig`,
  `ThrottleConfigBuilder`, `ThrottleConfigError`, `MAX_THROTTLE_BUDGETS`,
  `MAX_THROTTLE_QUEUE_DEPTH`, `MAX_THROTTLE_WINDOW`,
  `DEFAULT_THROTTLE_QUEUE_DEPTH`), the types re-exported at the crate root;
  `Initiator::with_throttle` and `Initiator::throttle`,
  `Acceptor::with_throttle` and `Acceptor::throttle`,
  `EngineBuilder::with_throttle`; `Connection::inbound_app_messages`; and
  `NotSentReason::Throttled { budget }` and
  `NotSentReason::DiscardedByThrottle { budget }` on a `#[non_exhaustive]`
  enum. `cargo semver-checks` reports no breaking change.
- **Cost:** without a throttle, one `Option` check per message and per loop
  pass. With one, a throttled message costs no allocation in steady state:
  the per-budget queue keeps its capacity and the release timer is reset,
  not rebuilt. The #126 allocation test measures a throttled window at one
  block per message, as without the throttle. No throughput figure is
  claimed.
- **Plain sends:** with a throttle the reactor goes on draining the outbound
  queue into the budgets, so `Connection::send` is no longer held back by the
  throttle; a plain send the throttle refuses is dropped with a warning
  (counted per budget, logged at the 1st, 2nd, 4th, 8th... refusal so it
  cannot flood), and `send_tracked` reports it. The documentation
  recommends `send_tracked` whenever a throttle is attached.
- **Cancels:** a cancel in its own budget can overtake the order it cancels
  while that order is still held, and the venue then rejects the cancel.
- **Tests:** unit tests of the bucket with synthetic instants (validation of
  every value, rounding, burst, refuse, over-depth, FIFO within a budget,
  independence and arrival order across budgets, refund, a clock that steps
  back, the `burst + rate - 1` bound); `ironfix-engine/tests/throttle_tests.rs`
  on a paused clock, in both roles: release in order at the rate under
  `Queue` with `Sent` only once released, refusal under `Refuse` with no gap,
  independent budgets, the TestRequest answer, the gap fill and the Logout
  while the budget is exhausted, a resend not throttled with a held message
  behind it, a held message never written after the Logout, a Logout and a
  kill with both queues full, a partial write that is `Unknown` with the rest
  `NotSent`, a veto that gives its token back, a plain send throttled, a
  budget faster than one per millisecond, and a session routed by an
  `AcceptorRegistry`. `ironfix-engine/tests/allocations.rs` adds the
  throttled window.
- **Not done:** the throttle's state does not outlive a session, so a
  reconnect starts with full budgets; a resend is never throttled, so a venue
  that counts resent messages against its limit can see a large resend
  exceed it; administrative messages take no token, so a venue that counts
  every message sees them on top of the budget; the inbound side is a count,
  not an engine-enforced limit.
