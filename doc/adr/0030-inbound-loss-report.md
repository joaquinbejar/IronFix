# ADR-0030 — Report inbound messages lost across a crash

- **Status:** Proposed (issue #105)
- **Date:** 2026-10-19
- **Amends:** ADR-0005 ("Inbound delivery semantics")

## Context

ADR-0005 persists the next target `MsgSeqNum` (34) before an inbound message
is acted on, so the receive cursor is exact across a crash and a failed write
under `StoreFailurePolicy::CloseSession` keeps the message from `from_app`.
The price is that inbound application delivery is **at most once**: a crash,
or a dispatcher aborted at close, between that write and `from_app`
returning loses the message to the application, and the counterparty is
never asked for it again. The window is the application queue (up to
`DEFAULT_APP_QUEUE_CAPACITY` = 1024) plus the message `from_app` is
handling. Until now nothing reported it after a restart, and the close only
logged it, so #89's acceptance gate (at most once is acceptable only if the
loss is reported) was not met for inbound traffic.

`doc/fix_operations.md` and the FIX specification say how a receiver
detects and recovers a gap in the counterparty's numbers; they are silent on
how an engine accounts for messages it accepted and its own application did
not finish. That is an engine decision, recorded here.

Issue #105 offered two options: at most once, reported (option 1), or at
least once, by redelivery (option 2, which needs an inbound journal or a
`ResendRequest` for numbers already accepted). **The owner chose option 1.**
Nothing is redelivered.

## Decision

### The watermark

The **inbound application watermark** W is the highest inbound `MsgSeqNum`
up to which every message the engine accepted was acted on: every
application message at or below it has returned from `from_app`, and every
administrative message at or below it has been processed. 0 means none.

Covering administrative messages is what makes the report exact. A
watermark of application messages only would leave every session that ends on
a Heartbeat or a Logout (all of them) with a span of administrative numbers
above it, reported as lost at every restart.

W is kept by the application dispatcher, the task that runs `from_app`:

- after `from_app` returns for message M, it publishes M in memory and
  persists it;
- the reactor publishes, after every pass of its loop, the number up to which
  it has processed or handed over everything (one below the next expected
  target number) on a `tokio::sync::watch` channel. The dispatcher takes a
  published mark only once it has delivered every frame queued before it (the
  reactor queues a frame before it publishes a mark covering it; on seeing
  the mark the dispatcher drains the queue with `try_recv`, then accounts for
  the mark). Administrative messages, gap fills and locally rejected
  application messages therefore move W, without going through the bounded
  application queue, so they can never fill it or change its capacity;
- the session's opening position (everything the handshake processed) is the
  first mark, written before any frame is delivered;
- when the queue closes at the end of a session the dispatcher accounts for
  the last mark, so a clean close leaves W at the last number accepted.

A mark is written only when it is above the last one written.

### The store contract: two defaulted methods

```rust
fn app_watermark(&self) -> u64 { 0 }
async fn set_app_watermark(&self, watermark: u64) -> Result<(), StoreError> { Ok(()) }
```

Contract: the value is not monotonic; `reset` and `reset_to` **clear** it to
0 (it describes the stream the reset replaces); `Ok` means as durable as the
store's counters (it is not forced to stable storage, unlike the owed-reset
marker of ADR-0029, because it is written on the per-message path); it is a
mutation and takes effect in call order. The defaults keep no watermark, and
the engine then reports nothing at start: a third-party store compiles and
behaves as before.

A failed watermark write is handled like every other mutation (ADR-0005,
ADR-0029): it owes a reset, because the store cannot say the failed write
changed nothing, and the policy decides the rest. Under `Continue` it is
logged; under `CloseSession` the dispatcher stops delivering and the reactor
closes the session with `CloseReason::StoreFailure`. A watermark that did not
land leaves the stored one lower, which reports more, never less.

### Reporting: a typed `Application` callback

```rust
async fn on_inbound_lost(&self, session_id: &SessionId, loss: &InboundLoss) { /* logs */ }
```

`InboundLoss` carries `first()`, `last()` (inclusive) and `cause()`, an
`InboundLossCause` (`#[non_exhaustive]`): `FoundAtStart` or
`DispatcherStopped`. The default logs the span at error level, numbers only.

A callback rather than a `CloseReason` variant or a `SendOutcome`-style
event, because:

- the main report happens at the **start** of a session, about a previous
  session that may have died with its process; there is no close to attach
  it to, and no `Connection` exists yet when the engine finds it;
- a session that closes normally has one `CloseReason`; the loss at close is
  an addition to it (a peer Logout, a store failure), not a replacement;
- the application is the party that has to act (reconcile with the
  counterparty), and every other application-facing event of the session
  already is an `Application` callback with a default.

When it is called:

- **At start**, in both roles, before the store is seeded (a reset would
  erase the numbers): before the Logon is sent (initiator) or before the
  accepted Logon is acknowledged (acceptor). The span is W+1 up to the
  stored next target minus one. After the callback returns, W is written up
  to the span's end: a crash in between reports it again, never not at all.
  Under `CloseSession` a failed write refuses the session.
- **At close**, when the dispatcher was aborted after `APP_DRAIN_TIMEOUT`,
  or stopped by a failed watermark write: the span from the in-memory W + 1
  up to the in-memory next target minus one, before `on_session_closed`.
  The watermark is then written up to its end, so the next start does not
  report it again. The drain now runs before the close-time reset, so the
  dispatcher's last write lands before the reset that clears it, and the
  span is named in the numbers of the stream it belongs to. Without a store
  the close report still works, from memory.

### The span names numbers

The span can include administrative messages processed while an application
message ahead of them was still in `from_app`, and an application message
whose `from_app` had returned but whose watermark write had not landed when
the process died. It never leaves out a message that did not reach
`from_app`. Making it name each message would need either a durable record
per message type (an inbound journal, deferred by ADR-0005) or a second
per-message write.

### `FileStore`: a field in the counter slots, journal format version 4

The counter slot grows from 44 to 52 bytes: W (`u64`) at offset 32, the
flags at 40, the CRC at 48 over bytes 0..48. A watermark write is a counter
write: the next generation, into the slot the next counter write goes to,
flushed as the `SyncPolicy` says. Every slot carries the current W, so
the newest valid slot holds it. A reset writes 0 into the new journal's
slots; a compaction and a repair carry it.

**Version 4, not an in-place change to version 3.** The compatibility rule is
ADR-0029's (and ADR-0022's before it): a journal in an unreleased development
format is refused with `StoreError::Corrupted` naming the version, not
migrated. Version 3 changed the slot layout and was never released (v0.4.1
on crates.io predates `FileStore`); version 4 changes it again. Keeping the
number 3 would make this build misread a version-3 journal's flags as W and
its CRC position as data; bumping the number refuses it cleanly. A version-3
journal is not migrated: its slots cannot say which inbound messages were
acted on, and reading them as "no watermark" would report nothing for a
journal that may hold an unreported loss.

### `MemoryStore`

An `AtomicU64`, cleared by `reset` and `reset_to`. Like the owed-reset
marker, it survives an engine restart over the same store, not a process
restart.

## Hot-path cost

The watermark write runs once per inbound application message, after
`from_app` returns, **on the dispatcher task, not the reactor**: it delays
the next `from_app`, never a socket read, a heartbeat or a send. Measured
with `ironfix-engine/tests/allocations.rs` (dhat, macOS): one more boxed
store future per message delivered (2 blocks instead of 1 with a
`FileStore`) and per locally rejected message (3 instead of 2); the profile
without TLS goes from about 12330 to about 13360 blocks. With a `FileStore`
each write is one 52-byte slot write through the writer thread, flushed as
the `SyncPolicy` says (one more fsync per message under `EveryWrite`). The
reactor adds an atomic load and a comparison per loop pass, and a `watch`
send per advance. No latency figure is claimed (ADR-0001: no baseline).

Rejected alternatives:

- **Coalescing**: write W only when the queue is empty, or every N
  messages. Cheaper under load, but a crash then reports up to N delivered
  messages as lost, so the report stops being exact exactly when the queue is
  deep, which is when it matters.
- **Piggybacking on the next target write**: the next inbound message's
  counter write carries the previous W. No extra write, but W lags by one
  message and by the whole queue depth under load, with the same inexactness,
  and a session that goes quiet never writes it.
- **The reactor writing W on a completion signal**: puts a store call on the
  reactor's path for every delivery, which is what the dispatcher exists to
  avoid.

## Consequences

- A crash anywhere from the target write of message M to the watermark write
  after `from_app(M)` reports M at the next start, in both roles: tested in
  `ironfix-engine/tests/lost_inbound_tests.rs` for both store types, with
  the span asserted exactly and nothing redelivered; a crash after the
  watermark write and a clean close report nothing; a reset at the next start
  reports the old span first and clears W; a dispatcher aborted after its
  drain timeout, or stopped by a failed watermark write, reports at close and
  not again at the next start.
- **Residual window:** a crash after `from_app(M)` returned and before its
  watermark write landed reports M although the application saw it. The
  application must treat the span as "may not have been seen".
- A store whose watermark writes all failed under `Continue` holds W = 0,
  which reads as "none": nothing is reported for that stream.
- The span is reported to the application; recovering the content (asking
  the counterparty out of band, an order status request) is the
  application's business. The engine does not send a `ResendRequest` for
  numbers it has accepted.
- Public surface: two defaulted `MessageStore` methods (additive); one
  defaulted `Application` method (additive); a new public module
  `ironfix_engine::loss` with `InboundLoss` and `InboundLossCause`
  (re-exported at the crate root). A minor bump. The journal format bump to 4
  breaks development-build version-3 journals; none was released.
