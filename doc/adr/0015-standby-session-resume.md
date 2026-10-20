# ADR-0015: Resuming a session on a standby process

- **Status:** Accepted (issue #80): option 2, the owner's choice, which
  includes option 1's documented store contract
- **Date:** 2026-10-20

## Context

A FIX acceptor run as an active/standby pair (a venue gateway is the usual
case) must let the counterparty reconnect to the standby and continue the
same session: the same next expected inbound `MsgSeqNum` (34), the same next
outbound number, and resends of the original messages under their original
numbers. When the standby's copy of the state is incomplete, the FIX Session
Layer offers two recovery profiles: initiator-assisted restoration with
`NextExpectedMsgSeqNum` (789, §4.4.4) and a reset agreed at Logon with
`ResetSeqNumFlag` (141) = Y (§4.4.3). `doc/fix_operations.md` defines both on
the wire; it is silent on how an engine moves a live session between
processes. Issue #80 asks whether IronFix should support that, and what the
minimum is.

### What exists today

These are the building blocks any answer reuses. Each is implemented and
tested on `main`:

- **A pluggable, fallible store.** `MessageStore`
  (`ironfix-store/src/traits.rs`) is an `async` trait the engine holds as
  `Arc<dyn MessageStore>`; a user can implement it outside IronFix. Since
  ADR-0005 every mutation returns `Result<_, StoreError>` and takes effect in
  call order, and the engine awaits it with a timeout under a
  `StoreFailurePolicy` before it spends a number or acts on an inbound
  message. When the engine recovers counters from an attached store it
  calls `refresh()` first and refuses the session if that fails. This is
  not a guarantee that every store rereads a medium: the trait default of
  `refresh()` is a no-op, and the reset paths and explicit seeds under
  `StoreFailurePolicy::Continue` do not call it.
- **`FileStore`** (ADR-0006, ADR-0022): a CRC-32 journal, now in format
  version 4 (ADR-0030), with two counter slots behind a durable boundary, one
  writer thread, and fail-closed recovery. It is **single-writer**: while
  open it holds an advisory `try_lock` on `<name>.lock`, so a second store on
  the same files fails with `StoreError::Io`. The lock is advisory, network
  file systems may not honour it, and the durability guarantees are stated
  for Unix only. Durability across an operating-system crash needs
  `SyncPolicy::EveryWrite` together with `StoreFailurePolicy::CloseSession`.
- **The durable owed reset** (#111, ADR-0029): a reset the engine owes its
  next session is a marker in the store. For a resetting Logon of our own the
  marker is durable before the Logon is transmitted. When the counterparty's
  acknowledgement is the first to carry 141=Y, ADR-0029 documents a residual
  window: a crash after it arrives and before the marker is durable still
  restarts from the previous stream.
- **Resend from the store in both roles** (#60, ADR-0017): an inbound
  `ResendRequest` replays stored application messages under their original
  numbers with `PossDupFlag` (43) = Y and `OrigSendingTime` (122), and
  gap-fills administrative messages and holes.
- **789 on the Logon exchange** (#79, ADR-0021): each side declares the next
  number it expects; a counterparty's 789 below our Logon number queues a
  resend of exactly the missing range, and one above our next outbound
  number is refused with a Logout and
  `EngineError::NextExpectedMsgSeqNum`. 789 never moves a counter.
- **A typed close reason** (#69, ADR-0025): `CloseReason` tells the
  application how a session ended, so an operator can tell a graceful close
  from a store failure or a lost stream.
- **The inbound loss report** (#105, ADR-0030): the store keeps an
  application watermark, and at session start the engine reports through
  `Application::on_inbound_lost` the inbound numbers above it and below the
  stored next target as possibly lost to the application. Inbound delivery
  is at most once, reported.
- **Seeding counters:** `Initiator::with_initial_sequences` and
  `Acceptor::with_initial_sequences` start a session at explicit numbers.

So a standby that opens **the same, complete, durable** store state the
active process left behind (after that process has stopped) already resumes
correctly: counters come from the store, resends come from the journal, an
owed reset is honoured, 789 closes a small outbound gap, and the application
is told which inbound messages it may not have processed.

### What a standby takeover needs that does not exist

None of the following exists in IronFix today, and this ADR does not claim
otherwise:

1. **Shared or replicated storage.** `FileStore` writes a local journal. A
   standby on another host sees it only through a shared volume or a
   replication layer outside IronFix, and IronFix states no guarantee for
   either. There is no replicated `MessageStore` implementation, in the
   workspace or as an example.
2. **Fencing.** Nothing stops the old active process from writing after the
   standby has taken over (a paused process, a partition). The advisory lock
   is not a fence: it is released only when the holder dies or closes, it is
   not honoured by every network file system, and it means nothing across
   hosts with separate disks. Two writers on one session number the same
   `MsgSeqNum` twice, which the counterparty cannot recover from.
3. **A takeover of the single-writer lock.** `FileStore` refuses a second
   opener while the first holds the lock; there is no API to break or hand
   over a lock, by design.
4. **A report of the state the session resumed from.** No callback says
   "this session started from counters X/Y taken over from another process",
   or "the peer's Logon `MsgSeqNum` and 789 do not match the stored state".
   Today a mismatch follows the ordinary rules: a gap starts recovery
   through 789 (when both sides declare it, the gapped Logon uses implied
   recovery while the peer sends the declared range) or a
   `ResendRequest`, a too-low number closes the session, a 789 above our next
   outbound number is refused.
5. **Replication lag accounting.** An outbound message the active process
   sent but the standby's copy does not hold cannot be resent with its
   original content; the counterparty may then hold a number the standby
   never saw (caught today only as a 789 above our next outbound, refused).

## Options

### Option 1: documentation plus an example store

State that standby takeover is a store implementation concern. Document the
contract a replicated `MessageStore` must meet for a takeover to be safe,
using the guarantees that already exist: every mutation acknowledged only once
durable on the standby's medium, mutations applied in call order, `refresh()`
rereading the replicated state, `reset_owed` and the app watermark replicated
with the counters, and **fencing done by the store or the deployment**, not by
the engine. Ship an example (under `ironfix-example/examples/`, not a library
crate) that wraps a store and illustrates the contract, clearly labelled as
not a production HA store.

Consequences:

- No `pub` change in any published library crate: **semver none**. No new
  dependency, no DAG change.
- It reuses what is tested: counters, resend, owed reset, 789, the loss
  report.
- Fencing and replication remain the user's problem, and the docs must say
  so in those words. A user who replicates asynchronously can still lose
  outbound messages at takeover; the docs must say that too.
- The application still gets no explicit "resumed" signal; it infers it from
  its own deployment.
- No failover time and no durability across hosts is claimed, because no
  test exercises either.

### Option 2: an engine resume API

Add a way to start a session from an explicit, validated snapshot (counters,
owed reset, watermark, a journal handle), and a typed outcome when the peer's
Logon `MsgSeqNum` or 789 does not match it, so the application can choose a
recovery profile.

Consequences:

- New `pub` surface on `ironfix-engine` (a snapshot type, an outcome type,
  probably an `Application` callback with a default body): a **minor** bump.
  The new types must be `#[non_exhaustive]`; a new variant on an existing
  exhaustive public enum would be breaking.
- It overlaps heavily with what the store already provides: a snapshot is
  what `refresh()` plus the counter getters return. The real gain is the
  mismatch report.
- It still does not solve fencing or replication; a snapshot taken from a
  stale replica is validated against itself, not against the truth.
- It is a sensible follow-up if users of option 1 ask for the mismatch
  report, and can be added later without breaking option 1.

### Option 3: recovery profiles in the engine

Make the engine configurable for an incomplete state: adopt the initiator's
counters and report the unknown range, require 141=Y, or Logout with a
reason.

Consequences:

- **Adopting counters presented by the peer** makes the counterparty the
  authority over our own sequence state. It contradicts ADR-0021 ("789 never
  moves a counter") and the rule that a session never invents a number it
  cannot back with a stored message: anything resent in the adopted range
  must be gap-filled, so orders the active process sent are replaced by gap
  fills from the counterparty's point of view.
- Requiring 141=Y throws away the session's history, which an application
  can already ask for (`reset_on_logon`, the owed-reset marker) without a new
  engine mode.
- Logout with a reason is what the engine does today for an unrecoverable
  Logon (ADR-0021, ADR-0025).
- It adds a configuration matrix to the protocol-critical Logon path, which
  is the hardest code to test, and every profile still depends on the
  fencing and replication the engine does not have.
- New `pub` configuration and outcome types: a **minor** bump at least.

## Decision

**Option 2, the owner's choice: a resume mismatch report in
`ironfix-engine`, together with option 1's documented store contract.
Option 3 is rejected.** Fencing stays out of scope.

### The store contract (from option 1)

A `doc/` page states what a `MessageStore` must provide for a standby to
resume a session from it. IronFix ships no replicated store; the contract
is what a user's store must meet:

- every mutation returns `Ok` only once it is durable on the medium the
  standby will read, and mutations take effect in call order;
- `refresh()` rereads that medium (the trait default is a no-op, so a
  takeover store must override it);
- the counters, the owed-reset marker (`reset_owed` / `set_reset_owed`,
  ADR-0029) and the application watermark (`app_watermark` /
  `set_app_watermark`, ADR-0030) are replicated together and durably; a
  store on the defaults keeps neither marker nor watermark and is not a
  takeover store;
- for `FileStore`, operating-system crash durability needs
  `SyncPolicy::EveryWrite` with `StoreFailurePolicy::CloseSession`, and the
  ADR-0029 residual window (a peer acknowledgement that first carries 141=Y,
  then a crash before the marker is durable) remains;
- an asynchronously replicated store can lose outbound messages at
  takeover; the mismatch report below is how the engine says so.

An example store under `ironfix-example/examples/` may illustrate the
contract; it is labelled illustrative and is not a production HA store.

### The mismatch report

**Where it surfaces.** A new `Application` callback with a default body, as
`on_inbound_lost` is (ADR-0030):

```rust
async fn on_sequence_mismatch(&self, session_id: &SessionId, mismatch: &SequenceMismatch) {
    /* default: logs the numbers at warn level, nothing else */
}
```

A callback, not a `CloseReason` variant or a new event, because the report
is about the start of a session, not its end: most mismatches are
recoverable and the session goes on, and no `Connection` exists yet. When
the existing rules close the session, the close keeps its own
`CloseReason`; the report is an addition to it, made before it.

**When it runs.** Once per Logon exchange, in both roles, after the
counterparty's Logon (initiator: its acknowledgement) has been accepted by
`from_admin` and its 789 parsed, and before `on_logon`. It is not called
when the exchange carries 141=Y, since a reset discards both histories by
agreement and the counters are compared after the reset at 1. It is called
only when at least one comparison below differs.

**What it compares.** Our side is the persisted state the session started
from: the values of `next_sender_seq()` and `next_target_seq()` read after
`refresh()`, or the seeds of `with_initial_sequences` when no store is
attached. These are the same numbers the engine numbers from; the report
adds no new store method and no snapshot type, so a store on the trait
defaults gets the report too.

- *Inbound*: the `MsgSeqNum` (34) of the counterparty's Logon against our
  persisted next target. Higher: a gap of `next_target ..= logon_seq - 1`
  (`InboundMismatch::Gap { first, last }`). Lower: the counterparty is
  behind our record (`InboundMismatch::TooLow { received, expected }`).
- *Outbound*: the counterparty's 789, if present, against the number of our
  own Logon (or acknowledgement) and our next outbound, as ADR-0021 already
  reads them. Below our Logon number: the counterparty missed
  `789 ..= own_logon_seq - 1` (`OutboundMismatch::PeerMissed { first,
  last }`). Above our next outbound: the counterparty holds numbers our
  store has no record of, the signature of a lagging replica
  (`OutboundMismatch::PeerAhead { declared, next_outbound }`). Without 789
  the counterparty's Logon says nothing about our outbound stream, and the
  report says so (`OutboundMismatch::NotDeclared`); the `MsgSeqNum` of its
  Logon is never read as a statement about our numbers.

`SequenceMismatch` is `#[non_exhaustive]` with private fields and
`#[must_use]` `const fn` getters: `persisted_next_sender()`,
`persisted_next_target()`, `peer_logon_seq()`, `peer_next_expected() ->
Option<u64>`, `inbound() -> Option<InboundMismatch>`, `outbound() ->
OutboundMismatch`. Both enums are `#[non_exhaustive]`. Numbers only: no
frame bytes, no `Text`, nothing that could carry a credential.

**It never moves a counter.** The report is informational and runs before
the engine acts on the mismatch; what the engine then does is unchanged:
a gap starts recovery through 789 or a `ResendRequest`, a too-low
`MsgSeqNum` without `PossDupFlag` closes the session, a 789 below our Logon
number queues a resend, a 789 above our next outbound is refused with
`EngineError::NextExpectedMsgSeqNum` (ADR-0021). The callback returns
nothing, so it cannot ask the engine to adopt the counterparty's numbers
(the option 3 behaviour this ADR rejects). An application that wants a
different recovery profile acts with the tools it already has: logging out
through the `Connection` once Active, or arranging a reset (`reset_on_logon`,
the owed-reset marker) for the next session.

**Order with the other start reports.** `on_inbound_lost` (ADR-0030) runs
first, from the store alone; `on_sequence_mismatch` runs at the exchange,
once the counterparty's numbers are known; then `on_logon`.

### What stays out of scope

- **Fencing.** The engine does not fence a former owner and the docs say so.
  A lease alone is not a fence: a paused former owner can resume after its
  lease expires and send or write again. A deployment must enforce that the
  former owner can no longer operate (revocation enforced outside the
  process, for example at the storage or network layer), or confirm its
  termination, before the standby opens the store. A lease is sufficient
  only when coupled to that enforcement.
- Replication, a replicated store in a library crate, and a takeover of
  `FileStore`'s single-writer lock.
- Adopting counters presented by the counterparty, in any profile. On the
  question in #80's tasks: the engine never adopts them, and
  `on_sequence_mismatch` reports the disagreement instead.
- Any failover-time or cross-host durability figure; none is claimed without
  a test that exercises it.

## Consequences

- **Semver: minor** for `ironfix-engine`: a new defaulted `Application`
  method and three new `#[non_exhaustive]` public types. No existing
  signature, variant or default changes; existing `Application` impls
  compile unchanged. The documentation page adds no `pub` item.
- **Crate DAG unchanged.** The comparison lives in the engine, next to the
  789 plan; `ironfix-session` and `ironfix-store` gain nothing. No new
  dependency.
- The application finally gets a typed signal for the state the session
  resumed from, which is the part of a takeover the engine can observe.
  Whether the state was complete is still the store's and the deployment's
  responsibility.
- The gaps (no replication, no fencing, a single-writer lock with no
  takeover) stay open and are named in the docs rather than hidden.
- Follow-up: the implementation issue (callback, types, tests in both roles
  for every mismatch kind and for the 141=Y and no-mismatch cases), and the
  store-contract documentation page. The implementation PR closes #80.
- No code changes in this ADR.
