# ADR-0015: Resuming a session on a standby process

- **Status:** Proposed (issue #80); the repository owner makes the final call
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
  message. At session start the engine calls `refresh()` and refuses the
  session if it fails, so the store is reread from its medium before a
  single number is used.
- **`FileStore`** (ADR-0006, ADR-0022): a CRC-32 journal, now in format
  version 4 (ADR-0030), with two counter slots behind a durable boundary, one
  writer thread, and fail-closed recovery. It is **single-writer**: while
  open it holds an advisory `try_lock` on `<name>.lock`, so a second store on
  the same files fails with `StoreError::Io`. The lock is advisory, network
  file systems may not honour it, and the durability guarantees are stated
  for Unix only. Its guarantees hold under
  `StoreFailurePolicy::CloseSession`.
- **The durable owed reset** (#111, ADR-0029): a reset the engine owes its
  next session is a marker in the store, so a process that dies after the
  counterparty acknowledged a 141=Y Logon, but before the store reset landed,
  still resets on the next Logon instead of replaying the old stream.
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
   Today a mismatch follows the ordinary rules: a gap triggers a
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

## Decision (proposed)

**Recommend option 1; reject option 3; keep option 2 as a possible
follow-up.**

- Document standby takeover as a `MessageStore` concern, with the
  replicated-store contract above and an explicit list of what IronFix does
  not provide: replication, fencing, lock takeover, a resume callback, and any
  failover-time or cross-host durability guarantee.
- Ship one example replicated store under `ironfix-example/examples/`,
  labelled as illustrative. It must not be described as production ready,
  and no takeover time may be quoted without a test that measures it.
- The engine never adopts sequence counters presented by the counterparty.
  On the question in #80's tasks ("whether the engine should ever adopt
  counters presented by the peer, and which callback reports it"): no, and
  therefore no callback for it.
- If a resume mismatch report is wanted later, it is a new issue under
  option 2, with its own ADR.

The owner may choose differently; this ADR stays "Proposed" until then.

## Consequences

- **Semver: none** for option 1. The docs and the example add no `pub`
  item to any crate that `semver.yml` checks (`ironfix-example` is outside
  it).
- **Crate DAG unchanged.** No new dependency.
- The gaps (no replication, no fencing, a single-writer lock with no
  takeover) stay open and are named in the docs rather than hidden. A user
  who needs HA must provide fencing (for example a lease, or killing the old
  process in the deployment) before the standby opens the store.
- Follow-up issues if accepted: the documentation page (a section in
  `doc/fix_operations.md` or a new `doc/` page), the example store, and, on
  request, an option 2 mismatch report.
- No code changes in this ADR.
