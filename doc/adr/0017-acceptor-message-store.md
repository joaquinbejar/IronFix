# ADR-0017 — A message store on the Acceptor, and who a refused Logon is answered for

- **Status:** Accepted (issue #60, in the plan the owner approved; the refusal
  policy and the reset rule as revised in the #60 review)
- **Date:** 2026-10-18

## Context

The `Acceptor` attached no `MessageStore`. Every handshake frame it sent went
out with no store binding, each session's counters came only from
`with_initial_sequences`, and an inbound `ResendRequest` was answered with one
gap fill. A venue-side gateway is an acceptor, and must replay application
messages with `PossDupFlag` and `OrigSendingTime` from its outbound journal.
The initiator already had all of this, with the write order and failure policy
of ADR-0005.

Three things are specific to the acceptor:

- **The peer is not known when the Logon arrives.** The initiator dials a
  counterparty it chose; the acceptor answers whoever connects. A Logon with
  `ResetSeqNumFlag` (141) = Y resets the outbound journal, so the moment the
  acceptor touches its store decides whether an unknown or unauthenticated
  peer can wipe it.
- **Refusals.** The acceptor answers a refused Logon with a Reject and/or a
  Logout. With a store, a frame has to be filed under a number before it is
  written (ADR-0005), and a number sent without being filed may reuse, with
  different content, one the session's stream already holds, which #89
  forbids in every scenario.
- **A reset the acceptor drives.** With `reset_on_logon`, or a reset owed by an
  earlier session, the acceptor resets although the peer's Logon may be
  numbered N > 1 without 141.

## Decision

### Same store, same write order

`Acceptor::with_store`, `with_store_failure_policy`, `with_store_timeout`,
`with_write_timeout` and `with_app_queue_capacity` mirror the initiator's
settings, and `EngineBuilder::with_store` attaches a store in both terminal
methods. Both engines hold the store settings in one `persistence::StoreAttachment`
(store, policy, call timeout, owed-reset record), so they cannot drift. Every
frame the acceptor sends to its counterparty goes through the shared outbound
step of ADR-0005; the Logon's number is persisted before the session goes
Active; the reactor, which both roles share, does the rest unchanged.

A store belongs to exactly one engine instance: two engines or processes
writing to one store would interleave two sequence streams. The owed-reset
record lives in memory in the engine (#111).

### One seeding helper for both roles

`persistence::seed_session` decides a session's counters for either role, by
priority: a reset (store reset to 1/1 with one `reset_to` call), an explicit
initial seed (a zero seed is refused with `EngineError::InvalidInitialSequence`
in both roles, and under `CloseSession` a sender seed below the store's next
sender number is refused), the store's refreshed counters, or 1/1. Each role
decides only whether the session resets: the initiator for `reset_on_logon` or
an owed reset; the acceptor for an inbound `141=Y`, `reset_on_logon`, or an
owed reset. Every reset and refresh fails closed whatever the policy.

### The order of the acceptor's checks

Version, encryption method, `MsgSeqNum` (present in the header, and not 0),
identity, admission (one live session), `SendingTime`, `from_admin`; the peer
is authenticated from here on; then `141=Y` carrying `MsgSeqNum` 1,
`HeartBtInt`; then the store is reset (if the session resets) or refreshed;
then `MsgSeqNum` is validated and the acknowledgement sent. The store is not
touched before authentication, and only a Logon that passes every check can
reset it.

### Who a refused Logon is answered for

1. **An unauthenticated peer** (version, encryption, CompIDs, `SendingTime`,
   credentials refused by `from_admin`). With a store attached it gets no reply
   and the store is not touched: a frame could neither be filed (that would let
   it write to the journal and move the counters) nor numbered without reusing
   a number of the stream. Without a store the Reject and/or Logout are sent as
   before, numbered from the seed or 1. A Logon without a valid `MsgSeqNum`
   (absent, outside the header, or 0) gets no reply in either mode.
2. **A duplicate Logon** for a session already live. It gets no reply with or
   without a store: the live session owns the sequence stream, and nothing the
   newcomer could be sent belongs to it. This changes the store-less behaviour,
   which used to send a Logout (FIX session test case 1S(b)).
3. **An authenticated peer** (`from_admin` accepted it), refused by a `141=Y`
   Logon not numbered 1, by its `HeartBtInt`, or by a `MsgSeqNum` below the
   expected one. It gets a Logout saying why, sent like every session frame:
   numbered from a seed that never resets (the store's refreshed counters, or
   the configured seed) and filed when a store is attached. None of these
   refusals resets the store.

Matching CompIDs authenticate nobody: they are caller-supplied. A Logon
refused by the `SendingTime` check or by `from_admin` therefore belongs to
group 1, not group 3: with a store attached it gets no reply and the store is
not touched, so a peer that knows the CompIDs but not the credentials cannot
append to the journal or advance the session's counters. (An earlier revision
of this ADR filed those refusals; review found that hole.) A Logon numbered 0
names no message and is refused with a missing `MsgSeqNum`, before identity:
no reply in either mode, and it never reaches the reset rule, which takes only
a positive old-stream number as message 1.

### The reset rule both roles share

In a Logon exchange that resets the sequence, each side's Logon or
acknowledgement is message 1 of its new stream: its next sender number is 2,
and the next number it expects from the other side is 2.

- The acceptor, after a reset of any origin, acks at 1 with `141=Y` and takes
  the peer's Logon as its message 1 whatever `MsgSeqNum` it carries. A peer that
  did not ask for the reset is told to make it by the ack, and no gap (and no
  `ResendRequest`) is opened for the numbers of its old stream.
- The initiator, after a reset it declared, takes the acknowledgement as the
  acceptor's message 1 whatever its `MsgSeqNum`; an ack that declares `141=Y`
  itself must carry 1. After a reset the acceptor declares on the ack, the
  initiator sets its next sender number to 2, treating its Logon as message 1.

### Owed resets and admission

The acceptor keeps the same owed-reset record as the initiator (ADR-0005): a
failed close-time reset, or a failed reset for a session that resets, is owed
to the next accepted Logon, whose acknowledgement then declares `141=Y` at 1;
that reset is paid once that acknowledgement is sent, and a store write that
fails while the acknowledgement is filed stays owed (ADR-0006). As in ADR-0005
("Cancellation and timeouts"), the reset is recorded as owed before it is
awaited, so a `serve` dropped while it is pending still leaves it owed, and a
store mutation that overruns the store timeout leaves a reset owed too; both
engines get this from the same `StoreAttachment` and `SessionStore` code. The
admission slot is held
until a session's task ends: past its close-time store writes, the drain of its
application queue (up to 5 s) and `on_logout`. So two sessions never write to
the store at once, and a Logon that arrives while the previous session is still
closing is refused as a duplicate, without a reply.

### Configuration check

`Acceptor::new` validates the configuration. `accept` and `serve` check it, and
the FIX version, before anything else: `accept` before it takes a connection
off the listener, as `Initiator::connect` does before dialling.

## Consequences

- **Semver (additive):** `Acceptor::with_store`,
  `Acceptor::with_store_failure_policy`, `Acceptor::with_store_timeout`,
  `Acceptor::with_write_timeout`, `Acceptor::with_app_queue_capacity`,
  `EngineBuilder::with_store`, `EngineBuilder::has_store`. The derived `Debug`
  on `Acceptor` and `EngineBuilder` is replaced by hand-written ones, which
  drop the `A: Debug` bound.
- **Semver (breaking, auto traits):** `Acceptor` and `EngineBuilder` now hold
  an optional `Arc<dyn MessageStore>`, so they are no longer `UnwindSafe` or
  `RefUnwindSafe`; `cargo-semver-checks` reports `auto_trait_impl_removed` on
  both. `Initiator` already held one and already lacked both traits, so the
  two engines now agree. The alternative, wrapping the store in
  `AssertUnwindSafe`, would assert for every store implementation something
  the engine cannot vouch for (`MemoryStore`'s lock does not poison), so it was
  not taken.
- **Behaviour changes, with or without a store:** a duplicate Logon gets no
  reply; an acceptor with an unusable configuration refuses to serve, and
  `accept` refuses before taking a connection; a zero initial seed that would
  be used is refused instead of raised to 1; a Logon numbered 0 gets no reply;
  and after a reset the acceptor drives, a peer Logon numbered N > 1 no longer
  draws a `ResendRequest`. The initiator, after a reset it declared, no longer
  opens a gap for an ack with a positive number that does not echo the reset;
  an ack numbered 0 is still refused as too low.
- **Behaviour with a store:** an unauthenticated peer (wrong CompIDs, clock or
  credentials included) gets no reply. A misconfigured or unauthorised
  counterparty sees the connection close; the reason is in the acceptor's log
  and in the error `serve` returns.
- The crate DAG is unchanged. The decisions are synchronous and read no clock
  (ADR-0002); only the store calls are async, bounded by the store timeout.
- No performance claim (ADR-0001).
