# ADR-0006 — A message store on the Acceptor, touched only after authentication

- **Status:** Proposed (issue #60). The store attachment, the shared seeding
  and the authentication-first rule follow the plan the owner approved; the
  "no reply to an unauthenticated Logon when a store is attached" rule is new
  here and awaits review.
- **Date:** 2026-10-18

## Context

The `Acceptor` attached no `MessageStore`. Every handshake frame it sent went
out with no store binding, each session's counters came only from
`with_initial_sequences`, and an inbound `ResendRequest` was answered with one
gap fill. A venue-side gateway is an acceptor, and must replay application
messages with `PossDupFlag` and `OrigSendingTime` from its outbound journal.
The initiator already had all of this, with the write order and failure policy
of ADR-0005.

Two things are specific to the acceptor:

- **The peer is not known when the Logon arrives.** The initiator dials a
  counterparty it chose; the acceptor answers whoever connects. A Logon with
  `ResetSeqNumFlag` (141) = Y resets the outbound journal, so the moment the
  acceptor touches its store decides whether an unauthenticated peer can wipe
  it.
- **Refusals before authentication.** The acceptor answers a refused Logon
  with a Reject and/or a Logout. With a store, a frame has to be filed under a
  number before it is written (ADR-0005).

## Decision

### Same store, same write order

`Acceptor::with_store`, `with_store_failure_policy`, `with_store_timeout`,
`with_write_timeout` and `with_app_queue_capacity` mirror the initiator's
knobs, and `EngineBuilder::with_store` attaches a store in both terminal
methods. Every frame the acceptor sends once the Logon is authenticated (a
refusing Logout, the acknowledgement) goes through the shared outbound step of
ADR-0005; the Logon's number is persisted before the session goes Active; the
reactor, which both roles share, does the rest unchanged.

### One seeding helper for both roles

`persistence::seed_session` decides a session's counters for either role, by
priority: a reset (store reset to 1/1 with one `reset_to` call), an explicit
initial seed (checked against the store under `CloseSession`), the store's
refreshed counters, or 1/1. Each role decides only whether the session resets:
the initiator for `reset_on_logon` or an owed reset; the acceptor for an
inbound `141=Y`, `reset_on_logon`, or an owed reset. Every reset and refresh
fails closed whatever the policy.

### The store is touched only after authentication

The acceptor checks, in order, the version, the encryption method, identity,
admission (one live session), `SendingTime`, and `from_admin`, then that a
`141=Y` Logon carries `MsgSeqNum` 1. Only then does it seed from the store,
resetting it if the session resets. So a Logon that fails any of those checks,
`141=Y` or not, can neither clear the journal nor write to it, and a refresh
cannot be triggered by an unauthenticated peer.

### No reply to an unauthenticated Logon when a store is attached

A refusal frame sent before authentication would either be filed, letting an
unauthenticated peer write to the journal and move its counters (and, for a
duplicate Logon, race the writes of the live session that owns the store), or
be numbered without being filed, reusing with different content a number the
session's stream already holds, which #89 forbids in every scenario. With a
store attached the acceptor therefore closes the connection without a Reject or
Logout at that stage, logs the reason, and returns the typed error. Without a
store nothing changes: those refusals are sent as before, numbered from the
seed or 1. Refusals after authentication (an invalid `HeartBtInt`, a
`MsgSeqNum` too low) are filed like any other frame.

### Owed resets and admission

The acceptor keeps the same owed-reset record as the initiator (ADR-0005): a
failed close-time reset, or a failed reset for a `141=Y` Logon, is owed to the
next authenticated Logon, whose acknowledgement then declares `141=Y` at 1;
the record clears once that acknowledgement is sent. The admission slot is
released only after a session's close path, its store writes included, has
run, so two sessions of one acceptor never write to the store at once.

### Configuration check

`Acceptor::new` validates the configuration and `serve` refuses an unusable one
with `EngineError::Config` before the handshake, as `Initiator::connect` does
before dialling.

## Consequences

- **Semver (additive):** `Acceptor::with_store`,
  `Acceptor::with_store_failure_policy`, `Acceptor::with_store_timeout`,
  `Acceptor::with_write_timeout`, `Acceptor::with_app_queue_capacity`,
  `EngineBuilder::with_store`, `EngineBuilder::has_store`. The derived `Debug`
  on `Acceptor` and `EngineBuilder` is replaced by hand-written ones, which
  drop the `A: Debug` bound.
- **Semver (breaking, auto traits):** `Acceptor` and `EngineBuilder` now hold
  an `Option<Arc<dyn MessageStore>>`, so they are no longer `UnwindSafe` or
  `RefUnwindSafe`; `cargo-semver-checks` reports `auto_trait_impl_removed` on
  both. `Initiator` already held one and already lacked both traits, so the
  two engines now agree. The alternative, wrapping the store in
  `AssertUnwindSafe`, would assert for every store implementation something
  the engine cannot vouch for (`MemoryStore`'s lock does not poison), so it was
  not taken.
- **Behaviour without a store:** unchanged, except that an acceptor built with
  an unusable configuration now refuses to serve (`EngineError::Config`)
  instead of running a handshake whose messages that configuration corrupts.
- **Behaviour with a store:** an unauthenticated Logon gets no reply. A
  misconfigured counterparty sees the connection close; the reason is in the
  acceptor's log and in the error `serve` returns.
- The crate DAG is unchanged. The decisions are synchronous and read no clock
  (ADR-0002); only the store calls are async, bounded by the store timeout.
- No performance claim (ADR-0001).
