# Resuming a session on a standby process

This page states what IronFix provides, and what it does not, when a FIX
session that ran on one process (the active) is resumed on another (the
standby). The decision is recorded in
[ADR-0015](adr/0015-standby-session-resume.md) (issue #80).

IronFix ships **no replicated store and no fencing**. A standby resumes a
session correctly only from a store that meets the contract below, opened
after the former owner can no longer operate. No failover time and no
cross-host durability figure is claimed: no test exercises either.

## The store contract

A `MessageStore` a standby resumes from must provide all of the following.
None of it is checked by the engine.

- **Durable acknowledgement, in order.** Every mutation returns `Ok` only
  once it is durable on the medium the standby will read, and mutations take
  effect in call order (the ordering rule in the `ironfix-store` trait
  documentation).
- **`refresh()` rereads that medium.** The trait default is a no-op, so a
  takeover store must override it. The engine calls it before it recovers
  counters from an attached store; the reset paths, and explicit seeds under
  `StoreFailurePolicy::Continue`, do not call it.
- **Replicated together.** The counters, the owed-reset marker
  (`reset_owed` / `set_reset_owed`, ADR-0029) and the inbound application
  watermark (`app_watermark` / `set_app_watermark`, ADR-0030) are replicated
  together and durably. A store on the trait defaults keeps neither marker
  nor watermark and is not a takeover store.
- **`FileStore`.** Operating-system crash durability needs
  `SyncPolicy::EveryWrite` together with
  `StoreFailurePolicy::CloseSession`. The ADR-0029 residual window remains: a
  counterparty acknowledgement that is the first to carry
  `ResetSeqNumFlag` (141) = Y, then a crash before the marker is durable,
  restarts from the previous stream. `FileStore` is single writer (an
  advisory lock on `<name>.lock`) and offers no takeover of that lock.
- **Asynchronous replication loses outbound messages.** A message the active
  process sent but the standby's copy does not hold cannot be resent with its
  original content. A replica that acknowledges a write before it is
  durable there relaxes the first point of this contract (`Ok` only once
  durable), and this loss is the price. The mismatch report below detects
  only the disagreements a Logon makes observable; it does not detect every
  asynchronous replication loss. Outbound replication loss cannot be inferred when the counterparty
  declares no usable 789 (absent, malformed, or the session does not use
  789), or when the counterparty never received the lost messages either:
  its numbers then agree with the standby's and the loss is invisible at
  Logon.

## What is tested

`ironfix-engine/tests/acceptance_gate_tests.rs` (issue #89) resumes sessions
on a `FileStore` (`SyncPolicy::EveryWrite`, `StoreFailurePolicy::CloseSession`)
after the active engine has been killed, in both roles. With a complete
store, the standby continues both sequence streams and replays every original
application message under its original number. With a copy that ends early,
an acceptor on FIX.4.4 or FIXT.1.1 reports the missing ranges and refuses the
Logon, as described below. The results, and their limits, are listed in
`doc/fix_operations.md` ("What the crash and takeover gate proves"). No
shared or replicated storage, no fencing and no failover time is tested.

## Fencing is the deployment's job

The engine does not fence a former owner. Two writers on one session number
the same `MsgSeqNum` twice, which the counterparty cannot recover from. A
lease alone is not a fence: a paused former owner can resume after its lease
expires and send or write again. The deployment must enforce that the former
owner can no longer operate (revocation enforced outside the process, for
example at the storage or network layer), or confirm its termination, before
the standby opens the store.

## The mismatch report

Once per Logon exchange, in both roles, the engine compares the
counterparty's Logon (initiator: its acknowledgement) with the **effective
startup counters**: the next sender and target numbers the session actually
starts from, after store recovery, explicit seeds (`with_initial_sequences`)
or a reset. When a comparison differs it calls
`Application::on_sequence_mismatch` with a `SequenceMismatch`:

- **inbound**: the Logon's `MsgSeqNum` (34) against the effective next
  target, a `Gap { first, last }` or `TooLow { received, expected }`;
- **outbound**: the counterparty's `NextExpectedMsgSeqNum` (789), when the
  session uses 789, against our own Logon number and next outbound:
  `PeerMissed { first, last }`, `PeerAhead { declared, next_outbound }` (the
  signature of a lagging replica), or `NotDeclared` / `Consistent` when it
  says nothing wrong;
- what the store held before any seed or reset, reported and never compared.

It runs after `from_admin` accepts the Logon, after `on_inbound_lost`, and
before `on_logon`; never on an exchange that carries 141=Y. It carries
numbers only. It never moves a counter and changes nothing the engine does
next (ADR-0021): a gap is recovered, a Logon too low or a 789 above our next
outbound closes the session with its own error. The engine never adopts the
counterparty's numbers.
