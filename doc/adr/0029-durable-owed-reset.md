# ADR-0029 — A durable owed-reset marker in the store

- **Status:** Proposed (issue #111)
- **Date:** 2026-10-19

## Context

The engine keeps a record of the sequence resets it owes its next session
(ADR-0005, ADR-0017): a reset it is about to make, a reset that failed, and a
store mutation that failed or timed out. The record is generation based
(`OwedReset` in `ironfix-engine/src/persistence.rs`) and lived only in the
engine's memory. A crash before the store reset was durable lost it. With a
`FileStore` that means: the counterparty acknowledged our Logon with
`ResetSeqNumFlag` (141) = Y, the process died before `reset_to` landed, and
the next process logged on at the old number without 141. The counterparty,
already reset and expecting 2, asked for a resend, and frames of the old
session were replayed into the new one with `PossDupFlag` (43) = Y. The same
happened for a crash during a `reset_on_logout` / `reset_on_disconnect` close,
and (ADR-0023) for a `StoreRefused` frame a failed write may have filed
anyway. That breaks #89's rule that no frame of the old session is ever
replayed in the new one.

`doc/fix_operations.md` defines what a reset is on the wire (141=Y on the
Logon, both sides at 1); it is silent on how an engine remembers an intent to
reset across a restart. That part is an engine decision, recorded here.

## Decision

### The store contract: two defaulted methods

`MessageStore` gains

```rust
fn reset_owed(&self) -> bool { false }
async fn set_reset_owed(&self, owed: bool) -> Result<(), StoreError> { Ok(()) }
```

The marker is a separate, explicit mutation rather than a flag folded into
`reset_to`. The intent has to be durable **before** the reset is made (a crash
inside `reset_to` is one of the windows), and it has to outlive the reset
until the Logon or acknowledgement that declares it has been exchanged (a
crash after `reset_to` and before the Logon is acknowledged is another). A
two-phase `reset_to` would need both of those as extra states anyway.

Contract: `Ok` means the marker is as durable as the store's counters can be
made, whatever the store's own sync policy; `reset` and `reset_to` keep the
marker; it is a mutation and takes effect in call order like the others.
The defaults keep no marker, which is the behaviour before this ADR, so a
third-party store compiles and behaves as it did.

### The engine: set before acting, read at start, clear once paid

- Before any reset is made (the Logon-declared reset in either role, the
  initiator's reset for a resetting acknowledgement, the close-time reset),
  the engine records the obligation and writes the marker. In a handshake a
  failed marker write refuses the session under every policy. The close-time
  reset is made even when the marker write fails (logged), because not making
  it leaves the previous stream in a store the counterparty no longer
  continues.
- After any failed store mutation the marker is written as a best effort.
- `StoreAttachment::reset_is_owed` reads the store's marker; a set marker is
  taken into the in-memory record, so the session resets the store and
  declares 141=Y at 1, in either role.
- After the Logon declaring the reset is acknowledged (initiator), or the
  acknowledgement declaring it is sent (acceptor), and before `on_logon`, and
  after a successful close-time reset, the marker is cleared if nothing else
  is owed by then. A failed clear records an obligation again (the record
  never says less than the store), so the next session resets again. In a
  handshake a failed clear follows the store failure policy.
- Marker writes are serialised by a `tokio::sync::Mutex` in `OwedReset`, and
  each one writes the record's state when it runs, so a clear computed before
  a new obligation can never land after the write recording it.

### `FileStore`: a flag in the counter slots, journal format version 3

The counter slot grows from 36 to 44 bytes: a `u64` of flags (bit 0 is the
marker, every other bit must be 0) before the CRC, which now covers bytes
0..40. Every slot written carries the current marker, so the newest valid
slot says whether a reset is owed. Setting or clearing it writes **both**
slots, each flushed before the next, whatever the `SyncPolicy`: once set, a
slot torn or damaged later still leaves the other carrying it, and both slots
failing their check already refuses the journal. A reset and a compaction
carry the marker into the new journal's slots. A slot with an undefined flag
bit is treated as invalid. Setting the marker on a journal left unusable by a
failed write refreshes it first, since that is when the marker is most needed.
A failed marker write reports the marker set in memory (the safe direction).

### Compatibility: version 2 is refused, not migrated

The slot layout changed, so the format version is bumped to 3. The existing
rule (ADR-0022, for version 1) is that a journal in an unreleased
development format is refused with `StoreError::Corrupted` naming the
version, not migrated. Version 2 was never released: v0.4.1 on crates.io
predates `FileStore` entirely. It is refused the same way. Migrating it
would have to read every version-2 journal as "no reset owed", which is
exactly the loss of intent this format exists to prevent.

### `MemoryStore`

An `AtomicBool`, kept across `reset` / `reset_to`. It survives an engine
restart over the same store (a new `Initiator` or `Acceptor` handed the same
`Arc<MemoryStore>`), not a process restart. Without a crash, a session never
leaves it set: it is set for a reset and cleared in the same handshake.

## Consequences

- A crash at any point from the marker write on restarts with a reset and
  141=Y at 1, in both roles: tested in
  `ironfix-engine/tests/durable_reset_tests.rs` at each step (marker, reset,
  Logon filed and persisted, spent and written, acknowledgement persisted,
  clear) for both store types.
- **Residual window:** a crash after a resetting Logon acknowledgement has
  arrived and before the marker is durable still restarts from the previous
  stream's counters. Closing it would mean setting the marker before every
  Logon, which would turn every crash during a handshake into a reset.
- A `StoreRefused` frame (ADR-0023) can be replayed after a restart only if
  the marker write after the failure fails too, which is logged.
- Cost: with a store attached, each reset costs one marker set and one clear,
  each two flushed slot writes on a `FileStore`, at handshake or close time
  only. Nothing is added to the per-message path.
- Public surface: two defaulted trait methods on `MessageStore` (additive, a
  minor bump). No engine `pub` item changes. The journal format bump is a
  breaking change for anyone holding version-2 journals from development
  builds of `main`; there is no released one.
