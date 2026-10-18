# ADR-0006 — A persistent, file-backed message store

- **Status:** Accepted (issue #78, in the plan the owner approved; the layout
  deviates from that plan in one respect, recorded under "Deviation from the
  plan")
- **Date:** 2026-10-18

## Context

`MemoryStore` was the only `MessageStore`. A process restart lost the
outbound journal and both sequence counters, so a session after a restart
could not resume from its counters, and a `ResendRequest` (35=2) for traffic
sent before the restart could only be answered with a `SequenceReset`-GapFill.

ADR-0005 (#62) made the store contract able to express a durable store, and
states what the engine relies on:

- every write is `async` and fallible; `Ok` means "as durable as the
  implementation promises";
- `store` has **replace** semantics at a number already filed;
- `file_outbound(seq, msg_type, frame, next_sender)` and
  `reset_to(next_sender, next_target)` are defaulted as two and three calls,
  and a durable store should make each one atomic write;
- `refresh` reloads the counters; `get_range` and the bounded `get_page`
  answer resends;
- the engine bounds every call with a timeout, which drops the call's
  future, and **mutations must take effect in call order even when a call's
  future is dropped**.

#89 lists the crash points a durable store has to survive, and asks each
store to state what it guarantees at the "store write, before fsync" row.

Constraints: `ironfix-store` depends on `ironfix-core` only, no dependency is
added (not even `tracing`, so the store cannot log), and no engine code
changes.

## Options for the layout

1. **QuickFIX-style files**: a body file, a header index file, a sequence
   numbers file and a session file. Four files that change independently; a
   reset or a frame-plus-counter write cannot be made atomic without a
   commit protocol across them.
2. **A message journal plus a counters file rewritten by temp-and-rename**
   (the approved plan). Three problems on inspection:
   - A reset has to replace both files, and two renames are not atomic
     together: a crash between them leaves a new empty journal with the old
     counters, or the reverse, the mix #89 forbids. Fixing it needs a
     generation number tying the two files together.
   - `file_outbound` writing frame and counter in one journal record means
     the next sender number lives in two places (the record and the counters
     file), and loading needs a rule for which is newer.
   - Each counter write is a create, a write, a flush, a rename and a
     directory flush. The engine writes the target counter for every inbound
     message, so under a flush-every-write policy that is two flushes per
     inbound message.
3. **One journal holding frames and counters as records**, with the counters
   the journal starts from in its header, replaced by temp-and-rename on a
   reset (chosen). Every call has exactly one commit point: one appended
   record, or one rename. Each write costs one flush under the strictest
   policy.

## Decision

### Files

A store is named (1 to 128 bytes of ASCII letters, digits, `.`, `-`, `_`, not
starting with `.`) and lives in a directory:

- `<name>.journal`: the journal;
- `<name>.journal.tmp`: a replacement journal while a reset is being written;
  removed at the next open if a crash left it behind (that reset did not
  happen);
- `<name>.lock`: locked (`std::fs::File::try_lock`, advisory) while the store
  is open. A second `FileStore` on the same files, in the same process or
  another, fails to open with `StoreError::Io` instead of interleaving two
  sequence streams. This enforces ADR-0005's "one store, one engine" for
  `FileStore`.

### Format, version 1

Little-endian. A 44-byte header: magic `IRFXJRNL`, format version (u16),
reserved (u16), creation time (u64 seconds and u32 nanoseconds since the Unix
epoch), the next sender and next target numbers the journal starts from (two
u64), and a CRC-32 of the preceding 40 bytes.

Then records, back to back: `len` (u32, body length), `!len` (u32, its bitwise
complement), the CRC-32 of the body (u32), and the body. A body is a kind byte
and its payload:

| Kind | Payload | Written by |
|---|---|---|
| 1, frame | `seq` u64, `MsgType` length u8, `MsgType`, frame | `store` |
| 2, frame and next sender | `seq` u64, `next_sender` u64, `MsgType` length u8, `MsgType`, frame | `file_outbound` |
| 3, next sender | u64 | `set_next_sender_seq` |
| 4, next target | u64 | `set_next_target_seq` |

Loading replays the records in file order: a later frame record for a number
replaces the earlier one (the replace semantics), and a later counter value
replaces the earlier one. The complement lets the loader tell a damaged record
header (zeroed or garbage bytes a crash can leave) from a well-formed one
before it trusts `len`. The CRC is CRC-32/ISO-HDLC (the zlib one), written by
hand with a compile-time table, so no dependency is added.

In memory the store keeps an index from sequence number to the record's
offset and length, and the two counters: the index is the only per-message
state. Frames are read back from the file when a resend asks for them, and
their record is checked again (length, complement, CRC, sequence number) on
the way. `get_page` reads only the frames of the page.

### Atomicity of each call

- `store`, `set_next_sender_seq`, `set_next_target_seq`: one record.
- `file_outbound`: **one record carrying both** the frame and the next sender
  number. After a crash both are in the journal or neither is: the #89 row
  "counter update, before store write" cannot happen.
- `reset` and `reset_to`: a complete new journal (header only, carrying the
  new counters and a new creation time) is written to `<name>.journal.tmp`
  and renamed over the journal. The rename is the commit point: after a crash
  the store is entirely the previous stream or entirely the new one. `reset`
  is `reset_to(1, 1)`. A reset sets a new creation time, as QuickFIX's does
  (`MemoryStore` keeps its creation time; the engine does not read it).

### Call order, and dropped futures

Every call takes one internal `tokio::sync::Mutex`, which is first-in,
first-out, before it does anything, and moves the owned guard onto the
blocking thread (`tokio::task::spawn_blocking`) that does its file I/O. So:

- calls run one at a time, in the order they were first polled;
- a call whose future is dropped while it waits for the lock writes nothing;
- a call whose future is dropped once its I/O has started still completes
  that I/O, holding the lock, before any later call runs.

A mutation therefore takes effect before any mutation called after it, or not
at all, which is the call-order contract of ADR-0005. When the engine's store
timeout drops a mutation and it owes a reset, the late write lands before that
reset, which erases it. Tests drop a `file_outbound` and a `reset_to` while
their I/O is held in flight, issue the next mutation, reopen, and check the
order on disk.

A slow disk, under `EveryWrite`, can overrun the store timeout; each overrun
costs the next session a sequence reset (ADR-0005). The store timeout has to
cover the flush the policy asks for.

The synchronous getters (`next_sender_seq`, `next_target_seq`,
`creation_time`) read values the journal publishes after each change is in the
file; they never take the lock.

### Sync policies

Every write is a `write` system call made before the call returns, with no
buffering in the process, so under **every** policy a write that returned `Ok`
survives the process crashing. The policy decides what survives the operating
system crashing or the machine losing power, which a flush
(`std::fs::File::sync_data`) protects against:

| Policy | Journal writes | Replacement on reset or creation | Survives OS crash / power loss |
|---|---|---|---|
| `EveryWrite` (default) | flushed before `Ok` | file flushed before the rename, directory after | every write that returned `Ok` |
| `EveryN(n)` | flushed after every n-th write | as `EveryWrite` | all but at most the last `n - 1` writes that returned `Ok` |
| `Never` | not flushed | not flushed | nothing is promised |

`FileStore::sync` flushes on demand under any policy. The directory flush is
made on Unix only; elsewhere a directory cannot be opened as a file.

Against the #89 outbound crash table, for a message numbered N:

| Crash after | `FileStore` |
|---|---|
| frame encode, before counter update | No record for N: N is reused, and the peer never saw it. |
| counter update, before store write | Impossible: frame and counter are one record. |
| store write, before fsync | The call has not returned, so the engine has not written the bytes. The record survives whole (a process crash; or an OS crash after the page reached the disk), giving frame N and N+1 as in the next row, or it is cut as torn, giving neither as in the first row. Both are rows #89 accepts, and neither mixes them. Under `EveryN` and `Never` this holds for a **process** crash only: an OS crash or power loss can also lose *earlier* writes that returned `Ok` and whose bytes the peer received, rolling the counters back, so a number can be reused with different content. Only `EveryWrite` meets #89 against an OS crash or power loss. |
| fsync, before socket send | Frame N and N+1 are durable (under `EveryWrite`): N is never reused, and a resend of N replays the filed frame. |
| socket send, before peer confirmation | As above. |

Inbound: the next-target record is written, and under `EveryWrite` flushed,
before the engine acts on the message (ADR-0005), so the receive cursor after
a restart includes every message that was acted on.

Resets: under `EveryWrite` and `EveryN` the replacement is flushed before its
rename and the directory after, so a crash leaves the complete old journal or
the complete new one. Under `Never` an OS crash or power loss can leave a
renamed but empty journal; `FileStore::open` then refuses it as corrupted (a
typed error, never a mix of streams and never a silently fresh store).

### Recovery

`FileStore::open` and `refresh` read the whole journal.

- **Cut and continue.** A record the file ends inside (a write a crash
  interrupted: `TruncationCause::Incomplete`), or one whose complement or CRC
  check fails (`TruncationCause::Damaged`), is cut from the file **together
  with everything after it**, flushed unless the policy is `Never`, and never
  returned. The store continues from the last good record.
  `FileStore::last_truncation` reports the cut (offset, bytes dropped,
  cause), because the crate cannot log. An `Incomplete` cut loses only the
  interrupted write. A `Damaged` cut can come from a crash under a policy
  that does not flush every write, or from damage to data already on disk; in
  the second case it drops records that were acknowledged, counters
  included, and an application may refuse to start a session over it.
- **Refuse.** A well-formed record header declaring a body of 0 bytes, or
  above the configured maximum frame size plus the 26-byte record overhead;
  a record that passes its CRC but does not decode (unknown kind, malformed
  fields, invalid `MsgType`); and a header that is not a version-1 header
  (short file, wrong magic, wrong version, failed header CRC) are
  `StoreError::Corrupted`. The store does not open and nothing is cut: a
  well-formed header claiming a larger body is more likely a journal written
  under a larger frame limit than damage, and cutting it would destroy it.
- **Bounded.** Nothing is allocated for a record before its declared length
  has been checked against the configured limit, so no file, however
  hostile, makes the store allocate more than one maximum-size record.
- **I/O.** Every I/O error is `StoreError::Io`, naming the operation and the
  path, never frame bytes.
- **After a failed write.** A failed append is undone by cutting the file back
  to where the record started. A failed flush, or a failed undo, leaves the
  file possibly out of step with the store (after a failed flush the
  operating system may have dropped data an earlier write reported as
  written), so the store then fails every call except `refresh`, which
  rereads the file and clears the state. A write that reached the file before
  its flush failed is found by that refresh: the call took effect although it
  reported a failure, a case ADR-0005 already allows for.

### Limits

- The journal grows until it is reset: every counter write adds a 21-byte
  record, and a frame filed again under the same number leaves the earlier
  record in the file. There is no compaction. FIX sessions that reset their
  sequence daily bound it by the day.
- Opening and refreshing read and check the whole journal.
- Frames above `FileStoreConfig::max_frame_size` (default 1 MiB, at most
  64 MiB) are refused with `StoreError::StoreFailed`. Lowering the limit below
  a frame already filed makes the journal refuse to open until it is raised
  again.
- Inbound frames are not filed (ADR-0005, "Not done").
- The lock is advisory and depends on the file system honouring it.
- No memory-mapped store exists.

### Compatibility promise

The format is versioned by the header. This build reads and writes version 1
only and refuses any other version with `StoreError::Corrupted`. A release
that changes the format bumps the version and states in its changelog whether
it reads earlier versions; it never reinterprets a version-1 journal under
other rules. The format is not QuickFIX's and cannot read QuickFIX store
files.

### Deviation from the plan

The approved plan kept the counters in a separate file rewritten through a
temporary file and a rename. They are records in the journal instead, for the
three reasons under option 2: a reset that replaces two files is not atomic,
a counter in two places needs a precedence rule, and a rename per counter
write costs two flushes per inbound message. The temp-and-rename the plan
describes is kept for what replaces the whole journal: `reset`, `reset_to`
and the creation of a new store.

Two smaller additions the plan did not name: the lock file, and
`FileStore::last_truncation` (with `Truncation` and `TruncationCause`) to
report a cut without a logging dependency.

## Consequences

- **Semver (additive only):** the `ironfix_store::file` module with
  `FileStore` (`open`, `config`, `last_truncation`, `sync`, and the
  `MessageStore` implementation), `FileStoreConfig` (`try_new`,
  `with_sync_policy`, `with_max_frame_size`, `directory`, `name`,
  `sync_policy`, `max_frame_size`, `journal_path`, `lock_path`),
  `FileStoreConfigError`, `SyncPolicy`, `Truncation`, `TruncationCause`,
  `DEFAULT_MAX_FRAME_SIZE`, `MAX_FRAME_SIZE_LIMIT` and `MAX_STORE_NAME_LEN`;
  the six types are re-exported at the crate root. `SyncPolicy`,
  `FileStoreConfigError` and `TruncationCause` are `#[non_exhaustive]`. No
  existing item changes.
- **Dependencies:** none added. `ironfix-store` still depends on
  `ironfix-core` only; `File::try_lock` is in the standard library.
- **Engine:** unchanged. A `FileStore` is attached like any store
  (`Initiator::with_store`, `Acceptor::with_store`,
  `EngineBuilder::with_store`); an engine test reopens one in a new
  `Initiator` and checks that a `ResendRequest` replays the original frames.
- **#89:** `FileStore` under `EveryWrite` is the store the joint acceptance
  suite can run against. Its fault-injection hooks (a stalled call, a failed
  flush, flush counters) are private to the crate's own tests; the fsync
  interception #89 asks for, usable from `ironfix-engine` tests, is not
  provided here.
- No performance claim is made (ADR-0001).
