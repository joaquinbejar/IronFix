# ADR-0006 — A persistent, file-backed message store

- **Status:** Accepted (issue #78, in the plan the owner approved, revised in
  the #78 review round; the layout deviates from that plan in one respect,
  recorded under "Deviation from the plan"). Amended by ADR-0022 (#112):
  format version 2 keeps the counters in two fixed slots instead of counter
  records, every call runs on one writer thread per store instead of behind
  a lock on Tokio's blocking pool, the index is dense, and the journal can be
  compacted. The sections below on the format, the call order, the limits
  and the compatibility promise describe version 1 as #78 built it, and so
  does the sentence on dropping a store under "One store, one owner": a
  dropped store now releases its lock once any call or automatic compaction
  its writer thread is running finishes. Version 1 was never released; this
  build reads version 2 only and refuses version 1, like any other version,
  with `StoreError::Corrupted` naming it. The recovery rules, the sync
  policies and the crash table hold unchanged for version 2.
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

Constraints: `ironfix-store` depends on `ironfix-core` only, and no runtime
dependency is added (not even `tracing`, so the store cannot log).

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

A store is named and lives in a directory:

- `<name>.journal`: the journal;
- `<name>.journal.tmp`: a replacement journal while a reset is being written;
  removed at the next open if a crash left it behind (that reset did not
  happen);
- `<name>.lock`: locked while the store is open (see "One store, one owner").

The name is 1 to 128 bytes of ASCII letters, digits, `.`, `-` and `_`, does
not start with `.`, and is not (before its first `.`, in any case) a device
name Windows reserves (`CON`, `PRN`, `AUX`, `NUL`, `COM1` to `COM9`, `LPT1` to
`LPT9`). Names must be treated as case-insensitive: on a case-insensitive file
system (the default on macOS and Windows) two names that differ only in case
are the same files; the lock refuses the second store while the first is
open, but two sessions opened one after the other would share one journal.

A journal holds complete outbound frames, an outbound Logon's `Password` (554)
included. On Unix every file the store creates (the journal, the replacement a
reset writes, the lock file) is created `0600`, readable and writable by its
owner only, and every directory it creates is `0700`. The replacement is
always a new file, so a reset never loosens the journal's permissions,
whatever a leftover temporary file or a hand-loosened journal had. Files and
directories that already exist keep their permissions. Off Unix the
platform's defaults apply.

A missing journal is an error unless `FileStoreConfig::with_create_if_missing`
is set (default off), so a store that was expected to exist (a wrong
directory, an unmounted volume) is never silently replaced by a fresh one at
1/1. With it set, missing directories are created and each is flushed into its
parent, and the new journal is created like a reset.

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
state. A frame record is built in one allocation; a counter record is 21 bytes
on the stack. Appends are positional writes. A resend reads each record with
one positional read and checks it again (length, complement, CRC, sequence
number); `get_page` reads only the frames of the page.

### Atomicity of each call

- `store`, `set_next_sender_seq`, `set_next_target_seq`: one record.
- `file_outbound`: **one record carrying both** the frame and the next sender
  number. After a crash both are in the journal or neither is: the #89 row
  "counter update, before store write" cannot happen.
- `reset` and `reset_to`: a complete new journal (header only, carrying the
  new counters and a new creation time) is written to `<name>.journal.tmp`,
  flushed, renamed over the journal, and the directory flushed, **whatever
  the sync policy**. The rename is the commit point: after a crash the store
  is entirely the previous stream or entirely the new one, and an
  operating-system crash cannot bring the previous stream back. `reset` is
  `reset_to(1, 1)`. A reset sets a new creation time, as QuickFIX's does
  (`MemoryStore` keeps its creation time; the engine does not read it).

### Call order, and dropped futures

Every call checks that it runs inside a Tokio runtime (outside one it returns
`StoreError::Io` rather than letting `spawn_blocking` panic, which
`panic = "abort"` would turn into a process exit), then takes one internal
`tokio::sync::Mutex`, which is first-in, first-out, and moves the owned guard
onto the blocking thread that does its file I/O, with no await in between.
So:

- calls run one at a time, in the order they reach the lock;
- a call whose future is dropped before it holds the lock writes nothing;
- once a call holds the lock, its I/O completes before any later call runs,
  even if its future is dropped.

A mutation therefore takes effect before any mutation called after it, or not
at all: the call-order contract of ADR-0005. When the engine's store timeout
drops a mutation and it owes a reset, the late write lands before that reset,
which erases it. Tests drop a `file_outbound` and a `reset_to` while their I/O
is held in flight, issue the next mutation, reopen, and check the order on
disk.

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
(`std::fs::File::sync_data`; on Apple platforms the standard library
implements it with `F_FULLFSYNC`) protects against:

| Policy | Journal writes | Open and refresh | Survives OS crash / power loss |
|---|---|---|---|
| `EveryWrite` (default) | flushed before `Ok`: one flush per message in each direction | journal flushed once loaded | every write that returned `Ok` |
| `EveryN(n)` | flushed after every n-th write; no time bound | journal flushed once loaded | all but at most the last `n - 1` writes that returned `Ok` |
| `Never` | not flushed | not flushed | nothing is promised |

Resets and the creation of a journal are flushed under every policy (see
"Atomicity"). `FileStore::sync` flushes on demand, and `FileStore::close`
flushes what `EveryN` left pending; the engine calls neither, so an
application that wants them keeps its own `Arc<FileStore>`. What a flush
costs is not stated: `ironfix-store/benches/file_store.rs` measures it on
whatever machine runs it, and no figure is published (ADR-0001).

**Platform.** These guarantees are stated for Unix. Off Unix the directory is
not flushed after a rename (a directory cannot be opened as a file there), and
the store is untested.

**Failure policy.** The store's guarantees reach the wire only under the
engine's `StoreFailurePolicy::CloseSession`, where a failed write keeps its
frame off the wire. Under `Continue` the frame is sent anyway; since every
failed mutation owes a reset (below), the next session then starts a new
stream rather than building on a store that missed what the counterparty saw.

Against the #89 crash tables, for an outbound message numbered N and an
inbound message numbered M, with `CloseSession`:

| Crash after | `FileStore` |
|---|---|
| frame encode, before counter update | No record for N: N is reused, and the peer never saw it. |
| counter update, before store write | Impossible: frame and counter are one record. |
| store write, before fsync | The call has not returned, so the engine has not written the bytes. The record survives whole (a process crash; or an OS crash after its page reached the disk), giving frame N and N+1 as in the next row, or it is cut as an interrupted write, giving neither as in the first row. Both are rows #89 accepts, and neither mixes them. Under `EveryN` and `Never` this holds for a **process** crash only: an OS crash or power loss can also lose *earlier* writes that returned `Ok` and whose bytes the peer received, rolling the counters back, so a number can be reused with different content. Only `EveryWrite` meets #89 against an OS crash or power loss. |
| fsync, before socket send | Frame N and N+1 are durable (under `EveryWrite`): N is never reused, and a resend of N replays the filed frame. |
| socket send, before peer confirmation | As above. |
| inbound M read, before the target counter write | The counter still expects M: the peer's resend of M is accepted. |
| target counter write (M+1), before the application handled M | Durable under `EveryWrite` before M is acted on (ADR-0005), so the restart expects M+1: M is lost to the application (at most once, ADR-0005), and **reported** at the next start through `Application::on_inbound_lost`, as part of the span above the inbound application watermark (ADR-0030, #105). Not redelivered. |
| `from_app` returned for M, before the watermark write | The watermark still stands below M: M is reported as possibly lost although the application saw it (the residual window of ADR-0030). |
| watermark write for M | M is not reported. |
| an administrative or locally rejected inbound message | Its M+1 is written like any other, so the receive cursor after a restart includes it. |
| reset (`reset_to`), before the rename | The previous stream, complete; the leftover `.tmp` is removed at open. The engine recorded the reset as owed before awaiting it, but that record is in memory (see the unmet row). |
| reset, after the rename | The new stream, complete, under every policy. |
| `ResetSeqNumFlag` (141) = Y acknowledged by the counterparty, before the store reset made it durable | **Met from the marker on** (ADR-0029, #111). The engine writes its intent to reset into the store's durable marker before it resets the store, and clears it after `on_logon`'s handshake step; a crash in between restarts with a reset and 141=Y at 1. A crash after the ack arrives and before the marker is durable still restarts from the previous stream's counters. |

### Recovery

`FileStore::open` and `refresh` read the whole journal. Recovery cuts only
what an interrupted write can leave, and refuses the rest. The policy the
store is opened with decides the window, so a journal should be opened with
the policy it was written under.

- **Cut.** A record the file ends inside (`TruncationCause::Incomplete`,
  always the tail); a record whose body fails its CRC and is the last record
  in the file; a damaged record header (the complement check fails) with no
  more than one maximum-size record from it to the end of the file; any such
  damage followed only by zero bytes (a file system can leave a file longer
  than what reached it, and no record is ever zeros). Under `EveryN(n)` the
  window is `n` maximum-size records for both a CRC failure and a damaged
  header, since up to `n` writes can be in flight. Under `Never`, which
  promises nothing after an OS crash, damage is cut wherever it is. These are
  `TruncationCause::Damaged`. A cut removes the record and everything after
  it, so the record is never returned; the cut is flushed unless the policy is
  `Never`, and `FileStore::last_truncation` reports it (offset, bytes
  dropped, cause), because the crate cannot log. The report is sticky: the
  last cut since the store was opened stays on record through clean
  refreshes.
- **Refuse.** Damage outside that window is damage to data already written,
  and acknowledged: a record failing its CRC with more records after it, under
  `EveryWrite`. Cutting it would drop acknowledged records, counters included,
  and the next session could reuse a `MsgSeqNum` with different content. The
  store refuses to open with `StoreError::Corrupted` and leaves the file
  untouched, as it does for a well-formed record header declaring a body of 0
  bytes or above the configured maximum frame size plus the 26-byte record
  overhead (more likely a journal written under a larger limit than damage),
  a record that passes its CRC but does not decode, and a header that is not a
  version-1 header (short file, wrong magic, wrong version, failed header
  CRC).
- **Repair.** `FileStore::repair` is the operator's opt-in salvage of a
  refused journal: it cuts at the first record that cannot be read for any
  reason, flushes, and closes the store, returning the cut. The records cut
  away can include ones the counterparty received, so **the next session must
  reset its sequence** (`ResetSeqNumFlag` (141) = Y, for example through
  `reset_on_logon`, or `MessageStore::reset` before the store is attached).
  A repair never creates a store.
- **Bounded.** Nothing is allocated for a record before its declared length
  has been checked against the configured limit, so no file, however
  hostile, makes the store allocate more than one maximum-size record.
- **I/O.** Every I/O error is `StoreError::Io`, naming the operation and the
  path, never frame bytes.

### A write that fails

- **A failed write** is undone by cutting the file back to where the record
  started. If the undo fails, the cut is left pending.
- **A failed flush.** After a failed flush the operating system may have
  dropped data that earlier writes reported as written, and a later flush can
  report success without bringing it back. The store therefore tracks where
  its last successful flush left the journal (`durable_end`), cuts the journal
  back to it at once, and leaves that cut pending. Every write since that
  flush is treated as not filed: under `EveryWrite` that is only the write
  whose flush failed, so its `Err` means "not filed"; under `EveryN` it is
  every unflushed write.
- **A failed flush during a refresh.** A refresh flushes what it loaded
  (under `EveryN`, the writes left unflushed). That flush goes through the
  same step as any other, so a failure cuts back to the last successful flush
  and leaves the cut pending; the next refresh makes it durable before it
  rereads anything, and never adopts the unflushed bytes. A failure to read
  or scan the journal is not a flush failure and leaves the store as it was.
- **A failed directory flush** after a reset's rename leaves the rename
  committed (the store reports the new stream) but not known durable; the
  directory flush is left pending.

While anything is pending the store refuses every call except `reset` /
`reset_to` and `refresh`. `refresh` completes what is pending (the directory
flush; the cut back to `durable_end`, flushed) before it rereads the journal,
so it never re-adopts bytes the page cache held past a failed flush. A reset
replaces the journal, flushed, and clears everything pending.

### The engine side

Three engine changes come with the store (`ironfix-engine/src/persistence.rs`,
`reactor.rs`, and the two handshakes):

- **Every failed mutation owes a reset**, not only one that overruns the store
  timeout, under both policies. The `MessageStore` contract gives a store no
  way to say a failed write changed nothing, so the store's state after a
  failure is unknown. Under `Continue` the session carries on and the next one
  starts with a reset and `ResetSeqNumFlag` = Y.
- **The owed-reset record is kept by generation.** Each obligation is
  numbered when it is recorded, and paying a reset settles the obligation it
  was started for and every earlier one, never a later one: the reset erased
  what an earlier failed write left, but not what a write made after it
  started. Before, paying the reset declared on a Logon cleared the whole
  record, so a store write that failed during that same handshake (filing
  the Logon or its acknowledgement, or persisting the acknowledgement's
  number) lost its owed reset. Both roles share the record through
  `StoreAttachment`.
- **A corrupted resend read closes the session.** When `get_page` reports
  `StoreError::Corrupted` (a `FileStore` record failing its checks on read,
  or no longer whole because the file was cut under the open store, which
  fails the whole page), the engine closes the session instead of
  gap-filling the rest of the range: a gap fill would tell the counterparty
  that application messages it may never have received do not exist. Other
  read errors still degrade to a gap fill (ADR-0005).

### One store, one owner

While a store is open it holds an advisory lock on `<name>.lock`
(`std::fs::File::try_lock`, standard since Rust 1.89, which this crate
therefore needs; no MSRV is declared). A second `FileStore` on the same files,
in this process or another, fails to open with `StoreError::Io` instead of
interleaving two sequence streams. The operating system releases the lock
when the process dies. It is advisory, and network file systems may not
honour it. Where the platform or file system cannot lock at all, opening fails
rather than proceeding unlocked. Dropping a store releases the lock once any
call still running on a blocking thread finishes; `FileStore::close` waits for
that, flushes what `EveryN` left pending, and releases it. This enforces
ADR-0005's "one store, one engine" for `FileStore`.

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
- No memory-mapped store exists.
- The performance work the review deferred (a dedicated writer thread instead
  of one blocking task per call, a dense index, counter slots instead of
  counter records, compaction) is #112.

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
a counter kept in two places needs a precedence rule, and a rename per counter
write costs two flushes per inbound message. The temp-and-rename the plan
describes is kept for what replaces the whole journal: `reset`, `reset_to`
and the creation of a new store.

Additions the plan did not name: the lock file, `FileStore::last_truncation`
(with `Truncation` and `TruncationCause`) to report a cut without a logging
dependency, `FileStore::sync`, `FileStore::close`, `FileStore::repair`, and
`create_if_missing`.

## Consequences

- **Semver (additive only):** the `ironfix_store::file` module with
  `FileStore` (`open`, `repair`, `close`, `config`, `last_truncation`, `sync`,
  and the `MessageStore` implementation), `FileStoreConfig` (`try_new`,
  `with_sync_policy`, `with_max_frame_size`, `with_create_if_missing`,
  `directory`, `name`, `sync_policy`, `max_frame_size`, `create_if_missing`,
  `journal_path`, `lock_path`), `FileStoreConfigError`, `SyncPolicy`,
  `Truncation`, `TruncationCause`, `DEFAULT_MAX_FRAME_SIZE`,
  `MAX_FRAME_SIZE_LIMIT` and `MAX_STORE_NAME_LEN`; the six types are
  re-exported at the crate root. `SyncPolicy`, `FileStoreConfigError` and
  `TruncationCause` are `#[non_exhaustive]`. No existing item changes.
- **Behaviour (engine):** a failed store mutation now owes a reset under both
  policies, and stays owed when a reset started before it is paid; a
  corrupted resend read closes the session instead of gap-filling.
- **Dependencies:** no runtime dependency added. `ironfix-store` still
  depends on `ironfix-core` only; it gains `criterion` as a dev-dependency
  (the workspace one, ADR-0001) for its benchmark.
- **#89:** `FileStore` under `EveryWrite` with `CloseSession` is the store the
  joint acceptance suite can run against. Its fault-injection hooks (a stalled
  call, a failed journal flush, a failed directory flush, flush counters) are
  private to the crate's own tests; the fsync interception #89 asks for,
  usable from `ironfix-engine` tests, is not provided here. The durable
  owed-reset intent is ADR-0029 (#111): a flag in the counter slots, format
  version 3. The inbound application watermark is ADR-0030 (#105): a field
  in the counter slots, format version 4.
- No performance claim is made (ADR-0001).
