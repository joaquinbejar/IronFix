# ADR-0022 — FileStore: a writer thread, a dense index, counter slots and compaction

- **Status:** Accepted (issue #112, revised in the #112 review round;
  amends ADR-0006)
- **Date:** 2026-10-18

## Context

The `FileStore` of #78 (ADR-0006) is correct but deliberately simple, and the
perf review of #78 found four costs that grow with traffic or with the length
of a session:

- **Per call.** Every call took a `tokio::sync::Mutex` and ran its I/O as a
  new task on Tokio's blocking pool (`spawn_blocking`). Counted with `dhat`
  in steady state, `set_next_target_seq` allocated 2.00 heap blocks per call
  and `file_outbound` 3.17.
- **Index memory.** The in-memory index was a `BTreeMap<u64, IndexEntry>`,
  one entry per outbound message, estimated at 40 to 50 bytes each.
- **File growth.** Every counter write appended a 21-byte record, one per
  inbound message, and a frame filed again under the same number left the
  earlier record behind. Only a reset made the file smaller.
- **Restart time.** Opening and refreshing read and check the whole file, so
  they took longer as the file grew, counter records included.

Every change has to keep what ADR-0005 and ADR-0006 promise:

- mutations take effect in call order even when a call's future is dropped,
  with the cancellation semantics the #78 tests pin (a call dropped before it
  runs does nothing; one that has started finishes before the next one);
- one commit point per call: one appended record or one rename (and now,
  for a counter write, one slot write);
- the #89 crash table, the recovery rules (cut what an interrupted write can
  leave, refuse the rest), the fail-closed handling of a failed flush, and
  the sync policies;
- `ironfix-store` depends on `ironfix-core` only, plus `crossbeam-channel`
  (a workspace dependency, approved for this issue); it cannot log; no
  `unsafe`.

The #78 store-level tests in `file.rs` pass unchanged: their module is
byte-identical to the one on `main`. The #78 format tests targeted the
version-1 reader, which is gone; they are ported to version-2 record framing.

## Options

**Running the calls.**

1. Keep the lock and `spawn_blocking`. Rejected: the cost the issue is about.
2. **One writer thread per store**, fed by a bounded first-in, first-out
   `crossbeam-channel` queue, answering through pooled reply cells (chosen).
3. One writer pool shared by every store. Ordering per store still needs a
   queue per store; deferred until many stores per process make the thread
   count matter.
4. Run a call inline on the caller's thread when the writer is idle. Rejected:
   the I/O is blocking and must stay off the Tokio worker threads.

**Keeping the counters.**

1. Appended records (version 1). Rejected: the file grows with inbound
   traffic.
2. A counters file replaced by a rename. Rejected in ADR-0006: two flushes
   per counter write, and a reset that is not atomic across two files.
3. **Two fixed counter slots in the journal, written in place, numbered by a
   generation shared with the frame records** (chosen).

**Indexing the frames.**

1. The `BTreeMap`. Rejected: 40 to 50 bytes per message.
2. One `Vec` keyed by `seq - base`. Rejected: growing it copies the whole
   index, and a jump in the numbers would allocate a slot for every number
   skipped.
3. **Fixed chunks of slots keyed by `seq - start`, with a bounded number of
   holes, falling back to the `BTreeMap` past that bound** (chosen).

**Journals in the #78 format (version 1).**

1. Migrate them when they are opened. Rejected in review: version 1 existed
   only on `main` between #78 and this change and was never released.
   Migrating would turn an unreleased format into a compatibility promise of
   the next release, and keep a second parser of untrusted input on the open
   path.
2. **Refuse them with `StoreError::Corrupted` naming the version** (chosen),
   as ADR-0006 promised for any version a build does not read.

## Decision

### The writer thread

Each `FileStore` starts one thread, named `ironfix-store`, with a 256 KiB
stack, when it opens. The thread opens the journal and owns it from then on.

**What a call costs.** An async call builds a typed command (an enum, sent
by value: the record bytes it carries travel in a buffer taken from a pool)
and queues it with `try_send` on a bounded `crossbeam-channel` queue, before
its future first yields; the answer comes back through a reply cell taken
from a pool and returned to it after use. Compared with #78 this removes the
Tokio mutex, the blocking-pool task per call and every allocation the store
made per call. Counted with `dhat` (the `allocations` test, which asserts it):

| Call | #78 | now |
|---|---|---|
| `set_next_target_seq` | 2.00 blocks per call | 1 block per call |
| `file_outbound` | 3.17 blocks per call | 1 block per call |

The block that remains is the `async_trait` future, which the `MessageStore`
trait shape costs every implementation (ADR-0005). The locks the caller and
the writer thread share on every call (a reply cell's, the two pools') are
`std::sync` mutexes, whose contention waits in the kernel without
allocating: a `parking_lot` lock allocates its process-wide table of parked
threads the first time a thread parks on one, and the first test run of the
count caught exactly that (4 extra blocks in 1 000 calls, in about one run in
twelve). The journal's own lock stays `parking_lot`: only the writer thread
takes it. What does **not** change:
each call still makes two cross-thread wakes, one when queueing wakes the
writer thread and one when the answer wakes the caller's task. No timing
claim is made for either design (see "Consequences").

**Order and dropped calls.** The queue is first in, first out, and the thread
runs one call at a time, so calls take effect in the order they were queued.
Before running a call the thread checks whether its caller still waits (the
reply future exists). A call dropped before the thread takes it is skipped
and does nothing; a call the thread has started runs to the end, even if its
future is dropped meanwhile, before the thread takes the next one. These are
the semantics of the first-in, first-out lock it replaces, and the #78 tests
that pin them (a dropped `file_outbound` and a dropped `reset_to` land before
the next call; a call dropped while it waits writes nothing) pass unchanged.
Exactly one party returns a reply cell to its pool: the caller once it has
the answer (or drops a future that already has one), the writer once it has
skipped or answered a call whose future was dropped; the cell's lock decides.

**The queue is bounded at 1 024 calls**, and a call is never blocked on it: a
call made while it is full fails at once with `StoreError::Io`, without having
been queued or changed anything, which is a failed write the engine already
handles (ADR-0005). The engine awaits each store call, but a call whose
future its store timeout dropped stays in the queue, holding a slot, until
the thread reaches and skips it; the bound holds under a slow disk that
times calls out faster than the thread drains them.

**Every call is answered, a panic included.** A queued call holds a ticket
on its reply cell, and the ticket answers it exactly once: with the call's
outcome when it runs, or, when it is dropped unanswered, that the store is
closed (if the caller dropped its future, the ticket gives the cell back to
the pool instead). In a build that unwinds, a panic in the journal's opening,
in a call or in after-call work is caught on the writer thread: the call that
panicked is answered with `StoreError::Io`, and the store closes. The journal
is not trusted after a panic, since it may be half-way through a change: it
is dropped as it is, which leaves the files as a process crash would, and the
next open recovers them under the rules of ADR-0006. The thread survives and
answers every queued and later call that the store is closed; should it stop
anyway, it drains the queue as it exits. Without this, a panic would have
left the call that panicked and every call queued behind it (up to 1 023)
waiting for ever: crossbeam keeps the queued calls until the sender side
goes, and the sender side is the store itself. Under the workspace's
`panic = "abort"` release profile a panic ends the process instead.

**Commands that do not run give their buffers back.** A `store` or
`file_outbound` that is skipped (its future was dropped first), refused by a
full queue, or reaches a closed store returns its record buffer to the pool,
through a `discard` hook the writer calls on each of those paths.

**After-call work.** Whether an automatic compaction is due is checked under
the same lock guard as the call. The compaction itself runs after the call
has been answered, under a second guard, so the call that crossed the
threshold is not delayed; the next call waits for it.

**Shutdown.** Dropping the store closes the queue. If neither a call nor an
automatic compaction is running, the drop closes the journal (its files and
its lock) on the dropping thread and joins the writer thread, so the lock is
free when the drop returns. If one is running, the drop does not wait for it:
the thread finishes it, skips what is left in the queue (no caller can be
waiting any more), closes the journal and exits on its own. `FileStore::close`
closes the journal on the writer thread before it answers. After a failed
open the thread keeps answering every call that the store is closed, so no
call waits for an answer that never comes.

**Runtime.** A call made outside a Tokio runtime still fails with
`StoreError::Io`, checked per call. The review asked for the check to move to
`open`; it stays per call because the #78 test that pins it
(`test_file_store_outside_a_tokio_runtime_is_an_error_not_a_panic`) calls the
store outside a runtime and must pass unchanged. The check reads a
thread-local and allocates nothing.

**Not done: group commit.** The thread could gather writes queued together
into one flush. The engine never pipelines store calls, so it would never
apply; it is left until a caller does.

### The dense index

The index keeps one 12-byte slot per sequence number (the record's offset in
two 32-bit halves and its body length; all zeros is a hole, since no record
starts at offset 0 and no body is empty) in fixed chunks of 4 096 slots
(48 KiB), keyed by `seq - start`, `start` being the first number of the first
chunk, a multiple of 4 096. Filing a number past the last chunk allocates one
chunk and never moves the slots already there; the list of chunks holds one
pointer per chunk. A frame filed below the lowest number prepends chunks the
same way.

- **Memory per outbound message:** 12 bytes per sequence number from the
  first number of the chunk holding the lowest number filed to the last
  number of the chunk holding the highest, filed or not: 12 bytes per number,
  plus at most two partly used chunks (96 KiB) and 8 bytes per chunk for the
  list of chunks.
- **Bounded.** Between its lowest and its highest number the dense index
  holds at most `MAX_DENSE_HOLES` (65 536) holes, 768 KiB, in either
  direction. Only a frame that would take it past that bound switches it to
  the `BTreeMap` (about 40 to 50 bytes per filed frame and nothing per hole,
  by estimate) until the journal is reset, compacted or reloaded. Memory is
  then bounded by the number of records in the journal plus the hole bound,
  however far the numbers jump. A compaction writes the records in ascending
  order, so a reloaded journal is dense unless its numbers themselves jump.

### Format version 2 and the counter slots

| Offset | Size | Content |
|---|---|---|
| 0 | 44 | header, the version-1 layout declaring version `2`; its counters are the ones the journal was written with, superseded by the slots |
| 4 096 | 36 | counter slot 0 |
| 8 192 | 36 | counter slot 1 |
| 12 288 | | records |

The bytes between are zeros. The header and each slot sit alone in their own
4 KiB block, so a slot write torn by a power loss cannot reach the other slot
or the header on a device that writes blocks of at most 4 KiB. The cost is
12 KiB per journal. A compile-time check keeps the layout constants in
agreement.

A **counter slot** is a generation (u64), the next sender number (u64), the
next target number (u64), the durable boundary (u64, see below) and a CRC-32
of those 32 bytes. A **record** is kind
1 (a frame) or kind 5 (a frame with a generation and the next sender number,
written by `file_outbound`); any other kind is refused.

**Generations.** Every write that changes a counter takes the next number of
one sequence the journal shares between its slots and its kind-5 records. A
counter write (`set_next_sender_seq`, `set_next_target_seq`) carries both
counters. Loading takes:

- the next target from the newest valid slot (only slots carry it);
- the next sender from whichever is newer, that slot or the kind-5 record
  with the highest generation. A write-back of an unspent number after a frame
  record (the engine's close-time write after a failed `file_outbound`) and a
  frame record after a seed are both ordered correctly.

**Slot rotation: the durable checkpoint is never overwritten.** One slot
holds the last checkpoint known to be on stable storage (the newest slot at
the last successful flush). Every counter write until the next flush goes
into the **other** slot, overwriting it again and again; after a successful
flush that slot becomes the durable one, and the writes move to the opposite
slot. Under `EveryWrite`, which flushes every write, the slots alternate.
This rule came from review (thread 4307678227): the first version simply
alternated on every write, and under `EveryN` the second unflushed write
went over the slot holding the flushed checkpoint, so a power loss that
discarded the first and tore the second recovered counters older than the
flush, and one that tore both refused the journal. Now only one slot block
is written between flushes; whatever a power loss does to it, loading finds
at least the flushed checkpoint, and never refuses. A test enumerates every
discarded, kept and torn state of the slot blocks after two unflushed
counter writes.

**A torn slot write** damages only the slot being written, and the store
reopens from the other one: the counters as they were before the write that
did not return. That is not a cut, so `last_truncation` does not report it, and the
next counter write goes into the damaged slot. Both slots failing their check
is damage no single torn write leaves: the journal is refused with
`StoreError::Corrupted`, by `FileStore::repair` too, as a damaged header is.

**Durable boundary: damage the slots vouch for is refused.** Each slot
records the offset up to which the records were known to be on stable
storage when it was written (the end of the last successful flush; under
`EveryWrite`, the end of the journal). A record that starts below the
boundary of the newest valid slot was acknowledged before that slot was:
under the tail rules of `EveryWrite` and `EveryN`, damage to it, or a journal
that ends before the boundary, refuses the journal with
`StoreError::Corrupted`, and only damage past the boundary may be cut as a
torn tail. This rule also came from review (thread 4307678262): with counters
in slots, a damaged frame record could become the last record of the file
although a later counter write had acknowledged it, and recovery cut it while
keeping the sender number that said it was filed, so a resend gap-filled an
acknowledged frame. #78 refused the same damage, because the counter record
appended after the frame made it non-tail damage; the boundary restores that.
`FileStore::repair` (and `Never`, which cuts damage wherever it is) still cut
below the boundary; the store then writes one new slot (the same counters, a
generation above every other, the cut journal's end as its boundary) into the
position that does not hold the newest slot, so the journal is consistent for
any policy afterwards. One slot is enough, since loading reads the newest
slot's boundary only, and writing only the other position keeps it
crash-safe: a torn write leaves the newest slot, and the journal as it was,
for the next repair to cut and restamp again. The new boundary is true:
everything below the cut lay below the old boundary, which vouched for it. A
reset starts the boundary at the first record; a compaction sets it to the
end of the records it copied, all flushed before its rename; the cut back
after a failed flush leaves the slots on disk as the last successful flush
left them, whose boundaries are no higher than the cut.

**A slot never vouches for more than is known durable.** The boundary a
counter write records is the end of the last successful flush. When the store
opens or refreshes under a flushing policy it flushes what it loaded, so all
of it is durable. Under `Never` it does not flush (its documented behaviour),
so the journal counts as durable only as far as the boundary of the newest
slot it loaded; the records it read past that may still be only in the page
cache. Before this rule, a store reopened under `Never` took the end of what
it read as durable: a counter write then vouched for frames a power loss
could still lose, and a later open under a flushing policy refused a journal
that had only lost its unflushed tail. Flushing at open under every policy
would also have fixed it, but would change what `Never` promises; a test
simulates the sequence (two runs under `Never`, a power loss that keeps the
slot and loses the frames, a third run under `EveryWrite`).

**Failures.** A slot write that fails puts the slot's previous bytes back (or
leaves that pending). A failed flush, as in ADR-0006, cuts the records back to
the last successful flush and also puts back the slot written since that
flush, as the flush left it (only that slot differs; the one holding the
durable checkpoint is never written, here or when the refresh completes the
undo); both stay pending, and the store refuses every call but a reset until a
refresh has made them durable **and reloaded the journal**. Before this
change a refresh cleared what was pending as soon as the undo was on disk,
before the reload; a reload that then failed left the store usable with an
in-memory end past the real end of the file, and the next append left a gap
of zero bytes. Now the undo stays pending until the reload succeeds; a test
injects that failure.

**The #89 crash table** of ADR-0006 holds row for row. The one row that
changes mechanism is the inbound one: the target counter write is an in-place
slot write, durable before `Ok` under `EveryWrite`, and a crash during it
leaves the previous target (the "inbound M read, before the target counter
write" row).

**`EveryN` and `Never`: a slot can be ahead of a lost frame.** The slots and
the records are different blocks of the file, which an operating-system
crash or a power loss can bring back in either order. Under these policies a
counter slot that reached the disk can therefore be ahead of a frame record
that did not: the store's next sender number is past that frame, the frame
cannot be resent, and the engine answers a `ResendRequest` for its number
with a gap fill although the counterparty received it. This is within what
those policies already allow (losing some of the last writes that returned
`Ok`), and is stated in the `SyncPolicy` documentation. `EveryWrite` does not
have the problem: every write is on disk before the next one starts.

### Compaction

`FileStore::compact` rewrites the journal with only its live records: a
temporary file holding the header (the creation time kept), two fresh slots
with the current counters and generations above every record's, and each live
record read back into one reused buffer, checked and copied as it is, in
ascending order; then a flush, the rename (the commit point) and the
directory flush, whatever the policy. It returns the bytes reclaimed. Its
outcome at each crash point:

| Crash after | After the next open |
|---|---|
| writing the temporary file, before its flush | the old journal; the temporary file is removed |
| the flush, before the rename | the old journal; the temporary file is removed |
| the rename, before the directory flush | the compacted journal after a process crash; either journal after an operating-system crash |

Both journals hold the same frames and counters, so every row recovers the
same state. A test stops a compaction after each step and reopens.

**Automatic compaction is opt-in**: `FileStoreConfig::with_compaction_threshold`
takes any non-zero number of bytes (no upper bound) or `None`, the default.
With a threshold, the store compacts once the superseded records take at
least that many bytes **and** at least as many bytes as the live records; the
second condition bounds the work, since a compaction then copies no more than
was superseded since the last one. It never runs as part of opening.

**A compaction blocks the store.** It copies every live record, so it takes
time in proportion to the journal, and every call queued behind it waits.
Under `ironfix-engine` a call that waits past the store timeout
(`with_store_timeout`, default the 10-second write timeout) counts as a failed
write: the next session owes a sequence reset, and under
`StoreFailurePolicy::CloseSession` the session closes. **A failed automatic
compaction is silent**: it reaches no caller (the crate does not log), leaves
the journal as it was, and is not tried again until another threshold's worth
is superseded; one that fails after its rename leaves the store refusing calls
until a refresh, as a failed reset does.

With counters in slots, what a compaction reclaims is frames filed again under
the same number, which is rare: after a failed `file_outbound` the engine
writes back the number it did not spend and files the next frame under it
(ADR-0005), and a `with_initial_sequences` seed below the store's counter
refiles the numbers in between. A journal still grows with every outbound
frame until a reset: those frames answer resends.

### No migration: version 1 is refused

A journal whose header declares any version other than 2 is refused with
`StoreError::Corrupted` naming the version, by `open`, `refresh` and `repair`
alike, and the file is left as it is. That includes version 1, the #78
format, which only development builds of `main` wrote and no release
shipped. A store holding one is reset (or its journal removed) before it is
used with this build.

### Other changes

- Opening and refreshing read the journal through a 256 KiB buffer. Reading a
  resend page with one positional read per contiguous span of records was
  considered and not done: each record is still one positional read.
- The recovery rules and the window each policy allows, the sync policies,
  the lock file, the `0600` and `0700` permissions (every replacement is a new
  file), the store name rules, the synchronous getters and `last_truncation`
  do not change. Opening and refreshing still read the whole journal; it is
  smaller by every counter record version 1 appended.

## Consequences

- **Semver (additive):** `FileStore::compact`,
  `FileStoreConfig::with_compaction_threshold` and
  `FileStoreConfig::compaction_threshold`. No existing item changes its
  signature. `FileStoreConfig` gains a private field, so its `Debug` output
  and equality now include the threshold.
- **Behaviour:** automatic compaction is off unless configured. A call made
  while 1 024 calls are queued fails without being queued. Dropping a store
  with a call running no longer keeps its journal in a blocking task: the
  writer thread finishes the call and then releases the files, as before,
  without blocking the dropping thread.
- **On disk:** journals are version 2, 12 KiB larger than an empty version-1
  journal; version-1 journals are refused; builds from before this change
  refuse version-2 journals.
- **Threads:** one OS thread per open store, with a 256 KiB stack.
- **Dependencies:** `ironfix-store` gains `crossbeam-channel` (a workspace
  dependency) and, as a dev-dependency, `dhat` for the allocation test. The
  pools are a `std::sync::Mutex` over a `Vec` with a fixed capacity, so no
  other queue crate is added. The crate DAG is unchanged: `ironfix-store`
  still depends on `ironfix-core` only among the internal crates.
- **Evidence:** the `dhat` counts above are deterministic and asserted by
  `ironfix-store/tests/allocations.rs`. Timing is not: the before and after
  runs of `ironfix-store/benches/file_store.rs` for this change were taken on
  a machine under heavy load, where the same binary varied more between runs
  than the two designs did, so they are inconclusive and no timing figure is
  stated (ADR-0001). A later run on named, quiet hardware is left open; the
  benchmark gains a multi-thread case and a compaction case for it.
- **Not done:** group commit on the writer thread; a writer pool shared by
  stores; an index checkpoint so that opening does not read the whole
  journal; one read per contiguous span of a resend page.
