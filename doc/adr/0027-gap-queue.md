# ADR-0027: An optional queue for messages received above a gap

- **Status:** Accepted (issue #71, in the plan the owner approved)
- **Date:** 2026-10-19

## Context

When an inbound message arrives above the expected `MsgSeqNum` (34), the
reactor sends one open-ended `ResendRequest` (2) from the first missing number
(`doc/fix_operations.md`, "Resend Request"). Until now an application message
above the gap was then dropped, and an administrative one was acted on (a
TestRequest answered, a ResendRequest served) with its number left for the
counterparty's resend to gap-fill. That is legal, but every message received
intact above the gap crosses the wire twice, and ADR-0021 records two costs
that come from it: only a held Logon's number survives a gap, so
administrative frames that overtake a `NextExpectedMsgSeqNum` (789) resend are
stranded until the resend timeout asks for them again (#128), and a receiver
that does not queue is left waiting when a new number is interleaved with a
resend.

`doc/fix_operations.md` allows either behaviour and says nothing about a
bound, about what a queued administrative message means, or about how a
queue meets a `SequenceReset` or a Logout. The choices below are IronFix's;
QuickFIX/C++ queues every message that is too high and processes each in
turn.

Constraints any answer keeps:

- additive only at v0.4.1, and the default unchanged;
- no typestate change; checked sequence arithmetic;
- the crate DAG unchanged: the knob lives in `ironfix-session`'s
  `SessionConfig`, with no new dependency; the engine applies it;
- no allocation on the in-sequence path while the queue is empty;
- the order of ADR-0005 for every number consumed: the target counter is
  persisted before the expectation moves;
- the frame observer (ADR-0026) sees each inbound frame once, when it is
  framed;
- never delivered twice.

## Decision

1. **`GapPolicy`** (`ironfix_session::GapPolicy`, re-exported by
   `ironfix-engine`), `#[non_exhaustive]`: `Discard` (the default, the old
   behaviour) or `Queue { max_messages, max_bytes }`. It is
   `SessionConfig::gap_policy`, with `SessionConfig::with_gap_policy` and
   `SessionConfigBuilder::gap_policy`. `SessionConfig::validate` refuses a
   queue with a zero bound or one above `MAX_GAP_QUEUE_MESSAGES` (65 536) or
   `MAX_GAP_QUEUE_BYTES` (1 GiB), with
   `SessionConfigError::GapQueueOutOfRange`.
2. **The queue** is a private `GapQueue` in `ironfix-engine`: a
   `BTreeMap<u64, Gapped>` keyed by `MsgSeqNum`, bounded by count and by the
   sum of frame lengths. `Gapped::Frame(Bytes)` holds the frozen inbound frame
   (a reference count on the buffer it was read into, as for a frame handed
   to the dispatcher), `Gapped::Processed` only a number. `BTreeMap::new`
   does not allocate, so a session that never sees a gap pays one emptiness
   check per frame.
3. **What is queued.** Only an Active session with no Logout owed queues.
   Every message above the expectation still triggers the same
   `ResendRequest` (deduplicated as before): the counterparty cannot know what
   was kept, and the policy only spares delivering twice, not asking.
   - An application message: its frame.
   - A `SequenceReset`-GapFill: its frame. A gapped fill is not applied when
     it arrives, as before, so it is applied in turn, through
     `on_sequence_reset`, when the expectation reaches it. Its `from_admin`
     runs then, once.
   - Any other administrative message except a Logout: acted on at once, as
     under `Discard` (a TestRequest gets its Heartbeat now, a ResendRequest is
     served now, a Reject is logged now), and its number queued as
     `Processed`. Deferring it instead would delay a Heartbeat the
     counterparty is timing and change behaviour `Discard` keeps; acting on
     it twice would answer a TestRequest twice. So a queued administrative
     message is never processed at release, only its number consumed.
   - A Logout: never queued; see 6.
4. **Release.** After every inbound frame the reactor consumes, in a loop,
   whatever the expectation has reached: the held Logon of ADR-0021, then
   the queued message at the expectation, then the held Logon again, until
   neither is next (`Reactor::release_ready`). Held messages below the
   expectation (a gap fill, the held Logon or a `SequenceReset` moved it past
   them) are dropped. A released frame goes through the path it would have
   taken in sequence, minus what was done when it was framed: it was
   observed (ADR-0026), counted as proof of life, and checked for identity
   and `SendingTime` then, and is not again. An application message goes
   through `on_app_in_sequence`, so the `ApplVerID` check of ADR-0020, the
   target persist and the dispatcher apply, `PossDupFlag` (43) is passed to
   `from_app` as it arrived, and the order of ADR-0005 holds. A `Processed`
   number is persisted as `seq + 1` before the expectation moves. Recovery
   progress is noted for each, so the `ResendRequest` state clears once the
   expectation passes its water mark.
5. **Duplicates.** A second message for a number already held is dropped,
   whether or not it carries `PossDupFlag` = Y: the first copy is kept. Once a
   queued number is released, the counterparty's resent copy arrives below the
   expectation with `PossDupFlag` = Y and is ignored as before (a gap fill
   over it too). No number reaches `from_app` twice.
6. **What empties the queue.** A `SequenceReset`-Reset that is accepted
   (it renumbers the stream, so nothing queued under the old numbers is
   released), a Logout from the counterparty (in the gap or not), and this
   session's own Logout once written. Session close drops the reactor and the
   queue with it. Nothing dropped this way was persisted, so the target
   counter still names the first missing number.
7. **Overflow.** A message that would take the queue past either bound is
   discarded, exactly as under `Discard`, and what is held stays; the session
   is never closed for it. The open-ended `ResendRequest` already covers it, so
   it arrives from the resend, after the held messages it follows. The first
   overflow since the queue last emptied is logged at `warn`, the rest not,
   so a flood cannot flood the log. Discarding the whole queue was considered
   and refused: the held messages are valid and the resend makes up the rest
   either way.
8. **The held Logon (ADR-0021).** Frames past a held Logon `L` are queued like
   any other: once the gap below `L` is filled and `L` is consumed,
   `L + 1 .. L + k` are released in turn, so administrative frames that
   overtook the resend are no longer stranded until the resend timeout under
   `Queue`. Under `Discard` nothing changes, and #128 still applies.

## Consequences

- One public enum, two constants, one config field, two setters and one
  error variant are added to `ironfix-session`, and one re-export to
  `ironfix-engine`; all additive. `SessionConfig` and `SessionConfigError`
  are already `#[non_exhaustive]`.
- `Discard` keeps every existing test green; the new behaviour is opt-in.
- A queued message is checked for `SendingTime` accuracy when it arrives, not
  when it is released: a long gap does not make it stale.
- Memory under `Queue` is bounded by `max_bytes` of frames plus a map entry
  per message; the frames may pin larger read buffers than their own length.
- Tests: `ironfix-engine/src/gap_queue.rs` (bounds, duplicates, superseded
  numbers) and `ironfix-engine/tests/gap_queue_tests.rs`, in both roles: a
  gap filled by a resend with queued messages released in order and none
  duplicated, a TestRequest inside the gap, `Discard` unchanged, overflow by
  count and by bytes, a `SequenceReset`-Reset and an in-sequence gap fill
  during a gap, a gapped gap fill applied in turn, a Logout during a gap, and
  the held-Logon case of #128.
- No performance claim (ADR-0001): nothing was measured.
- **Not done:** the queue does not survive a restart (it holds frames, not
  persisted state); a `ResendRequest` is still sent for the whole range,
  including what is queued, since FIX has no way to ask for less without
  knowing the gap is contiguous.
