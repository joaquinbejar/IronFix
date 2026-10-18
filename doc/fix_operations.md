# FIX Protocol Operations Specification

This document defines all operations that IronFix servers should support. It covers session-level messages, application-level messages, and the expected behavior for each operation.

## Table of Contents

1. [Session Layer Messages](#session-layer-messages)
2. [Pre-Trade Messages](#pre-trade-messages)
3. [Trade Messages](#trade-messages)
4. [Post-Trade Messages](#post-trade-messages)
5. [Market Data Messages](#market-data-messages)
6. [Error Handling](#error-handling)

---

## Session Layer Messages

These messages are required for establishing and maintaining FIX sessions.

### Logon (MsgType = A)

**Direction**: Bidirectional (Initiator → Acceptor, Acceptor → Initiator)

**Purpose**: Establish a FIX session between two parties.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 8 | BeginString | FIX version (e.g., "FIX.4.4", "FIXT.1.1") |
| 9 | BodyLength | Message body length |
| 35 | MsgType | "A" |
| 49 | SenderCompID | Sender identifier |
| 56 | TargetCompID | Target identifier |
| 34 | MsgSeqNum | Message sequence number |
| 52 | SendingTime | Timestamp (UTC) |
| 98 | EncryptMethod | Encryption method (0 = None) |
| 108 | HeartBtInt | Heartbeat interval in seconds |
| 1137 | DefaultApplVerID | Default application version. **Required when `8=FIXT.1.1`**; not part of FIX 4.x |
| 10 | CheckSum | Message checksum |

**Optional Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 141 | ResetSeqNumFlag | Reset sequence numbers (Y/N) |
| 553 | Username | Authentication username |
| 554 | Password | Authentication password |
| 384 | NoMsgTypes | FIXT.1.1 only: repeating group of supported message types (372, 385, 1130, 1406, 1131, 1410). The embedded QuickFIX `FIXT11.xml` does not define it; see "Dictionary side, standalone" below |

**Server Behavior**:
1. Validate SenderCompID and TargetCompID
2. Authenticate credentials if provided
3. Initialize session state
4. Respond with Logon message
5. Begin heartbeat monitoring

**What IronFix implements today (initiator side)**

`ironfix-engine::Initiator` validates the Logon acknowledgement in this order,
and stops at the first failure:

1. **MsgType.** A Logout or Reject is a rejected Logon; anything else is an
   unexpected message.
2. **Identity.** Inbound `SenderCompID` (49) must equal the configured
   `target_comp_id` and inbound `TargetCompID` (56) the configured
   `sender_comp_id`; when `sender_sub_id` / `target_sub_id` are configured,
   inbound `TargetSubID` (57) and `SenderSubID` (50) are checked the same way.
   Each must both carry the expected value **and** occur in the standard header:
   a CompID that appears only after the message body identifies nothing and is
   treated as missing. A mismatch or a misplacement produces a session Reject
   with reason 9 (CompID problem) followed by a Logout, and the handshake fails.
   This is checked before any callback runs and before sequence state moves, so
   a cross-wired connection can never establish a session.
3. **`SendingTime` (52).** Validated against the local clock (see "Reject",
   reason 10). A skew beyond the tolerance, an absent field, or an unparseable
   one Rejects and fails the handshake, before the heartbeat clock is set.
4. **`from_admin`.** A rejection sends a Logout and fails the handshake.
5. **`HeartBtInt` (108).** 108 is a *required* field of the Logon, so an ack
   that omits it (session Reject, reason 1 — required tag missing) or carries a
   non-numeric value (session Reject, reason 6 — incorrect data format for
   value), `RefTagID` = 108 in both cases and each followed by a Logout, fails
   the handshake with `EngineError::HeartbeatInterval` rather than silently
   establishing the session on the locally configured interval. When present and
   numeric the interval confirmed by the counterparty wins, within a bound.
   Because the value is counterparty-controlled and drives every liveness timer
   in the session, a confirmed interval above
   `ironfix_session::heartbeat::MAX_HEARTBEAT_INTERVAL_SECS` (3600 s) is
   refused with a session Reject, reason 5 (value is incorrect),
   `RefTagID` = 108, followed by a Logout; the handshake then fails with
   `EngineError::HeartbeatInterval`. Adopting an unbounded value would let a
   peer switch dead-peer detection off for as long as it liked. The one
   exception is a confirmed value that is *exactly* the interval this side
   requested: echoing our own configuration back is our choice, not the
   counterparty pushing us past the ceiling. `108=0` is legal and always
   accepted; see "Heartbeat" below for what it means.
6. **`ResetSeqNumFlag` (141).** `141=Y` on the ack must arrive under
   `MsgSeqNum = 1` — the reset and the number carrying it have to describe the
   same stream — and a peer that sends any other number fails the handshake
   rather than having one half of the contradiction guessed for it. It is
   honored **before** MsgSeqNum is validated — otherwise the ack's
   `34=1` reads as fatally too low against continuity-seeded counters. The
   inbound counter is reset to 1. The outbound counter is set to 2, not 1.
   That is an interpretive choice, not a derivation: it is exact when
   `reset_on_logon` was set (the Logon on the wire really was message 1 of the
   reset stream, and rewinding would re-emit a number the peer has seen), but
   with continuity-seeded counters the Logon went out under its seeded number
   and nothing numbered 1 was ever sent. QuickFIX/J's two halves disagree here
   — its initiator would set 1, its acceptor 2 — and IronFix matches the
   acceptor. The mismatch self-heals: the peer sees a gap at 2, requests a
   resend of 1, and receives a GapFill that resynchronises it.
7. **`MsgSeqNum` (34).** The header 34 is read positionally, *before* identity —
   the same standard-header contract step 2 applies to the CompIDs — so a 34 that
   occurs only after the body is treated as missing and fails the handshake. The
   value read there is then validated at this step: too low fails the handshake,
   and a gap completes the handshake and immediately issues a ResendRequest.

The same identity and `SendingTime` checks (steps 2 and 3) run on every inbound
frame once the session is established; there a failure produces the Reject and
Logout and then tears the session down. An unsatisfied ResendRequest from step 7
does not stall forever — it is retried and then escalated to Logout; see "Resend
Request".

Outbound `ResetSeqNumFlag` is driven by `SessionConfig::reset_on_logon`.

**What IronFix implements today (acceptor side)**

`ironfix-engine::Acceptor` is the mirror of the above. It waits for the inbound
Logon (bounded by `SessionConfig::logon_timeout`) and validates it in the same
order — it must decode and be a Logon; its `BeginString` (8) must match this
session's version and its `EncryptMethod` (98) must be 0 (None); it must carry
`MsgSeqNum` (34) **in the standard header** (a body-only 34 is treated as
missing, exactly as for the CompIDs); then identity (49/56, plus 50/57 when
configured), after which the acceptor claims its single admission slot;
then `SendingTime` (52), and the `from_admin` authentication hook (where
`Username` (553) / `Password` (554) are inspected); then `HeartBtInt` (108) and
`ResetSeqNumFlag` (141); then `MsgSeqNum`. The differences from the initiator
are role-symmetric:

- **`HeartBtInt` (108).** The acceptor *adopts* the interval the initiator
  requested and echoes it back on its Logon reply, rather than proposing one.
  Because the value is counterparty-controlled and drives a `Duration` on the
  heartbeat clock, it is bounded at the handshake: a missing, non-numeric, or
  over-range 108 (above one day) fails the handshake with a Logout rather than
  being defaulted — a value near `u64::MAX` would otherwise overflow the clock's
  `interval + grace` and abort the process under `panic = "abort"`. `108 = 0`
  remains legal and is not specially handled today.
- **`ResetSeqNumFlag` (141).** The acceptor resets when the peer asks (`141=Y`,
  which must arrive under `MsgSeqNum = 1`) **or** when it is locally configured
  with `reset_on_logon`. Whichever drives the reset, both counters go to 1 and
  the reply Logon carries `141=Y` at its own `MsgSeqNum = 1`: a locally driven
  reset that acked without the flag would silently desync the peer.
- **Duplicate connections.** An `Acceptor` is one configured session, so it
  admits one live session at a time for its counterparty. A second concurrent
  Logon while a session is established is refused with a Logout ("session
  already active") rather than allowed to fork the session into two independent
  sequence streams; the slot frees when the live session closes.

A failure at any step sends a session Reject (reason 9 for identity, the
`SendingTime` reason for a clock problem) and/or a Logout, drives the typestate
through `reject_logon`, and drops the connection without ever reaching Active. A
gap in the inbound Logon completes the handshake and immediately issues a
`ResendRequest` (2). Once Active, the session runs the same reactor as the
initiator, so every inbound-frame rule below applies identically to both roles.

---

### Logout (MsgType = 5)

**Direction**: Bidirectional

**Purpose**: Gracefully terminate a FIX session.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "5" |
| 49 | SenderCompID | Sender identifier |
| 56 | TargetCompID | Target identifier |
| 34 | MsgSeqNum | Message sequence number |
| 52 | SendingTime | Timestamp |

**Optional Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 58 | Text | Logout reason |

**Server Behavior**:
1. Send Logout response
2. Wait for acknowledgment (optional)
3. Close TCP connection
4. Persist session state for recovery

---

### Heartbeat (MsgType = 0)

**Direction**: Bidirectional

**Purpose**: Maintain session connectivity and detect connection failures.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "0" |
| 49 | SenderCompID | Sender identifier |
| 56 | TargetCompID | Target identifier |
| 34 | MsgSeqNum | Message sequence number |
| 52 | SendingTime | Timestamp |

**Optional Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 112 | TestReqID | Echo of TestRequest ID |

**Server Behavior**:
1. Send Heartbeat at configured interval if no other messages sent
2. When responding to TestRequest, include TestReqID (tag 112)
3. Monitor for missing heartbeats from counterparty

**What IronFix implements today**

`ironfix-session::HeartbeatManager` owns the timing; `ironfix-engine`'s
reactor polls it on a 100 ms tick.

- **`HeartBtInt` = 0 means no heartbeating.** Zero is a legal negotiated
  interval and disables the mechanism outright: no Heartbeat is emitted, no
  TestRequest is sent, and the session is never timed out for silence.
  `should_send_heartbeat`, `should_send_test_request` and `is_timed_out` all
  return `false` for the life of such a session. It is *not* treated as a
  zero-length interval. Note the consequence the FIX spec implies: with
  `108=0` there is no heartbeat-driven liveness check at all, so a dead peer is
  only noticed when TCP notices.
- **The configured interval is whole seconds.** Tag 108 carries whole seconds,
  so a fractional `SessionConfig::heartbeat_interval` is refused at
  configuration time (`SessionConfigError::FractionalHeartbeatInterval`) rather
  than truncated: flooring 500 ms to `108=0` would negotiate *no heartbeating*
  while the local timers ran sub-second. The accepted range is 1 s to
  `MAX_HEARTBEAT_INTERVAL_SECS` (3600 s), plus the `108=0` case, which
  `SessionConfigBuilder::disable_heartbeats` asks for by name. `Initiator`
  re-checks the whole configuration before it dials, so a configuration
  assembled through the public fields cannot bypass this either.
- **Heartbeat due.** One interval with nothing sent. Any outbound message
  resets the timer, so a busy session emits no Heartbeats.
- **TestRequest due.** One interval plus a transmission grace with nothing
  received, and no TestRequest already outstanding.
- **Transmission grace.** Derived from the interval, not configured:
  `HeartBtInt / 5` (the 20% the QuickFIX family uses), floored at 250 ms. The
  floor exists because the proportional allowance collapses into scheduling
  noise for sub-second intervals. It is readable as
  `HeartbeatManager::test_request_grace()`.

---

### Test Request (MsgType = 1)

**Direction**: Bidirectional

**Purpose**: Request a Heartbeat from counterparty to verify connectivity.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "1" |
| 49 | SenderCompID | Sender identifier |
| 56 | TargetCompID | Target identifier |
| 34 | MsgSeqNum | Message sequence number |
| 52 | SendingTime | Timestamp |
| 112 | TestReqID | Unique request identifier |

**Server Behavior**:
1. Send TestRequest if no message received within HeartBtInt + tolerance
2. Expect Heartbeat response with matching TestReqID
3. If no response, consider session disconnected

**What IronFix implements today — what counts as "a response"**

Item 3 above is the only guidance the FIX session spec gives, and it does not
define what a response is. IronFix defines it explicitly, because the choice is
the difference between disconnecting a dead peer and disconnecting a live one:

> **Any inbound message the session accepts stops the timeout countdown.** A
> Heartbeat echoing the outstanding `TestReqID` (112) is the positive
> confirmation; anything else — an ExecutionReport, a Heartbeat without tag
> 112, a Heartbeat with the wrong ID — clears the pending TestRequest as
> *superseded by traffic*.

"Accepted" means the frame decoded, carried a `MsgSeqNum` (34), and passed the
CompID identity check; foreign traffic never touches the heartbeat clock. A
sequence gap does *not* disqualify a message here: a gapped frame is still
proof the peer is transmitting.

Rationale. A peer that is sending us messages is alive, whatever it did with
our `TestReqID`, and the FIX liveness question is about the connection, not
about protocol pedantry. Real venues answer a TestRequest with a Heartbeat that
omits tag 112, or let that Heartbeat be reordered behind a burst of application
traffic; keying the timeout on the echo alone tears down demonstrably healthy
sessions. This is also what the QuickFIX family does — it resets its
test-request counter on any successfully verified inbound message.

Consequence, stated plainly: a peer that streams traffic but never answers a
TestRequest is never disconnected by this engine. That is deliberate. The
timeout exists to detect a peer that has stopped talking, and such a peer is
still talking. The engine distinguishes the two cases in its logs
(`ironfix_session::TestRequestOutcome`), so a counterparty that never echoes
`TestReqID` is observable without being disconnected.

The countdown itself is: `is_timed_out()` is true only when a TestRequest was
sent and **nothing at all** arrived in the interval that followed.

---

### Resend Request (MsgType = 2)

**Direction**: Bidirectional

**Purpose**: Request retransmission of messages within a sequence range.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "2" |
| 7 | BeginSeqNo | First sequence number to resend |
| 16 | EndSeqNo | Last sequence number (0 = infinity) |

**Server Behavior**:
1. Retrieve messages from message store
2. Resend with PossDupFlag = Y
3. Use SequenceReset-GapFill for admin messages
4. Maintain original SendingTime with OrigSendingTime

**What IronFix implements today**

All four mandate items are implemented, **provided a message store is attached**
with `Initiator::with_store(Arc<dyn MessageStore>)`. Every sequenced outbound
frame is then filed in the store under its `MsgSeqNum`, before it goes on the
wire, and is available to be replayed. Without a store there is nothing to
replay and the engine falls back to answering the whole range with one gap fill
(see "Without a store" below).

*Validation, identical in both modes:*

- `BeginSeqNo` (7) absent or unparseable → session Reject, reason 1 (required
  tag missing), `RefTagID` = 7. There is deliberately **no** default value;
  defaulting a missing BeginSeqNo to 1 silently answers a request the
  counterparty never made.
- `EndSeqNo` (16) absent or unparseable → session Reject, reason 1,
  `RefTagID` = 16.
- `BeginSeqNo` = 0, or at or beyond our next outbound sequence number → session
  Reject, reason 5 (value incorrect), `RefTagID` = 7. We cannot resend what we
  have not sent.
- `EndSeqNo` below `BeginSeqNo` (and not 0) → session Reject, reason 5,
  `RefTagID` = 16.

*The reply range.* The reply always covers exactly
`BeginSeqNo .. NewSeqNo`, where `NewSeqNo` = min(EndSeqNo + 1, next outbound
sequence), or the next outbound sequence when `EndSeqNo` = 0 (infinity). A
bounded request therefore never advances the counterparty past what it asked
for, and every sequence number inside the range is accounted for by either a
replayed message or a gap fill — never skipped.

*What is replayed.* An **application** message that is present in the store and
can be rebuilt is resent with:

- its **original `MsgSeqNum` (34)** — a resend re-occupies the number it was
  first sent under, and allocates no new one;
- its original body, field for field, in its original order;
- `PossDupFlag` (43) = Y (mandate item 2);
- `OrigSendingTime` (122) = the `SendingTime` (52) recorded on the original
  frame, while 52 is restamped with the time of this retransmission (mandate
  item 4);
- `BodyLength` (9) and `CheckSum` (10) recomputed, since 43 and 122 change both.

*What is gap-filled.* Everything else in the range is covered by
`SequenceReset`-GapFill messages interleaved between the replayed messages,
each carrying `MsgSeqNum` = the first number it covers, `GapFillFlag` (123) = Y,
`NewSeqNo` (36) = the first number it does **not** cover, and `PossDupFlag`
(43) = Y with `OrigSendingTime` (122). Specifically:

- **administrative messages** in the range (mandate item 3) — a stale Heartbeat
  or Logon says nothing true about the session now;
- **sequence numbers the store never held or has evicted**;
- **stored frames that cannot be rebuilt** — a frame that does not decode, or
  that carries no `SendingTime` (52) to copy into `OrigSendingTime` and so
  cannot be resent conformantly;
- **the whole range**, if the store itself returns an error.

A gap fill allocates no sender sequence number either: it occupies the range it
replaces. So answering a resend never moves the session's own outbound
numbering, whatever mix of replay and fill the reply turns out to be.

A GapFill's "original" messages are administrative filler that was never sent,
so there is no recorded original sending time for it and 122 is stamped with
the same value as `SendingTime` (52) — the FIX handling for an unavailable
OrigSendingTime. That substitution applies to gap fills only; a genuine replay
always carries the real original time.

**Without a store**, mandate items 1, 2 and 4 cannot be satisfied — the engine
has nothing to replay from — and the whole requested range is answered with a
single `SequenceReset`-GapFill with `MsgSeqNum` = BeginSeqNo and `NewSeqNo` as
above. A counterparty asking for business traffic then receives a gap fill
rather than the traffic.

**Restart caveat.** `MemoryStore` is the only `MessageStore` implementation and
is not persistent: it holds messages and sequence numbers in process memory
only. Replay therefore works within a live process, but no message and no
sequence number survives a restart. A durable store is separate, tracked work.

**Store write order.** Every store call (`store`, `file_outbound`,
`set_next_sender_seq`, `set_next_target_seq`, `reset`, `refresh`, `get_page`)
is asynchronous and can fail, and the session awaits each one inline: a slow
store delays the session for as long as the call takes. Each call is bounded
by the store timeout (`Initiator::with_store_timeout`, default: the write
timeout), and an overrun is `StoreError::Timeout`. With a store attached the
engine writes in this order, in the Logon handshake and in the session reactor
alike, through one shared step (`doc/adr/0005-fallible-store-writes.md`):

1. *Outbound:* the frame is filed under its `MsgSeqNum` N and N+1 persisted as
   the next sender number, in one `file_outbound` call; then N is spent in
   memory, and only then are the frame's bytes written to the socket. Filing
   comes first, so a crash between the two writes leaves frame N and counter
   N: N is reused for a message the peer never saw, and the filed frame is
   replaced (`store` has replace semantics). A crash after both writes leaves
   frame N and counter N+1: N is never reused, and a resend of N replays the
   filed frame, whether or not its bytes reached the peer.
2. *Inbound:* when a message M is accepted in sequence, M+1 is persisted as the
   next target number before M is acted on and before the in-memory
   expectation moves: before an administrative message is processed, before
   an in-sequence `SequenceReset`-GapFill reaches `from_admin`, and before an
   application message is handed to the application. An accepted `NewSeqNo`
   (36) is persisted before the expectation moves to it.
3. *Exceptions:* the initiator's Logon ack reaches `from_admin` before its
   number is persisted (the ack is validated, including `from_admin` and its
   `ResetSeqNumFlag` (141), before its number is consumed; the number is
   persisted before the session goes Active and before `on_logon`), and a
   `SequenceReset` in Reset mode reaches `from_admin` before its `NewSeqNo` is
   persisted (it has no place in the sequence).
4. A counter is written only when its value changed. The handshake hands the
   reactor the record of what it wrote, so an idle session makes no counter
   write at all.
5. A Logon ack with `ResetSeqNumFlag` (141) = Y, when our Logon did not ask for
   a reset, resets the store (under the policy) and persists next sender 2 and
   next target 2 before `on_logon` runs, so a connect abandoned from there on
   cannot leave the previous stream for a later session to replay.

*Inbound delivery is at most once.* Because M+1 is durable before M is handed
over, a crash after that write and before `from_app` has finished with M
loses M to the application: on restart the engine expects M+1 and never asks
the counterparty for M again. The window is every message waiting in the
application queue, up to its capacity (1024 by default), plus the one
`from_app` is handling. The same messages are lost without a crash when the
session closes and the dispatcher does not finish its queue within 5 s: it is
then aborted, and the engine logs at error level the `MsgSeqNum` range it had
handed over and `from_app` had not finished. Under `CloseSession` a message
whose target write failed is never handed over; under `Continue` it is.

The engine does not detect or report, after a restart, the inbound messages
lost across a crash, so the requirement of #89 that a lost message be reported
is not met for inbound traffic. Reporting needs a completion signal from the
dispatcher, a durable application watermark (a new defaulted `MessageStore`
method) and a typed report at restart; at-least-once delivery additionally
needs an inbound journal or redelivery through a `ResendRequest`. Both are
tracked in #105.

**Store failure policy.** `Initiator::with_store_failure_policy` chooses what a
failed write (or one that overran the store timeout) means:

- `StoreFailurePolicy::Continue` (the default, and the behaviour before writes
  were fallible): log a warning without frame bytes and carry on as if the
  write had succeeded. The frame is written anyway and the message acted on
  anyway; a frame that could not be filed is gap-filled if it is ever
  requested again. This gives **no** crash guarantee: after a failed write, a
  crash can leave the store behind what the counterparty has seen.
- `StoreFailurePolicy::CloseSession`: fail closed. A frame whose filing or
  sender-counter write fails is not written (the counterparty reads no bytes
  for it), an inbound message whose target write fails is not acted on (a
  TestRequest gets no Heartbeat, an application message never reaches
  `from_app`), and the session closes, not gracefully, without a Logout, which
  could not be filed either. A Logout reply to the counterparty that the store
  refuses makes the close non-graceful, so `reset_on_logout` does not run.
  The failure is logged at error level. During the handshake,
  `Initiator::connect` returns `EngineError::Store` and the frame concerned is
  never written; a store failure while a Logon ack is being refused stops the
  refusal and is the error `connect` returns. A `with_initial_sequences`
  sender seed below the store's next sender number is refused with
  `EngineError::InitialSequenceBelowStore`.

Whatever the policy, the reset for a `ResetSeqNumFlag` Logon, the refresh
that recovers the counters, and a reset owed by the previous session fail the
connect with `EngineError::Store`. A reset is owed when the close-time reset of
`reset_on_logout` / `reset_on_disconnect` fails: no counter is then written,
and the `Initiator` resets the store on its next `connect` before anything
else. The record lives in the `Initiator`, so a process restart forgets it.

The `Acceptor` attaches no store yet, so the policy has nothing to act on
there. Not done: inbound frames are not filed (only the target counter is
kept).

**Outbound `EndSeqNo` sentinel — a version caveat.** When the engine detects an
inbound gap it requests retransmission with `EndSeqNo` (16) = 0, the open-ended
"to infinity" sentinel. That `16=0` convention was introduced in FIX 4.2; FIX
4.0 and 4.1 instead use `999999` for an open-ended request and read `16=0` as an
empty range. IronFix emits `16=0` for **every** configured version — the
sentinel is not selected by `BeginString` — so an open-ended resend request sent
to a strict FIX 4.0/4.1 counterparty is not framed the way that version expects.
This is recorded here as a **known limitation** rather than fixed with a
version-aware sentinel; selecting the sentinel by `BeginString` is small,
isolated follow-up work. (The inbound direction is unaffected in practice: a
`16=999999` request from such a peer resolves to the same range as `16=0`,
because the GapFill's `NewSeqNo` is capped at our next outbound sequence
regardless.)

**Outbound resend recovery is bounded.** When *this* engine detects an inbound
gap it sends a `ResendRequest` and waits. A peer that never satisfies it — while
its other traffic keeps the heartbeat clock alive — used to hold the session
open indefinitely, the inbound expectation pinned and nothing reaching the
application. The request is now retried every
`SessionConfig::resend_timeout` (default **10 seconds**), up to
`SessionConfig::resend_attempt_limit` attempts (default **3**, counting the
first). Once the attempts are spent the session is logged out with a `Text` (58)
naming the stalled sequence number, turning a silent stall into an observable,
graceful close. Any in-sequence message clears the outstanding request, so the
timer measures a gap that is making no progress at all, not a slow replay.

---

### Reject (MsgType = 3)

**Direction**: Bidirectional

**Purpose**: Reject a malformed or invalid message at the session level.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "3" |
| 45 | RefSeqNum | Sequence number of rejected message |

**Optional Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 371 | RefTagID | Tag number causing rejection |
| 372 | RefMsgType | Message type of rejected message |
| 373 | SessionRejectReason | Reason code |
| 58 | Text | Human-readable explanation |

**Session Reject Reasons**:
| Code | Description |
|------|-------------|
| 0 | Invalid tag number |
| 1 | Required tag missing |
| 2 | Tag not defined for message type |
| 3 | Undefined tag |
| 4 | Tag specified without value |
| 5 | Value incorrect for tag |
| 6 | Incorrect data format |
| 7 | Decryption problem |
| 8 | Signature problem |
| 9 | CompID problem |
| 10 | SendingTime accuracy problem |
| 11 | Invalid MsgType |
| 99 | Other |

**Reason codes IronFix emits today**

| Code | Emitted when |
|---|---|
| 1 | `SequenceReset` without `NewSeqNo` (36); `ResendRequest` without `BeginSeqNo` (7) or `EndSeqNo` (16); inbound `SendingTime` (52) absent |
| 5 | `SequenceReset` whose `NewSeqNo` would rewind or fails to advance; `ResendRequest` whose range is outside what we have sent |
| 6 | `SequenceReset` with a malformed `GapFillFlag` (123) that is present but neither `Y` nor `N`; inbound `SendingTime` (52) present but not a `UTCTimestamp` |
| 9 | Inbound `SenderCompID`/`TargetCompID` (and `SenderSubID`/`TargetSubID` when configured) do not match the session configuration, **or** appear outside the standard header |
| 10 | Inbound `SendingTime` (52) differs from the local clock by more than the configured tolerance |
| any | Whatever an `Application::from_admin` / `from_app` implementation returns in its `RejectReason` |

**Reason 10 (SendingTime accuracy) is implemented.** Every inbound frame's
`SendingTime` (52) is compared against the local clock, immediately after the
CompID check and before the heartbeat clock is refreshed. The tolerance is the
typed `SessionConfig::sending_time_tolerance`, defaulting to **120 seconds** in
either direction — the interval FIX engines have converged on (QuickFIX's
`MaxLatency`): far more slack than an NTP-synchronised host ever needs, yet
tight enough that an unsynchronised clock is caught within days. A value outside
the window is rejected with reason 10 (`RefTagID` = 52), an absent field with
reason 1, and an unparseable one with reason 6; in each case the session is then
logged out, because a wrong clock is systemic rather than per-message. Setting
the tolerance to `Duration::ZERO` disables the check — including the presence and
format checks — for a peer with a known clock problem.

---

### Sequence Reset (MsgType = 4)

**Direction**: Bidirectional

**Purpose**: Reset sequence numbers or fill gaps in message sequence.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "4" |
| 36 | NewSeqNo | New sequence number |

**Optional Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 123 | GapFillFlag | Y = Gap Fill, N = Reset |

**Server Behavior**:
- **Gap Fill Mode**: Skip sequence numbers for admin messages during resend
- **Reset Mode**: Force sequence number reset (use with caution)

**What IronFix implements today**

The two modes are **not** interchangeable, and `GapFillFlag` (123) is what
selects between them. A Gap Fill is an ordinary sequenced message: it occupies
its own `MsgSeqNum` and is validated like any other inbound message. **Reset
mode is the only mode allowed to ignore `MsgSeqNum`.** Applying a gapped Gap
Fill as though it were a Reset jumps the inbound expectation past messages that
were never received and will now never be requested — a silent, permanent loss
of (potentially) Execution Reports.

**Not bounded:** `NewSeqNo` is accepted at any magnitude, so a peer can jump the
inbound expectation arbitrarily far ahead — up to `u64::MAX`, after which the
next message exhausts the counter and the session is torn down with a typed
error. There is no principled ceiling in the specification to check against, and
the failure mode is a clean teardown rather than silent corruption, so no
arbitrary limit is invented here.

`ironfix-engine` handles an inbound `SequenceReset` as follows:

| Condition | Behavior |
|---|---|
| `123` present but neither `Y` nor `N` (malformed GapFillFlag) | session Reject, reason 6 (incorrect data format), `RefTagID` = 123; the mode is not guessed from an uninterpretable field. An **absent** 123 stays Reset mode |
| `123=Y`, MsgSeqNum gapped | ResendRequest for the missing range; `NewSeqNo` **not** applied. Classified **before** `from_admin`, so a rejecting application cannot suppress the required ResendRequest |
| `123=Y`, MsgSeqNum too low with `PossDupFlag` = Y | dropped as an already-applied duplicate, **without** reaching `from_admin` |
| `123=Y`, MsgSeqNum too low without `PossDupFlag` | Logout and disconnect, as for any other too-low message |
| `from_admin` rejects an in-sequence fill or a Reset | session Reject with the application's reason; `NewSeqNo` not applied. An in-sequence GapFill still **consumes** its own MsgSeqNum — a rejected fill left unconsumed would wedge the inbound stream — while a Reset consumes nothing |
| `NewSeqNo` (36) absent or unparseable | session Reject, reason 1, `RefTagID` = 36. An in-sequence GapFill (`123=Y`) still **consumes** its own MsgSeqNum, since it occupies that number even though its NewSeqNo is unusable; Reset mode (`123=N` or absent) consumes nothing. A gapped or too-low fill never reaches this branch — it is classified first (rows above) |
| `123=Y`, MsgSeqNum in sequence, `NewSeqNo` ≤ MsgSeqNum | session Reject, reason 5, `RefTagID` = 36; the fill message itself is consumed so the session does not deadlock on that number |
| `123=Y`, MsgSeqNum in sequence, `NewSeqNo` > MsgSeqNum | applied: inbound expectation becomes `NewSeqNo` |
| `123=N` or 123 absent (Reset mode), `NewSeqNo` < expected | session Reject, reason 5, `RefTagID` = 36; not applied |
| `123=N` or 123 absent (Reset mode), `NewSeqNo` ≥ expected | applied regardless of MsgSeqNum. An outstanding ResendRequest is only cleared when the reset actually advances the expectation; a reset landing on the number already expected changes nothing, and clearing for it would let a peer replay it to trigger a fresh ResendRequest every round |

---

## Pre-Trade Messages

### Security Definition Request (MsgType = c)

**Purpose**: Request security/instrument definitions.

**Key Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 320 | SecurityReqID | Unique request identifier |
| 321 | SecurityRequestType | Type of request |
| 55 | Symbol | Security symbol (optional) |
| 48 | SecurityID | Security identifier (optional) |

**Server Response**: Security Definition (MsgType = d)

---

### Security List Request (MsgType = x)

**Purpose**: Request a list of available securities.

**Key Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 320 | SecurityReqID | Unique request identifier |
| 559 | SecurityListRequestType | Type of list request |

**Server Response**: Security List (MsgType = y)

---

## Trade Messages

### New Order Single (MsgType = D)

**Direction**: Client → Server

**Purpose**: Submit a new order.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "D" |
| 11 | ClOrdID | Client order identifier |
| 21 | HandlInst | Handling instructions |
| 55 | Symbol | Security symbol |
| 54 | Side | Buy (1) / Sell (2) |
| 60 | TransactTime | Order creation time |
| 38 | OrderQty | Order quantity |
| 40 | OrdType | Order type |

**Optional Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 44 | Price | Limit price |
| 99 | StopPx | Stop price |
| 59 | TimeInForce | Order duration |
| 18 | ExecInst | Execution instructions |
| 1 | Account | Account identifier |

**Order Types (Tag 40)**:
| Value | Description |
|-------|-------------|
| 1 | Market |
| 2 | Limit |
| 3 | Stop |
| 4 | Stop Limit |
| P | Pegged |

**Side (Tag 54)**:
| Value | Description |
|-------|-------------|
| 1 | Buy |
| 2 | Sell |
| 5 | Sell Short |
| 6 | Sell Short Exempt |

**Server Response**: Execution Report (MsgType = 8)

---

### Order Cancel Request (MsgType = F)

**Direction**: Client → Server

**Purpose**: Request cancellation of an existing order.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "F" |
| 11 | ClOrdID | New client order ID |
| 41 | OrigClOrdID | Original client order ID |
| 55 | Symbol | Security symbol |
| 54 | Side | Order side |
| 60 | TransactTime | Request time |

**Server Response**: 
- Execution Report with ExecType = 4 (Canceled)
- Order Cancel Reject (MsgType = 9) if rejection

---

### Order Cancel/Replace Request (MsgType = G)

**Direction**: Client → Server

**Purpose**: Modify an existing order (price, quantity, etc.).

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "G" |
| 11 | ClOrdID | New client order ID |
| 41 | OrigClOrdID | Original client order ID |
| 55 | Symbol | Security symbol |
| 54 | Side | Order side |
| 60 | TransactTime | Request time |
| 38 | OrderQty | New quantity |
| 40 | OrdType | Order type |

**Optional Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 44 | Price | New limit price |

**Server Response**:
- Execution Report with ExecType = 5 (Replaced)
- Order Cancel Reject if rejection

---

### Order Status Request (MsgType = H)

**Direction**: Client → Server

**Purpose**: Request current status of an order.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "H" |
| 11 | ClOrdID | Client order ID |
| 55 | Symbol | Security symbol |
| 54 | Side | Order side |

**Server Response**: Execution Report with current order status

---

### Execution Report (MsgType = 8)

**Direction**: Server → Client

**Purpose**: Report order status, fills, and rejections.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "8" |
| 37 | OrderID | Server order identifier |
| 11 | ClOrdID | Client order identifier |
| 17 | ExecID | Execution identifier |
| 150 | ExecType | Execution type |
| 39 | OrdStatus | Order status |
| 55 | Symbol | Security symbol |
| 54 | Side | Order side |
| 151 | LeavesQty | Remaining quantity |
| 14 | CumQty | Cumulative filled quantity |
| 6 | AvgPx | Average fill price |

**Execution Types (Tag 150)**:
| Value | Description |
|-------|-------------|
| 0 | New |
| 1 | Partial Fill |
| 2 | Fill |
| 3 | Done for Day |
| 4 | Canceled |
| 5 | Replaced |
| 6 | Pending Cancel |
| 7 | Stopped |
| 8 | Rejected |
| 9 | Suspended |
| A | Pending New |
| C | Expired |
| D | Restated |
| E | Pending Replace |
| F | Trade |
| H | Trade Cancel |
| I | Trade Correct |

**Order Status (Tag 39)**:
| Value | Description |
|-------|-------------|
| 0 | New |
| 1 | Partially Filled |
| 2 | Filled |
| 3 | Done for Day |
| 4 | Canceled |
| 5 | Replaced |
| 6 | Pending Cancel |
| 7 | Stopped |
| 8 | Rejected |
| 9 | Suspended |
| A | Pending New |
| B | Calculated |
| C | Expired |
| D | Accepted for Bidding |
| E | Pending Replace |

---

### Order Cancel Reject (MsgType = 9)

**Direction**: Server → Client

**Purpose**: Reject a cancel or cancel/replace request.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "9" |
| 37 | OrderID | Server order ID |
| 11 | ClOrdID | Client order ID of request |
| 41 | OrigClOrdID | Original order ID |
| 39 | OrdStatus | Current order status |
| 434 | CxlRejResponseTo | 1 = Cancel, 2 = Cancel/Replace |
| 102 | CxlRejReason | Rejection reason code |

---

### Order Mass Cancel Request (MsgType = q)

**Direction**: Client → Server

**Purpose**: Cancel multiple orders at once.

**Key Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 530 | MassCancelRequestType | Scope of cancellation |
| 11 | ClOrdID | Request identifier |

**Server Response**: Order Mass Cancel Report (MsgType = r)

---

## Post-Trade Messages

### Allocation Instruction (MsgType = J)

**Purpose**: Allocate trades to sub-accounts.

**Key Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 70 | AllocID | Allocation identifier |
| 71 | AllocTransType | Transaction type |
| 626 | AllocType | Allocation type |

---

### Confirmation (MsgType = AK)

**Purpose**: Confirm trade allocation.

**Key Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 664 | ConfirmID | Confirmation identifier |
| 666 | ConfirmStatus | Status |

---

### Position Report (MsgType = AP)

**Purpose**: Report current positions.

**Key Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 721 | PosMaintRptID | Report identifier |
| 710 | PosReqID | Request ID (if requested) |
| 55 | Symbol | Security symbol |
| 704 | LongQty | Long position quantity |
| 705 | ShortQty | Short position quantity |

---

## Market Data Messages

### Market Data Request (MsgType = V)

**Direction**: Client → Server

**Purpose**: Subscribe to or request market data.

**Required Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 35 | MsgType | "V" |
| 262 | MDReqID | Request identifier |
| 263 | SubscriptionRequestType | 0=Snapshot, 1=Subscribe, 2=Unsubscribe |
| 264 | MarketDepth | Depth of book (0 = full) |
| 267 | NoMDEntryTypes | Number of entry types |
| 269 | MDEntryType | Entry type (repeating) |
| 146 | NoRelatedSym | Number of symbols |
| 55 | Symbol | Security symbol (repeating) |

**MD Entry Types (Tag 269)**:
| Value | Description |
|-------|-------------|
| 0 | Bid |
| 1 | Offer |
| 2 | Trade |
| 3 | Index Value |
| 4 | Opening Price |
| 5 | Closing Price |
| 6 | Settlement Price |
| 7 | Trading Session High |
| 8 | Trading Session Low |
| 9 | Trading Session VWAP |
| A | Imbalance |
| B | Trade Volume |
| C | Open Interest |

---

### Market Data Snapshot/Full Refresh (MsgType = W)

**Direction**: Server → Client

**Purpose**: Provide complete market data snapshot.

**Key Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 262 | MDReqID | Request identifier |
| 55 | Symbol | Security symbol |
| 268 | NoMDEntries | Number of entries |
| 269 | MDEntryType | Entry type |
| 270 | MDEntryPx | Price |
| 271 | MDEntrySize | Size |

---

### Market Data Incremental Refresh (MsgType = X)

**Direction**: Server → Client

**Purpose**: Provide incremental market data updates.

**Key Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 262 | MDReqID | Request identifier |
| 268 | NoMDEntries | Number of entries |
| 279 | MDUpdateAction | 0=New, 1=Change, 2=Delete |
| 269 | MDEntryType | Entry type |
| 270 | MDEntryPx | Price |
| 271 | MDEntrySize | Size |

---

### Market Data Request Reject (MsgType = Y)

**Direction**: Server → Client

**Purpose**: Reject a market data request.

**Key Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 262 | MDReqID | Request identifier |
| 281 | MDReqRejReason | Rejection reason |
| 58 | Text | Explanation |

---

## Error Handling

### Garbled Messages and Transport Resynchronization

**Scope**: `ironfix-transport::FixCodec`, the framing layer that turns a byte
stream into complete FIX frames, and what `ironfix-engine` does with a garbled
frame, during the Logon handshake and in session. It does not describe
session-level rejection. The design is recorded in
`doc/adr/0004-garbled-frame-recovery.md`.

**FIX convention**: a *garbled* message is one whose framing cannot be
trusted: BeginString (8) is not the first field, BodyLength (9) is not the
second or does not agree with the frame layout, MsgType (35) is not the third,
or CheckSum (10) is absent, malformed, wrong or not last. It is **ignored**.
The receiver does **not** send a Reject, does **not** send a ResendRequest for
it, and does **not** increment the inbound MsgSeqNum, because the sequence
number of a garbled message cannot be trusted either. Recovery is left to the
normal gap-detection path on the next well-formed message.

**What IronFix implements**

*Recoverable versus fatal.* `CodecError::is_recoverable()` splits the codec's
errors in two. Every framing error the convention calls garbled is recoverable:
`InvalidBeginString`, `MissingBodyLength`, `InvalidBodyLength`,
`HeaderTooLong`, `InvalidTrailer`, `InvalidChecksumFormat` and
`ChecksumMismatch`. Two errors are fatal: `MessageTooLarge`, a frame whose
declared size exceeds `max_message_size` (skipping it would mean buffering it,
or trusting its attacker-chosen length to size the discard), and `Io`. A frame
that frames but whose header fails to decode (MsgType not third, BodyLength
invalid) is garbled at the decode level; the codec cannot see it, and the
engine treats it like a frame the codec skipped. The verdict follows where
decoding failed: a malformed field among the first three (a third field
`abc=0`) is garbled even though the decoder reports an invalid tag. A frame
whose header decodes but whose body does not (an invalid tag, a bad data
length), or whose MsgType value is unacceptable, is not garbled; see *The
engine* below.

*Skipping inside the codec.* `tokio_util::Framed` ends its stream after any
decoder error, so a garbled frame cannot be skipped by the caller of a
`Framed` stream. `FixCodec::with_garbled_recovery(true)` moves the skip into the
codec. A recoverable error is never returned. The codec discards the garbled
bytes, counts the skip, and keeps going in the same `decode` call, returning the
next valid frame if it is already buffered. It must not return `Ok(None)` with a
whole frame buffered, because `Framed` would then wait for the next socket read
before asking again. `FixCodec::take_garbled_count()` reports and resets the
count. Recovery is off by default, so another `FixCodec` user keeps one error
per garbled frame.

*Bytes consumed per error.* "Resync" means discard up to the next candidate
frame start. Without recovery the candidate is the `8` of a `<SOH>8` pair. With
recovery it is a complete header opening after a plausible boundary (see the
first rationale point). When there is no candidate the whole buffer is
discarded, except a tail that may still become one: a trailing `<SOH>` without
recovery, a partial header opening with it.

| `CodecError` | Without recovery | With recovery |
|---|---|---|
| `InvalidBeginString` | resync, error returned | resync, skipped |
| `InvalidTrailer` | resync, error returned | resync, skipped |
| `InvalidChecksumFormat`, `ChecksumMismatch` | the whole declared frame, error returned | the whole declared frame, skipped |
| `MissingBodyLength`, `InvalidBodyLength`, `HeaderTooLong` | none, error returned | resync, skipped |
| `MessageTooLarge`, `Io` | none, error returned | none, error returned |

Rationale:

- After `InvalidBeginString` the stream position is unknown, so the only safe
  anchor is a byte sequence that can legally start a frame. A bare `8=` is not
  one, because it occurs inside ordinary tags such as `18=` and `58=`. Without
  recovery the anchor is therefore `<SOH>8`. The cost is that a well-formed
  frame arriving straight after garbage is discarded with it, unless the garbage
  ends on an SOH. With recovery that anchor is not safe either: `<SOH>8` also
  matches tags 80 to 89 and 800 up, so a resync through one skipped frame would
  stop at each and count it again. Recovery mode therefore accepts a candidate
  only when the bytes open a real header (`8=`, an accepted BeginString, SOH,
  `9=`) **and** the byte before it is SOH, the start of the buffer, or neither
  an ASCII digit nor `=`. Accepted means the FIX family (`FIX.4.0` to
  `FIX.4.4`, `FIXT.1.1`) by default, and only the session's own BeginString
  with `FixCodec::with_begin_string`, which both engines set; every real frame
  of the session carries it. The second condition excludes a tag (`448=FIX…`)
  and an opening at the very start of a field value (`96=8=FIX…`,
  `213=8=FIX…`), and nothing else: an embedded frame further inside a value is
  the residual risk listed under Known limits. The byte before is remembered
  across a read boundary when a resync empties the buffer, so an embedded frame
  that arrives at offset 0 of the next read is still recognised as part of the
  same garbled span. The shape is checked inside the scan, so a false start
  costs about a dozen byte comparisons and is not counted. The scan stops at the
  first candidate, so its cost is linear in the bytes it discards, and it never
  allocates.
- After a checksum error the trailer literal is exactly where BodyLength said it
  would be, so the declared boundary is corroborated by the frame's own
  structure. Consuming that many bytes keeps a stream of otherwise well-formed
  frames aligned, and counts one skip per garbled frame.
- A missing trailer is the opposite case. Nothing corroborates BodyLength, and
  trusting it to size the discard hands an attacker a lever: a short header
  declaring a large body would consume every well-formed frame that merely
  follows it. So this case resyncs instead.
- Before the header is complete no boundary exists at all, so the codec keeps
  the bytes and bounds them instead. The header region `8=…<SOH>9=…<SOH>` is
  capped at 64 bytes and the whole frame at `max_message_size` (1 MiB by
  default). Exceeding either is an error, never a request for more data, which
  is what stops a peer from growing the read buffer without bound. With
  recovery the header ceiling is checked first, so whether malformed header
  bytes are skipped never depends on how many good frames happen to be buffered
  behind them.
- Without recovery, `MissingBodyLength`, `InvalidBodyLength` and `HeaderTooLong`
  consume nothing, because no frame boundary can be inferred and the error is
  the caller's to act on. With recovery the codec is about to skip the frame and
  must make progress, so it resyncs. Every skip consumes at least one byte, so
  one `decode` call is bounded by the buffered bytes, and skipping itself never
  allocates.

*The engine.* Both `Initiator` and `Acceptor` frame with recovery on, anchored
on the session's own BeginString, during the Logon handshake and in the session
reactor, and both also treat a frame whose header frames but does not decode as
garbled. A message whose header decodes but whose body does not is **not**
garbled: in session it is dropped with a fixed-label warning, consumes no
`MsgSeqNum` and does not count toward the bound, as before; during the
handshake it is skipped under the same deadline, because it cannot be read as
a Logon either. A garbled frame:

- **consumes no MsgSeqNum.** The next valid frame with a higher `MsgSeqNum` is a
  gap and gets the usual `ResendRequest`, and the gap is filled by the normal
  resend or `SequenceReset`-GapFill path;
- **is not proof of life.** It does not refresh the heartbeat clock or clear a
  pending TestRequest, so a peer that sends nothing but garbage is timed out
  exactly like a silent one;
- **is logged without its bytes**, as a count and a static cause with the
  session id, because a garbled Logon can still carry `Password` (554);
- **does not end the handshake.** A garbled Logon (acceptor) or Logon ack
  (initiator) of either kind is skipped and the wait continues against the same
  `logon_timeout`. A counterparty that never sends an intact one ends in
  `EngineError::LogonTimeout`, and the skips are reported when the wait ends so
  the timeout is diagnosable.

The reactor reads the codec's count before handling each inbound frame and on
every 100 ms tick. The tick is what catches a garbled frame with nothing valid
behind it. The read is one synchronous integer read; only a non-zero count goes
further, and only a configured bound reads the clock.

*The optional bound.* `SessionConfig::garbled_frame_limit` takes a
`GarbledFrameLimit` of `max` frames within a sliding `window` (`max` a
`NonZeroU32` of at most 1024, `window` non-zero and at most 24 hours; set it
with `SessionConfigBuilder::garbled_frame_limit(max, window)` or
`SessionConfig::with_garbled_frame_limit`). Frames garbled at the framing level
and at the header-decode level count alike; a malformed body does not count. When `max` garbled frames arrive within
`window`, the session sends a Logout with the reason in `Text` (58) and closes
without waiting for the acknowledgement; a session already waiting on its own
Logout closes without a second one. The default is no bound: the
specification sets none, and the heartbeat already ends a session whose peer
sends only garbage. The bound covers a link that garbles intermittently while
its valid traffic keeps the session alive, and `HeartBtInt = 0`. Frames skipped
during the handshake are reported but not counted against it.

*Fatal errors* still close the session directly. For a frame above
`max_message_size` an Active session first sends a Logout with `Text` (58)
"message too large", since the write side still works; an I/O error closes it
without one.

**Known limits**

The first five only show with recovery on: without it the first garbled frame
ends a `Framed` stream.

- A real frame whose BodyLength is corrupted *upward* holds every later frame
  in the buffer until the declared span has arrived (at most
  `max_message_size`), because only then can its trailer be checked and
  rejected. The frames behind it are kept, not discarded, but delayed; on a
  quiet session the heartbeat and TestRequest timeout can fire first.
- Residual phantom-frame risk: inside a frame that is already garbled badly
  enough to need a resync through it, a data-field value that contains a
  complete header opening of the session's own BeginString preceded by any byte
  other than an ASCII digit or `=` (a `|`, a space, `MSG:`, `<![CDATA[`, an
  SOH) is a resync candidate. If a well-formed frame follows, it is handed up.
  Only an opening at the very start of the value (`96=8=FIX…`) or after a digit
  is excluded. An embedded frame of another FIX version is excluded too, since
  both engines restrict anchors to their own BeginString.
- A frame whose opening follows an ASCII digit or `=` (for example after
  garbage that ends in a digit) is passed over by the resync, and its gap is
  recovered by `ResendRequest`. A stream whose BeginString is not accepted
  still frames, but a resync does not land on it.
- Garbage that happens to spell a header whose declared span ends exactly on a
  later frame's `<SOH>10=NNN<SOH>` has a corroborated boundary, and the
  checksum error consumes that frame with it. The gap is then recovered by
  `ResendRequest` like any other.
- The skip count is one per garbled frame, with two exceptions that can only
  make the optional bound trip earlier: garbage delivered in separate reads
  counts once per read, and a partial header opening kept at the end of one
  read counts once more if the next read shows it was garbage.
- A framed message whose body does not decode is dropped without a Reject,
  because no `MsgSeqNum` can be read to reference. A peer that answers the
  resulting `ResendRequest` by resending the same bytes has them dropped again,
  so that gap can stall until the bounded resend gives up and logs out.
- After the "message too large" Logout, and after the garbled-limit Logout,
  the socket is dropped while the peer's input may still be arriving. Closing a
  socket with unread input can make the kernel send RST, and the peer may then
  lose the Logout. This holds until a graceful drain exists.

---

### Business Message Reject (MsgType = j)

**Purpose**: Reject an application-level message.

**Key Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 45 | RefSeqNum | Rejected message sequence |
| 372 | RefMsgType | Rejected message type |
| 380 | BusinessRejectReason | Reason code |
| 58 | Text | Explanation |

**Business Reject Reasons**:
| Code | Description |
|------|-------------|
| 0 | Other |
| 1 | Unknown ID |
| 2 | Unknown Security |
| 3 | Unsupported Message Type |
| 4 | Application not available |
| 5 | Conditionally required field missing |
| 6 | Not authorized |
| 7 | DeliverTo firm not available |
| 18 | Invalid price increment |

---

## Implementation Priority

### Phase 1: Core Session Layer (Required)
- [x] Logon / Logout
- [x] Heartbeat / Test Request — the interval is negotiated (bounded, since it
  is counterparty-controlled), a Logon ack that omits the required `HeartBtInt`
  (108) or carries a non-numeric value fails the handshake rather than
  establishing a session on the local interval, `HeartBtInt = 0` disables
  heartbeating as FIX intends, heartbeats and TestRequests fire at the interval
  plus a derived grace, and the silent-peer timeout stops the moment any
  accepted inbound message arrives. See "Heartbeat" and "Test Request" above for
  the negotiation bound, the grace rule, and the definition of "a response".
  This covers **both roles**: `Initiator` and `Acceptor` hand the socket to the
  same session reactor once Logon completes. Of the example servers only
  `fix44_server` runs on the `Acceptor`; the other `fixNN_server` examples
  hand-roll their accept loop and do their own heartbeating.
- [x] Reject
- [x] Sequence Reset
- [x] Resend Request — inbound requests are validated, and with a
  `MessageStore` attached (`Initiator::with_store`) the stored application
  messages in the range are replayed with `PossDupFlag` (43) = Y and the
  original `SendingTime` in `OrigSendingTime` (122), with administrative
  messages and unavailable sequence numbers gap-filled. Three limits are worth
  stating: the store is **opt-in**, and without one the whole range is still
  answered with a single gap fill; the store can be attached to the
  **initiator only**, since the `Acceptor` attaches none and so answers every
  resend with gap fill; and `MemoryStore` is not persistent, so nothing is
  replayable after a restart. Store writes are ordered (frame and next sender
  number before the bytes, next target number before an inbound message is
  acted on) and fallible, under a `StoreFailurePolicy` that either warns and
  continues or fails closed; inbound delivery is at most once across a crash.
  An *outbound* request the peer never
  satisfies is also bounded — retried every `SessionConfig::resend_timeout` and
  then escalated to Logout after `SessionConfig::max_resend_requests` attempts,
  rather than stalling the session forever. See "Resend Request" above.

### Phase 2: Order Entry (High Priority)
- [ ] New Order Single
- [ ] Execution Report
- [ ] Order Cancel Request
- [ ] Order Cancel/Replace Request
- [ ] Order Cancel Reject
- [ ] Order Status Request

### Phase 3: Market Data (Medium Priority)
- [ ] Market Data Request
- [ ] Market Data Snapshot
- [ ] Market Data Incremental Refresh
- [ ] Market Data Request Reject

### Phase 4: Extended Order Types (Lower Priority)
- [ ] Order Mass Cancel Request/Report
- [ ] Order Mass Status Request
- [ ] List Orders (New Order List)

### Phase 5: Post-Trade (Lower Priority)
- [ ] Allocation Instruction
- [ ] Confirmation
- [ ] Position Report

---

## Version-Specific Considerations

### FIX 4.0 - 4.2
- No DefaultApplVerID
- Limited execution report fields
- Tag 20 (ExecTransType) required in Execution Reports

### FIX 4.3 - 4.4
- Enhanced execution report
- More order types supported
- Tag 150 (ExecType) replaces Tag 20

### FIX 5.0 / FIXT.1.1
- Separate transport and application layers
- DefaultApplVerID (tag 1137) in Logon
- ApplVerID (tag 1128) in application messages
- Enhanced market data support

**What IronFix implements today.** A session configured with a 5.0 version
string is carried as a FIXT.1.1 session on the wire: `BeginString` (8) is
always `FIXT.1.1` and the application version travels in 1137 / 1128. Putting
`FIX.5.0` in tag 8 is rejected outright by conforming acceptors, so the
configured string is a *session* version, not a literal BeginString.

| `SessionConfig::begin_string` | Tag 8 | 1137 (Logon) / 1128 (app messages) |
|---|---|---|
| `FIX.4.0` … `FIX.4.4` | verbatim | not sent |
| `FIX.5.0` | `FIXT.1.1` | `7` |
| `FIX.5.0SP1` | `FIXT.1.1` | `8` |
| `FIX.5.0SP2` | `FIXT.1.1` | `9` |
| `FIXT.1.1` | — | session refused |
| anything else | — | session refused |

`FIXT.1.1` on its own names the transport version and no application version,
so the engine cannot supply `DefaultApplVerID` (1137) — a **required** field of
the FIXT.1.1 Logon. Rather than send a Logon missing a required field, or
default the application version to a guess, `Initiator::connect` refuses the
session with `EngineError::UnsupportedVersion` before dialling; configure
`FIX.5.0`, `FIX.5.0SP1` or `FIX.5.0SP2` instead. An unrecognised version string
is refused the same way, rather than being passed through onto the wire.

This table exists exactly once in the workspace, as `ironfix_core::FixVersion`
(`ironfix-core/src/version.rs`). `ironfix-dictionary` re-exports it as
`schema::Version` and `ironfix-engine` resolves the configured string to it in
`wire::wire_version`, so the two consumers cannot drift — which matters because
`ironfix-engine` does not and must not depend on `ironfix-dictionary`. Note the
distinction the type draws: `FixVersion::as_str` is the version's own name
(`FIX.5.0SP2`), `FixVersion::begin_string` is what goes in tag 8 (`FIXT.1.1`).

**Not implemented for 5.0:** no application-version-driven validation of any
kind. The `ApplVerID` values are stamped, not enforced, and the engine never
consults a dictionary.

**Dictionary side, standalone.** `ironfix-dictionary` embeds the QuickFIX
FIXT 1.1 transport dictionary (`Dictionary::fixt11()`) and the FIX 5.0 SP2
application dictionary (`Dictionary::fix50sp2()`), alongside FIX 4.2 and FIX
4.4. `SessionDictionary` composes the FIXT 1.1 transport with an application
dictionary of any version FIXT.1.1 carries (FIX 4.0 through 5.0 SP2, ApplVerID
2 to 9), and `Validator::for_session` validates a message against the pair
with QuickFIX-like semantics: `BeginString` (8) must be `FIXT.1.1`; an admin
message the transport defines (Logon, Heartbeat, ...) is checked against FIXT
1.1 alone, so a Logon must carry `DefaultApplVerID` (1137); an application
message takes its header and trailer from FIXT 1.1 and its body from the
application dictionary. Neither the engine nor the codec calls it. See
ADR-0010.

Where it differs from QuickFIX:

- **No `ApplVerID`-based selection.** QuickFIX picks the application dictionary
  per message from `ApplVerID` (1128), falling back to the counterparty's
  `DefaultApplVerID` (1137). Here the pair names one application dictionary
  and neither tag is consulted.
- **Admin routing by `msgcat`.** Any message type the transport defines with
  `msgcat='admin'` is admin, so `XMLnonFIX` (35=n) is validated against FIXT
  1.1. QuickFIX's `Message::isAdminMsgType` covers only `0`, `A` and `1` to `5`,
  so it treats 35=n as an application message.
- **All errors, no ordering check.** Every error is returned rather than the
  first, and header/body/trailer field order is not enforced.
- **`DefaultApplVerID` (1137) values are not checked.** `FIXT11.xml` declares it
  as a STRING with no enumeration, so any value passes.

**Known upstream deviation.** FIXT 1.1 defines the Logon `MsgTypeGrp` component
as the `NoMsgTypes` (384) group (`RefMsgType` 372, `MsgDirection` 385,
`RefApplVerID` 1130, `RefApplExtID` 1406, `RefCstmApplVerID` 1131,
`DefaultVerIndicator` 1410). The vendored QuickFIX `FIXT11.xml` defines
`MsgTypeGrp` with no members and does not define 384 or 385, so a Logon carrying
the group is reported as invalid against `Dictionary::fixt11()`. The file stays
unpatched; to accept the group, load a FIXT 1.1 dictionary that defines it with
`Dictionary::from_quickfix_xml` and compose that instead.

---

## References

- [FIX Protocol Specification](https://www.fixtrading.org/standards/)
- [FIX 4.4 Specification](https://www.fixtrading.org/standards/fix-4-4/)
- [FIX 5.0 SP2 Specification](https://www.fixtrading.org/standards/fix-5-0-sp-2/)
- [FIXT 1.1 Transport](https://www.fixtrading.org/standards/fixt-1-1/)
