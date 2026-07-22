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
| 10 | CheckSum | Message checksum |

**Optional Fields**:
| Tag | Field Name | Description |
|-----|------------|-------------|
| 141 | ResetSeqNumFlag | Reset sequence numbers (Y/N) |
| 553 | Username | Authentication username |
| 554 | Password | Authentication password |
| 1137 | DefaultApplVerID | Default application version (FIX 5.0+) |

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

**Scope**: `ironfix-transport::FixCodec` — the framing layer that turns a byte
stream into complete FIX frames. This subsection is the codec's contract; it
does not describe session-level rejection.

**FIX convention**: a *garbled* message — one whose framing cannot be trusted:
BeginString (8) is not the first field, BodyLength (9) is missing or does not
agree with the frame layout, or CheckSum (10) is absent or malformed — is
**ignored**. The receiver does **not** send a Reject, does **not** send a
ResendRequest for it, and does **not** increment the inbound MsgSeqNum, because
the sequence number of a garbled message cannot be trusted either. Recovery is
left to the normal gap-detection path on the next well-formed message.

**What IronFix implements today**

The codec detects garbling and, for the errors where a frame boundary can be
inferred, decides how many bytes to discard so that a caller which keeps reading
can make progress. The remaining variants consume nothing and a caller must
treat them as fatal. Consumption per error:

| `CodecError` | Bytes consumed from the read buffer |
|---|---|
| `InvalidBeginString` | up to and including the `<SOH>` of the next `<SOH>8` pair, so the buffer restarts at the `8` (the whole buffer when there is no such pair, minus a trailing `<SOH>` that may still be the first half of one) |
| `InvalidTrailer` | the same resync as above — the trailer is absent from the offsets BodyLength implies, so BodyLength is not corroborated and its declared length is not trusted to bound the discard |
| `InvalidChecksumFormat`, `ChecksumMismatch` | the whole declared frame (`BodyLength` + header + 7-byte trailer) |
| `MissingBodyLength`, `InvalidBodyLength`, `HeaderTooLong`, `MessageTooLarge`, `Io` | none — no frame boundary can be inferred |

Rationale for the two policies:

- After `InvalidBeginString` the stream position is unknown, so the only safe
  anchor is the next byte sequence that can legally start a frame: an SOH
  followed by `8`. Scanning to it is bounded by the buffer length and never
  allocates.
- After a checksum error the trailer literal is exactly where BodyLength said it
  would be, so the declared boundary is corroborated by the frame's own
  structure: consuming `BodyLength`-worth of bytes keeps a stream of otherwise
  well-formed frames aligned.
- A missing trailer is the opposite case — nothing corroborates BodyLength, and
  trusting it to size the discard hands an attacker a lever. A short header
  declaring a large body would otherwise consume every well-formed frame that
  merely follows it (tens of thousands, at the default ceiling) and report the
  loss as a single error. So this case resyncs instead.
- Recovery is best-effort, not lossless: because the anchor is `<SOH>8` rather
  than a bare `8=` (which occurs inside ordinary tags such as `18=` and `58=`),
  a well-formed frame arriving immediately after garbage is normally discarded
  with it, unless the garbage happens to end on an SOH. Recovery resumes at the
  frame after that one.
- Before the header is complete no boundary exists at all, so the codec keeps
  the bytes and bounds them instead: the header region `8=…<SOH>9=…<SOH>` is
  capped at 64 bytes and the whole frame at `max_message_size` (1 MiB by
  default). Exceeding either is an error, never a request for more data — this
  is what stops a peer from growing the read buffer without bound.

**What IronFix does not implement**

- **The MsgSeqNum half of the convention is the session layer's
  responsibility and is not implemented.** The codec has no access to session
  state and never touches sequence numbers; nothing in `ironfix-session` or
  `ironfix-engine` currently distinguishes "garbled, do not count" from any
  other failure.
- **The resynchronization above is not reachable from the engine as built, and
  not only because `ironfix-engine::Initiator` treats every codec error as
  fatal.** `tokio_util::Framed` terminates its stream after *any* decoder error:
  it latches an internal error flag and returns `None` on the next poll, so the
  well-formed frame the resync had just aligned onto is discarded along with the
  stream. No way of writing the caller changes that. Honouring the convention
  from the engine would require either the codec to report garbling as
  `Ok(None)` while skipping the bad bytes internally — which is itself a change
  to framing semantics — or the engine to drive `Decoder::decode` by hand
  instead of using `Framed`. The consumption policy above is therefore
  observable today only by a caller that drives the codec directly, which is how
  it is tested.

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
  Note this covers the **initiator** only: there is no Acceptor in
  `ironfix-engine`, so the server-side examples do their own heartbeating.
- [x] Reject
- [x] Sequence Reset
- [x] Resend Request — inbound requests are validated, and with a
  `MessageStore` attached (`Initiator::with_store`) the stored application
  messages in the range are replayed with `PossDupFlag` (43) = Y and the
  original `SendingTime` in `OrigSendingTime` (122), with administrative
  messages and unavailable sequence numbers gap-filled. Two limits are worth
  stating: the store is **opt-in**, and without one the whole range is still
  answered with a single gap fill; and `MemoryStore` is not persistent, so
  nothing is replayable after a restart. An *outbound* request the peer never
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

---

## References

- [FIX Protocol Specification](https://www.fixtrading.org/standards/)
- [FIX 4.4 Specification](https://www.fixtrading.org/standards/fix-4-4/)
- [FIX 5.0 SP2 Specification](https://www.fixtrading.org/standards/fix-5-0-sp-2/)
- [FIXT 1.1 Transport](https://www.fixtrading.org/standards/fixt-1-1/)
