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
| 789 | NextExpectedMsgSeqNum | FIX.4.4 and FIXT.1.1 only: the next `MsgSeqNum` the sender expects to receive. Sent and honoured only with `SessionConfig::send_next_expected_msg_seq_num`; see "NextExpectedMsgSeqNum (789), both roles" below |
| 553 | Username | Authentication username |
| 554 | Password | Authentication password |
| 384 | NoMsgTypes | FIXT.1.1 only: repeating group of supported message types (372, 385, 1130, 1406, 1131, 1410). The embedded QuickFIX `FIXT11.xml` does not define it; see "Dictionary side, standalone" below |

**Server Behavior**:
1. Validate SenderCompID and TargetCompID (a server fronting several
   counterparties first selects the session by them; see "Routing a Logon to
   its session" below)
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
   inbound `TargetSubID` (57) and `SenderSubID` (50) are checked the same way,
   and so, when `sender_location_id` / `target_location_id` are configured,
   are inbound `TargetLocationID` (143) and `SenderLocationID` (142).
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
5. **`DefaultApplVerID` (1137), FIX 5.0 only.** On a FIXT.1.1 session an ack
   that carries 1137 must carry it once, naming an application version the
   session accepts: its own configured version or one in
   `SessionConfig::allowed_appl_versions` (`SessionConfig::accepts_appl_version`).
   A value that names no version (anything but the `ApplVerID` codes `2` to
   `9`) or names one outside that set (every FIX 4.x code does) draws a
   session Reject with reason 18 (Invalid/Unsupported Application
   Version), a repeated 1137 one with reason 13, `RefTagID` = 1137 in both
   cases, followed by a Logout; the handshake fails with
   `EngineError::ApplVersion`. By default an ack **without** 1137 is
   accepted: the initiator checks the acknowledgement's 1137 only when present
   (issue #67), although FIXT.1.1 makes it required on every Logon. Strict mode
   (`SessionConfig::require_ack_default_appl_ver_id`, default `false`) requires
   it: an ack without 1137 then draws a Reject with reason 1 (required tag
   missing), `RefTagID` = 1137, and a Logout. A FIX 4.x ack is not checked.
6. **`HeartBtInt` (108).** 108 is a *required* field of the Logon, so an ack
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
7. **`ResetSeqNumFlag` (141).** `141=Y` on the ack must arrive under
   `MsgSeqNum = 1` — the reset and the number carrying it have to describe the
   same stream — and a peer that sends any other number fails the handshake
   rather than having one half of the contradiction guessed for it. It is
   honored **before** MsgSeqNum is validated — otherwise the ack's
   `34=1` reads as fatally too low against continuity-seeded counters. The
   inbound counter is reset to 1 and the outbound counter set to 2, under the
   reset rule below. With continuity-seeded counters the Logon went out under
   its seeded number and nothing numbered 1 was ever sent; QuickFIX/J's two
   halves disagree here — its initiator would set 1, its acceptor 2 — and
   IronFix matches the acceptor. The mismatch self-heals: the peer sees a gap
   at 2, requests a resend of 1, and receives a GapFill that resynchronises it.
8. **`NextExpectedMsgSeqNum` (789)**, only with
   `SessionConfig::send_next_expected_msg_seq_num` set. Decided after the
   "`141=Y` under `MsgSeqNum = 1`" check of step 7 and before its reset reaches
   the store, against the counters that reset sets (our Logon is then 1 and 2
   goes next), so a refused ack never resets the store. A 789 above the next
   number we send fails the handshake with a Logout alone; a 789 that is 0, not
   a number or repeated with a session Reject (reason 5, 6 or 13, `RefTagID` =
   789) and a Logout; both as `EngineError::NextExpectedMsgSeqNum`. A 789 below
   our Logon makes the session resend the missed range once Active. When our
   Logon declared a reset (`reset_on_logon`, or one an earlier session owes)
   and the ack does not echo `141=Y`, the reset rule (step 9) takes the ack as
   message 1 whatever its number, and its 789 may describe the discarded
   stream: a well-formed value is ignored; a malformed one is still refused.
   See "NextExpectedMsgSeqNum (789), both roles" below.
9. **`MsgSeqNum` (34).** The header 34 is read positionally, *before* identity —
   the same standard-header contract step 2 applies to the CompIDs — so a 34 that
   occurs only after the body is treated as missing and fails the handshake. The
   value read there is then validated at this step: too low fails the handshake,
   and a gap completes the handshake and immediately issues a ResendRequest,
   unless both sides declared `NextExpectedMsgSeqNum` (789): the ack is then
   held instead (see "NextExpectedMsgSeqNum (789), both roles").
   After a reset the initiator declared (`reset_on_logon`, or a reset an
   earlier session owes), the ack is not validated: under the reset rule it is
   the acceptor's message 1 whatever its number, and 2 is expected next.

**The reset rule, both roles.** In a Logon exchange that resets the sequence,
each side's Logon or acknowledgement is message 1 of its new stream: its next
sender number is 2, and the next number it expects from the other side is 2.
The side that drives the reset therefore takes the other side's Logon or ack as
message 1 whatever `MsgSeqNum` it carries, and opens no gap for the numbers of
the old stream; a message that declares `141=Y` itself must still carry 1.

The same identity and `SendingTime` checks (steps 2 and 3) run on every inbound
frame once the session is established; there a failure produces the Reject and
Logout and then tears the session down. An unsatisfied ResendRequest from step 9
does not stall forever — it is retried and then escalated to Logout; see "Resend
Request".

Outbound `ResetSeqNumFlag` is driven by `SessionConfig::reset_on_logon`, and by a
store reset an earlier session owes.

**What IronFix implements today (acceptor side)**

`ironfix-engine::Acceptor` is the mirror of the above. It waits for the inbound
Logon (bounded by `SessionConfig::logon_timeout`) and validates it in this
order — it must decode and be a Logon; its `BeginString` (8) must match this
session's version and its `EncryptMethod` (98) must be 0 (None); it must carry
`MsgSeqNum` (34) **in the standard header** (a body-only 34 is treated as
missing, exactly as for the CompIDs); then identity (49/56, plus 50/57 and
142/143 when configured), after which the acceptor claims its single admission
slot;
then `SendingTime` (52), and the `from_admin` authentication hook (where
`Username` (553) / `Password` (554) are inspected); then, on a FIX 5.0 session,
`DefaultApplVerID` (1137); then a `ResetSeqNumFlag` (141) Logon must carry
`MsgSeqNum = 1`; then `HeartBtInt` (108); then, with
`send_next_expected_msg_seq_num` set, `NextExpectedMsgSeqNum` (789) is read
and, on a Logon that asked for the reset, must be 1; only then is an attached
store reset or refreshed; then 789 is compared with the next number the
acceptor sends; then `MsgSeqNum` is validated and the acknowledgement sent.
The differences from the initiator are role-symmetric:

- **`DefaultApplVerID` (1137).** 1137 is a required field of the FIXT.1.1
  Logon, so on a FIX 5.0 session the acceptor requires it, exactly once, naming
  an application version the session accepts (its own configured version or
  one in `SessionConfig::allowed_appl_versions`). A Logon without it, with it
  twice, with a value that names no version, or naming a version outside the
  set (a FIX 4.x code `2` to `6` always is) is refused with a Logout whose `Text` says
  why and lists the accepted versions (`EngineError::ApplVersion`). The check
  runs after `from_admin`, so the refusal belongs to the authenticated group
  below. The acknowledgement declares the acceptor's own version in 1137
  whatever the peer declared. A FIX 4.x Logon is not checked.

- **`HeartBtInt` (108).** The acceptor *adopts* the interval the initiator
  requested and echoes it back on its Logon reply, rather than proposing one.
  Because the value is counterparty-controlled and drives a `Duration` on the
  heartbeat clock, it is bounded at the handshake: a missing, non-numeric, or
  over-range 108 (above one day) fails the handshake with a Logout rather than
  being defaulted — a value near `u64::MAX` would otherwise overflow the clock's
  `interval + grace` and abort the process under `panic = "abort"`. `108 = 0`
  remains legal and is not specially handled today.
- **`ResetSeqNumFlag` (141).** The acceptor resets when the peer asks (`141=Y`,
  which must arrive under `MsgSeqNum = 1`), when it is locally configured with
  `reset_on_logon`, or when an earlier session left a store reset owed.
  Whichever drives the reset, both counters go to 1 and the reply Logon carries
  `141=Y` at its own `MsgSeqNum = 1`: a locally driven reset that acked without
  the flag would silently desync the peer. Under the reset rule the peer's
  Logon is its message 1 whatever its number: a Logon at `34=N`, `N > 1`,
  without 141 opens no gap and draws no `ResendRequest`, and 2 is expected
  next.
- **`NextExpectedMsgSeqNum` (789)**, only with
  `send_next_expected_msg_seq_num` set. A malformed 789 (0, not a number,
  repeated), a `141=Y` Logon whose 789 is not 1, and a 789 above the number
  the acknowledgement would take are refused with a Logout alone
  (`EngineError::NextExpectedMsgSeqNum`), the first two before the store is
  touched, the last before the Logon's `MsgSeqNum` is consumed. A 789 below the
  acknowledgement's number makes the session resend the missed range once
  Active. When the acceptor drives a reset the peer did not ask for, the peer's
  789 describes the discarded stream and is ignored. The acknowledgement
  declares the acceptor's own next expected number.
- **Duplicate connections.** An `Acceptor` is one configured session, so it
  admits one live session at a time for its counterparty. A second concurrent
  Logon while a session is established is refused **without a reply**, with or
  without a store, rather than allowed to fork the session into two
  independent sequence streams: the live session owns the stream, and nothing
  the newcomer could be sent belongs to it. The slot is held until the live
  session's task has ended, past its close-time store writes, the drain of its
  application queue (up to 5 s) and `on_logout`; a Logon arriving before then
  is refused the same way. While the session is live, a Logon refused before
  the slot is reached (wrong `BeginString`, `EncryptMethod` or CompIDs) gets no
  reply either, with or without a store: a refusal would be numbered from the
  provisional counters, a stream the live session owns.
- **The message store.** With `Acceptor::with_store`, the store is touched only
  once the peer is authenticated (after identity, admission, `SendingTime` and
  `from_admin`), and reset only for a Logon that passes every check (for `141=Y`,
  `reset_on_logon`, or a reset an earlier session owes; one `reset_to` call,
  before the acknowledgement is filed, failing closed whatever the policy).
  Otherwise the session starts from the store's refreshed counters, or the
  `with_initial_sequences` seed. A refused `141=Y` Logon therefore never clears
  the outbound journal. Every frame the acceptor sends to its counterparty is
  filed, and the Logon's number is persisted before the session goes Active.

A refused Logon drives the typestate through `reject_logon` and the connection
is dropped without ever reaching Active. What is sent first depends on who sent
the Logon:

1. **An unauthenticated peer** — wrong `BeginString` or `EncryptMethod`, wrong
   CompIDs, a `SendingTime` out of tolerance, or credentials that `from_admin`
   refuses. Matching CompIDs authenticate nobody: they are caller-supplied.
   With a store attached, nothing is sent and the store is not touched: a frame
   could neither be filed (that would let a peer that knows the CompIDs but not
   the credentials append to the outbound journal and advance the session's
   counters) nor be numbered without reusing, with different content, a number
   the session's stream already holds. Without a store, a Reject (reason 9 for
   identity, 10 for the clock) and/or a Logout, numbered from the seed or 1, as
   before, unless the session is live on another connection: then a refusal
   for the version, encryption or CompIDs gets nothing either.
2. **A Logon without a valid `MsgSeqNum`** — absent, outside the header, or 0
   (which names no message): nothing, in either mode.
3. **A duplicate Logon** — nothing, in either mode (above).
4. **An authenticated peer** (`from_admin` accepted it) — refused by its
   `DefaultApplVerID` (FIX 5.0), by a `141=Y` Logon not numbered 1, by its
   `HeartBtInt`, by its `NextExpectedMsgSeqNum` (789, when used), or by a
   `MsgSeqNum` too low: a
   Logout saying why, sent like every session frame, numbered from the store's
   refreshed counters (or the seed), never from a reset, and filed when a store
   is attached.

A gap in the inbound Logon completes the handshake and immediately issues a
`ResendRequest` (2), unless both sides declared `NextExpectedMsgSeqNum` (789):
the Logon is then held instead (below). Once Active, the session runs the same reactor as the
initiator, so every inbound-frame rule below applies identically to both roles.

**NextExpectedMsgSeqNum (789), both roles**

FIX.4.4 and FIXT.1.1 define `NextExpectedMsgSeqNum` (789) on the Logon: the
next `MsgSeqNum` the sender expects to receive, so each side learns at Logon
which of its messages the other missed, and can tell a counterparty that
claims to expect a number never sent. IronFix uses it only when
`SessionConfig::send_next_expected_msg_seq_num` is set (default `false`), and
then in both directions; with it unset no 789 is sent and a counterparty's is
ignored. Setting it on a session below FIX.4.4 (FIX.4.0 to FIX.4.3, which do
not define the field) is `SessionConfigError::NextExpectedMsgSeqNumUnsupported`,
reported by the builder, by `SessionConfig::validate` and by both engines
(`EngineError::Config`) before a connection is taken or dialled
(`doc/adr/0021-next-expected-msg-seq-num.md`).

**789 is bilateral: enable it on both sides.** Engines differ on what they do
with it. QuickFIX/C++ acts on an inbound 789 whatever its own setting says,
and when it declared 789 itself it holds a gapped Logon and sends no
`ResendRequest` for the gap, with no resend timer. Such a counterparty logging
on to an IronFix session with the flag off declares 789, gets none back, and
with its defaults never asks for the gap at all: it sends no request for a
number at or above the start of the range it recorded
(`SendRedundantResendRequests` defaults to false), the range clears only when
an in-order message at or above its end arrives, which cannot happen while the
gap is open, and the gapped traffic does not count as proof of life. The
session wedges until its heartbeat timeout disconnects it, and on reconnect its
789 opens the same gap again: a reconnect loop
(`doc/adr/0021-next-expected-msg-seq-num.md`). The other way round, against
QuickFIX/C++ with its own flag off (it sends no 789 but acts on ours), IronFix
requests the gap at once, and that request crosses the retransmit QuickFIX/C++
sends for our 789: a harmless double replay, whose second copy is dropped as a
possible duplicate.

*What is declared.* The session's own next expected inbound `MsgSeqNum`,
placed after `ResetSeqNumFlag` (141) and before `DefaultApplVerID` (1137):

| Logon | 789 |
|---|---|
| Initiator Logon | the next number expected from the acceptor (the seeded target counter) |
| Initiator Logon with `141=Y` | 1: the acknowledgement of a reset is message 1 |
| Acceptor acknowledgement, the Logon in sequence | the Logon's `MsgSeqNum` + 1 |
| Acceptor acknowledgement with `141=Y` | 2: the Logon it answers is message 1 of the new stream |
| Acceptor acknowledgement, the Logon gapped | the first missing number: a gapped Logon is not consumed at the handshake (it is held or requested, below) |

*What the counterparty's 789 does.* It is compared with the `MsgSeqNum` of the
session's own Logon (initiator) or acknowledgement (acceptor) and with the next
number the session sends, both taken after any reset of the exchange. It never
moves a counter.

| Counterparty's 789 | Result |
|---|---|
| above the next number the session sends | the counterparty claims messages never sent: Logout with a `Text` saying so, no `on_logon`, `EngineError::NextExpectedMsgSeqNum` |
| below the session's own Logon or acknowledgement | once Active, the session resends exactly 789 up to, **not including**, its own Logon, as the answer to a `ResendRequest` for that range (see "Resend Request") |
| 0, not a number (a sign included), above `u64::MAX`, or repeated | refused without a panic: a Logout (the initiator first sends a session Reject, reason 5, 6 or 13, `RefTagID` = 789) and `EngineError::NextExpectedMsgSeqNum` |
| from the session's own Logon up to the next number it sends | nothing to resend |

The resend is queued as the session reactor opens, right after the
`ResendRequest` for a gap the Logon exchange found, if one was requested, and
written like the answer to any `ResendRequest`: one frame per pass of the
reactor loop, between inbound reads, ahead of any live application message
(see "Resend Request").

*A gapped Logon or acknowledgement, held.* 789 is the Logon sender's built-in
`ResendRequest`: the counterparty that reads this session's 789 resends the
gap on its own, right after the Logon exchange. IronFix resends below its own
Logon; QuickFIX/C++ resends through it, gap-filling its Logon and replaying
any live messages its application sent from `onLogon`. So when this session
declared 789, the
counterparty's Logon or acknowledgement carries a well-formed 789 too, and it
arrives with a gap below it, the session does **not** send a `ResendRequest`,
which would cross that resend (QuickFIX/C++ behaves the same):

- The Logon is held: it was processed at the handshake, and only its
  `MsgSeqNum` is left to take. Once the inbound expectation reaches that
  number, the number plus one is persisted as the next target and the
  expectation moves past it, as for any inbound message; if a gap fill jumps
  past it instead (a counterparty that fills through its own Logon), the hold
  is dropped. Both resend shapes are absorbed: when a resend through the
  Logon reaches the Logon's number with an application message, the Logon is
  consumed there and the gap fill for it, arriving below the expectation with
  `PossDupFlag` = Y, is dropped as a possible duplicate.
- The gap is armed as recovery with nothing requested: a gapped frame arriving
  meanwhile sends no request either. When the gap makes no progress for
  `SessionConfig::resend_timeout` (no resend at all, or one that stalls
  partway), exactly one `ResendRequest` goes out, from the first missing
  number, also with `max_resend_requests` = 1; after that the usual retry and
  Logout rules apply.
- Nothing is requested when the held Logon is consumed, even if frames from
  beyond it arrived while it was held: a counterparty that resends through its
  Logon covers them, and a request would cross that resend. The recovery stays
  armed at the next number with a fresh clock, so frames nobody resends are
  requested once that gap has made no progress for the resend timeout.
- A real `ResendRequest` ends the hold: once one goes out (the fallback, or a
  later retry), the Logon is no longer consumed locally. The open-ended
  request covers the Logon's own number and its answer fills it, so that
  number arrives in sequence, together with any administrative message past
  the Logon that arrived during the hold.
- When two resends of the counterparty overlap (a late 789 resend that stops
  below its Logon, then an answer to the request whose gap fill starts lower
  and runs through the Logon), that fill is a possible duplicate below the
  expectation and is ignored, but the numbers it spans are re-requested at
  once (see "Sequence Reset"), so the recovery completes one round trip later
  rather than stalling.
- A counterparty whose Logon or acknowledgement declares no 789, or a session
  with the flag off, gets the immediate `ResendRequest` as before.

Between two IronFix engines with the flag on, a restarted side therefore gets
back what it missed with no `ResendRequest` either way, and the next live
message is delivered in sequence right after the resend.

**Routing a Logon to its session (several counterparties on one listener)**

An `Acceptor` is one configured session. `ironfix-engine::AcceptorRegistry`
holds one `Acceptor` per session (each with its own configuration, optional
store and settings; one application type for all), reads each inbound Logon
once and routes it before any session's handshake runs
(`doc/adr/0018-acceptor-registry.md`):

1. **Read.** The Logon is framed under the registry's own ceiling
   (`AcceptorRegistry::with_max_message_size`, default 64 KiB) with checksum
   validation always on (whatever the session's own setting) and
   garbled-frame recovery on (garbled frames are skipped, as on
   `Acceptor::serve`). Reading it and resolving its session share one
   deadline, the registry's logon timeout (`with_logon_timeout`, default
   10 s); expiry is `EngineError::LogonTimeout`. The first frame must be a
   Logon.
2. **Bound the identity.** `SenderCompID` (49) and `TargetCompID` (56), and
   `SenderSubID` (50), `TargetSubID` (57), `SenderLocationID` (142) and
   `TargetLocationID` (143) when present, are read from the **standard header**
   only (a body-only 49 or 56 is absent), must each occur there at most once
   (a repeated one is the "tag appears more than once" case,
   `SessionRejectReason` 13), and must each be 1 to 32 bytes of printable
   ASCII, the bound a configured CompID, sub ID or location ID obeys. Anything
   else is `EngineError::UnroutableLogon`, decided before any session or the
   lookup is consulted. Only these fields are ever logged, so `Password`
   (554), `NewPassword` (925) and `RawData` (96) never are.
3. **Match.** The key is the session's configured identity, reversed: the
   Logon's 49 is the session's `target_comp_id`, its 56 the session's
   `sender_comp_id`, and a sub or location ID the session configures must be
   carried with the reversed value; one it does not configure places no
   requirement. The routed session then checks the same fields on every
   inbound message (see the identity checks above), so a peer cannot be routed
   on one identity and send under another. `BeginString` (8) is not part of
   the key; the routed session checks it, and two sessions that differ only by
   version cannot share a registry. Registration refuses a session whose key
   overlaps one already registered (a Logon could match both), whose
   `SessionId` is already registered, or whose store another session uses, so
   a Logon matches at most one session and a store belongs to one session.
4. **Look up.** With no match, an optional `SessionLookup` is asked about the
   identity (never the Logon, so it never sees credentials). It returns the
   `Acceptor` that serves it (which must route that identity, overlap no
   session and share no store), refuses (`EngineError::UnknownSession`), or
   reports that it cannot decide (`LookupError`, surfaced as
   `EngineError::Lookup`). It is asked once per Logon whose identity matches
   no session, so an unauthenticated peer can make it run once per connection.
   An admitted session is **provisional** while its first handshake runs,
   because the lookup admits before `from_admin` authenticates anyone: if that
   handshake ends before `from_admin` accepts the Logon (a dropped `serve`
   included) and no other connection is routed to the session, it is evicted,
   losing nothing since its store was never touched. Once a handshake gets
   past `from_admin`, the session stays for the registry's lifetime, so its
   single admission slot and owed-reset record persist. `with_max_sessions`
   caps the lookup-admitted sessions held at once (`EngineError::SessionLimit`
   beyond it). Two lookups racing for one identity end with one `Acceptor`,
   and the second Logon is then refused as a duplicate.
5. **Hand over.** The routed `Acceptor` runs its handshake on the Logon
   exactly as `Acceptor::serve` does once a Logon has arrived: the checks
   above in the same order, with the same refusal groups. `on_create` fires
   for it at this point (not before the read, as on `serve`), the socket
   switches to the session's own codec settings, and a Logon above the
   session's `max_message_size` is refused as its codec would have refused it.

A Logon that cannot be routed (unroutable identity, unknown session, a lookup
that refuses, fails or does not answer in time, the session cap, a first frame
that is not a Logon) is closed **without a reply**, touches no store and runs no
`Application` callback: before routing there is no session whose stream could
number a reply, no store to file it in, and no configured identity to stamp on
it. These refusals are logged at debug level, since any peer can provoke them
at will; a lookup that fails or overruns, returns a session the registry
cannot hold, or meets the session cap is logged as a warning. A second Logon
for a session that is live gets no reply, even with a wrong `BeginString` or
`EncryptMethod`, while the live session continues. Capping the connections
whose Logon is still being read or routed is the consumer's job, in its accept
loop. Every session keeps its own sequence numbers, store and heartbeat.

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

All four mandate items are implemented in **both roles**, **provided a message
store is attached**: `Initiator::with_store(Arc<dyn MessageStore>)`,
`Acceptor::with_store(Arc<dyn MessageStore>)`, or `EngineBuilder::with_store`,
which both terminal methods honour. Every sequenced outbound frame, the Logon
and its acknowledgement included, is then filed in the store under its
`MsgSeqNum`, before it goes on the wire, and is available to be replayed. Both
roles run the same reactor, so the replay below is identical for them. Without
a store there is nothing to replay and the engine falls back to answering the
whole range with one gap fill (see "Without a store" below).

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
for (unless more than 64 requests were queued at once and it was merged with
a later one, below), and every sequence number inside the range is accounted
for by either a replayed message or a gap fill — never skipped.

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
- **the rest of the range**, if the store returns an error reading it, except
  `StoreError::Corrupted`: a store that finds its own records damaged cannot
  say which messages it still holds intact, so the engine closes the session
  instead of gap-filling them, and the counterparty asks again in the next
  session.

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

**How a resend is written.** A valid request is queued and answered by the
session reactor one frame per pass of its loop, reading the store a page at a
time; before each resend frame the reactor reads any frame the counterparty
has already sent, which then takes the normal inbound path. Two sides that
owe each other more than the socket buffers hold, and resend at once, keep
draining each other instead of both blocking on a full socket until the write
timeout. Nothing that takes a new number is written in the middle of a resend:
a new number inside the range being answered would leave a receiver that does
not queue gapped messages (IronFix itself, until #71) waiting for it. Until the
resend is done, live application messages (and a Logout the consumer asks for)
wait in the outbound queue; a Heartbeat answering a TestRequest, a session
Reject and the session's own `ResendRequest` for an inbound gap are held back
and written, in order, right after it (a held `ResendRequest` is built then,
from the gap as it stands, and skipped if the gap has closed); and no
Heartbeat or TestRequest is sent for idleness, since resend frames are
traffic. Only messages that end the session (its Logouts, and the Rejects
before them) are written at once, and past 1024 held messages a new one is
written at once too, so the hold stays bounded. A Logout from the counterparty
waits for the resend it is owed (FIX gives the remote end the chance to fill
any gap first): the reply goes out once the resend and the messages held
behind it are written, or when `SessionConfig::logout_timeout` runs out,
dropping the rest. A resend the counterparty asks for after this session's
own Logout is still answered. `Connection::send` waits for the whole resend
once the outbound queue is full. Requests are answered in the order they
arrive; past 64 queued, a new request is merged into the last one not yet
under way, widening it to cover both, so every number asked for is still
answered (a number neither asked for reaches the counterparty as a possible
duplicate).

**A resend asked for at Logon.** With
`SessionConfig::send_next_expected_msg_seq_num` set, a counterparty whose
`NextExpectedMsgSeqNum` (789) on its Logon or acknowledgement is below this
session's own Logon or acknowledgement gets, once the session is Active,
exactly the answer a `ResendRequest` with `BeginSeqNo` = 789 and `EndSeqNo` =
the number before that Logon would get: the same replay from the store, the
same gap fills, one gap fill without a store, and the same close when the store
reports itself corrupted. Nothing at or past the session's own Logon is resent.
See "NextExpectedMsgSeqNum (789), both roles" under "Logon".

**Across a restart.** `MemoryStore` holds messages and sequence numbers in
process memory only, so with it replay works within a live process and
nothing survives a restart. `FileStore` keeps the filed frames and both
counters in a journal file: a session started on a reopened `FileStore`
resumes from its counters, and a `ResendRequest` after the restart replays the
original frames. What survives depends on its `SyncPolicy`: every write that
returned `Ok` survives a process crash under every policy, and an OS crash or
power loss only under `SyncPolicy::EveryWrite` (the default), and only under
`StoreFailurePolicy::CloseSession` does a failed write keep its frame off the
wire. When it opens, `FileStore` cuts only what an interrupted write can leave
at the end of its journal (a cut record is never replayed); damage anywhere
else makes it refuse to open with `StoreError::Corrupted` until an operator
runs `FileStore::repair`, after which the session must reset its sequence
(`ResetSeqNumFlag` (141) = Y). A missing journal is an error unless the store
is configured to create it. These guarantees are stated for Unix
(`doc/adr/0006-file-store.md`).

**Store write order.** Every store call (`store`, `file_outbound`,
`set_next_sender_seq`, `set_next_target_seq`, `reset`, `reset_to`, `refresh`,
`get_page`)
is asynchronous and can fail, and the session awaits each one inline: a slow
store delays the session for as long as the call takes. Each call is bounded
by the store timeout (`with_store_timeout` on the `Initiator` or the
`Acceptor`, default: the write timeout), and an overrun is
`StoreError::Timeout`. With a store attached the engine writes in this order,
in both roles' Logon handshakes and in the session reactor alike, through one
shared step (`doc/adr/0005-fallible-store-writes.md`):

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
   a reset, resets the store and sets next sender 2 and next target 2 (one
   `reset_to` call) before `on_logon` runs, so a connect abandoned from there
   on cannot leave the previous stream for a later session to replay. If that
   fails, `connect` fails with `EngineError::Store` whatever the policy, and
   the reset is owed to the next connect (below).
6. A gap found in the Logon exchange is requested by the session reactor as
   its first act, so a failure to send that `ResendRequest` after `on_logon`
   closes the session through the normal close path (`on_logout`, the
   close-time reset, the last counter writes).

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

**Store failure policy.** `with_store_failure_policy` (on the `Initiator` or
the `Acceptor`) chooses what a failed write (or one that overran the store
timeout) means:

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

Whatever the policy, the resets and the refresh fail the connect with
`EngineError::Store`: the reset for a `ResetSeqNumFlag` Logon, the reset for
the counterparty's `ResetSeqNumFlag` on its Logon ack, a reset owed by an
earlier session, and the refresh that recovers the counters. Carrying on past
any of them runs one sequence stream over another. A reset is owed when the
close-time reset of `reset_on_logout` / `reset_on_disconnect` fails (no
counter is then written) or when the reset for the counterparty's
`ResetSeqNumFlag` fails. The `Initiator`'s next `connect` then resets the
store before anything else, and its Logon declares `ResetSeqNumFlag` (141) = Y
at `MsgSeqNum` 1, so the counterparty restarts the sequence with it; that
reset is paid once that Logon is acknowledged. On the `Acceptor` (whose
reset fails closed the same way for a session that resets), the next accepted
Logon resets the store and its acknowledgement declares `141=Y` at 1; that
reset is paid once that acknowledgement is sent. The record lives in the
engine, in memory, so a process restart forgets it whichever store is
attached; `FileStore` does not persist it. A crash after the counterparty
acknowledged a `ResetSeqNumFlag` reset and before the store made it durable
therefore restarts from the previous stream's counters; making the intent
durable is #111. For the same reason a store
must belong to exactly one engine instance; `FileStore` enforces this with a
lock file.

With a store attached, call `Initiator::connect` again only once the previous
session's `Connection::wait_closed` has returned: until then the closing
session still writes to the store and may record a reset owed to the next one.
The `Acceptor` enforces this itself: its admission slot is held until a
session's task has ended (past its close-time store writes, the drain of its
application queue and `on_logout`), so the next Logon cannot share the store
with a closing session; one that arrives before then is refused as a duplicate,
without a reply.

*Cancellation and timeouts.* Every reset is recorded as owed before it is
awaited and paid only once it has succeeded, so a connect dropped while a
reset is pending still leaves it owed. The record is kept by generation:
paying a reset settles what was owed before it started, never what was owed
after, so a store write that fails during the handshake paying an owed reset
(before or after the acknowledgement) still owes the next session a reset. A store write that overruns the store
timeout may still land later, and one that fails may have changed the store
before failing (the `MessageStore` contract cannot say otherwise), so either
leaves a reset owed, under both policies, and the next session starts with a
reset and `ResetSeqNumFlag` (141) = Y. This relies on
the store applying its mutations in call order even when a call is dropped,
which `MessageStore` now requires and `MemoryStore` and `FileStore` satisfy
(`FileStore` runs every call on its own writer thread, first in, first out,
and finishes a call it has started even if its future is dropped); a store
that
does not must not be reused after a timed-out write
(`doc/adr/0005-fallible-store-writes.md`, "Cancellation and timeouts").

The default `MessageStore::reset_to` is three calls, not one atomic write: a
crash between them leaves the store cleared with its initial counters, and the
next Logon goes out at 1 without `ResetSeqNumFlag`. A durable store should
override it. `FileStore` does: its `reset_to` writes a new journal and renames
it into place, and its `file_outbound` writes the frame and the next sender
number as one record.

Not done: inbound frames are not filed (only the target counter is kept).

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
| 1130 | RefApplVerID | FIXT.1.1 only: `ApplVerID` of the rejected message |
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
| 12 | XML validation error |
| 13 | Tag appears more than once |
| 14 | Tag specified out of required order |
| 15 | Repeating group fields out of order |
| 16 | Incorrect NumInGroup count for repeating group |
| 17 | Non "data" value includes field delimiter (SOH) |
| 18 | Invalid/Unsupported application version |
| 99 | Other |

Codes 12 to 18 are listed as the vendored FIXT.1.1 session dictionary
(`ironfix-dictionary/spec/FIXT11.xml`, `SessionRejectReason` (373)) defines
them; a FIX 4.x dictionary defines a shorter list (FIX 4.4: 0 to 17 and 99).
Code 18 belongs to the FIXT.1.1 session layer, which governs the Reject
message on every FIXT.1.1 session whatever application version it carries, so
IronFix uses it on FIX 5.0, 5.0 SP1 and 5.0 SP2 sessions alike, and never on a
FIX 4.x session (which carries no `ApplVerID` to reject).

**Reason codes IronFix emits today**

| Code | Emitted when |
|---|---|
| 1 | `SequenceReset` without `NewSeqNo` (36); `ResendRequest` without `BeginSeqNo` (7) or `EndSeqNo` (16); inbound `SendingTime` (52) absent; FIX 5.0, initiator in strict mode only: a Logon acknowledgement without `DefaultApplVerID` (1137), `RefTagID` = 1137, followed by a Logout |
| 5 | `SequenceReset` whose `NewSeqNo` would rewind or fails to advance; `ResendRequest` whose range is outside what we have sent; initiator, with `send_next_expected_msg_seq_num`: a Logon acknowledgement whose `NextExpectedMsgSeqNum` (789) is 0, `RefTagID` = 789, followed by a Logout |
| 6 | `SequenceReset` with a malformed `GapFillFlag` (123) that is present but neither `Y` nor `N`; inbound `SendingTime` (52) present but not a `UTCTimestamp`; initiator, with `send_next_expected_msg_seq_num`: a Logon acknowledgement whose `NextExpectedMsgSeqNum` (789) is not a number, `RefTagID` = 789, followed by a Logout |
| 9 | Inbound `SenderCompID`/`TargetCompID` (and `SenderSubID`/`TargetSubID` when configured) do not match the session configuration, **or** appear outside the standard header |
| 10 | Inbound `SendingTime` (52) differs from the local clock by more than the configured tolerance |
| 13 | FIX 5.0 only: `ApplVerID` (1128) more than once in the standard header of an inbound application message, or `DefaultApplVerID` (1137) more than once on the Logon acknowledgement (initiator); with `send_next_expected_msg_seq_num`, `NextExpectedMsgSeqNum` (789) more than once on the Logon acknowledgement (initiator, followed by a Logout); `RefTagID` = the repeated tag |
| 14 | FIX 5.0 only: `ApplVerID` (1128), a standard-header field, after the header of an inbound application message has ended; `RefTagID` = 1128, the number is consumed and the message never reaches `from_app` |
| 18 | FIX 5.0 only: an inbound application message whose `ApplVerID` (1128) names no version or a version the session does not accept (`RefTagID` = 1128, and `RefApplVerID` (1130) = the refused code when it names a version, `2` to `9`; the message's number is consumed and it never reaches `from_app`), or a Logon acknowledgement whose `DefaultApplVerID` (1137) fails the same rule (`RefTagID` = 1137, followed by a Logout; initiator) |
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
| `123=Y`, MsgSeqNum too low with `PossDupFlag` = Y | dropped as an already-applied duplicate, **without** reaching `from_admin`. When its `NewSeqNo` reaches past the expected number, the fill spans numbers still missing (two overlapping resends of the counterparty): they are re-requested at once from the expected number, at most once per expected number and not charged against `max_resend_requests`; `NewSeqNo` is still not applied |
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
  the residual risk listed under Known limits. Both conditions hold across a
  read boundary: when a resync empties the buffer (the byte before is
  remembered) or stops on a partial opening, the start of the next read is
  judged exactly as the scan judges a candidate, and anything else it opens
  with, an embedded frame of another version included, is the rest of the same
  garbled span. Where TCP splits the bytes changes neither the frames handed up
  nor the skip count. The shape is checked inside the scan, so a false start
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
  both engines restrict anchors to their own BeginString, and this holds
  however the bytes are split across reads.
- A frame whose opening follows an ASCII digit or `=` (for example after
  garbage that ends in a digit) is passed over by the resync, and its gap is
  recovered by `ResendRequest`. A stream whose BeginString is not accepted
  still frames, but a resync does not land on it.
- Garbage that happens to spell a header whose declared span ends exactly on a
  later frame's `<SOH>10=NNN<SOH>` has a corroborated boundary, and the
  checksum error consumes that frame with it. The gap is then recovered by
  `ResendRequest` like any other.
- The skip count is one per garbled frame, and a run of garbage up to the next
  accepted frame start counts once however it is split across reads. The
  exception is a codec restricted to a BeginString outside the FIX family,
  which has no anchor: it frames a read that starts after a plausible
  boundary as it is, so garbage delivered in separate reads can count once
  per read. Neither engine builds one.
- A framed message whose body does not decode is dropped without a Reject,
  because no `MsgSeqNum` can be read to reference. A peer that answers the
  resulting `ResendRequest` by resending the same bytes has them dropped again,
  so that gap can stall until the bounded resend gives up and logs out.
- After the "message too large" Logout, and after the garbled-limit Logout,
  the socket is dropped while the peer's input may still be arriving. Closing a
  socket with unread input can make the kernel send RST, and the peer may then
  lose the Logout. This holds until a graceful drain exists.

### Repeating groups in dictionary validation

**Scope**: `ironfix-dictionary::Validator`, the standalone, opt-in validator.
Neither the codec nor the engine calls it, so nothing below is enforced on the
session path today.

A repeating group is checked in two layers. Its **structure**: the entries
follow the count field contiguously, each entry starts with the delimiter (the
group's first field), no tag repeats inside one entry, and the number of
entries found equals the declared count. And, for a structurally sound group,
the **required members of every entry**, reported as
`ValidationError::MissingRequiredFieldInGroupEntry { count_tag, group, entry,
tag, name }` with a **0-based** `entry` index. An entry's required set is what
the dictionary marks required, applied per the FIX rule that a required member
is required in every entry of every group instance present, whether or not the
group itself is required:

- member fields marked `required='Y'`;
- nested groups marked `required='Y'` (reported with the nested group's count
  tag), whose own entries are checked the same way;
- the required members of components referenced as `required='Y'`. A component
  referenced as `required='N'` contributes no required members, nested groups
  included, even when some of its fields are present.

A tag required twice (directly and through a component) is reported once. The
delimiter is never reported missing; when it is a nested group's count tag,
that nested group counts as present. A group that already carries a structural
error gets no per-entry errors, nested groups included; a malformed nested
group suppresses only its own.

Error order within an entry: first the group's own required fields in
declaration order, then the required members of components referenced as
required (component by component in declaration order, each component's own
fields before the components it references), then missing required nested
groups by ascending count tag; each tag once, at its first position. A field
declared after a component in the XML is still reported before that
component's members, because the schema keeps a group's fields and components
in separate lists. Entries are reported in the order they close (a nested
group's entries before the entry that encloses them). Example from
the vendored FIX 4.4 dictionary: each `NoOrders` (73) entry of a NewOrderList
(35=E) requires `ClOrdID` (11), `ListSeqNo` (67) and `Side` (54); an entry
without 67 is reported with its index.

Conditional requirements are not enforced. FIX 4.4 says `PartyIDSource` (447)
and `PartyRole` (452) are "Required if NoPartyIDs > 0", but QuickFIX XML cannot
express a condition, and the vendored dictionary marks both `required='N'`;
with the dictionary as the authority, they are not enforced.

One validation call returns at most `MAX_VALIDATION_ERRORS` (1024) errors;
past that it stops and appends `ValidationError::ErrorLimitReached`, so a
hostile message (for example a ListStatus of 200,000 one-field entries, which
fits the codec's 1 MiB frame limit) cannot make the report grow with the
message. Per-entry errors stay provisional until their group is known to be
well-formed and never take room from the result while provisional, so a
structural error that replaces them is always recorded: a ListStatus declaring
206 `NoOrders` entries but carrying 205 delimiter-only ones (1025 provisional
per-entry errors) reports just the count mismatch.

**Differences from QuickFIX.**

- **Stricter.** QuickFIX (C++ and Java, `addXMLGroup`) enforces an entry's
  required fields only when the group itself is `required='Y'`, and QuickFIX
  C++ ignores the required fields of components referenced inside a group.
  IronFix enforces them in every entry of every present group, so a message a
  QuickFIX counterparty accepts can be rejected here: for example FIX 4.4
  `PosUndInstrmtGrp` `NoUnderlyings` (711) entries without
  `UnderlyingSettlPrice` (732), FIX 4.2 Allocation `NoAllocs` (78) entries
  without `AllocShares` (80), and in FIX 5.0 SP2 the ten optional groups
  (fifteen group definitions) that declare required fields directly, such as
  `NoOrders` (73) and `NoSides` (552).
- **Structural errors first.** QuickFIX checks required fields, per entry
  included, before group counts, so for a message with both problems it
  rejects with `SessionRejectReason` (373) = 1 (required tag missing); IronFix
  reports the group's structural error and suppresses that group's per-entry
  errors.
- **Not lowest tag first.** QuickFIX reports the lowest missing tag first.
  IronFix reports missing fields in schema order (within an entry as described
  above) and missing top-level groups by ascending count tag, after every
  missing field.

**Behaviour change.** This check is newer than the structural one, so
validation is stricter than it was, and stricter than QuickFIX: messages whose
entries lacked required members used to pass, and some still pass at a
QuickFIX counterparty.

**Overall error order.** `Validator::validate` (under `Validator::new` and
`Validator::for_session` alike) reports errors in a fixed order, identical on
every run and for every load of the same dictionary:

1. `BeginStringMismatch` (session validator only);
2. `UnknownMsgType`, after which nothing else is checked;
3. schema errors (`SchemaTooDeep`, `SchemaTooLarge`, `UnknownComponent`), in
   expansion order;
4. value errors (`UnknownTag`, `InvalidFieldFormat`, `InvalidEnumValue`), at
   most one per field, in wire order;
5. structural errors in the order one walk over the message meets them:
   `DuplicateTag` and `FieldNotAllowedForMessage` at the message level, and for
   each group instance its count, delimiter and repeated-tag errors as they
   appear, with its count mismatch when the instance ends (nested groups before
   their enclosing group);
6. `MissingRequiredFieldInGroupEntry` of the well-formed groups, in the
   per-entry order above;
7. `MissingRequiredField` in schema order: header, trailer, the message's own
   fields, then the members of required components, depth first;
8. `MissingRequiredGroup` by ascending count tag;
9. `ErrorLimitReached`, last, when the output was capped.

**Reading groups.** `ironfix-dictionary::group` reads a decoded message's
repeating groups with the same positional walk, so the reader and the
validator agree on entry boundaries and on which instances are malformed (a
test sweeps every validator fixture to keep it so). A `MessageLayout` is built
once per message type from the dictionary; `layout.read(&msg, count_tag)`
finds the count field at the message level only (the same tag inside another
group's entries is skipped), checks the whole instance, nested groups
included, and returns `Ok(None)` when the group is absent or a typed
`GroupError` for a count mismatch, a delimiter mismatch, a tag repeated in an
entry, a count that is not one or more ASCII digits (`+1` included), a count
field present twice, or nesting deeper than 32. Entries are borrowed ranges of
the message's field list: a successful read, iteration and field lookup
allocate nothing, nor does a read that fails with a structural error, for any
group with at most 512 entry-level members (every group of the embedded
dictionaries; a wider group allocates one small buffer per walk). A few error
paths do allocate their error value (`MsgTypeMismatch` carries two strings).
A group nested deeper than 32 fails the read even when it sits in another
top-level group that is only being skipped, since the walk cannot tell where
it ends. Both the reader and the validator settle one boundary with the
enclosing scope: once a group holds every entry its count declares (at once
for a count of 0), a field that the enclosing entry or the message level also
accepts ends the group rather than opening another entry, so
`110=0|300=X` is an empty group followed by the enclosing entry's 300. Required
members are the validator's concern; the reader does not check them. See
ADR-0011.

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
  `MessageStore` attached (`Initiator::with_store`, `Acceptor::with_store`)
  the stored application messages in the range are replayed with
  `PossDupFlag` (43) = Y and the original `SendingTime` in `OrigSendingTime`
  (122), with administrative messages and unavailable sequence numbers
  gap-filled. Two limits are worth stating: the store is **opt-in**, and
  without one the whole range is still answered with a single gap fill; and
  only `FileStore` replays after a restart (`MemoryStore` is not persistent),
  as durably as its `SyncPolicy` promises. Store writes are ordered (frame and next sender
  number before the bytes, next target number before an inbound message is
  acted on) and fallible, under a `StoreFailurePolicy` that either warns and
  continues or fails closed; inbound delivery is at most once across a crash.
  An *outbound* request the peer never
  satisfies is also bounded — retried every `SessionConfig::resend_timeout` and
  then escalated to Logout after `SessionConfig::max_resend_requests` attempts,
  rather than stalling the session forever. See "Resend Request" above.
- [x] `NextExpectedMsgSeqNum` (789) on Logon, opt-in
  (`SessionConfig::send_next_expected_msg_seq_num`, FIX.4.4 and FIXT.1.1 only)
  in both roles: declared on the Logon and its acknowledgement; a
  counterparty's 789 below this session's own Logon resends the missed range
  once Active, one above what was sent refuses the Logon with a Logout, and a
  gapped Logon from a counterparty that declared 789 is held instead of
  requested. Bilateral: both sides must enable it. See
  "NextExpectedMsgSeqNum (789), both roles" under "Logon".

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

**Application-version checks (issue #67, ADR-0020).** A FIX 5.0 session
accepts from its counterparty its own configured version (the one it declares
in its own 1137 and stamps in its own 1128) and any version in
`SessionConfig::allowed_appl_versions`; `SessionConfig::accepts_appl_version`
is the rule, and the default (an empty set) accepts the configured version
only. The set may name only FIX.5.0, FIX.5.0SP1 and FIX.5.0SP2, and only on a
FIX 5.0 session: anything else is `SessionConfigError::UnusableApplVersion`,
reported by the builder, by `SessionConfig::validate` and by both engines before
a connection is taken or dialled. Values are decoded by
`FixVersion::from_appl_ver_id`, which reads the whole `ApplVerID` list as far
as `FixVersion` has variants (`2` to `6` = FIX 4.0 to 4.4, `7` to `9` = FIX
5.0 to 5.0 SP2); decoding is not acceptance. A code that decodes to a version
the session does not accept (any FIX 4.x code, or a 5.0 one outside the set)
is refused as "not an application version this session accepts"; `0`
(FIX 2.7), `1` (FIX 3.0), `10` (FIX_LATEST) and anything else name no version
and are refused as unknown. Both are reason 18.

| Where | Rule | Refusal |
|---|---|---|
| Acceptor, inbound Logon | 1137 required, once, naming an accepted version | Logout with the reason and the accepted versions, after `from_admin` (filed when a store is attached; never resets it); `EngineError::ApplVersion` |
| Initiator, Logon ack | 1137, when present (required in strict mode, `require_ack_default_appl_ver_id`), once and naming an accepted version | Reject (18; 13 when repeated; 1 when missing in strict mode; `RefTagID` 1137) and Logout, filed when a store is attached; `EngineError::ApplVersion` |
| Both roles, in session | 1128 on an application message, when present, in the standard header, once, naming an accepted version | Reject (18; 13 when repeated in the header; 14 when outside it; `RefTagID` 1128; `RefApplVerID` (1130) = the code, on an 18 for a code that names a version); the number is consumed and persisted, `from_app` is not called, the session stays up |

1128 is a standard-header field (`FIXT11.xml`), so it is read positionally,
as the CompIDs are: one in the header (the leading run of standard-header
tags) is the message's version, and one after the header has ended is out of
order (reason 14) whatever its value, so no 1128 that
`RawMessage::get_field_str(1128)` could hand the application escapes the
check. 1137 is a body field of the Logon and is read across the whole message.
A message without 1128 is in the counterparty's default version, which the
Logon exchange checked. FIX 4.x sessions carry neither field and are not
checked.

**Not implemented for 5.0:**

- No dictionary is consulted: an accepted `ApplVerID` selects nothing, and the
  engine never validates a message body against an application dictionary.
- The counterparty's declared default is not adopted for outbound traffic:
  the session always declares and stamps its own configured version. It is
  kept and exposed as `Connection::counterparty_default_appl_version` (the
  version of every inbound message without 1128; `None` on FIX 4.x and on an
  initiator whose ack declared none), and the application can also read 1137
  off the Logon in `from_admin`.
- Per-message-type versions declared on the Logon are not honoured: the
  `NoMsgTypes` (384) group, with `RefMsgType` (372), `RefApplVerID` (1130) and
  `DefaultVerIndicator` (1410), is neither read nor sent, so a counterparty
  that declares a different default version for some message types has each
  such message checked against its 1128 and the Logon's single default only.
- FIX 4.x messages carried over FIXT.1.1 (`ApplVerID` `2` to `6`) are refused:
  the engine frames a FIX 4.x version only as a FIX 4.x session.
- `CstmApplVerID` (1129), `ApplExtID` (1156), `DefaultApplExtID` (1407) and
  `DefaultCstmApplVerID` (1408) are not checked.

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
  first (up to `MAX_VALIDATION_ERRORS`), and header/body/trailer field order is
  not enforced.
- **Group entries.** Required members are enforced in every entry of every
  present group, stricter than QuickFIX; see "Repeating groups in dictionary
  validation" under Error Handling.
- **`DefaultApplVerID` (1137) values are not checked** by the `Validator`.
  `FIXT11.xml` declares it as a STRING with no enumeration, so any value
  passes. (The engine checks it on the Logon exchange; see above.)

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
