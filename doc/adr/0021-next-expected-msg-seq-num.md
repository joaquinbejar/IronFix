# ADR-0021 — NextExpectedMsgSeqNum (789) on the Logon exchange, in both roles

- **Status:** Accepted (issue #79, in the plan the owner approved; the handling
  of a gapped Logon was decided in the #79 protocol review, see "A gapped Logon
  or acknowledgement")
- **Date:** 2026-10-18

## Context

FIX.4.4 and FIXT.1.1 define `NextExpectedMsgSeqNum` (789) on the Logon: the
next `MsgSeqNum` the sender expects to receive. With it each side learns, in
the Logon exchange itself, which of its messages the other missed, without
waiting for a `ResendRequest` (2), and can detect a counterparty that claims to
expect a number higher than was ever sent (FIX Session Layer, June 2020,
§4.4, as cited by issue #79). The vendored dictionaries agree: `FIX44.xml` and
`FIXT11.xml` list 789 on the Logon, after `ResetSeqNumFlag` (141) and before
`MaxMessageSize` (383); `FIX42.xml` does not define it.

The engine neither sent nor honoured it, and `doc/fix_operations.md` did not
mention it, so the semantics below come from the issue and the FIX Session
Layer it cites, not from the repository's own spec page, which now documents
them ("Logon", "Resend Request").

Constraints any answer keeps:

- the acceptor's check order and refusal groups (ADR-0017), for a session
  served directly and for one routed by an `AcceptorRegistry` (ADR-0018);
- the store write order, the owed reset and cancellation rules (ADR-0005);
- new decision logic is synchronous, takes what it compares as parameters and
  reads no clock (ADR-0002);
- `ironfix-session` holds the configuration and depends on `core` only;
  `ironfix-engine` composes;
- sequence arithmetic is checked; 789 must never move a counter.

## Decision

### Configuration

`SessionConfig::send_next_expected_msg_seq_num: bool`, default `false`, with
`SessionConfig::with_send_next_expected_msg_seq_num` and
`SessionConfigBuilder::send_next_expected_msg_seq_num`.
`SessionConfig::validate` refuses `true` with the new
`SessionConfigError::NextExpectedMsgSeqNumUnsupported { begin_string }` unless
the session is FIX.4.4 or framed as FIXT.1.1 (FIX.5.0, FIX.5.0SP1,
FIX.5.0SP2; bare FIXT.1.1 passes this check and is refused by the engines'
version check, as before). Both engines report it as `EngineError::Config`
before a connection is taken or dialled.

The flag governs **both directions**: with it set the session declares 789
and acts on the counterparty's; with it unset no 789 is sent and a
counterparty's is ignored, as before. Gating the inbound side keeps the
default behaviour unchanged: a counterparty that sends 789 to a session that
did not opt in is not suddenly logged out over it, and the issue's tasks name
one option "to enable 789".

The cost is that **789 is bilateral: both sides must enable it.** Engines
differ here. QuickFIX/C++ (`src/C++/Session.cpp`, `Session::nextLogon`) acts on
an inbound 789 whatever its own `SendNextExpectedMsgSeqNum` setting says, and,
when it declared 789 itself, queues a gapped Logon and records the gap as
already requested instead of sending a `ResendRequest`, with no resend timer.
Such a counterparty logging on to an IronFix session with the flag off
declares 789, gets none back, and with its defaults never asks for the gap at
all. `doTargetTooHigh` (`Session.cpp:1213-1222`) sends no request for a number
at or above the start of the recorded range, since `SendRedundantResendRequests`
defaults to false (`:56`); the range clears only when an in-order message at or
above its end arrives (`:1075-1085`), which cannot happen while the gap is
open; and `lastReceivedTime` is set only past the too-high early return
(`:1096`), so the gapped traffic does not count as proof of life. The session
wedges until its heartbeat timeout disconnects it, and on reconnect its 789
opens the same gap again: a reconnect loop. The flag's documentation and
`doc/fix_operations.md` say so.

### What the session declares

Its own next expected inbound `MsgSeqNum`, after any reset (`MessageFactory`
places 789 after 141 and before `DefaultApplVerID` (1137)):

- **Initiator Logon:** the seeded target counter, which is 1 when the Logon
  declares `ResetSeqNumFlag` (141) = Y (the acknowledgement of a reset is
  message 1).
- **Acceptor acknowledgement:** the target counter once the initiator's Logon
  has been processed: the Logon's number plus one when it was in sequence, 2
  after a reset (under the reset rule of ADR-0017 the Logon is message 1 of the
  new stream), and the first missing number when the Logon opened a gap: a
  gapped Logon is not consumed at the handshake (it is held or requested, see
  below).

So `141=Y` goes with 789 = 1 on the Logon that opens the exchange, and with
789 = 2 on the acknowledgement of it: in both cases 789 is "the next number
expected", and the acknowledgement is written after the Logon it answers was
taken as message 1.

### What the counterparty's 789 asks

One synchronous function, `next_expected::plan(declared, own_logon_seq,
next_outbound)` in a private module of `ironfix-engine`, decides it.
`own_logon_seq` is the `MsgSeqNum` of this session's own Logon (initiator) or
acknowledgement (acceptor); `next_outbound` the next number this session sends
when the 789 is read. Both are taken after any reset of the exchange. For the
acceptor, which reads the initiator's 789 before acknowledging, both are the
number its acknowledgement takes; for the initiator, `next_outbound` is one
past its Logon.

- `789 > next_outbound`: the counterparty claims messages that were never
  sent. Unrecoverable in this exchange: a Logout whose `Text` (58) says why,
  `on_logon` never runs, and `connect` / `serve` return the new
  `EngineError::NextExpectedMsgSeqNum { detail }`.
- `789 < own_logon_seq`: the counterparty missed `789 .. own_logon_seq - 1`.
  Once the session is Active the reactor resends exactly that range through
  `Reactor::resend_range`, the answer an inbound `ResendRequest` gets
  (factored out of `on_resend_request`): stored application messages replayed
  under their original numbers with `PossDupFlag` (43) = Y and
  `OrigSendingTime` (122), administrative messages, holes and unrebuildable
  frames gap-filled, one gap fill without a store, and a store reporting
  itself corrupted closes the session. The replay is the reactor's second
  opening act, right after the `ResendRequest` for any gap the exchange found
  (unchanged: ADR-0005 item 6), so a failure in it closes the session through
  the normal close path with `on_logout`. The range is checked again against
  the next sender number before it is sent.
- otherwise: nothing to do.

789 never moves a counter. It is a body field of the Logon, so it is read
across the whole message and must occur there once, as 1137 is (ADR-0020); a
value that is 0, empty, carries anything but the digits `0` to `9` (a sign
included), or exceeds `u64::MAX` is refused. The echoed value is bounded to 32
bytes and escaped.

### Where each role decides

**Acceptor**, after `from_admin` (the peer is authenticated, ADR-0017 group
3), in this order:

> version, encryption method, `MsgSeqNum`, identity, admission,
> `SendingTime`, `from_admin`; then `DefaultApplVerID` (FIX 5.0); then
> `141=Y` carrying `MsgSeqNum` 1, `HeartBtInt`; **then 789 is read (a
> malformed value refused); then, for a Logon that asked for the reset, a 789
> other than 1 is refused;** then the store is reset or refreshed; **then 789
> is compared with the next sender number;** then `MsgSeqNum` is validated and
> the acknowledgement sent.

Every 789 refusal is a Logout alone (the Logon is never acknowledged, so no
session exists for a Reject to belong to), numbered and filed like the other
authenticated refusals. The ones decided before the store is touched use the
same seed as ADR-0017 (never a reset), so a refused `141=Y` Logon cannot clear
the journal; the comparison after a refresh is a refusal numbered from the
refreshed counters, like a Logon too low, and the Logon's own number is not
consumed. When this side drives a reset the peer did not ask for
(`reset_on_logon`, an owed reset), the peer's 789 describes the stream being
discarded and the acknowledgement's 141 = Y tells the peer to restart, so the
value is ignored (logged at debug). A session routed by an `AcceptorRegistry`
runs the same handshake and behaves the same.

**Initiator**, after `from_admin`, 1137 and 108, and after the "141=Y must be
numbered 1" check: the acknowledgement's 789 is compared with the counters the
acknowledgement's own reset sets, if it declares one (own Logon 1, next 2), and
decided **before** that reset is applied to the store, so a refused
acknowledgement never resets it. A malformed value is refused like the
acknowledgement's other malformed fields: a session Reject (`SessionRejectReason`
13 repeated, 6 not a number, 5 for 0; `RefTagID` 789) and a Logout. A value
above what was sent gets the Logout alone, as FIX prescribes for that error.

### A gapped Logon or acknowledgement

789 is the Logon sender's built-in `ResendRequest`: by declaring the next
number it expects, a side asks the other to resend everything from there, and
the other does so right after the Logon exchange. IronFix resends below its own
Logon (the range above stops before it). QuickFIX/C++ resends through it: it
computes `endSeqNo = getExpectedSenderNum() - 1` (`Session.cpp:294`) after its
acknowledgement and after calling `onLogon` (`:287`), so its retransmit
gap-fills its own Logon and replays any live messages its application sent
from `onLogon`. So when both sides declared 789 and the
counterparty's Logon or acknowledgement arrives with a gap below it, sending a
`ResendRequest` as well would cross that resend: the counterparty would answer
the same range twice, and the second answer, arriving below the receiver's
expectation, is dropped as a possible duplicate, so the number of the Logon
itself was left to the request's retry timer. Avoiding that crossing request is
what 789 exists for. The decision, taken in the #79 protocol review and
matching QuickFIX/C++ (`Session::nextLogon` queues the Logon and records the
range as requested; `Session::nextQueued` then only increments the target for
a queued Logon or `ResendRequest`):

- **The gapped Logon is held, not requested**, when this session declared 789
  and the counterparty's Logon or acknowledgement carries a well-formed 789
  (evidence that it resends on its own). The acceptor uses the 789 after the
  reset filter above, so a Logon whose 789 is ignored because this side drives
  a reset is not held (no gap arises after a reset anyway). Without the
  counterparty's 789 the gap is requested at once, as before. QuickFIX/C++
  holds on its own flag alone; requiring the counterparty's 789 as well keeps
  the immediate request for a counterparty that is not known to resend. The
  price: against QuickFIX/C++ with its own flag off (no 789 on its Logon, but
  acting on ours), IronFix requests the gap at once, and that request crosses
  the retransmit QuickFIX/C++ sends for our 789, a harmless double replay (the
  second copy arrives below the expectation and is dropped as a possible
  duplicate).
- **The Logon's number is consumed once the gap below it is filled.** The
  reactor (`Reactor::release_held_logon`, after every inbound frame) watches
  the expectation: below the held number it waits; at it, it persists the
  number plus one as the next target and then moves the expectation, the order
  every inbound message takes (ADR-0005); above it (a counterparty that fills
  through its own Logon, one gap fill from the expected number to the Logon's
  plus one) the hold is simply dropped. The Logon itself was processed at the
  handshake, so only its number is left to take, as QuickFIX/C++ does for a
  queued Logon. Arithmetic is checked: an exhausted counter closes the session.
  The hold absorbs both resend shapes: IronFix's stops at the Logon, whose
  number is then consumed; QuickFIX/C++'s runs through it, and either its gap
  fill jumps the expectation past the Logon (the drop branch) or, when the
  message before the Logon is an application message, the Logon is consumed
  first and the gap fill for it arrives below the expectation with
  `PossDupFlag` = Y and is dropped as a possible duplicate (the too-low drop);
  the live messages it replays after that are then in sequence.
- **The gap is armed as an implied recovery** (`ResendState::implied`, with no
  request counted): a gapped frame arriving meanwhile sends no request either,
  and a counterparty that never resends gets exactly one real `ResendRequest`
  from the first missing number once the gap has made no progress for
  `SessionConfig::resend_timeout`, which a limit of one request still allows;
  partial progress keeps the recovery implied. Nothing is requested when the
  held Logon is consumed, even if frames from beyond it arrived while it was
  held: QuickFIX/C++ resends those too (they lie below its `endSeqNo`), and a
  request then would cross that resend, the double replay this decision exists
  to avoid. The recovery stays implied at the next number with a fresh clock,
  so a counterparty that does not cover them gets the one request once that
  gap has made no progress for the resend timeout. QuickFIX/C++ has no such
  timer; this fallback is IronFix's.

The replay range is unchanged: `plan` still answers `789 .. own_logon_seq`,
stopping before the session's own Logon, which the counterparty holds and
consumes in the same way.

### What does not change

A gapped Logon from a counterparty that declared no 789, or on a session with
the flag off, still draws a `ResendRequest` as the reactor's first act
(ADR-0005 item 6). The typestate is unchanged, and so are the heartbeat timers,
the store contract and the write order: the replay files nothing and spends no
number, and the held Logon's number is persisted before the expectation moves
past it.

## Consequences

- **Semver (additive):** `SessionConfig::send_next_expected_msg_seq_num` (a
  field on a `#[non_exhaustive]` struct),
  `SessionConfig::with_send_next_expected_msg_seq_num`,
  `SessionConfigBuilder::send_next_expected_msg_seq_num`,
  `SessionConfigError::NextExpectedMsgSeqNumUnsupported` and
  `EngineError::NextExpectedMsgSeqNum` (both enums `#[non_exhaustive]`). No
  existing item changes signature. The `next_expected` module, the factory's
  extra Logon parameter, `SessionParams::opening_replay` and
  `SessionParams::held_logon`, `ResendState::implied`, `Reactor::resend_range`
  and `Reactor::release_held_logon` are crate-private.
- **Behaviour:** none with the flag off. With it on, the Logon exchange
  carries 789, a counterparty's 789 can replay a range after `on_logon` or
  refuse the Logon before it, and a gapped Logon from a counterparty that
  declared 789 is held instead of requested. Between two IronFix engines with
  the flag on, a restarted side gets back what it missed with no
  `ResendRequest` either way, and the next live message is in sequence.
- The crate DAG is unchanged: `session` gains a flag and a check over `core`
  types, `engine` the decisions. No dependency was added.
- No performance claim (ADR-0001): the Logon exchange reads one more field,
  and the replay is the existing resend path; nothing was measured.
- **Not done:** 789 is not consulted outside the Logon exchange; only the
  Logon's number is held, and a general queue of messages received across a
  gap is #71; the joint crash and takeover suite that exercises 789 across
  injected crashes is #89.
- **Known limit, until #71:** when the fallback request has gone out and
  administrative messages from beyond the held Logon arrived live during the
  hold, the answer to that request covers the held Logon and those messages
  with one gap fill numbered with the Logon's number. That number is consumed
  as soon as the gap below it fills, so the gap fill arrives below the
  expectation and is dropped as a possible duplicate, and the messages beyond
  the Logon stay missing until the request's next retry asks for them. Nothing
  is lost and no number is reused; recovery takes one more resend timeout. A
  test pins it
  (`test_acceptor_fill_from_the_held_logon_after_the_fallback_waits_for_the_retry`).
