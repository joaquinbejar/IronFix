# ADR-0021 — NextExpectedMsgSeqNum (789) on the Logon exchange, in both roles

- **Status:** Accepted (issue #79, in the plan the owner approved; the replay
  range stopping before the session's own Logon is the plan's choice and is
  marked for protocol review, see "Open questions")
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
counterparty's is ignored, as before. QuickFIX/J's
`EnableNextExpectedMsgSeqNum` gates both directions the same way. Gating the
inbound side keeps the default behaviour unchanged: a counterparty that sends
789 to a session that did not opt in is not suddenly logged out over it.

### What the session declares

Its own next expected inbound `MsgSeqNum`, after any reset (`MessageFactory`
places 789 after 141 and before `DefaultApplVerID` (1137)):

- **Initiator Logon:** the seeded target counter, which is 1 when the Logon
  declares `ResetSeqNumFlag` (141) = Y (the acknowledgement of a reset is
  message 1).
- **Acceptor acknowledgement:** the target counter once the initiator's Logon
  has been processed: the Logon's number plus one when it was in sequence, 2
  after a reset (under the reset rule of ADR-0017 the Logon is message 1 of the
  new stream), and the first missing number when the Logon opened a gap,
  because a gapped Logon is not consumed.

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

### What does not change

A gap in the Logon's own `MsgSeqNum` still draws a `ResendRequest` (issue #79:
"stays as today"), in both roles. The typestate is unchanged, and so are the
heartbeat timers, the store contract and the write order: the replay files
nothing and spends no number.

## Open questions

- **The replay stops before the session's own Logon.** The approved plan
  replays `789 .. own_logon_seq` exclusive of that Logon, which matches the
  FIX model in which the receiver holds a gapped Logon until the gap before it
  is filled and then consumes it (QuickFIX/J does). IronFix's own receiver does
  not hold it (no gap queue yet, #71): a gapped Logon is processed, not
  consumed, and its number is recovered by the `ResendRequest` it sends. When
  the answer to that request covers the Logon with a gap fill that starts
  below the number the receiver then expects (the message before the Logon is
  administrative, typically the previous session's Logout), the receiver
  ignores that fill as a possible duplicate, and the Logon's number is
  recovered only by the request's retry after `SessionConfig::resend_timeout`
  (10 s by default). Nothing is lost and no number is reused, but between two
  IronFix engines the receiver's expectation waits on the Logon's number for
  up to one resend timeout; live messages arriving meanwhile are gapped and
  re-requested by that retry. Two remedies are open for protocol review:
  replay through the session's own Logon (gap-filling it) whenever 789 is
  below it, which the issue text ("replay `789..` as if a `ResendRequest` had
  arrived") also reads as and which a conformant receiver that consumed the
  Logon ignores as a duplicate; or the gap queue of #71.
- **Inbound gated by the same flag.** The issue's tasks name one option "to
  enable 789"; gating both directions is the reading taken here. Honouring a
  received 789 unconditionally would change the default behaviour.

## Consequences

- **Semver (additive):** `SessionConfig::send_next_expected_msg_seq_num` (a
  field on a `#[non_exhaustive]` struct),
  `SessionConfig::with_send_next_expected_msg_seq_num`,
  `SessionConfigBuilder::send_next_expected_msg_seq_num`,
  `SessionConfigError::NextExpectedMsgSeqNumUnsupported` and
  `EngineError::NextExpectedMsgSeqNum` (both enums `#[non_exhaustive]`). No
  existing item changes signature. The `next_expected` module, the factory's
  extra Logon parameter, `SessionParams::opening_replay` and
  `Reactor::resend_range` are crate-private.
- **Behaviour:** none with the flag off. With it on, the Logon exchange
  carries 789, and a counterparty's 789 can replay a range after `on_logon` or
  refuse the Logon before it.
- The crate DAG is unchanged: `session` gains a flag and a check over `core`
  types, `engine` the decisions. No dependency was added.
- No performance claim (ADR-0001): the Logon exchange reads one more field,
  and the replay is the existing resend path; nothing was measured.
- **Not done:** 789 is not consulted outside the Logon exchange; the gap
  queue that would let the receiver consume a gapped Logon is #71; the joint
  crash and takeover suite that exercises 789 across injected crashes is #89.
