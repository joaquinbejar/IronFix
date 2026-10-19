# ADR-0021 — NextExpectedMsgSeqNum (789) on the Logon exchange, in both roles

- **Status:** Accepted (issue #79, in the plan the owner approved; the handling
  of a gapped Logon was decided in the #79 protocol review, see "A gapped Logon
  or acknowledgement"). Amended by issue #126: the reactor's writes, in
  "Writing a resend".
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
  Once the session is Active the reactor resends exactly that range, as it
  answers an inbound `ResendRequest`: stored application messages replayed
  under their original numbers with `PossDupFlag` (43) = Y and
  `OrigSendingTime` (122), administrative messages, holes and unrebuildable
  frames gap-filled, one gap fill without a store, and a store reporting
  itself corrupted closes the session. The resend is queued as the reactor
  opens, right after the `ResendRequest` for any gap the exchange found
  (unchanged: ADR-0005 item 6), and written by the reactor loop (see "Writing
  a resend" below), so a failure in it closes the session through the normal
  close path with `on_logout`. The range is checked again against the next
  sender number before it is queued.
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
When the initiator declared a reset (`reset_on_logon`, or a reset an earlier
session owes) and the acknowledgement does not echo `141=Y`, the reset rule
takes the acknowledgement as the acceptor's message 1 whatever its number,
and its 789 may describe the stream the reset discards: a well-formed value is
ignored, as the acceptor ignores the Logon's 789 for a reset it drives alone.
A malformed value is still refused, and an acknowledgement that echoes `141=Y`
knew of the reset, so its 789 is still held to the new stream. (Found in
review: an acknowledgement at 7 with 789 = 9 used to be refused against a next
outbound number of 2 before the reset rule ran.)

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
- **A real request ends the hold.** Once a real `ResendRequest` goes out (the
  fallback, or a later retry), the hold is dropped rather than the Logon
  consumed locally: the open-ended request covers the Logon's own number, and
  its answer fills it (an administrative Logon is gap-filled), so that number
  then arrives in sequence. Consuming it locally made the answer's gap fill,
  numbered with the Logon's number, land below the expectation and be
  dropped as a possible duplicate, leaving any administrative message past the
  Logon that arrived during the hold missing; with `max_resend_requests` = 1
  the session was then logged out despite a complete answer (found in
  review). Duplicates of the counterparty's own 789 resend that arrive after
  the request are dropped as possible duplicates as usual.

The replay range is unchanged: `plan` still answers `789 .. own_logon_seq`,
stopping before the session's own Logon, which the counterparty holds and
consumes in the same way.

### Writing a resend

A resend used to be written to completion before the reactor read again: the
789 resend as an opening act, and the answer to a `ResendRequest` inside the
inbound handler. When both sides owe each other more than the socket buffers
hold (both missed messages, with or without 789), each blocked writing while
neither read, until the write timeout closed both sessions (found in review).

Resends are now queued (`Reactor::queue_resend`) and written by the reactor
loop in steps (`Reactor::resend_step`), reading the store a page at a time; a
page read is a step of its own and spends cooperative budget, so a run of
skipped entries cannot keep the reactor from yielding.

**The reactor never waits inside a write (#126).** The first version of this
section wrote one resend frame per pass with a blocking `send`, after reading
any frame the counterparty had already sent. That narrowed the bilateral
deadlock without removing it: a read that finds nothing does not mean the
counterparty is not about to send, so both sides could still enter a blocking
write of one frame with both directions full (frames larger than the socket
buffers, or a high-latency link), neither reading, until the write timeout
closed both. The bilateral tests of 9 MB per side timed out intermittently on
the Linux CI runners with the symptom of this deadlock (neither backlog
arriving, the write timeout closing the sessions); the pipe tests below
reproduce it on every run. It also made a resend run only
when inbound was idle, so a counterparty that sent without pause held it, and
everything behind it, back; and every resent frame was its own flush, so its
own write(2) and TCP segment. What the reactor does instead:

- **Every write is a feed.** Each frame the reactor writes (a resent frame, a
  gap fill, a live application message, a Heartbeat, a Reject, a Logout) is
  appended to the `Framed` write buffer through a codec of its own with the
  session's `max_message_size` (`Writer::feed`); no socket call is made. The
  buffer is written front to back, so the order on the wire is the order of
  feeding, and nothing about numbering changes: a new message is still
  filed, persisted and spent before it is fed (ADR-0005, with "write the
  bytes" now meaning "feed them").
- **The flush is a branch of its own.** One branch of the loop polls, on the
  same `&mut framed`, the flush of the write buffer and then the next
  inbound read (`poll_socket`), enabled while output waits or reading is
  allowed. A flush the counterparty is not taking never stops the reading,
  so two sides writing to each other at once always drain each other. A
  completed flush calls the heartbeat manager's `on_message_sent` once,
  whatever number of frames it carried.
- **Live frames are written through.** After a live frame (an application
  message, a Heartbeat reply, a Reject, a Logout) is fed, the flush is polled
  once without waiting, and polled again before the next command is taken
  (a write-through can come back empty although the stream has room when
  the task's cooperative budget ran out; by the next command the budget is
  fresh). A live frame therefore waits in the buffer only while the stream
  is not taking bytes, never while the next message's `to_app`, framing and
  store call (an fsync, under some sync policies) run first. The first
  version let the command branch beat the flush, and about 40% of frames left
  only after a later frame's store call (#126 perf review). Under
  backpressure frames still accumulate and leave together.
- **A resend step feeds up to a high-water mark.** A step feeds frames until
  the write buffer holds 64 KiB, 64 frames have been fed, a page must be
  read, or the resend is done, so one write carries many resent frames. A
  frame is added only below the mark, so the buffer exceeds it by one frame
  at most.
- **Live messages stop at a lower mark.** The command queue is not read past
  16 KiB of waiting output, which is what holds `Connection::send` back
  while the counterparty reads slowly, and bounds what a fresh message (a
  Heartbeat echoing a `TestReqID` (112), a message whose `SendingTime` (52)
  should be current) queues behind. The trade-off: under backpressure live
  frames are batched in smaller writes than a resend's; when the stream takes
  bytes, each live frame is its own write, as before #126.
- **Reads and resend steps alternate in a bounded ratio.** Before each resend
  step the socket is polled once without waiting, and a frame the
  counterparty has already sent is handled instead, so a resend never holds
  reading back (a Logout that arrived is seen before the resend runs on);
  after 16 inbound frames in a row the resend gets its step regardless, so a
  counterparty that sends without pause cannot hold it back either. The flush
  is polled before every read. Because a step can feed the rest of a resend
  at once, the owed Logout's deadline is checked before every step as well
  as on the tick, so a resend never runs on past it.
- **Reading pauses on piled-up replies, and the buffer gives its peak back.**
  Reading pauses while the replies to inbound frames have piled up 64 KiB
  past the frame that took the buffer over 64 KiB (resends and live sends
  cannot get there), so a counterparty that sends faster than it reads cannot
  grow the buffer. The first version put the ceiling one `max_message_size`
  above the mark: a TestRequest flood grew the buffer to 2 MiB at the default
  1 MiB maximum, and up to about 128 MiB at the 64 MiB one (#126 perf
  review). The buffer is sized for 64 KiB when the reactor starts, and a
  completed flush replaces a buffer grown past 128 KiB with one of 64 KiB:
  one allocation per shrink, never one per message.
- **The write timeout is "no progress".** It was the bound on one blocking
  write; it is now how long waiting output may go with the stream accepting
  none of it, checked on the 100 ms tick. The tick polls the flush once
  before it looks, so time the reactor spent inside an inline await (a store
  call, a callback, `persist_counters`), with nobody polling the flush, is
  not taken for a stall when the stream takes the bytes once polled. The
  first version only recorded progress when the socket branch polled, so a
  store call longer than the write timeout closed a session whose
  counterparty was reading normally (#126 protocol review); a store timeout
  left at its default, the write timeout, did the same under `Continue`.
  "Progress" means bytes the local stream accepted (for TCP, copied into the
  kernel's send buffer), not bytes the counterparty received; a stream that
  buffers on its own (TLS) hides a counterparty that stopped reading until
  its own buffer is full. A stall is detected about two ticks after the
  timeout, later if the reactor is inside an inline await when it runs out.
  Progress since the last tick also counts as sending for the heartbeat
  clock, and no idle Heartbeat is generated while output waits. The Logon
  handshakes, which exchange one frame at a time before the reactor exists,
  keep a blocking write bounded by the same timeout.
- **A Logout is sent when it has been written whole.** The Logout this
  session initiates is fed like any frame, and the session moves to a
  reactor phase `LogoutQueued` (it behaves as one logging out: no new
  application message, an inbound Logout completes the exchange). Only once
  the stream has accepted its last byte does the typestate move to
  `LogoutPending`, whose `sent_at` the logout timeout runs from. The first
  version started the timer when the Logout was fed: behind output the
  counterparty was not taking, the logout timeout fired first, the close
  counted as graceful and `reset_on_logout` reset the sequence numbers, so
  the next Logon went out at `MsgSeqNum` 1 without `ResetSeqNumFlag` (141)
  and was refused as too low (#126 protocol review). Now such a Logout is
  bounded by the write timeout, and a close whose own Logout (or Logout
  reply) was never written whole is not graceful, so no reset runs.
- **A closing session flushes what it left.** The messages that end a session
  (its Logout, the reply to the counterparty's, the Reject before an
  identity Logout) are fed like any other, so before the socket is dropped
  the write buffer is written out, for as long as the stream keeps accepting
  bytes within the write timeout (starting from what was left of it when
  the session closed), reading and dropping inbound frames meanwhile so a
  counterparty flushing its own last output is not left waiting. A slow but
  steady reader therefore still gets the last Logout. A session closed by a
  write failure or by the write timeout does not try again.
- **One hook for a completed flush.** `Reactor::on_flushed` is the one place
  a completed flush is observed, wherever it completes (the socket branch, a
  write-through, the tick, the close); it receives the range of new
  `MsgSeqNum`s the flush covered (resent frames and gap fills re-occupy old
  numbers and are not among them). Per-message send outcomes (#68) resolve
  there.

Live sends go through the same writer as resends rather than keeping a
blocking `send`: a blocking write of a live frame while the counterparty's
direction is full deadlocks two sides sending to each other under load just as
a resend did, and one writer keeps a single ordering rule for everything on the
wire.

Tested in `ironfix-engine/tests/writer_tests.rs`: a real `Initiator` against a
real `Acceptor` over a 256-byte `tokio::io::duplex` pipe, which makes the
crossing deterministic, resends a 200-message backlog of 1.6 KB frames each
way, with 789 and with `ResendRequest`s, and sends 200 such live messages each
way; the same recoveries run over loopback TCP with 4 KiB socket buffers on a
multi-threaded runtime. Against the reactor that wrote with a blocking `send`,
the pipe tests fail every time, closed by the write timeout. A resend of 300
padded reports, many steps long, is written while the counterparty keeps
20 000 Heartbeats coming, with reads between the steps (before #126 it was
written only after all of them). The review's probes are regression tests:
a store slower than the write timeout with a reading counterparty, a Logout
and a Logout reply stuck behind output the counterparty does not take (with
`reset_on_logout`), and a TestRequest flood that fills the hold during a
resend; each fails against the first version. So do 256 live frames that must
leave in 256 writes. Further tests cover a slow but steady reader, the final
Logout under backpressure, the owed Logout's deadline before each step, and
the write timeout's close reason and timing. The heap allocations of a live
send (with and without a store), of a reply and of a resent frame, and the
heap a reply pile-up holds and keeps, are counted with `dhat`
(`ironfix-engine/tests/allocations.rs`); the per-frame counts are those of the
reactor before #126.

**Nothing that takes a new number is written in the middle of a resend.** A
new number reaching the counterparty inside the range being answered is
outside it, and a receiver that does not queue gapped messages (IronFix itself,
until #71) is left waiting for it: it reads the frame as gapped, fills the rest
of the gap, and then expects that number, which nothing sends again until it
asks (found in review; the base never interleaved, because it wrote a resend to
completion). So while a resend is under way:

- live application messages, and a Logout the consumer asks for, wait in the
  command queue;
- a Heartbeat answering a TestRequest, a session Reject (from the session or
  the application dispatcher), and this session's own `ResendRequest` for an
  inbound gap are held back and written, in order, once the resend is done
  (`Reactor::finish_resends`). A held `ResendRequest` is built then, from the
  gap as it stands, and skipped if the gap has closed; recovery is armed when
  it is held, so later gapped frames do not ask again, and its stall clock
  restarts when it is written;
- the tick sends no Heartbeat or TestRequest (resend frames are traffic) and
  does not chase a stalled gap of this session's own (its request could not go
  out before the resend ends); it still enforces the logout and heartbeat
  deadlines.

Only messages that end the session are written at once: its Logouts and the
Rejects that precede them. Once 1024 messages are held (a counterparty
sending TestRequests faster than the resend drains), the reactor stops
reading, and stops taking Rejects from the application dispatcher, until the
resend is done (#126 review): the hold then grows past the bound by at most
what one inbound frame produces, and no new number is ever written in the
middle of the resend. The first version wrote the 1025th message at once,
under a new number, inside the range being answered. A counterparty that
neither reads nor stops sending is closed by the write timeout.

**A Logout from the counterparty waits for the resend it is owed.** FIX gives
the remote end the chance to fill any gap before it answers a Logout, and the
base did, writing the whole resend before reading the Logout. Now a Logout
arriving while a resend is owed marks the reply owed: the session keeps
resending and reading, and replies once the resend and the messages held
behind it are written, or, if the logout timeout runs out first, replies at
once and drops the rest. This session's own Logout cannot start while it owes
a resend (the consumer's waits behind it, and the stalled-gap Logout is not
chased meanwhile), and a resend the counterparty asks for after this
session's Logout is still answered, which FIX allows.

Requests are answered in the order they arrived; past 64 queued, a new request
is merged into the last unstarted one, widening it to cover both, so a
counterparty cannot grow the queue without bound (a number neither request
asked for reaches it as a possible duplicate, so a merged request can take the
counterparty past what one of the two asked for). This applies to every resend
the reactor writes, with or without 789.

### A gap fill that spans the expectation

A possible-duplicate `SequenceReset`-GapFill numbered below the expectation is
ignored, as FIX requires. One whose `NewSeqNo` reaches past the expectation
says, though, that the counterparty has sent numbers this session still lacks.
It arises when two resends of the counterparty overlap: after the fallback
request has gone out, a late IronFix-shaped 789 resend that stops below the
counterparty's Logon brings the expectation to the Logon's number, and the
answer to the request then covers an administrative message below the Logon
and the Logon itself with one fill that starts lower (found in review: the
Logon's number was never filled, and with `max_resend_requests` = 1 the
session logged out).

The fill is still ignored; this session immediately re-requests from its
expectation, so the answer starts there and arrives in sequence. The
re-request is not charged against `max_resend_requests` (recovery already
armed keeps its attempt count and restarts its clock; recovery armed by it
starts implied), and it is made at most once per expected number, so a
counterparty that keeps answering with a fill that starts too low cannot make
it loop; the usual retries and Logout then bound the gap. Applying `NewSeqNo`
from such a fill was the alternative; it would depart from the letter of
"ignore" and was not taken.

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
  `SessionParams::held_logon`, `ResendState::implied`, the resend queue
  (`ResendJob`, `Reactor::queue_resend`, `Reactor::resend_step`), the held
  messages (`DeferredSend`, `Reactor::finish_resends`), the owed Logout and
  `Reactor::release_held_logon` are crate-private. #126 adds only
  crate-private items (`Writer`, `poll_socket`, `flush_on_close`, the
  `LogoutQueued` phase, `Reactor::on_flushed`) and changes no public
  signature; what changes in public is documented behaviour:
  `with_write_timeout` on both engines, `Connection::send`,
  `Connection::logout` and `Connection::next_sender_seq`.
- **Behaviour, every session (whatever the flag):** the reactor never waits
  inside a write: every frame is fed to the write buffer, which a branch of
  the loop flushes while it goes on reading (#126, see "Writing a resend");
  a resend is fed a few frames per step, alternating with inbound reads in a
  bounded ratio, ahead of every message that takes a new number (application
  messages, Heartbeat replies, Rejects, this session's own `ResendRequest`);
  a live frame is written through as soon as the stream takes it;
  `Connection::send` waits for the whole resend once the outbound queue is
  full, and is held back while the counterparty reads slowly; the write
  timeout is how long output may go with the stream accepting none of it; a
  session's own Logout starts its logout timeout once written whole, and a
  close whose Logout never got out is not graceful; reading stops while a
  resend's hold is full; a counterparty's Logout
  is answered after the resend it is owed, within the logout timeout; and a
  possible-duplicate gap fill below the expectation whose `NewSeqNo` spans
  numbers still missing makes the session re-request them (see "A gap fill
  that spans the expectation").
- **Behaviour, with the flag on:** the Logon exchange carries 789, a
  counterparty's 789 can replay a range after `on_logon` or refuse the Logon
  before it, and a gapped Logon from a counterparty that declared 789 is held
  instead of requested. Between two IronFix engines with the flag on, a
  restarted side gets back what it missed with no `ResendRequest` either way,
  and the next live message is in sequence. With the flag off nothing about
  789 changes.
- The crate DAG is unchanged: `session` gains a flag and a check over `core`
  types, `engine` the decisions. No dependency was added.
- No performance claim (ADR-0001): the Logon exchange reads one more field,
  and the replay is the existing resend path; nothing was measured.
- **Not done:** 789 is not consulted outside the Logon exchange; only the
  Logon's number is held, and a general queue of messages received across a
  gap is #71; the joint crash and takeover suite that exercises 789 across
  injected crashes is #89.
- The overlapping gap fill of an earlier revision (after the fallback request,
  a fill numbered with an already consumed Logon was dropped) no longer
  arises there, since a real request now ends the hold. The same shape remains
  possible elsewhere (a late 789 resend that stops below the Logon, then an
  answer whose fill starts lower and runs through it), and is answered by the
  re-request described in "A gap fill that spans the expectation", at the cost
  of one round trip.
