[![License](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)
[![Crates.io](https://img.shields.io/crates/v/ironfix-core.svg)](https://crates.io/crates/ironfix-core)
[![Downloads](https://img.shields.io/crates/d/ironfix-core.svg)](https://crates.io/crates/ironfix-core)
[![Stars](https://img.shields.io/github/stars/joaquinbejar/IronFix.svg)](https://github.com/joaquinbejar/IronFix/stargazers)
[![Issues](https://img.shields.io/github/issues/joaquinbejar/IronFix.svg)](https://github.com/joaquinbejar/IronFix/issues)
[![PRs](https://img.shields.io/github/issues-pr/joaquinbejar/IronFix.svg)](https://github.com/joaquinbejar/IronFix/pulls)

[![Build](https://img.shields.io/github/actions/workflow/status/joaquinbejar/IronFix/build.yml?branch=main&label=build)](https://github.com/joaquinbejar/IronFix/actions/workflows/build.yml)
[![Tests](https://img.shields.io/github/actions/workflow/status/joaquinbejar/IronFix/tests.yml?branch=main&label=tests)](https://github.com/joaquinbejar/IronFix/actions/workflows/tests.yml)
[![Coverage](https://img.shields.io/codecov/c/github/joaquinbejar/IronFix)](https://codecov.io/gh/joaquinbejar/IronFix)
[![Dependencies](https://img.shields.io/librariesio/github/joaquinbejar/IronFix)](https://libraries.io/github/joaquinbejar/IronFix)
[![Documentation](https://img.shields.io/badge/docs-latest-blue.svg)](https://docs.rs/ironfix-engine)

# IronFix

A FIX/FAST protocol engine for Rust, built as a Cargo workspace of focused
crates: the wire layer, the session layer, and a client and server engine.

## Overview

IronFix implements FIX tag=value messaging and the FAST encoding primitives from
the ground up — there is no upstream protocol library underneath it. The
tag=value decoder is zero-copy and dictionary-free: it scans bytes and hands out
field slices that borrow the input buffer, with schema validation available as a
separate, opt-in pass.

**Scope.** IronFix covers the FIX tag=value layer (FIX 4.0 to FIX 5.0 SP2 over
FIXT.1.1) and FAST. A binary order-entry stack, SOFH framing and a FIXP session
over SBE (via `ironsbe-core`), is being built inside the workspace
(`doc/adr/0003-fixp-sofh-in-workspace.md`, tracked in #94 to #97). The SOFH
framing codec (`ironfix-sofh`) and the sans-IO FIXP session core with its SBE
session messages (`ironfix-fixp`) exist; nothing drives them yet, because the
engine wiring (#96) does not exist.

**What works today**, end to end:

- **Decoding and encoding** FIX tag=value messages, including `BodyLength` (tag
  9) and `CheckSum` (tag 10) handling and length-prefixed Length/Data field
  pairs. Every malformed-input path is a typed error, never a panic.
- **Framing** over a Tokio codec (`FixCodec`) with a bounded read buffer and an
  unconditionally verified trailer. Both engines skip garbled inbound frames (a
  bad `CheckSum` or `BodyLength`, bytes before `8=`, `MsgType` not third) as
  FIX requires, in session and during the Logon handshake: the frame consumes
  no `MsgSeqNum`, is not counted as proof of life, and its gap is recovered by
  `ResendRequest`. An optional `garbled_frame_limit` logs out a link that keeps
  garbling. A frame above `max_message_size` still closes the session, after a
  Logout saying "message too large".
- **SOFH framing** in `ironfix-sofh`: the FIX Simple Open Framing Header v1.0
  (the Draft Standard of December 2016), the binary counterpart of
  `FixCodec`. `SofhHeader` encodes and decodes the 6-byte big-endian header
  (`Message_Length`, header included, then `Encoding_Type`); `EncodingType`
  names every value the v1.0 table registers (SBE 1.0 big- and
  little-endian, tag=value, FAST, FIXML and the rest) and preserves any other
  value rather than rejecting it, so a receiver can skip a message it has no
  codec for. `SofhCodec` is a Tokio codec that hands each payload out as a
  `Bytes` view of the read buffer, without copying the payload bytes. That
  view shares the buffer's allocation, so a frame kept alive pins it, and
  each refill that runs out of room while frames are kept allocates a new
  buffer and copies the unread tail: size the read buffer with
  `Framed::with_capacity`, or copy small payloads out, if you keep frames
  (see "Retaining frames" in `ironfix_sofh::codec`). The codec refuses a
  declared length below 7 bytes or above `with_max_message_size` (1 MiB by
  default) before reserving anything, and treats every framing error as
  fatal for the stream: SOFH has no resynchronisation anchor. It does not
  interpret payloads and nothing in the engine uses it yet.
- **A FIXP session core** in `ironfix-fixp`: the FIX Performance Session
  Layer v1.1 (the Draft Standard of April 2019, the highest version
  published; v1.0 is the April 2021 Technical Standard) for point-to-point
  sessions, client (`FixpClient`) and server (`FixpServer`).
  It is sans-IO: decoded session messages, application-message arrivals,
  commands and timer ticks go in with an explicit `Instant`, and messages to
  write, transport closes and events come out; it reads no clock and does no
  I/O. All 19 session messages of the FIXP SBE schema (id 2748, version 0)
  encode and decode on `ironsbe-core`, checked field by field against the
  schema published by FIX Trading Community. Negotiation and establishment
  (re-establishment included) with credentials left to the application,
  implicit sequencing with checked arithmetic, the Recoverable flow (gap
  detection, one bounded RetransmitRequest in flight, Retransmission
  validation and RetransmitReject, both as requester and as provider, with a
  configurable policy for a stalled retransmission), the Idempotent flow
  (NotApplied), Unsequenced and None flows, keepalive heartbeats and
  termination on counterparty silence, bounded handshake timeouts, the
  Terminate handshake, and the receiving side of a finalization (a
  counterparty's FinishedSending is answered with FinishedReceiving).
  Malformed input is a typed error and protocol violations are answered on
  the wire. What is implemented and tested, and every decision
  the specification leaves open, are listed in `doc/fixp_operations.md`.
  No driver uses it yet.
- **A client engine and a server engine** in `ironfix-engine`. `Initiator`
  dials over TCP and runs the initiator half of the Logon handshake. `Acceptor`
  serves inbound connections for one configured counterparty and runs the
  acceptor half: CompID authentication, a logon timeout, honouring the
  counterparty's `HeartBtInt`, and mirroring `ResetSeqNumFlag`.
  `AcceptorRegistry` serves many counterparties on one listener: it reads
  each inbound Logon once, routes it by the CompIDs (and configured sub and
  location IDs) in its standard header, bounded before anything is looked
  up, to a registered `Acceptor` or one an optional `SessionLookup` admits,
  and runs that session's handshake; a Logon it cannot route is closed
  without a reply, touching no store. A session the lookup admits stays
  only once a Logon for it gets past `from_admin` (it is evicted otherwise),
  and `with_max_sessions` caps how many it holds. Each session keeps its own
  sequence numbers, store and heartbeat, and checks its configured sub and
  location IDs on every inbound message. `EngineBuilder` terminates in any
  of them via `into_initiator()`, `into_acceptor()` or
  `into_acceptor_registry()`.
- **Any byte stream, not only TCP.** `Initiator::establish`,
  `Acceptor::serve_stream` and `AcceptorRegistry::serve_stream` run the same
  handshake and reactor over a stream the caller has already connected or
  accepted: anything `AsyncRead + AsyncWrite + Unpin + Send + 'static`, such
  as a TLS stream built with the TLS crate of your choice, a Unix socket, or
  a `tokio::io::duplex` pipe for tests without sockets. `connect`, `serve`
  and `accept` are the TCP dial or accept (with `TCP_NODELAY` set) followed by
  that same path. No public type gains a type parameter. The TCP path is
  unaffected: its socket is held by value, with no allocation and no dynamic
  call. A caller's stream is boxed once per session, and each outbound frame
  written in one piece then costs three dynamic calls and each read poll one
  (the `Pending` poll on every wakeup included); nothing has measured that
  cost. Pass the concrete stream type, not one already boxed, and a stream
  whose `poll_read` never swaps the `ReadBuf` it is given. See
  `doc/adr/0007-engine-over-any-stream.md`.
- **One session reactor shared by both roles.** Once Logon completes, the
  engine owns the socket: heartbeats and TestRequests at the negotiated
  interval, CompID and `SendingTime` validation, sequence-gap detection with
  bounded `ResendRequest` recovery, `SequenceReset` / gap fill, `PossDupFlag`
  and `OrigSendingTime` handling, session-level `Reject`, a write timeout
  (output the stream accepts none of for that long closes the session), the
  Logout handshake (whose timeout starts once the Logout has been written
  whole; a close whose Logout never got out is not graceful;
  `Connection::logout_with_text` puts a checked `Text` (58) on it), a typed
  `CloseReason` for every close (peer or local Logout with the peer's
  `Text`, logout timeout, heartbeat or write timeout, transport closed or
  failed, MsgSeqNum too low, garbled-frame limit, identity, `SendingTime`,
  store failure, a failed handshake, and more) handed to
  `Application::on_session_closed` (whose default forwards to `on_logout`
  for a session that reached Active) and read with
  `Connection::close_reason()` (`doc/adr/0025-typed-close-reason.md`), and
  `FIXT.1.1` BeginString with `ApplVerID`
  for FIX 5.0 sessions. A FIX 5.0 session also checks the application version
  its counterparty declares and uses against its own version plus
  `SessionConfig::allowed_appl_versions`: `DefaultApplVerID` is required by
  the acceptor on the Logon, and checked on the acknowledgement when present
  (or required, in strict mode); `ApplVerID` is checked on each application
  message, which is rejected (`SessionRejectReason` 18) if it names another
  version. The declared default is exposed as
  `Connection::counterparty_default_appl_version`; no dictionary is selected
  by it. `HeartBtInt = 0` disables heartbeating (ask for it
  with `SessionConfigBuilder::disable_heartbeats`), and any inbound message
  clears a pending TestRequest. `SendingTime` and `OrigSendingTime` are
  written in whole seconds on FIX 4.0 and FIX 4.1 sessions, whose `time` type
  has no fraction, and in milliseconds from FIX 4.2 on; inbound, both forms
  are accepted on every version.
- **Resend from store** in both roles. Attach a `MessageStore` with
  `Initiator::with_store`, `Acceptor::with_store` or `EngineBuilder::with_store`
  (`MemoryStore` in memory, or `FileStore`, a journal file that survives a
  restart and refuses to open over damage it cannot attribute to an
  interrupted write) and an inbound `ResendRequest` replays the stored
  application messages with `PossDupFlag = Y` and the original `SendingTime`
  in `OrigSendingTime`; administrative messages, and anything the store
  cannot produce, are covered by gap fill (a store that reports itself
  corrupted closes the session instead). The reactor never waits inside a
  write: frames go into a write buffer that is flushed while inbound is still
  read (a live frame is written through at once when the stream takes it),
  so two sides resending large backlogs, or sending live traffic, to
  each other at once do not block each other. A resend alternates with
  inbound reads in a bounded ratio, so a counterparty that never pauses
  cannot hold it back, and every message that takes a new number follows it (a
  counterparty's Logout is answered after the resend it is owed). A session
  starts from the store's counters unless it resets the sequence. Store
  writes are fallible and ordered: a frame is filed and the next sender number
  persisted before its bytes are written, and the next target number is
  persisted before an inbound message is acted on.
  `with_store_failure_policy` chooses between warning and continuing (the
  default, which gives no crash guarantee) or failing closed, writing nothing
  the store has not accepted. Every store call is bounded by
  `with_store_timeout`. A store belongs to exactly one engine. The acceptor
  touches its store only once the peer is authenticated (`from_admin` accepted
  it), and resets it only for a Logon that passes every check, so a refused
  `ResetSeqNumFlag` Logon cannot clear it. With a store attached, a Logon
  refused before authentication (wrong version, encryption, CompIDs, clock or
  credentials) gets no reply; a second Logon for a session already live gets
  no reply in every case; an authenticated peer refused after that
  (`DefaultApplVerID` on a FIX 5.0 session, a `ResetSeqNumFlag` Logon not
  numbered 1, `HeartBtInt`, `NextExpectedMsgSeqNum` when it is used,
  `MsgSeqNum`) gets a filed Logout saying why.
- **An outbound gate and per-message send outcomes** in both roles.
  `Application::to_app_checked` runs on every new outbound application
  message, whether it came through `Connection::send` or
  `Connection::send_tracked`, when it is about to be written, and can veto
  it (the equivalent of QuickFIX's `DoNotSend`): a vetoed message spends no
  `MsgSeqNum` and is never filed, so the next message takes its number. The
  default forwards to `to_app`, so an application that overrides only
  `to_app` is unchanged, and costs no allocation beyond `to_app`'s own. An
  override returns a `SendVerdict`: `SendVerdict::ready` for a decision
  taken at once (no allocation), `SendVerdict::new` for one that must wait.
  A replay of a filed frame is resent as filed and is
  not gated (see below). Administrative messages (Logon, Logout, Heartbeat,
  TestRequest, ResendRequest, SequenceReset, Reject, XmlMessage) go through
  `to_admin` and cannot be vetoed. `Connection::send_tracked` reports each
  message's fate as a `SendOutcome`: `Sent` with the `MsgSeqNum` and
  `SendingTime` (in the session's precision) the counterparty reads, once a
  flush of the session's write buffer covering the frame completes, and
  `filed`, which says whether the store confirmed it filed the frame (false
  without a store, and under `StoreFailurePolicy::Continue` after a failed
  or timed out filing; false means filing was not confirmed, so the frame
  may or may not be replayed, since a store can fail after saving it); `NotSent` with a `NotSentReason` when no byte
  reached the stream and no number was spent (vetoed, invalid, refused by
  the store under `CloseSession`, sequence exhausted, session closed, Logout
  pending, or discarded when the session ended, in the queue or behind a
  resend); `Unknown` with the spent number when the frame was buffered (or
  being filed) and the session ended before a flush covering it completed:
  a number is spent when the frame is buffered. An `Unknown` order may be
  live: do
  not resubmit it blindly, reconcile it by `ClOrdID` after the next Logon
  (an `ExecutionReport`, or an `OrderStatusRequest`), and if it must be
  resubmitted reuse the `ClOrdID` with `PossResend` (97) = Y. Its frame is
  replayed only if it was filed, no reset erased it (`reset_on_disconnect`,
  or `ResetSeqNumFlag` on the next Logon), the store still holds it, and the
  counterparty asks. `Connection::send` stays fire-and-forget and allocates
  nothing for tracking (`doc/adr/0023-outbound-veto-and-send-outcomes.md`).
- **An optional per-session outbound throttle** in both roles, attached with
  `with_throttle` on the `Initiator`, the `Acceptor` or the `EngineBuilder`
  (a session an `AcceptorRegistry` routes keeps its `Acceptor`'s). A
  `ThrottleConfig` holds up to 16 token-bucket budgets, each a rate per
  window and a burst (default 1, which keeps a session within a venue limit
  of `rate` per window wherever the venue places it), with an optional
  classifier so cancels can have a budget of their own. A message that finds
  no token is held in order, up to `max_depth`, or refused, per budget
  (`ThrottlePolicy::Queue` or `Refuse`); a refusal reports `NotSent` with
  `Throttled` through `send_tracked`, before a `MsgSeqNum` is spent or the
  store touched, and a held message goes through `to_app_checked` only when
  it is released. Administrative messages (Heartbeats and TestRequest
  answers, ResendRequests, gap fills, Rejects, Logouts) and replays are never
  throttled; this session's Logout goes out at once and what the throttle
  holds then reports `DiscardedByThrottle`. `Connection::inbound_app_messages`
  counts the counterparty's application messages, so an application can
  refuse over-rate ones in `from_app`. The decision is synchronous over the
  driver's clock, tested on a paused Tokio clock; a throttled send allocates
  nothing more than an unthrottled one in steady state, and a budget's queue
  keeps the capacity of its deepest fill until the session ends: `max_depth`
  bounds the messages held, and the queue's allocation may round up past it
  (128 slots for a depth of 65) (`doc/adr/0024-outbound-throttle.md`).
- **`NextExpectedMsgSeqNum` (789) on Logon**, opt-in with
  `SessionConfig::send_next_expected_msg_seq_num` on FIX.4.4 and FIXT.1.1
  sessions (refused below FIX.4.4), in both roles. The Logon and its
  acknowledgement declare the next `MsgSeqNum` each side expects (1 on a
  `ResetSeqNumFlag` Logon). A counterparty's 789 below the session's own Logon
  makes it resend exactly the missed range once Active, through the resend
  path above; one above what was sent refuses the Logon with a Logout, before
  `on_logon`. The resend stops before the session's own Logon. A side that
  declared 789 and receives a gapped Logon from a counterparty that declared
  it too sends no `ResendRequest`, which would cross that resend: it holds the
  Logon, consumes its number once the resend fills the gap below it, and
  falls back to one `ResendRequest` when the gap makes no progress for one
  `resend_timeout`, a resend that stalls partway included. Between two IronFix engines a restarted side
  gets back what it missed with no `ResendRequest` either way. 789 is
  bilateral: enable it on both sides, since a counterparty such as
  QuickFIX/C++ that declares it waits for a resend a session without the flag
  never sends (`doc/adr/0021-next-expected-msg-seq-num.md`).
- **A typestate session FSM** and checked sequence arithmetic in
  `ironfix-session`.
- **A QuickFIX XML dictionary loader** and a `Validator` in
  `ironfix-dictionary`, with four QuickFIX dictionaries embedded verbatim:
  FIX 4.2 (`Dictionary::fix42()`), FIX 4.4 (`Dictionary::fix44()`), the
  FIXT 1.1 transport dictionary (`Dictionary::fixt11()`) and the FIX 5.0 SP2
  application dictionary (`Dictionary::fix50sp2()`). `SessionDictionary`
  composes FIXT 1.1 with an application dictionary of any version FIXT 1.1
  carries (FIX 4.0 through 5.0 SP2), and `Validator::for_session` validates
  against the pair with QuickFIX-like semantics: `BeginString` must be
  `FIXT.1.1`, header and trailer come from the transport, the body from the
  application, and admin messages entirely from the transport.
- **A FIX Orchestra 1.0 loader** in `ironfix-dictionary`:
  `Dictionary::from_orchestra_xml` reads the base scenario of an Orchestra
  repository into the same `Dictionary` model and returns, next to it, an
  `OrchestraReport` of what the model cannot hold (other scenarios,
  conditional rules, forbidden or constant presence, value constraints,
  workflow). It is tested against the FIX Trading Community's FIX 4.4
  repository, compared with the embedded QuickFIX FIX 4.4 dictionary
  (`doc/adr/0013-load-fix-orchestra-repositories.md`).
- **A zero-copy repeating-group reader** in `ironfix-dictionary`. Build a
  `MessageLayout` once per message type from a dictionary (or describe the
  groups at compile time with `GroupSpec` / `GroupSet`), then read a decoded
  message's groups as borrowed views: `layout.read(&msg, 453)` checks the
  whole group with the validator's own walk and yields one `GroupEntry` per
  entry, with own-level field lookup and nested groups; `GroupSet::field`
  finds a message-level field without taking the same tag inside a group
  entry for it. A malformed group is
  a typed `GroupError`, never a partial view. A successful read (iteration
  and field lookup included) and a read that fails with a structural error
  allocate nothing, for groups of up to 512 entry-level members (every group
  of the embedded dictionaries); a wider group allocates one small buffer per
  walk, and errors that carry strings (`MsgTypeMismatch`) allocate them. The
  allocation-free paths are proved with a counting allocator in
  `ironfix-dictionary/tests/group_reader_allocations.rs`. It is opt-in: the
  engine does not call it.
- **Code generation.** `#[derive(FixMessage)]` and `#[derive(FixField)]` in
  `ironfix-derive` implement the `ironfix-core` traits with typed
  `DecodeError` / `EncodeError` paths (compile-tested in
  `ironfix-derive/tests/`), and `ironfix-codegen` emits Rust from a loaded
  `Dictionary`: tag constants and data-only structs, one per message, per
  component a message reaches and per repeating-group definition, each
  referenced by name wherever it is used, members in XML order
  (`doc/adr/0019-shared-component-and-group-types-in-the-default-output.md`).
  A golden sample and the full FIX 4.2 and FIXT 1.1 outputs are
  compile-tested in `ironfix-codegen/tests/`, and the full data structs of
  all four embedded dictionaries, FIX 5.0 SP2 included, by the unpublished
  `ironfix-codegen-check` crate under `make lint` and `make doc`. Opt-in,
  `CodeGenerator::generate_views` emits borrowed message views with typed
  accessors (`rust_decimal::Decimal` for prices and quantities, each value
  checked against the validator's grammar), an enumeration per field with
  declared values (an undeclared value reads as `Other`), `const` group
  layouts for the group reader, and writers that check every value and send a
  body in XML order (each group entry delimiter first) to a generated `Sink`
  (any `FnMut(u32, &[u8])` closure, or the tag=value `Encoder` through a
  LENGTH/DATA-aware impl). The output carries no `#[allow]`. The full views of
  the embedded FIX 4.4, FIX 4.2 and FIXT 1.1 dictionaries are generated by
  the unpublished `ironfix-codegen-check` crate's build script and checked by
  `make lint` and `make doc`; golden files (a sample, FIXT 1.1, and FIX 4.4
  Heartbeat, Logon and NewOrderSingle) are exercised against real frames in
  `ironfix-codegen/tests/generated_views.rs`. The FIX 5.0 SP2 views (about
  31 MB) were checked with clippy out of tree only
  (`doc/adr/0012-generated-views-enums-and-writers.md`; why they stay out of
  CI: `doc/adr/0019-shared-component-and-group-types-in-the-default-output.md`).
- **FAST primitives** in `ironfix-fast`: stop-bit encode/decode of unsigned
  and signed integers, ASCII strings and byte vectors, each in nullable and
  non-nullable form, plus presence maps, all round-trip tested. The `Operator`
  table and `Operator::transfer` (which decides, from the operator, the field's
  optionality and the presence map, where a field's value comes from) are
  implemented; *applying* an operator to produce a value is not.

## What is not implemented yet

This list is deliberately explicit. If a capability is not named under "What
works today" and appears below, it does not exist in the code — do not plan
around it.

- **Replays are not gated by `to_app_checked`.** The answer to a
  `ResendRequest`, and the resend a counterparty's `NextExpectedMsgSeqNum`
  (789) asks for, write each filed application frame as it was filed, with
  `PossDupFlag = Y`, without calling the outbound gate. QuickFIX calls
  `toApp` on each resent application message and gap-fills one that throws
  `DoNotSend`; IronFix does not yet, so a gate cannot stop a stale order from
  being resent.
- **Throttle limits.** Replays and administrative messages take no token, so
  a venue that counts them against its limit can see a large resend, or the
  heartbeats, on top of the budget. A budget's state does not outlive its
  session: a reconnect starts with full budgets. The release timer has
  Tokio's one-millisecond resolution, so a budget faster than one message per
  millisecond keeps its rate only with a burst of at least a millisecond's
  worth of tokens. The inbound side is a count, not an engine-enforced limit.
- **Store limits.** There is no memory-mapped store. `FileStore`'s journal
  grows with every outbound frame until the sequence is reset: its counters
  sit in two fixed slots, so inbound traffic does not grow it, and compaction
  (`FileStore::compact`, or on its own past an opt-in threshold) reclaims only
  frames filed again under the same number. A compaction blocks the store's
  calls while it copies the journal
  (`doc/adr/0022-file-store-writer-thread-and-compaction.md`). Opening it
  still reads the whole journal, and a journal in the unreleased version-1
  format is refused, not migrated. Only its `SyncPolicy::EveryWrite` (the
  default) makes every acknowledged write survive an OS crash or a power
  loss; `EveryN` and `Never` survive a process crash only. Its guarantees reach the wire only under
  `StoreFailurePolicy::CloseSession`, and are stated for Unix only
  (`doc/adr/0006-file-store.md`). The record of a reset owed to the next
  session lives in the engine's memory, not in the store, so a crash forgets
  it (#111). Inbound
  application messages are delivered at most once: a crash, or a session
  close whose application queue does not drain in time, loses the messages
  still queued. The close logs the lost range; nothing reports a loss across
  a restart yet (#105). Inbound frames are not filed.
- **One session per `Initiator` or `Acceptor`.** `into_initiator()` and
  `into_acceptor()` return `EngineError::Configuration` unless exactly one
  `SessionConfig` was added (`ironfix-engine/src/builder.rs`). Several
  acceptor sessions on one listener go through `AcceptorRegistry`
  (`into_acceptor_registry()`); there is no multi-session initiator. The
  registry's routing key does not include `BeginString`, so two sessions
  that differ only by FIX version cannot share a registry, and
  `into_acceptor_registry()` accepts a builder store only for exactly one
  session (register each `Acceptor` with its own store instead). The
  registry bounds each connection, not how many there are: capping the
  connections still in their Logon handshake is the consumer's job, in its
  accept loop.
- **No TLS.** There is no `rustls` dependency anywhere. `ironfix-transport`
  contains `FixCodec` only, and the engines open plain TCP themselves
  (`Initiator::connect` calls `TcpStream::connect`, `Acceptor::serve` serves a
  `TcpStream`). To run FIX over TLS, build the TLS stream yourself and hand it
  to `Initiator::establish` or `Acceptor::serve_stream`: IronFix chooses no
  TLS stack and no crypto provider. See "Current limitations" in
  `ironfix-engine/src/lib.rs`.
- **Async only.** Everything that touches a socket runs on Tokio. There is no
  synchronous mode, no kernel-bypass path, and no busy-polling transport. A
  sans-IO session core with Tokio as one driver is the accepted direction
  (`doc/adr/0002-session-driver.md`, tracked in #90 to #93); none of it exists
  yet.
- **Only four dictionaries are embedded**: FIX 4.2, FIX 4.4, FIXT 1.1 and
  FIX 5.0 SP2 (`ironfix-dictionary/spec/`, vendored verbatim from QuickFIX).
  FIX 4.0, 4.1, 4.3, 5.0 and 5.0 SP1 require
  `Dictionary::from_quickfix_xml` with your own XML
  (`ironfix-dictionary/src/loader.rs`). `SessionDictionary` does not read
  `ApplVerID(1128)`: you choose the application dictionary when you build it.
  `Validator::new` does not check `BeginString`; only `Validator::for_session`
  does. The `Validator` is *not* invoked by the engine or the codec; you call
  it yourself (`ironfix-engine/src/lib.rs`).
- **The embedded FIXT 1.1 dictionary deviates from FIXT 1.1 on Logon.** The
  vendored QuickFIX `FIXT11.xml` defines the `MsgTypeGrp` component with no
  members and does not define `NoMsgTypes(384)` or `MsgDirection(385)`, so a
  Logon carrying the `NoMsgTypes` group is reported as invalid. The file is
  kept verbatim; to accept the group, load a FIXT 1.1 dictionary that defines
  it with `Dictionary::from_quickfix_xml` and compose that
  (`ironfix-dictionary/spec/README.md`).
- **Orchestra loading is tested on FIX 4.4 only.** The only Orchestra
  repository exercised is the FIX Trading Community's `OrchestraFIX44.xml`, a
  test fixture that is not embedded or published. `FIX.Latest` repositories
  are rejected (`DictionaryError::UnsupportedVersion`): FIX Latest names no
  fixed FIX version. So is a repository named `FIXT` whose version is not
  `FIXT.1.1`, which includes the FIX Trading Community's FIXT session
  repository (it declares `FIX.5.0SP2_EP247`). Only the `base` scenario is
  loaded.
- **Generated code has no consumer.** Nothing in the workspace uses the
  derives or `ironfix-codegen` output (data structs or views) at run time
  (`ironfix-codegen-check` only compiles generated code: the data structs
  of the four embedded dictionaries, the views of the embedded FIX 4.4,
  FIX 4.2 and FIXT 1.1 dictionaries, and both outputs for the FIX 4.4
  Orchestra repository), so field
  access on the session path is untyped tag lookup
  (`ironfix-codegen/src/lib.rs`). Generated views cover the message body
  only, and are generated from one dictionary: a FIXT.1.1 + FIX 5.0
  composition is not an input.
- **FAST has no template layer.** There is no FAST template XML parser, no
  operator application (copy, delta, increment, tail), no decimal codec and no
  sequence decoding, so `ironfix-fast` decodes the fields of a message only when
  something else supplies their order. There is also no UDP multicast receiver
  and no wiring into the session or engine path (`ironfix-fast/src/lib.rs`).
- **No binary order-entry session can run yet.** `ironfix-sofh` frames and
  `ironfix-fixp` runs the FIXP session logic, but no driver composes them
  over a socket: the engine wiring behind a `fixp` feature is #96. Of FIXP
  itself, sending a finalization (this side never sends FinishedSending, so
  it never finalizes a session itself), multiplexing several sessions on one
  transport, datagram transports, multicast, WebSocket and session
  persistence across process restarts are not implemented; the application
  SBE schemas a venue uses are out of `ironfix-fixp`'s scope. The SOFH v1.1
  Release Candidate is not implemented: the header is read and written
  big-endian only (v1.1 RC1 allows little-endian by bilateral agreement), and
  its SBE 2.0 encoding types (`0x5BE1`, `0xEB51`) are decoded as
  unregistered values, preserved as received.
- **No recorded benchmark baseline.** A criterion harness now exists (see
  Benchmarks below): `ironfix-tagvalue`, `ironfix-fast`, `ironfix-transport`,
  `ironfix-sofh` and `ironfix-store` each carry a `benches/` target run by
  `make bench`. It ships no saved baseline
  and no published figures, so every latency and throughput target in `doc/`
  remains a design goal, unmeasured until you run it on hardware you name.

## FIX version support

The session layer is version-parameterised by `BeginString`, and there is a
runnable client/server example pair for each version below. "Dictionary
embedded" means a dictionary is embedded in `ironfix-dictionary` and loadable
without extra files. The FIX 5.0 family runs over a FIXT 1.1 session, so it
needs two dictionaries: the FIXT 1.1 transport dictionary (`Dictionary::fixt11()`,
embedded) and the application dictionary for the version, composed with
`SessionDictionary`. The same composition accepts a FIX 4.x application
dictionary, for a counterparty that carries FIX 4.x messages over FIXT 1.1
(ApplVerID 2 to 6).

| Version | BeginString | Example pair | Dictionary embedded |
|---------|-------------|--------------|---------------------|
| FIX 4.0 | `FIX.4.0` | yes | no |
| FIX 4.1 | `FIX.4.1` | yes | no |
| FIX 4.2 | `FIX.4.2` | yes | **yes** (`Dictionary::fix42()`) |
| FIX 4.3 | `FIX.4.3` | yes | no |
| FIX 4.4 | `FIX.4.4` | yes | **yes** (`Dictionary::fix44()`) |
| FIX 5.0 | `FIXT.1.1` | yes | transport only (FIXT 1.1); application no |
| FIX 5.0 SP1 | `FIXT.1.1` | yes | transport only (FIXT 1.1); application no |
| FIX 5.0 SP2 | `FIXT.1.1` | yes | **yes** (`Dictionary::fixt11()` + `Dictionary::fix50sp2()`) |

The embedded dictionaries are the QuickFIX data dictionaries, redistributed
under the QuickFIX Software License, Version 1.0
(`ironfix-dictionary/spec/LICENSE-QUICKFIX`; provenance and checksums in
`ironfix-dictionary/spec/README.md`). This product includes software developed
by quickfixengine.org (<http://www.quickfixengine.org/>).

The FIX 4.4 Orchestra repository the tests load is the FIX Trading
Community's, under the Apache License, Version 2.0
(`ironfix-dictionary/tests/fixtures/orchestra/LICENSE`; provenance and
checksums in `ironfix-dictionary/tests/fixtures/orchestra/README.md`). It is a
test fixture only, left out of the published `ironfix-dictionary` package.

The FIXP SBE message schema the `ironfix-fixp` conformance test reads is FIX
Protocol Ltd.'s, published by FIX Trading Community under the Creative Commons
Attribution-NoDerivatives 4.0 International License, and is vendored
unmodified (`ironfix-fixp/spec/LICENSE-FIXP`; provenance and checksums in
`ironfix-fixp/spec/README.md`). It is a test input only, left out of the
published `ironfix-fixp` package; the codec is written by hand and checked
against it.

## Crate Organization

| Crate | Description |
|-------|-------------|
| `ironfix-core` | Fundamental types, traits, and error definitions; depends on no other IronFix crate |
| `ironfix-dictionary` | QuickFIX XML and FIX Orchestra loading, schema types, and the opt-in `Validator` |
| `ironfix-tagvalue` | Zero-copy tag=value decoding and encoding; dictionary-free |
| `ironfix-session` | Session-layer protocol logic: typestate FSM, sequences, heartbeats. No I/O |
| `ironfix-store` | The `MessageStore` trait, `MemoryStore`, and the persistent `FileStore` |
| `ironfix-transport` | `FixCodec`, a Tokio codec that frames FIX messages; depends on `ironfix-tagvalue` only. No TCP helpers, no TLS |
| `ironfix-sofh` | `SofhCodec`, a Tokio codec for the Simple Open Framing Header v1.0 that frames SBE and other binary encodings; depends on no other IronFix crate. Not published yet |
| `ironfix-fixp` | The FIXP v1.1 session core, sans-IO: `FixpClient`, `FixpServer`, and the SBE session messages on `ironsbe-core`; depends on `ironfix-core` and `ironsbe-core` only. Not published yet |
| `ironfix-fast` | FAST encoding/decoding primitives: stop-bit, presence maps, the operator table; depends on no other IronFix crate. No template layer |
| `ironfix-codegen` | Build-time Rust generation from a `Dictionary`: data structs, and opt-in views, enumerations and writers (no in-workspace consumer) |
| `ironfix-codegen-check` | Not published. A CI check: its build script generates the full views of the embedded FIX 4.4, FIX 4.2 and FIXT 1.1 dictionaries and the workspace lints compile them |
| `ironfix-derive` | `#[derive(FixMessage)]` / `#[derive(FixField)]` for the `ironfix-core` traits (no in-workspace consumer) |
| `ironfix-engine` | The composition root: `Initiator`, `Acceptor`, `EngineBuilder`, `Connection`, the `Application` trait |
| `ironfix-example` | Umbrella facade (`prelude`) plus the runnable examples |

There is no `ironfix` facade crate. The umbrella re-exports live in
`ironfix-example`.

## Installation

Each crate is published separately on crates.io. For the engine:

```toml
[dependencies]
ironfix-core = "0.4"
ironfix-engine = "0.4"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "net"] }
```

## Quick Start

### Client

Connect as an initiator, send a `NewOrderSingle`, then log out. The engine owns
the socket: it dials, frames, performs the Logon handshake, and stamps the
header, `MsgSeqNum` and trailer on everything you send.

```rust,no_run
use std::sync::Arc;
use std::time::Duration;

use ironfix_engine::{Initiator, NoOpApplication, OutboundMessage};
use ironfix_engine::SessionConfig;
use ironfix_core::MsgType;
use ironfix_core::types::CompId;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Sender is this client; target is the venue (the server below).
    let config = SessionConfig::new(
        CompId::new("CLIENT")?,
        CompId::new("VENUE")?,
        "FIX.4.4",
    )
    .with_heartbeat_interval(Duration::from_secs(30));

    // Replace NoOpApplication with your own `Application` impl to receive
    // on_logon / from_app / from_admin callbacks.
    let initiator = Initiator::new(config, Arc::new(NoOpApplication))
        .with_connect_timeout(Duration::from_secs(5));
    let connection = initiator.connect("127.0.0.1:9876").await?;

    let mut order = OutboundMessage::new(MsgType::NewOrderSingle);
    order
        .push_str(11, "ORD001")
        .push_str(55, "AAPL")
        .push_char(54, '1')
        .push_uint(38, 100)
        .push_str(44, "150.50")
        .push_char(40, '2');
    connection.send(order).await?;

    connection.logout().await?;
    connection.wait_closed().await;
    Ok(())
}
```

### Server

`EngineBuilder` terminates in either engine: `into_initiator()` produces the
client above, and `into_acceptor()` produces an `Acceptor` that establishes
sessions on inbound connections. Both engines hand the socket to the same
session reactor once the Logon handshake completes. To run either over a
stream you opened yourself (TLS, a Unix socket, an in-memory pipe), use
`Initiator::establish` or `Acceptor::serve_stream` in place of `connect` or
`accept`.

```rust,no_run
use ironfix_core::types::CompId;
use ironfix_engine::{EngineBuilder, SessionConfig};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Sender is this venue; target is the client it expects to log on.
    let config = SessionConfig::new(
        CompId::new("VENUE")?,
        CompId::new("CLIENT")?,
        "FIX.4.4",
    );

    // Add `.with_application(your_app)` to receive the session callbacks.
    let acceptor = EngineBuilder::new()
        .add_session(config)
        .into_acceptor()?;

    let listener = TcpListener::bind("0.0.0.0:9876").await?;
    let connection = acceptor.accept(&listener).await?;
    connection.wait_closed().await;
    Ok(())
}
```

See `ironfix-example/examples/fix44_engine_client.rs` for the client flow with a
real `Application` implementation, and `fix44_server.rs` for the matching
`Acceptor`-based server that answers each `NewOrderSingle` with an
`ExecutionReport`.


## 🛠 Makefile Commands

This project includes a `Makefile` with common tasks to simplify development.
Here's a list of useful commands:

### 🔧 Build & Run

```sh
make build         # Compile the workspace
make release       # Build the workspace in release mode
make run EXAMPLE=fix44_server   # Run one example (the workspace has no binaries)
```

### 🧪 Test & Quality

```sh
make test          # Run all tests
make fmt           # Format code
make fmt-check     # Check formatting without applying
make lint          # Run clippy with warnings as errors
make lint-fix      # Auto-fix lint issues
make fix           # Auto-fix Rust compiler suggestions
make check         # Run fmt-check + lint + test + doc + check-spanish
make pre-push      # Run fix + fmt + lint-fix + test + check-spanish + readme + doc
```

### 📦 Packaging & Docs

```sh
make doc           # Fail on any undocumented public item (clippy -D missing_docs)
make doc-open      # Build and open Rust documentation
make create-doc    # Generate internal docs
make readme        # No-op: README.md is hand-maintained in this workspace
make publish       # Explain how to publish; see publish-all
make publish-all   # Publish all crates in dependency order, fail-fast
```

Publishing reads `CARGO_REGISTRY_TOKEN` from the environment — it is never
passed on a command line. Preview the sequence without touching crates.io with
`make publish-all DRY_RUN=1`.

### 📈 Coverage & Benchmarks

```sh
make coverage            # Generate code coverage report (XML)
make coverage-html       # Generate HTML coverage report
make open-coverage       # Open HTML report
make bench               # Run the criterion benchmarks
make bench-quick         # Reduced sample count; a smoke run, not a measurement
make bench-build         # Compile the benchmarks without running them
make bench-show          # Open the criterion HTML report
make bench-save          # Save the current run as a named baseline
make bench-compare       # Compare the current run against a saved baseline
make bench-clean         # Remove benchmark data
```

Benchmarks cover the hot paths: tag=value decode/encode and checksum
(`ironfix-tagvalue`), the FAST stop-bit and presence-map primitives
(`ironfix-fast`), the `FixCodec` framing loop (`ironfix-transport`), the
`SofhCodec` framing loop (`ironfix-sofh`), and the `FileStore` journal
(`ironfix-store`, `file_store`: filing and sequence writes under each
`SyncPolicy`, a resend page, and reopening a 10 000-frame journal).

ℹ️ The harness ships **no recorded baseline and no published figures**. Every
performance number in `doc/` is a design target; treat any figure as unmeasured
until you have produced it yourself with `make bench` on hardware you name.

### 🧪 Git & Workflow Helpers

```sh
make git-log             # Show commits on current branch vs main
make check-spanish       # Enforce English-only sources and docs (runs in CI)
make zip                 # Create zip without target/ and temp files
make tree                # Visualize project tree (excludes common clutter)
```

### 🤖 GitHub Actions (via act)

```sh
make workflow-build      # Simulate build workflow
make workflow-lint       # Simulate lint workflow
make workflow-test       # Simulate test workflow
make workflow-coverage   # Simulate coverage workflow
make workflow            # Run all workflows
```

ℹ️ Requires act for local workflow simulation and cargo-tarpaulin for coverage.

## Examples

All examples live in `ironfix-example/examples/`. Each FIX version has a
client/server pair; run the server first, then the client in another terminal.

```bash
# Start a FIX 4.4 server
cargo run --example fix44_server

# In another terminal, start the client
cargo run --example fix44_client
```

Per-version pairs. Only `fix44_server` runs on the engine's `Acceptor`; the
other servers hand-roll their accept loop with a raw `Decoder` / `Encoder` and
implement no real session behaviour, so treat them as wire-format demos rather
than templates:

- `fix40_server` / `fix40_client` — FIX 4.0 (port 9870)
- `fix41_server` / `fix41_client` — FIX 4.1 (port 9871)
- `fix42_server` / `fix42_client` — FIX 4.2 (port 9872)
- `fix43_server` / `fix43_client` — FIX 4.3 (port 9873)
- `fix44_server` / `fix44_client` — FIX 4.4 (port 9876)
- `fix50_server` / `fix50_client` — FIX 5.0 over FIXT.1.1 (port 9880)
- `fix50sp1_server` / `fix50sp1_client` — FIX 5.0 SP1 (port 9881)
- `fix50sp2_server` / `fix50sp2_client` — FIX 5.0 SP2 (port 9882)

Engine and concurrency examples:

- `fix44_engine_client`: the client flow driven by `Initiator`, which owns the
  socket, framing, Logon and heartbeats. Pairs with `fix44_server`.
- `fix44_server_channel`: per-connection reader tasks hand decoded messages to
  a single processor task over an mpsc channel, keeping business logic off the
  read path.

FAST examples:

- `fast_server` / `fast_client`: FAST encode/decode over a socket (port 9890)
- `fast_server_lockfree`: a generator thread and an encoding broadcaster
  thread joined by a bounded lock-free `crossbeam-channel`, both outside the
  Tokio runtime

## Docker

`Docker/` holds a Dockerfile per example server (the eight FIX versions plus
FAST), each a static musl build on Alpine. Build and run commands are in
`Docker/README.md`; CI builds the images through `docker.yml` when they or the
examples change.

## Documentation

- `doc/fix_operations.md` — the FIX operations specification this engine
  conforms to, plus the implementation checklist. This is the authority for
  message layouts, required tags and session semantics.
- `doc/architecture.md` — a **forward-looking design target**, not a description
  of the current code. Read its status banner before relying on anything in it.

## Contribution and Contact

We welcome contributions to this project! If you would like to contribute, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and ensure that the project still builds and all tests pass.
4. Commit your changes and push your branch to your forked repository.
5. Submit a pull request to the main repository.

If you have any questions, issues, or would like to provide feedback, please feel free to contact the project
maintainer:

### **Contact Information**
- **Author**: Joaquín Béjar García
- **Email**: jb@taunais.com
- **Telegram**: [@joaquin_bejar](https://t.me/joaquin_bejar)
- **Repository**: <https://github.com/joaquinbejar/IronFix>
- **Documentation**: <https://docs.rs/ironfix-engine>

We appreciate your interest and look forward to your contributions!

**License**: MIT. The QuickFIX data dictionaries vendored in
`ironfix-dictionary/spec/` remain under the QuickFIX Software License,
Version 1.0 (`ironfix-dictionary/spec/LICENSE-QUICKFIX`). The FIXP SBE schema
vendored in `ironfix-fixp/spec/` remains under CC BY-ND 4.0
(`ironfix-fixp/spec/LICENSE-FIXP`) and, like the Orchestra test fixture, is
not part of any published package.

<!-- related-projects:start -->
## Related projects

Repositories by the same author that this project depends on, and repositories that depend on it.

### Depends on

| Repository | Description |
|------------|-------------|
| [IronSBE](https://github.com/joaquinbejar/IronSBE) | Simple Binary Encoding for Rust: `ironfix-fixp` encodes the FIXP session messages with `ironsbe-core`. |

### Used by

| Repository | Description |
|------------|-------------|
| [fauxchange](https://github.com/joaquinbejar/fauxchange) | Exchange-in-a-box: local options exchange simulator with realistic matching, FIX/WS/REST APIs and historical replay. |
| [otc-rfq](https://github.com/joaquinbejar/otc-rfq) | OTC Request-for-Quote engine with REST, SBE streaming and FIX/WebSocket/gRPC venue connectivity. |

<!-- related-projects:end -->
