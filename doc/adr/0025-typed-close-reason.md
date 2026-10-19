# ADR-0025: A typed close reason, and a Logout with Text

- **Status:** Accepted (issue #69, in the plan the owner approved)
- **Date:** 2026-10-19

## Context

When a session ended, the application learned only that it ended:
`Application::on_logout` took the `SessionId` alone, and `Connection`
exposed a closed flag. The reactor knew why (a counterparty Logout, our own
Logout, a heartbeat timeout, a dropped transport, a MsgSeqNum too low, and
more) but kept it as a `String` for one log line. Cancel on disconnect has to
tell an orderly Logout from a TCP loss or a timeout, and a kill switch that
logs out has to say why on the wire. Issue #69 asks for a typed reason on
both the application and the connection, and for a Logout carrying `Text`
(58).

`doc/fix_operations.md` gives Logout an optional `Text` (58) "Logout
reason", and says nothing on its length, its character set, or how an
engine reports a close to its application. The semantics below are engine
behaviour.

Constraints any answer keeps:

- additive only at v0.4.1: existing `Application` implementors compile and
  behave unchanged; `Connection::wait_closed` keeps its signature;
- no typestate or sequence change;
- the graceful flag that decides `reset_on_logout` keeps its meaning,
  including the downgrade of a close whose own Logout was never written
  whole (issue #142), and the reported reason agrees with it;
- no reason carries a frame, so no credential (554, 925, 96) can leak
  through one; the counterparty's `Text` is bounded and never parsed.

## Decision

1. **`CloseReason`** (`ironfix_engine::close`, re-exported at the root):
   a `#[non_exhaustive]` enum whose variants are all `#[non_exhaustive]`
   struct variants, so new close paths (the TLS failure #81 will add) and new
   fields are minor changes. Every `closed(..)` site of the reactor builds one
   directly; nothing matches on a string. Structured data only: sequence
   numbers, a tag, a size, an `io::ErrorKind`, a duration, and the one free
   text of a Logout.
2. **The graceful flag is the reason.** The reactor's internal outcome lost
   its separate `graceful: bool`; `CloseReason::is_graceful()` is true for
   `LocalLogout`, `PeerLogout` and `LogoutTimeout` exactly where the old flag
   was true. The close-time downgrade (own Logout still in the write buffer)
   rewrites the reason to `LogoutUnwritten`, which is not graceful, so the
   two cannot disagree.
3. **Why we logged out** travels in `LogoutCause` (`Requested { text }`,
   `HandlesDropped`, `ResendStalled { expected, attempts }`), recorded when
   our Logout is fed and reported by `LocalLogout`, `LogoutTimeout` or
   `LogoutUnwritten`. A stalled resend is therefore a cause of a Logout
   exchange, not a close of its own: the session still logs out gracefully.
4. **`Application::on_session_closed(&SessionId, &CloseReason)`**, with a
   default that calls `on_logout` when `CloseReason::was_active()`. The
   engine calls it, instead of `on_logout`, on every close of an Active
   session, and also when a Logon handshake fails after `on_create`
   (`CloseReason::LogonFailed`), which the default does not forward: exactly
   the calls `on_logout` received before.
5. **`Connection::close_reason() -> Option<CloseReason>`**, backed by a
   `OnceLock` in the shared runtime set before the callback and before the
   closed flag, so it is `Some` once `wait_closed` returns.
   `NotSentReason::SessionClosed` gains `reason: Option<CloseReason>` (the
   variant was `#[non_exhaustive]` with no fields).
6. **`Connection::logout_with_text(&str)`**: 1 to `MAX_LOGOUT_TEXT_LEN`
   (1024) bytes of printable ASCII, refused otherwise with
   `EngineError::InvalidField { tag: 58 }`. ASCII only because a non-ASCII
   `Text` belongs in `EncodedText` (355) under a declared `MessageEncoding`
   (347), which the session does not set. The counterparty's `Text` is kept
   up to `MAX_PEER_TEXT_LEN` (1024) bytes, cut at a character boundary.

## Options considered

- **Change `on_logout` to take the reason.** Breaking for every
  implementor; rejected.
- **`wait_closed` returning the reason.** Breaking signature change;
  `close_reason()` after `wait_closed()` gives the same information.
- **Keep `graceful` beside the reason.** Two sources of truth for one fact;
  rejected in favour of deriving it.
- **One `ResendStalled` close variant.** It would hide that the session
  still completed a Logout exchange (graceful, `reset_on_logout` applies);
  carrying it as a `LogoutCause` keeps both facts.

## Consequences

- Public surface, additive: `close` module, `CloseReason`, `LogoutCause`,
  `LogoutInitiator`, `MAX_PEER_TEXT_LEN`, `connection::MAX_LOGOUT_TEXT_LEN`,
  `Application::on_session_closed` (defaulted),
  `Connection::close_reason`, `Connection::logout_with_text`, and the
  `reason` field of the `#[non_exhaustive]` `NotSentReason::SessionClosed`.
- A transport failure that surfaces through the framing codec reports
  `TransportError { kind: None }`: `CodecError::Io` keeps the error's text,
  not its `io::ErrorKind`. Carrying the kind needs a `CodecError` change in
  `ironfix-transport`, out of this issue's scope.
- `LogonFailed` carries no detail; the `EngineError` returned to the caller
  of `connect`, `establish` or `serve` has it.
- There is no resend-hold-limit close and no throttle close: the hold pauses
  reading rather than closing, and a throttle refuses or discards messages
  without ending the session, so neither has a variant.
