# ADR-0018 — A multi-session acceptor that routes each Logon by CompID

- **Status:** Accepted (issue #61, in the plan the owner approved; the refusal
  of an unknown identity deviates from the issue text, see "Refusals")
- **Date:** 2026-10-18

## Context

An `Acceptor` is one configured session: one expected counterparty, one
admission slot, one optional store. A venue gateway terminates the sessions of
many members on shared listeners, so it has to pick the session for an inbound
connection, and the only thing that identifies the peer is its first Logon,
which `Acceptor::serve` read itself. The socket address identifies nothing a
member directory knows about.

Constraints any answer keeps:

- the acceptor handshake, its check order and its refusal groups (ADR-0017)
  stay exactly as they are, for a routed session and for `Acceptor::serve`;
- the per-session admission guarantee (one live session per counterparty)
  holds for every session, including ones not known at startup;
- nothing reaches a store before the peer is authenticated (ADR-0017);
- the identity is read from a Logon nothing has validated yet, so it is
  untrusted input, and the Logon carries `Password` (554);
- decision logic is synchronous and reads no clock (ADR-0002);
- the crate DAG: all of it lives in `ironfix-engine`.

## Decision

### Split the handshake from the read

`Acceptor::serve` now reads the Logon and hands it, with its `Framed` stream,
to a private `complete_handshake`, which is the rest of the old `serve`
unchanged. A crate-private `Acceptor::serve_logon(framed, frame)` runs the
configuration check and `on_create`, replaces the socket's codec with the
session's own, holds the Logon to the session's `max_message_size`, and calls
the same `complete_handshake`. Every existing acceptor test passes unchanged.

### The registration unit is an `Acceptor`

`AcceptorRegistry<A>` holds one `Acceptor<A>` per session. An `Acceptor`
already carries everything a session needs (configuration, application,
optional store and failure policy, timeouts, initial sequences, capacities),
so `register(acceptor)` reuses that whole surface instead of restating it,
and a routed session is served by the very object that would serve it alone.
One application type `A` serves every session; the instances may differ.

`EngineBuilder::into_acceptor_registry()` builds one `Acceptor` per added
`SessionConfig`, sharing the builder's application. The builder holds one
store, and a store belongs to one session (ADR-0017), so it is attached only
when exactly one session is configured; with several, a store is refused with
`EngineError::Configuration`, and stores are attached per `Acceptor` before
`register`.

### The routing key

The key is the session's configured identity reversed into the Logon's
orientation: the Logon's `SenderCompID` (49) is the session's
`target_comp_id`, its `TargetCompID` (56) the session's `sender_comp_id`, and
its `SenderSubID` (50), `TargetSubID` (57), `SenderLocationID` (142) and
`TargetLocationID` (143) are the session's target and sender sub and location
IDs. A sub or location ID the session configures must be carried with that
value; one it does not configure places no requirement, as in the
identity check the handshake already runs (`PeerIdentity`).

`BeginString` (8) is not part of the key. The routed session checks it as
`Acceptor::serve` does, with its refusal policy. The cost: two sessions that
differ only by FIX version cannot share a registry. Adding the version to the
key would make a wrong `BeginString` an unknown session (no reply) instead of
the routed session's version refusal, and FIX 5.0 sessions would still
collide on `FIXT.1.1`; it was left out of the approved plan.

`register` refuses a session whose key **overlaps** one already registered
(same CompIDs, and no optional field required by both with different values:
some Logon would match both), and one whose `SessionId` is already registered
(two sessions that differ only by location ID: the application, which is
called with a `SessionId`, could not tell them apart). A Logon therefore
matches at most one session, and routing never depends on registration order.
The table is a `std::sync::RwLock<HashMap<(49, 56), Vec<route>>>`: never held
across an await, poison recovered (every write is one push after its checks).
`DashMap`, which the ruleset prefers, is not a dependency and was not added.

### Bounding the untrusted identity

The Logon is decoded but not validated when it is routed. The identity fields
are read from the **standard header** only (a 49 or 56 that occurs only in the
body names nobody, as for the handshake's identity check), as raw bytes, and
each must be 1 to `MAX_ID_LEN` (32) bytes of printable ASCII, the bound every
configured CompID, sub ID and location ID obeys, so a value outside it could
not match any session. A failure is `EngineError::UnroutableLogon { tag,
detail }`, decided before any session or the lookup is consulted; the detail
never quotes the value. The log line carries the tag, the length and at most
16 bytes of the value, escaped. Nothing else of the Logon is logged, so `Password`
(554), `NewPassword` (925) and `RawData` (96) never reach a log line.
`LogonIdentity::from_logon` and the matching are synchronous and read no clock.

### Sessions not known at startup: `SessionLookup`

`#[async_trait] SessionLookup<A>` is asked about an identity no registered
session matches. It sees the `LogonIdentity` only, never the Logon, so it
cannot leak credentials; authentication stays with `Application::from_admin`,
which runs in the routed handshake. It returns `Some(acceptor)` to admit or
`None` to refuse.

An admitted session is **registered for the registry's lifetime**, like a
static registration, and the lookup is not asked about it again. That is what
keeps the admission guarantee: an `Acceptor` built afresh per Logon would have
its own admission slot, and two concurrent Logons for the same session would
both reach Active and fork the sequence stream. It also keeps the session's
in-memory owed-reset record (ADR-0005, ADR-0017) across connections. When two
lookups for one identity race, the first admitted `Acceptor` is kept and the
second is dropped (`SamePattern::KeepRegistered`), so both Logons compete for
one slot and the loser is refused as a duplicate. The returned acceptor must
route the identity it was asked about and must not overlap a registered
session; otherwise the Logon is refused with `EngineError::Configuration`.
The lookup is bounded by the routing deadline (below); expiry is
`EngineError::LogonTimeout`.

The cost of caching: a lookup cannot revoke a session it has admitted (refuse
the credentials in `from_admin` instead), and each admitted identity costs one
`Acceptor` for the registry's lifetime, bounded by what the lookup admits.
Removing a session from a running registry is not provided.

### Limits

Reading the Logon and resolving its session are bounded together by one
deadline, the registry's logon timeout (`with_logon_timeout`, default 10 s,
non-zero and at most `MAX_TIMEOUT`), so a peer that never logs on and a lookup
that never answers end in the same `LogonTimeout`. The routed session's own
`logon_timeout` does not apply: its Logon has already been read.

The Logon is framed with a registry codec: a ceiling from the registry
(`with_max_message_size`, default 64 KiB, within the session limits'
`MIN_MESSAGE_SIZE_LIMIT..=MAX_MESSAGE_SIZE_LIMIT`), since it bounds what an
unknown, unauthenticated peer can make the registry buffer; checksum
validation always on, for the same reason; garbled-frame recovery on with
every FIX-family `BeginString` as a resync anchor, since the version is not
known yet. Out-of-range settings are refused by `serve` and by `accept`
before it takes a connection, as `Acceptor` reports its configuration. After
routing the socket switches to the session's codec, which governs every later
frame; bytes already read stay in the `Framed` buffer, and the codec holds no
partial frame once it has returned one. The Logon is then held to the
session's `max_message_size`, so a frame that session's codec would have
refused is refused here, without a reply. A session configured to skip
checksum validation still has its Logon checked during routing.

### Refusals

Before routing there is no session: no sequence stream to number a reply from,
no store to file one in, and no configured identity to stamp on it. A Logon
that cannot be routed (unroutable identity, unknown session, a lookup that
refuses or overruns, a first frame that is not a Logon) is closed **without a
reply**, touches no store and runs no `Application` callback (`on_create`
included). This is the treatment ADR-0017 gives an unauthenticated peer when a
store is attached, applied here whether or not any session has one.

**Deviation from the issue text.** #61 asked for an unknown identity to get a
Logout with a generic Text. The approved plan closes without a reply instead:
a Logout would have to carry a `MsgSeqNum` from no stream and CompIDs the peer
supplied, and would tell a scanner which identities are not configured. A
peer whose identity is wrong learns it from the closed connection; the reason
is in the registry's log and in the error `serve` returns.

Once routed, the session's handshake answers the Logon exactly as
`Acceptor::serve` would, all four refusal groups of ADR-0017 included. A
second Logon for a session that is live is refused without a reply by the
session's admission slot while the live session continues.

`on_create` fires for a routed session when its handshake starts, after the
read, rather than before the read as on `Acceptor::serve`: there is no
session to name before routing.

## Consequences

- **Semver (additive):** the `registry` module with `AcceptorRegistry`
  (`new`, `with_lookup`, `with_logon_timeout`, `with_max_message_size`,
  `logon_timeout`, `max_message_size`, `register`, `session_ids`, `accept`,
  `serve`, `Default`, `Debug`), `LogonIdentity` (six getters, `Display`),
  `SessionLookup`, all re-exported at the crate root;
  `EngineBuilder::into_acceptor_registry`; `EngineError::UnroutableLogon` and
  `EngineError::UnknownSession` (`EngineError` is `#[non_exhaustive]`). No
  existing item changes signature. The text of the builder's "several
  sessions" `Configuration` error now names `into_acceptor_registry`.
- **Behaviour:** none for `Acceptor::serve` or `Initiator`.
- Every session keeps its own `SequenceManager`, heartbeat, store, policy and
  owed-reset record; the registry only chooses the `Acceptor`. The registry
  spawns no task: each routed session's reactor is spawned by its `Acceptor`,
  with the shutdown path it already has.
- The crate DAG is unchanged: everything is in `ironfix-engine`, and
  `ironfix-session` gains nothing. No dependency was added.
- No performance claim (ADR-0001): routing adds a second decode of the Logon
  and one read-locked hash lookup per connection; nothing was measured.
