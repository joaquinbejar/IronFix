# ADR-0018 — A multi-session acceptor that routes each Logon by CompID

- **Status:** Accepted (issue #61, in the plan the owner approved, revised in
  the #61 review round; the refusal of an unknown identity deviates from the
  issue text, see "Refusals")
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
  stay as they are, for a routed session and for `Acceptor::serve`;
- the per-session admission guarantee (one live session per counterparty)
  holds for every session, including ones not known at startup;
- nothing reaches a store before the peer is authenticated (ADR-0017);
- the identity is read from a Logon nothing has validated yet, so it is
  untrusted input, and the Logon carries `Password` (554);
- an unauthenticated peer must not be able to grow what the registry holds;
- decision logic is synchronous and reads no clock (ADR-0002);
- the crate DAG: all of it lives in `ironfix-engine`.

## Decision

### Split the handshake from the read

`Acceptor::serve` reads the Logon and hands it, with its `Framed` stream, to a
private `complete_handshake`, which is the rest of the old `serve` unchanged. A
crate-private `Acceptor::serve_logon(framed, frame, authenticated)` runs the
configuration check and `on_create`, replaces the socket's codec with the
session's own, holds the Logon to the session's `max_message_size`, and calls
the same `complete_handshake`, which sets `authenticated` once `from_admin`
has accepted the Logon. Every pre-existing acceptor test passes unchanged.

### The registration unit is an `Acceptor`

`AcceptorRegistry<A>` holds one `Acceptor<A>` per session. An `Acceptor`
already carries everything a session needs (configuration, application,
optional store and failure policy, timeouts, initial sequences, capacities),
so `register(acceptor)` reuses that whole surface instead of restating it,
and a routed session is served by the very object that would serve it alone.
One application type `A` serves every session; the instances may differ.

`EngineBuilder::into_acceptor_registry()` builds one `Acceptor` per added
`SessionConfig`, sharing the builder's application. The builder holds one
store, and a store belongs to one session (ADR-0017), so a builder store is
accepted only with exactly one session; with none or several it is refused
with `EngineError::Configuration` (with none it would otherwise be dropped
without a word), and stores are attached per `Acceptor` before `register`.

### The routing key, and what the session enforces

The key is the session's configured identity reversed into the Logon's
orientation: the Logon's `SenderCompID` (49) is the session's
`target_comp_id`, its `TargetCompID` (56) the session's `sender_comp_id`, and
its `SenderSubID` (50), `TargetSubID` (57), `SenderLocationID` (142) and
`TargetLocationID` (143) are the session's target and sender sub and location
IDs. A sub or location ID the session configures must be carried with that
value; one it does not configure places no requirement.

The session enforces the same rule on every inbound message. `PeerIdentity`
already checked 49/56 always and 50/57 when configured; it now checks 142/143
when configured too, with the same reject (reason 9) and Logout. Otherwise a
peer routed on one location could send under another, and routing would
promise something the session does not hold. This is a behaviour change for
any session, in either role, that configures location IDs: a counterparty
that does not stamp them back is now refused, as it already was for sub IDs.

`BeginString` (8) is not part of the key. The routed session checks it as
`Acceptor::serve` does, with its refusal policy. The cost: two sessions that
differ only by FIX version cannot share a registry (`register` refuses the
second as overlapping). Adding the version to the key would make a wrong
`BeginString` an unknown session (no reply) instead of the routed session's
version refusal, and FIX 5.0 sessions would still collide on `FIXT.1.1`.

`register` refuses a session whose key **overlaps** one already in the
registry (same CompIDs, and no optional field required by both with different
values: some Logon would match both), one whose `SessionId` is already there
(two sessions that differ only by location ID: the application, which is
called with a `SessionId`, could not tell them apart), and one whose store
another session uses (compared by address: a store belongs to one session). A
Logon therefore matches at most one session, and routing never depends on
registration order.

### Bounding the untrusted identity

The Logon is decoded but not validated when it is routed. The identity fields
are read from the **standard header** only (a 49 or 56 that occurs only in the
body names nobody, as for the handshake's identity check), as raw bytes. Each
must occur there at most once: a repeated one is the "tag appears more than
once" case (`SessionRejectReason` 13), which FIX answers by disconnecting, and
no occurrence can be trusted over the other. Each value must be 1 to
`MAX_ID_LEN` (32) bytes of printable ASCII, the bound every configured CompID,
sub ID and location ID obeys, so a value outside it could not match any
session. A failure is `EngineError::UnroutableLogon { tag, detail }`, decided
before any session or the lookup is consulted; the detail never quotes the
value. The log line carries the tag, the length and at most 16 bytes of the
value, escaped. Nothing else of the Logon is logged, so `Password` (554),
`NewPassword` (925) and `RawData` (96) never reach a log line. The standard
header set the scan uses gains `OnBehalfOfSendingTime` (370), which was
missing and would have ended the header early.
`LogonIdentity::from_logon` and the matching are synchronous and read no clock.

### Sessions not known at startup: `SessionLookup`

`#[async_trait] SessionLookup<A>` is asked about an identity no session in the
registry matches. It sees the `LogonIdentity` only, never the Logon, so it
cannot leak credentials; authentication stays with `Application::from_admin`,
which runs in the routed handshake. It returns
`Result<Option<Acceptor<A>>, LookupError>`: `Ok(Some)` admits, `Ok(None)`
refuses (`EngineError::UnknownSession`), and `Err(LookupError)` says the
directory cannot decide (`EngineError::Lookup`), so an outage is not reported,
or logged, as a refusal.

**Admission is provisional.** The lookup admits before `from_admin` has
authenticated anyone. A first version kept every admitted session for the
registry's lifetime, so a peer cycling fresh `SenderCompID`s that the lookup
admitted could grow the route table, and whatever each session held (a store,
its file descriptors), without bound and without ever authenticating. Now an
admitted session is inserted **provisionally**, and the connection's claim on
it is a guard settled when the handshake ends, however it ends (a `serve`
future dropped mid-handshake included):

- if the handshake got past `from_admin`, the session is **confirmed** and
  kept for the registry's lifetime, like a registered one, so its admission
  slot and in-memory owed-reset record (ADR-0005, ADR-0017) outlive the
  connection;
- otherwise, if the session is still provisional and no other connection is
  routed to it (the table's reference and the guard's are the only ones;
  references are cloned only under the read lock, which the settle's write
  lock excludes), it is **evicted**. Nothing is lost: before authentication
  its store is never touched.

`with_max_sessions(n)` caps the lookup-admitted sessions held at once,
provisional and confirmed together; registered sessions do not count. An
admission beyond it is refused with `EngineError::SessionLimit { max }`; an
eviction frees a place. There is no default cap: the lookup is expected to
admit only identities from a bounded directory, as its documented example
does, and the cap bounds the rest.

When two lookups for one identity race, the first admitted `Acceptor` is kept
and the second is dropped, so both Logons compete for one admission slot and
the loser is refused as a duplicate. The returned acceptor must route the
identity it was asked about, must not overlap a session in the registry and
must not share one's store; otherwise the Logon is refused with
`EngineError::Configuration`. The lookup is bounded by the routing deadline
(below); expiry is `EngineError::LogonTimeout`.

**Resource use**, stated on `SessionLookup`: the lookup runs once per Logon
whose identity matches no session, so an unauthenticated peer can make it run
once per connection; an admission costs one `Acceptor`, and whatever the
lookup built for it, until the first handshake settles it. A confirmed
session cannot be revoked by the lookup (refuse the credentials in
`from_admin` instead), and removing a session from a running registry is not
provided.

### Locking

The route table is a `std::sync::RwLock`, not `tokio::sync` or `DashMap`. Every
critical section is synchronous and short (a lookup, a push, a retain, a state
change), no guard is ever held across an `.await`, and `register`, `Debug` and
the guard's `Drop` need the lock outside any async context. A poisoned lock is
recovered: every write is one push, retain or state change after its checks.
`DashMap`, which the ruleset prefers, is not a dependency; this is recorded as
an allowed deviation.

### Limits

Reading the Logon and resolving its session are bounded by one deadline, the
registry's logon timeout (`with_logon_timeout`, default 10 s, non-zero and at
most `MAX_TIMEOUT`): the read runs until that deadline and the lookup until
the same one, so a peer that never logs on and a lookup that never answers
end in the same `LogonTimeout`. The routed session's own `logon_timeout` does
not apply: its Logon has already been read.

The Logon is framed with a registry codec: a ceiling from the registry
(`with_max_message_size`, default 64 KiB, within the session limits'
`MIN_MESSAGE_SIZE_LIMIT..=MAX_MESSAGE_SIZE_LIMIT`), since it bounds what an
unknown, unauthenticated peer can make the registry buffer; checksum
validation always on, for the same reason, so a session configured to skip
checksum validation still has its Logon checked; garbled-frame recovery on
with every FIX-family `BeginString` as a resync anchor, since the version is
not known yet. Out-of-range settings are refused by `serve` and by `accept`
before it takes a connection. After routing the socket switches to the
session's codec, which governs every later frame; bytes already read stay in
the `Framed` buffer, and the codec holds no partial frame once it has returned
one, so a frame pipelined behind the Logon is framed by the session's codec.
The Logon is then held to the session's `max_message_size`, so a frame that
session's codec would have refused is refused here, without a reply.

The registry bounds each connection, not how many there are. Capping the
connections whose Logon is still being read or routed is the consumer's, as
the accept loop is; the module example does it with a `tokio::sync::Semaphore`
taken before `serve` and released when it returns.

### Refusals

Before routing there is no session: no sequence stream to number a reply from,
no store to file one in, and no configured identity to stamp on it. A Logon
that cannot be routed (unroutable identity, unknown session, a lookup that
refuses, fails or overruns, the session cap, a first frame that is not a
Logon) is closed **without a reply**, touches no store and runs no
`Application` callback (`on_create` included). This is the treatment ADR-0017
gives an unauthenticated peer when a store is attached, applied here whether
or not any session has one. The refusals a peer can provoke at will are logged
at debug level, so they cannot flood the log; a lookup that fails or overruns,
a lookup that returns an unusable session and the session cap are logged as
warnings, since they are the operator's to fix.

**Deviation from the issue text.** #61 asked for an unknown identity to get a
Logout with a generic Text. The approved plan closes without a reply instead:
a Logout would have to carry a `MsgSeqNum` from no stream and CompIDs the peer
supplied, and would tell a scanner which identities are not configured. A
peer whose identity is wrong learns it from the closed connection; the reason
is in the registry's log and in the error `serve` returns.

Once routed, the session's handshake answers the Logon as `Acceptor::serve`
would, all four refusal groups of ADR-0017 included, with one refinement that
applies to `serve` too: **while the session is live on another connection, a
Logon refused before the admission slot is reached (wrong `BeginString`,
`EncryptMethod` or CompIDs) gets no reply, with or without a store.** ADR-0017
already gave a duplicate Logon no reply because the live session owns the
sequence stream; a store-less refusal numbered from the provisional counters
would reuse one of its numbers just the same, whatever the Logon got wrong.
The check reads the slot without claiming it, at refusal time, and the error
returned still names the actual fault.

`on_create` fires for a routed session when its handshake starts, after the
read, rather than before the read as on `Acceptor::serve`: there is no
session to name before routing.

## Consequences

- **Semver (additive against `main`):** the `registry` module with
  `AcceptorRegistry` (`new`, `with_lookup`, `with_max_sessions`,
  `with_logon_timeout`, `with_max_message_size`, `logon_timeout`,
  `max_message_size`, `max_sessions`, `register`, `session_ids`, `accept`,
  `serve`, `Default`, `Debug`), `LogonIdentity` (six getters, `Display`),
  `LookupError` (`new`, `reason`) and `SessionLookup`, all re-exported at the
  crate root; `EngineBuilder::into_acceptor_registry`; and
  `EngineError::UnroutableLogon`, `EngineError::UnknownSession` (carrying a
  `Box<LogonIdentity>`, boxed to keep `EngineError` small),
  `EngineError::SessionLimit` and `EngineError::Lookup` (`EngineError` is
  `#[non_exhaustive]`). No existing item changes signature. The text of the
  builder's "several sessions" `Configuration` error now names
  `into_acceptor_registry`.
- **Behaviour, outside the registry:** a session that configures
  `sender_location_id` / `target_location_id` now checks inbound 143/142 on
  every message, in both roles; an `Acceptor` without a store no longer
  answers a Logon refused for its version, encryption or CompIDs while its
  session is live; `OnBehalfOfSendingTime` (370) is part of the standard
  header for the header-position checks.
- Every session keeps its own `SequenceManager`, heartbeat, store, policy and
  owed-reset record; the registry only chooses the `Acceptor`. The registry
  spawns no task: each routed session's reactor is spawned by its `Acceptor`,
  with the shutdown path it already has.
- The crate DAG is unchanged: everything is in `ironfix-engine`, and
  `ironfix-session` gains nothing. No dependency was added.
- No performance claim (ADR-0001): routing adds a second decode of the Logon
  and one read-locked hash lookup per connection; nothing was measured.
