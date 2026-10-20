# ADR-0003 — FIXP and SOFH live in the IronFix workspace, on the IronSBE codec

- **Status:** Accepted (owner decision on issue #65, 2026-10-17). Amended by
  #122 (2026-10-18): `ironfix-sofh` has no internal dependency; see
  Consequences.
- **Date:** 2026-10-17

## Context

Issue #65 asks where the FIX Performance Session Layer (FIXP) and the Simple
Open Framing Header (SOFH) belong. Binary order entry at venues commonly uses
SBE messages framed by SOFH over a FIXP session (Negotiate, Establish,
Sequence, RetransmitRequest, Retransmission, Terminate), with recoverable and
idempotent flows.

What exists today:

- IronFix has no FIXP, SOFH or SBE code. Its members are the tag=value and FAST
  stack listed in the root `Cargo.toml`; `ironfix-fast` is FAST only.
- Almost nothing in the tag=value session stack carries over: `SessionConfig`
  is built around `BeginString` and CompIDs (`ironfix-session/src/config.rs`),
  the typestate models tag=value Logon/Logout, `MessageStore` files records
  by sequence number but requires a tag=value `MsgType` as metadata and the
  complete tag=value frame (`BeginString` through `CheckSum`) as the payload
  (`ironfix-store/src/traits.rs`), and the reactor is framed by `FixCodec`.
- FIXP's session messages are defined in SBE. The SBE codec `ironsbe-core`
  (0.7.x, same author, repository `joaquinbejar/IronSBE`) depends only on
  `crossbeam-queue` and `thiserror`, both already workspace dependencies.
- All IronFix crates version and publish in lockstep (`make version`,
  `make publish-all`), and `semver.yml` checks every published crate.
- ADR-0002 makes session cores sans-IO, with the runtime as a driver.

## Options

1. **New crates in this workspace** (`ironfix-sofh` framing, `ironfix-fixp`
   session), depending on an SBE codec for the session messages.
2. A separate project next to the SBE codec, with IronFix only documenting
   interoperability.
3. Out of scope for both, documented as a non-goal.

## Decision

Option 1. Two new crates join the workspace, and the engine composes them:

- **`ironfix-sofh`**: SOFH framing (message length and encoding type) and a
  `tokio-util` codec, the binary counterpart of `FixCodec`. Depends on
  `ironfix-core` only; it never interprets the payload.
- **`ironfix-fixp`**: the FIXP session core, sans-IO from the start per
  ADR-0002 (decoded session messages and an explicit time in; messages to send
  and events out). Depends on `ironfix-core` and `ironsbe-core`; it depends on
  neither `ironfix-sofh` nor any tag=value crate.
- **`ironfix-engine`** stays the only composition root: it runs FIXP over SOFH
  on a stream behind an optional `fixp` feature, so tag=value users do not pull
  `ironsbe-core`.

`ironsbe-core` is the one new external runtime dependency, approved with this
decision and pinned to a compatible 0.7 range when `ironfix-fixp` lands.

## Consequences

- **Crate DAG** gains two leaves next to `session`: `sofh -> core` and
  `fixp -> core + ironsbe-core`; `engine` additionally depends on `sofh` and
  `fixp` under the `fixp` feature. No existing edge changes.

  > **Amended by #122, 2026-10-18.** `ironfix-sofh` no longer depends on
  > `ironfix-core`: it is a leaf with no internal dependency, not
  > `sofh -> core`, which also supersedes "depends on `ironfix-core` only" in
  > the #94 entry below. The edge was declared but never used. SOFH framing
  > reads a length and an encoding type and names no core type, and
  > `FixError` has no framing variant to bridge `SofhError` into; that bridge
  > belongs in `EngineError` when the engine wiring (#96) lands. Keeping the
  > edge made a standalone build of `ironfix-sofh` pull `ironfix-core` and its
  > tree (`rust_decimal`, `chrono` with its platform time-zone crates,
  > `num-traits`, `num-derive`, `smallvec`, `arrayvec` and `serde_derive`)
  > for nothing. Dropping it is not a breaking change, because no core
  > type appears in the crate's public API. `fixp -> core + ironsbe-core` is
  > unchanged: `ironfix-fixp` uses the core vocabulary (`SeqNum`,
  > `Timestamp`). The same issue dropped the unused `core` edge of
  > `ironfix-transport` (which still reaches `core` through `tagvalue`) and of
  > `ironfix-fast`. The `make publish-all` order still holds, since removing
  > an edge only relaxes it.
- **Release process:** both crates join the lockstep version, the
  `make publish-all` order (after `core`, before `engine`), and the
  `semver.yml` matrix after their first publish. IronFix releases now also
  track `ironsbe-core`'s compatibility range.
- **Semver:** additive (new crates, a new optional feature). No existing
  `pub` item changes.
- **Honesty:** until the follow-up work lands, the README states that the
  binary stack is planned and that none of it exists.
- Follow-up issues: #94 (`ironfix-sofh`), #95 (`ironfix-fixp` session core,
  recoverable and idempotent flows), #96 (FIXP over SOFH in `ironfix-engine`
  behind the `fixp` feature), #97 (FIXP/SOFH conformance suite).
- **`ironfix-sofh` exists** (#94). It implements SOFH v1.0, the Draft
  Standard of December 2016: `SofhHeader`, the registered `EncodingType`
  values (an unregistered value is preserved, not rejected), and `SofhCodec`,
  a `tokio-util` codec with a `Message_Length` ceiling whose every error is
  fatal for the stream, since SOFH has no resynchronisation anchor. It
  depends on `ironfix-core` only, joins the lockstep version, and is
  published right after `ironfix-core`; it enters the `semver.yml` matrix
  after its first publish. Nothing composes it yet: the engine wiring (#96)
  does not exist.
- **`ironfix-fixp` exists** (#95). It implements FIXP v1.1, the Draft
  Standard of April 18, 2019 (the highest version published; v1.0 is the
  April 2021 Technical Standard, with the same point-to-point protocol), as a
  sans-IO core in both roles, per ADR-0002: decoded messages and an explicit
  `Instant` in, messages, transport closes and events out, no clock read. It
  depends on `ironfix-core` and `ironsbe-core` only, the latter at `0.7.1`
  (compatible range `^0.7.1`), which brings `crossbeam-queue` into the lock
  file; no `ironsbe-core` type appears in its public API, so a breaking
  `ironsbe-core` release does not force one here. The 19 session messages of
  the FIXP SBE schema (id 2748, version 0) are encoded by hand on
  `ironsbe-core`'s header and buffer primitives. That schema is © FIX
  Protocol Ltd. under CC BY-ND 4.0, so it is vendored byte for byte under
  `ironfix-fixp/spec/` with its license and provenance as the input of a
  conformance test, and excluded with that test from the published package,
  which stays MIT; no description from it is reused in the crate's
  documentation. Recoverable, Idempotent, Unsequenced and None flows run on
  one state machine. What happens when a RetransmitRequest stalls is a typed
  policy (`RetransmitStallPolicy`), because FIXP both forbids a second
  request while a retransmission is in progress and makes asking again the
  requester's duty; the default only asks again once a context switch has cut
  a batch short. A counterparty's finalization is answered; sending one,
  multiplexing, datagram transports, multicast and persistence are not
  implemented (`doc/fixp_operations.md`). The engine driver (#96) owns the
  transports: the crate states which transport each output belongs to, and a
  server session left negotiated without a transport needs an eviction
  policy there. The crate joins the lockstep version and `make publish-all`
  right after `ironfix-sofh`, and enters the `semver.yml` matrix after its
  first publish.
- **The engine wiring exists** (#96). `ironfix-engine`'s optional `fixp`
  feature adds the `fixp` module: `FixpInitiator`, `FixpAcceptor`,
  `FixpConnection`, the `FixpApplication` trait, and `FixpEngineError`, its
  own `thiserror` boundary (the bridge from `SofhError` that the #122
  amendment expected in `EngineError` lives there instead, so `EngineError`
  does not change shape with a feature). One driver task per transport
  composes `SofhCodec` with the core, separate from the tag=value reactor.
  With the feature off the engine's normal graph holds neither
  `ironfix-sofh`, `ironfix-fixp` nor `ironsbe-core`; `make check-fixp-deps`
  checks it in CI. The module re-exports `ironfix_fixp` and `ironfix_sofh`,
  so a breaking release of either is a breaking change of the engine's
  `fixp` surface. Not driven yet: re-establishment on a new transport and
  persistence (`doc/fixp_operations.md`, "Engine driver").
- **The conformance suite exists** (#97).
  `ironfix-engine/tests/fixp_conformance_tests.rs` runs the engine in both
  roles against a raw peer of hand-built SOFH and SBE bytes (neither
  `SofhCodec` nor the `ironfix-fixp` codec), each case citing a FIXP v1.1
  section and page and marking local policy where the specification is
  open; the coverage table is in `doc/fixp_operations.md`. It found one
  defect, fixed with it: a Negotiate or Establish the server could not
  grant (two None flows, a failed or lapsed application decision) was
  closed without the NegotiationReject or EstablishmentReject sections
  4.2.3 and 4.3 require. No `pub` item changed.
