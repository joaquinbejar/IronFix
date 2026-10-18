# ADR-0003 — FIXP and SOFH live in the IronFix workspace, on the IronSBE codec

- **Status:** Accepted (owner decision on issue #65, 2026-10-17)
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
  after its first publish. Nothing composes it yet: `ironfix-fixp` (#95) and
  the engine wiring (#96) do not exist.
