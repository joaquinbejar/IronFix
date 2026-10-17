# ADR-0003 — FIXP and SOFH live next to the SBE codec, outside IronFix

- **Status:** Proposed (awaiting the owner's decision on issue #65)
- **Date:** 2026-10-17

## Context

Issue #65 asks where the FIX Performance Session Layer (FIXP) and the Simple
Open Framing Header (SOFH) belong. Binary order entry at venues commonly uses
SBE messages framed by SOFH over a FIXP session (Negotiate, Establish,
Sequence, RetransmitRequest, Retransmission, Terminate), and a downstream
gateway design proposes exactly that while recording that IronFix documents no
FIXP.

What exists today:

- IronFix has no FIXP, SOFH or SBE code. Its workspace members are the
  tag=value and FAST stack listed in the root `Cargo.toml`; `ironfix-fast` is
  FAST only.
- Almost nothing in the tag=value session stack carries over to FIXP:
  `SessionConfig` is built around `BeginString` and CompIDs
  (`ironfix-session/src/config.rs`), the typestate models tag=value
  Logon/Logout, `MessageStore::store` keys records on `MsgType`
  (`ironfix-store/src/traits.rs`), and the reactor is framed by `FixCodec`.
- FIXP's own session messages are defined in SBE, and the SBE codec (IronSBE)
  is a separate project by the same author.
- All IronFix crates version and publish in lockstep (`make version`,
  `make publish-all`).

## Options

1. **New crates in this workspace** (`ironfix-sofh` framing, `ironfix-fixp`
   session), depending on an SBE codec for the session messages.
2. **A separate project next to the SBE codec**, with IronFix only documenting
   interoperability.
3. **Out of scope for both**, documented as a non-goal.

## Proposed decision

Option 2. FIXP and SOFH are built next to the SBE codec, not in IronFix.
IronFix states in its README that it implements the tag=value (FIX 4.0 to
FIXT.1.1) and FAST layers only, and points to the binary stack for FIXP/SOFH.

Option 1 is rejected because it adds an external runtime dependency (the SBE
codec) to a workspace that publishes in lockstep, tying every IronFix release
to the codec's, while reusing almost no session code. Option 3 is rejected
because it leaves binary order entry unserved by either project.

## Consequences

- **IronFix code:** none. The README gains a scope statement; no crate, no
  dependency and no public surface change. **Semver: none.**
- The crate DAG is unchanged, and the lockstep publish order in
  `make publish-all` keeps its eleven crates.
- Shared vocabulary that a FIXP implementation may want (for example
  `SeqNum`, `CompId` or `Timestamp` from `ironfix-core`) stays available as a
  normal crates.io dependency; nothing in this decision prevents that reuse.
- No issue in #60–#84 depends on this decision.
- If the owner chooses option 1 instead, follow-up issues are filed for SOFH
  framing, the FIXP session state machine (both flow types) and conformance
  tests, and a new ADR records the SBE dependency and the crate DAG change.
