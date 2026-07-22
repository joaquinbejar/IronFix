# ADR-0001 — Adopt criterion as a dev-only benchmark harness

- **Status:** Accepted
- **Date:** 2026-07-22

## Context

IronFix targets single-digit-microsecond decode on a zero-allocation hot path,
and `doc/architecture.md` quotes latency and throughput figures throughout.
Those figures are design targets: until this change the workspace had no
`benches/` directory and no `criterion` dependency, so the Makefile's `bench*`
targets measured nothing and no claim about hot-path performance could be
grounded in a run anyone could reproduce. The hot paths that need measuring are
concentrated in three crates — tag=value decode/encode and checksum
(`ironfix-tagvalue`), the FAST stop-bit and presence-map primitives
(`ironfix-fast`), and the `FixCodec` framing loop (`ironfix-transport`). Adding a
dependency normally requires an ADR and user approval; the criterion harness was
pre-approved for this reason, and it is dev-only, but it is the first
ADR-worthy dependency call and the repo had no `doc/adr/` yet.

## Decision

Adopt `criterion` (0.8, `html_reports`) as a **dev-only** dependency, declared
once in `[workspace.dependencies]` and pulled into `ironfix-tagvalue`,
`ironfix-fast` and `ironfix-transport` through their `[dev-dependencies]` with a
`[[bench]]` target that sets `harness = false`. Each crate carries a `benches/`
file that measures its own hot path over fixtures the crate can build itself.
The harness only makes measurement possible: it records no baseline and ships no
figure. `make bench` runs it; CI compiles it (`bench-build`) but does not treat
timings taken on a shared runner as a measurement.

## Consequences

- Hot-path work now has a place to produce evidence, and the "no bench harness"
  gap in `CLAUDE.md`'s design-canon table is closed. What remains open is a
  recorded baseline: no latency or throughput figure may still be stated as
  measured anywhere in the repository until someone produces it with `make bench`
  on named hardware.
- **Semver: none.** criterion is a dev-dependency, so it does not appear in any
  crate's published dependency graph and adds no `pub` surface. It is invisible
  to `cargo-semver-checks` and to downstream consumers; `semver.yml` is
  unaffected and no version bump is forced by this change.
- The dev-dependency does lengthen a full `cargo build --all-targets` and the CI
  bench-compile step, the cost of keeping the benches building alongside the
  code they measure.
- No `unsafe` is introduced, the release profile is untouched, and the
  internal crate dependency DAG is unchanged (a dev-dependency is not a DAG
  edge).
