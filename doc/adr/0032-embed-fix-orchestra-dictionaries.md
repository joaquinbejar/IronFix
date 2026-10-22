# ADR-0032 — Embed the FIX Orchestra repositories instead of the QuickFIX dictionaries

- **Status:** Accepted
- **Date:** 2026-10-22
- **Supersedes:** ADR-0010 (the embedding decision; its transport plus application composition stands)

## Context

ADR-0010 embedded four QuickFIX XML dictionaries (FIX 4.2, FIX 4.4, FIXT 1.1,
FIX 5.0 SP2) in `ironfix-dictionary`. They are under the QuickFIX Software
License 1.0 while the crate declares MIT, so the package understated what
users redistribute, and downstream users that only accept an allowlist of
licences could not adopt it (#201). The FIX Trading Community publishes the
same standard as FIX Orchestra repositories under Apache-2.0, and #200 made
the Orchestra loader read all four versions and diffed each against its
QuickFIX counterpart (`doc/orchestra_differences.md`).

## Decision

- Embed the FIX Trading Community's Orchestra repositories, vendored verbatim
  under `ironfix-dictionary/spec/orchestra/` with the upstream `LICENSE` and a
  provenance README: `OrchestraFIX42.xml`, `OrchestraFIX44.xml`,
  `FIXTSession.xml` and `OrchestraFIXLatest.xml`, all at upstream commit
  `cd24169a`.
- `Dictionary::fix42`, `fix44` and `fixt11` load the first three with
  `Dictionary::from_orchestra_xml`. `Dictionary::fix50sp2` derives FIX 5.0
  SP2 from FIX Latest with `Dictionary::from_orchestra_latest_xml`, by
  pedigree, because upstream no longer publishes a FIX 5.0 SP2 repository.
  Names, signatures and caching are unchanged.
- **On a conflict, Orchestra wins.** Every difference from the QuickFIX
  dictionaries is listed in `doc/orchestra_differences.md` and the user
  observable ones in `CHANGELOG.md`.
- The crate ships no QuickFIX file. The QuickFIX dictionaries stay in the
  repository as test fixtures (`ironfix-dictionary/tests/fixtures/quickfix/`,
  excluded from the package) for the QuickFIX loader's tests, the
  equivalence diff and the code generator's component tests.
  `Dictionary::from_quickfix_xml` stays for callers' own files.
- The files are stored uncompressed: the packaged crate grows from about
  0.36 MB to about 1.1 MB, far below the crates.io limit, so no
  decompression dependency is added.

## Consequences

- The published crate carries Apache-2.0 content next to its MIT code; the
  package licence metadata is decided in #202.
- Behaviour changes (breaking, a minor bump at 0.x; the version is decided
  in #202): stricter FIX 5.0 SP2 enumerations, fields that FIX 5.0 SP2 does
  not define any more, a complete FIX 5.0 SP2 dictionary, the FIXT 1.1 Logon
  `NoMsgTypes(384)` group, renamed fields and messages, and generated code
  with per-message group types where QuickFIX had shared components.
- First loads are slower (FIX 5.0 SP2 about 30 ms instead of about 10 ms on
  an Apple M4 Max); cached access is unchanged.
- The transport plus application composition of ADR-0010 stands. Because
  the FIXT 1.1 repository enumerates `MsgType(35)` and `RefMsgType(372)` with
  the session message types only, `Validator::for_session` admits the union
  of both sides' enumerations for a field both define.
