# FIXP SBE schema

`SBEschemaForFIXP.xml` is the SBE message schema of the FIX Performance Session
Layer (FIXP) session messages, published by FIX Trading Community.
`LICENSE-FIXP` is the license of the repository it comes from. Both are
vendored **verbatim**, byte for byte with no edits and no re-encoding, as the
input of `ironfix-fixp/tests/schema_conformance.rs`. That test checks the
hand-written codec in `ironfix-fixp/src/codec.rs` against the schema: every
template id, block length, field offset, optional null value and enumeration
value.

## Provenance

Both files come from <https://github.com/FIXTradingCommunity/fixp-specification>
at commit `af0e9d7eca87b2b7a9a1ace996dd3076013e37d2` (2021-10-26, the
repository head when vendored on 2026-10-18), fetched as git blobs so that
their bytes are untouched.

| File | Upstream path | Git blob | Size | SHA-256 |
|---|---|---|---|---|
| `SBEschemaForFIXP.xml` | `v1-1/resources/SBEschemaForFIXP.xml` (last changed in `d0b241b4`, 2021-04-18) | `0719eef226af56376c0d95e3443ef90465ef6740` | 9 471 bytes | `e14417224cbd625ca21fab118ef8ac1776a0ad7c70799950e1d3e807f4dcdac1` |
| `LICENSE-FIXP` | `LICENSE` | `c23bcfa0671360d5377b70d0d0a1d13edc38dd3c` | 12 497 bytes | `74d98d1ae857283a71708267537327c6fea2a44fb9068d561c6a7c97ffab7141` |

`git hash-object <file>` reproduces the blob column. The schema is plain ASCII
(`package="FIXP"`, `id="2748"`, `version="0"`, `byteOrder="littleEndian"`).
`LICENSE` upstream is Windows-1252 text, and so is `LICENSE-FIXP`: a first copy
taken through a tool that re-encoded it as UTF-8 (12 515 bytes) was replaced
with the upstream bytes.

The file at `v1-0-STANDARD/resources/SBEschemaForFIXP.xml` in the same commit,
the schema of the v1.0 Technical Standard, is byte-identical (same SHA-256).

The specification it belongs to is the **FIX Performance Session Layer
Technical Specification v1.1, Draft Standard, April 18, 2019**, the highest
version listed at <https://www.fixtrading.org/standards/fixp/> (checked
2026-10-18). Version 1.0 is the Technical Standard, approved in April 2021.

To refresh a file, fetch it as a git blob from a named upstream commit, check
`git hash-object` against the blob, update the table above, and run the
conformance test. Never edit either file, the schema to make a test pass
included.

## Rules for this directory

- The schema is **never edited**, not even to make a test pass.
- It is **never used to generate shipped code** or documentation: no build
  script, macro or code generator reads it, and nothing derived from it is
  published. The codec in `src/codec.rs` stays hand-written.
- It is **only read by tests** (`tests/schema_conformance.rs`).
- It is **never published**: `make check-licences` (alias
  `make check-package-fixp`), run in CI by `lint.yml`, fails if any file
  under `spec/` appears in `cargo package -p ironfix-fixp --list`.

## Known upstream quirks

- Template 13 is spelled `RestransmitReject` in the schema; the specification
  text spells it `RetransmitReject`, and so does this crate. The template id is
  what goes on the wire.
- The `Context` message declares `NextSeqNo` required, while the table in
  section 3.5.3 of the specification marks it optional. The crate follows the
  schema on the wire and reads the `uint64` null value as "no number given".

## License

The FIXP specification, this schema included, is © Copyright 2014-2021 FIX
Protocol Ltd. and is licensed under the Creative Commons
Attribution-NoDerivatives 4.0 International License, reproduced verbatim in
[`LICENSE-FIXP`](LICENSE-FIXP).

Attribution, as section 3(a)(1) of that license asks: "FIX Performance Session
Layer specification" by FIX Protocol Ltd.
(<http://www.fixtradingcommunity.org/>), licensed under CC BY-ND 4.0
(<https://creativecommons.org/licenses/by-nd/4.0/>). Based on a work at
<https://github.com/FIXTradingCommunity/fixp-specification>. The files are
unmodified.

That license allows the files to be copied and redistributed unmodified, with
this attribution, but it is not an open-source software license and forbids
distributing modified copies. So they live in the IronFix repository for the
test, and they are **excluded from the published `ironfix-fixp` package**
(`exclude` in `ironfix-fixp/Cargo.toml`, together with the test that reads
them): everything that ships on crates.io is MIT. Nothing in the crate is
generated from the schema or reuses its descriptions; the codec and its
documentation are written from the specification in this project's own words
and checked against the schema.
