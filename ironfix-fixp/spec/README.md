# FIXP SBE schema

`SBEschemaForFIXP.xml` is the SBE message schema of the FIX Performance Session
Layer (FIXP) session messages, published by FIX Trading Community. It is
vendored **verbatim** (byte for byte, no edits) as the input of
`ironfix-fixp/tests/schema_conformance.rs`, which checks the hand-written codec
in `ironfix-fixp/src/codec.rs` against it: every template id, block length,
field offset, optional null value and enumeration value.

## Provenance

| | |
|---|---|
| Repository | <https://github.com/FIXTradingCommunity/fixp-specification> |
| Commit | `af0e9d7eca87b2b7a9a1ace996dd3076013e37d2` (2021-10-26, the repository head when vendored on 2026-10-18) |
| Path | `v1-1/resources/SBEschemaForFIXP.xml` (last changed in `d0b241b4`, 2021-04-18) |
| Git blob | `0719eef226af56376c0d95e3443ef90465ef6740` |
| SHA-256 | `e14417224cbd625ca21fab118ef8ac1776a0ad7c70799950e1d3e807f4dcdac1` |
| Schema | `package="FIXP"`, `id="2748"`, `version="0"`, `byteOrder="littleEndian"` |

The file at `v1-0-STANDARD/resources/SBEschemaForFIXP.xml` in the same commit,
the schema of the v1.0 Technical Standard, is byte-identical (same SHA-256).

The specification it belongs to is the **FIX Performance Session Layer
Technical Specification v1.1, Draft Standard, April 18, 2019**, the latest
version listed at <https://www.fixtrading.org/standards/fixp/> (checked
2026-10-18). Version 1.0 is the Technical Standard, approved April 15, 2021.

To refresh the file, fetch it from a named upstream commit, update the commit
and checksums above, and run the conformance test. Never edit it to make a
test pass.

## Known upstream quirks

- Template 13 is spelled `RestransmitReject` in the schema; the specification
  text spells it `RetransmitReject`, and so does this crate. The template id is
  what goes on the wire.
- The `Context` message declares `NextSeqNo` required, while the table in
  section 3.5.3 of the specification marks it optional. The crate follows the
  schema.

## License

The FIXP specification, this schema included, is © Copyright 2014-2021 FIX
Protocol Ltd. and is licensed under the Creative Commons
Attribution-NoDerivatives 4.0 International License, reproduced verbatim in
[`LICENSE-FIXP`](LICENSE-FIXP) (fetched from `LICENSE` at the same commit,
git blob `c23bcfa0671360d5377b70d0d0a1d13edc38dd3c`).

"FIX Performance Session Layer specification" by FIX Protocol Ltd. is licensed
under CC BY-ND 4.0 (<https://creativecommons.org/licenses/by-nd/4.0/>). Based
on a work at <https://github.com/FIXTradingCommunity/fixp-specification>. The
file is unmodified.

That license allows the file to be copied and redistributed unmodified, with
this attribution, but it is not an open-source software license and forbids
distributing modified copies. So the file lives in the IronFix repository for
the test, and it is **excluded from the published `ironfix-fixp` package**
(`exclude` in `ironfix-fixp/Cargo.toml`, together with the test that reads it):
everything that ships on crates.io is MIT. Nothing in the crate is generated
from the schema; the codec is hand-written from the specification and checked
against this file.
