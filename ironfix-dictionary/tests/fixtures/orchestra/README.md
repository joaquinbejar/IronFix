# FIX Orchestra test fixture

`OrchestraFIX44.xml` is the FIX Trading Community's FIX Orchestra repository
for FIX 4.4 as of Extension Pack 311, vendored **verbatim** (byte for byte, no
edits) from
[FIXTradingCommunity/orchestrations](https://github.com/FIXTradingCommunity/orchestrations)
at commit
[`cd24169a2abd8daba7c360987c7a46ca11873a12`](https://github.com/FIXTradingCommunity/orchestrations/tree/cd24169a2abd8daba7c360987c7a46ca11873a12/FIX%20Standard)
(2026-09-08, "Update FIX 4.2, 4.4 and Latest"). It was fetched from
`FIX Standard/OrchestraFIX44.xml` at that commit.

| File | Upstream path | Size | SHA-256 | Git blob |
|---|---|---|---|---|
| `OrchestraFIX44.xml` | `FIX Standard/OrchestraFIX44.xml` | 1 517 010 bytes | `a36262895e90bbcad2948e0c98072173a571a253ba63107a89617441c67a9f86` | `1a13ac528daaabbbea19a94cc117b3774504ac75` |
| `LICENSE` | `LICENSE` | 11 357 bytes | `b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1` | `8dada3edaf50dbc082c9a125058f25def75e625a` |

The file is a **test fixture only**: the `ironfix-dictionary` tests load it
with `Dictionary::from_orchestra_xml` and compare the result with the embedded
QuickFIX FIX 4.4 dictionary, and `ironfix-codegen-check` generates and compiles
code from it. It is not embedded in the crate, and this directory and the test
that includes it (`tests/orchestra_fix44.rs`) are excluded from the published
package (`exclude` in `ironfix-dictionary/Cargo.toml`).
Never edit it to make a test pass: where the loader needs to understand a
construct the file uses, the loader changes, not the file. To refresh it, fetch
it from a named upstream commit and update the commit and checksums above.

## Known upstream issue

The upstream `FIX Standard/Known Issues.md` records that FIX 4.4 types
`MassCancelRejectReason(532)` as `char` where FIX 5.0 corrected it to `int`.
This file's code set for it, `MassCancelRejectReasonCodeSet`, is typed `int`;
the QuickFIX `FIX44.xml` types the field `STRING`. The equivalence test lists
the difference.

## License

The repository is distributed under the Apache License, Version 2.0,
reproduced verbatim in [`LICENSE`](LICENSE) (fetched from `LICENSE` at the
same upstream commit). The file's own metadata reads "Copyright (c) FIX
Protocol Ltd. All Rights Reserved." (`dcterms:rights`); its use here, as a
test fixture under the repository's Apache-2.0 license, was approved by the
IronFix owner. The rest of the `ironfix-dictionary` crate is MIT-licensed.
