# FIX Orchestra test fixtures

These are FIX Trading Community FIX Orchestra repositories, vendored
**verbatim** (byte for byte, no edits) from
[FIXTradingCommunity/orchestrations](https://github.com/FIXTradingCommunity/orchestrations):

- `OrchestraFIX44.xml`: FIX 4.4 as of Extension Pack 311;
- `OrchestraFIX42.xml`: FIX 4.2 as of Extension Pack 310;
- `FIXTSession.xml`: the FIXT session layer, which declares
  `FIX.5.0SP2_EP247` and loads as FIXT 1.1 (see the `orchestra` module docs
  for the rule);
- `FixRepository50SP2.xml`: FIX 5.0 SP2, generated from the FIX Unified
  Repository on 2019-03-12, without extension packs.

The first three, and `LICENSE`, were fetched at commit
[`cd24169a2abd8daba7c360987c7a46ca11873a12`](https://github.com/FIXTradingCommunity/orchestrations/tree/cd24169a2abd8daba7c360987c7a46ca11873a12/FIX%20Standard)
(2026-09-08, "Update FIX 4.2, 4.4 and Latest"). Upstream publishes no FIX 5.0
SP2 repository at that commit: `FixRepository50SP2.xml` was replaced by FIX
Latest in commit `d0ad0cd` (2020-03-23, "Replace FIX 5.0SP2 snapshot with FIX
Latest #9"), so it was fetched from its last version, commit
[`fe873abc21c5f5fab217877e4e9c3f45be30e34f`](https://github.com/FIXTradingCommunity/orchestrations/tree/fe873abc21c5f5fab217877e4e9c3f45be30e34f/FIX%20Standard)
(2020-03-03, "Updated to Orchestra v1.0 Draft Standard schema"). The
`LICENSE` at that commit is byte for byte the one below.

| File | Commit | Upstream path | Size | SHA-256 | Git blob |
|---|---|---|---|---|---|
| `OrchestraFIX44.xml` | `cd24169a` | `FIX Standard/OrchestraFIX44.xml` | 1 517 010 bytes | `a36262895e90bbcad2948e0c98072173a571a253ba63107a89617441c67a9f86` | `1a13ac528daaabbbea19a94cc117b3774504ac75` |
| `OrchestraFIX42.xml` | `cd24169a` | `FIX Standard/OrchestraFIX42.xml` | 672 357 bytes | `a64db207c0510eb98b7e4950a055abeb9acb372ce0e847695428bfee2e499091` | `a561973c9ef8ea718103e723ba29d41cdf45b58d` |
| `FIXTSession.xml` | `cd24169a` | `FIX Standard/FIXTSession.xml` | 144 300 bytes | `6c639185022fd6d88aa3959a59ad2ce11c77be791a6416d3b3f662ed3be170a3` | `d1175f6ebca0d928da34bdf5cc9290e03b6612a1` |
| `FixRepository50SP2.xml` | `fe873abc` | `FIX Standard/FixRepository50SP2.xml` | 2 604 558 bytes | `cd9029c3443a66d581e52948ec3820fe9117c16aa670dc87606b3867989a2fb6` | `7c44e6fe5ee8dbb0add5c849f93f90550270184d` |
| `LICENSE` | `cd24169a` | `LICENSE` | 11 357 bytes | `b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1` | `8dada3edaf50dbc082c9a125058f25def75e625a` |

The files are **test fixtures only**: the `ironfix-dictionary` tests load
them with `Dictionary::from_orchestra_xml` and compare each with the embedded
QuickFIX dictionary of its version (`tests/orchestra_fix44.rs`,
`tests/orchestra_equivalence.rs`; the differences are listed in
`doc/orchestra_differences.md`), and `ironfix-codegen-check` generates and
compiles code from `OrchestraFIX44.xml`. They are not embedded in the crate,
and this directory and the tests that include it are excluded from the
published package (`exclude` in `ironfix-dictionary/Cargo.toml`).
Never edit them to make a test pass: where the loader needs to understand a
construct a file uses, the loader changes, not the file. To refresh one,
fetch it from a named upstream commit and update the commit and checksums
above.

## Known upstream issue

The upstream `FIX Standard/Known Issues.md` records that FIX 4.4 types
`MassCancelRejectReason(532)` as `char` where FIX 5.0 corrected it to `int`.
This file's code set for it, `MassCancelRejectReasonCodeSet`, is typed `int`;
the QuickFIX `FIX44.xml` types the field `STRING`. The equivalence test lists
the difference.

## License

The repository is distributed under the Apache License, Version 2.0,
reproduced verbatim in [`LICENSE`](LICENSE) (fetched from `LICENSE` at
`cd24169a`). `OrchestraFIX42.xml` and `OrchestraFIX44.xml` carry their own
metadata reading "Copyright (c) FIX Protocol Ltd. All Rights Reserved."
(`dcterms:rights`); their use here, as test fixtures under the repository's
Apache-2.0 license, was approved by the IronFix owner. The rest of the
`ironfix-dictionary` crate is MIT-licensed.
