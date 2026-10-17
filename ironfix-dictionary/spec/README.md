# FIX specification data

The XML files in this directory are QuickFIX data dictionaries, vendored
**verbatim** (byte for byte, no edits) from the
[QuickFIX project](https://github.com/quickfix/quickfix) at commit
[`386ce46e917ae494ab6e90b1be90fd421cdbe3f9`](https://github.com/quickfix/quickfix/tree/386ce46e917ae494ab6e90b1be90fd421cdbe3f9/spec)
(2026-05-20). Each was fetched from
`https://raw.githubusercontent.com/quickfix/quickfix/386ce46e917a/spec/<FILE>`.

| File | Upstream path | SHA-256 | Exposed as |
|---|---|---|---|
| `FIX42.xml` | `spec/FIX42.xml` | `de70931a0bbb7c06ee0cd1aed3621a090aea2439dfb7946aa5cd4e481f8cd3fa` | `Dictionary::fix42()` |
| `FIX44.xml` | `spec/FIX44.xml` | `a82655b54363aa9c6d1b2f21f294f1198c0d7125d7b44c26d93d3179f3358425` | `Dictionary::fix44()` |
| `FIXT11.xml` | `spec/FIXT11.xml` | `baf0ef6ddebbbbe32c6d66c00bd4a9bab7ded324c4bbca6a07f42e808090bf20` | `Dictionary::fixt11()` |
| `FIX50SP2.xml` | `spec/FIX50SP2.xml` | `7d34e565586dd4096a08691d10e415b5a2fd531a8dadfcfc831daea419d3c3f3` | `Dictionary::fix50sp2()` |

`FIX44.xml` was vendored earlier from the same project; it is byte-identical to
the file at the commit above.

The files are embedded into the `ironfix-dictionary` crate at compile time via
`include_str!` and parsed on first use. Never edit them to make a test pass:
where the loader needs to understand a construct these files use (a type
spelling such as `UTCDATE` or `XID`, a self-closing component definition), the
loader changes, not the file. To refresh a file, fetch it from a named upstream
commit and update the commit and checksum above.

## License

The QuickFIX data dictionaries are distributed under the QuickFIX Software
License, Version 1.0, reproduced verbatim in [`LICENSE-QUICKFIX`](LICENSE-QUICKFIX)
(fetched from `LICENSE` at the same upstream commit). The rest of the
`ironfix-dictionary` crate is MIT-licensed.

This product includes software developed by quickfixengine.org
(http://www.quickfixengine.org/).
