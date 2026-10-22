# Changelog

All notable changes to the IronFix workspace are recorded here. Versions
follow [Semantic Versioning](https://semver.org/); while the workspace is at
0.x, a change that breaks behaviour or the public API takes a minor bump.

## 0.5.1 (2026-10-22)

Breaking: a minor bump at 0.x. `cargo-semver-checks` against 0.5.0 finds no
API break in any package; the bump is for the dictionary behaviour changes
below.

### Changed: published licences are declared and checked (#202)

- `ironfix-dictionary` declares `license = "MIT AND Apache-2.0"`: its code is
  MIT and the FIX Orchestra repositories it embeds are Apache-2.0
  (`spec/orchestra/LICENSE`, shipped in the crate). Every other crate stays
  `MIT`.
- `make check-licences` (CI, `lint.yml`) lists what each publishable crate
  publishes and fails on a licence file or vendored specification the
  crate's `license` does not declare, and on any QuickFIX or FIXP
  specification content. It replaces `make check-package-fixp`, kept as an
  alias.
- `deny.toml` and a `cargo deny check licenses` CI job allow MIT and
  Apache-2.0 for dependencies, plus five named permissive exceptions
  (Unicode-3.0, BSD-3-Clause, ISC).

### Changed: embedded dictionaries come from FIX Orchestra (#201)

`ironfix-dictionary` no longer ships QuickFIX content. `Dictionary::fix42()`,
`fix44()`, `fixt11()` and `fix50sp2()` keep their names, signatures and
caching, but are now built from the FIX Trading Community's FIX Orchestra
repositories (Apache-2.0, vendored verbatim under
`ironfix-dictionary/spec/orchestra/`). FIX 5.0 SP2 is derived from FIX
Latest by pedigree. `Dictionary::from_quickfix_xml` stays for your own
QuickFIX files.

**Semver impact: released as a patch (0.5.1), by owner decision.**
`cargo-semver-checks` reports no API break against 0.5.0, but the
dictionaries answer differently, so a `cargo update` within 0.5 changes
validation results and generated code. Pin `=0.5.0` to keep the QuickFIX-based
dictionaries. Every difference is listed in
`doc/orchestra_differences.md`; the ones users observe:

- **FIX 5.0 SP2 validates more strictly.** 1233 more fields carry an
  enumeration, so a value outside it is `ValidationError::InvalidEnumValue`
  when validation is on. 141 fields are no longer defined (86 added by FIX
  Latest after FIX 5.0 SP2, 55 deprecated by FIX 5.0 SP2, among them
  `Signature(89)`); a message carrying one reports `UnknownTag`.
- **FIX 5.0 SP2 is a complete dictionary.** It defines the standard header,
  the trailer and the session messages. Composed with FIXT 1.1 nothing
  changes; validated alone, a complete message now passes instead of every
  header tag being reported.
- **FIXT 1.1 defines the Logon `NoMsgTypes(384)` group** and enumerates
  `DefaultApplVerID(1137)`, `MsgType(35)` and `RefMsgType(372)`. A Logon
  carrying the group now validates; an unknown `DefaultApplVerID` is
  `InvalidEnumValue`.
- **Field types change**: FIX 4.4 `MassCancelRejectReason(532)` and
  `LegAllocAcctIDSource(674)` are `Int` (were `String`).
- **Names change**: `HaltReason(327)` in every version; FIX 4.2 `IOIID(23)`,
  `QuoteAckStatus(297)`, `AllocationAck (P)`; FIX 5.0 SP2
  `DerivativeOptPayoutAmount(1225)`, `RateSourceReferencePageHeading(2412)`,
  `RoutingArrangementIndicator(2883)`,
  `ContraRoutingArrangementIndicator(2884)`, `ExecutionAcknowledgement (BN)`,
  `MassQuoteAcknowledgement (b)`. `Dictionary::get_field_by_name` and
  generated identifiers follow.
- **More fields are required** in some messages, mostly the count tag of a
  block Orchestra holds as a required group (`NoPartyIDs(453)` in several
  FIX 4.4 and 5.0 SP2 messages).
- **Generated code changes shape.** Orchestra holds blocks such as `Parties`
  as groups: `ironfix-codegen` emits per-message entry types and views
  (`NewOrderSingleNoPartyIDsEntry`) where it emitted a shared component
  (`Parties`).
- **Crate size and first load.** The published `ironfix-dictionary` crate
  grows (the FIX Latest repository is 8.6 MB uncompressed), and first loads
  take longer; see the #201 pull request for the figures.

### Added (#200)

- `Dictionary::from_orchestra_latest_xml(xml, Version::Fix50Sp2)` derives a
  FIX 5.0 SP2 dictionary from a FIX Latest Orchestra repository.
  `Dictionary::from_orchestra_xml` still rejects FIX Latest. Minor.
- `Dictionary::from_orchestra_xml` loads the FIX Trading Community's FIXT
  session repository (which declares `FIX.5.0SP2_EP247`) as FIXT 1.1, maps a
  data field's `lengthId` to a `Length` field, and marks the session
  message types admin in a repository that gives its messages no category
  (FIX 4.2). Minor.

### Fixed (#200)

- `Validator::for_session` admits, for a field both the transport and the
  application dictionary enumerate, the values of either; a transport that
  lists only the session message types for `MsgType(35)` no longer rejects
  every application message. Patch.
