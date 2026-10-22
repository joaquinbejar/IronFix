# FIX Orchestra vs. QuickFIX: dictionary differences

Up to 0.5, `ironfix-dictionary` embedded four QuickFIX XML dictionaries (FIX
4.2, FIX 4.4, FIXT 1.1, FIX 5.0 SP2); since #201 it embeds the FIX Orchestra
repositories below instead, and the QuickFIX files are test fixtures only
(`ironfix-dictionary/tests/fixtures/quickfix/`). Issue #200 loads the FIX Trading Community's FIX
Orchestra repository for each of these versions with
`Dictionary::from_orchestra_xml` (FIX 5.0 SP2 is derived from FIX Latest
with `Dictionary::from_orchestra_latest_xml`) and diffs it against the embedded QuickFIX
dictionary. This page records every difference, which is what a user of
the embedded dictionaries observes on upgrading, the diff finds and how it is
decided.

**Policy: on a conflict, Orchestra wins.** Orchestra is the FIX Trading
Community's own machine-readable standard; QuickFIX is a third party's
rendering of it. The embedded dictionaries answer what the Orchestra
repositories say.

## How the diff is made

`ironfix-dictionary/tests/orchestra_equivalence.rs` loads both dictionaries
and compares, flattened through components (Orchestra holds blocks such as
`Parties` as groups where QuickFIX wraps the group in a component, so the two
models only agree once components are expanded):

- **fields**: tag, name, type, enumeration values;
- **messages**: message type, name, category, the tags each can carry, the
  tags it must carry (outside groups);
- **components**: name and the tags each can carry, except a QuickFIX
  component that only wraps one group (its content is compared where
  messages use it);
- **header and trailer**: tags, required tags;
- **repeating groups**: which groups (by count tag) each side holds, and, for
  a group both hold at the same place, its delimiter and the order of the
  members both list.

Each difference is one line, classed **Orchestra-only**, **QuickFIX-only** or
**conflicting**. The lines are an explicit allowlist, one file per version
under `ironfix-dictionary/tests/orchestra_equivalence/`; each file carries a
comment above every block of lines stating its cause. A difference missing
from the allowlist fails the test, and so does an allowlisted one that no
longer occurs.

## Sources

| Version | Orchestra repository (embedded, `spec/orchestra/`) | Loaded with | QuickFIX file |
|---|---|---|---|
| FIX 4.2 | `OrchestraFIX42.xml` (FIX 4.2 as of EP310) | `from_orchestra_xml` | `tests/fixtures/quickfix/FIX42.xml` |
| FIX 4.4 | `OrchestraFIX44.xml` (FIX 4.4 as of EP311) | `from_orchestra_xml` | `tests/fixtures/quickfix/FIX44.xml` |
| FIXT 1.1 | `FIXTSession.xml` (FIXT session layer, declares `FIX.5.0SP2_EP247`) | `from_orchestra_xml` | `tests/fixtures/quickfix/FIXT11.xml` |
| FIX 5.0 SP2 | `OrchestraFIXLatest.xml` (FIX Latest as of EP312) | `from_orchestra_latest_xml(.., Version::Fix50Sp2)` | `tests/fixtures/quickfix/FIX50SP2.xml` |

All four were fetched from FIXTradingCommunity/orchestrations at commit
`cd24169a` and are embedded from `ironfix-dictionary/spec/orchestra/`; the
QuickFIX files are under `ironfix-dictionary/tests/fixtures/quickfix/`. The FIX Trading Community no longer publishes a FIX 5.0 SP2
repository (its last snapshot was replaced by FIX Latest in March 2020, and
had no extension packs), so FIX 5.0 SP2 is derived from FIX Latest by
pedigree: what was added at or before FIX 5.0 SP2 and not deprecated by
then (see the `orchestra` module docs for the rule). See
`ironfix-dictionary/spec/orchestra/README.md` for provenance and
checksums.

## Summary

| Version | Orchestra-only | QuickFIX-only | Conflicting | Total |
|---|---:|---:|---:|---:|
| FIX 4.2 | 7 | 0 | 4 | 11 |
| FIX 4.4 | 43 | 0 | 3 | 46 |
| FIXT 1.1 | 12 | 1 | 0 | 13 |
| FIX 5.0 SP2 | 1290 | 181 | 5 | 1476 |

## FIX 4.2

| Class | Difference | Decision |
|---|---|---|
| Conflicting | Field names: `IOIID(23)` vs `IOIid`, `QuoteAckStatus(297)` vs `QuoteStatus`, `HaltReason(327)` vs `HaltReasonChar` | Orchestra |
| Conflicting | Message name: `AllocationAck (P)` vs `AllocationInstructionAck` | Orchestra |
| Orchestra-only | Code sets for `156`, `172`, `394`, `399`, `401`, `429`, `431` | Orchestra |

Messages, required fields, header, trailer and groups agree. Two loader
rules close what would otherwise differ:

- the FIX 4.2 repository gives its messages no category; when no message
  of a repository has one, the loader marks the session message types
  (`0` to `5`, `A`, `n`) admin, as QuickFIX does;
- every data field's length field (`RawDataLength(95)`, ...) is typed `int`
  in the FIX 4.2 repository, which has no `Length` datatype; the loader
  maps each data field's `lengthId` and types the field it names `Length`.

## FIX 4.4

| Class | Difference | Decision |
|---|---|---|
| Conflicting | Field name: `HaltReason(327)` vs `HaltReasonChar` | Orchestra |
| Conflicting | Types of `MassCancelRejectReason(532)` and `LegAllocAcctIDSource(674)`: `int` vs `STRING` (the upstream known issue for 532) | Orchestra |
| Orchestra-only | Code sets, or single codes, for 32 fields: nested party roles and sources, security identifier sources, `RefMsgType(372)`, `ExecInst(18)` `T`, `OrdStatus(39)` `5`, `OrdRejReason(103)` `12`, ... | Orchestra |
| Orchestra-only | Members: `ClearingFeeIndicator(635)` in `AE`, `OrigOrdModTime(586)` in `s` and `t` | Orchestra |
| Orchestra-only | Required: count tags of blocks Orchestra holds as required groups and QuickFIX as a required component around an optional group (`AK`, `AL`, `AM`, `AN`, `AO`, `AP`, `AW`); `CollInquiryID(909)` in `BB` | Orchestra |

## FIXT 1.1

| Class | Difference | Decision |
|---|---|---|
| Orchestra-only | Code sets for `MsgType(35)` and `RefMsgType(372)`, listing only the session message types (`0`-`5`, `A`, `j`, `n`) | Orchestra; under composition the validator takes the union with the application's message types, see below |
| Orchestra-only | Code sets, or codes, for `ApplVerID(1128)`, `RefApplVerID(1130)`, `DefaultApplVerID(1137)`, `SessionStatus(1409)` | Orchestra |
| Orchestra-only | The Logon `NoMsgTypes(384)` group (`372`, `385`, `1130`, `1131`, `1406`, `1410`), the Logon session qualifiers (`1600`-`1605`), `XMLnonFIX`'s `NoMessageEvents(2104)` group, `1744` in `SequenceReset`, `NextExpectedMsgSeqNum(789)` in `Logout` | Orchestra: this also closes the `MsgTypeGrp` deviation documented in `spec/README.md` |
| QuickFIX-only | Component `MsgTypeGrp` (empty in QuickFIX) | Orchestra |

## FIX 5.0 SP2

The derived dictionary holds 164 messages: all 156 of QuickFIX's
`FIX50SP2.xml`, and the eight session messages (`0` to `5`, `A`, `n`) that
QuickFIX keeps in `FIXT11.xml`. It holds 5887 fields against QuickFIX's
6028 and 163 components.

| Class | Difference | Decision |
|---|---|---|
| Orchestra-only | Session messages `0` to `5`, `A`, `n`, the standard header and trailer, the groups `NoHops(627)` (header) and `NoMsgTypes(384)` (Logon) | Orchestra |
| Orchestra-only | Code sets, or codes, for 1233 fields: QuickFIX enumerates 668 of its 6028 fields, Orchestra many more | Orchestra; a behaviour change, see below |
| Orchestra-only | Required flags on 44 messages, mostly the flag of a block Orchestra holds as a required group (`Parties`, `PositionQty`, `MDFullGrp`, ...) where QuickFIX holds a required component around an optional group | Orchestra |
| QuickFIX-only | 141 fields: 86 FIX Latest added after FIX 5.0 SP2 (extension packs 266 to 280, which QuickFIX's file includes) and 55 deprecated at or before FIX 5.0 SP2 (`Signature(89)` and its kin moved to FIXT 1.1, `RepurchaseTerm(226)`, ...), with the members of 121 messages and 22 components, the groups `NoUnderlyingLegs(1342)` and `NoUnderlyingLegSecurityAltID(1334)`, and the required flags on `W` (`779`) and `r` (`37`) | Orchestra: the pedigree places them outside FIX 5.0 SP2 |
| QuickFIX-only | Codes for 34 fields, added after FIX 5.0 SP2 or deprecated by then | Orchestra |
| Conflicting | Field names: `HaltReason(327)`, `DerivativeOptPayoutAmount(1225)`, and QuickFIX misspellings `RateSourceReferemcePageHeading(2412)`, `RoutingArrangmentIndicator(2883)`, `ContraRoutingArrangmentIndicator(2884)` | Orchestra |

No group delimiter, member order or field type differs.

## Behaviour changes since 0.5

With Orchestra as the embedded source (#201), these differences change
behaviour:

1. **FIXT 1.1: `MsgType(35)` and `RefMsgType(372)` list only the session
   message types.** Resolved in #200: under `Validator::for_session`, a
   field both dictionaries enumerate admits the values of either, so an
   application message type is valid in a FIXT.1.1 header and in a session
   Reject (tested against the Orchestra FIXT repository composed with the
   derived FIX 5.0 SP2 dictionary).
2. **FIX 5.0 SP2: 1233 fields gain an enumeration.** The validator then
   rejects a value outside it with `InvalidEnumValue` where it accepted any
   value before. Counterparties that send unlisted or user-defined codes
   (the `Reserved100Plus` ranges Orchestra marks with `unionDataType`, which
   the loader reports but does not map) will see Rejects when validation is
   on.
3. **FIX 5.0 SP2: 141 fields leave the dictionary**: those FIX Latest added
   after FIX 5.0 SP2 and those deprecated by FIX 5.0 SP2. A message that
   carries one is reported as `UnknownTag` when validated.
4. **FIX 5.0 SP2: the dictionary gains a header, a trailer and the session
   messages.** Composed with a FIXT 1.1 transport this is harmless (admin
   messages and the envelope come from the transport side), but used alone
   the dictionary now validates the header.
5. **Field types change** (FIX 4.4 `532`, `674`): the validator checks values
   against the new types, and generated code changes type.
6. **Field and message names change** (`327` in every version, FIX 4.2 `23`,
   `297`, `P`, FIX 5.0 SP2 `1225`, `2412`, `2883`, `2884`):
   `Dictionary::get_field_by_name` and generated identifiers follow.

7. **FIXT 1.1: the Logon `NoMsgTypes(384)` group is defined**, closing the
   deviation the QuickFIX `FIXT11.xml` carried; `DefaultApplVerID(1137)` is
   enumerated, so an unknown application version is `InvalidEnumValue`.
8. **Generated code changes shape.** Orchestra holds blocks such as
   `Parties` as groups, not components: `ironfix-codegen` emits one entry
   type and one view per message (`NewOrderSingleNoPartyIDsEntry`) where it
   emitted one shared component type (`Parties`, `PartiesNoPartyIDsEntry`).
