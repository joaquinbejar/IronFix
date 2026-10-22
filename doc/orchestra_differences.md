# FIX Orchestra vs. QuickFIX: dictionary differences

`ironfix-dictionary` embeds four QuickFIX XML dictionaries (FIX 4.2, FIX 4.4,
FIXT 1.1, FIX 5.0 SP2). Issue #200 loads the FIX Trading Community's FIX
Orchestra repository for each of these versions with
`Dictionary::from_orchestra_xml` and diffs it against the embedded QuickFIX
dictionary. This page records every difference the diff finds and how it is
decided.

**Policy: on a conflict, Orchestra wins.** Orchestra is the FIX Trading
Community's own machine-readable standard; QuickFIX is a third party's
rendering of it. When Orchestra becomes the embedded source (issue #201), the
dictionary answers what the Orchestra repository says.

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

| Version | Orchestra repository (test fixture) | Upstream commit | QuickFIX file |
|---|---|---|---|
| FIX 4.2 | `OrchestraFIX42.xml` (FIX 4.2 as of EP310) | `cd24169a` | `spec/FIX42.xml` |
| FIX 4.4 | `OrchestraFIX44.xml` (FIX 4.4 as of EP311) | `cd24169a` | `spec/FIX44.xml` |
| FIXT 1.1 | `FIXTSession.xml` (FIXT session layer, declares `FIX.5.0SP2_EP247`) | `cd24169a` | `spec/FIXT11.xml` |
| FIX 5.0 SP2 | `FixRepository50SP2.xml` (FIX 5.0 SP2, generated 2019-03-12, no extension pack) | `fe873abc` | `spec/FIX50SP2.xml` |

The FIX Trading Community publishes no FIX 5.0 SP2 Orchestra repository
today: `FixRepository50SP2.xml` was replaced by FIX Latest in March 2020
(upstream `d0ad0cd`), and `fe873abc` is its last version. FIX Latest is FIX
5.0 SP2 plus every extension pack since, but it names no fixed FIX version, so
the loader rejects it. See
`ironfix-dictionary/tests/fixtures/orchestra/README.md` for provenance and
checksums.

## Summary

| Version | Orchestra-only | QuickFIX-only | Conflicting | Total |
|---|---:|---:|---:|---:|
| FIX 4.2 | 7 | 0 | 11 | 18 |
| FIX 4.4 | 43 | 0 | 3 | 46 |
| FIXT 1.1 | 12 | 1 | 0 | 13 |
| FIX 5.0 SP2 | 153 | 415 | 19 | 587 |

## FIX 4.2

| Class | Difference | Decision |
|---|---|---|
| Conflicting | Field names: `IOIID(23)` vs `IOIid`, `QuoteAckStatus(297)` vs `QuoteStatus`, `HaltReason(327)` vs `HaltReasonChar` | Orchestra |
| Conflicting | Message name: `AllocationAck (P)` vs `AllocationInstructionAck` | Orchestra |
| Conflicting | Category of `0`, `1`, `2`, `3`, `4`, `5`, `A`: the repository gives its messages no category, so they load as application messages; QuickFIX marks them admin | Orchestra; see below |
| Orchestra-only | Code sets for `156`, `172`, `394`, `399`, `401`, `429`, `431` | Orchestra |

Messages, required fields, header, trailer and groups agree. Every data
field's length field (`RawDataLength(95)`, ...) is typed `int` in the FIX 4.2
repository, which has no `Length` datatype; the loader maps each field's
`lengthId` and types the field it names `Length`, as QuickFIX does, so these
fields do not differ.

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
| Orchestra-only | Code sets for `MsgType(35)` and `RefMsgType(372)`, listing only the session message types (`0`-`5`, `A`, `j`, `n`) | Orchestra; **affects #201**, see below |
| Orchestra-only | Code sets, or codes, for `ApplVerID(1128)`, `RefApplVerID(1130)`, `DefaultApplVerID(1137)`, `SessionStatus(1409)` | Orchestra |
| Orchestra-only | The Logon `NoMsgTypes(384)` group (`372`, `385`, `1130`, `1131`, `1406`, `1410`), the Logon session qualifiers (`1600`-`1605`), `XMLnonFIX`'s `NoMessageEvents(2104)` group, `1744` in `SequenceReset`, `NextExpectedMsgSeqNum(789)` in `Logout` | Orchestra: this also closes the `MsgTypeGrp` deviation documented in `spec/README.md` |
| QuickFIX-only | Component `MsgTypeGrp` (empty in QuickFIX) | Orchestra |

## FIX 5.0 SP2

Most differences come from the two files' vintages, not from modelling: the
Orchestra snapshot is FIX 5.0 SP2 without extension packs, and QuickFIX's
`FIX50SP2.xml` includes later extension packs.

| Class | Difference | Decision |
|---|---|---|
| Orchestra-only | Session messages `0`-`5`, `A`, `n`, the standard header and trailer (QuickFIX keeps them in `FIXT11.xml`; its `FIX50SP2.xml` header and trailer are empty) | Orchestra |
| Orchestra-only | Members in `BZ` and `r` (`41`), required flags on 32 messages (mostly the flattened flag of a block held as a required group), codes for 106 fields, groups `NoMsgTypes(384)` and `NoHops(627)` | Orchestra |
| QuickFIX-only | 48 messages (`CF` to `EB`), 4 576 fields, their groups and 154 components, members of 95 messages, codes for 115 fields, `W` requiring `779`: all from extension packs after the snapshot | Orchestra; **affects #201**, see below |
| Conflicting | 11 fields: names (`1008`, `327`) and types (`1009`, `1193`, `1283`, `1317`, `1492`, `1493`, `213`, `674`, `877`) | Orchestra |
| Conflicting | Message names: `ExecutionAcknowledgement (BN)`, `MassQuoteAcknowledgement (b)` | Orchestra |
| Conflicting | `NoOrders(534)` delimiter (`41` vs `1824`), and the member order of `NoLegs(555)` in five layouts | Orchestra |

## Differences that matter for #201

When Orchestra replaces the embedded QuickFIX files, these differences change
behaviour:

1. **FIXT 1.1: `MsgType(35)` gains an enumeration of the session message
   types only.** Composed as the transport side of a `SessionDictionary`,
   the header comes from the transport dictionary, so
   `Validator::for_session` reports every application message as
   `InvalidEnumValue { tag: 35 }` (checked: a `35=D` that validates against
   QuickFIX `FIXT11.xml` + `FIX50SP2.xml` fails against the Orchestra FIXT
   repository + `FIX50SP2.xml`). `RefMsgType(372)` in `Reject` is restricted
   the same way. #201 must decide how the transport enumeration of these two
   fields composes with the application dictionary before switching.
2. **FIX 5.0 SP2: the only Orchestra source loses 48 messages and 4 576
   fields** that the embedded QuickFIX file carries today, and every type
   and layout change the extension packs made. Switching to it is a
   regression for any user of those messages. The FIX Latest repository has
   them, but the loader rejects FIX Latest by design; #201 needs an owner
   decision on the FIX 5.0 SP2 source.
3. **FIX 5.0 SP2: the dictionary gains a header, a trailer and the session
   messages.** Composed with a FIXT 1.1 transport this is harmless (admin
   messages and the envelope come from the transport side), but used alone
   the dictionary now validates the header.
4. **FIX 4.2: session messages lose the admin category.** No engine path
   reads the category (the engine decides what is administrative by message
   type), and `SessionDictionary` only takes it from the transport side,
   which is FIXT 1.1; generated code and any caller filtering on
   `MessageCategory::Admin` would see the change.
5. **Field types change** (FIX 4.4 `532`, `674`; FIX 5.0 SP2 `1009`, `1193`,
   `1283`, `1317`, `1492`, `1493`, `213`, `674`, `877`): the validator checks
   values against the new types, and generated code changes type.
6. **Field and message names change** (`327` in every version, FIX 4.2 `23`,
   `297`, `P`, FIX 5.0 SP2 `1008`, `BN`, `b`): `Dictionary::get_field_by_name`
   and generated identifiers follow.

Existing tests that pin QuickFIX content (for example `spec/README.md`'s
`MsgTypeGrp` deviation and the tests built on it) will need updating in #201.
