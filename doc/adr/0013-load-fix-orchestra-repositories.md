# ADR-0013 — Load FIX Orchestra repositories into the dictionary model

- **Status:** Accepted
- **Date:** 2026-10-18

## Context

`ironfix-dictionary` read QuickFIX XML only. The FIX Trading Community
publishes the machine-readable standard as FIX Orchestra repositories: the
FIX Latest content, the legacy FIX 4.2 and 4.4 translations, the session
layers, and venue rules of engagement (issue #73). Orchestra models more than
QuickFIX XML does, and models some of the same things differently:

- every definition (field, code set, component, group, message) has a numeric
  `id`, and members reference definitions by id, not by name;
- a repeating group is a named definition of its own (`Parties`, id 1012),
  referenced with `groupRef`, where QuickFIX writes the group inline or wraps
  it in a component;
- enumerations are code sets, named by a field's `type`, and datatypes declare
  a `baseType`;
- a definition belongs to a scenario (`base` by default), so one message can
  have several variants;
- a member's presence can be `forbidden`, `ignored` or `constant`, and can
  depend on conditional `rule`s;
- workflow (actors, flows, message responses), concepts, value constraints
  (`minInclusive`, `implMaxLength`, `implMaxOccurs`, ...), documentation and
  pedigree (`added`, `updated`, `deprecated`).

The `Dictionary` model holds fields, enumerations, components, inline groups,
messages, required flags and member order; nothing else. The repository is
untrusted input, like any dictionary file (issue #14).

Expansion sizes, counted from the upstream files at the pinned commit (every
member at every place a group is inlined): FIX 4.4 4 226, FIX Latest (EP312)
17 515.

## Decision

**API.** `Dictionary::from_orchestra_xml(&str) -> Result<OrchestraImport,
DictionaryError>`, in a new module `ironfix-dictionary/src/orchestra.rs`.
`OrchestraImport` has private fields, `dictionary()`, `report()` and
`into_parts()`. `OrchestraReport` lists `UnmappedConstruct` entries, in
document order and then the unreferenced definitions (`entries()`, `len()`,
`is_empty()`). `UnmappedConstruct` and
`OrchestraKind` are `#[non_exhaustive]`, and so is every variant of
`UnmappedConstruct`, so entries and their fields can grow in a minor release.
`DictionaryError` (already `#[non_exhaustive]`) gains `NotOrchestra`,
`DocumentTooLarge`, `AttributesTooLong`, `InvalidOrchestraId`,
`UnknownOrchestraReference`, `DuplicateOrchestraDefinition`,
`UnknownDatatype`, `MissingCountField`, `GroupCycle`, `TooManyMembers`,
`EnvelopeReference`, `NameTooLong`, `TooManyUnmapped` and `TooManyFieldValues`; the existing variants are reused where they fit
(`UnsupportedVersion`, `MissingAttribute`, `UnknownFieldType`, `EmptyGroup`,
`ComponentCycle`, `NestingTooDeep`, `DuplicateDefinition`,
`DuplicateFieldTag`, `Xml`). `DefinitionKind` is not extended: it is
exhaustive, and a variant would break callers; Orchestra errors carry
`OrchestraKind` instead.

Rejected: returning a `(Dictionary, Report)` tuple (no room to add to the
result later); logging the unmapped constructs with `tracing` (a caller needs
them as data, and a dictionary load is not a runtime event); a strict mode
that fails on any unmapped construct (a caller who wants that checks
`report().is_empty()`).

**Orchestra version.** Orchestra 1.0, namespace
`http://fixprotocol.io/2020/orchestra/repository` (`ORCHESTRA_NAMESPACE`), the
namespace of the FIX 4.2, FIX 4.4, FIX Latest and FIXT session repositories
the FIX Trading Community publishes at the pinned commit. A root that is
not `repository` in that namespace, including the 1.1 drafts' `http://fixprotocol.io/2026/orchestra/repository`, is
`NotOrchestra`. The loader reads with quick-xml's `NsReader` (namespace
resolution, local names); no new dependency.

**FIX version.** From `repository/@version`: `FIX.4.0` to `FIX.4.4`, `FIX.5.0`,
`FIX.5.0SP1`, `FIX.5.0SP2` and `FIXT.1.1`, each optionally followed by an
extension-pack suffix `_EP<n>` (`FIX.4.4_EP311` is FIX 4.4). Anything else is
`UnsupportedVersion`: `FIX.Latest` names no fixed FIX version and
`ironfix_core::FixVersion` has no variant for it, and the pre-4.0 versions,
`major.minor` and date versions name none either. The repository's stable
`name` is descriptive, with one exception: a repository named `FIXT` can only
describe FIXT.1.1, so one whose version is not `FIXT.1.1` is
`UnsupportedVersion` too. The FIX Trading Community's `FIXTSession.xml` is
one: it declares `FIX.5.0SP2_EP247`, and loading it as a FIX 5.0 SP2
dictionary would mislabel the FIXT.1.1 session layer it describes.

**Scenarios.** Only `base` is loaded. A definition in another scenario is
reported (`UnmappedConstruct::Scenario`) and not loaded; a member referencing
another scenario is reported (`ScenarioReference`) and left out.

**Mapping.**

| Orchestra | `Dictionary` |
|---|---|
| `field` (`id` is the tag) | `FieldDef` |
| `datatype` | `FieldType`: its own name when that is a FIX data type (the same spellings `FieldType::from_str` accepts for QuickFIX), else its `baseType`'s, following at most `MAX_COMPONENT_DEPTH` base types; the datatype must be declared |
| `codeSet` named by a field's `type` | the field's type is the code set's `type`; `FieldDef::values` maps each `base` code value to the code name |
| `component` named `StandardHeader` / `StandardTrailer` | `Dictionary::header` / `trailer` and their groups |
| any other `component` | `ComponentDef`, keeping its name |
| `group`, at each `groupRef` | an inline `GroupDef` named after its `numInGroup` field |
| `message` | `MessageDef`; category `Session` is `MessageCategory::Admin`, any other `App` |
| `presence="required"` / `"optional"` | `required` |

Members keep the order the repository lists them in, through the ordered
`new(..., members)` constructors of ADR-0016. A group's delimiter is its first
member, through components, as in QuickFIX.

*Group naming.* Groups are named after their count field (`NoPartyIDs`, not
`Parties`), as QuickFIX names them, so a dictionary loaded from either source
names a group the same way and code generated from it keeps its names. The
Orchestra group name has no place in the model and is not kept.

*Envelope.* `StandardHeader` and `StandardTrailer` are the FIX standard's
component names for the envelope, which the dictionary keeps apart from the
body. A message's own reference to either is the envelope, not a member. A
reference from a component or group is `EnvelopeReference`. A component the
header or trailer references is expanded in place, because the dictionary
holds the envelope as fields and groups. Its members keep their own presence
when the reference is required; when it is optional they become optional,
since they are required only with the block, through nested components too.
The members of a group's entries keep theirs: they are required per entry.

*Category.* The FIX standard repositories file the session-level messages
under category `Session`; that is the dictionary's answer to admin versus
application, with no list of message types in the loader.

**Reported, not mapped.** Each becomes an `UnmappedConstruct`, in document
order, then the unreferenced definitions:

- `Element`: an element the loader does not map, skipped with its content:
  `actors`, `concepts`, a message's `responses`, a member's `assign` or
  `blockAssignment`, an element from another namespace, or one Orchestra 1.0
  does not define;
- `Scenario` / `ScenarioReference`: see above;
- `Presence`: `forbidden` (the member is left out), `ignored` and `constant`
  (kept, optional; a constant's `value` is in the entry), or an undefined
  value (kept, optional);
- `Rule`: a conditional presence rule, not evaluated, with its name, the
  presence it gives and its `when` condition (character and entity
  references resolved); the member keeps its static presence;
- `Attribute`: an attribute that constrains what the model cannot hold
  (`minInclusive`, `maxInclusive`, `implLength`, `implMinLength`,
  `implMaxLength`, `implMinOccurs`, `implMaxOccurs`, `lengthId`,
  `discriminatorId`, `unionDataType`, `encoding`, a code set's `default`,
  `which`, `instanceName`, `supported` other than `supported`, the `value`
  of a member whose presence is `optional` or `required`), and any attribute
  Orchestra 1.0 does not define. A member's `value` is reported once: with
  its presence when the presence is reported, as an attribute otherwise;
- `Unreferenced`: a `base` group no message or component reaches, or a code
  set no field names. The dictionary holds a group only where it is
  referenced and a code set only on its fields. Every group is checked all
  the same: its count field is present, every id it references resolves,
  and the groups it nests form no cycle (`GroupCycle`) and no chain deeper
  than a message can hold (`NestingTooDeep`), by a memoised walk from every
  group (linear in the group references, its recursion bounded by the
  nesting limit). An unreferenced group cannot hide a dangling id, a cycle
  or an over-deep chain.

A mapped section's own attributes (`<fixr:fields custom="x">`, self-closing
sections included) are read like any element's: bounded by the attribute and
name limits, and reported unless descriptive (`latestEP`, `xml:base`). A
code's id is unique within its code set among `base` codes; a code of
another scenario may reuse one.

The issue asks for unknown elements to be typed errors; they are reported
instead, because Orchestra allows elements from other namespaces and a
repository from a later schema revision should load with what this loader
understands. Hostile nesting and sizes inside an unknown element are still
typed errors.

**Ignored without an entry** (descriptive): `annotation` (documentation and
appinfo), `metadata`, `categories`, `sections`, `mappedDatatype`, the
repository's stable `name`, and the pedigree, naming and grouping attributes
(`added`, `addedEP`, `updated`, `updatedEP`, `deprecated`, `deprecatedEP`,
`replaced`, `replacedEP`, `replacedByField`, `changeType`, `issue`,
`lastModified`, `abbrName`, `category`, `section`, `rendering`,
`baseCategory`, `baseCategoryAbbrName`, `specUrl`, `latestEP`, `guid`,
`namespace`, `applVerId`, `expressionLanguage`, `sort`, `group`,
`FIXMLFileName`, `componentType`, `includeFile`, `displayOrder`, `flow`),
namespace declarations and `xml:` attributes.

**One assembly step.** The QuickFIX loader's assembly is now crate-internal and
shared: `loader::assemble` takes the parsed document (`Item` members by name,
`MessageIr`, `ComponentIrs`) and runs `check_component_graph`, the duplicate
checks and the name resolution for both loaders. The Orchestra loader parses
the repository into definitions that reference by id, resolves the ids into
those name references (inlining each group), and hands them over, so both
loaders reject a component cycle, an over-deep component chain, a duplicate
field name or tag, a duplicate message type and an empty group the same way.
Finding a group's delimiter walks each component once: its first tag is
cached, so a chain of components without fields, each referencing the next
twice, costs one walk per component instead of one per path (a QuickFIX
document had the same exponential walk).

**Untrusted input.** Every malformed repository is a typed error, never a panic
or an unbounded recursion:

| Limit | Value | Bounds |
|---|---|---|
| `MAX_ORCHESTRA_DOCUMENT_LEN` | 64 MiB | the document, checked before parsing |
| `MAX_ORCHESTRA_ATTRIBUTES_LEN` | 16 KiB | the attributes of one element, and so their number |
| `MAX_ORCHESTRA_NAME_LEN` | 255 bytes | every element name, attribute name and attribute value the loader keeps, in the dictionary or the report (Orchestra 1.0 limits names to 255 characters; the longest kept from FIX Latest is 65 bytes) |
| `MAX_ORCHESTRA_REPORT_ENTRIES` | 65 536 | the report (FIX 4.4 needs 41) |
| `MAX_NESTING_DEPTH` | 32 | XML element nesting, and repeating-group nesting counted as in the QuickFIX loader (a message is level 1) |
| `MAX_COMPONENT_DEPTH` | 32 | component chains (shared check), envelope component expansion, datatype base-type chains |
| `MAX_ORCHESTRA_MEMBERS` | 262 144 | members produced by inlining groups |
| `MAX_ORCHESTRA_FIELD_VALUES` | 131 072 | enumeration values the fields hold together: a field naming a code set holds its own copy (`FieldDef::values` is a plain `HashMap`, which sharing would change), so a code set named by many fields is copied once per field; counted before each copy (FIX Latest needs 27 103) |

The parser is iterative over the document (it skips unmapped content without
recursion). Four walks recurse, each bounded: the check of the group graph,
memoised, by the nesting limit; group expansion, by the nesting limit, with
group cycles rejected (`GroupCycle`); the expansion of
components in the header and trailer, by `MAX_COMPONENT_DEPTH`, with cycles
rejected (`ComponentCycle`); and the shared assembly's walks over the
component graph (the cycle and depth check, and the cached first-tag
lookup), by `MAX_COMPONENT_DEPTH`.

The member limit exists because the dictionary inlines a group at every
reference: twenty groups, each referencing the next twice, are a few
kilobytes of XML and over a million members. It is about fifteen times what
FIX Latest needs. It counts members, not bytes; the name limit is what
bounds the bytes, since each member copies a name. Before the name and
report limits, a review measured documents of 18 KB to 16 MB at 340 MB to
556 MB of resident memory: a 16 KiB name copied into every member or report
entry that mentions it, and a report as long as the document. Each kept
string is now at most 255 bytes and is copied into at most
`MAX_ORCHESTRA_MEMBERS` members (twice: the expansion, then the assembly),
`MAX_ORCHESTRA_REPORT_ENTRIES` entries or `MAX_ORCHESTRA_FIELD_VALUES`
enumeration values (a review found one code set of 4 096 codes named by
2 048 fields would copy 8 388 608 values, over 2 GB of names).
`tests/orchestra_memory.rs` measures the peak heap with `dhat` at each limit
(a flood of unmapped elements, the member limit with a 255-byte name, a full
report of the longest locations, that shared code set with 255-byte names,
and the largest expansion that loads) against bounds about twice the peaks
measured: at most 87.6 MiB, for the expansion just under the member limit;
47.6 MiB for the shared code set.
A condition of a `rule` is copied once from the document, so all of them
together are no longer than the document.

Dangling ids (`UnknownOrchestraReference`), duplicate ids or names,
datatypes and code sets that map to no FIX type (`UnknownFieldType`,
`UnknownDatatype`), groups without a `numInGroup` (`MissingCountField`) or
members (`EmptyGroup`), ids that are not positive or do not fit a `u32`
(`InvalidOrchestraId`), oversized attributes, names past the name limit
(`NameTooLong`), a report past its limit (`TooManyUnmapped`), enumeration
values past theirs (`TooManyFieldValues`), and truncated or ill-formed XML
are each a typed error, with a unit test.

**Fixture.** The FIX Trading Community's `FIX Standard/OrchestraFIX44.xml` at
commit `cd24169a2abd8daba7c360987c7a46ca11873a12` (FIX 4.4 as of Extension
Pack 311), Apache-2.0, is vendored verbatim under
`ironfix-dictionary/tests/fixtures/orchestra/` with the repository's `LICENSE`
and a provenance README (URL, commit, SHA-256, git blob). The owner approved
the licensing; the file's own metadata reads "All Rights Reserved". The
directory, and `tests/orchestra_fix44.rs` which includes it, are excluded
from the published package (`exclude` in the crate manifest).

**Equivalence.** `ironfix-dictionary/tests/orchestra_fix44.rs` loads the
fixture and compares it with the embedded QuickFIX FIX 4.4 dictionary. Orchestra
holds some blocks as groups where QuickFIX wraps them in components, so
messages are compared flattened: the tags each message can carry, the tags
reached through required members outside every group, the count and
delimiter tags of every group, and, for each of the 730 groups of the 93
messages at every nesting level (keyed by the path of count tags), the tags
each entry must carry. Fields are compared by tag, name, type and
enumeration keys. Every difference is pinned in the test with its cause:

- tag 327 is `HaltReasonChar` in QuickFIX, `HaltReason` in Orchestra;
- `MassCancelRejectReason(532)` and `LegAllocAcctIDSource(674)` are `STRING`
  in QuickFIX, `int` code sets in Orchestra;
- 32 fields carry more enumeration values in Orchestra; QuickFIX never carries
  a value Orchestra lacks;
- TradeCaptureReport (`AE`) can carry ClearingFeeIndicator(635), and
  NewOrderCross / CrossOrderCancelReplaceRequest (`s`, `t`) OrigOrdModTime(586),
  only in Orchestra;
- seven messages (`AK`, `AL`, `AM`, `AN`, `AO`, `AP`, `AW`) have count tags
  required only in Orchestra, which marks a group reference required where
  QuickFIX marks the wrapping component required over an optional group;
  CollateralInquiry (`BB`) requires CollInquiryID(909) only in Orchestra.

Header, trailer, message names, message categories, group delimiters and
every per-entry required set agree. A NewOrderSingle validates the same
against both dictionaries. The report of the fixture holds 41 entries: 40
attributes (`lengthId` 16, `discriminatorId` 12, `unionDataType` 10,
`implMaxOccurs` 2) and the unreferenced group `ExecsGrp`.

**Code generation.** `ironfix-codegen-check` generates and compiles both
outputs, `CodeGenerator::generate` and `generate_views`, for the Orchestra
FIX 4.4 dictionary, under the workspace lints; its tests check that the
compiled text is what the generator produces at run time and that the views
read an ExecutionReport as the QuickFIX views do. `ironfix-codegen` itself
does not change.

## Consequences

- Public surface: additions only. A new module (`orchestra`), four types,
  seven constants, the `from_orchestra_xml` method and fourteen
  `DictionaryError` variants (the enum is `#[non_exhaustive]`). `cargo semver-checks` reports
  nothing beyond ADR-0016's break.
- Version support stays honest: Orchestra loading is tested on the FIX 4.4
  standard repository and on synthetic documents only. FIX Latest, and the
  FIXT session repository as published, are rejected;
  supporting it needs a decision on how a dictionary names a version that is
  not a fixed FIX version, and an `ironfix-core` change.
- Scenarios, conditional rules, value constraints and workflow do not reach
  the `Validator`; they are in the report. Loading a venue's rules of
  engagement gives its `base` scenario's message structure, not its rules.
- Both loaders share `assemble`: a change there changes both, and both test
  suites run against it.
- The `Validator` stays a standalone facility: the engine and the codec use
  neither loader.
