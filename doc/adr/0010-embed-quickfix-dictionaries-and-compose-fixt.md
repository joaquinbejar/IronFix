# ADR-0010 — Embed the FIX 4.2, FIXT 1.1 and FIX 5.0 SP2 QuickFIX dictionaries and compose transport with application

- **Status:** Accepted
- **Date:** 2026-10-17

## Context

Until this change `ironfix-dictionary` embedded one dictionary, FIX 4.4
(`spec/FIX44.xml`), and had no way to describe a FIX 5.0 session. FIX 5.0 and
later run over a FIXT.1.1 session, and QuickFIX ships them as two files: a
*transport* dictionary (`FIXT11.xml`: standard header, trailer and the admin
messages) and an *application* dictionary (`FIX50SP2.xml`: the application
messages, with an empty `<header />` and `<trailer />`). Neither describes a
complete message on its own, and `Dictionary` keeps header, trailer and
messages in one value whose fields are all `pub` and which is not
`#[non_exhaustive]` (`ironfix-dictionary/src/schema.rs`), so adding a
"transport" field to it would be a breaking change. Downstream gateways run
FIXT.1.1 with FIX 5.0 SP2 as the application version, and FIX 4.2 remains a
common participant dialect (issue #72).

Three verbatim upstream files did not load with the existing loader:

- `FIX42.xml` declares `MDEntryDate(272)` with type `UTCDATE`, the FIX 4.2
  spelling of what FIX 4.3 renamed `UTCDateOnly`;
- `FIX50SP2.xml` declares 63 fields with types `XID` (34) and `XIDREF` (29),
  element identifiers and references to them, which the FIX specification
  derives from `String`;
- `FIXT11.xml` defines the component `MsgTypeGrp` as a self-closing element
  (`<component name='MsgTypeGrp' />`). The loader only registered component
  definitions written as start/end pairs, so the definition was skipped and
  Logon's reference to it failed the load with `UnknownComponent`. The same
  skip silently dropped `<message name='XMLnonFIX' msgtype='n' msgcat='admin' />`,
  which both `FIXT11.xml` and the already-embedded `FIX44.xml` define.

The vendored files are an external contract: they are never edited to make the
loader accept them.

## Decision

**Vendoring and licensing.** `FIX42.xml`, `FIXT11.xml` and `FIX50SP2.xml` are
vendored into `ironfix-dictionary/spec/` byte for byte from `spec/<FILE>` of
quickfix/quickfix at commit `386ce46e917ae494ab6e90b1be90fd421cdbe3f9`; the
existing `FIX44.xml` was verified byte-identical to the same commit.
`spec/README.md` records the commit and each file's SHA-256. The QuickFIX
Software License, Version 1.0, is reproduced verbatim from `LICENSE` at that
commit as `spec/LICENSE-QUICKFIX`, which also covers the previously vendored
`FIX44.xml`. The acknowledgement its clause 3 requires ("This product includes
software developed by quickfixengine.org (http://www.quickfixengine.org/).")
appears in `spec/README.md`, in the crate docs (`lib.rs`, `loader.rs`) and in
the workspace `README.md`. The crate's own `license` field stays `MIT`; the
crate has no `include` / `exclude`, so `cargo package` ships `spec/` whole
(verified with `cargo package --list`).

**Embedded constructors.** `Dictionary::fix42()`, `Dictionary::fixt11()` and
`Dictionary::fix50sp2()` join `Dictionary::fix44()` with the same shape:
`fn() -> Result<&'static Dictionary, DictionaryError>`, parsed on first use
from an `include_str!` constant and cached in a `OnceLock`, so every call
returns the same instance.

**Type mappings, not new types.** `FieldType` is an exhaustive `pub` enum, so a
new variant would break every downstream exhaustive `match`. Instead
`FieldType::from_str` maps the new spellings onto the variant with the same
wire form: `UTCDATE` → `FieldType::UtcDateOnly` (`YYYYMMDD`), `XID` and
`XIDREF` → `FieldType::String`. An unrecognised type name is still
`DictionaryError::UnknownFieldType`, never a silent `String`.

**Self-closing definitions are empty definitions.** At the top level of a
document, a self-closing `<component name='…' />` defines a component with no
members and a self-closing `<message … />` defines a message with no body
fields; both go through the same duplicate checks as their start/end forms.
Member references cannot reach that loop, because `parse_items` consumes
everything inside a message, component, group, header or trailer. A group whose
only member is an empty component still has no reachable delimiter, so it is
still `DictionaryError::EmptyGroup`.

**Composition.** A new `SessionDictionary<'d>` (module `composition`, private
fields) borrows a transport and an application dictionary.
`SessionDictionary::new(transport, application)` accepts the pair when the
transport is `Version::Fixt11` and the application is any version FIXT.1.1
carries: FIX 4.0 through 4.4 (ApplVerID `2` to `6`) and FIX 5.0 through 5.0 SP2
(`7` to `9`), that is, every version except `Fixt11`. The rule is an explicit,
exhaustive `match` on `Version`, deliberately not derived from
`Version::appl_ver_id`, which answers a different question (what to stamp on
the wire for a configured session) and has no value for FIX 4.x. Anything
else, a swapped pair or FIXT.1.1 as the application included, is the new
`DictionaryError::IncompatibleComposition { transport, application }`.
`Validator::for_session(&SessionDictionary)` validates with QuickFIX-like
semantics:

- `BeginString(8)` must equal the transport's `begin_string` (`FIXT.1.1`);
  anything else is the new `ValidationError::BeginStringMismatch { expected,
  found }`;
- a message type the transport defines with `msgcat='admin'` is validated
  entirely against the transport (so a Logon must carry `DefaultApplVerID(1137)`
  and an application-only tag in a Heartbeat is `UnknownTag`);
- any other message type must be defined by the application dictionary; tags of
  the transport's header and trailer (members of header and trailer groups
  included) resolve against the transport, every other tag against the
  application dictionary.

Where it differs from QuickFIX, stated so nobody assumes parity:

- no `ApplVerID`-based dictionary selection: QuickFIX picks the application
  dictionary per message from `ApplVerID(1128)`, falling back to the
  counterparty's `DefaultApplVerID(1137)`; here the pair names one
  application dictionary and neither tag is consulted;
- admin routing follows the transport's `msgcat`, so `XMLnonFIX` (35=n,
  `msgcat='admin'` in `FIXT11.xml`) goes to the transport, whereas QuickFIX's
  `Message::isAdminMsgType` (`0`, `A`, `1` to `5`) treats it as application;
- every error is returned rather than the first, and header/body/trailer
  field order is not enforced;
- a tag the pair defines but the answering dictionary does not is
  `UnknownTag`, which a session reject would map to `373=0` where `373=2` is
  more accurate; mapping validation errors to `SessionRejectReason` is future
  work (#84).

`Validator::new(&Dictionary)` is the degenerate case of the same code, both
roles played by one dictionary, so its behaviour is unchanged; in particular it
still does not check `BeginString(8)`, a pre-existing gap now documented on the
constructor.

## Consequences

- **Semver: additive (minor bump).** New `pub` items:
  `Dictionary::{fix42, fixt11, fix50sp2}`, the `composition` module and its
  `SessionDictionary` (re-exported at the crate root), `Validator::for_session`,
  the `DictionaryError::IncompatibleComposition` variant and the
  `ValidationError::BeginStringMismatch` variant (both enums are
  `#[non_exhaustive]`). No `pub` item is renamed or removed; `FieldType` and
  `Dictionary` are untouched; `Validator`'s fields were already private.
  Observable behaviour changes, all toward what the files say:
  `FieldType::from_str` accepts three more spellings; a self-closing component
  definition now loads instead of failing references to it; and the embedded
  FIX 4.4 dictionary now defines msg type `n` (XMLnonFIX), so validating `35=n`
  against it is no longer `UnknownMsgType`, and `CodeGenerator` output for FIX
  4.4 gains an empty `XMLnonFIX` struct.
- **Stricter loading of self-closing definitions.** A top-level self-closing
  `<message/>` or `<component/>` used to be skipped silently, whatever it
  contained. It is now a definition, so one that lacks `msgtype` / `name` is
  `DictionaryError::MissingAttribute`, and one that repeats another
  definition's message type or component name is
  `DictionaryError::DuplicateDefinition`. A caller-supplied XML that loaded
  before only because such an element was ignored is now rejected.
- **The dictionary answers, unpatched: an upstream deviation.** FIXT 1.1
  defines the Logon `MsgTypeGrp` component as the `NoMsgTypes(384)` group
  (`RefMsgType(372)`, `MsgDirection(385)`, `RefApplVerID(1130)`,
  `RefApplExtID(1406)`, `RefCstmApplVerID(1131)`, `DefaultVerIndicator(1410)`).
  The vendored QuickFIX `FIXT11.xml` defines `MsgTypeGrp` with no members and
  does not define 384 or 385, so a Logon carrying the group is reported
  (`UnknownTag { tag: 384 }`). The file stays verbatim; the workaround is to
  load a FIXT 1.1 dictionary that defines the group with
  `Dictionary::from_quickfix_xml` and compose that. Both the deviation and the
  workaround are tested. Likewise `FIXT11.xml` gives `DefaultApplVerID(1137)` no
  enumeration, so any value passes (pinned by a test).
- **XID / XIDREF are a documented loosening.** Mapping them to `String` checks
  only their wire form; `XID` uniqueness, `XIDREF` reference integrity and the
  `xs:ID` / `NCName` lexical rules are not validated.
- **Crate size.** `spec/` grows from about 0.3 MB to about 1.9 MB uncompressed
  (about 174 KB more compressed; `FIX50SP2.xml` is 1.47 MB of it). The packaged
  `ironfix-dictionary` crate is 2.0 MiB, 249.6 KiB compressed. A binary carries
  in its read-only data the files whose constructors it links; whether unused
  ones are discarded depends on the linker's dead-section elimination and has
  not been measured. `ironfix-codegen` gains two golden files (157 KB FIX 4.2,
  10 KB FIXT 1.1) that its compile test `include!`s.
- **Validation ceilings hold.** Under the existing `MAX_SCOPE_NODES = 4096` and
  `MAX_SCOPE_DEPTH = 32`, the worst-case expansion is FIX 4.2: 4 nodes / depth
  1; FIX 4.4: 56 / 8; FIXT 1.1: 2 / 0; FIX 5.0 SP2 bodies under the FIXT 1.1
  header: 934 nodes (TradeCaptureReport) / depth 16 (MassQuote). Each dictionary
  has a test asserting no message reaches a ceiling.
- **Code generation.** `CodeGenerator::generate` succeeds on all three new
  dictionaries. The full FIX 4.2 and FIXT 1.1 outputs are compiled in-repo as
  golden files; the FIX 5.0 SP2 output (about 50 MB) is generated and inspected
  in a unit test but not compiled.
- **Not done, stated rather than implied.** FIX 4.0, 4.1, 4.3, 5.0 and 5.0 SP1
  are not embedded (a caller-supplied dictionary of any of them composes with
  the embedded FIXT 1.1; FIX 4.4 over FIXT.1.1 is tested with the embedded
  files). Nothing selects the application dictionary from `ApplVerID`.
  `Validator::new` does not check `BeginString`. The `Validator` is still not
  invoked by the engine or the codec.
- **Unchanged.** No new dependency, no feature flag, no `unsafe`, no change to
  the release profile, and no change to the crate DAG: `ironfix-dictionary`
  still depends on `ironfix-core` only, with `ironfix-tagvalue` as a
  dev-dependency for tests, and `ironfix-tagvalue` still does not depend on
  `ironfix-dictionary`.
