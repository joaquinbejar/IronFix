# ADR-0012 — Generated borrowed views, enumerations and writers, as an opt-in output of ironfix-codegen

- **Status:** Accepted
- **Date:** 2026-10-18

## Context

`ironfix-codegen` emitted one kind of output: tag constants and owned data
structs (`String`, `Vec`, `Option<Vec<..Entry>>` per group) with no way to
read them from, or write them to, a message. Declared field values were
loaded but unused, and nothing generated read a repeating group. Users who
generated code from a dictionary still hand-wrote parsing and encoding
(issue #83). A downstream gateway generates its fields, messages and
enumerations at build time, requires the generated code to pass the lint gate
without `#[allow]`, and copies or allocates no field value on the message
path.

The constraints:

- **The default output is a contract.** Consumers commit or build from it; a
  change to it must not happen silently. `GeneratorConfig` has `pub` fields
  and is not `#[non_exhaustive]` (`ironfix-codegen/src/generator.rs`), so a
  new configuration field is a breaking change.
- **Size.** The data-struct output repeats every component's fields, and
  every group's entry struct, in each message that uses them: about 1.4 MB for
  FIX 4.4 and about 50 MB for FIX 5.0 SP2 (#98 tracks that output).
- **Group structure lives in the dictionary.** Decoding is dictionary-free;
  ADR-0011 added a reader whose `GroupSpec` / `GroupSet` tables are `const`
  constructible precisely so generated code can carry them.
- **LENGTH/DATA pairs.** `ironfix_tagvalue::Encoder::put_raw` refuses the
  tags of a spec-defined LENGTH/DATA pair; they must go through `put_data`,
  which derives the length. A sink that only takes `(tag, bytes)` cannot
  express that.

## Decision

**An opt-in output mode, by method.** `CodeGenerator::generate_views(&self,
&Dictionary) -> Result<String, GeneratorError>` returns a second,
self-contained source file. `CodeGenerator::generate` and its output are
unchanged, byte for byte (the existing golden files did not move). No
configuration field was added; of `GeneratorConfig`, only `visibility` applies
to the views (components are always expanded, because a view must know every
group of a message to tell a message-level field from one inside a group). The
file has four modules:

- **`enums`**: one enumeration per field with declared values that a view or
  writer uses, ordered by tag, variants ordered by wire value. Every
  enumeration has `Other(&'a [u8])`, so an undeclared venue value reads
  instead of failing, and `const fn from_bytes` / `as_bytes` matching exact
  wire bytes (`01` is not `1`). A `Boolean` with declared values stays `bool`.
  A multi-value field reads with `tokens` (one item per space-separated value)
  and writes with `join`.
- **`layouts`**: one `GroupSpec<'static>` constant per group *definition*
  and one `GroupSet<'static>` per message, holding its header, trailer and
  body groups, exactly as `MessageLayout` expands them (components
  flattened, members sorted, the first of two groups sharing a count tag
  kept). Each constant matches the constructor's `SpecError` to `panic!`, so a
  bad table is a compile error. The constants are tested against
  `MessageLayout` group by group.
- **`views`**: `XxxView<'m, 'a>` per message, a `Copy` wrapper over
  `&'m RawMessage<'a>` built with `from_message` (which checks the MsgType),
  and one `XxxView<'m, 'a>` per group definition over a `GroupEntry`.
  Accessors borrow the buffer: strings are `&'a str`, data `&'a [u8]`,
  enumerations borrow, numbers are `Copy`; `Price`, `Qty`, `Amt`,
  `PriceOffset`, `Percentage` and `Float` are `rust_decimal::Decimal`, never
  `f64`. They call `ironfix_core`'s `FieldRef` conversions, so a malformed
  value is that `DecodeError`, and an absent required field is
  `DecodeError::MissingRequiredField`. A group accessor returns
  `Result<Option<Entries<..>>, GroupError>`: checked whole before any entry is
  handed out (ADR-0011), `None` when absent. A message-level accessor uses the
  new `GroupSet::field`, so the same tag inside a group entry is never taken
  for it.
- **`writers`**: `XxxFields<'v>` per message and group definition, a
  `Copy + Default` struct of `Option` fields and slices (one item per group
  entry, or per multi-value token). `write` checks required fields, required
  groups, each entry's delimiter and that every `char` is ASCII *before*
  writing anything, then sends the body in dictionary order: fields, groups,
  components (the loader does not keep the XML interleaving), a group as its
  count and then each entry with its delimiter first.

**One type per group definition.** A group is named after where it is
declared: the component (`PartiesNoPartyIDs`), the message
(`NewOrderSingleNoAllocs`), the enclosing group, or `Header` / `Trailer`.
Every message that reaches it shares its layout constant, view and writer.
That keeps the full FIX 5.0 SP2 views at about 23 MB, under half the data
structs.

**Requiredness follows the validator.** A field reached through components
is required only when every component reference on the way is required and
the field is; a field reached twice is required if any occurrence is. An
entry's delimiter is always required: it opens the entry.

**The sink is a generated trait with a closure impl.** `writers::Sink` has
`field(tag, value)` and `data(length_tag, data_tag, value)`, whose default
writes the length (the size of `value`) then the data. Every
`FnMut(u32, &[u8])` implements it, so a closure is a sink; a target that frames
pairs itself implements `data` too, for example
`impl writers::Sink for Encoder` calling `put_raw` and `put_data` (allowed in
the consumer's crate, the trait being local there). `write` takes
`&mut S` with `S: Sink + ?Sized`, so `&mut dyn FnMut(..)` works. No engine or
core API changed. A `data` field is paired with the `Length` field listed
right before it, the way every pair of the embedded dictionaries is listed;
the writer derives the length and does not take it, the view reads both.

**Lint-clean by construction.** The generated text has no `#[allow]`, and
must pass `-D warnings` and the default clippy lints for any dictionary:
helpers and imports are emitted only when used; every `pub` item is
documented; a variant never starts or ends with its enumeration's name
(`clippy::enum_variant_names`) and never is an all-capital acronym
(`clippy::upper_case_acronyms`); an accessor never starts with `from_`,
`into_` or `to_` (`clippy::wrong_self_convention`; it is prefixed `field_`)
nor takes a generated method's name (`get`, `message`, `entry`, `clone`, ...;
it takes the tag as suffix); `#[must_use]` is put only where the return type
is not already must-use.

**Variant naming is deterministic.** The first acceptable candidate wins: the
description in PascalCase; then followed by the wire value; then `Value` and
the wire value; then `Value`, the description and the value; then `Value1`,
`Value2`, ... (`Code1`, ... for an enumeration whose name starts with `V`, so
the loop ends). An empty description becomes `Value` and the wire value; a
leading digit gets a `Value` prefix. A candidate is refused if it is not an
identifier, is `Other`, a keyword, taken, an acronym, or repeats the
enumeration's name. So FIX 4.4 `OTHER` (99) is `Other99`, `NO_SECURITY_TYPE`
is `NoSecurityTypeNone`, and FIX 5.0 SP2 `Triggered` gets `NotTriggered0`
and `Triggered1`.

**`Debug` is opaque.** Generated views and writers print their type name
only, never a field value, so a Logon `Password` (554) cannot reach a log
through them. Enumerations derive `Debug`.

## Consequences

- **Semver: additive (minor).** New `pub` items: `CodeGenerator::generate_views`
  in `ironfix-codegen` and `GroupSet::field` in `ironfix-dictionary`. Nothing
  is renamed or removed; `GeneratorError` gains no variant (`UnnameableItem`
  can now carry `what: "component"`, a value, not a variant).
- **Dev-dependencies, approved:** `ironfix-core`, `ironfix-tagvalue` and
  `rust_decimal` (all workspace dependencies) for `ironfix-codegen`'s tests
  only. The golden files of the default output now compile against the real
  `rust_decimal`; the `i64` stand-in is gone.
- **What is compiled in-repo.** Three views golden files, compiled and
  exercised in `ironfix-codegen/tests/generated_views.rs`: a hand-built
  sample covering every naming and structural edge case, the embedded
  FIXT 1.1 dictionary in full, and FIX 4.4 Heartbeat, Logon and
  NewOrderSingle (generated from the full FIX 4.4 dictionary with the other
  messages removed, so they generate exactly as they would in full). The
  tests decode a FIX 4.4 NewOrderSingle with a nested party group and read
  every field, read undeclared enumeration values as `Other`, read
  multi-value tokens, check every typed error, and validate writer output
  against the FIX 4.4 dictionary with `Validator`.
- **What is verified out of tree only.** The full FIX 4.4 (about 3.7 MB),
  FIX 4.2 (about 0.9 MB) and FIX 5.0 SP2 (about 23 MB) views are too large to
  commit. They were compiled as a library with `#![deny(missing_docs)]` under
  `cargo clippy -- -D warnings` in edition 2024 and 2021, and documented with
  `RUSTDOCFLAGS="-D warnings"`, from a scratch crate. That is not a CI gate.
  The generator's unit tests generate all four, check determinism and that
  they carry no `#[allow]` and no binary float.
- **No performance or allocation claim.** Views delegate to the group
  reader (whose read path is proved allocation-free, `GroupSet::field`
  included) and to `ironfix_core`'s conversions, which allocate on their
  error paths; the views themselves are not measured. Writers format numbers
  on a 64-byte stack buffer; `join` allocates.
- **Not covered.** Header and trailer fields have no accessor (read them from
  the `RawMessage`); a FIXT.1.1 composition (`SessionDictionary`) is not an
  input, so views generated from a FIX 5.0 application dictionary know no
  header group; group presence is not enforced by views (it is by writers and
  by the `Validator`); a group delimiter that is half of a LENGTH/DATA pair is
  written as a plain field; the data-struct output's size (#98) is unchanged.
- **No consumer.** Nothing in the workspace consumes either output; the
  engine and the codec still read fields by tag.
- **Unchanged.** No `unsafe`, no new runtime dependency, and the crate DAG
  is as before: `ironfix-codegen` depends on `ironfix-dictionary` only;
  `ironfix-tagvalue` does not depend on `ironfix-dictionary`.
