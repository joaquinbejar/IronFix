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
  which derives the length (`OutboundMessage` has `push_data` for the same
  reason). A sink that only takes `(tag, bytes)` cannot express that.
- **The validator's grammar.** `ironfix-core`'s field conversions are
  lenient (`as_decimal` accepts `1e5` and `1_000.5` and rounds digits a
  `Decimal` cannot hold; `as_i64` accepts `+5`), where the `Validator` checks
  each value against its FIX type with `FieldType::is_valid_value`. A view
  that reads what the validator refuses would disagree with it.

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
  wire bytes (`01` is not `1`). A `Boolean` with declared values stays `bool`,
  and a `data` field stays bytes. A multi-value field reads with `tokens`
  (one item per space-separated value) and writes with `join`.
- **`layouts`**: one `GroupSpec<'static>` constant per group *definition*
  and one `GroupSet<'static>` per message, holding its header, trailer and
  body groups, exactly as `MessageLayout` expands them (components
  flattened, members sorted, the first of two groups sharing a count tag
  kept). Each constant matches the constructor's `SpecError` to `panic!`, so a
  bad table is a compile error.
- **`views`**: `XxxView<'m, 'a>` per message, a `Copy` wrapper over
  `&'m RawMessage<'a>` built with `from_message` (which checks the MsgType),
  and one `XxxView<'m, 'a>` per group definition over a `GroupEntry`.
  Accessors borrow the buffer: strings are `&'a str`, data `&'a [u8]`,
  enumerations borrow, numbers are `Copy`; `Price`, `Qty`, `Amt`,
  `PriceOffset`, `Percentage` and `Float` are `rust_decimal::Decimal`, never
  `f64`. An absent required field is `DecodeError::MissingRequiredField`. A
  group accessor returns `Result<Option<Entries<..>>, GroupError>`: checked
  whole before any entry is handed out (ADR-0011), `None` when absent. A
  message-level accessor uses the new `GroupSet::field`, so the same tag
  inside a group entry is never taken for it; of a tag repeated at the
  message level it returns the first (a repetition is session reject reason
  13; `GroupSet::field` does not report it, the `Validator` does, as
  `DuplicateTag`).
- **`writers`**: `XxxFields<'v>` per message and group definition, a
  `Copy + Default` struct of `Option` fields and slices (one item per group
  entry, or per multi-value token). `write` checks everything before writing
  anything (see below), then sends the body in dictionary order: fields,
  groups, components (the loader does not keep the XML interleaving), a group
  as its count and then each entry with its delimiter first.

**Views read what the validator accepts, and nothing else.** Before
converting, every value except an enumeration's and a `data` field's is
checked with `FieldType::is_valid_value` for the field's own type: the
predicate the validator uses. So `44=1e5`, `+1.5` and `1_000.5`, `+5` for an
integer, a malformed `UTCTimestamp`, `UTCTimeOnly`, `UTCDateOnly`,
`LocalMktDate`, `MonthYear`, `Country` or `Currency`, a `DayOfMonth` outside
1 to 31, and a multi-value field with an empty token (a doubled or trailing
space) or a `MultipleCharValue` token longer than one character are all
`DecodeError::InvalidFieldValue`. A decimal is then parsed with
`Decimal::from_str_exact`: a value with more digits than a `Decimal` holds is
an error, never rounded. An enumeration still reads every value, an
undeclared one as `Other`.

**One type per group definition, a naming rule #98 should reuse.** A group is
named `<DeclaringOwner><GroupName>` after where it is declared: the component
(`PartiesNoPartyIDs`), the message (`NewOrderSingleNoAllocs`), the enclosing
group, or `Header` / `Trailer`. Every message that reaches it shares its
layout constant, view and writer. Components themselves stay flattened into
each message's view and writer: a message lists every field its components
contribute. That keeps the full FIX 5.0 SP2 views at about 26 MB, about half
the data structs. #98, which tracks the data structs' size, should reuse the
same per-definition naming so both outputs name a group alike.

**Requiredness follows the validator.** A field reached through components
is required only when every component reference on the way is required and
the field is; a field reached twice is required if any occurrence is. An
entry's delimiter is always required: it opens the entry.

**LENGTH/DATA pairs come from the dictionary, and fail closed.** The
dictionary does not name the pairs; it lists a `data` (or `XMLData`) field
right after the `Length` field that frames it, as every pair of the embedded
dictionaries is listed, so that is the pairing rule. A `data` field listed any
other way, or one that would open a group entry (its length would have to
precede the delimiter), is `GeneratorError::UnpairedDataField`: a writer that
could not frame it would corrupt the frame. The writer derives the length and
does not take it; the view reads both. When the `Length` half is a group's
delimiter (FIX 5.0 SP2 `NoPaymentStreamFormulas`,
`NoLegPaymentStreamFormulas` and `NoUnderlyingPaymentStreamFormulas` open
with `PaymentStreamFormulaLength` 43109, 43110 and 43111), the pair is kept:
its data is required, and the writer emits the pair first, so the length
still opens the entry. A test checks every pair the writers of the four
embedded dictionaries emit against `Encoder::try_put_data`, and every other
written tag against `Encoder::try_put_raw`, without making the encoder's pair
table public.

**The sink is a generated trait.** `writers::Sink` has
`field(tag, value)` and `data(length_tag, data_tag, value)`; `data` has no
default, so a hand-written implementation cannot forget it. Every
`FnMut(u32, &[u8])` implements it, writing a pair as its length then its data,
so a closure is a sink (its parameters need explicit types, since the bound is
no longer a closure bound). A target that frames pairs itself implements both
methods in the consumer's crate, where the trait is local: over
`ironfix_tagvalue::Encoder`, `put_raw` and `put_data`; over
`ironfix_engine::OutboundMessage`, `push_raw` and `push_data`. `write` takes
`&mut S` with `S: Sink + ?Sized`, so `&mut dyn FnMut(..)` works. No engine or
core API changed.

**Writers check every value before writing anything.** A missing required
field, required group or entry delimiter is
`EncodeError::MissingRequiredField`. An empty value, SOH in any value other
than `data`, a `char` that is not printable ASCII, and a multi-value token
that is empty or carries a space or SOH are `EncodeError::InvalidFieldValue`.
`data` may carry SOH (it goes through `Sink::data`) but not be empty. The
sink is therefore only ever handed a value it can write.

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
identifier, is `Other`, is `None`, `Some`, `Ok` or `Err` (which would shadow
the prelude's `Option` and `Result` variants under a glob import), is a
keyword, is taken, is an acronym, or repeats the enumeration's name. So FIX
4.4 `OTHER` (99) is `Other99`, EncryptMethod `NONE` (0) is `None0`,
`NO_SECURITY_TYPE` is `NoSecurityTypeNone`, and FIX 5.0 SP2 `Triggered` gets
`NotTriggered0` and `Triggered1`.

**`Debug` is opaque on the generated wrappers.** Generated views and writers
print their type name only, never a field value, so a Logon `Password` (554)
cannot reach a log through them. That covers the generated types only: a
view's `message()` returns the `RawMessage` and an entry view's `entry()` the
`GroupEntry`, whose `Debug` prints raw values, credentials included; the
generated docs say so. Enumerations derive `Debug`.

**The generated file states its dependencies.** Its header names
`ironfix-core`, `rust_decimal`, and `ironfix-dictionary >0.4.1`: the calls to
`GroupSet::field` need a release after 0.4.1. The exact version is set when
that release is cut.

## Consequences

- **Semver: additive (minor).** New `pub` items: `CodeGenerator::generate_views`
  and the variant `GeneratorError::UnpairedDataField` (the enum is
  `#[non_exhaustive]`) in `ironfix-codegen`, and `GroupSet::field` in
  `ironfix-dictionary`. Nothing is renamed or removed. `UnnameableItem` can
  now carry `what: "component"`, a value, not a variant.
- **Dev-dependencies, approved:** `ironfix-core`, `ironfix-tagvalue` and
  `rust_decimal` (all workspace dependencies) for `ironfix-codegen`'s tests
  only. The golden files of the default output now compile against the real
  `rust_decimal`; the `i64` stand-in is gone.
- **What is compiled in-repo.** Three views golden files, compiled and
  exercised in `ironfix-codegen/tests/generated_views.rs`: a hand-built
  sample covering every naming, structural and grammar edge case (a
  `TypeSampler` message with one field per FIX type that has a grammar, and a
  required group delimited by the length of a LENGTH/DATA pair), the embedded
  FIXT 1.1 dictionary in full, and FIX 4.4 Heartbeat, Logon and
  NewOrderSingle (generated from the full FIX 4.4 dictionary with the other
  messages removed, so they generate exactly as they would in full). The
  tests decode a FIX 4.4 NewOrderSingle with a nested party group and read
  every field, read undeclared enumeration values as `Other`, read
  multi-value tokens, check every typed error the views and writers raise,
  enforce a required group at run time, and validate writer output against
  the FIX 4.4 and sample dictionaries with `Validator`.
- **What is checked from the generated text.** For every message of the four
  embedded dictionaries, the `layouts` constants are parsed back and compared
  group by group with `MessageLayout`, and every emitted LENGTH/DATA pair and
  plain field is checked against the encoder. That checks the tables and tags
  the generator emits, not that the full outputs compile.
- **What is verified out of tree only.** The full FIX 4.4 (about 4.2 MB),
  FIX 4.2 (about 1 MB) and FIX 5.0 SP2 (about 26 MB) views are too large to
  commit. They were compiled as a library with `#![deny(missing_docs)]` under
  `cargo clippy -- -D warnings` in edition 2024 and 2021, and documented with
  `RUSTDOCFLAGS="-D warnings"`, from a scratch crate. That is not a CI gate.
  The generator's unit tests generate all four, check determinism and that
  they carry no `#[allow]` and no binary float.
- **No performance or allocation claim.** Views delegate to the group
  reader (whose read path is proved allocation-free, `GroupSet::field`
  included) and to `ironfix_core`'s conversions and the grammar check, which
  allocate on their error paths; the views themselves are not measured.
  Writers format numbers on a 64-byte stack buffer; `join` allocates.
- **Not covered.** Header and trailer fields have no accessor (read them from
  the `RawMessage`); a FIXT.1.1 composition (`SessionDictionary`) is not an
  input, so views generated from a FIX 5.0 application dictionary know no
  header group; group presence is not enforced by views (it is by writers and
  by the `Validator`); the data-struct output's size (#98) is unchanged.
- **Open: group-entry member order.** Writers emit an entry's delimiter
  first and then its members in the order the loader keeps (fields, nested
  groups, components), not the order the XML lists them, which FIX expects
  inside a repeating group. Keeping the XML order needs the dictionary schema
  to record it; that change is pending an owner decision and is not made
  here.
- **No consumer.** Nothing in the workspace consumes either output; the
  engine and the codec still read fields by tag.
- **Unchanged.** No `unsafe`, no new runtime dependency, and the crate DAG
  is as before: `ironfix-codegen` depends on `ironfix-dictionary` only;
  `ironfix-tagvalue` does not depend on `ironfix-dictionary`.
