# ADR-0019 — One type per component and per repeating-group definition in the default codegen output

- **Status:** Accepted (issue #98)
- **Date:** 2026-10-18

## Context

`CodeGenerator::generate`, the default output of `ironfix-codegen`, emitted
one struct per message with every component's fields copied in, and one entry
struct per repeating group *per use*: a group a component declares got a new
entry struct in every message (and every group entry) that reached the
component. The output grew with component reuse. Byte counts of the
generated text and the number of `pub struct` lines, before (`origin/main`
at `6c62771`) and after this change:

| Dictionary | Messages | Components | Before: bytes | Before: structs | After: bytes | After: structs |
|---|---|---|---|---|---|---|
| FIX 4.2 | 46 | 0 | 188,698 | 84 | 188,706 | 84 |
| FIX 4.4 | 93 | 104 | 1,690,721 | 823 | 448,921 | 285 |
| FIXT 1.1 | 8 | 2 | 10,467 | 8 | 10,956 | 9 |
| FIX 5.0 SP2 | 156 | 725 | 56,766,914 | 26,083 | 2,426,344 | 1,438 |
| FIX 4.4 Orchestra fixture (ADR-0013, not embedded) | 93 | 13 | 1,690,096 | 823 | 614,895 | 527 |

(Issue #98 quotes about 49.6 MB and 26,000 structs for FIX 5.0 SP2. The
struct count matches; the bytes predate #83, which spells standard items by
absolute path: shortening `::std::string::String`, `::core::option::Option`,
`::std::vec::Vec` and `::rust_decimal::Decimal` in the "before" text back to
their short forms gives 49,592,721 bytes.)

At 57 MB the FIX 5.0 SP2 output was never compiled in-repo, so #72's
acceptance criterion "generated output compiles" did not hold for it.
ADR-0012 (#83) had already named each group *definition* once in the views,
`<DeclaringOwner><GroupName>`, and asked #98 to reuse that naming. ADR-0016
(#106) records the XML member order, which the default output had so far
ignored to keep its text stable.

The constraints:

- **The default output is a contract.** Consumers `include!` it from a build
  script; a change of type names or field paths breaks their code. Crate
  semver does not see it: `cargo-semver-checks` compares Rust items of
  `ironfix-codegen`, not the text it returns.
- **The dictionary is the authority for structure.** Requiredness belongs to
  each field, group and component *reference* (`ComponentRef::required`);
  the member order is `members()`.
- **Fail closed.** An undefined field or component, a component that
  contains itself, nesting past the depth limit, and an unnameable item stay
  typed `GeneratorError`s.

## Decision

**One struct per definition, referenced by name.**

- `messages`: one struct per message, ordered by MsgType, each followed by
  the entry structs of the groups it declares.
- `components`: one struct per component that some message reaches
  (directly, through other components, or through group entries), ordered by
  component name, each followed by the entry structs of the groups it
  declares. The module is emitted only when a message reaches a component;
  FIX 4.2 has none. Components no message lists are not generated (in FIX
  4.4, `Hop`, whose NoHops group the header declares itself, and `ExecsGrp`).
- A message, component or group entry that lists a component has one field
  named after it in snake case (`parties`, `order_qty_data`), typed
  `super::components::Parties` from the `messages` module and `Parties`
  inside `components`, wrapped in `Option` unless that reference is required.
- A group is one field `::std::vec::Vec<Entry>` (in an `Option` unless the
  group is required), and its entry struct is generated once, next to the
  declaring owner: `<DeclaringOwner><GroupName>Entry`, the views'
  per-definition base followed by `Entry`. The owner is the message's or component's type
  name, or for a group nested in an entry, the enclosing entry's base:
  `NewOrderSingleNoAllocsEntry`, `PartiesNoPartyIDsEntry`,
  `NewOrderSingleNoAllocsNoNestedPartyIDsEntry`. The data struct of the group
  whose view is `PartiesNoPartyIDsView` is `PartiesNoPartyIDsEntry`. A
  collision takes a numeric suffix after the base (`XNoA2Entry`).

**Members in XML order.** Each struct lists its members as `members()` gives
them, a component as one field in its place. FIX 4.4 `PreAllocGrp`'s
NoAllocs entry now reads AllocAccount, AllocAcctIDSource, AllocSettlCurrency,
IndividualAllocID, `nested_parties`, AllocQty.

**Requiredness per definition.** A field is bare when its own reference is
required, in whichever struct lists it: a field required inside a component
is bare in the component's struct, and the `Option` around the component
field says whether the component is present. The previous output, which
predated `ComponentRef::required`, made every component-contributed field
optional.

**Names.** Messages claim their names in `messages`, then reached components
in `components`, before any entry; `FixDecimal`, the decimal alias each module
imports, is reserved in both. A member listed twice in one definition is one
field (the first listing wins). A component field whose name is taken gets a
`_component` suffix.

**Fail closed, in two passes.** A first pass walks the messages and collects
the components they reach, reporting an undefined component (with the scope
that references it, for example `group NoPartyIDs of component Parties`), a
component cycle with the path that closes it (through a group entry too:
Rust could compile `A -> group -> A` through the `Vec`, but the loader
rejects it as `DictionaryError::ComponentCycle` and so do the views), and
nesting past `MAX_NESTING_DEPTH`. The second pass builds the structs and
reports undefined fields (now scoped to the component or entry that lists
them) and unnameable items, `what: "component"` included.

**Unchanged.** `GeneratorConfig` keeps its fields. `generate_components:
false` still drops components: no `components` module and no component field
anywhere. `Price`, `Qty`, `Amt`, `PriceOffset`, `Percentage` and `Float`
stay `FixDecimal` (`::rust_decimal::Decimal`), never `f64`; standard items
keep their absolute paths; the output has no `#[allow]` and is
deterministic (no output order depends on the dictionary's `HashMap`s; a test
generates two separately built dictionaries and compares the text). The
views (`generate_views`) are byte-identical before and after for the four
embedded dictionaries and the Orchestra fixture.

**Alternatives rejected.**

- *Flatten components, share only group entries.* Most of the size is
  components such as `Instrument` copied into every message and every entry
  that lists them; sharing only entries leaves that.
- *One module for everything.* A message and a component may share a name;
  separate modules keep both names, and the types a message uses stay
  visibly apart from the message types.
- *Generate every component the dictionary defines.* That emits types nothing
  uses and turns a defect in an unreferenced definition into a generation
  error, where before it was never examined.

## Consequences

- **The default output changes shape; crate semver does not.** Users who
  `include!` the output must update their code:
  - component fields moved into the component's struct: FIX 4.4
    `order.symbol` is now `order.instrument.symbol` (Instrument is required
    in NewOrderSingle), `order.order_qty` is `order.order_qty_data.order_qty`;
  - entry structs are renamed after their declaring owner and exist once:
    FIX 4.4 `NewOrderSingleNoAllocsEntry` (and one copy per message) is now
    `components::PreAllocGrpNoAllocsEntry`; a nested entry drops the inner
    `Entry` (`XNoAEntryNoBEntry` is `XNoANoBEntry`);
  - a new `components` module, and fields in XML order;
  - a field required inside a component or entry is no longer an `Option`
    there.
  No Rust item of `ironfix-codegen` was added, renamed or removed
  (`cargo semver-checks -p ironfix-codegen` against `origin/main` passes); the
  break is in the generated text, so it must be stated in the release notes.
- **FIX 5.0 SP2 compiles in CI.** The unpublished `ironfix-codegen-check`
  crate now also generates the data definitions of the embedded FIX 4.4,
  FIX 4.2, FIXT 1.1 and FIX 5.0 SP2 dictionaries from its build script and
  includes them under `#![deny(missing_docs)]`, so `make lint` and `make doc`
  check all four in full; a test there builds a FIX 5.0 SP2 `Parties` with
  its nested sub-party group, reads it, and checks through functions typed
  on NewOrderSingle and ExecutionReport that both messages hold that one
  type. The default output it compiles for the FIX 4.4 Orchestra fixture
  (ADR-0013) takes the new shape too; its tests pass unchanged. The FIX 5.0
  SP2 views (about 31 MB of source, unchanged here) are still not compiled
  in CI; see the build times below.
- **Build times, measured on the machine this was written on only** (an
  18-core Apple M5 Max, rustc 1.99.1, while other builds kept the load
  average between 16 and 21, so the spread is wide; these are not CI
  figures). The whole `ironfix-codegen-check` crate, cold for that crate
  only, before (views of three dictionaries and both Orchestra outputs) and
  after (plus the data structs of the four embedded dictionaries): debug
  build 21 to 24 s before, 22 to 43 s after (seven runs, most near 30 s);
  `clippy --all-targets` 17 to 19 s before, 19 to 20 s after; release build
  44 to 45 s before, 39 to 40 s after, which is within the noise. On its
  own, in a scratch crate, the FIX 5.0 SP2 data-struct file compiles in
  about 1.5 s (debug), 2.5 s (clippy) and 1.5 s (default release profile).
  The FIX 5.0 SP2 views, compiled the same way on their own, took 57 s
  (debug, 7.4 GB peak resident memory), 42 s (clippy, 5.0 GB) and 115 s
  (the workspace's release profile, 6.1 GB); `make lint` checks the crate
  twice (library and test target) and the build workflow builds it in debug
  and release on two runners, so they stay out of CI.
- **Golden files.** The default-output goldens (`sample.rs`, `fix42.rs`,
  `fixt11.rs`, `std_names.rs`) were regenerated and still compile in
  `ironfix-codegen`'s tests; the sample dictionary gained shared components
  (one optional and one required reference), a component inside a component,
  and a group nested in a component's group through a further component. The
  views goldens did not change.
- **Not covered.** The data structs still carry no encode or decode (that is
  the views and writers of ADR-0012); a field FIX makes conditionally required
  is not enforced; a tag a message reaches twice (listed on the message and
  inside one of its components) is a field of each struct, and nothing decides
  which one a wire value belongs to.
- **Unchanged.** No new dependency, no `unsafe`, and the crate DAG is as
  before: `ironfix-codegen` depends on `ironfix-dictionary` only; the
  generated code names `rust_decimal` only at the consumer.
