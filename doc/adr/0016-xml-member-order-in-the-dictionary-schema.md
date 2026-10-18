# ADR-0016 — Keep the XML member order in the dictionary schema

- **Status:** Accepted
- **Date:** 2026-10-18

## Context

The QuickFIX XML loader split every message, component and group into three
lists: fields, groups, components (`ironfix-dictionary/src/loader.rs`). The
XML interleaving of members was lost before any consumer saw the schema
(issue #106). FIX requires the fields of a repeating-group entry to follow the
message definition order; session reject reason 15, "repeating group fields
out of order", exists for it. Anything writing from the dictionary therefore
could not produce a conformant entry: the protocol review of #83 found it in
FIX 4.4 `PreAllocGrp`, whose `NoAllocs(78)` entry lists AllocAccount(79),
AllocAcctIDSource(661), AllocSettlCurrency(736), IndividualAllocID(467), the
`NestedParties` component (`NoNestedPartyIDs` 539) and AllocQty(80), where the
split put AllocQty before the component.

How often the split order differs from the XML order, counting every loaded
group definition once (a definition reached from several messages or
components is one; header and trailer groups included):

| Dictionary | Group definitions | Direct members reordered | Reordered once components are expanded in place |
|---|---|---|---|
| FIX 4.2 | 38 | 1 | 1 |
| FIX 4.4 | 93 | 34 | 40 |
| FIXT 1.1 | 2 | 0 | 0 |
| FIX 5.0 SP2 | 561 | 103 | 113 |

"Direct members" compares a definition's own list (fields, groups, component
references) with the split's fields-then-groups-then-components order;
"expanded" replaces each component reference by its members, recursively,
in each order. Issue #106 states 40 of 90 for FIX 4.4 and 109 of 559 for FIX
5.0 SP2; its counting method is not recorded and those figures were not
reproduced.

`MessageDef`, `ComponentDef` and `GroupDef` had public fields and were not
`#[non_exhaustive]`, so recording the order is a breaking change to
`ironfix-dictionary`. The owner accepted the break (2026-10-17); the release
already goes to 0.5.0, and the version bump is deferred to the last PR of the
programme.

## Decision

**One private record of the members, two read-only views of it.** Each of the
three definitions keeps its members in a private value: the per-kind lists
and, beside them, the *kind* of each member in dictionary order. Within one
kind the lists keep their relative order, so the sequence of kinds is all it
takes to interleave them again. They are read through:

- `members()`, the members in dictionary order, as an `ExactSizeIterator`
  (also `FusedIterator`) of `MemberRef<'_>` (`Field`, `Group`, `Component`,
  borrowed), without allocating;
- `fields()`, `groups()` and `components()`, `#[must_use]` slices per kind,
  for the readers that want a kind on its own (the validator's scope
  expansion, the group reader's layouts, the default code generator).

The plain values stay public fields: `name`, `msg_type` and `category` on a
message, `name` on a component, `count_tag`, `name`, `delimiter_tag` and
`required` on a group.

**Built with constructors, extended with `push`.** The three structs are
`#[non_exhaustive]`, so later additions are not breaking again. They are built
with `MessageDef::new(msg_type, name, category, members)`,
`ComponentDef::new(name, members)` and `GroupDef::new(count_tag, name,
delimiter_tag, required, members)`, where `members` is any iterator of the
owned `Member` enum (`Field(FieldRef)`, `Group(GroupDef)`,
`Component(ComponentRef)`) in dictionary order, and extended with
`push(member)`, which appends in both views at once. There is no mutable
access to the lists, so the two views cannot disagree. The loader builds every
definition from the XML items it already kept in document order.

**Alternatives rejected.**

- *Public per-kind lists with the order recorded privately* (this change's
  first version). Any edit other than an append desynchronised the two
  silently: with members `[F1, C, F2]`, `fields.remove(0)` made `members()`
  yield `[F2, C]`, with `F2` moved before the component; `insert`, `retain`
  and `reverse` misplace members the same way, in nested groups too. No
  reconciliation rule can recover the intended order from such an edit.
- *Deriving the per-kind lists from one public ordered list.* The readers of a
  single kind would have had to filter the whole list on every read, and the
  validator, the reader and the generator would all have changed, for no gain
  in what the schema can express.

**`Member` and `MemberRef` are exhaustive enums.** Issue #106 suggested a
`#[non_exhaustive]` member enum "for example". The kinds are those of the
QuickFIX XML format (`field`, `group`, `component`); the dictionary and its
consumers (the code generator) are versioned together; and a new kind would
be a breaking change regardless. An exhaustive enum lets consumers match
without a wildcard, so the compiler finds every one of them if a kind is ever
added, instead of a wildcard arm silently skipping it.

**The serialized form.** `Dictionary` and the three definitions derive
`Serialize` / `Deserialize`. A definition serializes its members flattened
into its own map under the keys it had before, `fields`, `groups` and
`components`, plus a new `order` key: a list of `"Field"`, `"Group"` and
`"Component"`, one per member in dictionary order, so the private kind enum's
variant names are now part of the saved format. When a definition is loaded,
a missing list is empty, and a missing `order`, or one that does not count the
members of each kind, is rebuilt as the fields, then the groups, then the
components: data written before this change loads with the order it meant
then. A loaded definition therefore always satisfies the invariant the
accessors rely on.

**Scope.** Messages, components and groups record their order. The header and
trailer stay as `Dictionary`'s separate field and group lists; their groups
record their own entries' order like any group. No validation behaviour
changes: the validator does not use the order, and checking it (reject reason
15) is out of scope. The delimiter is still the first field reachable in
document order.

## Consequences

- **Semver: breaking (for 0.x, a minor bump, the same 0.5.0).** On
  `MessageDef`, `ComponentDef` and `GroupDef`: the public `fields`, `groups`
  and `components` fields are removed (now private, read through methods of
  the same names); the structs are `#[non_exhaustive]`, so they can no longer
  be built with a struct literal or matched exhaustively outside the crate.
  New `pub` items: `Member`, `MemberRef`, the three `new` constructors and the
  `members()`, `fields()`, `groups()`, `components()` and `push()` methods.
- **Callers outside the crate** switch from `def.fields` to `def.fields()`
  (likewise for groups and components) and from struct literals to the
  constructors, listing members in dictionary order; listing fields, then
  groups, then components reproduces the old meaning exactly. In this
  workspace that is `ironfix-codegen`.
- **Tested against the XML.** A test re-reads each embedded XML without the
  loader and asserts, for every message, component and group definition of
  FIX 4.2, FIX 4.4, FIXT 1.1 and FIX 5.0 SP2, that `members()` lists the
  same members in the same order; another pins the FIX 4.4 `PreAllocGrp`
  case. Making `members()` ignore the recorded order fails both. Others cover
  `push`, the per-kind accessors, the exact length of `members()`, and the
  repair of a missing or inconsistent `order` on load.
- **Consumers.** The code generator's writers (#83) and shared component
  types (#98) can write in XML order; a future order check in the validator
  has the data it needs.
- **Unchanged.** No `unsafe`, no new dependency, no change to the crate DAG,
  the validator's results, the group reader or the default code generator's
  output.
