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
split put AllocQty before the component. Counting each loaded group
definition once (header and trailer groups included), the split order differs
from the XML in 1 of 38 in FIX 4.2, 34 of 93 in FIX 4.4, 0 of 2 in FIXT 1.1
and 103 of 561 in FIX 5.0 SP2; the issue's own count, made another way, gives
40 of 90 in FIX 4.4 and 109 of 559 in FIX 5.0 SP2.

`MessageDef`, `ComponentDef` and `GroupDef` had public fields and were not
`#[non_exhaustive]`, so recording the order is a breaking change to
`ironfix-dictionary`. The owner accepted the break (2026-10-17); the release
already goes to 0.5.0, and the version bump is deferred to the last PR of the
programme.

## Decision

**Keep the per-kind lists, record the order beside them.** The three
definitions keep their public `fields`, `groups` and `components` lists,
unchanged, so every reader of the schema (the validator's scope expansion,
the group reader's layouts, the default code generator) keeps working
untouched. Each definition also records, in a private field, the *kind* of
each member in dictionary order. Within one kind the lists already keep their
relative order, so the sequence of kinds is all it takes to interleave them
again: `members()` walks it and takes the next member of the recorded kind
from its list, returning an iterator of `MemberRef<'_>` (`Field`, `Group`,
`Component`, all borrowed) without allocating.

Deriving the per-kind lists from a single ordered list instead was rejected:
it would have removed or changed the public lists every consumer reads,
turning a schema addition into a rewrite of the validator, the reader and
the generator, for no gain in what the schema can express.

**Construction goes through constructors.** The three structs are
`#[non_exhaustive]` from this change on, so later additions are not breaking
again. They are built with `MessageDef::new(msg_type, name, category,
members)`, `ComponentDef::new(name, members)` and `GroupDef::new(count_tag,
name, delimiter_tag, required, members)`, where `members` is any iterator of
the owned `Member` enum (`Field(FieldRef)`, `Group(GroupDef)`,
`Component(ComponentRef)`, `#[non_exhaustive]`) in dictionary order. The
loader builds every definition that way from the XML items it already kept
in document order. The order field is private, so the constructors are the
only way to set it, even inside the crate.

**The public lists can still be edited; `members()` stays defined.** A
member pushed onto a list after construction has no recorded position and is
yielded after the recorded members (fields first, then groups, then
components); a member removed from a list is skipped and the others keep
their order. A definition deserialized without a recorded order (the field is
`#[serde(default)]`) yields its fields, then its groups, then its
components, which is what the split meant before.

**Scope.** Messages, components and groups record their order. The header and
trailer stay as `Dictionary`'s separate field and group lists; their groups
record their own entries' order like any group. No validation behaviour
changes: the validator does not use the order, and checking it (reject reason
15) is out of scope. The delimiter is still the first field reachable in
document order.

## Consequences

- **Semver: breaking (for 0.x, a minor bump).** `MessageDef`, `ComponentDef`
  and `GroupDef` become `#[non_exhaustive]` and gain a private field: they
  can no longer be built with a struct literal or matched exhaustively
  outside the crate. New `pub` items: `Member`, `MemberRef`, the three `new`
  constructors and the three `members()` methods. Every public field stays.
- **Callers outside the crate** that built definitions with struct literals
  (in this workspace, the tests of `ironfix-codegen`) switch to the
  constructors, listing members in dictionary order; listing fields, then
  groups, then components reproduces the old meaning exactly.
- **Tested against the XML.** A test re-reads each embedded XML without the
  loader and asserts, for every message, component and group definition of
  FIX 4.2, FIX 4.4, FIXT 1.1 and FIX 5.0 SP2, that `members()` lists the
  same members in the same order; another pins the FIX 4.4 `PreAllocGrp`
  case. Making `members()` ignore the recorded order fails both.
- **Consumers.** The code generator's writers (#83) and shared component
  types (#98) can write in XML order; a future order check in the validator
  has the data it needs.
- **Unchanged.** No `unsafe`, no new dependency, no change to the crate DAG,
  the validator's results, the group reader or the default code generator's
  output.
