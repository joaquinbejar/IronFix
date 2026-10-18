# ADR-0011 — A zero-copy, dictionary-driven repeating-group reader in ironfix-dictionary

- **Status:** Accepted
- **Date:** 2026-10-18

## Context

A decoded `RawMessage` is a flat list of fields in wire order. Until this
change there was no API to read its repeating groups: a user who wanted the
entries of `NoPartyIDs(453)` walked the fields by hand and had to know the
delimiter and member tags (issue #75). The positional group walk existed, but
only inside the `Validator`, with its own private schema expansion
(`Level` / `GroupNode` with hash sets). Downstream gateways need field access
through a validated view with groups parsed against the dictionary, and no
allocation on the message path.

Three constraints shaped the answer:

- `ironfix-tagvalue` must not depend on `ironfix-dictionary`: decoding is
  dictionary-free by design, and group structure exists only in the
  dictionary.
- The reader and the validator must agree on entry boundaries and on which
  group instances are malformed. Two walks would drift.
- Code generation (#83) wants to emit group structure as `static` data, so a
  generated reader needs no dictionary at run time.

## Decision

**Where it lives.** The reader is the new `ironfix_dictionary::group` module.
`ironfix-tagvalue` is untouched and the crate DAG is unchanged. The only change
outside the crate is one additive accessor, `RawMessage::field_slice(&self) ->
&[FieldRef<'a>]` in `ironfix-core`, so the reader can hand out sub-slices of
the field list instead of collecting it.

**One walk, two consumers.** The validator's schema expansion moves to an
internal `scope` module and its positional walk to an internal `walk` module.
`walk::walk_group` reports events (an entry closed, a count mismatch, a
delimiter mismatch, a repeated tag, too deep) to a `Visitor`: the validator's
visitor turns them into `ValidationError`s (keeping #74's provisional
per-entry errors and its end-of-entry hook), the reader's records the first
`GroupError`. The nested-delimiter fix (a delimiter that is itself a nested
group's count tag) lives in the shared walk, so both have it. The expanded
schema stores sorted vectors, so membership and group lookup are binary
searches, and the tags seen in an entry are tracked in a stack bitset indexed
by the tag's rank among the group's members: no hashing and no allocation for
any group with at most 1024 entry-level members. The widest group of the
embedded dictionaries has 412 (FIX 5.0 SP2 `NoMDEntries`); a wider one spills
that bitset to the heap.

**Layout and borrowing model.**

- `MessageLayout` is built once per message type from a `Dictionary`
  (`MessageLayout::new`) or a `SessionDictionary` (`for_session`, resolving
  admin and application messages as `Validator::for_session` does). All
  allocation happens there. Components are flattened, so a group is found by
  its count tag wherever a component declared it; header and trailer groups
  are included.
- `GroupSpec<'s>` describes one group (count tag, delimiter, sorted
  entry-level members, nested groups) and `GroupSet<'s>` a set of sibling
  groups. Both are `Copy` views, either borrowed from a `MessageLayout` or
  built from static tables.
- Reading yields `GroupEntries<'m, 'a, 's>` (an exact-size iterator) of
  `Copy` `GroupEntry<'m, 'a, 's>` values: `'m` borrows the message's field
  list, `'a` the decoded buffer, `'s` the layout. An entry is a sub-slice of
  the field list; `get(tag)` looks at the entry's own level only, `fields()`
  returns the whole entry, and `group(count_tag)` reads a nested group. Each
  iterator step walks one entry; nothing is collected.

**Static specs for code generation.** `GroupSpec::new` and `GroupSet::new` are
`const fn`s over sorted `&'static [u32]` tag lists that check their arguments
and return `Result<_, SpecError>`. `SpecError` is `Copy` and drop-free, so a
generated `const` item can match the error to `panic!` and turn a bad table
into a compile error. A static set reads exactly like a layout.

**Error semantics.**

- The whole group instance is walked before any view is handed out, nested
  groups included. A malformed instance is a `GroupError` (`CountMismatch`,
  `DelimiterMismatch`, `RepeatedTag`, `InvalidCount`, `TooDeep`), naming the
  group, nested or not, where the problem is. Never a partial view.
- An absent group is `Ok(None)`. A count tag the layout does not know is
  `NotInLayout`; a count field present twice at the message level is
  `DuplicateGroup`; a message of another type is `MsgTypeMismatch`.
- Top-level lookup is positional: the runs of the other top-level groups are
  skipped, so the same tag inside one of their entries is not taken for the
  group asked for.
- A count is one or more ASCII digits fitting a `u64`. `+1` is refused even
  though Rust's `u64::from_str` accepts it, because a FIX `NumInGroup` has no
  sign. The validator shares this parse.
- The reader checks structure only. Required members (#74) remain the
  validator's job.

## Consequences

- **Semver: additive (minor bump).** New `pub` items: the `group` module with
  `MessageLayout`, `GroupSpec`, `GroupSet`, `GroupEntries`, `GroupEntry`,
  `GroupError` and `SpecError` (both enums `#[non_exhaustive]`), re-exported
  at the crate root; and `RawMessage::field_slice` in `ironfix-core`. No `pub`
  item is renamed or removed. `scope` and `walk` are private.
- **Validator behaviour.** Unchanged except for the count parse: a signed
  count such as `453=+1`, which `str::parse` used to accept as 1, is now also
  `ValidationError::InvalidGroupCount` (it was already an
  `InvalidFieldFormat`). `MissingRequiredGroup` errors now come out in
  ascending count-tag order instead of hash order. The validator no longer
  collects the field list into a `Vec`.
- **Agreement is tested, not assumed.** Every validator test goes through one
  helper that also reads every top-level group of the same message with the
  reader and asserts the two agree; sabotaging the reader's count check makes
  twelve validator tests fail.
- **Zero allocation is proved, not claimed.** `dhat` (exact version 0.3.3) is
  a dev-dependency of `ironfix-dictionary` only, declared in the workspace
  dependencies. `tests/group_reader_allocations.rs` installs it as the global
  allocator in its own harness-free binary and asserts that reading,
  iterating, field lookup and nested reads allocate zero blocks, through a
  layout and through static specs. No timing is claimed.
- **Unchanged.** No `unsafe`, no feature flag, no new runtime dependency, and
  the crate DAG is as before: `ironfix-dictionary` depends on `ironfix-core`
  only, `ironfix-tagvalue` does not depend on it, and the engine does not call
  the reader.
