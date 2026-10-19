# ADR-0031 — Validate inbound application messages against a dictionary on the session path

- **Status:** Proposed (issue #84)
- **Date:** 2026-10-20
- **Number:** ADR-0014 was once reserved for #84 and never written; this ADR
  takes the next free number instead, and 0014 stays unused.

## Context

`ironfix_dictionary::Validator` checks a decoded message against a
dictionary, but nothing on the session path called it: an inbound
application message reached `from_app` unchecked unless the application
validated it itself. A gateway wants each message framed, checksummed and
validated once on receipt, so everything after works on validated views.

Two constraints shape the answer:

- **The crate DAG.** `ironfix-engine` depends on `core`, `session`, `store`,
  `transport` and `tagvalue`, and not on `ironfix-dictionary`. The engine
  cannot name `Validator` without changing the graph.
- **The FIX version.** Which `SessionRejectReason` (373) codes exist depends
  on the version: FIX 4.0 and 4.1 define no 373 at all, FIX 4.2 defines 0
  to 11 (`spec/FIX42.xml`), FIX 4.4 adds 12 to 17 and 99 (`spec/FIX44.xml`),
  and FIXT.1.1 adds 18. The validator does not know the session's version;
  the engine does.

`doc/fix_operations.md` lists the 373 codes and the Reject and
BusinessMessageReject layouts. It is silent on when an engine should
validate against a dictionary, where in the inbound pipeline, and which
defect maps to which code. Those are engine decisions, recorded here; the
mapping follows QuickFIX/J, as the #74 review recommended.

## Decision

### A trait in `ironfix-core`

`ironfix_core::validation` defines:

- `InboundValidator: Send + Sync`, with
  `fn validate(&self, msg: &RawMessage<'_>) -> Result<(), InboundRejection>`;
- `InboundRejection`: an `InboundDefect`, an optional `RefTagID`, and a text;
- `InboundDefect` (`#[non_exhaustive]`): the version-neutral defects
  (`InvalidTagNumber`, `RequiredTagMissing`, `TagNotDefinedForMessageType`,
  `ValueIncorrect`, `IncorrectDataFormat`, `InvalidMsgType`,
  `TagAppearsMoreThanOnce`, `RepeatingGroupFieldsOutOfOrder`,
  `IncorrectNumInGroupCount`, `Other`).

`ironfix-dictionary` already depends on `core`, so it implements the trait
for `Validator<'_>`, for `Dictionary` (validating as `Validator::new` does,
so an `Arc<Dictionary>` loaded at run time is a validator) and for
`SessionDictionary<'_>` (as `Validator::for_session`, for FIXT.1.1).
`ValidationError::inbound_rejection` maps each error, exhaustively within
the dictionary crate, so a new `ValidationError` variant does not compile
until its mapping is decided. The first error in `Validator::validate`'s
deterministic order (#100) decides the rejection.

The engine holds `Option<InboundValidation>`, which wraps an
`Arc<dyn InboundValidator>`. **The crate DAG is unchanged**: no new normal
dependency edge. `ironfix-engine` gains `ironfix-dictionary` as a
**dev-dependency** only, for its end-to-end tests.

Alternatives rejected:

- *Engine depends on dictionary.* Changes the DAG and puts schema code in
  every engine build, for a feature that is off by default.
- *Trait in `ironfix-engine`, implemented in an adapter crate.* One more
  published crate for a three-impl adapter; `core` is where the shared
  vocabulary already lives.
- *The validator returns a 373 code.* The code depends on the session's
  version, which the validator does not know.

### Policy

`ValidationPolicy::{Off, Log, Reject}`, `Off` by default.

- `Off`, or no validation attached: the reactor holds `None`, the validator
  is never called; one branch per application message, no allocation.
- `Log`: a failure emits a `warn` event (session, `MsgSeqNum`, MsgType,
  defect, `RefTagID`, policy) and the message is delivered.
- `Reject`: a failure is answered with a Reject; the message never reaches
  `from_app`.

`ValidationRejectMessage::{SessionReject, BusinessMessageReject}` chooses the
message for content defects under `Reject`; `SessionReject` by default.

### Where it runs

On every **in-sequence application message**, in
`Reactor::on_app_in_sequence`, the one path to the dispatcher:

1. framing and decode; a malformed body is the #102 path (a session Reject
   with its own codes) and never reaches the validator;
2. `MsgSeqNum` present, identity (49/56), `SendingTime` (52);
3. the sequence check. A message above the expectation is not validated on
   arrival; under `GapPolicy::Queue` (#71) it is validated when released in
   order, otherwise when its resend arrives. A duplicate below the
   expectation (43=Y) is dropped unvalidated;
4. on FIXT.1.1, the `ApplVerID` (1128) check (#67): a message in a refused
   version is rejected for that (373 = 18), not validated against a
   dictionary of another version;
5. **validation**;
6. the dispatcher, then `from_app`.

Validating after the sequence check keeps the numbering rules unchanged: a
validation failure is a property of one message, never a gap. Validating
before the dispatcher is what keeps a rejected message from `from_app`.
Administrative messages are **not** validated: the session layer already
checks every field it acts on, and rejecting a Logout, a ResendRequest or a
SequenceReset over an unrelated field would break recovery.

### Sequence semantics

A rejected message **consumes its `MsgSeqNum`**, as the FIX session layer
requires for a message answered with a session-level Reject: `MsgSeqNum + 1`
is persisted as the next target before the expectation moves (ADR-0005
order), then the Reject is sent, and the session stays up. The arithmetic is
checked (`checked_add`, `try_increment_target_seq`); exhaustion closes the
session with the usual typed reason. The same helper now serves the #67
`ApplVerID` reject.

### The Reject

A session-level Reject (35=3) carries `RefSeqNum` (45), `RefTagID` (371),
`RefMsgType` (372), `SessionRejectReason` (373) and `Text` (58):

| Defect | 373 | 371 | Validation errors |
|---|---|---|---|
| `InvalidTagNumber` | 0 | the tag | `UnknownTag` |
| `RequiredTagMissing` | 1 | the field, or the count tag | `MissingRequiredField`, `MissingRequiredGroup`, `MissingRequiredFieldInGroupEntry` (the group and entry index go in Text only) |
| `TagNotDefinedForMessageType` | 2 | the tag | `FieldNotAllowedForMessage` |
| `ValueIncorrect` | 5 | the field | `InvalidEnumValue`, `BeginStringMismatch` (371 = 8) |
| `IncorrectDataFormat` | 6 | the field, or the count tag | `InvalidFieldFormat`, `InvalidGroupCount` |
| `InvalidMsgType` | 11 | 35 | `UnknownMsgType` |
| `TagAppearsMoreThanOnce` | 13 | the tag | `DuplicateTag`, `RepeatedTagInGroupEntry` |
| `RepeatingGroupFieldsOutOfOrder` | 15 | the tag found | `GroupDelimiterMismatch` |
| `IncorrectNumInGroupCount` | 16 | the count tag | `GroupCountMismatch` |
| `Other` | 99 | none | `UnknownComponent`, `SchemaTooDeep`, `SchemaTooLarge`, `ErrorLimitReached` |

Per version:

- **FIX 4.3 and later, FIXT.1.1:** the code above.
- **FIX 4.2:** defines 0 to 11 only, so for 13, 15, 16 and 99 the Reject goes
  out **without 373**; 371 and 58 still name the problem. 373 is optional in
  the FIX 4.2 Reject, so omitting it is legal where inventing a code is not.
- **FIX 4.0 and 4.1:** the Reject is 45 and 58 only, as for every Reject the
  engine sends.

FIX 4.3 is not vendored; that it defines 13, 15, 16 and 99 is taken from the
#74 review note ("introduced after FIX 4.2") and is not checked against a
FIX 4.3 dictionary in this repository.

**BusinessMessageReject.** With `ValidationRejectMessage::BusinessMessageReject`,
on FIX 4.2 and later, the two content defects get a BusinessMessageReject
(35=j) with `RefSeqNum` (45), `RefMsgType` (372), `BusinessRejectReason`
(380) and `Text` (58): `RequiredTagMissing` is 5 (*Conditionally required
field missing*), `InvalidMsgType` is 3 (*Unsupported message type*). Every
other defect is a syntax problem of the message and stays a session-level
Reject. FIX 4.0 and 4.1 have no 35=j, so the option has no effect there. A
35=j is an application message: it spends an outbound number, runs through
`to_app_checked` (which may veto it) and is filed for resend.

**No field values.** The text is built from tag numbers, dictionary names
and entry positions only. `ValidationError`'s `Display` quotes values and is
never used on this path. The `Log` warning carries the defect label and the
tag, never the text of a field, so `Password` (554), `NewPassword` (925) and
`RawData` (96) cannot leak through either.

## Consequences

- New public surface (minor bump): `ironfix_core::validation` with
  `InboundValidator`, `InboundRejection`, `InboundDefect`, re-exported from
  the crate root; `ironfix_dictionary::ValidationError::inbound_rejection`
  and three trait impls; `ironfix_engine::validation` with
  `InboundValidation`, `ValidationPolicy`, `ValidationRejectMessage`,
  re-exported; `with_inbound_validation` and `inbound_validation` on
  `Initiator`, `Acceptor` and `EngineBuilder`. `AcceptorRegistry` sessions
  use the validation of the `Acceptor` they are routed to. Nothing is
  renamed or removed.
- With `Off` the hot path is unchanged: one `Option` branch, no allocation.
  With `Log` or `Reject` each application message costs a full
  `Validator::validate`, which allocates (scope expansion, error list); no
  benchmark measures it.
- Not covered: per-`ApplVerID` dictionary selection (a `SessionDictionary`
  names one application dictionary), validation of administrative messages,
  and the `Validator`'s documented gaps (no field-order check; `Validator::new`
  does not check `BeginString`).
