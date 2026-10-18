# ADR-0020 — Validating the application version on FIXT.1.1 sessions

- **Status:** Accepted (issue #67, in the plan the owner approved; the
  initiator's leniency on an ack without 1137 follows the issue text, see
  "Deviations")
- **Date:** 2026-10-18

## Context

A FIX 5.0 session is framed as FIXT.1.1: `BeginString` (8) is `FIXT.1.1`, and
the application version travels in `DefaultApplVerID` (1137), a required body
field of the Logon, and `ApplVerID` (1128), an optional header field of each
application message. IronFix stamped both (`wire.rs`, from `FixVersion`) and
checked neither: an acceptor configured for FIX 5.0 SP2 reached Active with a
peer declaring FIX 5.0, or nothing, and handed its messages to `from_app` as
SP2 (`doc/fix_operations.md`, "FIX 5.0 / FIXT.1.1", before this change).

Constraints any answer keeps:

- the acceptor's check order and refusal groups (ADR-0017), for a session
  served directly and for one routed by an `AcceptorRegistry` (ADR-0018);
- new decision logic is synchronous, takes what it needs as parameters and
  reads no clock (ADR-0002);
- `FixVersion` (`ironfix-core`) is the single version table (ADR-0010 and
  `version.rs`); `ironfix-session` depends on `core` only and holds the
  configuration; `ironfix-engine` composes;
- a check on application messages must hold for every path that releases one
  to `from_app`, including a future queue of messages held across a gap (#71);
- FIX 4.x sessions do not change.

## Decision

### Vocabulary: one table, decoding apart from acceptance

`FixVersion::from_appl_ver_id(&str) -> Option<FixVersion>` decodes the whole
`ApplVerID` enumeration as far as `FixVersion` has variants: `2` to `6` name
FIX 4.0 to FIX 4.4, `7`, `8` and `9` name FIX.5.0, 5.0 SP1 and 5.0 SP2. `0`
(FIX 2.7) and `1` (FIX 3.0) name versions the type does not model, and `10`
(FIX_LATEST in later editions of the enumeration) names no fixed version; all
three, and anything else, are `None` and refused as unknown. The inverse of
`FixVersion::appl_ver_id` holds one way only: every code it stamps decodes back
to its version, but a FIX 4.x version decodes from its code and stamps none,
because this workspace frames FIX 4.x as its own pre-FIXT session.

Decoding is not acceptance. Whether a decoded version is accepted is the
session's rule (below), which takes only versions with an `ApplVerID` code
this workspace stamps, so a peer declaring FIX 4.x over FIXT.1.1 (`6`) is
refused as "6 (FIX.4.4) is not an application version this session accepts"
(reason 18) rather than as unknown. The decoder covers the full list so that
`core`'s table stays the single authority for it, and so that selecting a
dictionary by `ApplVerID` later does not have to change what a published
`const fn` returns. (An earlier revision decoded only `7` to `9`; review
asked for the whole list.)

### Configuration: what a session accepts

`SessionConfig::allowed_appl_versions: Vec<FixVersion>` lists versions the
session accepts besides its own. `SessionConfig::accepts_appl_version` is the
rule: true for the version `begin_string` names (the one the session declares
in its own 1137 and stamps in its own 1128) and for every version in the set,
false for anything else and always false on a non-FIX-5.0 session. The
default, an empty set, accepts exactly the configured version (issue #67:
"default: exactly the configured one").

The configured version is always accepted rather than required to be listed:
a set that left it out would refuse the version the session itself declares,
so an initiator and an acceptor configured alike could not log on to each
other. A union cannot be contradictory, so no error is needed for that case.

`SessionConfig::validate` (and so the builder and both engines' preflight)
refuses, with `SessionConfigError::UnusableApplVersion { version,
begin_string }`, a non-empty set on a session whose `begin_string` is not
FIX.5.0, FIX.5.0SP1 or FIX.5.0SP2, and a set naming a version without an
`ApplVerID` code (FIX 4.x, bare FIXT.1.1). Either would promise a check the
session cannot make. Setters: `SessionConfig::with_allowed_appl_versions` and
`SessionConfigBuilder::allowed_appl_versions`.

### The decision function

`wire::ApplVersionGuard` (crate-private) resolves the accepted set once per
session from `accepts_appl_version`, and is off on a FIX 4.x session. It
offers two synchronous checks over one decoded message, reading no clock and
no session state:

- `check_logon(raw, required)` for 1137: absent (an error only when
  `required`), repeated, not a code (`Unknown`), or not accepted
  (`NotAccepted`);
- `check_application(raw)` for 1128: absent passes (the message is in the
  counterparty's default version, which the handshake checked); repeated, not
  a code, or not accepted fail.

Each tag is looked up across the whole message, not the header alone: the
application reads 1128 with `RawMessage::get_field_str`, which returns the
first occurrence wherever it is, so the value the session checks must be the
value the application can read. A repeated tag fails because no occurrence
can be trusted over the other.

`ApplVersionProblem::reject_reason` maps a failure to a Reject:
`SessionRejectReason` 18 for an unknown or unaccepted value, 13 for a
repeated tag, 1 for a missing required tag, `RefTagID` the tag. The refusal
text echoes at most 16 bytes of the value, escaped, and names the accepted
versions; neither tag can carry a credential.

### Reason 18

`SessionRejectReason` 18 is "Invalid/Unsupported Application Version"
(`INVALID_UNSUPPORTED_APPLICATION_VERSION`) in the vendored FIXT.1.1 session
dictionary (`ironfix-dictionary/spec/FIXT11.xml`). The Reject message is a
FIXT.1.1 session message, governed by that dictionary on every FIXT.1.1
session whatever application version it carries, so 18 is used on FIX 5.0,
5.0 SP1 and 5.0 SP2 sessions alike. A FIX 4.x dictionary stops at 17 (the
vendored FIX 4.4 defines 0 to 17 and 99), and a FIX 4.x session never runs
this check, so a FIX 4.x peer never receives 18.

### Acceptor: an authenticated refusal

The acceptor checks 1137 (required) right after `from_admin` accepts the
Logon, before `ResetSeqNumFlag` (141) and `HeartBtInt` (108). The check order
of ADR-0017 gains one step:

> version, encryption method, `MsgSeqNum`, identity, admission, `SendingTime`,
> `from_admin`; then `DefaultApplVerID` (FIX 5.0); then `141=Y` carrying
> `MsgSeqNum` 1, `HeartBtInt`; then the store is reset or refreshed; then
> `MsgSeqNum` is validated and the acknowledgement sent.

Placing it after `from_admin` makes the refusal belong to ADR-0017's group 3,
an authenticated peer: a Logout whose `Text` says why, numbered from a seed
that never resets (the store's refreshed counters, or the configured seed) and
filed when a store is attached. It is decided before the store can be reset,
so a refused `141=Y` Logon cannot clear the journal. Checking it before
`from_admin`, next to `BeginString`, was the other option: it would have been
an unauthenticated refusal (no reply with a store attached), giving a peer with
the right credentials and the wrong version a silent close instead of a reason.
The version is not a credential, and an authenticated peer is owed the reason.

The refusal is a Logout only, like the acceptor's other authenticated
refusals (141, 108): the peer's Logon is not acknowledged, so no session
exists for a Reject to belong to. `serve` returns `EngineError::ApplVersion {
detail }`, a new variant (`EngineError` is `#[non_exhaustive]`). A session
routed by an `AcceptorRegistry` runs the same handshake, so it behaves the same.

The acknowledgement keeps declaring the acceptor's own version in 1137; the
peer's declared default is logged at debug level and is not adopted for
outbound traffic.

### Initiator: the ack's 1137 when present

The initiator checks 1137 on the acknowledgement right after `from_admin`,
with `required = false`: an ack without 1137 is accepted (issue #67: "check
the 1137 echoed on the Logon ack when present"). A present 1137 that fails is
refused like the ack's other field problems (108): a Reject (18, or 13 when
repeated; `RefTagID` 1137) and a Logout, filed when a store is attached, and
`connect` returns `EngineError::ApplVersion`.

### In session: one path to `from_app`

The reactor's in-sequence application branch is now one method,
`Reactor::on_app_in_sequence`: it runs `check_application`, then either
delivers the message (as before) or calls `Reactor::reject_appl_version`. A
rejected message's number is **consumed**, as for any message answered with a
session-level Reject: `MsgSeqNum + 1` is persisted as the next target number
before the expectation moves (the order delivery uses), recovery progress is
noted, and the Reject is sent; the message never reaches `from_app` and the
session stays up, because the version is a property of the message, not of
the session. A message inside a gap is not checked until it arrives in
sequence (a resend), and a too-low `PossDupFlag` duplicate is dropped as
before.

Any later path that releases application messages, such as the gap queue of
#71, must release each through `on_app_in_sequence`, in order, rather than
calling `deliver_app` directly; the method's documentation says so.

## Deviations

- **The initiator accepts an ack without 1137.** FIXT.1.1 makes 1137 required
  on every Logon, the acknowledgement included. The issue asks the initiator
  to check it "when present", and the plan follows the issue. What the
  leniency gives up is small: the initiator declared its own version in its
  Logon, an ack without 1137 leaves that declaration unanswered rather than
  contradicted, and every application message that names another version in
  1128 is still rejected in session. The acceptor, the side the issue requires
  it of, refuses a Logon without it.
- **The issue placed the acceptor's step "after EncryptMethod".** The approved
  plan places it after `from_admin`, for the refusal-group reason above.

## Consequences

- **Semver (additive):** `FixVersion::from_appl_ver_id`;
  `SessionConfig::allowed_appl_versions` (a field on a `#[non_exhaustive]`
  struct), `SessionConfig::accepts_appl_version`,
  `SessionConfig::with_allowed_appl_versions`,
  `SessionConfigBuilder::allowed_appl_versions`;
  `SessionConfigError::UnusableApplVersion` and `EngineError::ApplVersion`
  (both enums `#[non_exhaustive]`). No existing item changes signature.
- **Behaviour, FIX 5.0 sessions only:** an acceptor refuses a Logon whose 1137
  is missing, repeated, unknown or not accepted; an initiator refuses an ack
  whose present 1137 is; an application message whose 1128 is not accepted is
  rejected and not delivered. A FIX 5.0 peer that previously logged on with
  another version, or none, is now refused. FIX 4.x sessions are unchanged.
- **Not done:** no dictionary is selected by `ApplVerID`; the peer's default
  is not adopted for outbound messages; FIX 4.x over FIXT.1.1 (`ApplVerID` 2 to
  6) is refused; `CstmApplVerID` (1129), `ApplExtID` (1156),
  `DefaultApplExtID` (1407) and `DefaultCstmApplVerID` (1408) are not
  checked.
- The crate DAG is unchanged: `core` gains a function, `session` a field and a
  pure rule over `core` types, `engine` the checks. No dependency was added.
- No performance claim (ADR-0001). The in-session check adds one scan of the
  message's fields per application message on a FIX 5.0 session, and
  allocates only when it refuses; nothing was measured.
